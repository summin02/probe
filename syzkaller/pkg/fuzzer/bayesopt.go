// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 11l — Bayesian Optimization via Nelder-Mead simplex for hyperparameter tuning.
// Tunes 5 hyperparameters over 10-minute epochs with safety rollback.
// Phase 12 C3: warm-start save/load with staleness detection.
// Phase 12 C2: full Nelder-Mead state machine (7 transitions).

package fuzzer

import (
	"encoding/json"
	"math"
	"os"
	"sync"
	"time"
)

const (
	boNumParams    = 8     // Phase 12 C1: expanded from 5 to 8
	boEpochSeconds = 300   // Phase 12 C1: 5 min per epoch (was 10min, halved for 8D convergence)
	boSafetyFrac   = 0.70  // rollback if coverage rate drops below 70% of baseline
	boMaxEpochs    = 200   // Phase 12 C1: doubled for 8D (was 100)
	boEMATransAlpha = 0.3  // Phase 12 C1: EMA transition smoothing for param changes
	boEpochsPerEval = 2    // Phase 12 C1: multi-epoch averaging per vertex
	boCascadeHealthMin     = 2   // minimum active TS layers before health alarm
	boCascadeHealthTimeout = 300 // 5 minutes in seconds
)

// Phase 12 C2: Nelder-Mead state machine operation types.
type nmOpState int

const (
	nmReady           nmOpState = iota // ready for new step (find worst, reflect)
	nmWaitReflection                   // waiting for reflected point evaluation
	nmWaitExpansion                    // waiting for expanded point evaluation
	nmWaitContraction                  // waiting for contracted point evaluation
)

// Nelder-Mead standard coefficients.
const (
	nmAlpha = 1.0 // reflection
	nmGamma = 2.0 // expansion
	nmRho   = 0.5 // contraction
	nmSigma = 0.5 // shrink
	nmShrinkMinGap  = 20 // minimum epochs between shrinks (HIGH-8)
	nmStuckTimeout  = 2  // force shrink after N epochs stuck
	nmConvergeEps   = 1e-6 // convergence: simplex diameter threshold
)

// paramBounds defines [min, max] for each hyperparameter.
// Phase 12 C1: Expanded from 5 to 8 parameters.
var paramBounds = [boNumParams][2]float64{
	{0.05, 0.30}, // [0] delayInjectionRate
	{0.10, 0.50}, // [1] focusBudgetFrac
	{0.10, 0.40}, // [2] smashExploreProb
	{2.0, 10.0},  // [3] cusumThreshold
	{3.0, 6.0},   // [4] deflakeMaxRuns
	{0.90, 0.95}, // [5] dezzerDecayFactor (CRIT-5: lower bound 0.90)
	{0.10, 0.25}, // [6] dezzerTSDeltaLimit
	{0.30, 1.00}, // [7] linucbAlpha (NEW-2: tightened from [0.5, 3.0])
}

// paramDefaults provides safe starting values.
var paramDefaults = [boNumParams]float64{0.10, 0.30, 0.20, 5.0, 4.0, 0.90, 0.20, 1.0}

// BayesOpt implements Nelder-Mead simplex optimization for hyperparameter tuning.
type BayesOpt struct {
	mu sync.Mutex

	// Simplex: N+1 vertices, each a point in N-dimensional space.
	simplex  [boNumParams + 1][boNumParams]float64
	values   [boNumParams + 1]float64 // objective value at each vertex
	evalDone [boNumParams + 1]bool    // has each vertex been evaluated?

	// Current state.
	currentVertex int                    // which vertex is being evaluated
	currentParams [boNumParams]float64
	epochStart    time.Time
	epochCovStart int64 // coverage at epoch start
	epoch         int

	// Phase 12 C2: Nelder-Mead state machine.
	nmState     nmOpState              // pending operation type
	nmCentroid  [boNumParams]float64   // cached centroid (excluding worst)
	nmReflected [boNumParams]float64   // reflected point
	nmExpanded  [boNumParams]float64   // expanded point
	nmContracted [boNumParams]float64  // contracted point
	nmWorst     int                    // index of worst vertex
	nmSecWorst  int                    // index of second-worst vertex
	nmBest      int                    // index of best vertex
	nmReflVal    float64                // value of reflected point
	nmWorstOrig  [boNumParams]float64  // original worst vertex saved before reflection overwrites it
	nmLastShrink int                   // epoch of last shrink (HIGH-8: max once per 20 epochs)
	nmStuckCount int                   // consecutive epochs where same vertex is worst

	// Baseline tracking for safety rollback.
	baselineRate float64 // coverage gain rate during first 2 epochs (baseline)
	baselineSet  bool
	baseRateSum  float64
	baseRateN    int

	// Best known parameters.
	bestParams [boNumParams]float64
	bestValue  float64

	// Active flag.
	active bool

	// Phase 12 C1: Multi-epoch averaging.
	epochRateSum  float64 // sum of rates across sub-epochs for current vertex
	epochRateN    int     // number of sub-epochs completed

	// Phase 12 C1: Focus-isolated objective (NEW-7).
	fuzzOnlyCovStart int64     // fuzz-only coverage at epoch start
	fuzzOnlyTimeStart time.Time // fuzz-only time tracking

	// Phase 12 C1: Adaptive noise margin (replaces flat 10%).
	startTime time.Time // for time-based margin scaling

	// Phase 12 C1: BO cascade health metric (NEW-4).
	cascadeHealthAlarm bool      // true when <2 TS layers active for >5min
	cascadeAlarmStart  time.Time // when the alarm condition first triggered

	// Phase 12 C3: Warm-start tracking.
	warmStarted    bool   // true if loaded from saved state
	warmStartEpoch int    // epoch when warm-start was applied
	savePath       string // path for periodic save (set via SetSavePath)

	logf func(level int, msg string, args ...any)
}

// NewBayesOpt creates a new Nelder-Mead optimizer.
func NewBayesOpt(logf func(level int, msg string, args ...any)) *BayesOpt {
	bo := &BayesOpt{
		logf:       logf,
		active:     true,
		bestParams: paramDefaults,
		bestValue:  -1,
		startTime:  time.Now(),
	}

	// Initialize simplex: vertex 0 = defaults, others = defaults + perturbation along axis i.
	bo.simplex[0] = paramDefaults
	for i := 0; i < boNumParams; i++ {
		bo.simplex[i+1] = paramDefaults
		step := (paramBounds[i][1] - paramBounds[i][0]) * 0.15 // 15% of range
		bo.simplex[i+1][i] = clampBOParam(i, paramDefaults[i]+step)
	}

	bo.currentVertex = 0
	bo.currentParams = bo.simplex[0]
	bo.epochStart = time.Now()
	return bo
}

// GetCurrentParams returns the hyperparameters for the current epoch.
func (bo *BayesOpt) GetCurrentParams() [boNumParams]float64 {
	bo.mu.Lock()
	defer bo.mu.Unlock()
	return bo.currentParams
}

// IsActive returns whether BO is still running.
func (bo *BayesOpt) IsActive() bool {
	bo.mu.Lock()
	defer bo.mu.Unlock()
	return bo.active
}

// CheckEpoch checks if the current epoch has ended and starts a new one.
// Returns true if parameters changed (caller should apply them).
// covTotal = total coverage signal length at this moment.
func (bo *BayesOpt) CheckEpoch(covTotal int64) bool {
	bo.mu.Lock()
	defer bo.mu.Unlock()

	if !bo.active {
		return false
	}

	elapsed := time.Since(bo.epochStart).Seconds()
	if elapsed < float64(boEpochSeconds) {
		return false
	}

	// Compute coverage rate for this epoch.
	covGain := covTotal - bo.epochCovStart
	rate := float64(covGain) / elapsed

	bo.logf(0, "PROBE: BO epoch %d complete: covGain=%d rate=%.2f/s params=[%.3f,%.3f,%.3f,%.1f,%.0f,%.3f,%.3f,%.2f]",
		bo.epoch, covGain, rate,
		bo.currentParams[0], bo.currentParams[1], bo.currentParams[2],
		bo.currentParams[3], bo.currentParams[4],
		bo.currentParams[5], bo.currentParams[6], bo.currentParams[7])

	// Phase 12 C3: Check warm-start safety (discard if underperforming).
	bo.checkWarmStartSafety(rate)

	// Safety check: rollback if rate drops below 70% of baseline.
	// Phase 12 C1: EMA transition (not sudden revert) — Edge Case B.
	if bo.baselineSet && rate < bo.baselineRate*boSafetyFrac {
		bo.logf(0, "PROBE: BO safety rollback! rate=%.2f < %.2f (70%% baseline). EMA revert to best.",
			rate, bo.baselineRate*boSafetyFrac)
		for i := 0; i < boNumParams; i++ {
			bo.currentParams[i] = 0.7*bo.currentParams[i] + 0.3*bo.bestParams[i]
		}
		bo.epochStart = time.Now()
		bo.epochCovStart = covTotal
		bo.epoch++
		return true
	}

	// Record baseline from first 2 epochs — but skip epochs 0-2 (startup burst).
	// Burst coverage rate (epoch 0: ~380/s) would inflate the baseline, causing
	// all subsequent epochs to fall below 70% threshold → perpetual rollback.
	if !bo.baselineSet && bo.epoch >= 3 {
		bo.baseRateSum += rate
		bo.baseRateN++
		if bo.baseRateN >= 2 {
			bo.baselineRate = bo.baseRateSum / float64(bo.baseRateN)
			bo.baselineSet = true
			bo.logf(0, "PROBE: BO baseline rate set: %.2f/s", bo.baselineRate)
		}
	}

	// Record value for current vertex.
	bo.values[bo.currentVertex] = rate
	bo.evalDone[bo.currentVertex] = true
	if rate > bo.bestValue {
		bo.bestValue = rate
		bo.bestParams = bo.currentParams
	}

	// Phase 12 C3: Periodic save every 10 epochs.
	if bo.savePath != "" && bo.epoch > 0 && bo.epoch%10 == 0 {
		go bo.SaveState(bo.savePath) // async to avoid blocking
	}

	// Advance to next vertex or run Nelder-Mead step.
	bo.epoch++
	if bo.epoch >= boMaxEpochs {
		bo.active = false
		bo.currentParams = bo.bestParams
		bo.logf(0, "PROBE: BO completed %d epochs. Using best params.", bo.epoch)
		return true
	}

	// Phase 12 C2: If in mid-NM-step (state machine), continue NM regardless.
	if bo.nmState != nmReady {
		bo.nelderMeadStep()
	} else {
		allEval := true
		for i := range bo.evalDone {
			if !bo.evalDone[i] {
				allEval = false
				break
			}
		}
		if !allEval {
			// Still evaluating initial simplex.
			bo.currentVertex++
			if bo.currentVertex <= boNumParams {
				bo.currentParams = bo.simplex[bo.currentVertex]
			}
		} else {
			// All vertices evaluated — run one Nelder-Mead step.
			bo.nelderMeadStep()
		}
	}

	bo.epochStart = time.Now()
	bo.epochCovStart = covTotal
	return true
}

// nelderMeadStep performs one iteration of the full Nelder-Mead algorithm.
// Phase 12 C2: State machine supporting reflection, expansion, contraction, and shrink.
// Since we evaluate one vertex per epoch, the state machine spans multiple calls.
func (bo *BayesOpt) nelderMeadStep() {
	switch bo.nmState {
	case nmReady:
		bo.nmStepReady()
	case nmWaitReflection:
		bo.nmStepAfterReflection()
	case nmWaitExpansion:
		bo.nmStepAfterExpansion()
	case nmWaitContraction:
		bo.nmStepAfterContraction()
	}
}

// nmFindVertices identifies worst, second-worst, and best vertices.
func (bo *BayesOpt) nmFindVertices() {
	bo.nmWorst, bo.nmSecWorst, bo.nmBest = 0, 0, 0
	for i := 1; i <= boNumParams; i++ {
		if bo.values[i] < bo.values[bo.nmWorst] {
			bo.nmSecWorst = bo.nmWorst
			bo.nmWorst = i
		} else if i != bo.nmWorst && bo.values[i] < bo.values[bo.nmSecWorst] {
			bo.nmSecWorst = i
		}
		if bo.values[i] > bo.values[bo.nmBest] {
			bo.nmBest = i
		}
	}
}

// nmComputeCentroid computes centroid excluding the worst vertex.
func (bo *BayesOpt) nmComputeCentroid() {
	for j := 0; j < boNumParams; j++ {
		bo.nmCentroid[j] = 0
	}
	for i := 0; i <= boNumParams; i++ {
		if i == bo.nmWorst {
			continue
		}
		for j := 0; j < boNumParams; j++ {
			bo.nmCentroid[j] += bo.simplex[i][j]
		}
	}
	for j := 0; j < boNumParams; j++ {
		bo.nmCentroid[j] /= float64(boNumParams)
	}
}

// nmSimplexDiameter returns the max distance between any two vertices.
func (bo *BayesOpt) nmSimplexDiameter() float64 {
	maxDist := 0.0
	for i := 0; i <= boNumParams; i++ {
		for k := i + 1; k <= boNumParams; k++ {
			dist := 0.0
			for j := 0; j < boNumParams; j++ {
				d := bo.simplex[i][j] - bo.simplex[k][j]
				dist += d * d
			}
			if dist > maxDist {
				maxDist = dist
			}
		}
	}
	return math.Sqrt(maxDist)
}

// nmEvaluate sets up the next vertex for evaluation.
func (bo *BayesOpt) nmEvaluate(point [boNumParams]float64) {
	bo.simplex[bo.nmWorst] = point
	bo.evalDone[bo.nmWorst] = false
	bo.currentVertex = bo.nmWorst
	bo.currentParams = point
}

// nmStepReady starts a new Nelder-Mead iteration: find vertices, check convergence, reflect.
func (bo *BayesOpt) nmStepReady() {
	bo.nmFindVertices()
	bo.nmComputeCentroid()

	// Convergence detection: stop if simplex is too small.
	if bo.nmSimplexDiameter() < nmConvergeEps {
		bo.active = false
		bo.currentParams = bo.simplex[bo.nmBest]
		bo.bestParams = bo.simplex[bo.nmBest]
		bo.logf(0, "PROBE: BO Nelder-Mead converged (diameter < eps), using best params")
		return
	}

	// 2-epoch stuck timeout: if same vertex is worst twice, force shrink.
	bo.nmStuckCount++
	if bo.nmStuckCount >= nmStuckTimeout && (bo.epoch-bo.nmLastShrink) >= nmShrinkMinGap {
		bo.logf(0, "PROBE: BO NM stuck for %d epochs, forcing shrink", bo.nmStuckCount)
		bo.nmShrink()
		return
	}

	// Save original worst vertex before reflection overwrites it (needed for inside contraction).
	bo.nmWorstOrig = bo.simplex[bo.nmWorst]

	// Reflection: x_r = centroid + alpha * (centroid - x_worst)
	for j := 0; j < boNumParams; j++ {
		bo.nmReflected[j] = clampBOParam(j, bo.nmCentroid[j]+nmAlpha*(bo.nmCentroid[j]-bo.nmWorstOrig[j]))
	}
	bo.nmState = nmWaitReflection
	bo.nmEvaluate(bo.nmReflected)
}

// nmStepAfterReflection processes the reflected point evaluation result.
func (bo *BayesOpt) nmStepAfterReflection() {
	bo.nmReflVal = bo.values[bo.currentVertex]

	// Case 1: Reflected is best so far → try expansion.
	if bo.nmReflVal > bo.values[bo.nmBest] {
		for j := 0; j < boNumParams; j++ {
			bo.nmExpanded[j] = clampBOParam(j, bo.nmCentroid[j]+nmGamma*(bo.nmReflected[j]-bo.nmCentroid[j]))
		}
		bo.nmState = nmWaitExpansion
		bo.nmEvaluate(bo.nmExpanded)
		return
	}

	// Case 2: Reflected is better than second-worst → accept reflection.
	if bo.nmReflVal > bo.values[bo.nmSecWorst] {
		// Already placed in simplex by nmEvaluate, accept it.
		bo.nmStuckCount = 0
		bo.nmState = nmReady
		return
	}

	// Case 3: Reflected is worse than second-worst → contraction.
	// Outside contraction if reflected >= worst, inside contraction if reflected < worst.
	if bo.nmReflVal >= bo.values[bo.nmWorst] {
		// Outside contraction: x_c = centroid + rho * (x_r - centroid)
		for j := 0; j < boNumParams; j++ {
			bo.nmContracted[j] = clampBOParam(j, bo.nmCentroid[j]+nmRho*(bo.nmReflected[j]-bo.nmCentroid[j]))
		}
	} else {
		// Inside contraction: x_ic = centroid + rho * (x_worst_original - centroid)
		// Uses saved nmWorstOrig since nmEvaluate overwrote the worst vertex with reflected point.
		for j := 0; j < boNumParams; j++ {
			bo.nmContracted[j] = clampBOParam(j, bo.nmCentroid[j]+nmRho*(bo.nmWorstOrig[j]-bo.nmCentroid[j]))
		}
	}
	bo.nmState = nmWaitContraction
	bo.nmEvaluate(bo.nmContracted)
}

// nmStepAfterExpansion processes the expanded point evaluation result.
func (bo *BayesOpt) nmStepAfterExpansion() {
	expandVal := bo.values[bo.currentVertex]

	if expandVal > bo.nmReflVal {
		// Expansion is better → keep expanded point (already in simplex).
		bo.logf(1, "PROBE: BO NM expansion accepted (%.4f > %.4f)", expandVal, bo.nmReflVal)
	} else {
		// Reflected was better → revert to reflected.
		bo.simplex[bo.nmWorst] = bo.nmReflected
		bo.values[bo.nmWorst] = bo.nmReflVal
	}
	bo.nmStuckCount = 0
	bo.nmState = nmReady
}

// nmStepAfterContraction processes the contracted point evaluation result.
func (bo *BayesOpt) nmStepAfterContraction() {
	contractVal := bo.values[bo.currentVertex]

	// Accept contraction if it's better than the reflected value.
	if contractVal > bo.nmReflVal {
		// Contraction accepted (already in simplex).
		bo.nmStuckCount = 0
		bo.nmState = nmReady
		return
	}

	// Contraction failed → shrink (if allowed).
	if (bo.epoch - bo.nmLastShrink) >= nmShrinkMinGap {
		bo.nmShrink()
	} else {
		// Can't shrink yet (HIGH-8) — accept reflected as fallback.
		bo.simplex[bo.nmWorst] = bo.nmReflected
		bo.values[bo.nmWorst] = bo.nmReflVal
		bo.nmState = nmReady
		bo.logf(1, "PROBE: BO NM contraction failed, shrink throttled, accepting reflection")
	}
}

// nmShrink performs the shrink operation: move all vertices toward best.
func (bo *BayesOpt) nmShrink() {
	bo.logf(0, "PROBE: BO NM shrink toward vertex %d", bo.nmBest)
	for i := 0; i <= boNumParams; i++ {
		if i == bo.nmBest {
			continue
		}
		for j := 0; j < boNumParams; j++ {
			bo.simplex[i][j] = clampBOParam(j, bo.simplex[bo.nmBest][j]+nmSigma*(bo.simplex[i][j]-bo.simplex[bo.nmBest][j]))
		}
		bo.evalDone[i] = false
	}
	// Re-evaluate all non-best vertices: start from first unevaluated.
	for i := 0; i <= boNumParams; i++ {
		if !bo.evalDone[i] {
			bo.currentVertex = i
			bo.currentParams = bo.simplex[i]
			break
		}
	}
	bo.nmLastShrink = bo.epoch
	bo.nmStuckCount = 0
	bo.nmState = nmReady
}

// clampBOParam constrains parameter i to its bounds.
func clampBOParam(i int, val float64) float64 {
	if val < paramBounds[i][0] {
		return paramBounds[i][0]
	}
	if val > paramBounds[i][1] {
		return paramBounds[i][1]
	}
	return val
}

// BOEpoch returns the current epoch number (for stats).
func (bo *BayesOpt) BOEpoch() int {
	bo.mu.Lock()
	defer bo.mu.Unlock()
	return bo.epoch
}

// BOBestValue returns the best coverage rate observed (for stats).
func (bo *BayesOpt) BOBestValue() float64 {
	bo.mu.Lock()
	defer bo.mu.Unlock()
	return math.Max(bo.bestValue, 0)
}

// Phase 12 C1: Adaptive noise margin — replaces flat 10%.
// Returns the noise fraction based on elapsed time since BO start.
func (bo *BayesOpt) adaptiveNoiseMargin() float64 {
	elapsed := time.Since(bo.startTime)
	switch {
	case elapsed < 30*time.Minute:
		return 0.02 // tight margin early — let good params win
	case elapsed < 2*time.Hour:
		return 0.05 // moderate margin
	default:
		return 0.10 // loose margin late — avoid over-rejection
	}
}

// Phase 12 C1: CheckCascadeHealth monitors TS layer activity.
// If fewer than boCascadeHealthMin layers are active for >5min,
// revert decayFactor to default and penalize current vertex.
// activeLayers = number of TS layers with sufficient data (pair, cluster, cross, global).
func (bo *BayesOpt) CheckCascadeHealth(activeLayers int) {
	bo.mu.Lock()
	defer bo.mu.Unlock()
	if !bo.active {
		return
	}
	if activeLayers < boCascadeHealthMin {
		if !bo.cascadeHealthAlarm {
			bo.cascadeHealthAlarm = true
			bo.cascadeAlarmStart = time.Now()
		} else if time.Since(bo.cascadeAlarmStart).Seconds() > float64(boCascadeHealthTimeout) {
			// Revert decayFactor (param[5]) to default.
			bo.logf(0, "PROBE: BO cascade health alarm: only %d layers active for >5min, reverting decayFactor",
				activeLayers)
			bo.currentParams[5] = paramDefaults[5]
			// Penalize current vertex.
			if bo.currentVertex >= 0 && bo.currentVertex <= boNumParams {
				bo.values[bo.currentVertex] *= 0.5
			}
			bo.cascadeHealthAlarm = false
		}
	} else {
		bo.cascadeHealthAlarm = false
	}
}

// RecordFuzzOnlyCov records fuzz-only coverage for focus-isolated objective (NEW-7).
func (bo *BayesOpt) RecordFuzzOnlyCov(covTotal int64) {
	bo.mu.Lock()
	defer bo.mu.Unlock()
	if bo.fuzzOnlyTimeStart.IsZero() {
		bo.fuzzOnlyTimeStart = time.Now()
		bo.fuzzOnlyCovStart = covTotal
	}
}

// SetSavePath sets the file path for periodic warm-start saves.
func (bo *BayesOpt) SetSavePath(path string) {
	bo.mu.Lock()
	defer bo.mu.Unlock()
	bo.savePath = path
}

// Phase 12 C3: Warm-start save/load with staleness detection.

const boStateVersion = 1 // increment on structural changes (e.g., B4/C1 deploy)

// BOState is the JSON-serializable warm-start state.
type BOState struct {
	Version    int                    `json:"version"`
	Params     [boNumParams]float64   `json:"params"`
	Value      float64                `json:"value"`
	Epoch      int                    `json:"epoch"`
	KernelHash string                 `json:"kernelHash"`
	CorpusSize int                    `json:"corpusSize"`
	Timestamp  time.Time              `json:"timestamp"`
}

// SaveState writes the current best BO params to a JSON file.
// Called every 10 epochs and on graceful shutdown.
func (bo *BayesOpt) SaveState(path string) error {
	bo.mu.Lock()
	state := BOState{
		Version:    boStateVersion,
		Params:     bo.bestParams,
		Value:      bo.bestValue,
		Epoch:      bo.epoch,
		Timestamp:  time.Now(),
	}
	bo.mu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// Write to temp file then rename for atomicity.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SaveStateWithContext writes state with kernel hash and corpus size for staleness detection.
func (bo *BayesOpt) SaveStateWithContext(path, kernelHash string, corpusSize int) error {
	bo.mu.Lock()
	state := BOState{
		Version:    boStateVersion,
		Params:     bo.bestParams,
		Value:      bo.bestValue,
		Epoch:      bo.epoch,
		KernelHash: kernelHash,
		CorpusSize: corpusSize,
		Timestamp:  time.Now(),
	}
	bo.mu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadState loads warm-start params from a JSON file with staleness detection.
// Returns true if params were loaded and applied to simplex vertex 0.
func (bo *BayesOpt) LoadState(path, kernelHash string, corpusSize int) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false // file missing or unreadable — cold start
	}

	var state BOState
	if err := json.Unmarshal(data, &state); err != nil {
		bo.logf(0, "PROBE: BO warm-start: corrupt file, cold start")
		return false
	}

	// Staleness checks.
	if state.Version != boStateVersion {
		bo.logf(0, "PROBE: BO warm-start: version mismatch (%d != %d), cold start", state.Version, boStateVersion)
		return false
	}
	if state.KernelHash != "" && kernelHash != "" && state.KernelHash != kernelHash {
		bo.logf(0, "PROBE: BO warm-start: kernel hash changed, cold start")
		return false
	}
	if state.CorpusSize > 0 && corpusSize > 0 {
		ratio := float64(corpusSize) / float64(state.CorpusSize)
		if ratio < 0.5 || ratio > 2.0 {
			bo.logf(0, "PROBE: BO warm-start: corpus size changed >50%% (%d→%d), cold start",
				state.CorpusSize, corpusSize)
			return false
		}
	}
	if !state.Timestamp.IsZero() && time.Since(state.Timestamp) > 48*time.Hour {
		bo.logf(0, "PROBE: BO warm-start: state is >48h old, cold start")
		return false
	}

	// Apply warm-start: initialize simplex vertex 0 with saved params.
	bo.mu.Lock()
	defer bo.mu.Unlock()
	for i := 0; i < boNumParams; i++ {
		bo.simplex[0][i] = clampBOParam(i, state.Params[i])
	}
	bo.currentParams = bo.simplex[0]
	bo.bestParams = bo.simplex[0]
	bo.warmStarted = true
	bo.warmStartEpoch = bo.epoch // track when warm-start began for safety eval

	bo.logf(0, "PROBE: BO warm-start loaded from epoch %d (value=%.4f)", state.Epoch, state.Value)
	return true
}

// CheckWarmStartSafety evaluates if warm-started params are performing well.
// If rate < 50% of baseline after 3 epochs, discard warm-start and revert to defaults.
// Called from CheckEpoch.
func (bo *BayesOpt) checkWarmStartSafety(rate float64) {
	if !bo.warmStarted || !bo.baselineSet {
		return
	}
	if bo.epoch-bo.warmStartEpoch < 3 {
		return // need at least 3 epochs of data
	}
	if rate < bo.baselineRate*0.50 {
		bo.logf(0, "PROBE: BO warm-start safety: rate=%.2f < 50%% baseline=%.2f, reverting to defaults",
			rate, bo.baselineRate)
		bo.simplex[0] = paramDefaults
		bo.currentParams = paramDefaults
		bo.bestParams = paramDefaults
		bo.bestValue = -1
		bo.warmStarted = false
	}
}

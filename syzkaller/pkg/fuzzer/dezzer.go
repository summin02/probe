// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 6 — DEzzer: Hybrid Thompson Sampling + Differential Evolution optimizer
// for mutation operator weights.
//
// Architecture (4-Layer):
//   Final Weight = Default × AI Base × TS Delta × DE Correction
//
// Thompson Sampling (primary): Per-operator Bayesian adaptation with Beta-Bernoulli posteriors.
//   - Binary success/failure signals with path-weighted feedback
//   - Time-based decay (configurable half-life)
//   - IPW correction for selection bias
//   - Saturation detection with relative performance mode
//   - ±20% delta range
//
// Differential Evolution (secondary): Joint weight vector optimization for operator synergies.
//   - ±5% correction range (narrower, supplementary role)
//   - Independent fitness function (squared error from ideal, not TS-dependent)
//   - Conflict detection with automatic dampening
//
// Risk mitigations: warm-up period, exploration rounds, crash bonus,
// selective AI reset, starvation prevention, Phase 12 feature collection.
package fuzzer

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/google/syzkaller/prog"
)

// FeedbackSource identifies which execution path produced the result.
type FeedbackSource int

const (
	SourceMutate FeedbackSource = iota // mutateProgRequest (async, high volume, noisier)
	SourceSmash                        // smashJob (sync, medium volume)
	SourceFocus                        // focusJob (sync, low volume, highest quality)
)

const (
	dezzerWindowSize = 100 // sliding window per operator
	dezzerPopSize    = 10  // DE population size
	dezzerEvolveEvery = 100 // evolve DE every N records
	dezzerNumOps     = 5   // squash, splice, insert, mutate_arg, remove

	// Thompson Sampling.
	dezzerWarmupRecords       = 1000  // delta=1.0 during warm-up (no TS/DE applied)
	dezzerDecayIntervalSec    = 30    // time-based decay interval (seconds)
	dezzerDecayFactor         = 0.9   // alpha/beta *= this each decay interval (~3.3 min half-life)
	dezzerAlphaFloor          = 1.0   // minimum alpha (preserves prior, prevents starvation)
	dezzerBetaFloor           = 1.0   // minimum beta
	dezzerSaturationThreshold = 0.001 // mean success prob below this → saturation mode

	// TS delta range.
	dezzerTSDeltaLimit = 0.20 // ±20%

	// DE correction range (secondary, narrower).
	dezzerDECorrLimit       = 0.05 // ±5%
	dezzerF                 = 0.5  // DE mutation factor
	dezzerCR                = 0.7  // DE crossover rate

	// Path weights (feedback quality scaling).
	dezzerWeightMutate = 1.0
	dezzerWeightSmash  = 2.0
	dezzerWeightFocus  = 3.0

	// Exploration rounds.
	dezzerExploreEvery  = 5000 // exploration round every N records
	dezzerExploreLength = 50   // records in exploration mode (neutral delta)

	// Inverse Propensity Weighting cap.
	dezzerIPWCap = 5.0

	// Conflict detection.
	dezzerConflictThreshold = 3    // N/5 operators disagree → dampen DE
	dezzerDampenedCorrLimit = 0.02 // ±2% when dampened
	dezzerDampenRecoveryGen = 10   // generations until DE range restored

	// DE stagnation.
	dezzerStagnantLimit = 50
	dezzerKeepBest      = 3

	// Crash bonus.
	dezzerCrashBonus = 10.0

	// Phase 12 feature log.
	dezzerFeatureLogSize = 100000

	// Phase 8b: Op-pair conditional TS.
	dezzerPairMinData = 50 // minimum observations before using pair TS (fallback to single-op)

	// Phase 8e: Per-cluster TS.
	numClusters          = 6
	dezzerClusterMinData = 100 // per-cluster fallback threshold

	// Phase 8c: Multi-objective meta-bandit.
	NumObjectives     = 3
	ObjCoverage       = 0
	ObjMemorySafety   = 1
	ObjPrivEsc        = 2
	objEpochSize      = 100   // re-select objective every N records
	objCovFloorInit   = 0.70  // initial coverage floor (first hour)
	objCovFloorMid    = 0.50  // mid-phase floor (1-4 hours)
	objCovFloorLate   = 0.30  // late-phase floor (4+ hours)
)

// opNames maps operator index to name.
var opNames = [dezzerNumOps]string{"squash", "splice", "insert", "mutate_arg", "remove"}

// opNameToIndex returns the index for a given operator name, or -1 if unknown.
func opNameToIndex(name string) int {
	for i, n := range opNames {
		if n == name {
			return i
		}
	}
	return -1
}

// DEzzer is a hybrid Thompson Sampling + Differential Evolution optimizer.
// TS provides fast per-operator adaptation; DE finds operator combination synergies.
// 4-Layer: Default × AI Base × TS Delta × DE Correction = Final Weights.
type DEzzer struct {
	mu sync.Mutex

	// Per-operator performance tracking (sliding window).
	opStats [dezzerNumOps]OperatorStats

	// Thompson Sampling posteriors (per operator).
	alpha [dezzerNumOps]float64
	beta  [dezzerNumOps]float64

	// DE population (correction vectors, ±5%).
	population [dezzerPopSize]WeightVector
	fitness    [dezzerPopSize]float64
	bestIdx    int
	generation int

	// AI base weights (layer 2).
	aiBaseWeights WeightVector

	// State tracking.
	totalRecords  int64
	warmupDone    bool
	lastDecayTime time.Time
	saturated     bool

	// Exploration mode.
	explorationMode bool
	explorationLeft int

	// Conflict detection.
	conflictDampened bool
	dampenGensLeft   int

	// DE stagnation.
	stagnantGens int
	lastBestCorr WeightVector

	// Phase 12 ML feature log (ring buffer).
	featureLog    [dezzerFeatureLogSize]FeatureTuple
	featureLogIdx int
	featureLogLen int

	// Phase 8b: Op-pair conditional TS.
	pairAlpha [dezzerNumOps][dezzerNumOps]float64 // pairAlpha[prevOp][nextOp]
	pairBeta  [dezzerNumOps][dezzerNumOps]float64
	pairCount [dezzerNumOps][dezzerNumOps]int64

	// Phase 8e: Per-cluster TS.
	clusterAlpha [numClusters][dezzerNumOps]float64
	clusterBeta  [numClusters][dezzerNumOps]float64
	clusterCount [numClusters]int64

	// Phase 8c: Multi-objective meta-bandit.
	objAlpha   [NumObjectives][dezzerNumOps]float64
	objBeta    [NumObjectives][dezzerNumOps]float64
	objRewards [NumObjectives]float64 // UCB-1 cumulative reward
	objCounts  [NumObjectives]int64   // UCB-1 pull counts
	currentObj int                    // current epoch objective
	epochLeft  int                    // remaining records in this epoch
	startTime  time.Time             // fuzzer start time (dynamic coverage floor)

	logf func(level int, msg string, args ...any)
}

// OperatorStats tracks recent performance of a single mutation operator.
type OperatorStats struct {
	Window    [dezzerWindowSize]OpResult
	WindowIdx int
	Count     int64 // total records ever
}

// OpResult is a single operator execution result.
type OpResult struct {
	CovGainBits int
}

// WeightVector holds per-operator delta multipliers.
// Values are centered on 1.0 (no change from base).
type WeightVector struct {
	Squash    float64
	Splice    float64
	Insert    float64
	MutateArg float64
	Remove    float64
}

// FeatureTuple stores (context, operator, reward) for Phase 12 ML training.
type FeatureTuple struct {
	Timestamp int64          // unix seconds
	OpIdx     int            // operator index
	CovGain   int            // raw coverage gain
	Success   bool           // covGain > 0
	Source    FeedbackSource // which feedback path
	Saturated bool           // was system in saturation mode
}

// NewDEzzer creates a new hybrid TS+DE optimizer.
func NewDEzzer(logf func(level int, msg string, args ...any)) *DEzzer {
	d := &DEzzer{
		logf:          logf,
		lastDecayTime: time.Now(),
		aiBaseWeights: WeightVector{1.0, 1.0, 1.0, 1.0, 1.0},
		startTime:     time.Now(),
		epochLeft:     objEpochSize,
	}
	// Initialize TS posteriors with uniform prior.
	for i := 0; i < dezzerNumOps; i++ {
		d.alpha[i] = dezzerAlphaFloor
		d.beta[i] = dezzerBetaFloor
	}
	// Phase 8b: Initialize pair TS with uniform prior.
	for i := 0; i < dezzerNumOps; i++ {
		for j := 0; j < dezzerNumOps; j++ {
			d.pairAlpha[i][j] = 1.0
			d.pairBeta[i][j] = 1.0
		}
	}
	// Phase 8e: Initialize cluster TS with uniform prior.
	for c := 0; c < numClusters; c++ {
		for i := 0; i < dezzerNumOps; i++ {
			d.clusterAlpha[c][i] = 1.0
			d.clusterBeta[c][i] = 1.0
		}
	}
	// Phase 8c: Initialize multi-objective TS with uniform prior.
	for o := 0; o < NumObjectives; o++ {
		for i := 0; i < dezzerNumOps; i++ {
			d.objAlpha[o][i] = 1.0
			d.objBeta[o][i] = 1.0
		}
	}
	// Initialize DE population around 1.0 (±5%).
	rnd := rand.New(rand.NewSource(42))
	for i := range d.population {
		d.population[i] = randomVector(rnd, dezzerDECorrLimit)
	}
	return d
}

// RecordResult records an operator execution result for TS+DE optimization.
// Phase 8b: prevOp tracks the previous mutation operator for pair TS ("" = no pair).
// Phase 8e: cluster is the kernel subsystem cluster index (-1 = global only).
func (d *DEzzer) RecordResult(op, prevOp string, covGainBits int, source FeedbackSource, cluster int) {
	idx := opNameToIndex(op)
	if idx < 0 {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// 1. Update sliding window.
	stats := &d.opStats[idx]
	wIdx := int(stats.Count % int64(dezzerWindowSize))
	stats.Window[wIdx] = OpResult{CovGainBits: covGainBits}
	stats.WindowIdx = (wIdx + 1) % dezzerWindowSize
	stats.Count++
	d.totalRecords++

	// 2. Time-based decay for TS posteriors.
	d.maybeDecay()

	// 3. Update TS posterior (binary signal + path weight + IPW).
	success := covGainBits > 0
	pathWeight := d.pathWeight(source)
	ipwWeight := d.ipwWeight(idx)
	weight := math.Min(pathWeight*ipwWeight, dezzerIPWCap)

	// Easy-coverage filter: reduce weight during warm-up.
	if !d.warmupDone {
		weight *= 0.5
	}

	if success {
		d.alpha[idx] += weight
	} else {
		d.beta[idx] += weight
	}

	// Phase 8b: Update pair TS if we have a valid prevOp.
	prevIdx := opNameToIndex(prevOp)
	if prevIdx >= 0 {
		if success {
			d.pairAlpha[prevIdx][idx] += weight
		} else {
			d.pairBeta[prevIdx][idx] += weight
		}
		d.pairCount[prevIdx][idx]++
	}

	// Phase 8e: Update per-cluster TS if valid cluster.
	if cluster >= 0 && cluster < numClusters {
		if success {
			d.clusterAlpha[cluster][idx] += weight
		} else {
			d.clusterBeta[cluster][idx] += weight
		}
		d.clusterCount[cluster]++
	}

	// Phase 8c: Update objective-specific TS.
	if d.currentObj >= 0 && d.currentObj < NumObjectives {
		if success {
			d.objAlpha[d.currentObj][idx] += weight
		} else {
			d.objBeta[d.currentObj][idx] += weight
		}
	}

	// 4. Feature log for Phase 12 ML.
	d.recordFeature(idx, covGainBits, success, source)

	// 5. Check warm-up completion.
	if !d.warmupDone && d.totalRecords >= dezzerWarmupRecords {
		d.warmupDone = true
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer warm-up complete (%d records), activating TS+DE optimization", d.totalRecords)
		}
	}

	// 6. Exploration round management.
	if d.totalRecords%dezzerExploreEvery == 0 && d.warmupDone {
		d.explorationMode = true
		d.explorationLeft = dezzerExploreLength
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer exploration round (next %d records with neutral delta)", dezzerExploreLength)
		}
	}
	if d.explorationMode {
		d.explorationLeft--
		if d.explorationLeft <= 0 {
			d.explorationMode = false
		}
	}

	// 7. DE evolution (lazy, every 100 records).
	if d.totalRecords%dezzerEvolveEvery == 0 && d.warmupDone {
		d.recalcDEFitness()
		d.evolveDEOneGeneration()
	}

	// Phase 8c: Epoch management — re-select objective periodically.
	d.epochLeft--
	if d.epochLeft <= 0 && d.warmupDone {
		d.currentObj = d.selectObjective()
		d.epochLeft = objEpochSize
	}
}

// RecordCrash gives a bonus to the operator that triggered a crash.
// In saturation phase, crashes are the most valuable signal.
func (d *DEzzer) RecordCrash(op string) {
	idx := opNameToIndex(op)
	if idx < 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.alpha[idx] += dezzerCrashBonus
	if d.logf != nil {
		d.logf(0, "PROBE: DEzzer crash bonus for '%s' (alpha now %.1f)", op, d.alpha[idx])
	}
}

// GetCurrentWeights returns final weights: Default × AI Base × TS Delta × DE Correction.
func (d *DEzzer) GetCurrentWeights() prog.MutateOpts {
	d.mu.Lock()
	defer d.mu.Unlock()

	defaults := prog.DefaultMutateOpts

	// During warm-up or exploration, use neutral delta (Default × AI Base only).
	if !d.warmupDone || d.explorationMode {
		return prog.MutateOpts{
			ExpectedIterations: defaults.ExpectedIterations,
			MutateArgCount:     defaults.MutateArgCount,
			SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash)),
			SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice)),
			InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert)),
			MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg)),
			RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove)),
		}
	}

	tsDelta := d.computeTSDelta()
	deCorr := d.population[d.bestIdx]

	return prog.MutateOpts{
		ExpectedIterations: defaults.ExpectedIterations,
		MutateArgCount:     defaults.MutateArgCount,
		SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash*tsDelta.Squash*deCorr.Squash)),
		SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice*tsDelta.Splice*deCorr.Splice)),
		InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert*tsDelta.Insert*deCorr.Insert)),
		MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg*tsDelta.MutateArg*deCorr.MutateArg)),
		RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove*tsDelta.Remove*deCorr.Remove)),
	}
}

// GetCurrentWeightsForPair returns weights considering pair TS and cluster TS.
// Phase 8b: If prevOp has enough pair data, use pair-conditioned TS delta.
// Phase 8e: If cluster has enough data, use cluster-specific TS delta.
func (d *DEzzer) GetCurrentWeightsForPair(prevOp string, cluster int) prog.MutateOpts {
	d.mu.Lock()
	defer d.mu.Unlock()

	defaults := prog.DefaultMutateOpts

	// During warm-up or exploration, use neutral delta (Default × AI Base only).
	if !d.warmupDone || d.explorationMode {
		return prog.MutateOpts{
			ExpectedIterations: defaults.ExpectedIterations,
			MutateArgCount:     defaults.MutateArgCount,
			SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash)),
			SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice)),
			InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert)),
			MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg)),
			RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove)),
		}
	}

	// Compute TS delta: prefer pair TS > cluster TS > global TS.
	tsDelta := d.computeTSDeltaLayered(prevOp, cluster)
	deCorr := d.population[d.bestIdx]

	return prog.MutateOpts{
		ExpectedIterations: defaults.ExpectedIterations,
		MutateArgCount:     defaults.MutateArgCount,
		SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash*tsDelta.Squash*deCorr.Squash)),
		SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice*tsDelta.Splice*deCorr.Splice)),
		InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert*tsDelta.Insert*deCorr.Insert)),
		MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg*tsDelta.MutateArg*deCorr.MutateArg)),
		RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove*tsDelta.Remove*deCorr.Remove)),
	}
}

// computeTSDeltaLayered computes TS delta using the best available data:
// pair TS (Phase 8b) → cluster TS (Phase 8e) → global TS (fallback).
func (d *DEzzer) computeTSDeltaLayered(prevOp string, cluster int) WeightVector {
	prevIdx := opNameToIndex(prevOp)

	// Try pair TS first (Phase 8b).
	if prevIdx >= 0 {
		totalPairData := int64(0)
		for j := 0; j < dezzerNumOps; j++ {
			totalPairData += d.pairCount[prevIdx][j]
		}
		if totalPairData >= dezzerPairMinData {
			return d.computePairTSDelta(prevIdx)
		}
	}

	// Try cluster TS (Phase 8e).
	if cluster >= 0 && cluster < numClusters && d.clusterCount[cluster] >= dezzerClusterMinData {
		return d.computeClusterTSDelta(cluster)
	}

	// Fallback to global TS.
	return d.computeTSDelta()
}

// computePairTSDelta computes TS delta conditioned on prevOp.
func (d *DEzzer) computePairTSDelta(prevIdx int) WeightVector {
	var probs [dezzerNumOps]float64
	for j := 0; j < dezzerNumOps; j++ {
		probs[j] = d.pairAlpha[prevIdx][j] / (d.pairAlpha[prevIdx][j] + d.pairBeta[prevIdx][j])
	}
	return d.probsToTSDelta(probs)
}

// computeClusterTSDelta computes TS delta for a specific kernel subsystem cluster.
func (d *DEzzer) computeClusterTSDelta(cluster int) WeightVector {
	var probs [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		probs[i] = d.clusterAlpha[cluster][i] / (d.clusterAlpha[cluster][i] + d.clusterBeta[cluster][i])
	}
	return d.probsToTSDelta(probs)
}

// probsToTSDelta converts success probabilities into a TS delta weight vector.
func (d *DEzzer) probsToTSDelta(probs [dezzerNumOps]float64) WeightVector {
	meanProb := 0.0
	for _, p := range probs {
		meanProb += p
	}
	meanProb /= float64(dezzerNumOps)

	lo := 1.0 - dezzerTSDeltaLimit
	hi := 1.0 + dezzerTSDeltaLimit
	var arr [dezzerNumOps]float64

	maxProb := 0.0
	for _, p := range probs {
		if p > maxProb {
			maxProb = p
		}
	}

	if meanProb < dezzerSaturationThreshold {
		// Saturation mode.
		if maxProb < 1e-10 {
			maxProb = 1e-10
		}
		for i := 0; i < dezzerNumOps; i++ {
			relative := probs[i] / maxProb
			arr[i] = clampFloat(0.6+0.8*relative, lo, hi)
		}
	} else {
		if meanProb < 1e-10 {
			meanProb = 1e-10
		}
		for i := 0; i < dezzerNumOps; i++ {
			arr[i] = clampFloat(probs[i]/meanProb, lo, hi)
		}
	}
	return arrToVec(arr)
}

// SetAIBaseWeights updates the AI base weights with selective reset.
// Small changes → soft TS reset (30% preserve) + DE kept.
// Large changes → hard reset both TS and DE.
func (d *DEzzer) SetAIBaseWeights(opts prog.MutateOpts) {
	d.mu.Lock()
	defer d.mu.Unlock()

	defaults := prog.DefaultMutateOpts
	newBase := WeightVector{
		Squash:    safeDiv(float64(opts.SquashWeight), float64(defaults.SquashWeight)),
		Splice:    safeDiv(float64(opts.SpliceWeight), float64(defaults.SpliceWeight)),
		Insert:    safeDiv(float64(opts.InsertWeight), float64(defaults.InsertWeight)),
		MutateArg: safeDiv(float64(opts.MutateArgWeight), float64(defaults.MutateArgWeight)),
		Remove:    safeDiv(float64(opts.RemoveCallWeight), float64(defaults.RemoveCallWeight)),
	}

	// Compute change magnitude.
	oldArr := vecToArr(d.aiBaseWeights)
	newArr := vecToArr(newBase)
	change := 0.0
	for i := 0; i < dezzerNumOps; i++ {
		change += math.Abs(newArr[i] - oldArr[i])
	}

	d.aiBaseWeights = newBase

	if change < 0.3 {
		// Small change: soft reset TS (preserve 30%), keep DE.
		for i := 0; i < dezzerNumOps; i++ {
			d.alpha[i] = dezzerAlphaFloor + 0.3*(d.alpha[i]-dezzerAlphaFloor)
			d.beta[i] = dezzerBetaFloor + 0.3*(d.beta[i]-dezzerBetaFloor)
		}
		// Inject AI direction hint into TS prior.
		for i := 0; i < dezzerNumOps; i++ {
			if newArr[i] > oldArr[i] {
				d.alpha[i] += 2.0 // AI says boost → slight positive prior
			} else if newArr[i] < oldArr[i] {
				d.beta[i] += 2.0 // AI says suppress → slight negative prior
			}
		}
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer AI base minor update (change=%.2f) — TS soft reset, DE kept", change)
		}
	} else {
		// Large change: hard reset TS + DE.
		for i := 0; i < dezzerNumOps; i++ {
			d.alpha[i] = dezzerAlphaFloor
			d.beta[i] = dezzerBetaFloor
			// Inject AI direction hint.
			if newArr[i] > 1.0 {
				d.alpha[i] += 2.0
			} else if newArr[i] < 1.0 {
				d.beta[i] += 2.0
			}
		}
		rnd := rand.New(rand.NewSource(d.totalRecords))
		for i := range d.population {
			d.population[i] = randomVector(rnd, dezzerDECorrLimit)
			d.fitness[i] = 0
		}
		d.bestIdx = 0
		d.generation = 0
		d.stagnantGens = 0
		d.lastBestCorr = WeightVector{}
		d.conflictDampened = false
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer AI base major update (change=%.2f) — full TS+DE reset", change)
		}
	}

	if d.logf != nil {
		d.logf(0, "PROBE: DEzzer AI base — Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f",
			d.aiBaseWeights.Squash, d.aiBaseWeights.Splice, d.aiBaseWeights.Insert,
			d.aiBaseWeights.MutateArg, d.aiBaseWeights.Remove)
	}
}

// --- Snapshot for dashboard and AI prompts ---

// DEzzerSnapshot is the serializable state for external consumption.
type DEzzerSnapshot struct {
	Generation   int                `json:"generation"`
	TotalRecords int64              `json:"total_records"`
	WarmupDone   bool               `json:"warmup_done"`
	Saturated    bool               `json:"saturated"`

	OpSuccessRates map[string]float64 `json:"op_success_rates"`
	OpAvgCovGain   map[string]float64 `json:"op_avg_cov_gain"`

	AIBaseWeights map[string]float64 `json:"ai_base_weights"`
	TSDelta       map[string]float64 `json:"ts_delta"`
	DECorrection  map[string]float64 `json:"de_correction"`
	FinalWeights  map[string]int     `json:"final_weights"`

	// Backward compat: DEDelta = TS×DE combined.
	DEDelta     map[string]float64 `json:"de_delta"`
	BestFitness float64            `json:"best_fitness"`

	// TS diagnostics.
	TSAlpha      map[string]float64 `json:"ts_alpha"`
	TSBeta       map[string]float64 `json:"ts_beta"`
	TSConfidence map[string]float64 `json:"ts_confidence"`

	// Phase 8b: Pair TS success rates.
	PairSuccessRates map[string]float64 `json:"pair_success_rates,omitempty"` // "prev->next" → rate

	// Phase 8e: Cluster TS summary.
	ClusterCounts map[string]int64 `json:"cluster_counts,omitempty"` // cluster_name → count

	// Phase 8c: Multi-objective status.
	CurrentObjective string         `json:"current_objective,omitempty"`
	ObjectiveCounts  map[string]int64 `json:"objective_counts,omitempty"`
}

func (d *DEzzer) Snapshot() DEzzerSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()

	snap := DEzzerSnapshot{
		Generation:     d.generation,
		TotalRecords:   d.totalRecords,
		WarmupDone:     d.warmupDone,
		Saturated:      d.saturated,
		BestFitness:    d.fitness[d.bestIdx],
		OpSuccessRates: make(map[string]float64),
		OpAvgCovGain:   make(map[string]float64),
		AIBaseWeights:  make(map[string]float64),
		TSDelta:        make(map[string]float64),
		DECorrection:   make(map[string]float64),
		FinalWeights:   make(map[string]int),
		DEDelta:        make(map[string]float64),
		TSAlpha:        make(map[string]float64),
		TSBeta:         make(map[string]float64),
		TSConfidence:   make(map[string]float64),
	}

	tsDelta := d.computeTSDelta()
	deCorr := d.population[d.bestIdx]
	defaults := prog.DefaultMutateOpts
	tsArr := vecToArr(tsDelta)
	deArr := vecToArr(deCorr)
	aiArr := vecToArr(d.aiBaseWeights)
	defaultWeights := [dezzerNumOps]int{
		defaults.SquashWeight, defaults.SpliceWeight, defaults.InsertWeight,
		defaults.MutateArgWeight, defaults.RemoveCallWeight,
	}

	for i, name := range opNames {
		sr, avg := d.opSuccessRate(i)
		snap.OpSuccessRates[name] = sr
		snap.OpAvgCovGain[name] = avg
		snap.AIBaseWeights[name] = aiArr[i]
		snap.TSDelta[name] = tsArr[i]
		snap.DECorrection[name] = deArr[i]
		snap.DEDelta[name] = tsArr[i] * deArr[i] // backward compat: combined
		snap.FinalWeights[name] = maxInt(1, int(float64(defaultWeights[i])*aiArr[i]*tsArr[i]*deArr[i]))
		snap.TSAlpha[name] = d.alpha[i]
		snap.TSBeta[name] = d.beta[i]
		snap.TSConfidence[name] = d.alpha[i] + d.beta[i]
	}

	// Phase 8b: Pair TS success rates.
	snap.PairSuccessRates = make(map[string]float64)
	for i := 0; i < dezzerNumOps; i++ {
		for j := 0; j < dezzerNumOps; j++ {
			if d.pairCount[i][j] > 0 {
				rate := d.pairAlpha[i][j] / (d.pairAlpha[i][j] + d.pairBeta[i][j])
				key := opNames[i] + "->" + opNames[j]
				snap.PairSuccessRates[key] = rate
			}
		}
	}

	// Phase 8e: Cluster counts.
	clusterNames := [numClusters]string{"fs", "net", "mm", "ipc", "device", "other"}
	snap.ClusterCounts = make(map[string]int64)
	for c := 0; c < numClusters; c++ {
		if d.clusterCount[c] > 0 {
			snap.ClusterCounts[clusterNames[c]] = d.clusterCount[c]
		}
	}

	// Phase 8c: Multi-objective status.
	objNames := [NumObjectives]string{"coverage", "memory_safety", "priv_esc"}
	snap.CurrentObjective = objNames[d.currentObj]
	snap.ObjectiveCounts = make(map[string]int64)
	for i := 0; i < NumObjectives; i++ {
		snap.ObjectiveCounts[objNames[i]] = d.objCounts[i]
	}

	return snap
}

// StatusString returns a human-readable DEzzer status for logging.
func (d *DEzzer) StatusString() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	tsDelta := d.computeTSDelta()
	deCorr := d.population[d.bestIdx]
	tsArr := vecToArr(tsDelta)
	deArr := vecToArr(deCorr)

	var parts []string
	for i, name := range opNames {
		sr, _ := d.opSuccessRate(i)
		parts = append(parts, fmt.Sprintf("%s=%.1f%%", name, sr*100))
	}

	return fmt.Sprintf("gen=%d TS={Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f} DE={Sq:%.3f Sp:%.3f In:%.3f MA:%.3f Rm:%.3f} rates=[%s]%s",
		d.generation,
		tsArr[0], tsArr[1], tsArr[2], tsArr[3], tsArr[4],
		deArr[0], deArr[1], deArr[2], deArr[3], deArr[4],
		joinStrings(parts, ", "),
		d.statusSuffix())
}

// --- Thompson Sampling internals (caller must hold d.mu) ---

// computeTSDelta computes TS delta from posteriors.
// Normal mode: delta = prob/meanProb clamped to ±20%.
// Saturation mode: relative performance (prob/maxProb).
func (d *DEzzer) computeTSDelta() WeightVector {
	var probs [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		probs[i] = d.alpha[i] / (d.alpha[i] + d.beta[i])
	}

	// Saturation detection.
	meanProb := 0.0
	for _, p := range probs {
		meanProb += p
	}
	meanProb /= float64(dezzerNumOps)
	d.saturated = meanProb < dezzerSaturationThreshold

	var arr [dezzerNumOps]float64
	lo := 1.0 - dezzerTSDeltaLimit
	hi := 1.0 + dezzerTSDeltaLimit

	if d.saturated {
		// Saturation mode: relative performance (best operator = max delta).
		maxProb := 0.0
		for _, p := range probs {
			if p > maxProb {
				maxProb = p
			}
		}
		if maxProb < 1e-10 {
			maxProb = 1e-10
		}
		for i := 0; i < dezzerNumOps; i++ {
			relative := probs[i] / maxProb
			arr[i] = clampFloat(0.6+0.8*relative, lo, hi)
		}
	} else {
		// Normal mode: proportional to prob/meanProb.
		if meanProb < 1e-10 {
			meanProb = 1e-10
		}
		for i := 0; i < dezzerNumOps; i++ {
			arr[i] = clampFloat(probs[i]/meanProb, lo, hi)
		}
	}

	return arrToVec(arr)
}

// maybeDecay applies time-based exponential decay to TS posteriors.
func (d *DEzzer) maybeDecay() {
	now := time.Now()
	elapsed := now.Sub(d.lastDecayTime).Seconds()
	if elapsed < float64(dezzerDecayIntervalSec) {
		return
	}

	intervals := int(elapsed / float64(dezzerDecayIntervalSec))
	factor := math.Pow(dezzerDecayFactor, float64(intervals))
	for i := 0; i < dezzerNumOps; i++ {
		d.alpha[i] = math.Max(dezzerAlphaFloor, d.alpha[i]*factor)
		d.beta[i] = math.Max(dezzerBetaFloor, d.beta[i]*factor)
	}
	// Phase 8b: Decay pair TS.
	for i := 0; i < dezzerNumOps; i++ {
		for j := 0; j < dezzerNumOps; j++ {
			d.pairAlpha[i][j] = math.Max(1.0, d.pairAlpha[i][j]*factor)
			d.pairBeta[i][j] = math.Max(1.0, d.pairBeta[i][j]*factor)
		}
	}
	// Phase 8e: Decay cluster TS.
	for c := 0; c < numClusters; c++ {
		for i := 0; i < dezzerNumOps; i++ {
			d.clusterAlpha[c][i] = math.Max(1.0, d.clusterAlpha[c][i]*factor)
			d.clusterBeta[c][i] = math.Max(1.0, d.clusterBeta[c][i]*factor)
		}
	}
	d.lastDecayTime = now
}

// pathWeight returns the feedback quality weight for the given source.
func (d *DEzzer) pathWeight(source FeedbackSource) float64 {
	switch source {
	case SourceSmash:
		return dezzerWeightSmash
	case SourceFocus:
		return dezzerWeightFocus
	default:
		return dezzerWeightMutate
	}
}

// ipwWeight returns inverse propensity weight to correct for selection bias.
// Rarely-selected operators get higher weight per observation.
func (d *DEzzer) ipwWeight(opIdx int) float64 {
	total := int64(0)
	for i := 0; i < dezzerNumOps; i++ {
		total += d.opStats[i].Count
	}
	if total == 0 {
		return 1.0
	}
	propensity := float64(d.opStats[opIdx].Count) / float64(total)
	if propensity < 0.05 {
		propensity = 0.05 // cap at 20x to prevent extreme weights
	}
	return math.Min(1.0/propensity, dezzerIPWCap)
}

// --- DE internals (caller must hold d.mu) ---

// recalcDEFitness uses INDEPENDENT data (raw sliding window, not TS posteriors).
// Fitness = negative squared error from ideal correction vector.
// ideal[op] = clamp(rate[op]/meanRate, 1±corrLimit)
func (d *DEzzer) recalcDEFitness() {
	var rates [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		rates[i], _ = d.opSuccessRate(i)
	}
	meanRate := 0.0
	for _, r := range rates {
		meanRate += r
	}
	meanRate /= float64(dezzerNumOps)

	corrLimit := d.activeCorrLimit()

	for p := range d.population {
		arr := vecToArr(d.population[p])
		fit := 0.0
		for i := 0; i < dezzerNumOps; i++ {
			ideal := 1.0
			if meanRate > 1e-10 {
				ideal = clampFloat(rates[i]/meanRate, 1.0-corrLimit, 1.0+corrLimit)
			}
			diff := arr[i] - ideal
			fit -= diff * diff
		}
		d.fitness[p] = fit
		if fit > d.fitness[d.bestIdx] {
			d.bestIdx = p
		}
	}
}

// evolveDEOneGeneration runs one DE/rand/1 evolution step with ±5% correction.
func (d *DEzzer) evolveDEOneGeneration() {
	rnd := rand.New(rand.NewSource(d.totalRecords + int64(d.generation)))
	corrLimit := d.activeCorrLimit()

	// Conflict recovery countdown.
	if d.conflictDampened {
		d.dampenGensLeft--
		if d.dampenGensLeft <= 0 {
			d.conflictDampened = false
			if d.logf != nil {
				d.logf(0, "PROBE: DEzzer DE correction range restored to ±%.0f%%", dezzerDECorrLimit*100)
			}
		}
	}

	for i := range d.population {
		a, b, c := i, i, i
		for a == i {
			a = rnd.Intn(dezzerPopSize)
		}
		for b == i || b == a {
			b = rnd.Intn(dezzerPopSize)
		}
		for c == i || c == a || c == b {
			c = rnd.Intn(dezzerPopSize)
		}

		trial := d.deMutantVector(d.population[a], d.population[b], d.population[c], rnd)
		trial = clampVectorRange(trial, corrLimit)
		trialFit := d.evalDEVector(trial, corrLimit)

		if trialFit >= d.fitness[i] {
			d.population[i] = trial
			d.fitness[i] = trialFit
			if trialFit > d.fitness[d.bestIdx] {
				d.bestIdx = i
			}
		}
	}

	d.generation++

	// Conflict detection.
	d.checkConflict()

	// Stagnation detection.
	best := d.population[d.bestIdx]
	if best == d.lastBestCorr {
		d.stagnantGens++
	} else {
		d.stagnantGens = 0
		d.lastBestCorr = best
	}
	if d.stagnantGens >= dezzerStagnantLimit {
		d.partialRestart(corrLimit)
	}

	// Periodic logging.
	if d.logf != nil && d.generation%10 == 0 {
		tsDelta := d.computeTSDelta()
		deCorr := d.population[d.bestIdx]
		d.logf(0, "PROBE: DEzzer gen=%d TS={Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f} DE={Sq:%.3f Sp:%.3f In:%.3f MA:%.3f Rm:%.3f}%s",
			d.generation,
			tsDelta.Squash, tsDelta.Splice, tsDelta.Insert, tsDelta.MutateArg, tsDelta.Remove,
			deCorr.Squash, deCorr.Splice, deCorr.Insert, deCorr.MutateArg, deCorr.Remove,
			d.statusSuffix())
	}
}

// checkConflict detects when TS and DE disagree on direction for ≥3/5 operators.
func (d *DEzzer) checkConflict() {
	tsDelta := d.computeTSDelta()
	deCorr := d.population[d.bestIdx]
	tsArr := vecToArr(tsDelta)
	deArr := vecToArr(deCorr)

	conflicts := 0
	for i := 0; i < dezzerNumOps; i++ {
		tsDir := tsArr[i] - 1.0
		deDir := deArr[i] - 1.0
		if (tsDir > 0.01 && deDir < -0.01) || (tsDir < -0.01 && deDir > 0.01) {
			conflicts++
		}
	}

	if conflicts >= dezzerConflictThreshold && !d.conflictDampened {
		d.conflictDampened = true
		d.dampenGensLeft = dezzerDampenRecoveryGen
		if d.logf != nil {
			d.logf(0, "PROBE: DEzzer TS/DE conflict (%d/%d), dampening DE to ±%.0f%%",
				conflicts, dezzerNumOps, dezzerDampenedCorrLimit*100)
		}
		// Re-clamp population to dampened range.
		for i := range d.population {
			d.population[i] = clampVectorRange(d.population[i], dezzerDampenedCorrLimit)
		}
	}
}

func (d *DEzzer) evalDEVector(v WeightVector, corrLimit float64) float64 {
	var rates [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		rates[i], _ = d.opSuccessRate(i)
	}
	meanRate := 0.0
	for _, r := range rates {
		meanRate += r
	}
	meanRate /= float64(dezzerNumOps)

	arr := vecToArr(v)
	fit := 0.0
	for i := 0; i < dezzerNumOps; i++ {
		ideal := 1.0
		if meanRate > 1e-10 {
			ideal = clampFloat(rates[i]/meanRate, 1.0-corrLimit, 1.0+corrLimit)
		}
		diff := arr[i] - ideal
		fit -= diff * diff
	}
	return fit
}

func (d *DEzzer) activeCorrLimit() float64 {
	if d.conflictDampened {
		return dezzerDampenedCorrLimit
	}
	return dezzerDECorrLimit
}

func (d *DEzzer) statusSuffix() string {
	suffix := ""
	if d.saturated {
		suffix += " [SATURATED]"
	}
	if d.conflictDampened {
		suffix += " [DAMPENED]"
	}
	if d.explorationMode {
		suffix += " [EXPLORING]"
	}
	return suffix
}

// partialRestart keeps the top dezzerKeepBest individuals and randomizes the rest.
func (d *DEzzer) partialRestart(corrLimit float64) {
	type idxFit struct {
		idx int
		fit float64
	}
	sorted := make([]idxFit, dezzerPopSize)
	for i := range d.population {
		sorted[i] = idxFit{i, d.fitness[i]}
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].fit > sorted[i].fit {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	keep := make(map[int]bool)
	for i := 0; i < dezzerKeepBest && i < len(sorted); i++ {
		keep[sorted[i].idx] = true
	}

	rnd := rand.New(rand.NewSource(d.totalRecords + int64(d.generation)*7))
	for i := range d.population {
		if keep[i] {
			continue
		}
		d.population[i] = randomVector(rnd, corrLimit)
		d.fitness[i] = d.evalDEVector(d.population[i], corrLimit)
	}

	d.bestIdx = 0
	for i := 1; i < dezzerPopSize; i++ {
		if d.fitness[i] > d.fitness[d.bestIdx] {
			d.bestIdx = i
		}
	}
	d.stagnantGens = 0
	d.lastBestCorr = d.population[d.bestIdx]

	if d.logf != nil {
		best := d.population[d.bestIdx]
		d.logf(0, "PROBE: DEzzer DE partial restart (kept top %d) — gen=%d corr={Sq:%.3f Sp:%.3f In:%.3f MA:%.3f Rm:%.3f}",
			dezzerKeepBest, d.generation, best.Squash, best.Splice, best.Insert, best.MutateArg, best.Remove)
	}
}

func (d *DEzzer) deMutantVector(a, b, c WeightVector, rnd *rand.Rand) WeightVector {
	jrand := rnd.Intn(dezzerNumOps)
	aArr := vecToArr(a)
	bArr := vecToArr(b)
	cArr := vecToArr(c)

	var result [dezzerNumOps]float64
	for j := 0; j < dezzerNumOps; j++ {
		if rnd.Float64() < dezzerCR || j == jrand {
			result[j] = aArr[j] + dezzerF*(bArr[j]-cArr[j])
		} else {
			result[j] = aArr[j]
		}
	}
	return arrToVec(result)
}

// --- Common helpers ---

func (d *DEzzer) opSuccessRate(opIdx int) (float64, float64) {
	stats := &d.opStats[opIdx]
	n := int(stats.Count)
	if n == 0 {
		return 0, 0
	}
	if n > dezzerWindowSize {
		n = dezzerWindowSize
	}
	successes := 0
	totalGain := 0
	for i := 0; i < n; i++ {
		r := stats.Window[i]
		if r.CovGainBits > 0 {
			successes++
		}
		totalGain += r.CovGainBits
	}
	return float64(successes) / float64(n), float64(totalGain) / float64(n)
}

func (d *DEzzer) recordFeature(opIdx int, covGain int, success bool, source FeedbackSource) {
	d.featureLog[d.featureLogIdx] = FeatureTuple{
		Timestamp: time.Now().Unix(),
		OpIdx:     opIdx,
		CovGain:   covGain,
		Success:   success,
		Source:    source,
		Saturated: d.saturated,
	}
	d.featureLogIdx = (d.featureLogIdx + 1) % dezzerFeatureLogSize
	if d.featureLogLen < dezzerFeatureLogSize {
		d.featureLogLen++
	}
}

// --- Phase 8c: Multi-objective meta-bandit ---

// selectObjective uses UCB-1 to choose the next objective.
func (d *DEzzer) selectObjective() int {
	totalPulls := int64(0)
	for _, c := range d.objCounts {
		totalPulls += c
	}

	// Ensure each objective is tried at least once.
	for i := 0; i < NumObjectives; i++ {
		if d.objCounts[i] == 0 {
			return i
		}
	}

	// Dynamic coverage floor: coverage must get at least this fraction of selection.
	hours := time.Since(d.startTime).Hours()
	covFloor := objCovFloorInit
	if hours > 4 {
		covFloor = objCovFloorLate
	} else if hours > 1 {
		covFloor = objCovFloorMid
	}

	// If coverage is under-selected, force it.
	covFrac := float64(d.objCounts[ObjCoverage]) / float64(totalPulls)
	if covFrac < covFloor {
		return ObjCoverage
	}

	// UCB-1: argmax(reward/count + sqrt(2*ln(totalCount)/count))
	bestObj := 0
	bestScore := -1.0
	lnTotal := math.Log(float64(totalPulls))
	for i := 0; i < NumObjectives; i++ {
		avgReward := d.objRewards[i] / float64(d.objCounts[i])
		exploration := math.Sqrt(2.0 * lnTotal / float64(d.objCounts[i]))
		score := avgReward + exploration
		if score > bestScore {
			bestScore = score
			bestObj = i
		}
	}

	if d.logf != nil {
		objNames := [NumObjectives]string{"coverage", "memory_safety", "priv_esc"}
		d.logf(0, "PROBE: DEzzer objective selected: %s (counts: cov=%d mem=%d priv=%d)",
			objNames[bestObj], d.objCounts[ObjCoverage], d.objCounts[ObjMemorySafety], d.objCounts[ObjPrivEsc])
	}
	return bestObj
}

// RecordObjectiveReward records a reward for the current objective.
func (d *DEzzer) RecordObjectiveReward(reward float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.currentObj >= 0 && d.currentObj < NumObjectives {
		d.objRewards[d.currentObj] += reward
		d.objCounts[d.currentObj]++
	}
}

// CurrentObjective returns the currently active objective.
func (d *DEzzer) CurrentObjective() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentObj
}

// --- Utility functions ---

func randomVector(rnd *rand.Rand, limit float64) WeightVector {
	return WeightVector{
		Squash:    1.0 + (rnd.Float64()-0.5)*2*limit,
		Splice:    1.0 + (rnd.Float64()-0.5)*2*limit,
		Insert:    1.0 + (rnd.Float64()-0.5)*2*limit,
		MutateArg: 1.0 + (rnd.Float64()-0.5)*2*limit,
		Remove:    1.0 + (rnd.Float64()-0.5)*2*limit,
	}
}

func vecToArr(v WeightVector) [dezzerNumOps]float64 {
	return [dezzerNumOps]float64{v.Squash, v.Splice, v.Insert, v.MutateArg, v.Remove}
}

func arrToVec(a [dezzerNumOps]float64) WeightVector {
	return WeightVector{a[0], a[1], a[2], a[3], a[4]}
}

func clampVectorRange(v WeightVector, limit float64) WeightVector {
	lo := 1.0 - limit
	hi := 1.0 + limit
	v.Squash = clampFloat(v.Squash, lo, hi)
	v.Splice = clampFloat(v.Splice, lo, hi)
	v.Insert = clampFloat(v.Insert, lo, hi)
	v.MutateArg = clampFloat(v.MutateArg, lo, hi)
	v.Remove = clampFloat(v.Remove, lo, hi)
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func safeDiv(a, b float64) float64 {
	if b == 0 || math.IsNaN(b) {
		return 1.0
	}
	r := a / b
	if math.IsNaN(r) || math.IsInf(r, 0) {
		return 1.0
	}
	return r
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}

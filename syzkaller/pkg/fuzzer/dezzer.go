// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 6 — DEzzer: Differential Evolution optimizer for mutation operator weights.
// Tracks per-operator success rates via a sliding window and evolves weight vectors
// using a Lazy DE (DE/rand/1) strategy. Integrates with AI base weights via 3-layer
// architecture: Default × AI Base × DE Delta.
package fuzzer

import (
	"fmt"
	"math"
	"math/rand"
	"sync"

	"github.com/google/syzkaller/prog"
)

const (
	dezzerWindowSize    = 100  // sliding window per operator
	dezzerPopSize       = 10   // DE population size
	dezzerEvolveEvery   = 100  // evolve 1 generation every N records
	dezzerDeltaLimit    = 0.20 // ±20% delta from AI base
	dezzerF             = 0.5  // DE mutation factor
	dezzerCR            = 0.7  // DE crossover rate
	dezzerNumOps        = 5    // squash, splice, insert, mutate_arg, remove
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

// DEzzer is the Differential Evolution optimizer for mutation weights.
type DEzzer struct {
	mu sync.Mutex

	// Per-operator performance tracking (sliding window).
	opStats [dezzerNumOps]OperatorStats

	// DE population (weight delta vectors).
	population [dezzerPopSize]WeightVector
	fitness    [dezzerPopSize]float64
	bestIdx    int
	generation int

	// AI base weights (layer 2) — set by SetAIMutationHints.
	aiBaseWeights WeightVector

	// Execution counter for lazy evolution.
	totalRecords int64

	// Logging function.
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
// Values are centered on 1.0 (no change from AI base).
type WeightVector struct {
	Squash    float64
	Splice    float64
	Insert    float64
	MutateArg float64
	Remove    float64
}

// NewDEzzer creates a new DEzzer with default initial state.
func NewDEzzer(logf func(level int, msg string, args ...any)) *DEzzer {
	d := &DEzzer{
		logf: logf,
		aiBaseWeights: WeightVector{
			Squash:    1.0,
			Splice:    1.0,
			Insert:    1.0,
			MutateArg: 1.0,
			Remove:    1.0,
		},
	}
	// Initialize population with slight random variation around 1.0.
	rnd := rand.New(rand.NewSource(42))
	for i := range d.population {
		d.population[i] = WeightVector{
			Squash:    1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
			Splice:    1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
			Insert:    1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
			MutateArg: 1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
			Remove:    1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
		}
	}
	return d
}

// RecordResult records an operator execution result for DE optimization.
func (d *DEzzer) RecordResult(op string, covGainBits int) {
	idx := opNameToIndex(op)
	if idx < 0 {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Update sliding window.
	stats := &d.opStats[idx]
	wIdx := int(stats.Count % int64(dezzerWindowSize))
	stats.Window[wIdx] = OpResult{CovGainBits: covGainBits}
	stats.WindowIdx = (wIdx + 1) % dezzerWindowSize
	stats.Count++

	// Lazy evolution: evolve 1 generation every N records.
	d.totalRecords++
	if d.totalRecords%dezzerEvolveEvery == 0 {
		d.recalcFitness()
		d.evolveOneGeneration()
	}
}

// SetAIBaseWeights updates the AI base weights and resets the DE population.
func (d *DEzzer) SetAIBaseWeights(opts prog.MutateOpts) {
	d.mu.Lock()
	defer d.mu.Unlock()

	defaults := prog.DefaultMutateOpts
	d.aiBaseWeights = WeightVector{
		Squash:    safeDiv(float64(opts.SquashWeight), float64(defaults.SquashWeight)),
		Splice:    safeDiv(float64(opts.SpliceWeight), float64(defaults.SpliceWeight)),
		Insert:    safeDiv(float64(opts.InsertWeight), float64(defaults.InsertWeight)),
		MutateArg: safeDiv(float64(opts.MutateArgWeight), float64(defaults.MutateArgWeight)),
		Remove:    safeDiv(float64(opts.RemoveCallWeight), float64(defaults.RemoveCallWeight)),
	}

	// Reset population to explore around new base.
	rnd := rand.New(rand.NewSource(d.totalRecords))
	for i := range d.population {
		d.population[i] = WeightVector{
			Squash:    1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
			Splice:    1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
			Insert:    1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
			MutateArg: 1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
			Remove:    1.0 + (rnd.Float64()-0.5)*2*dezzerDeltaLimit,
		}
		d.fitness[i] = 0
	}
	d.bestIdx = 0
	d.generation = 0

	if d.logf != nil {
		d.logf(0, "PROBE: DEzzer AI base reset — Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f",
			d.aiBaseWeights.Squash, d.aiBaseWeights.Splice, d.aiBaseWeights.Insert,
			d.aiBaseWeights.MutateArg, d.aiBaseWeights.Remove)
	}
}

// GetCurrentWeights returns the final mutation weights: Default × AI Base × DE Delta.
func (d *DEzzer) GetCurrentWeights() prog.MutateOpts {
	d.mu.Lock()
	defer d.mu.Unlock()

	best := d.population[d.bestIdx]
	defaults := prog.DefaultMutateOpts

	return prog.MutateOpts{
		ExpectedIterations: defaults.ExpectedIterations,
		MutateArgCount:     defaults.MutateArgCount,
		SquashWeight:       maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash*best.Squash)),
		SpliceWeight:       maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice*best.Splice)),
		InsertWeight:       maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert*best.Insert)),
		MutateArgWeight:    maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg*best.MutateArg)),
		RemoveCallWeight:   maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove*best.Remove)),
	}
}

// Snapshot returns a copy of the DEzzer state for external consumption (AI prompts, dashboard).
type DEzzerSnapshot struct {
	Generation      int                `json:"generation"`
	BestFitness     float64            `json:"best_fitness"`
	TotalRecords    int64              `json:"total_records"`
	OpSuccessRates  map[string]float64 `json:"op_success_rates"`
	OpAvgCovGain    map[string]float64 `json:"op_avg_cov_gain"`
	AIBaseWeights   map[string]float64 `json:"ai_base_weights"`
	DEDelta         map[string]float64 `json:"de_delta"`
	FinalWeights    map[string]int     `json:"final_weights"`
}

func (d *DEzzer) Snapshot() DEzzerSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()

	snap := DEzzerSnapshot{
		Generation:     d.generation,
		BestFitness:    d.fitness[d.bestIdx],
		TotalRecords:   d.totalRecords,
		OpSuccessRates: make(map[string]float64),
		OpAvgCovGain:   make(map[string]float64),
		AIBaseWeights:  make(map[string]float64),
		DEDelta:        make(map[string]float64),
		FinalWeights:   make(map[string]int),
	}

	for i, name := range opNames {
		sr, avg := d.opSuccessRate(i)
		snap.OpSuccessRates[name] = sr
		snap.OpAvgCovGain[name] = avg
	}

	best := d.population[d.bestIdx]
	defaults := prog.DefaultMutateOpts

	snap.AIBaseWeights["squash"] = d.aiBaseWeights.Squash
	snap.AIBaseWeights["splice"] = d.aiBaseWeights.Splice
	snap.AIBaseWeights["insert"] = d.aiBaseWeights.Insert
	snap.AIBaseWeights["mutate_arg"] = d.aiBaseWeights.MutateArg
	snap.AIBaseWeights["remove"] = d.aiBaseWeights.Remove

	snap.DEDelta["squash"] = best.Squash
	snap.DEDelta["splice"] = best.Splice
	snap.DEDelta["insert"] = best.Insert
	snap.DEDelta["mutate_arg"] = best.MutateArg
	snap.DEDelta["remove"] = best.Remove

	snap.FinalWeights["squash"] = maxInt(1, int(float64(defaults.SquashWeight)*d.aiBaseWeights.Squash*best.Squash))
	snap.FinalWeights["splice"] = maxInt(1, int(float64(defaults.SpliceWeight)*d.aiBaseWeights.Splice*best.Splice))
	snap.FinalWeights["insert"] = maxInt(1, int(float64(defaults.InsertWeight)*d.aiBaseWeights.Insert*best.Insert))
	snap.FinalWeights["mutate_arg"] = maxInt(1, int(float64(defaults.MutateArgWeight)*d.aiBaseWeights.MutateArg*best.MutateArg))
	snap.FinalWeights["remove"] = maxInt(1, int(float64(defaults.RemoveCallWeight)*d.aiBaseWeights.Remove*best.Remove))

	return snap
}

// --- Internal DE methods (caller must hold d.mu) ---

// opSuccessRate returns (successRate, avgCovGain) from the sliding window.
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

// recalcFitness recalculates fitness for all population members.
// fitness = weighted sum of operator (successRate × avgCovGain).
func (d *DEzzer) recalcFitness() {
	var rates [dezzerNumOps]float64
	var gains [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		rates[i], gains[i] = d.opSuccessRate(i)
	}

	for p := range d.population {
		vec := d.population[p]
		deltas := [dezzerNumOps]float64{vec.Squash, vec.Splice, vec.Insert, vec.MutateArg, vec.Remove}

		fit := 0.0
		for i := 0; i < dezzerNumOps; i++ {
			// Fitness rewards operators proportional to delta × success × gain.
			fit += deltas[i] * rates[i] * (gains[i] + 1)
		}
		d.fitness[p] = fit
		if fit > d.fitness[d.bestIdx] {
			d.bestIdx = p
		}
	}
}

// evolveOneGeneration runs one DE/rand/1 evolution step.
func (d *DEzzer) evolveOneGeneration() {
	rnd := rand.New(rand.NewSource(d.totalRecords + int64(d.generation)))

	for i := range d.population {
		// Select 3 distinct random indices != i.
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

		// Create mutant vector: a + F*(b-c).
		trial := d.mutantVector(d.population[a], d.population[b], d.population[c], rnd)

		// Clamp to [1-deltaLimit, 1+deltaLimit].
		trial = d.clampVector(trial)

		// Evaluate trial (using current operator stats).
		trialFit := d.evalVector(trial)

		if trialFit >= d.fitness[i] {
			d.population[i] = trial
			d.fitness[i] = trialFit
			if trialFit > d.fitness[d.bestIdx] {
				d.bestIdx = i
			}
		}
	}

	d.generation++
	if d.logf != nil && d.generation%10 == 0 {
		best := d.population[d.bestIdx]
		d.logf(0, "PROBE: DEzzer gen=%d best_fitness=%.3f delta={Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f}",
			d.generation, d.fitness[d.bestIdx],
			best.Squash, best.Splice, best.Insert, best.MutateArg, best.Remove)
	}
}

func (d *DEzzer) mutantVector(a, b, c WeightVector, rnd *rand.Rand) WeightVector {
	trial := WeightVector{}
	// DE/rand/1 with binomial crossover.
	jrand := rnd.Intn(dezzerNumOps) // ensure at least one dimension from mutant
	aArr := vecToArr(a)
	bArr := vecToArr(b)
	cArr := vecToArr(c)
	curArr := vecToArr(d.population[0]) // current (will use in crossover)
	_ = curArr

	var result [dezzerNumOps]float64
	for j := 0; j < dezzerNumOps; j++ {
		if rnd.Float64() < dezzerCR || j == jrand {
			result[j] = aArr[j] + dezzerF*(bArr[j]-cArr[j])
		} else {
			result[j] = aArr[j] // keep from base vector
		}
	}
	trial.Squash = result[0]
	trial.Splice = result[1]
	trial.Insert = result[2]
	trial.MutateArg = result[3]
	trial.Remove = result[4]
	return trial
}

func (d *DEzzer) clampVector(v WeightVector) WeightVector {
	lo := 1.0 - dezzerDeltaLimit
	hi := 1.0 + dezzerDeltaLimit
	v.Squash = clampFloat(v.Squash, lo, hi)
	v.Splice = clampFloat(v.Splice, lo, hi)
	v.Insert = clampFloat(v.Insert, lo, hi)
	v.MutateArg = clampFloat(v.MutateArg, lo, hi)
	v.Remove = clampFloat(v.Remove, lo, hi)
	return v
}

func (d *DEzzer) evalVector(v WeightVector) float64 {
	var rates [dezzerNumOps]float64
	var gains [dezzerNumOps]float64
	for i := 0; i < dezzerNumOps; i++ {
		rates[i], gains[i] = d.opSuccessRate(i)
	}
	deltas := [dezzerNumOps]float64{v.Squash, v.Splice, v.Insert, v.MutateArg, v.Remove}
	fit := 0.0
	for i := 0; i < dezzerNumOps; i++ {
		fit += deltas[i] * rates[i] * (gains[i] + 1)
	}
	return fit
}

// StatusString returns a human-readable DEzzer status for logging.
func (d *DEzzer) StatusString() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	best := d.population[d.bestIdx]
	var parts []string
	for i, name := range opNames {
		sr, _ := d.opSuccessRate(i)
		parts = append(parts, fmt.Sprintf("%s=%.0f%%", name, sr*100))
	}
	return fmt.Sprintf("gen=%d fit=%.3f delta={Sq:%.2f Sp:%.2f In:%.2f MA:%.2f Rm:%.2f} rates=[%s]",
		d.generation, d.fitness[d.bestIdx],
		best.Squash, best.Splice, best.Insert, best.MutateArg, best.Remove,
		joinStrings(parts, ", "))
}

// --- Utility functions ---

func vecToArr(v WeightVector) [dezzerNumOps]float64 {
	return [dezzerNumOps]float64{v.Squash, v.Splice, v.Insert, v.MutateArg, v.Remove}
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

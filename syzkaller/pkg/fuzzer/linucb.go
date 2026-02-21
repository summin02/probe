// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 11j — LinUCB contextual bandit for delay pattern selection.
// Completely separate from DEzzer (no shared state).
//
// Arms (4 delay patterns):
//   0 = DelayNone      — no delay injection
//   1 = DelayRandom    — random delays on random calls
//   2 = DelayBetween   — uniform delay between all calls
//   3 = DelayAroundLocks — targeted delay near lock-related syscalls
//
// Feature vector (d=8):
//   [prog_len, lock_syscall_ratio, ebpf_contention, ebpf_concurrent,
//    sched_switches, coverage_delta, prog_category, is_focus]
package fuzzer

import (
	"math"
	"sync"
)

const (
	linucbArms     = 4  // number of delay pattern arms
	linucbDim      = 8  // feature vector dimension
	linucbAlphaMax = 0.5
	linucbAlphaMin = 0.1
	linucbAnnealN  = 100000 // observations until alpha reaches min
)

// LinUCB implements the LinUCB contextual bandit algorithm for delay pattern selection.
type LinUCB struct {
	mu       sync.Mutex
	A        [linucbArms][][]float64 // d x d matrix per arm
	Ainv     [linucbArms][][]float64 // A^{-1} per arm (Sherman-Morrison incremental)
	b        [linucbArms][]float64   // d x 1 per arm
	alpha    float64                 // exploration coefficient (annealing)
	totalObs int64                   // total observations for annealing
	armPicks [linucbArms]int64       // arm selection counts for diagnostics
	logf     func(level int, msg string, args ...any)
}

// NewLinUCB creates a new LinUCB contextual bandit with identity-initialized matrices.
func NewLinUCB() *LinUCB {
	l := &LinUCB{
		alpha: linucbAlphaMax,
	}
	for a := 0; a < linucbArms; a++ {
		l.A[a] = identityMatrix(linucbDim)
		l.Ainv[a] = identityMatrix(linucbDim)
		l.b[a] = make([]float64, linucbDim)
	}
	return l
}

// SelectArm selects the best delay pattern arm given context features.
// UCB: p_a = theta_a^T x + alpha * sqrt(x^T A_a^{-1} x), return argmax.
func (l *LinUCB) SelectArm(features []float64) int {
	if len(features) != linucbDim {
		return 0 // default: no delay
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Copy features to fixed-size array to avoid heap allocations.
	var featArr [linucbDim]float64
	copy(featArr[:], features)

	// Forced exploration: ensure each arm is tried at least 10 times before UCB takes over.
	// Without this, global alpha annealing (0.5→0.1 after 1000 obs) combined with strict
	// tie-breaking causes arms 2 and 3 to never be selected after arm 0/1 accumulate data.
	for a := 0; a < linucbArms; a++ {
		if l.armPicks[a] < 10 {
			return a
		}
	}

	bestArm := 0
	bestScore := math.Inf(-1)

	for a := 0; a < linucbArms; a++ {
		// theta_a = A_a^{-1} * b_a
		theta := matVecMul(l.Ainv[a], l.b[a])
		// exploitation: theta_a^T * x
		exploit := dotProductArr(theta, featArr)
		// exploration: alpha * sqrt(x^T * A_a^{-1} * x)
		Ainvx := matVecMul(l.Ainv[a], features)
		explore := l.alpha * math.Sqrt(math.Max(0, dotProduct(features, Ainvx)))
		score := exploit + explore
		if score > bestScore {
			bestScore = score
			bestArm = a
		}
	}

	return bestArm
}

// Update updates the LinUCB model for the chosen arm with observed reward.
// Uses Sherman-Morrison incremental inverse update:
//   A_a^{-1} = A_a^{-1} - (A_a^{-1} x x^T A_a^{-1}) / (1 + x^T A_a^{-1} x)
func (l *LinUCB) Update(arm int, features []float64, reward float64) {
	if arm < 0 || arm >= linucbArms || len(features) != linucbDim {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// A_a = A_a + x * x^T (conceptual, but we update Ainv directly)
	// b_a = b_a + reward * x
	for i := 0; i < linucbDim; i++ {
		l.b[arm][i] += reward * features[i]
	}

	// Sherman-Morrison update for A_a^{-1}:
	// Ainv_new = Ainv - (Ainv * x * x^T * Ainv) / (1 + x^T * Ainv * x)
	Ainv := l.Ainv[arm]
	AinvxArr := matVecMul(Ainv, features)
	denom := 1.0 + dotProduct(features, AinvxArr)
	if denom < 1e-10 {
		denom = 1e-10
	}

	// Outer product: Ainvx * Ainvx^T / denom, subtracted from Ainv.
	for i := 0; i < linucbDim; i++ {
		for j := 0; j < linucbDim; j++ {
			Ainv[i][j] -= (AinvxArr[i] * AinvxArr[j]) / denom
		}
	}

	// Anneal alpha: alpha = max(0.1, 0.5 * (1 - totalObs/1000))
	l.totalObs++
	l.armPicks[arm]++
	ratio := float64(l.totalObs) / float64(linucbAnnealN)
	if ratio > 1.0 {
		ratio = 1.0
	}
	l.alpha = math.Max(linucbAlphaMin, linucbAlphaMax*(1.0-ratio))

	// Diagnostic log every 1000 observations.
	if l.logf != nil && l.totalObs%1000 == 0 {
		l.logf(0, "PROBE: LinUCB status: obs=%d, alpha=%.3f, arms=[None:%d Rand:%d Between:%d Locks:%d], reward=%.3f",
			l.totalObs, l.alpha,
			l.armPicks[0], l.armPicks[1], l.armPicks[2], l.armPicks[3],
			reward)
	}
}

// SetAlpha overrides the LinUCB exploration parameter. Phase 12 C1: BO-tunable.
func (l *LinUCB) SetAlpha(alpha float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.alpha = math.Max(linucbAlphaMin, math.Min(alpha, 3.0))
}

// --- Linear algebra helpers ---

func identityMatrix(n int) [][]float64 {
	m := make([][]float64, n)
	for i := 0; i < n; i++ {
		m[i] = make([]float64, n)
		m[i][i] = 1.0
	}
	return m
}

func matVecMul(mat [][]float64, vec []float64) [linucbDim]float64 {
	var result [linucbDim]float64
	for i := 0; i < linucbDim; i++ {
		s := 0.0
		for j := 0; j < linucbDim; j++ {
			s += mat[i][j] * vec[j]
		}
		result[i] = s
	}
	return result
}

func dotProduct(a []float64, b [linucbDim]float64) float64 {
	s := 0.0
	for i := 0; i < linucbDim; i++ {
		s += a[i] * b[i]
	}
	return s
}

func dotProductArr(a, b [linucbDim]float64) float64 {
	s := 0.0
	for i := 0; i < linucbDim; i++ {
		s += a[i] * b[i]
	}
	return s
}

// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE Phase 9e: Anamnesis-style exploit assessment.
// Evaluates eBPF anomaly signals to produce a composite exploitability score.
// Heuristic baseline is always available; LLM-based deep assessment is
// activated when an API endpoint is configured (future integration).

package fuzzer

import (
	"fmt"

	"github.com/google/syzkaller/pkg/flatrpc"
)

// ExploitClass categorizes the type of exploit primitive detected.
type ExploitClass int

const (
	ExploitNone       ExploitClass = iota
	ExploitUAF                     // slab use-after-free
	ExploitDoubleFree              // double-free
	ExploitCrossCache              // cross-cache reallocation
	ExploitWriteFreed              // write to freed object
	ExploitPrivEsc                 // privilege escalation
	ExploitPageUAF                 // page-level UAF / dirty pagetable
	ExploitFDReuse                 // file descriptor reuse-after-close
)

// AnamnesisResult holds the assessment output.
type AnamnesisResult struct {
	Score        int          // 0–100 composite exploitability score
	Class        ExploitClass // primary exploit class
	Summary      string       // human-readable one-liner
	FocusTier    int          // 1 = highest priority, 2 = medium, 3 = low
	ShouldFocus  bool         // whether this warrants a Focus candidate
}

// AnamnesisAssessor evaluates eBPF metrics for exploit potential.
type AnamnesisAssessor struct {
	logf func(level int, msg string, args ...interface{})
}

// NewAnamnesisAssessor creates a new assessor instance.
func NewAnamnesisAssessor(logf func(int, string, ...interface{})) *AnamnesisAssessor {
	return &AnamnesisAssessor{logf: logf}
}

// Assess evaluates a program's eBPF metrics and returns an exploitability assessment.
// This is the heuristic baseline — it combines multiple eBPF signals into a
// composite score that captures exploit potential better than any single signal.
func (a *AnamnesisAssessor) Assess(info *flatrpc.ProgInfoRawT) *AnamnesisResult {
	if info == nil {
		return &AnamnesisResult{Score: 0, Class: ExploitNone}
	}

	result := &AnamnesisResult{}
	var signals []scoredSignal

	// Privilege escalation — highest severity
	if info.EbpfPrivEscCount > 0 {
		signals = append(signals, scoredSignal{
			score: 95,
			class: ExploitPrivEsc,
			desc:  fmt.Sprintf("priv-esc: %d uid transitions", info.EbpfPrivEscCount),
		})
	}

	// Write to freed object — strong exploitability
	if info.EbpfWriteToFreedCount > 0 {
		s := 80
		if info.EbpfUafScore >= 60 {
			s = 90 // combined with UAF = very strong
		}
		signals = append(signals, scoredSignal{
			score: s,
			class: ExploitWriteFreed,
			desc:  fmt.Sprintf("write-to-freed: %d writes (uaf_score=%d)", info.EbpfWriteToFreedCount, info.EbpfUafScore),
		})
	}

	// Cross-cache reallocation — strong primitive
	if info.EbpfCrossCacheCount > 0 {
		s := 75
		if info.EbpfCrossCacheCount > 3 {
			s = 85
		}
		signals = append(signals, scoredSignal{
			score: s,
			class: ExploitCrossCache,
			desc:  fmt.Sprintf("cross-cache: %d reallocs", info.EbpfCrossCacheCount),
		})
	}

	// Slab UAF — reuse alone is still a signal; rapid reuse is stronger.
	if info.EbpfReuseCount > 0 {
		s := 60
		if info.EbpfRapidReuseCount > 0 {
			s = 70
		}
		if info.EbpfRapidReuseCount > 3 {
			s = 80
		}
		signals = append(signals, scoredSignal{
			score: s,
			class: ExploitUAF,
			desc:  fmt.Sprintf("slab-uaf: %d reuses (%d rapid)", info.EbpfReuseCount, info.EbpfRapidReuseCount),
		})
	}

	// Double-free
	if info.EbpfDoubleFreeCount > 0 {
		signals = append(signals, scoredSignal{
			score: 65,
			class: ExploitDoubleFree,
			desc:  fmt.Sprintf("double-free: %d events", info.EbpfDoubleFreeCount),
		})
	}

	// Page-level UAF
	if info.EbpfPageUafScore >= 60 {
		s := 60
		if info.EbpfPageReuseCount > 5 {
			s = 75
		}
		signals = append(signals, scoredSignal{
			score: s,
			class: ExploitPageUAF,
			desc:  fmt.Sprintf("page-uaf: score=%d reuse=%d", info.EbpfPageUafScore, info.EbpfPageReuseCount),
		})
	}

	// FD reuse
	if info.EbpfFdReuseScore >= 60 {
		signals = append(signals, scoredSignal{
			score: 65,
			class: ExploitFDReuse,
			desc:  fmt.Sprintf("fd-reuse: score=%d count=%d", info.EbpfFdReuseScore, info.EbpfFdReuseCount),
		})
	}

	if len(signals) == 0 {
		return &AnamnesisResult{Score: 0, Class: ExploitNone}
	}

	// Composite score: take the highest signal, then add diversity bonus
	// for multiple independent exploit primitives.
	best := signals[0]
	for _, s := range signals[1:] {
		if s.score > best.score {
			best = s
		}
	}
	result.Score = best.score
	result.Class = best.class
	result.Summary = best.desc

	// Diversity bonus: multiple independent primitives = more exploitable
	if len(signals) >= 3 {
		result.Score += 10
	} else if len(signals) >= 2 {
		result.Score += 5
	}

	// Context-sensitive coverage bonus: novel call paths = higher value
	if info.EbpfContextStacks > 5 {
		result.Score += 5
	}

	// Clamp
	if result.Score > 100 {
		result.Score = 100
	}

	// Determine Focus tier and whether to trigger
	switch {
	case result.Score >= 80:
		result.FocusTier = 1
		result.ShouldFocus = true
	case result.Score >= 60:
		result.FocusTier = 2
		result.ShouldFocus = true
	case result.Score >= 40:
		result.FocusTier = 3
		result.ShouldFocus = false // interesting but not Focus-worthy
	default:
		result.FocusTier = 3
		result.ShouldFocus = false
	}

	return result
}

type scoredSignal struct {
	score int
	class ExploitClass
	desc  string
}

// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aitriage

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const strategySystemPrompt = `You are an expert kernel fuzzing strategist. You analyze fuzzing progress data
and recommend actions to maximize vulnerability discovery.

Your recommendations must be in these categories:
1. SYSCALL WEIGHTS: Which syscalls to prioritize or deprioritize
2. SEED HINTS: Combinations of syscalls that should appear together in test programs
3. MUTATION STRATEGY: How to adjust mutation weights
4. FOCUS TARGETS: Which crashes deserve intensive exploration

CRITICAL RULES:
- For syscall_weights and seed_hints, you MUST ONLY use syscall names from the
  "Available Syscalls" list provided below. Do NOT invent syscall names.
  If no exact match exists, skip that recommendation.
- SEED HINTS: Suggest 2-5 syscall names that should appear together in a test program.
  The fuzzer will find existing corpus programs matching these syscalls.
  Use ONLY names from the Available Syscalls list. Do NOT write program code.
- Weight adjustments are multipliers (1.0 = no change, 2.0 = double priority)
- Be specific and actionable. Vague suggestions are useless.
- Limit to at most 10 syscall weight adjustments, 5 seed hints, and 3 focus targets.
- FOCUS TARGETS: Prioritize crashes with highest exploitability scores.
  A crash with score=40 (UAF Write) is FAR more valuable to explore than score=15 (WARNING).
  Only include crashes with score >= 25 as focus targets.

You MUST respond with ONLY a valid JSON object matching this schema:
{
  "syscall_weights": [{"name": "syscall_name", "weight": 1.5, "reason": "why"}],
  "seed_hints": [{"syscalls": ["syscall1", "syscall2", "syscall3"], "target": "goal", "reason": "why"}],
  "mutation_hints": {
    "splice_weight": 1.0,
    "insert_weight": 1.0,
    "mutate_arg_weight": 1.0,
    "remove_weight": 1.0,
    "reason": "explanation"
  },
  "focus_targets": [{"crash_title": "exact crash title", "reason": "why", "priority": 1}],
  "summary": "2-3 sentence strategy summary"
}`

func buildStrategyPrompt(snapshot *FuzzingSnapshot) (string, string) {
	var sb strings.Builder

	sb.WriteString("## Current Fuzzing State\n\n")
	sb.WriteString(fmt.Sprintf("- Total Signal (coverage): %d\n", snapshot.TotalSignal))
	sb.WriteString(fmt.Sprintf("- Signal Growth Rate (last hour): %.1f%%\n", snapshot.SignalGrowthRate))
	sb.WriteString(fmt.Sprintf("- Total Executions: %d\n", snapshot.TotalExecs))
	sb.WriteString(fmt.Sprintf("- Executions/sec: %.0f\n", snapshot.ExecsPerSec))
	sb.WriteString(fmt.Sprintf("- Corpus Size: %d\n", snapshot.CorpusSize))
	sb.WriteString(fmt.Sprintf("- New Crashes (this hour): %d\n", snapshot.NewCrashesCount))
	sb.WriteString("\n")

	// Syscall coverage distribution (top 30).
	if len(snapshot.SyscallCoverage) > 0 {
		sb.WriteString("### Syscall Coverage (top 30)\n")
		type kv struct {
			Name  string
			Count int
		}
		var sorted []kv
		for name, count := range snapshot.SyscallCoverage {
			sorted = append(sorted, kv{name, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Count > sorted[j].Count
		})
		limit := 30
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for _, kv := range sorted[:limit] {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", kv.Name, kv.Count))
		}
		sb.WriteString("\n")

		// Provide full list of available syscall names for weight/seed recommendations.
		sb.WriteString("### Available Syscalls (use ONLY these names for syscall_weights and seed_hints)\n")
		// Sort alphabetically for clarity.
		allNames := make([]string, 0, len(snapshot.SyscallCoverage))
		for name := range snapshot.SyscallCoverage {
			allNames = append(allNames, name)
		}
		sort.Strings(allNames)
		sb.WriteString(strings.Join(allNames, ", "))
		sb.WriteString("\n\n")
	}

	// Crash summaries (sorted by score descending — highest exploitability first).
	if len(snapshot.CrashSummaries) > 0 {
		sorted := make([]CrashSummary, len(snapshot.CrashSummaries))
		copy(sorted, snapshot.CrashSummaries)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Score > sorted[j].Score
		})
		sb.WriteString("### Crash Summary (sorted by exploitability score, highest first)\n")
		for _, c := range sorted {
			scoreStr := "-"
			if c.Score > 0 {
				scoreStr = fmt.Sprintf("%d", c.Score)
			}
			sb.WriteString(fmt.Sprintf("  [score=%s] %s (type=%s, variants=%d)\n",
				scoreStr, c.Title, c.VulnType, c.Variants))
		}
		sb.WriteString("\n")
	}

	// PROBE: Phase 6 — DEzzer operator performance data (TS+DE hybrid).
	if snapshot.DEzzerStatus != nil {
		ds := snapshot.DEzzerStatus
		sb.WriteString("### Mutation Operator Performance (DEzzer TS+DE Hybrid)\n")
		sb.WriteString(fmt.Sprintf("  Generation: %d", ds.Generation))
		if ds.Saturated {
			sb.WriteString(" [SATURATED]")
		}
		if !ds.WarmupDone {
			sb.WriteString(" [WARMING UP]")
		}
		sb.WriteString("\n  Operator success rates: ")
		for _, name := range []string{"splice", "insert", "mutate_arg", "squash", "remove"} {
			if rate, ok := ds.OpSuccessRates[name]; ok {
				sb.WriteString(fmt.Sprintf("%s=%.1f%% ", name, rate*100))
			}
		}
		// Show TS delta (primary, ±20%) if available.
		if len(ds.TSDelta) > 0 {
			sb.WriteString("\n  TS delta (primary, per-operator Bayesian): ")
			for _, name := range []string{"splice", "insert", "mutate_arg", "squash", "remove"} {
				if delta, ok := ds.TSDelta[name]; ok {
					pct := (delta - 1.0) * 100
					sb.WriteString(fmt.Sprintf("%s=%+.0f%% ", name, pct))
				}
			}
		}
		// Show DE correction (secondary, ±5%) if available.
		if len(ds.DECorrection) > 0 {
			sb.WriteString("\n  DE correction (secondary, synergy search): ")
			for _, name := range []string{"splice", "insert", "mutate_arg", "squash", "remove"} {
				if corr, ok := ds.DECorrection[name]; ok {
					pct := (corr - 1.0) * 100
					sb.WriteString(fmt.Sprintf("%s=%+.1f%% ", name, pct))
				}
			}
		}
		sb.WriteString("\n  Combined delta from AI base: ")
		for _, name := range []string{"splice", "insert", "mutate_arg", "squash", "remove"} {
			if delta, ok := ds.DEDelta[name]; ok {
				pct := (delta - 1.0) * 100
				sb.WriteString(fmt.Sprintf("%s=%+.0f%% ", name, pct))
			}
		}
		sb.WriteString("\n  Final weights: ")
		for _, name := range []string{"splice", "insert", "mutate_arg", "squash", "remove"} {
			if w, ok := ds.FinalWeights[name]; ok {
				sb.WriteString(fmt.Sprintf("%s=%d ", name, w))
			}
		}
		// Phase 8b: Top pair TS success rates (if available).
		if len(ds.PairSuccessRates) > 0 {
			sb.WriteString("\n  Op-pair success rates (top 5): ")
			type pairKV struct {
				Key  string
				Rate float64
			}
			var pairs []pairKV
			for k, v := range ds.PairSuccessRates {
				pairs = append(pairs, pairKV{k, v})
			}
			sort.Slice(pairs, func(i, j int) bool { return pairs[i].Rate > pairs[j].Rate })
			shown := 5
			if len(pairs) < shown {
				shown = len(pairs)
			}
			for _, p := range pairs[:shown] {
				sb.WriteString(fmt.Sprintf("%s=%.1f%% ", p.Key, p.Rate*100))
			}
		}
		// Phase 8e: Cluster distribution.
		if len(ds.ClusterCounts) > 0 {
			sb.WriteString("\n  Subsystem clusters: ")
			for _, name := range []string{"fs", "net", "mm", "ipc", "device", "other"} {
				if c, ok := ds.ClusterCounts[name]; ok {
					sb.WriteString(fmt.Sprintf("%s=%d ", name, c))
				}
			}
		}
		// Phase 8c: Multi-objective status.
		if ds.CurrentObjective != "" {
			sb.WriteString(fmt.Sprintf("\n  Current objective: %s", ds.CurrentObjective))
			if len(ds.ObjectiveCounts) > 0 {
				sb.WriteString(" (counts: ")
				for _, name := range []string{"coverage", "memory_safety", "priv_esc"} {
					if c, ok := ds.ObjectiveCounts[name]; ok {
						sb.WriteString(fmt.Sprintf("%s=%d ", name, c))
					}
				}
				sb.WriteString(")")
			}
		}
		sb.WriteString("\n\n")
	}

	// PROBE: Phase 6 — Focus job results feedback.
	if len(snapshot.FocusResults) > 0 {
		sb.WriteString("### Focus Job Results (last hour)\n")
		results := snapshot.FocusResults
		if len(results) <= 5 {
			// Show all results in detail.
			for _, r := range results {
				exitStr := "completed"
				if r.EarlyExit {
					exitStr = "early-exit"
				}
				sb.WriteString(fmt.Sprintf("  - \"%s\" (tier=%d): iters=%d, new_cov=%d, cov/exec=%.4f, %s\n",
					r.Title, r.Tier, r.TotalIters, r.NewCoverage, r.CoveragePerExec, exitStr))
			}
		} else {
			// Show recent 3 in detail + summary of rest.
			recent := results[len(results)-3:]
			older := results[:len(results)-3]
			for _, r := range recent {
				exitStr := "completed"
				if r.EarlyExit {
					exitStr = "early-exit"
				}
				sb.WriteString(fmt.Sprintf("  - \"%s\" (tier=%d): iters=%d, new_cov=%d, cov/exec=%.4f, %s\n",
					r.Title, r.Tier, r.TotalIters, r.NewCoverage, r.CoveragePerExec, exitStr))
			}
			// Aggregate summary of older results.
			totalCov := 0
			earlyExitCount := 0
			var totalCovPerExec float64
			bestTitle, worstTitle := "", ""
			bestCPE, worstCPE := -1.0, 999999.0
			for _, r := range older {
				totalCov += r.NewCoverage
				totalCovPerExec += r.CoveragePerExec
				if r.EarlyExit {
					earlyExitCount++
				}
				if r.CoveragePerExec > bestCPE {
					bestCPE = r.CoveragePerExec
					bestTitle = r.Title
				}
				if r.CoveragePerExec < worstCPE {
					worstCPE = r.CoveragePerExec
					worstTitle = r.Title
				}
			}
			avgCPE := totalCovPerExec / float64(len(older))
			sb.WriteString(fmt.Sprintf("  Summary of %d older jobs: avg_cov/exec=%.4f, early_exit=%d/%d\n",
				len(older), avgCPE, earlyExitCount, len(older)))
			if bestTitle != "" {
				sb.WriteString(fmt.Sprintf("    Best: \"%s\" (%.4f), Worst: \"%s\" (%.4f)\n",
					bestTitle, bestCPE, worstTitle, worstCPE))
			}
		}
		sb.WriteString("\n")
	}

	// PROBE: Phase 7b' — Slab-pair allocation patterns.
	if len(snapshot.SlabSites) > 0 {
		sb.WriteString("### Slab Allocation Patterns (top call sites from eBPF)\n")
		sb.WriteString("Note: call_site addresses change across reboots (KASLR). Focus on alloc/free RATIOS.\n")
		for _, s := range snapshot.SlabSites {
			label := "balanced"
			if s.FreeCount == 0 && s.AllocCount > 0 {
				label = "allocator-only (leak candidate)"
			} else if s.AllocCount == 0 && s.FreeCount > 0 {
				label = "deallocator-only (UAF source candidate)"
			} else if s.FreeCount > 0 && s.AllocCount > 0 {
				ratio := float64(s.FreeCount) / float64(s.AllocCount)
				if ratio > 1.2 {
					label = "over-freeing (double-free candidate)"
				} else if ratio < 0.5 {
					label = "under-freeing (leak candidate)"
				}
			}
			sb.WriteString(fmt.Sprintf("  Site 0x%x: %d allocs, %d frees — %s\n",
				s.CallSite, s.AllocCount, s.FreeCount, label))
		}
		sb.WriteString("\n")
	}

	// Coverage by file (top 20).
	if len(snapshot.CoverageByFile) > 0 {
		sb.WriteString("### Coverage by File (top 20)\n")
		type kv struct {
			File  string
			Count int
		}
		var sorted []kv
		for file, count := range snapshot.CoverageByFile {
			sorted = append(sorted, kv{file, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Count > sorted[j].Count
		})
		limit := 20
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for _, kv := range sorted[:limit] {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", kv.File, kv.Count))
		}
		sb.WriteString("\n")
	}

	return strategySystemPrompt, sb.String()
}

func parseStrategyResponse(content string) (*StrategyResult, error) {
	content = strings.TrimSpace(content)
	// Strip markdown code fences.
	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		if len(lines) > 2 {
			lines = lines[1 : len(lines)-1]
			if strings.TrimSpace(lines[len(lines)-1]) == "```" {
				lines = lines[:len(lines)-1]
			}
		}
		content = strings.Join(lines, "\n")
	}

	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		content = content[start : end+1]
	}

	var result StrategyResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse strategy JSON: %w\nraw: %s", err, content[:min(len(content), 500)])
	}

	// Clamp weights to [0.1, 10.0].
	for i := range result.SyscallWeights {
		w := result.SyscallWeights[i].Weight
		if w < 0.1 {
			result.SyscallWeights[i].Weight = 0.1
		}
		if w > 10.0 {
			result.SyscallWeights[i].Weight = 10.0
		}
	}
	// Clamp mutation hints.
	clampMut := func(v float64) float64 {
		if v < 0.1 {
			return 0.1
		}
		if v > 10.0 {
			return 10.0
		}
		return v
	}
	result.MutationHints.SpliceWeight = clampMut(result.MutationHints.SpliceWeight)
	result.MutationHints.InsertWeight = clampMut(result.MutationHints.InsertWeight)
	result.MutationHints.MutateArgWeight = clampMut(result.MutationHints.MutateArgWeight)
	result.MutationHints.RemoveWeight = clampMut(result.MutationHints.RemoveWeight)

	return &result, nil
}

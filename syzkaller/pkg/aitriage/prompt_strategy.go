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

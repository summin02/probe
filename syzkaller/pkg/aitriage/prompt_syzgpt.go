// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 7a — SyzGPT prompt construction for generating seed programs
// targeting low-frequency syscalls (LFS).
package aitriage

import (
	"encoding/json"
	"fmt"
	"strings"
)

const syzGPTSystemPrompt = `You are an expert Linux kernel fuzzer specializing in syzkaller program generation.
Your task: generate a valid syzkaller test program that exercises a specific low-frequency syscall.

SYZKALLER PROGRAM FORMAT:
- Each line is a syscall: name(arg1, arg2, ...) or r0 = name(arg1, ...)
- Resources (file descriptors, etc.) are captured with rN = syscall(...)
- Use r0, r1, r2, ... for resources returned by syscalls
- Pointers use &(0x7f0000000000)={...} or &(0x7f0000000000)="hex"
- Auto values use 0x0 or specific constants
- String arguments: &(0x7f0000000000)="text\x00"
- Length arguments are usually the size in bytes

CRITICAL RULES:
1. The program MUST include the target syscall specified below.
2. Include dependency syscalls (resource producers) BEFORE the target syscall.
3. Keep programs short (3-8 syscalls). Quality over quantity.
4. Use ONLY syscall names from the provided available list.
5. Use realistic argument values. Do not use random garbage.
6. Return ONLY the program text, NO explanations, NO markdown fences.

EXAMPLE OUTPUT (for target "connect$inet"):
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90, @loopback}, 0x10)
sendto$inet(r0, &(0x7f0000000040)="hello", 0x5, 0x0, 0x0, 0x0)
close(r0)`

// LFSTarget describes a low-frequency syscall with its dependency context.
type LFSTarget struct {
	// Name is the full syscall name (e.g., "socket$inet_tcp").
	Name string `json:"name"`
	// CallName is the base syscall name (e.g., "socket").
	CallName string `json:"call_name"`
	// Args describes the syscall argument types.
	Args []string `json:"args,omitempty"`
	// ReturnType describes what resource this syscall produces, if any.
	ReturnType string `json:"return_type,omitempty"`
	// InputResources lists resource types this syscall needs (with producers).
	InputResources []LFSResource `json:"input_resources,omitempty"`
	// CorpusExamples are serialized corpus programs containing related syscalls.
	CorpusExamples []string `json:"corpus_examples,omitempty"`
	// CoverageCount is the current coverage count for this syscall (0 = never covered).
	CoverageCount int `json:"coverage_count"`
}

// LFSResource describes a resource dependency for an LFS target.
type LFSResource struct {
	// ResourceName is the resource type (e.g., "fd", "fd[sock]").
	ResourceName string `json:"resource_name"`
	// Producers lists syscall names that can create this resource.
	Producers []string `json:"producers,omitempty"`
}

func buildSyzGPTPrompt(target LFSTarget, availableSyscalls []string) (string, string) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## Target Syscall: %s\n\n", target.Name))

	if target.CallName != target.Name {
		sb.WriteString(fmt.Sprintf("Base syscall: %s\n", target.CallName))
	}
	if target.CoverageCount == 0 {
		sb.WriteString("Coverage: NEVER COVERED — this is a high-priority target.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Coverage: %d (low frequency, needs more exploration)\n", target.CoverageCount))
	}
	sb.WriteString("\n")

	// Argument types.
	if len(target.Args) > 0 {
		sb.WriteString("### Argument Types\n")
		for i, arg := range target.Args {
			sb.WriteString(fmt.Sprintf("  arg%d: %s\n", i, arg))
		}
		sb.WriteString("\n")
	}

	// Return type.
	if target.ReturnType != "" {
		sb.WriteString(fmt.Sprintf("### Return Type\n  %s\n\n", target.ReturnType))
	}

	// Dependency chain.
	if len(target.InputResources) > 0 {
		sb.WriteString("### Required Resources (must create BEFORE calling target)\n")
		for _, res := range target.InputResources {
			sb.WriteString(fmt.Sprintf("  - %s", res.ResourceName))
			if len(res.Producers) > 0 {
				limit := 5
				if len(res.Producers) < limit {
					limit = len(res.Producers)
				}
				sb.WriteString(fmt.Sprintf(" ← created by: %s", strings.Join(res.Producers[:limit], ", ")))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Corpus examples.
	if len(target.CorpusExamples) > 0 {
		sb.WriteString("### Example Programs (from corpus, for reference)\n")
		for i, ex := range target.CorpusExamples {
			sb.WriteString(fmt.Sprintf("--- Example %d ---\n%s\n", i+1, ex))
		}
		sb.WriteString("\n")
	}

	// Available syscalls (truncated to save tokens).
	if len(availableSyscalls) > 0 {
		sb.WriteString("### Available Syscalls (use ONLY these)\n")
		// Limit to most relevant: same CallName family + related resources.
		sb.WriteString(strings.Join(availableSyscalls, ", "))
		sb.WriteString("\n\n")
	}

	sb.WriteString("Generate a valid syzkaller program that exercises the target syscall. Include necessary setup calls.\n")

	return syzGPTSystemPrompt, sb.String()
}

// SyzGPTResult holds the result of a SyzGPT seed generation attempt.
type SyzGPTResult struct {
	TargetSyscall string `json:"target_syscall"`
	ProgramText   string `json:"program_text"`
	Valid         bool   `json:"valid"`
	Injected      bool   `json:"injected"`
	Error         string `json:"error,omitempty"`
}

func parseSyzGPTResponse(content string) (string, error) {
	content = strings.TrimSpace(content)
	// Strip markdown code fences if present.
	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		if len(lines) > 2 {
			lines = lines[1:]
			for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "```" {
				lines = lines[:len(lines)-1]
			}
		}
		content = strings.Join(lines, "\n")
	}

	// Strip any leading JSON wrapper if the model wrapped it.
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "{") {
		// Try to extract "program" field from JSON.
		var wrapper struct {
			Program string `json:"program"`
		}
		if err := json.Unmarshal([]byte(content), &wrapper); err == nil && wrapper.Program != "" {
			content = wrapper.Program
		}
	}

	content = strings.TrimSpace(content)
	if content == "" {
		return "", fmt.Errorf("empty response from LLM")
	}

	// Basic validation: should contain at least one syscall-like line.
	lines := strings.Split(content, "\n")
	validLines := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.Contains(line, "(") && strings.Contains(line, ")") {
			validLines++
		}
	}
	if validLines == 0 {
		return "", fmt.Errorf("response contains no valid syscall lines")
	}

	return content, nil
}

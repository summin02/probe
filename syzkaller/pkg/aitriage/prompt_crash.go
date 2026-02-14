// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aitriage

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParsedReport extracts key fields from a KASAN/kernel crash report.
type ParsedReport struct {
	BugType     string
	AccessType  string
	AccessSize  int
	SlabCache   string
	ObjectSize  int
	OffsetInObj int
	AllocStack  string
	FreeStack   string
	AccessStack string
	GuiltyFile  string
}

var (
	reAccessType = regexp.MustCompile(`(?i)(Read|Write) of size (\d+)`)
	reSlabCache  = regexp.MustCompile(`(?i)(?:in cache|belongs to the cache) (\S+)`)
	reObjSize    = regexp.MustCompile(`(?i)(?:object size[: ]+|of size )(\d+)`)
	reOffset     = regexp.MustCompile(`(?i)offset (\d+)`)
	reBugType    = regexp.MustCompile(`(?i)BUG: KASAN: (\S+)`)
	reGuiltyFile = regexp.MustCompile(`(?m)^\s*(\S+\.\w+:\d+)`)
)

func parseKASANReport(text string) *ParsedReport {
	r := &ParsedReport{}

	if m := reBugType.FindStringSubmatch(text); len(m) > 1 {
		r.BugType = m[1]
	}
	if m := reAccessType.FindStringSubmatch(text); len(m) > 2 {
		r.AccessType = m[1]
		r.AccessSize, _ = strconv.Atoi(m[2])
	}
	if m := reSlabCache.FindStringSubmatch(text); len(m) > 1 {
		r.SlabCache = m[1]
	}
	if m := reObjSize.FindStringSubmatch(text); len(m) > 1 {
		r.ObjectSize, _ = strconv.Atoi(m[1])
	}
	if m := reOffset.FindStringSubmatch(text); len(m) > 1 {
		r.OffsetInObj, _ = strconv.Atoi(m[1])
	}

	// Extract stack sections.
	r.AllocStack = extractStack(text, "Allocated by", 5)
	r.FreeStack = extractStack(text, "Freed by", 5)
	r.AccessStack = extractStack(text, "BUG: KASAN", 5)

	if m := reGuiltyFile.FindStringSubmatch(text); len(m) > 1 {
		r.GuiltyFile = m[1]
	}

	return r
}

func extractStack(text, marker string, maxFrames int) string {
	idx := strings.Index(text, marker)
	if idx < 0 {
		return ""
	}
	lines := strings.Split(text[idx:], "\n")
	var frames []string
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		// Skip KASAN internal frames.
		if strings.Contains(line, "kasan_") || strings.Contains(line, "kmem_cache_") ||
			strings.Contains(line, "__asan_") || strings.Contains(line, "mm/kasan") {
			continue
		}
		frames = append(frames, line)
		if len(frames) >= maxFrames {
			break
		}
	}
	return strings.Join(frames, "\n")
}

const crashSystemPrompt = `You are an expert Linux kernel vulnerability researcher specializing in memory
corruption exploitation. You have deep knowledge of:
- SLUB/SLAB allocator internals and kmalloc bucket sizes
- KASAN report formats and their implications
- Heap spray techniques: msg_msg, pipe_buffer, sk_buff, add_key, setxattr
- Cross-cache attacks and cache isolation
- Privilege escalation: modprobe_path, cred overwrite, KASLR bypass

Evaluate the exploitability of the given crash based on these 5 criteria (weighted sum = 100):
1. Slab Cache Type (20%): generic kmalloc-N vs dedicated cache
2. Primitive Type (25%): write UAF > free > read
3. Timing & Controllability (20%): deterministic > race_extensible > race_tight
4. Object Overlap Feasibility (15%): spray possibility, controllable data objects
5. Privilege Escalation Path (20%): cred overwrite, modprobe_path

IMPORTANT: Be conservative. Only rate exploitability high with concrete evidence.

SCORING GUIDELINES for non-memory-corruption bugs:
- Diagnostic/info-only WARNINGs (e.g. WARN_ON sanity checks): score 5
- Logic bugs (assertion failures, invalid state transitions): score 10
- WARNINGs with potential state corruption (e.g. refcount, locking issues): score 15-20
- Memory-corruption bugs (UAF, OOB, double-free): use the 5-criteria weighted scoring above
- UAF Write primitives should score HIGHER than UAF Read (Write enables overwrite, Read is info-leak only)

You MUST respond with ONLY a valid JSON object matching this schema:
{
  "score": <0-100>,
  "confidence": "<high|medium|low>",
  "exploit_class": "<privilege_escalation|info_leak|dos|code_exec>",
  "reasoning": {
    "vuln_type": "<UAF|OOB-Write|OOB-Read|Double-Free|Use-After-Scope|etc>",
    "slab_cache": "<cache name>",
    "object_size": <bytes>,
    "primitive": "<write|read|free|arbitrary_write>",
    "timing_window": "<deterministic|race_extensible|race_tight>",
    "spray_feasible": "<easy|moderate|hard>",
    "spray_objects": "<msg_msg|pipe_buffer|etc>",
    "cross_cache": <true|false>,
    "controllable": "<description of controllable bytes/fields>"
  },
  "best_variant": "<which trigger path is most exploitable>",
  "summary": "<2-3 sentence exploitability summary>",
  "focus_hints": ["<syscall or subsystem to focus on>"]
}`

func buildCrashPrompt(c CrashForAnalysis) (string, string) {
	parsed := parseKASANReport(c.Report)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Crash: %s\n\n", c.Title))
	sb.WriteString(fmt.Sprintf("Tier: %d | Variants: %d | Has Repro: %v\n\n", c.Tier, c.NumVariants, c.HasRepro))

	if parsed.BugType != "" {
		sb.WriteString("### Parsed Fields\n")
		sb.WriteString(fmt.Sprintf("- Bug Type: %s\n", parsed.BugType))
		sb.WriteString(fmt.Sprintf("- Access: %s of %d bytes\n", parsed.AccessType, parsed.AccessSize))
		sb.WriteString(fmt.Sprintf("- Slab Cache: %s\n", parsed.SlabCache))
		sb.WriteString(fmt.Sprintf("- Object Size: %d bytes\n", parsed.ObjectSize))
		sb.WriteString(fmt.Sprintf("- Offset in Object: %d\n", parsed.OffsetInObj))
		if parsed.GuiltyFile != "" {
			sb.WriteString(fmt.Sprintf("- Guilty File: %s\n", parsed.GuiltyFile))
		}
		sb.WriteString("\n")
	}

	// Include the raw report (truncated to ~5000 chars to preserve slab/alloc info).
	report := c.Report
	if len(report) > 5000 {
		report = report[:5000] + "\n... [truncated]"
	}
	sb.WriteString("### Raw Report\n```\n")
	sb.WriteString(report)
	sb.WriteString("\n```\n")

	return crashSystemPrompt, sb.String()
}

func parseCrashResponse(content string) (*TriageResult, error) {
	// Strip markdown code fences if present.
	content = strings.TrimSpace(content)
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

	// Try to extract JSON from the response.
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		content = content[start : end+1]
	}

	var result TriageResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w\nraw: %s", err, content[:min(len(content), 500)])
	}

	// Clamp score.
	if result.Score < 0 {
		result.Score = 0
	}
	if result.Score > 100 {
		result.Score = 100
	}
	return &result, nil
}

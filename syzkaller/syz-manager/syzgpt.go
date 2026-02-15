// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 7a — SyzGPT manager-side integration.
// Computes low-frequency syscalls, builds dependency chains, and provides
// corpus examples for AI-guided seed program generation.
package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/aitriage"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// aiGetLFSTargets identifies low-frequency syscalls and builds LFSTarget structs
// with dependency information and corpus examples for the LLM prompt.
func (mgr *Manager) aiGetLFSTargets(maxTargets int) []aitriage.LFSTarget {
	f := mgr.fuzzer.Load()
	if f == nil {
		return nil
	}

	// Get coverage per syscall from corpus.
	callCov := mgr.corpus.CallCover()

	// Build list of enabled syscalls with low or zero coverage.
	type lfsCandidate struct {
		syscall  *prog.Syscall
		coverage int
	}
	var candidates []lfsCandidate
	for sc := range f.Config.EnabledCalls {
		if sc.Attrs.Disabled || sc.Attrs.NoGenerate {
			continue
		}
		cov := 0
		if cc := callCov[sc.Name]; cc != nil {
			cov = cc.Count
		}
		// Low frequency: either never covered (0) or rarely covered (<3).
		if cov < 3 {
			candidates = append(candidates, lfsCandidate{syscall: sc, coverage: cov})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Sort: uncovered first, then by name for stability.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].coverage != candidates[j].coverage {
			return candidates[i].coverage < candidates[j].coverage
		}
		return candidates[i].syscall.Name < candidates[j].syscall.Name
	})

	if len(candidates) > maxTargets {
		candidates = candidates[:maxTargets]
	}

	// Build available syscall name list (for prompt).
	var availableSyscalls []string
	for sc := range f.Config.EnabledCalls {
		if !sc.Attrs.Disabled {
			availableSyscalls = append(availableSyscalls, sc.Name)
		}
	}
	sort.Strings(availableSyscalls)

	// Build LFSTarget for each candidate.
	var targets []aitriage.LFSTarget
	for _, c := range candidates {
		target := mgr.buildLFSTarget(c.syscall, c.coverage, availableSyscalls)
		targets = append(targets, target)
	}

	return targets
}

// buildLFSTarget constructs a detailed LFSTarget with dependency chain and corpus examples.
func (mgr *Manager) buildLFSTarget(sc *prog.Syscall, coverage int, availableSyscalls []string) aitriage.LFSTarget {
	t := aitriage.LFSTarget{
		Name:          sc.Name,
		CallName:      sc.CallName,
		CoverageCount: coverage,
	}

	// Extract argument type descriptions.
	for _, field := range sc.Args {
		t.Args = append(t.Args, describeType(field.Type))
	}

	// Extract return type.
	if sc.Ret != nil {
		t.ReturnType = describeType(sc.Ret)
	}

	// Build input resource dependencies using ForeachCallType.
	resourceSet := make(map[string]bool)
	prog.ForeachCallType(sc, func(typ prog.Type, ctx *prog.TypeCtx) {
		if ctx.Dir == prog.DirOut {
			return // Only care about inputs (DirIn, DirInOut).
		}
		if res, ok := typ.(*prog.ResourceType); ok {
			resName := res.Desc.Name
			if resourceSet[resName] {
				return
			}
			resourceSet[resName] = true

			lfsRes := aitriage.LFSResource{
				ResourceName: resName,
			}

			// Find producers from resource constructors.
			for _, ctor := range res.Desc.Ctors {
				if ctor.Call.ID != sc.ID { // Exclude self.
					lfsRes.Producers = append(lfsRes.Producers, ctor.Call.Name)
				}
			}

			if len(lfsRes.Producers) > 0 {
				t.InputResources = append(t.InputResources, lfsRes)
			}
		}
	})

	// Find corpus examples containing this syscall or related syscalls.
	t.CorpusExamples = mgr.findCorpusExamples(sc, 2)

	return t
}

// describeType returns a human-readable description of a prog.Type.
func describeType(typ prog.Type) string {
	switch t := typ.(type) {
	case *prog.ResourceType:
		return fmt.Sprintf("resource<%s>", t.Desc.Name)
	case *prog.PtrType:
		return fmt.Sprintf("ptr<%s>", describeType(t.Elem))
	case *prog.IntType:
		if t.Kind == prog.IntRange {
			return fmt.Sprintf("int%d[%d:%d]", t.TypeSize*8, t.RangeBegin, t.RangeEnd)
		}
		return fmt.Sprintf("int%d", t.TypeSize*8)
	case *prog.FlagsType:
		return fmt.Sprintf("flags[%s]", t.Name())
	case *prog.ConstType:
		return fmt.Sprintf("const[0x%x]", t.Val)
	case *prog.LenType:
		if len(t.Path) > 0 {
			return fmt.Sprintf("len[%s]", strings.Join(t.Path, "."))
		}
		return "len"
	case *prog.CsumType:
		return "csum"
	case *prog.BufferType:
		switch t.Kind {
		case prog.BufferFilename:
			return "filename"
		case prog.BufferString:
			if t.SubKind != "" {
				return fmt.Sprintf("string[%s]", t.SubKind)
			}
			return "string"
		default:
			return "buffer"
		}
	case *prog.StructType:
		return fmt.Sprintf("struct<%s>", t.Name())
	case *prog.UnionType:
		return fmt.Sprintf("union<%s>", t.Name())
	case *prog.ArrayType:
		return fmt.Sprintf("array<%s>", describeType(t.Elem))
	case *prog.VmaType:
		return "vma"
	case *prog.ProcType:
		return "proc"
	default:
		return typ.Name()
	}
}

// findCorpusExamples searches the corpus for programs containing the target syscall
// or closely related syscalls, returning up to limit serialized examples.
func (mgr *Manager) findCorpusExamples(sc *prog.Syscall, limit int) []string {
	programs := mgr.corpus.Programs()
	if len(programs) == 0 {
		return nil
	}

	type scored struct {
		p     *prog.Prog
		score int
	}
	var matches []scored
	for _, p := range programs {
		score := 0
		for _, c := range p.Calls {
			if c.Meta.ID == sc.ID {
				score += 10 // Exact match.
			} else if c.Meta.CallName == sc.CallName {
				score += 5 // Same base syscall family.
			}
		}
		if score > 0 {
			matches = append(matches, scored{p, score})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].score > matches[j].score
	})

	var examples []string
	for i := 0; i < limit && i < len(matches); i++ {
		serialized := string(matches[i].p.Serialize())
		// Truncate overly long programs to save LLM tokens.
		if len(serialized) > 1000 {
			serialized = serialized[:1000] + "\n# ... (truncated)"
		}
		examples = append(examples, serialized)
	}
	return examples
}

// aiValidateAndInject validates an LLM-generated program and injects it into the fuzzer.
// Returns true if the program was valid and injected.
func (mgr *Manager) aiValidateAndInject(progText string) (bool, error) {
	f := mgr.fuzzer.Load()
	if f == nil {
		return false, fmt.Errorf("fuzzer not ready")
	}

	// Strict deserialization to validate the program.
	p, err := mgr.target.Deserialize([]byte(progText), prog.NonStrict)
	if err != nil {
		return false, fmt.Errorf("invalid program: %w", err)
	}

	// Additional sanity checks.
	if len(p.Calls) == 0 {
		return false, fmt.Errorf("empty program")
	}
	if len(p.Calls) > 20 {
		return false, fmt.Errorf("program too long (%d calls)", len(p.Calls))
	}

	// Inject into fuzzer.
	f.InjectProgram(p)
	log.Logf(0, "PROBE: SyzGPT injected program with %d calls", len(p.Calls))
	return true, nil
}

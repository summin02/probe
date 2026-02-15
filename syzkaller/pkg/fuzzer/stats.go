// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync/atomic"

	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Stats struct {
	// Indexed by prog.Syscall.ID + the last element for extra/remote.
	Syscalls []SyscallStats

	statCandidates          *stat.Val
	statNewInputs           *stat.Val
	statJobs                *stat.Val
	statJobsTriage          *stat.Val
	statJobsTriageCandidate *stat.Val
	statJobsSmash           *stat.Val
	statJobsFocus           *stat.Val // PROBE
	statJobsFaultInjection  *stat.Val
	statJobsHints           *stat.Val
	statExecTime            *stat.Val
	statExecGenerate        *stat.Val
	statExecFuzz            *stat.Val
	statExecCandidate       *stat.Val
	statExecTriage          *stat.Val
	statExecMinimize        *stat.Val
	statExecSmash           *stat.Val
	statExecFocus           *stat.Val // PROBE
	statExecFaultInject     *stat.Val
	statExecHint            *stat.Val
	statExecSeed            *stat.Val
	statExecCollide         *stat.Val
	statCoverOverflows      *stat.Val
	statCompsOverflows      *stat.Val
	statEbpfAllocs          *stat.Val // PROBE: Phase 5
	statEbpfReuses          *stat.Val // PROBE: Phase 5
	statEbpfUafDetected     *stat.Val // PROBE: Phase 5
	statEbpfDoubleFree      *stat.Val // PROBE: Phase 5
	statEbpfSizeMismatch    *stat.Val // PROBE: Phase 5
	statFocusCovGain        *stat.Val // PROBE: Phase 6 — per-source coverage metrics
	statSmashCovGain        *stat.Val // PROBE: Phase 6
	statFuzzCovGain         *stat.Val // PROBE: Phase 6
	statMutOpSquash         *stat.Val // PROBE: Phase 6 — mutation operator tracking
	statMutOpSplice         *stat.Val // PROBE: Phase 6
	statMutOpInsert         *stat.Val // PROBE: Phase 6
	statMutOpMutateArg      *stat.Val // PROBE: Phase 6
	statMutOpRemove         *stat.Val // PROBE: Phase 6
	statMutOpCovGain        *stat.Val // PROBE: Phase 6
}

type SyscallStats struct {
	// Number of times coverage buffer for this syscall has overflowed.
	CoverOverflows atomic.Uint64
	// Number of times comparisons buffer for this syscall has overflowed.
	CompsOverflows atomic.Uint64
}

func newStats(target *prog.Target) Stats {
	return Stats{
		Syscalls: make([]SyscallStats, len(target.Syscalls)+1),
		statCandidates: stat.New("candidates", "Number of candidate programs in triage queue",
			stat.Console, stat.Graph("corpus")),
		statNewInputs: stat.New("new inputs", "Potential untriaged corpus candidates",
			stat.Graph("corpus")),
		statJobs: stat.New("fuzzer jobs", "Total running fuzzer jobs", stat.NoGraph),
		statJobsTriage: stat.New("triage jobs", "Running triage jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=triage")),
		statJobsTriageCandidate: stat.New("candidate triage jobs", "Running candidate triage jobs",
			stat.StackedGraph("jobs"), stat.Link("/jobs?type=triage")),
		statJobsSmash: stat.New("smash jobs", "Running smash jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=smash")),
		statJobsFocus: stat.New("focus jobs", "Running focus mode jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=focus")),
		statJobsFaultInjection: stat.New("fault jobs", "Running fault injection jobs", stat.StackedGraph("jobs")),
		statJobsHints: stat.New("hints jobs", "Running hints jobs", stat.StackedGraph("jobs"),
			stat.Link("/jobs?type=hints")),
		statExecTime: stat.New("prog exec time", "Test program execution time (ms)", stat.Distribution{}),
		statExecGenerate: stat.New("exec gen", "Executions of generated programs", stat.Rate{},
			stat.StackedGraph("exec")),
		statExecFuzz: stat.New("exec fuzz", "Executions of mutated programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecCandidate: stat.New("exec candidate", "Executions of candidate programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecTriage: stat.New("exec triage", "Executions of corpus triage programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecMinimize: stat.New("exec minimize", "Executions of programs during minimization",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecSmash: stat.New("exec smash", "Executions of smashed programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecFocus: stat.New("exec focus", "Executions of focus mode programs",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecFaultInject: stat.New("exec inject", "Executions of fault injection",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecHint: stat.New("exec hints", "Executions of programs generated using hints",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecSeed: stat.New("exec seeds", "Executions of programs for hints extraction",
			stat.Rate{}, stat.StackedGraph("exec")),
		statExecCollide: stat.New("exec collide", "Executions of programs in collide mode",
			stat.Rate{}, stat.StackedGraph("exec")),
		statCoverOverflows: stat.New("cover overflows", "Number of times the coverage buffer overflowed",
			stat.Rate{}, stat.NoGraph),
		statCompsOverflows: stat.New("comps overflows", "Number of times the comparisons buffer overflowed",
			stat.Rate{}, stat.NoGraph),
		statEbpfAllocs: stat.New("ebpf allocs", "Kernel allocs observed by eBPF per execution",
			stat.Rate{}, stat.Graph("ebpf")),
		statEbpfReuses: stat.New("ebpf reuses", "Slab reuses detected by eBPF heap monitor",
			stat.Rate{}, stat.Graph("ebpf")),
		statEbpfUafDetected: stat.New("ebpf uaf", "Non-crashing UAF patterns detected by eBPF",
			stat.Graph("ebpf")),
		statEbpfDoubleFree: stat.New("ebpf double-free", "Double-free events detected by eBPF",
			stat.Graph("ebpf")),
		statEbpfSizeMismatch: stat.New("ebpf size-mismatch", "Cross-cache size mismatches detected by eBPF",
			stat.Rate{}, stat.Graph("ebpf")),
		statFocusCovGain: stat.New("focus cov gain", "Coverage gains from focus mode executions",
			stat.Rate{}, stat.StackedGraph("source cov")),
		statSmashCovGain: stat.New("smash cov gain", "Coverage gains from smash job executions",
			stat.Rate{}, stat.StackedGraph("source cov")),
		statFuzzCovGain: stat.New("fuzz cov gain", "Coverage gains from fuzz/generate executions",
			stat.Rate{}, stat.StackedGraph("source cov")),
		statMutOpSquash: stat.New("mut squash", "Squash operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpSplice: stat.New("mut splice", "Splice operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpInsert: stat.New("mut insert", "Insert operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpMutateArg: stat.New("mut arg", "MutateArg operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpRemove: stat.New("mut remove", "Remove operator applications",
			stat.Rate{}, stat.StackedGraph("mut ops")),
		statMutOpCovGain: stat.New("mut cov gain", "Coverage gains attributed to mutations",
			stat.Rate{}, stat.Graph("mut ops")),
	}
}

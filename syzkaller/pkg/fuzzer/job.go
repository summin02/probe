// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type job interface {
	run(fuzzer *Fuzzer)
}

type jobIntrospector interface {
	getInfo() *JobInfo
}

type JobInfo struct {
	Name  string
	Calls []string
	Type  string
	Execs atomic.Int32

	syncBuffer
}

func (ji *JobInfo) ID() string {
	return fmt.Sprintf("%p", ji)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.target.Generate(rnd,
		fuzzer.RecommendedCalls(),
		fuzzer.ChoiceTable())
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
	}
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.Config.Corpus.ChooseProgram(rnd)
	if p == nil {
		return nil
	}
	newP := p.Clone()
	// PROBE: C3 fix — apply DEzzer-optimized mutation weights (Phase 6/8b/8e).
	// Without this, 95% of mutations use default weights, bypassing DEzzer optimization.
	// Phase 12 A2: Load prevOp for pair TS conditioning (atomic.Value, ~15ns).
	prevOp := ""
	if v := fuzzer.lastMutOp.Load(); v != nil {
		prevOp = v.(string)
	}
	mutOpts := fuzzer.getAIMutateOpts(prevOp, classifyProgram(newP))
	op := newP.MutateWithOpts(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
		mutOpts,
	)
	// Phase 12 A2: Store current op for next mutation's pair TS context.
	if op != "" {
		fuzzer.lastMutOp.Store(op)
	}
	// Phase 12 B4: Two-level action space — select sub-op within parent op.
	subOp := ""
	if op != "" && fuzzer.dezzer != nil {
		subOp = fuzzer.dezzer.SelectSubOp(op)
	}
	// PROBE: Phase 6 — track operator usage.
	if op != "" {
		switch op {
		case "squash":
			fuzzer.statMutOpSquash.Add(1)
		case "splice":
			fuzzer.statMutOpSplice.Add(1)
		case "insert":
			fuzzer.statMutOpInsert.Add(1)
		case "mutate_arg":
			fuzzer.statMutOpMutateArg.Add(1)
		case "remove":
			fuzzer.statMutOpRemove.Add(1)
		case "reorder":
			fuzzer.statMutOpReorder.Add(1)
		}
	}

	// PROBE: Phase 11k — OZZ: 4-arm strategy selection wrapping ACTOR delay.
	delayPattern := -1
	schedArm := -1
	if fuzzer.schedTS != nil && fuzzer.linucb != nil {
		fuzzer.delayTotal.Add(1)
		// Adaptive rate control: 10% start, 20% max cap.
		delayed := fuzzer.delayedExecs.Load()
		total := fuzzer.delayTotal.Load()
		if total > 0 && delayed*100/total > 20 {
			delayPattern = prog.DelayNone
		} else if rnd.Intn(10) == 0 { // 10% base injection rate
			schedArm = fuzzer.schedTS.SelectArm(rnd)
			switch schedArm {
			case SchedNone:
				delayPattern = prog.DelayNone
				fuzzer.statDelayNone.Add(1)
			case SchedDelayOnly:
				features := fuzzer.buildDelayFeatures(newP, false)
				delayPattern = fuzzer.linucb.SelectArm(features)
				if delayPattern != prog.DelayNone {
					applyDelayPattern(newP, delayPattern, rnd)
					fuzzer.delayedExecs.Add(1)
					switch delayPattern {
					case prog.DelayRandom:
						fuzzer.statDelayRandom.Add(1)
					case prog.DelayBetween:
						fuzzer.statDelayBetween.Add(1)
					case prog.DelayAroundLocks:
						fuzzer.statDelayAroundLocks.Add(1)
					}
				} else {
					fuzzer.statDelayNone.Add(1)
				}
			case SchedYieldOnly:
				// Set sched_yield on ~33% of calls.
				for i := range newP.Calls {
					if rnd.Intn(3) == 0 {
						newP.Calls[i].Props.SchedYield = true
					}
				}
				fuzzer.delayedExecs.Add(1)
				fuzzer.statSchedYield.Add(1)
			case SchedBoth:
				// Combined: delay + yield.
				features := fuzzer.buildDelayFeatures(newP, false)
				delayPattern = fuzzer.linucb.SelectArm(features)
				if delayPattern != prog.DelayNone {
					applyDelayPattern(newP, delayPattern, rnd)
				}
				for i := range newP.Calls {
					if rnd.Intn(3) == 0 {
						newP.Calls[i].Props.SchedYield = true
					}
				}
				fuzzer.delayedExecs.Add(1)
				fuzzer.statSchedBoth.Add(1)
			}
			fuzzer.statDelayApplied.Add(1)
		}
	}

	// PROBE: Phase 15 — track whether BiGRU was used for UCB-1 feedback.
	usedBiGRU := mutOpts.PredictCall != nil

	return &queue.Request{
		Prog:         newP,
		ExecOpts:     setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:         fuzzer.statExecFuzz,
		MutOp:        op,           // PROBE: carry operator to processResult for DEzzer feedback
		SubOp:        subOp,        // PROBE: Phase 12 B4 — carry sub-op for two-level feedback
		DelayPattern: delayPattern, // PROBE: Phase 11j — carry delay pattern for LinUCB feedback
		SchedArm:     schedArm,     // PROBE: Phase 11k — carry schedTS arm for Global TS feedback
		UsedBiGRU:    usedBiGRU,    // PROBE: Phase 15 — UCB-1 feedback tracking
	}
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p        *prog.Prog
	executor queue.ExecutorID
	flags    ProgFlags
	fuzzer   *Fuzzer
	queue    queue.Executor
	// Set of calls that gave potential new coverage.
	calls map[int]*triageCall

	info *JobInfo
}

type triageCall struct {
	errno     int32
	newSignal signal.Signal

	// Filled after deflake:
	signals         [deflakeNeedRuns]signal.Signal
	stableSignal    signal.Signal
	newStableSignal signal.Signal
	cover           cover.Cover
	rawCover        []uint64
}

// As demonstrated in #4639, programs reproduce with a very high, but not 100% probability.
// The triage algorithm must tolerate this, so let's pick the signal that is common
// to 3 out of 5 runs.
// By binomial distribution, a program that reproduces 80% of time will pass deflake()
// with a 94% probability. If it reproduces 90% of time, it passes in 99% of cases.
//
// During corpus triage we are more permissive and require only 2/6 to produce new stable signal.
// Such parameters make 80% flakiness to pass 99% of time, and even 60% flakiness passes 96% of time.
// First, we don't need to be strict during corpus triage since the program has already passed
// the stricter check when it was added to the corpus. So we can do fewer runs during triage,
// and finish it sooner. If the program does not produce any stable signal any more, just flakes,
// (if the kernel code was changed, or configs disabled), then it still should be phased out
// of the corpus eventually.
// Second, even if small percent of programs are dropped from the corpus due to flaky signal,
// later after several restarts we will add them to the corpus again, and it will create lots
// of duplicate work for minimization/hints/smash/fault injection. For example, a program with
// 60% flakiness has 68% chance to pass 3/5 criteria, but it's also likely to be dropped from
// the corpus if we use the same 3/5 criteria during triage. With a large corpus this effect
// can cause re-addition of thousands of programs to the corpus, and hundreds of thousands
// of runs for the additional work. With 2/6 criteria, a program with 60% flakiness has
// 96% chance to be kept in the corpus after retriage.
const (
	deflakeNeedRuns         = 3
	deflakeMaxRuns          = 5
	deflakeMaxRunsAdaptive  = 4 // Phase 11b: default adaptive (was always 5)
	deflakeMaxRunsStrict    = 5 // Phase 11b: high-value programs only
	deflakeNeedCorpusRuns   = 2
	deflakeMinCorpusRuns    = 4
	deflakeMaxCorpusRuns    = 6
	deflakeTotalCorpusRuns  = 12 // Phase 11b: reduced from 20
	deflakeNeedSnapshotRuns = 2
)

func (job *triageJob) execute(req *queue.Request, flags ProgFlags) *queue.Result {
	defer job.info.Execs.Add(1)
	req.Important = true // All triage executions are important.
	return job.fuzzer.executeWithFlags(job.queue, req, flags)
}

func (job *triageJob) run(fuzzer *Fuzzer) {
	fuzzer.statNewInputs.Add(1)
	job.fuzzer = fuzzer
	job.info.Logf("\n%s", job.p.Serialize())
	for call, info := range job.calls {
		job.info.Logf("call #%d [%s]: |new signal|=%d%s",
			call, job.p.CallName(call), info.newSignal.Len(), signalPreview(info.newSignal))
	}

	// Compute input coverage and non-flaky signal for minimization.
	stop := job.deflake(job.execute)
	if stop {
		return
	}
	var wg sync.WaitGroup
	for call, info := range job.calls {
		wg.Add(1)
		go func() {
			job.handleCall(call, info)
			wg.Done()
		}()
	}
	wg.Wait()
}

func (job *triageJob) handleCall(call int, info *triageCall) {
	if info.newStableSignal.Empty() {
		return
	}

	p := job.p
	if job.flags&ProgMinimized == 0 {
		p, call = job.minimize(call, info)
		if p == nil {
			return
		}
	}
	callName := p.CallName(call)
	if !job.fuzzer.Config.NewInputFilter(callName) {
		return
	}
	if job.flags&ProgSmashed == 0 {
		job.fuzzer.startJob(job.fuzzer.statJobsSmash, &smashJob{
			exec: job.fuzzer.smashQueue,
			p:    p.Clone(),
			info: &JobInfo{
				Name:  p.String(),
				Type:  "smash",
				Calls: []string{p.CallName(call)},
			},
		})
		if job.fuzzer.Config.Comparisons && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsHints, &hintsJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				call: call,
				info: &JobInfo{
					Name:  p.String(),
					Type:  "hints",
					Calls: []string{p.CallName(call)},
				},
			})
		}
		if job.fuzzer.Config.FaultInjection && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsFaultInjection, &faultInjectionJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				call: call,
			})
		}
	}
	job.fuzzer.Logf(2, "added new input for %v to the corpus: %s", callName, p)
	input := corpus.NewInput{
		Prog:     p,
		Call:     call,
		Signal:   info.stableSignal,
		Cover:    info.cover.Serialize(),
		RawCover: info.rawCover,
	}
	job.fuzzer.Config.Corpus.Save(input)
}

func (job *triageJob) deflake(exec func(*queue.Request, ProgFlags) *queue.Result) (stop bool) {
	job.info.Logf("deflake started")

	avoid := []queue.ExecutorID{job.executor}
	needRuns := deflakeNeedCorpusRuns
	if job.fuzzer.Config.Snapshot {
		needRuns = deflakeNeedSnapshotRuns
	} else if job.flags&ProgFromCorpus == 0 {
		needRuns = deflakeNeedRuns
	}

	// Phase 11b: Determine if this is a high-value program (more deflake runs).
	highValue := false
	for _, info := range job.calls {
		if info.newSignal.Len() >= 10 {
			highValue = true
			break
		}
	}

	prevTotalNewSignal := 0
	for run := 1; ; run++ {
		job.fuzzer.statDeflakeRuns.Add(1)
		totalNewSignal := 0
		indices := make([]int, 0, len(job.calls))
		for call, info := range job.calls {
			indices = append(indices, call)
			totalNewSignal += len(info.newSignal)
		}

		// Phase 11b: Early exit — after run 2, if all calls have no new signal, stop.
		if run > 2 && job.flags&ProgFromCorpus == 0 && !job.fuzzer.Config.Snapshot {
			allEmpty := true
			for _, info := range job.calls {
				if info.newSignal.Len() > 0 {
					allEmpty = false
					break
				}
			}
			if allEmpty {
				job.fuzzer.statDeflakeEarlyExit.Add(1)
				break
			}
		}

		if job.stopDeflake(run, needRuns, prevTotalNewSignal == totalNewSignal, highValue) {
			break
		}
		prevTotalNewSignal = totalNewSignal
		result := exec(&queue.Request{
			Prog:            job.p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: indices,
			Avoid:           avoid,
			Stat:            job.fuzzer.statExecTriage,
		}, progInTriage)
		if result.Stop() {
			return true
		}
		avoid = append(avoid, result.Executor)
		if result.Info == nil {
			continue // the program has failed
		}
		deflakeCall := func(call int, res *flatrpc.CallInfo) {
			info := job.calls[call]
			if info == nil {
				job.fuzzer.triageProgCall(job.p, res, call, &job.calls)
				info = job.calls[call]
			}
			if info == nil || res == nil {
				return
			}
			if len(info.rawCover) == 0 && job.fuzzer.Config.FetchRawCover {
				info.rawCover = res.Cover
			}
			// Since the signal is frequently flaky, we may get some new new max signal.
			// Merge it into the new signal we are chasing.
			// Most likely we won't conclude it's stable signal b/c we already have at least one
			// initial run w/o this signal, so if we exit after needRuns runs,
			// it won't be stable. However, it's still possible if we do more than needRuns runs.
			// But also we already observed it and we know it's flaky, so at least doing
			// cover.addRawMaxSignal for it looks useful.
			prio := signalPrio(job.p, res, call)
			newMaxSignal := job.fuzzer.Cover.addRawMaxSignal(res.Signal, prio)
			info.newSignal.Merge(newMaxSignal)
			info.cover.Merge(res.Cover)
			thisSignal := signal.FromRaw(res.Signal, prio)
			for j := needRuns - 1; j > 0; j-- {
				intersect := info.signals[j-1].Intersection(thisSignal)
				info.signals[j].Merge(intersect)
			}
			info.signals[0].Merge(thisSignal)
		}
		for i, callInfo := range result.Info.Calls {
			deflakeCall(i, callInfo)
		}
		deflakeCall(-1, result.Info.Extra)
	}
	job.info.Logf("deflake complete")
	for call, info := range job.calls {
		info.stableSignal = info.signals[needRuns-1]
		info.newStableSignal = info.newSignal.Intersection(info.stableSignal)
		job.info.Logf("call #%d [%s]: |stable signal|=%d, |new stable signal|=%d%s",
			call, job.p.CallName(call), info.stableSignal.Len(), info.newStableSignal.Len(),
			signalPreview(info.newStableSignal))
	}
	return false
}

func (job *triageJob) stopDeflake(run, needRuns int, noNewSignal bool, highValue bool) bool {
	if job.fuzzer.Config.Snapshot {
		return run >= needRuns+1
	}
	haveSignal := true
	for _, call := range job.calls {
		if !call.newSignal.IntersectsWith(call.signals[needRuns-1]) {
			haveSignal = false
		}
	}
	if job.flags&ProgFromCorpus == 0 {
		// For fuzzing programs we stop if we already have the right deflaked signal for all calls,
		// or there's no chance to get coverage common to needRuns for all calls.
		if run >= deflakeMaxRuns {
			return true
		}
		// Phase 11b: Adaptive early stop — non-high-value programs stop sooner
		// once stable signal is already found.
		if !highValue && run >= deflakeMaxRunsAdaptive && haveSignal {
			return true
		}
		noChance := true
		for _, call := range job.calls {
			if left := deflakeMaxRuns - run; left >= needRuns ||
				call.newSignal.IntersectsWith(call.signals[needRuns-left-1]) {
				noChance = false
			}
		}
		if haveSignal || noChance {
			return true
		}
	} else if run >= deflakeTotalCorpusRuns ||
		noNewSignal && (run >= deflakeMaxCorpusRuns || run >= deflakeMinCorpusRuns && haveSignal) {
		// For programs from the corpus we use a different condition b/c we want to extract
		// as much flaky signal from them as possible. They have large coverage and run
		// in the beginning, gathering flaky signal on them allows to grow max signal quickly
		// and avoid lots of useless executions later. Any bit of flaky coverage discovered
		// later will lead to triage, and if we are unlucky to conclude it's stable also
		// to minimization+smash+hints (potentially thousands of runs).
		// So we run them at least 5 times, or while we are still getting any new signal.
		return true
	}
	return false
}

func (job *triageJob) minimize(call int, info *triageCall) (*prog.Prog, int) {
	job.info.Logf("[call #%d] minimize started", call)
	minimizeAttempts := 3
	if job.fuzzer.Config.Snapshot {
		minimizeAttempts = 2
	}
	stop := false
	mode := prog.MinimizeCorpus
	if job.fuzzer.Config.PatchTest {
		mode = prog.MinimizeCallsOnly
	}
	p, call := prog.Minimize(job.p, call, mode, func(p1 *prog.Prog, call1 int) bool {
		if stop {
			return false
		}
		var mergedSignal signal.Signal
		for i := 0; i < minimizeAttempts; i++ {
			result := job.execute(&queue.Request{
				Prog:            p1,
				ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
				ReturnAllSignal: []int{call1},
				Stat:            job.fuzzer.statExecMinimize,
			}, 0)
			if result.Stop() {
				stop = true
				return false
			}
			if !reexecutionSuccess(result.Info, info.errno, call1) {
				// The call was not executed or failed.
				continue
			}
			thisSignal := getSignalAndCover(p1, result.Info, call1)
			if mergedSignal.Len() == 0 {
				mergedSignal = thisSignal
			} else {
				mergedSignal.Merge(thisSignal)
			}
			if info.newStableSignal.Intersection(mergedSignal).Len() == info.newStableSignal.Len() {
				job.info.Logf("[call #%d] minimization step success (|calls| = %d)",
					call, len(p1.Calls))
				return true
			}
		}
		job.info.Logf("[call #%d] minimization step failure", call)
		return false
	})
	if stop {
		return nil, 0
	}
	return p, call
}

func reexecutionSuccess(info *flatrpc.ProgInfo, oldErrno int32, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldErrno == 0 && info.Calls[call].Error != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return info.Extra != nil && len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *flatrpc.ProgInfo, call int) signal.Signal {
	inf := info.Extra
	if call != -1 {
		inf = info.Calls[call]
	}
	if inf == nil {
		return nil
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call))
}

func signalPreview(s signal.Signal) string {
	if s.Len() > 0 && s.Len() <= 3 {
		var sb strings.Builder
		sb.WriteString(" (")
		for i, x := range s.ToRaw() {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "0x%x", x)
		}
		sb.WriteByte(')')
		return sb.String()
	}
	return ""
}

func (job *triageJob) getInfo() *JobInfo {
	return job.info
}

type smashJob struct {
	exec queue.Executor
	p    *prog.Prog
	info *JobInfo
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	fuzzer.Logf(2, "smashing the program %s:", job.p)
	job.info.Logf("\n%s", job.p.Serialize())

	const iters = 25
	rnd := fuzzer.rand()
	lastSignalLen := fuzzer.Cover.MaxSignalLen()
	prevOp := ""                          // Phase 8b: track previous op for pair TS
	cluster := classifyProgram(job.p)     // Phase 8e: classify once per program
	for i := 0; i < iters; i++ {
		p := job.p.Clone()
		// P0-3/11f: Use DEzzer-optimized weights instead of raw Mutate().
		// 20% exploration: use default weights to maintain diversity.
		var mutOpts prog.MutateOpts
		if rnd.Intn(5) == 0 {
			mutOpts = prog.DefaultMutateOpts
			fuzzer.statSmashDiversity.Add(1)
		} else {
			mutOpts = fuzzer.getAIMutateOpts(prevOp, cluster)
		}
		op := p.MutateWithOpts(rnd, prog.RecommendedCalls,
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs(),
			mutOpts)
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:     fuzzer.statExecSmash,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		// PROBE: Phase 6 — feed actual coverage gain to DEzzer.
		if op != "" && fuzzer.dezzer != nil {
			currentSignalLen := fuzzer.Cover.MaxSignalLen()
			covGain := 0
			if currentSignalLen > lastSignalLen {
				covGain = currentSignalLen - lastSignalLen
				lastSignalLen = currentSignalLen
			}
			fuzzer.dezzer.RecordResult(op, prevOp, "", covGain, SourceSmash, cluster)
			prevOp = op
		}
	}
}

func (job *smashJob) getInfo() *JobInfo {
	return job.info
}

// PROBE: focusJob performs intensive mutation of high-severity crash programs.
// Unlike smashJob (25 iterations), focusJob runs up to focusMaxIters iterations
// with diminishing-returns early exit when no new coverage is found.
type focusJob struct {
	exec  queue.Executor
	p     *prog.Prog
	title string
	tier  int
	info  *JobInfo
}

const (
	focusMaxIters      = 100 // Reduced from 300: prevent Focus monopolization.
	focusNoProgressMax = 20  // Reduced from 50: faster early exit on diminishing returns.
)

func (job *focusJob) run(fuzzer *Fuzzer) {
	defer func() {
		fuzzer.focusMu.Lock()
		fuzzer.focusActive = false
		fuzzer.focusTarget = ""
		fuzzer.lastEbpfFocus = time.Now() // Reset cooldown at focus END (not start).
		fuzzer.focusMu.Unlock()
		// Launch next queued focus candidate if any.
		fuzzer.drainFocusPending()
	}()

	start := time.Now()
	rnd := fuzzer.rand()
	var newCoverage, totalIters int
	noProgress := 0
	lastSignalLen := fuzzer.Cover.MaxSignalLen()

	fuzzer.Logf(0, "PROBE: focus mode started for '%v' (tier %d)", job.title, job.tier)
	job.info.Logf("focus target:\n%s", job.p.Serialize())

	// PROBE: Phase 6 — track operator distribution and coverage gains.
	opDist := make(map[string]int)
	opCovGains := make(map[string]int)

	prevOp := ""                          // Phase 8b: track previous op for pair TS
	cluster := classifyProgram(job.p)     // Phase 8e: classify once per program

	// Phase 8f: Effective Component — identify essential syscalls for focused mutation.
	var essential []bool
	if len(job.p.Calls) >= 5 {
		essential = fuzzer.getOrComputeAblation(job.exec, job.p, job.title, rnd)
	}

	// Phase 11g: Optimal stopping — first 25% is observation phase.
	observeIters := focusMaxIters / 4 // 25 iterations
	var maxObservedGain int

	for i := 0; i < focusMaxIters; i++ {
		mutOpts := fuzzer.getAIMutateOpts(prevOp, cluster) // Phase 8b: pair-aware weights

		var p *prog.Prog
		var op string

		// Phase 8f: 50% chance to use essential-focused mutation.
		if essential != nil && rnd.Intn(2) == 0 {
			p, op = fuzzer.essentialMutate(job.p, essential, rnd, mutOpts)
		}
		if p == nil {
			p = job.p.Clone()
			op = p.MutateWithOpts(rnd, prog.RecommendedCalls,
				fuzzer.ChoiceTable(),
				fuzzer.Config.NoMutateCalls,
				fuzzer.Config.Corpus.Programs(),
				mutOpts)
		}
		if op != "" {
			opDist[op]++
		}

		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:     fuzzer.statExecFocus,
		})
		if result.Stop() {
			break
		}
		totalIters++
		job.info.Execs.Add(1)

		currentSignalLen := fuzzer.Cover.MaxSignalLen()
		covGain := 0
		if currentSignalLen > lastSignalLen {
			covGain = currentSignalLen - lastSignalLen
			newCoverage++
			noProgress = 0
			lastSignalLen = currentSignalLen
		} else {
			noProgress++
		}

		// PROBE: Phase 6 — feed result to DEzzer.
		if op != "" {
			if fuzzer.dezzer != nil {
				fuzzer.dezzer.RecordResult(op, prevOp, "", covGain, SourceFocus, cluster)
			}
			if covGain > 0 {
				opCovGains[op] += covGain
			}
			prevOp = op
		}

		// Phase 8c: Record objective reward based on eBPF signals.
		if fuzzer.dezzer != nil && result.Info != nil {
			fuzzer.recordObjectiveReward(result.Info, covGain)
		}

		// Phase 11g: Optimal stopping rule.
		if i < observeIters {
			// Observation phase: track max gain.
			if covGain > maxObservedGain {
				maxObservedGain = covGain
			}
		} else if maxObservedGain > 0 && covGain > maxObservedGain {
			// Post-observation: found gain exceeding observation max — stop successfully.
			fuzzer.statFocusOptStop.Add(1)
			fuzzer.Logf(0, "PROBE: focus optimal stop at iter %d (gain=%d > maxObserved=%d)",
				i, covGain, maxObservedGain)
			break
		}

		if noProgress >= focusNoProgressMax {
			break
		}
	}

	earlyExit := noProgress >= focusNoProgressMax
	optimalStop := totalIters < focusMaxIters && !earlyExit && totalIters > observeIters
	exitReason := "completed"
	if earlyExit {
		exitReason = fmt.Sprintf("no-progress(%d)", focusNoProgressMax)
	} else if optimalStop {
		exitReason = "optimal-stop"
	}
	duration := time.Since(start).Round(time.Second)
	fuzzer.Logf(0, "PROBE: focus mode ended for '%v' — iters: %d/%d, new_coverage: %d, exit_reason: %s, duration: %v",
		job.title, totalIters, focusMaxIters, newCoverage, exitReason, duration)

	// PROBE: Phase 6 — record focus result for AI feedback loop.
	covPerExec := 0.0
	if totalIters > 0 {
		covPerExec = float64(newCoverage) / float64(totalIters)
	}
	fuzzer.RecordFocusResult(FocusJobResult{
		Title:           job.title,
		Tier:            job.tier,
		TotalIters:      totalIters,
		NewCoverage:     newCoverage,
		CoveragePerExec: covPerExec,
		EarlyExit:       earlyExit,
		OpDistribution:  opDist,
		OpCovGains:      opCovGains,
		Timestamp:       time.Now(),
	})
}

func (job *focusJob) getInfo() *JobInfo {
	return job.info
}

// PROBE: Phase 11j — applyDelayPattern sets DelayUs on program calls based on delay pattern.
func applyDelayPattern(p *prog.Prog, pattern int, rnd *rand.Rand) {
	switch pattern {
	case prog.DelayNone:
		// No delay.
	case prog.DelayRandom:
		// Set random calls' DelayUs to rand(1,100).
		for i := range p.Calls {
			if rnd.Intn(3) == 0 { // ~33% of calls
				p.Calls[i].Props.DelayUs = rnd.Intn(100) + 1
			}
		}
	case prog.DelayBetween:
		// Set all calls' DelayUs to 50.
		for i := range p.Calls {
			p.Calls[i].Props.DelayUs = 50
		}
	case prog.DelayAroundLocks:
		// Set lock-related syscalls' DelayUs to 100.
		for i := range p.Calls {
			if isLockSyscall(p.Calls[i].Meta.Name) {
				p.Calls[i].Props.DelayUs = 100
			}
		}
	}
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

type faultInjectionJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog: newProg,
			Stat: fuzzer.statExecFaultInject,
		})
		if result.Stop() {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&flatrpc.CallFlagFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
	info *JobInfo
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program several times to get comparisons from KCOV.
	// Additional executions lets us filter out flaky values, which seem to constitute ~30-40%.
	p := job.p
	job.info.Logf("\n%s", p.Serialize())

	var comps prog.CompMap
	for i := 0; i < 3; i++ {
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectComps),
			Stat:     fuzzer.statExecSeed,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		if result.Info == nil || len(result.Info.Calls[job.call].Comps) == 0 {
			continue
		}
		got := make(prog.CompMap)
		for _, cmp := range result.Info.Calls[job.call].Comps {
			got.Add(cmp.Pc, cmp.Op1, cmp.Op2, cmp.IsConst)
		}
		if i == 0 {
			comps = got
		} else {
			comps.InplaceIntersect(got)
		}
	}

	job.info.Logf("stable comps: %d", comps.Len())
	fuzzer.hintsLimiter.Limit(comps)
	job.info.Logf("stable comps (after the hints limiter): %d", comps.Len())

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, comps,
		func(p *prog.Prog) bool {
			defer job.info.Execs.Add(1)
			result := fuzzer.execute(job.exec, &queue.Request{
				Prog:     p,
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:     fuzzer.statExecHint,
			})
			return !result.Stop()
		})
}

func (job *hintsJob) getInfo() *JobInfo {
	return job.info
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Logf(logFmt string, args ...any) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	fmt.Fprintf(&sb.buf, "%s: ", time.Now().Format(time.DateTime))
	fmt.Fprintf(&sb.buf, logFmt, args...)
	sb.buf.WriteByte('\n')
}

func (sb *syncBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Bytes()
}

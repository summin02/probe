// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.RWMutex
	ctRegenerate chan struct{}

	// PROBE: Focus Mode state.
	focusMu        sync.Mutex
	focusTitles    map[string]bool // titles that have been focused (prevents re-focus)
	focusActive    bool            // true while a focus job is running
	focusTarget    string          // title of the current focus target
	focusPending   []focusCandidate // queued candidates waiting for current focus to finish
	lastEbpfFocus  time.Time      // cooldown for eBPF-triggered focus (prevent over-triggering)

	// PROBE: AI mutation hints for focus jobs.
	aiMutHintsMu sync.Mutex
	aiMutHints   *prog.MutateOpts // nil = use default

	// PROBE: Phase 6 — DEzzer optimizer and focus feedback.
	dezzer       *DEzzer
	focusResultsMu sync.Mutex
	focusResults   []FocusJobResult

	execQueues
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	f := &Fuzzer{
		Stats:  newStats(target),
		Config: cfg,
		Cover:  newCover(),

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),

		focusTitles: map[string]bool{},
	}
	f.dezzer = NewDEzzer(f.Logf)
	f.execQueues = newExecQueues(f)
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

func (fuzzer *Fuzzer) RecommendedCalls() int {
	if fuzzer.Config.ModeKFuzzTest {
		return prog.RecommendedCallsKFuzzTest
	}
	return prog.RecommendedCalls
}

type execQueues struct {
	triageCandidateQueue *queue.DynamicOrderer
	candidateQueue       *queue.PlainQueue
	triageQueue          *queue.DynamicOrderer
	focusQueue           *queue.PlainQueue // PROBE
	smashQueue           *queue.PlainQueue
	source               queue.Source
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.DynamicOrder(),
		candidateQueue:       queue.Plain(),
		triageQueue:          queue.DynamicOrder(),
		focusQueue:           queue.Plain(), // PROBE
		smashQueue:           queue.Plain(),
	}
	// Alternate smash jobs with exec/fuzz to spread attention to the wider area.
	skipQueue := 3
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		skipQueue = 2
	}
	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(
		ret.triageCandidateQueue,
		ret.candidateQueue,
		ret.triageQueue,
		queue.Alternate(ret.focusQueue, 2), // PROBE: focus every 2nd request
		queue.Alternate(ret.smashQueue, skipQueue),
		queue.Callback(fuzzer.genFuzz),
	)
	return ret
}

func (fuzzer *Fuzzer) CandidatesToTriage() int {
	return fuzzer.statCandidates.Val() + fuzzer.statJobsTriageCandidate.Val()
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	return fuzzer.CandidatesToTriage() == 0
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	// If we are already triaging this exact prog, this is flaky coverage.
	// Hanged programs are harmful as they consume executor procs.
	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	// Triage the program.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	var triage map[int]*triageCall
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 && res.Info != nil && !dontTriage {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, info, call, &triage)
		}
		fuzzer.triageProgCall(req.Prog, res.Info.Extra, -1, &triage)

		if len(triage) != 0 {
			// PROBE: Phase 6 — per-source coverage gain tracking.
			switch req.Stat {
			case fuzzer.statExecFocus:
				fuzzer.statFocusCovGain.Add(1)
			case fuzzer.statExecSmash:
				fuzzer.statSmashCovGain.Add(1)
			case fuzzer.statExecFuzz, fuzzer.statExecGenerate:
				fuzzer.statFuzzCovGain.Add(1)
			}

			queue, stat := fuzzer.triageQueue, fuzzer.statJobsTriage
			if flags&progCandidate > 0 {
				queue, stat = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
			}
			job := &triageJob{
				p:        req.Prog.Clone(),
				executor: res.Executor,
				flags:    flags,
				queue:    queue.Append(),
				calls:    triage,
				info: &JobInfo{
					Name: req.Prog.String(),
					Type: "triage",
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			sort.Strings(job.info.Calls)
			fuzzer.startJob(stat, job)
		}
	}

	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)

		// PROBE: eBPF heap monitoring feedback (Phase 5).
		if res.Info.EbpfAllocCount > 0 {
			fuzzer.statEbpfAllocs.Add(int(res.Info.EbpfAllocCount))
		}
		if res.Info.EbpfReuseCount > 0 {
			fuzzer.statEbpfReuses.Add(int(res.Info.EbpfReuseCount))
		}
		if res.Info.EbpfDoubleFreeCount > 0 {
			fuzzer.statEbpfDoubleFree.Add(int(res.Info.EbpfDoubleFreeCount))
		}
		if res.Info.EbpfSizeMismatchCount > 0 {
			fuzzer.statEbpfSizeMismatch.Add(int(res.Info.EbpfSizeMismatchCount))
		}
		// Phase 7d: Privilege escalation metrics.
		if res.Info.EbpfCommitCredsCount > 0 {
			fuzzer.statEbpfCommitCreds.Add(int(res.Info.EbpfCommitCredsCount))
		}
		if res.Info.EbpfPrivEscCount > 0 {
			fuzzer.statEbpfPrivEsc.Add(int(res.Info.EbpfPrivEscCount))
		}
		// Phase 7c: Precise cross-cache metrics.
		if res.Info.EbpfCrossCacheCount > 0 {
			fuzzer.statEbpfCrossCache.Add(int(res.Info.EbpfCrossCacheCount))
		}

		// Cooldown check shared by double-free and UAF focus triggers.
		fuzzer.focusMu.Lock()
		ebpfCooldownOk := time.Since(fuzzer.lastEbpfFocus) >= 5*time.Minute
		fuzzer.focusMu.Unlock()

		// Double-free: trigger Focus (with cooldown to prevent over-triggering).
		if res.Info.EbpfDoubleFreeCount > 0 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.Logf(0, "PROBE: eBPF detected DOUBLE-FREE (count=%d) in %s",
				res.Info.EbpfDoubleFreeCount, req.Prog)
			fuzzer.AddFocusCandidate(req.Prog,
				fmt.Sprintf("PROBE:ebpf-double-free:%s", req.Prog.String()), 1)
		}
		// Non-crashing UAF detection: high UAF score without crash → UAF-favorable pattern.
		if res.Info.EbpfUafScore >= 70 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.statEbpfUafDetected.Add(1)
			fuzzer.Logf(0, "PROBE: eBPF detected UAF-favorable pattern (score=%d, reuse=%d, rapid=%d) in %s",
				res.Info.EbpfUafScore, res.Info.EbpfReuseCount,
				res.Info.EbpfRapidReuseCount, req.Prog)
			fuzzer.AddFocusCandidate(req.Prog, fmt.Sprintf("PROBE:ebpf-uaf:%s", req.Prog.String()), 1)
		}
		// Phase 7d: Privilege escalation — top priority focus trigger.
		if res.Info.EbpfPrivEscCount > 0 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.Logf(0, "PROBE: eBPF detected PRIVILEGE ESCALATION (priv_esc=%d, commit_creds=%d) in %s",
				res.Info.EbpfPrivEscCount, res.Info.EbpfCommitCredsCount, req.Prog)
			fuzzer.AddFocusCandidate(req.Prog, "PROBE:priv-esc", 1) // tier 1 = highest priority
		}
		// Phase 7c: Precise cross-cache detection — trigger focus.
		if res.Info.EbpfCrossCacheCount > 0 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.Logf(0, "PROBE: eBPF detected CROSS-CACHE reallocation (count=%d) in %s",
				res.Info.EbpfCrossCacheCount, req.Prog)
			fuzzer.AddFocusCandidate(req.Prog,
				fmt.Sprintf("PROBE:ebpf-cross-cache:%s", req.Prog.String()), 1)
		}
	}

	// Corpus candidates may have flaky coverage, so we give them a second chance.
	maxCandidateAttempts := 3
	if req.Risky() {
		// In non-snapshot mode usually we are not sure which exactly input caused the crash,
		// so give it one more chance. In snapshot mode we know for sure, so don't retry.
		maxCandidateAttempts = 2
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		fuzzer.statCandidates.Add(-1)
	}
	return true
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	Logf           func(level int, msg string, args ...any)
	Snapshot       bool
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	FetchRawCover  bool
	NewInputFilter func(call string) bool
	PatchTest      bool
	ModeKFuzzTest  bool
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:     info.Error,
		newSignal: newMaxSignal,
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
		fuzzer.statCompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
		fuzzer.statCoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	var req *queue.Request
	rnd := fuzzer.rand()
	if rnd.Float64() < mutateRate {
		req = mutateProgRequest(fuzzer, rnd)
	}
	if req == nil {
		req = genProgRequest(fuzzer, rnd)
	}
	if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
		req = &queue.Request{
			Prog: randomCollide(req.Prog, rnd),
			Stat: fuzzer.statExecCollide,
		}
	}
	fuzzer.prepare(req, 0, 0)
	return req
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}

		newJob.run(fuzzer)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...any) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed

	progCandidate
	progInTriage
)

type Candidate struct {
	Prog  *prog.Prog
	Flags ProgFlags
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.statCandidates.Add(len(candidates))
	for _, candidate := range candidates {
		req := &queue.Request{
			Prog:      candidate.Prog,
			ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:      fuzzer.statExecCandidate,
			Important: true,
		}
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
}

// PROBE: FocusStatus returns whether a focus job is active and its target title.
func (fuzzer *Fuzzer) FocusStatus() (active bool, title string) {
	fuzzer.focusMu.Lock()
	defer fuzzer.focusMu.Unlock()
	return fuzzer.focusActive, fuzzer.focusTarget
}

// focusCandidate holds a queued focus target awaiting execution.
type focusCandidate struct {
	prog  *prog.Prog
	title string
	tier  int
}

// PROBE: AddFocusCandidate queues a high-severity crash program for intensive mutation.
// If another focus job is active, the candidate is queued (up to 8 pending).
// Returns false only if the title was already focused.
func (fuzzer *Fuzzer) AddFocusCandidate(p *prog.Prog, title string, tier int) bool {
	fuzzer.focusMu.Lock()
	defer fuzzer.focusMu.Unlock()

	if fuzzer.focusTitles[title] {
		return false
	}

	// If a focus job is already running, queue this candidate.
	if fuzzer.focusActive {
		if len(fuzzer.focusPending) < 8 {
			fuzzer.focusPending = append(fuzzer.focusPending, focusCandidate{
				prog: p.Clone(), title: title, tier: tier,
			})
			fuzzer.Logf(0, "PROBE: focus queued '%v' (pending: %d)", title, len(fuzzer.focusPending))
		}
		return false
	}

	fuzzer.lastEbpfFocus = time.Now()
	fuzzer.launchFocusJob(p, title, tier)

	// PROBE: Also run fault injection on crash program's calls.
	// Error paths are a major source of UAFs (incomplete cleanup).
	if fuzzer.Config.FaultInjection {
		for i := range p.Calls {
			fuzzer.startJob(fuzzer.statJobsFaultInjection, &faultInjectionJob{
				exec: fuzzer.focusQueue,
				p:    p.Clone(),
				call: i,
			})
		}
		fuzzer.Logf(0, "PROBE: fault injection queued for '%v' (%d calls)", title, len(p.Calls))
	}
	return true
}

// launchFocusJob starts a focus job (caller must hold focusMu).
func (fuzzer *Fuzzer) launchFocusJob(p *prog.Prog, title string, tier int) {
	// Prevent unbounded memory growth in long runs: if too many titles accumulated,
	// reset the dedup set (allows re-focusing old titles, which is acceptable).
	if len(fuzzer.focusTitles) > 10000 {
		fuzzer.focusTitles = map[string]bool{}
	}
	fuzzer.focusTitles[title] = true
	fuzzer.focusActive = true
	fuzzer.focusTarget = title

	var calls []string
	for i := range p.Calls {
		calls = append(calls, p.CallName(i))
	}

	fuzzer.startJob(fuzzer.statJobsFocus, &focusJob{
		exec:  fuzzer.focusQueue,
		p:     p.Clone(),
		title: title,
		tier:  tier,
		info: &JobInfo{
			Name:  p.String(),
			Type:  "focus",
			Calls: calls,
		},
	})
}

// drainFocusPending launches the next queued focus candidate if any.
// Called when a focus job completes. Enforces a 2-minute cooldown between
// consecutive focus jobs to prevent resource starvation from over-triggering.
func (fuzzer *Fuzzer) drainFocusPending() {
	fuzzer.focusMu.Lock()
	defer fuzzer.focusMu.Unlock()

	// Enforce cooldown between focus jobs (prevents back-to-back monopolization).
	if time.Since(fuzzer.lastEbpfFocus) < 2*time.Minute {
		// Clear stale pending to prevent unbounded growth.
		fuzzer.focusPending = nil
		return
	}

	for len(fuzzer.focusPending) > 0 {
		c := fuzzer.focusPending[0]
		fuzzer.focusPending = fuzzer.focusPending[1:]
		if fuzzer.focusTitles[c.title] {
			continue // already focused
		}
		fuzzer.launchFocusJob(c.prog, c.title, c.tier)
		fuzzer.lastEbpfFocus = time.Now()
		fuzzer.Logf(0, "PROBE: focus dequeued '%v' (remaining: %d)", c.title, len(fuzzer.focusPending))
		return
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTable(programs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.RLock()
	defer fuzzer.ctMu.RUnlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

// PROBE: ApplyAIWeights applies LLM-recommended syscall weight adjustments to the ChoiceTable.
func (fuzzer *Fuzzer) ApplyAIWeights(weights map[int]float64) {
	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if fuzzer.ct != nil {
		fuzzer.ct.ApplyWeights(weights)
	}
}

// PROBE: InjectProgram injects an already-parsed program as a triage candidate.
// Used by AI seed hints to inject corpus programs matching requested syscall combinations.
// Note: does NOT use progCandidate flag — AI injections are not counted in CandidatesToTriage()
// to avoid interfering with corpus triage completion detection.
func (fuzzer *Fuzzer) InjectProgram(p *prog.Prog) {
	req := &queue.Request{
		Prog:      p.Clone(),
		ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:      fuzzer.statExecCandidate,
		Important: true,
	}
	fuzzer.enqueue(fuzzer.candidateQueue, req, ProgMinimized|ProgSmashed, 0)
}

// PROBE: InjectSeed parses a syzkaller-format program text and injects it as a triage candidate.
// Note: does NOT use progCandidate flag — AI seeds are not counted in CandidatesToTriage().
func (fuzzer *Fuzzer) InjectSeed(progText string) error {
	p, err := fuzzer.target.Deserialize([]byte(progText), prog.NonStrict)
	if err != nil {
		return err
	}
	req := &queue.Request{
		Prog:      p,
		ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:      fuzzer.statExecCandidate,
		Important: true,
	}
	fuzzer.enqueue(fuzzer.candidateQueue, req, ProgMinimized|ProgSmashed, 0)
	return nil
}

// PROBE: SetAIMutationHints applies LLM mutation hints to future focus jobs.
// Accepts aitriage.MutationHints via interface{} to avoid import cycle.
// The hints struct must have SpliceWeight, InsertWeight, MutateArgWeight, RemoveWeight float64 fields.
func (fuzzer *Fuzzer) SetAIMutationHints(hints interface{}) {
	// Extract fields via JSON round-trip to avoid import cycle with aitriage.
	type mutHints struct {
		SpliceWeight    float64 `json:"splice_weight"`
		InsertWeight    float64 `json:"insert_weight"`
		MutateArgWeight float64 `json:"mutate_arg_weight"`
		RemoveWeight    float64 `json:"remove_weight"`
		Reason          string  `json:"reason"`
	}
	data, err := json.Marshal(hints)
	if err != nil {
		fuzzer.Logf(0, "PROBE: AI mutation hints marshal error: %v", err)
		return
	}
	var mh mutHints
	if err := json.Unmarshal(data, &mh); err != nil {
		fuzzer.Logf(0, "PROBE: AI mutation hints unmarshal error: %v", err)
		return
	}

	defaults := prog.DefaultMutateOpts
	opts := prog.MutateOpts{
		ExpectedIterations: defaults.ExpectedIterations,
		MutateArgCount:     defaults.MutateArgCount,
		SquashWeight:       defaults.SquashWeight,
		SpliceWeight:       int(float64(defaults.SpliceWeight) * mh.SpliceWeight),
		InsertWeight:       int(float64(defaults.InsertWeight) * mh.InsertWeight),
		MutateArgWeight:    int(float64(defaults.MutateArgWeight) * mh.MutateArgWeight),
		RemoveCallWeight:   int(float64(defaults.RemoveCallWeight) * mh.RemoveWeight),
	}
	// Clamp to at least 1 to avoid zero-division.
	if opts.SpliceWeight < 1 {
		opts.SpliceWeight = 1
	}
	if opts.InsertWeight < 1 {
		opts.InsertWeight = 1
	}
	if opts.MutateArgWeight < 1 {
		opts.MutateArgWeight = 1
	}
	if opts.RemoveCallWeight < 1 {
		opts.RemoveCallWeight = 1
	}

	fuzzer.aiMutHintsMu.Lock()
	fuzzer.aiMutHints = &opts
	fuzzer.aiMutHintsMu.Unlock()

	// PROBE: Phase 6 — Push AI base weights to DEzzer (resets DE population).
	if fuzzer.dezzer != nil {
		fuzzer.dezzer.SetAIBaseWeights(opts)
	}

	fuzzer.Logf(0, "PROBE: AI mutation hints applied — splice=%d, insert=%d, mutate_arg=%d, remove=%d (%s)",
		opts.SpliceWeight, opts.InsertWeight, opts.MutateArgWeight, opts.RemoveCallWeight, mh.Reason)
}

// PROBE: getAIMutateOpts returns the layered mutation weights.
// Priority: DEzzer (Default × AI × DE) > AI only > Default.
func (fuzzer *Fuzzer) getAIMutateOpts() prog.MutateOpts {
	if fuzzer.dezzer != nil {
		return fuzzer.dezzer.GetCurrentWeights()
	}
	fuzzer.aiMutHintsMu.Lock()
	hints := fuzzer.aiMutHints
	fuzzer.aiMutHintsMu.Unlock()
	if hints != nil {
		return *hints
	}
	return prog.DefaultMutateOpts
}

// PROBE: Phase 6 — FocusJobResult captures focus job outcomes for AI feedback.
type FocusJobResult struct {
	Title           string         `json:"title"`
	Tier            int            `json:"tier"`
	TotalIters      int            `json:"total_iters"`
	NewCoverage     int            `json:"new_coverage"`
	CoveragePerExec float64        `json:"coverage_per_exec"`
	EarlyExit       bool           `json:"early_exit"`
	OpDistribution  map[string]int `json:"op_distribution"`
	OpCovGains      map[string]int `json:"op_cov_gains"`
	Timestamp       time.Time      `json:"timestamp"`
}

const maxFocusResults = 20

// RecordFocusResult stores a focus job result for AI feedback.
func (fuzzer *Fuzzer) RecordFocusResult(result FocusJobResult) {
	fuzzer.focusResultsMu.Lock()
	defer fuzzer.focusResultsMu.Unlock()
	fuzzer.focusResults = append(fuzzer.focusResults, result)
	if len(fuzzer.focusResults) > maxFocusResults {
		fuzzer.focusResults = fuzzer.focusResults[len(fuzzer.focusResults)-maxFocusResults:]
	}
}

// FocusResults returns a copy of recent focus job results.
func (fuzzer *Fuzzer) FocusResults() []FocusJobResult {
	fuzzer.focusResultsMu.Lock()
	defer fuzzer.focusResultsMu.Unlock()
	out := make([]FocusJobResult, len(fuzzer.focusResults))
	copy(out, fuzzer.focusResults)
	return out
}

// DEzzerSnapshot returns the current DEzzer state, or nil if disabled.
func (fuzzer *Fuzzer) DEzzerSnapshot() *DEzzerSnapshot {
	if fuzzer.dezzer == nil {
		return nil
	}
	snap := fuzzer.dezzer.Snapshot()
	return &snap
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	return flatrpc.ExecOpts{
		ExecFlags: execFlags,
	}
}

// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}

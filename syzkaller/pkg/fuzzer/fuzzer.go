// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	focusDedup     *LRU[uint64, bool] // Phase 14 D21: hash-based dedup (cross-trigger)
	focusActive    bool               // true while a focus job is running
	focusTarget    string             // title of the current focus target
	focusPending   []focusCandidate   // queued candidates waiting for current focus to finish
	lastEbpfFocus  time.Time          // cooldown for eBPF-triggered focus (prevent over-triggering)
	focusExecCount atomic.Int64       // total focus executions (for budget cap)
	totalExecCount atomic.Int64       // total executions (for budget cap)

	// Phase 14 D26: Epoch-based focus budget (5-min reset).
	epochFocusExecs atomic.Int64 // focus execs in current epoch
	epochTotalExecs atomic.Int64 // total execs in current epoch
	epochResetTime  atomic.Value // time.Time of last epoch reset

	// PROBE: AI mutation hints for focus jobs.
	aiMutHintsMu sync.Mutex
	aiMutHints   *prog.MutateOpts // nil = use default

	// PROBE: Phase 6 — DEzzer optimizer and focus feedback.
	dezzer       *DEzzer
	focusResultsMu sync.Mutex
	focusResults   []FocusJobResult

	// PROBE: Phase 8d — MOCK BiGRU client for context-aware insertCall.
	ngramClient *NgramClient
	anamnesis   *AnamnesisAssessor // Phase 9e: exploit assessment

	// PROBE: Phase 8f — ablation cache for effective component inference.
	ablationCache *LRU[string, []bool] // LRU cache: crash title → essential mask (Phase 11g)

	// PROBE: Phase 11i — LACE race detection Focus queue (independent from memory focus).
	lastRaceFocus      time.Time    // 3-minute cooldown, separate from memory 5-min cooldown
	raceThreshold      uint32       // starts at 0, auto-set to P90 after 24h
	raceSchedThreshold uint32       // sched_switch threshold
	raceFocusPending   []focusCandidate // independent race Focus queue (max 2)
	raceStartTime      time.Time    // when LACE started (for 24h threshold logic)

	// PROBE: Phase 11j — LinUCB delay pattern bandit (separate from DEzzer).
	linucb       *LinUCB
	delayedExecs atomic.Int64 // total executions with delay applied
	delayTotal   atomic.Int64 // total executions considered for delay

	// PROBE: Phase 11k — Global Thompson Sampling for schedule strategy.
	schedTS *SchedTS

	// PROBE: Phase 11l — Bayesian Optimization for hyperparameter tuning.
	bayesOpt *BayesOpt

	// PROBE: Phase 15 — BO-tunable parameters (atomic for lock-free access).
	boFocusBudgetPct  atomic.Int64 // focus budget cap percentage (default 30, BO param[1])
	boSmashExplorePct atomic.Int64 // explore probability percentage (default 0 = use hardcoded 0.95 mutate rate)

	// PROBE: Phase 12 A2 — last mutation operator for pair TS conditioning.
	lastMutOp atomic.Value // stores string; ~15ns per Load/Store

	// PROBE: Phase 11b — Shannon entropy for coverage plateau detection.
	coverageEntropy     atomic.Int64 // fixed-point x1000
	entropyCheckCounter atomic.Int64

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

		focusDedup:    NewLRU[uint64, bool](10000),
		ablationCache: NewLRU[string, []bool](2000),
		raceStartTime: time.Now(),
	}
	f.epochResetTime.Store(time.Now()) // Phase 14 D26: Initialize epoch timer
	f.boFocusBudgetPct.Store(30)       // Phase 15: default focus budget cap 30%
	f.dezzer = NewDEzzer(f.Logf)
	f.dezzer.entropyRef = &f.coverageEntropy  // Phase 12 B1: lock-free entropy access
	f.dezzer.configVersion = 2                 // Phase 14 W1-D4: v2 = 10 clusters (was 6)
	f.dezzer.statPairTSFallback = f.statPairTSFallback // Phase 12 B4: pair TS fallback counter
	f.dezzer.StartNormalization(ctx)           // Phase 12 A5: periodic normalization goroutine (60s)
	f.dezzer.StartAutoExport(ctx, cfg.Workdir) // Phase 12 B2: periodic feature log export (2min)
	f.linucb = NewLinUCB() // Phase 11j: LinUCB delay pattern bandit
	f.schedTS = NewSchedTS()       // Phase 11k: Global Thompson Sampling for schedule strategy
	f.bayesOpt = NewBayesOpt(cfg.Logf) // Phase 11l: Bayesian Optimization for hyperparameter tuning
	// Phase 12 C3: BO warm-start — load saved params and set save path.
	if cfg.Workdir != "" {
		boPath := cfg.Workdir + "/bo-params.json"
		f.bayesOpt.LoadState(boPath, "", 0) // kernelHash/corpusSize wired later when available
		f.bayesOpt.SetSavePath(boPath)
	}
	// Phase 8d: MOCK BiGRU client (Phase 14 D3: use config addr if provided)
	f.ngramClient = NewNgramClient(cfg.NgramAddr, f.Logf)
	f.anamnesis = NewAnamnesisAssessor(f.Logf)  // Phase 9e: exploit assessment
	go func() {
		<-ctx.Done()
		f.ngramClient.Stop()
		// Phase 12 C3: Save BO state on shutdown.
		if cfg.Workdir != "" && f.bayesOpt != nil {
			f.bayesOpt.SaveState(cfg.Workdir + "/bo-params.json")
		}
	}()
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
		queue.Alternate(ret.focusQueue, 4), // PROBE: focus every 4th request (Phase 11g: 25% bandwidth)
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
	// Phase 11g: track execution counts for focus budget cap.
	fuzzer.totalExecCount.Add(1)
	fuzzer.epochTotalExecs.Add(1) // Phase 14 D26: epoch counter
	if req.Stat == fuzzer.statExecFocus {
		fuzzer.focusExecCount.Add(1)
		fuzzer.epochFocusExecs.Add(1) // Phase 14 D26: epoch counter
	}

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

		// PROBE: Phase 6 — feed DEzzer from async mutateProgRequest results.
		// Only for statExecFuzz (mutateProgRequest); smashJob/focusJob feed directly.
		if req.MutOp != "" && fuzzer.dezzer != nil && req.Stat == fuzzer.statExecFuzz {
			covGain := 0
			if len(triage) > 0 {
				covGain = len(triage)
			}
			// Phase 12 A2: Pass req.MutOp as prevOp for pair TS conditioning.
			// Phase 12 B1: Pass actual cluster for FeatureTuple enrichment.
			cluster := classifyProgram(req.Prog)
			fuzzer.dezzer.RecordResult(req.MutOp, req.MutOp, req.SubOp, covGain, SourceMutate, cluster)
		}

		// PROBE: Phase 15 — UCB-1 feedback: record BiGRU vs ChoiceTable success.
		if fuzzer.ngramClient != nil && req.Stat == fuzzer.statExecFuzz {
			success := len(triage) > 0
			if req.UsedBiGRU {
				fuzzer.ngramClient.RecordBiGRUResult(success)
			} else {
				fuzzer.ngramClient.RecordCTResult(success)
			}
		}

		if len(triage) != 0 {
			// PROBE: H2 fix — track which mutation operators produce coverage gains.
			if req.MutOp != "" {
				fuzzer.statMutOpCovGain.Add(1)
			}
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
		// H3 fix: track free and rapid-reuse counts.
		if res.Info.EbpfFreeCount > 0 {
			fuzzer.statEbpfFrees.Add(int(res.Info.EbpfFreeCount))
		}
		if res.Info.EbpfRapidReuseCount > 0 {
			fuzzer.statEbpfRapidReuse.Add(int(res.Info.EbpfRapidReuseCount))
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
		// Phase 8a: Write-to-freed detection.
		if res.Info.EbpfWriteToFreedCount > 0 {
			fuzzer.statEbpfWriteToFreed.Add(int(res.Info.EbpfWriteToFreedCount))
		}

		// Cooldown check shared by double-free and UAF focus triggers.
		fuzzer.focusMu.Lock()
		ebpfCooldownOk := time.Since(fuzzer.lastEbpfFocus) >= 5*time.Minute
		fuzzer.focusMu.Unlock()

		// PROBE: Best-of-N Focus trigger — only the highest-priority trigger from
		// a single execution becomes a Focus candidate. Prevents cascading 4x bursts.
		// Priority: 1=double-free, 2=priv-esc, 3=write-to-freed, 4=UAF, 5=cross-cache,
		//           6=page-uaf, 7=fd-reuse, 8=anamnesis.
		bestFocusPriority := 99
		bestFocusTitle := ""
		bestFocusTier := 1

		// Double-free: trigger Focus (with cooldown to prevent over-triggering).
		if res.Info.EbpfDoubleFreeCount > 0 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.Logf(0, "PROBE: eBPF detected DOUBLE-FREE (count=%d) in %s",
				res.Info.EbpfDoubleFreeCount, req.Prog)
			if 1 < bestFocusPriority {
				bestFocusPriority = 1
				bestFocusTitle = fmt.Sprintf("PROBE:ebpf-double-free:%s", req.Prog.String())
				bestFocusTier = 1
			}
		}
		// Non-crashing UAF detection: high UAF score without crash → UAF-favorable pattern.
		// P0-2 fix: count UAF detections unconditionally (outside cooldown check).
		if res.Info.EbpfUafScore >= 70 && res.Status != queue.Hanged {
			fuzzer.statEbpfUafDetected.Add(1)
		}
		if res.Info.EbpfUafScore >= 70 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.Logf(0, "PROBE: eBPF detected UAF-favorable pattern (score=%d, reuse=%d, rapid=%d) in %s",
				res.Info.EbpfUafScore, res.Info.EbpfReuseCount,
				res.Info.EbpfRapidReuseCount, req.Prog)
			if 4 < bestFocusPriority {
				bestFocusPriority = 4
				bestFocusTitle = fmt.Sprintf("PROBE:ebpf-uaf:%s", req.Prog.String())
				bestFocusTier = 1
			}
		}
		// Phase 7d: Privilege escalation — top priority focus trigger.
		if res.Info.EbpfPrivEscCount > 0 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.Logf(0, "PROBE: eBPF detected PRIVILEGE ESCALATION (priv_esc=%d, commit_creds=%d) in %s",
				res.Info.EbpfPrivEscCount, res.Info.EbpfCommitCredsCount, req.Prog)
			if 2 < bestFocusPriority {
				bestFocusPriority = 2
				bestFocusTitle = "PROBE:priv-esc"
				bestFocusTier = 1
			}
		}
		// Phase 7c: Precise cross-cache detection — trigger focus (min threshold 50).
		if res.Info.EbpfCrossCacheCount >= 50 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.Logf(0, "PROBE: eBPF detected CROSS-CACHE reallocation (count=%d) in %s",
				res.Info.EbpfCrossCacheCount, req.Prog)
			if 5 < bestFocusPriority {
				bestFocusPriority = 5
				bestFocusTitle = fmt.Sprintf("PROBE:ebpf-cross-cache:%s", req.Prog.String())
				bestFocusTier = 1
			}
		}
		// Phase 8a: Write to freed object — strong exploitability signal.
		if res.Info.EbpfWriteToFreedCount > 0 && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.Logf(0, "PROBE: eBPF detected WRITE-TO-FREED (count=%d, score=%d) in %s",
				res.Info.EbpfWriteToFreedCount, res.Info.EbpfUafScore, req.Prog)
			if 3 < bestFocusPriority {
				bestFocusPriority = 3
				bestFocusTitle = fmt.Sprintf("PROBE:ebpf-write-to-freed:%s", req.Prog.String())
				bestFocusTier = 1
			}
		}
		// Phase 9b: Page-level UAF / Dirty Pagetable detection.
		if res.Info.EbpfPageAllocCount > 0 {
			fuzzer.statEbpfPageAllocs.Add(int(res.Info.EbpfPageAllocCount))
		}
		if res.Info.EbpfPageReuseCount > 0 {
			fuzzer.statEbpfPageReuses.Add(int(res.Info.EbpfPageReuseCount))
		}
		// H3 fix: track page free count.
		if res.Info.EbpfPageFreeCount > 0 {
			fuzzer.statEbpfPageFrees.Add(int(res.Info.EbpfPageFreeCount))
		}
		// Phase 14 D7: configurable threshold (default 60).
		pageUafThreshold := fuzzer.Config.PageUafThreshold
		if pageUafThreshold == 0 {
			pageUafThreshold = 60
		}
		if res.Info.EbpfPageUafScore >= uint32(pageUafThreshold) && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.statEbpfPageUaf.Add(1)
			fuzzer.Logf(0, "PROBE: eBPF detected PAGE-LEVEL UAF pattern (page_score=%d, page_reuse=%d) in %s",
				res.Info.EbpfPageUafScore, res.Info.EbpfPageReuseCount, req.Prog)
			if 6 < bestFocusPriority {
				bestFocusPriority = 6
				bestFocusTitle = fmt.Sprintf("PROBE:ebpf-page-uaf:%s", req.Prog.String())
				bestFocusTier = 1
			}
		}

		// Phase 9d: FD lifecycle tracking.
		if res.Info.EbpfFdInstallCount > 0 {
			fuzzer.statEbpfFdInstalls.Add(int(res.Info.EbpfFdInstallCount))
		}
		if res.Info.EbpfFdCloseCount > 0 {
			fuzzer.statEbpfFdCloses.Add(int(res.Info.EbpfFdCloseCount))
		}
		// Phase 14 D7: configurable threshold (default 60).
		fdReuseThreshold := fuzzer.Config.FdReuseThreshold
		if fdReuseThreshold == 0 {
			fdReuseThreshold = 60
		}
		if res.Info.EbpfFdReuseScore >= uint32(fdReuseThreshold) && res.Status != queue.Hanged && ebpfCooldownOk {
			fuzzer.statEbpfFdReuse.Add(1)
			fuzzer.Logf(0, "PROBE: eBPF detected FD REUSE pattern (fd_score=%d, fd_reuse=%d) in %s",
				res.Info.EbpfFdReuseScore, res.Info.EbpfFdReuseCount, req.Prog)
			if 7 < bestFocusPriority {
				bestFocusPriority = 7
				bestFocusTitle = fmt.Sprintf("PROBE:ebpf-fd-reuse:%s", req.Prog.String())
				bestFocusTier = 1
			}
		}

		// Phase 9c: Context-sensitive coverage diversity.
		if res.Info.EbpfContextStacks > 0 {
			fuzzer.statEbpfContextStacks.Add(int(res.Info.EbpfContextStacks))
		}

		// Phase 11i: LACE race condition detection.
		if res.Info.EbpfLockContention > 0 {
			fuzzer.statRaceLockContention.Add(int(res.Info.EbpfLockContention))
		}
		if res.Info.EbpfSchedSwitch > 0 {
			fuzzer.statRaceSchedSwitch.Add(int(res.Info.EbpfSchedSwitch))
		}
		if res.Info.EbpfConcurrentAccess > 0 {
			fuzzer.statRaceConcurrentAccess.Add(int(res.Info.EbpfConcurrentAccess))
		}
		// LACE race Focus trigger (independent 3-min cooldown, separate from memory 5-min).
		// First 24 hours: threshold=0 (log all contention>0), after 24h use raceThreshold (P90).
		if res.Info.EbpfLockContention > 0 && res.Status != queue.Hanged {
			fuzzer.focusMu.Lock()
			raceCooldownOk := time.Since(fuzzer.lastRaceFocus) >= 3*time.Minute
			raceThresh := fuzzer.raceThreshold
			fuzzer.focusMu.Unlock()

			if res.Info.EbpfLockContention > raceThresh &&
				res.Info.EbpfConcurrentAccess > 0 &&
				raceCooldownOk {
				fuzzer.statRaceCandidates.Add(1)
				raceTitle := fmt.Sprintf("PROBE:lace-race:%s", req.Prog.String())
				fuzzer.Logf(0, "PROBE: LACE race detected (lock_contention=%d, concurrent=%d, sched=%d) in %s",
					res.Info.EbpfLockContention, res.Info.EbpfConcurrentAccess,
					res.Info.EbpfSchedSwitch, req.Prog)
				// Submit to race Focus queue (independent from memory focus).
				fuzzer.focusMu.Lock()
				fuzzer.lastRaceFocus = time.Now()
				if len(fuzzer.raceFocusPending) < 2 {
					fuzzer.raceFocusPending = append(fuzzer.raceFocusPending, focusCandidate{
						prog: req.Prog.Clone(), title: raceTitle, tier: 1,
					})
				}
				fuzzer.focusMu.Unlock()
				// Also submit to the main best-of-N system with priority 9.
				if 9 < bestFocusPriority {
					bestFocusPriority = 9
					bestFocusTitle = raceTitle
					bestFocusTier = 1
				}
			}
		}

		// PROBE: Phase 11j — LinUCB delay feedback.
		if fuzzer.linucb != nil && req.DelayPattern >= 0 {
			features := fuzzer.buildDelayFeatures(req.Prog, req.Stat == fuzzer.statExecFocus)
			reward := 0.0
			// Reward: sched_switch activity + coverage gain indicates delay effectiveness.
			if res.Info.EbpfSchedSwitch > 5 {
				reward += 0.5
			}
			if len(triage) > 0 {
				reward += 0.5
			}
			// Concurrent access is a strong signal of race window creation.
			if res.Info.EbpfConcurrentAccess > 0 {
				reward += 0.5
			}
			if reward > 1.0 {
				reward = 1.0
			}
			fuzzer.linucb.Update(req.DelayPattern, features, reward)
		}

		// PROBE: Phase 11k — SchedTS feedback.
		if fuzzer.schedTS != nil && req.SchedArm >= 0 {
			reward := 0.0
			if len(triage) > 0 {
				reward = math.Min(float64(len(triage))/10.0, 1.0)
			}
			fuzzer.schedTS.Update(req.SchedArm, reward)
		}

		// PROBE: Phase 11l — periodic BO epoch check.
		if fuzzer.bayesOpt != nil && fuzzer.bayesOpt.IsActive() {
			covTotal := int64(fuzzer.Cover.MaxSignalLen())
			if fuzzer.bayesOpt.CheckEpoch(covTotal) {
				params := fuzzer.bayesOpt.GetCurrentParams()
				fuzzer.applyBOParams(params)
				fuzzer.statBOEpoch.Add(1)
				fuzzer.statBORate.Add(int(fuzzer.bayesOpt.BOBestValue() * 1000))
			}
		}

		// Phase 9 diagnostic: log raw page/FD/context metrics when non-trivial.
		if res.Info.EbpfPageAllocCount > 10 || res.Info.EbpfFdInstallCount > 10 || res.Info.EbpfContextStacks > 0 {
			fuzzer.Logf(2, "PROBE: Phase9 raw: page(a=%d f=%d r=%d s=%d) fd(i=%d c=%d r=%d s=%d) ctx=%d",
				res.Info.EbpfPageAllocCount, res.Info.EbpfPageFreeCount,
				res.Info.EbpfPageReuseCount, res.Info.EbpfPageUafScore,
				res.Info.EbpfFdInstallCount, res.Info.EbpfFdCloseCount,
				res.Info.EbpfFdReuseCount, res.Info.EbpfFdReuseScore,
				res.Info.EbpfContextStacks)
		}

		// Phase 9e: Anamnesis composite exploit assessment.
		// Evaluates all eBPF signals together for a holistic exploitability score.
		// Quick-skip: only run when at least one eBPF anomaly signal is non-zero.
		hasEbpfSignal := res.Info.EbpfReuseCount > 0 || res.Info.EbpfDoubleFreeCount > 0 ||
			res.Info.EbpfCrossCacheCount > 0 || res.Info.EbpfWriteToFreedCount > 0 ||
			res.Info.EbpfPrivEscCount > 0 || res.Info.EbpfPageReuseCount > 0 ||
			res.Info.EbpfFdReuseCount > 0 || res.Info.EbpfPageUafScore >= 60 ||
			res.Info.EbpfFdReuseScore >= 60
		if fuzzer.anamnesis != nil && ebpfCooldownOk && hasEbpfSignal {
			assessment := fuzzer.anamnesis.Assess(res.Info)
			if assessment.Score >= 40 {
				fuzzer.statAnamnesisAssessed.Add(1)
			}
			if assessment.ShouldFocus && res.Status != queue.Hanged {
				fuzzer.statAnamnesisFocused.Add(1)
				fuzzer.Logf(0, "PROBE: Anamnesis exploit assessment: score=%d class=%d tier=%d [%s] in %s",
					assessment.Score, assessment.Class, assessment.FocusTier, assessment.Summary, req.Prog)
				if 8 < bestFocusPriority {
					bestFocusPriority = 8
					bestFocusTitle = fmt.Sprintf("PROBE:anamnesis:%s", req.Prog.String())
					bestFocusTier = assessment.FocusTier
				}
			}

			// Phase 14 D9: Apply Anamnesis bonus to DEzzer mutation optimizer.
			if assessment.Score >= 40 && req.MutOp != "" && fuzzer.dezzer != nil {
				cluster := classifyProgram(req.Prog)
				mult := 1.2
				if assessment.ShouldFocus {
					mult = 1.5
				}
				if assessment.FocusTier == 1 {
					mult = 2.0
				}
				fuzzer.dezzer.RecordAnamnesisBonus(req.MutOp, cluster, mult)
			}
		}

		// Submit only the single best Focus candidate from this execution.
		if bestFocusTitle != "" {
			fuzzer.AddFocusCandidate(req.Prog, bestFocusTitle, bestFocusTier)
		}
		_ = bestFocusPriority // used in comparisons above
	}

	// PROBE: DEzzer crash bonus — reward the operator that led to a crash.
	if res.Status == queue.Crashed && req.MutOp != "" && fuzzer.dezzer != nil {
		fuzzer.dezzer.RecordCrash(req.MutOp)
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
	Workdir        string // Phase 12 B2: workdir for auto-export feature log
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

	// PROBE Phase 14: D3 — ngram server address configuration.
	NgramAddr string
	// PROBE Phase 14: D7 — Page-UAF and FD-reuse thresholds.
	PageUafThreshold int
	FdReuseThreshold int
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
	// Phase 15: Apply BO-tuned explore probability when active.
	if explorePct := fuzzer.boSmashExplorePct.Load(); explorePct > 0 {
		mutateRate = 1.0 - float64(explorePct)/100.0
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

// Phase 14 D21+D27: Hash-based focus dedup with cross-trigger deduplication.
// Hashes the program itself (not the title), so the same program is deduped
// even if it triggers different exploit patterns (e.g., "double-free" vs "UAF").
// This prevents redundant focus on semantically identical programs.
func focusProgHash(p *prog.Prog) uint64 {
	h := fnv.New64a()
	data := p.Serialize()
	h.Write(data)
	return h.Sum64()
}

// PROBE: AddFocusCandidate queues a high-severity crash program for intensive mutation.
// If another focus job is active, the candidate is queued (up to 4 pending, Phase 11g).
// Phase 14 D21+D27: Returns false if program hash was already focused (cross-trigger dedup).
func (fuzzer *Fuzzer) AddFocusCandidate(p *prog.Prog, title string, tier int) bool {
	fuzzer.focusMu.Lock()
	defer fuzzer.focusMu.Unlock()

	hash := focusProgHash(p)
	if fuzzer.focusDedup.Contains(hash) {
		return false
	}

	// If a focus job is already running, queue this candidate.
	if fuzzer.focusActive {
		if len(fuzzer.focusPending) < 4 {
			fuzzer.focusPending = append(fuzzer.focusPending, focusCandidate{
				prog: p.Clone(), title: title, tier: tier,
			})
			fuzzer.Logf(0, "PROBE: focus queued '%v' (pending: %d)", title, len(fuzzer.focusPending))
		} else {
			fuzzer.statFocusDropped.Add(1)
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
	// Phase 14 D21: Store hash instead of title for cross-trigger dedup.
	hash := focusProgHash(p)
	fuzzer.focusDedup.Put(hash, true)
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
	// Phase 14 D26: Epoch-based focus budget (5-min reset).
	epochReset := fuzzer.epochResetTime.Load().(time.Time)
	if time.Since(epochReset) > 5*time.Minute {
		// Reset epoch counters every 5 minutes
		fuzzer.epochFocusExecs.Store(0)
		fuzzer.epochTotalExecs.Store(0)
		fuzzer.epochResetTime.Store(time.Now())
	}

	// Check epoch budget first (30% cap per 5-min window)
	epochTotal := fuzzer.epochTotalExecs.Load()
	epochFocus := fuzzer.epochFocusExecs.Load()
	budgetPct := fuzzer.boFocusBudgetPct.Load() // Phase 15: BO-tunable focus budget
	if epochTotal > 100 && epochFocus*100/epochTotal > budgetPct {
		fuzzer.statFocusBudgetSkip.Add(1)
		time.AfterFunc(time.Minute, func() {
			fuzzer.drainFocusPending()
		})
		return
	}

	// Phase 11g: Lifetime budget cap (secondary guardrail) — skip if focus exceeds 30% of total executions.
	total := fuzzer.totalExecCount.Load()
	focusExecs := fuzzer.focusExecCount.Load()
	if total > 1000 && focusExecs*100/total > budgetPct {
		fuzzer.statFocusBudgetSkip.Add(1)
		// Retry after 1 minute.
		time.AfterFunc(time.Minute, func() {
			fuzzer.drainFocusPending()
		})
		return
	}

	fuzzer.focusMu.Lock()
	defer fuzzer.focusMu.Unlock()

	// Enforce cooldown between focus jobs (prevents back-to-back monopolization).
	if time.Since(fuzzer.lastEbpfFocus) < 2*time.Minute {
		// H6 fix: schedule a timer to retry after cooldown expires,
		// preventing candidates from being orphaned in the pending queue.
		if len(fuzzer.focusPending) > 0 {
			remaining := 2*time.Minute - time.Since(fuzzer.lastEbpfFocus) + time.Second
			time.AfterFunc(remaining, func() {
				fuzzer.drainFocusPending()
			})
		}
		return
	}

	for len(fuzzer.focusPending) > 0 {
		c := fuzzer.focusPending[0]
		fuzzer.focusPending = fuzzer.focusPending[1:]
		hash := focusProgHash(c.prog)
		if fuzzer.focusDedup.Contains(hash) {
			continue // already focused (D21+D27: cross-trigger dedup)
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
	// H1 fix: track SyzGPT injected programs in stats.
	fuzzer.statSyzGPTInjected.Add(1)
	req := &queue.Request{
		Prog:      p.Clone(),
		ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:      fuzzer.statExecCandidate,
		Important: true,
	}
	fuzzer.enqueue(fuzzer.candidateQueue, req, ProgMinimized|ProgSmashed, 0)
}

// RecordSyzGPTGenerated increments the SyzGPT generated counter.
// Called from AI triage when the LLM produces a program (even if invalid).
func (fuzzer *Fuzzer) RecordSyzGPTGenerated() {
	fuzzer.statSyzGPTGenerated.Add(1)
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
	// Extract fields via type assertion to avoid import cycle with aitriage.
	type mutHints struct {
		SpliceWeight    float64
		InsertWeight    float64
		MutateArgWeight float64
		RemoveWeight    float64
		Reason          string
	}
	// Type assert and copy fields directly
	src, ok := hints.(struct {
		SpliceWeight    float64
		InsertWeight    float64
		MutateArgWeight float64
		RemoveWeight    float64
		Reason          string
	})
	if !ok {
		fuzzer.Logf(0, "PROBE: AI mutation hints type assertion failed")
		return
	}
	mh := mutHints{
		SpliceWeight:    src.SpliceWeight,
		InsertWeight:    src.InsertWeight,
		MutateArgWeight: src.MutateArgWeight,
		RemoveWeight:    src.RemoveWeight,
		Reason:          src.Reason,
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
// Phase 8b: prevOp enables pair-conditioned TS. Phase 8e: cluster enables per-subsystem TS.
// Priority: DEzzer (Default × AI × PairTS/ClusterTS/GlobalTS × DE) > AI only > Default.
func (fuzzer *Fuzzer) getAIMutateOpts(prevOp string, cluster int) prog.MutateOpts {
	var opts prog.MutateOpts
	if fuzzer.dezzer != nil {
		opts = fuzzer.dezzer.GetCurrentWeightsForPair(prevOp, cluster)
	} else {
		fuzzer.aiMutHintsMu.Lock()
		hints := fuzzer.aiMutHints
		fuzzer.aiMutHintsMu.Unlock()
		if hints != nil {
			opts = *hints
		} else {
			opts = prog.DefaultMutateOpts
		}
	}

	// Phase 8d: Attach BiGRU prediction callback if server is healthy and UCB-1 favors it.
	if fuzzer.ngramClient != nil && fuzzer.ngramClient.ShouldUseBiGRU() {
		opts.PredictCall = func(calls []string) (string, float64) {
			name, conf, _ := fuzzer.ngramClient.PredictNextCall(calls)
			return name, conf
		}
	}

	return opts
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

// Phase 8f: Ablation cache for effective component inference.
// Maps crash title → essential syscall mask (true = essential for crash reproduction).
func (fuzzer *Fuzzer) getOrComputeAblation(exec queue.Executor, p *prog.Prog, title string, rnd *rand.Rand) []bool {
	// Phase 11g: Use LRU cache (automatic eviction, no manual reset).
	if cached, ok := fuzzer.ablationCache.Get(title); ok {
		return cached
	}

	result := fuzzer.computeAblation(exec, p, rnd)
	fuzzer.ablationCache.Put(title, result)

	essentialCount := 0
	for _, e := range result {
		if e {
			essentialCount++
		}
	}
	fuzzer.Logf(0, "PROBE: ablation for '%s': %d/%d calls essential", title, essentialCount, len(result))
	return result
}

// computeAblation identifies essential syscalls by removing each one and checking
// if the crash/coverage behavior changes. Essential calls are those whose removal
// reduces the program's effectiveness.
func (fuzzer *Fuzzer) computeAblation(exec queue.Executor, p *prog.Prog, rnd *rand.Rand) []bool {
	essential := make([]bool, len(p.Calls))
	for i := range essential {
		essential[i] = true // default: all essential
	}

	// Baseline: execute original program 3 times to get stable signal.
	var baselineSignal signal.Signal
	for rep := 0; rep < 3; rep++ {
		result := fuzzer.execute(exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:     fuzzer.statExecFocus,
		})
		if result.Stop() {
			return essential
		}
		if result.Info != nil {
			for _, ci := range result.Info.Calls {
				if ci != nil {
					thisSignal := signal.FromRaw(ci.Signal, 0)
					if baselineSignal == nil {
						baselineSignal = thisSignal
					} else {
						baselineSignal.Merge(thisSignal)
					}
				}
			}
		}
	}

	baselineLen := baselineSignal.Len()
	if baselineLen == 0 {
		return essential
	}

	// Try removing each call and compare signal.
	for i := range p.Calls {
		if len(p.Calls) <= 1 {
			break // cannot remove the only call
		}

		test := p.Clone()
		test.RemoveCall(i)
		if len(test.Calls) == 0 {
			continue
		}

		// Execute ablated program.
		var ablatedSignal signal.Signal
		significantLoss := false
		for rep := 0; rep < 3; rep++ {
			result := fuzzer.execute(exec, &queue.Request{
				Prog:     test,
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:     fuzzer.statExecFocus,
			})
			if result.Stop() {
				return essential
			}
			if result.Info != nil {
				for _, ci := range result.Info.Calls {
					if ci != nil {
						thisSignal := signal.FromRaw(ci.Signal, 0)
						if ablatedSignal == nil {
							ablatedSignal = thisSignal
						} else {
							ablatedSignal.Merge(thisSignal)
						}
					}
				}
			}
		}

		// If removing this call loses significant signal, it's essential.
		ablatedLen := ablatedSignal.Len()
		if ablatedLen >= baselineLen*80/100 {
			// Losing <20% signal → this call is non-essential.
			significantLoss = false
		} else {
			significantLoss = true
		}

		if !significantLoss {
			essential[i] = false
		}
	}

	return essential
}

// essentialMutate creates a mutated program focused on essential calls.
// Non-essential calls are preserved but not mutated — mutation budget is concentrated
// on essential calls to maximize crash reproduction/exploitation.
func (fuzzer *Fuzzer) essentialMutate(p *prog.Prog, essential []bool, rnd *rand.Rand, opts prog.MutateOpts) (*prog.Prog, string) {
	// Build noMutate map: block mutation of non-essential calls.
	// H5 fix: only block a syscall ID if it does NOT appear at any essential position,
	// otherwise we'd accidentally block essential calls sharing the same syscall ID.
	noMutate := make(map[int]bool)
	for k, v := range fuzzer.Config.NoMutateCalls {
		noMutate[k] = v
	}
	essentialIDs := make(map[int]bool)
	for i, e := range essential {
		if e && i < len(p.Calls) {
			essentialIDs[p.Calls[i].Meta.ID] = true
		}
	}
	for i, e := range essential {
		if !e && i < len(p.Calls) {
			sid := p.Calls[i].Meta.ID
			if !essentialIDs[sid] {
				noMutate[sid] = true
			}
		}
	}

	clone := p.Clone()
	op := clone.MutateWithOpts(rnd, prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		noMutate,
		fuzzer.Config.Corpus.Programs(),
		opts)
	if op == "" {
		return nil, ""
	}
	return clone, op
}

// Phase 8c: recordObjectiveReward computes and records reward based on current objective.
func (fuzzer *Fuzzer) recordObjectiveReward(info *flatrpc.ProgInfo, covGain int) {
	if fuzzer.dezzer == nil {
		return
	}
	obj := fuzzer.dezzer.CurrentObjective()
	var reward float64
	switch obj {
	case ObjCoverage:
		if covGain > 0 {
			reward = 1.0
		}
	case ObjMemorySafety:
		if info.EbpfUafScore > 0 {
			reward += float64(info.EbpfUafScore) / 100.0
		}
		if info.EbpfCrossCacheCount > 0 {
			reward += 0.5
		}
		if info.EbpfDoubleFreeCount > 0 {
			reward += 0.8
		}
		if info.EbpfWriteToFreedCount > 0 {
			reward += 1.0
		}
	case ObjPrivEsc:
		if info.EbpfPrivEscCount > 0 {
			reward = 1.0
		}
	}
	if reward > 0 {
		fuzzer.dezzer.RecordObjectiveReward(reward)
	}
}

// Phase 8e: Kernel subsystem cluster constants.
const (
	ClusterFS      = 0
	ClusterNet     = 1
	ClusterMM      = 2
	ClusterIPC     = 3
	ClusterDevice  = 4
	ClusterOther   = 5
	ClusterIOURING = 6
	ClusterBPF     = 7
	ClusterKEYCTL  = 8
	ClusterOther2  = 9
)

// classifyProgram determines the dominant kernel subsystem cluster for a program.
func classifyProgram(p *prog.Prog) int {
	var counts [numClusters]int
	for _, c := range p.Calls {
		name := c.Meta.Name
		switch {
		case isFS(name):
			counts[ClusterFS]++
		case isNet(name):
			counts[ClusterNet]++
		case isMM(name):
			counts[ClusterMM]++
		case isIPC(name):
			counts[ClusterIPC]++
		case isDevice(name):
			counts[ClusterDevice]++
		case isIOURING(name):
			counts[ClusterIOURING]++
		case isBPF(name):
			counts[ClusterBPF]++
		case isKEYCTL(name):
			counts[ClusterKEYCTL]++
		default:
			counts[ClusterOther2]++
		}
	}
	best := ClusterOther2
	for i, c := range counts {
		if c > counts[best] {
			best = i
		}
	}
	return best
}

func isFS(name string) bool {
	return strings.HasPrefix(name, "open") || strings.HasPrefix(name, "read") ||
		strings.HasPrefix(name, "write") || strings.HasPrefix(name, "close") ||
		strings.HasPrefix(name, "stat") || strings.HasPrefix(name, "fstat") ||
		strings.HasPrefix(name, "lstat") || strings.HasPrefix(name, "mkdir") ||
		strings.HasPrefix(name, "rmdir") || strings.HasPrefix(name, "unlink") ||
		strings.HasPrefix(name, "rename") || strings.HasPrefix(name, "lseek") ||
		strings.HasPrefix(name, "fsync") || strings.HasPrefix(name, "fchmod") ||
		strings.HasPrefix(name, "fchown") || strings.HasPrefix(name, "mount") ||
		strings.HasPrefix(name, "umount") || strings.HasPrefix(name, "fallocate") ||
		strings.HasPrefix(name, "truncate") || strings.HasPrefix(name, "ftruncate") ||
		strings.HasPrefix(name, "link") || strings.HasPrefix(name, "symlink") ||
		strings.HasPrefix(name, "readlink") || strings.HasPrefix(name, "getdents") ||
		strings.HasPrefix(name, "pread") || strings.HasPrefix(name, "pwrite") ||
		strings.HasPrefix(name, "sendfile") || strings.HasPrefix(name, "splice") ||
		strings.HasPrefix(name, "copy_file_range")
}

func isNet(name string) bool {
	return strings.HasPrefix(name, "socket") || strings.HasPrefix(name, "bind") ||
		strings.HasPrefix(name, "listen") || strings.HasPrefix(name, "accept") ||
		strings.HasPrefix(name, "connect") || strings.HasPrefix(name, "send") ||
		strings.HasPrefix(name, "recv") || strings.HasPrefix(name, "getsockopt") ||
		strings.HasPrefix(name, "setsockopt") || strings.HasPrefix(name, "getsockname") ||
		strings.HasPrefix(name, "getpeername") || strings.HasPrefix(name, "shutdown") ||
		strings.HasPrefix(name, "socketpair")
}

func isMM(name string) bool {
	return strings.HasPrefix(name, "mmap") || strings.HasPrefix(name, "munmap") ||
		strings.HasPrefix(name, "mprotect") || strings.HasPrefix(name, "madvise") ||
		strings.HasPrefix(name, "brk") || strings.HasPrefix(name, "mremap") ||
		strings.HasPrefix(name, "msync") || strings.HasPrefix(name, "mincore") ||
		strings.HasPrefix(name, "mlock") || strings.HasPrefix(name, "munlock") ||
		strings.HasPrefix(name, "remap_file_pages") || strings.HasPrefix(name, "mbind") ||
		strings.HasPrefix(name, "get_mempolicy") || strings.HasPrefix(name, "set_mempolicy")
}

func isIPC(name string) bool {
	return strings.HasPrefix(name, "pipe") || strings.HasPrefix(name, "shmget") ||
		strings.HasPrefix(name, "shmat") || strings.HasPrefix(name, "shmdt") ||
		strings.HasPrefix(name, "shmctl") || strings.HasPrefix(name, "semget") ||
		strings.HasPrefix(name, "semop") || strings.HasPrefix(name, "semctl") ||
		strings.HasPrefix(name, "msgget") || strings.HasPrefix(name, "msgsnd") ||
		strings.HasPrefix(name, "msgrcv") || strings.HasPrefix(name, "msgctl") ||
		strings.HasPrefix(name, "futex") || strings.HasPrefix(name, "eventfd") ||
		strings.HasPrefix(name, "signalfd") || strings.HasPrefix(name, "timerfd")
}

func isDevice(name string) bool {
	// Phase 12 D3: Add "$dev_" for broader device-specific opens (e.g., syz_open_dev$dev_snd).
	return strings.HasPrefix(name, "ioctl") || strings.Contains(name, "$dev") || strings.Contains(name, "$dev_")
}

func isIOURING(name string) bool {
	return strings.HasPrefix(name, "io_uring") || strings.HasPrefix(name, "syz_io_uring")
}

func isBPF(name string) bool {
	return strings.HasPrefix(name, "bpf$") || strings.HasPrefix(name, "syz_bpf")
}

func isKEYCTL(name string) bool {
	return strings.HasPrefix(name, "keyctl$") || strings.HasPrefix(name, "add_key$") || strings.HasPrefix(name, "request_key$")
}

// NgramClient returns the MOCK BiGRU client for external use (retrain, etc).
func (fuzzer *Fuzzer) NgramClient() *NgramClient {
	return fuzzer.ngramClient
}

// DEzzerSnapshot returns the current DEzzer state, or nil if disabled.
func (fuzzer *Fuzzer) DEzzerSnapshot() *DEzzerSnapshot {
	if fuzzer.dezzer == nil {
		return nil
	}
	snap := fuzzer.dezzer.Snapshot()
	return &snap
}

// Phase 11b: computeCoverageEntropy calculates Shannon entropy of coverage distribution
// across syscall categories. Low entropy (< 0.3) indicates coverage plateau.
func (fuzzer *Fuzzer) computeCoverageEntropy() float64 {
	counts := [numClusters]float64{}
	total := 0.0
	for _, p := range fuzzer.Config.Corpus.Programs() {
		c := classifyProgram(p)
		counts[c]++
		total++
	}
	if total == 0 {
		return 0
	}
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := count / total
			entropy -= p * math.Log2(p)
		}
	}
	// Store as fixed-point x1000 for atomic access.
	newVal := int64(entropy * 1000)
	oldVal := fuzzer.coverageEntropy.Swap(newVal)
	// Update stat by adding the delta.
	fuzzer.statCoverageEntropy.Add(int(newVal - oldVal))
	return entropy
}

// CoverageEntropy returns the last computed Shannon entropy (fixed-point x1000).
func (fuzzer *Fuzzer) CoverageEntropy() int64 {
	return fuzzer.coverageEntropy.Load()
}

// applyBOParams applies Bayesian Optimization hyperparameters.
// Phase 12 C1: Extended from 5 to 8 parameters with EMA transition for decay changes.
func (fuzzer *Fuzzer) applyBOParams(params [boNumParams]float64) {
	// param[0]: delayInjectionRate — stored for use in mutateProgRequest
	// param[1]: focusBudgetFrac — Phase 15: wired to focus budget cap.
	fuzzer.boFocusBudgetPct.Store(int64(params[1] * 100))
	// param[2]: smashExploreProb — Phase 15: wired to explore probability in genFuzz.
	fuzzer.boSmashExplorePct.Store(int64(params[2] * 100))
	// param[3]: cusumThreshold — apply to DEzzer
	// param[4]: deflakeMaxRuns — stored for use in triage
	// param[5]: dezzerDecayFactor — apply to DEzzer (EMA transition)
	// param[6]: dezzerTSDeltaLimit — apply to DEzzer
	// param[7]: linucbAlpha — apply to LinUCB

	// Pause CUSUM for 60s during parameter transition.
	if fuzzer.dezzer != nil {
		fuzzer.dezzer.PauseCUSUM(60 * time.Second)
		// Phase 12 C1: Apply decay factor and TS delta limit with EMA transition.
		fuzzer.dezzer.SetBOOverrides(params[5], params[6])
	}

	// Phase 12 C1: Apply LinUCB alpha.
	if fuzzer.linucb != nil {
		fuzzer.linucb.SetAlpha(params[7])
	}

	fuzzer.Logf(0, "PROBE: BO params applied: delay=%.2f focus=%.2f smash=%.2f cusum=%.1f deflake=%.0f decay=%.3f tsLimit=%.3f lucbAlpha=%.2f",
		params[0], params[1], params[2], params[3], params[4],
		params[5], params[6], params[7])
}

// PROBE: Phase 11j — buildDelayFeatures constructs the LinUCB feature vector from program + eBPF metrics.
// Feature vector (d=8): [prog_len, lock_syscall_ratio, ebpf_contention, ebpf_concurrent,
//   sched_switches, coverage_delta, prog_category, is_focus]
func (fuzzer *Fuzzer) buildDelayFeatures(p *prog.Prog, isFocus bool) []float64 {
	features := make([]float64, linucbDim)

	// Feature 0: program length (normalized to ~0-1 range).
	features[0] = math.Min(float64(len(p.Calls))/float64(prog.RecommendedCalls), 2.0)

	// Feature 1: lock-related syscall ratio.
	lockCount := 0
	for _, c := range p.Calls {
		if isLockSyscall(c.Meta.Name) {
			lockCount++
		}
	}
	if len(p.Calls) > 0 {
		features[1] = float64(lockCount) / float64(len(p.Calls))
	}

	// Features 2-4: eBPF race metrics (from recent stats, normalized).
	features[2] = math.Min(float64(fuzzer.statRaceLockContention.Val())/100.0, 1.0)
	features[3] = math.Min(float64(fuzzer.statRaceConcurrentAccess.Val())/100.0, 1.0)
	features[4] = math.Min(float64(fuzzer.statRaceSchedSwitch.Val())/100.0, 1.0)

	// Feature 5: coverage delta (recent coverage entropy as proxy).
	features[5] = float64(fuzzer.coverageEntropy.Load()) / 3000.0 // entropy x1000, max ~2.5

	// Feature 6: program category (cluster).
	features[6] = float64(classifyProgram(p)) / float64(numClusters)

	// Feature 7: is focus execution.
	if isFocus {
		features[7] = 1.0
	}

	return features
}

// isLockSyscall returns true if the syscall name indicates a lock-related operation.
func isLockSyscall(name string) bool {
	return strings.Contains(name, "mutex") || strings.Contains(name, "lock") ||
		strings.Contains(name, "futex") || strings.Contains(name, "flock") ||
		strings.Contains(name, "semop") || strings.Contains(name, "semtimedop")
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

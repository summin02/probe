// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: AI-guided fuzzing integration for syz-manager (Phase 3).
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/google/syzkaller/pkg/aitriage"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

func (mgr *Manager) initAITriage(ctx context.Context) {
	cfg := mgr.cfg.AITriage
	if cfg.APIKey == "" || cfg.Model == "" {
		log.Logf(0, "PROBE: AI triage disabled (no api_key or model configured)")
		return
	}

	triager, err := aitriage.NewTriager(cfg, mgr.cfg.AIEmbeddings, mgr.cfg.Workdir)
	if err != nil {
		log.Logf(0, "PROBE: AI triage init failed: %v", err)
		return
	}

	// Wire up callbacks.
	triager.GetCrashes = mgr.aiGetCrashes
	triager.GetSnapshot = mgr.aiGetSnapshot
	triager.OnTriageResult = mgr.aiOnTriageResult
	triager.OnStrategyResult = mgr.aiOnStrategyResult

	// Phase 7a: SyzGPT callbacks.
	triager.GetLFSTargets = mgr.aiGetLFSTargets
	triager.ValidateAndInjectProg = mgr.aiValidateAndInject
	triager.GetAvailableSyscalls = mgr.aiGetAvailableSyscalls
	// H1 fix: wire SyzGPT stat tracking to fuzzer.
	triager.OnSyzGPTGenerated = func() {
		if f := mgr.fuzzer.Load(); f != nil {
			f.RecordSyzGPTGenerated()
		}
	}

	// Phase 10: Initialize spec generation if configured.
	if mgr.cfg.AISpecGen.APIKey != "" {
		if err := triager.InitSpecGen(mgr.cfg.AISpecGen); err != nil {
			log.Logf(0, "PROBE: AI specgen init failed: %v", err)
		}
	}

	mgr.triager = triager
	mgr.http.Triager = triager

	go triager.Run(ctx)
}

func (mgr *Manager) aiGetCrashes() []aitriage.CrashForAnalysis {
	list, err := mgr.crashStore.BugList()
	if err != nil {
		log.Logf(0, "PROBE: AI triage: failed to list crashes: %v", err)
		return nil
	}

	var result []aitriage.CrashForAnalysis
	for _, info := range list {
		// Read the most recent report text.
		reportText := ""
		if len(info.Crashes) > 0 {
			reportFile := filepath.Join(mgr.cfg.Workdir, "crashes", info.ID,
				fmt.Sprintf("report%d", info.Crashes[0].Index))
			if data, err := os.ReadFile(reportFile); err == nil {
				reportText = string(data)
			}
		}
		result = append(result, aitriage.CrashForAnalysis{
			ID:          info.ID,
			Title:       info.Title,
			Tier:        info.Tier,
			Report:      reportText,
			NumVariants: info.NumVariants,
			HasRepro:    info.HasRepro,
		})
	}
	return result
}

func (mgr *Manager) aiGetSnapshot() *aitriage.FuzzingSnapshot {
	f := mgr.fuzzer.Load()
	if f == nil {
		return nil
	}

	snap := &aitriage.FuzzingSnapshot{
		TotalSignal: f.Cover.MaxSignalLen(),
		TotalExecs:  int64(mgr.servStats.StatExecs.Val()),
		CorpusSize:  len(mgr.corpus.Items()),
	}

	// Syscall coverage from corpus.
	corpusObj := mgr.corpus
	if corpusObj != nil {
		callCov := corpusObj.CallCover()
		snap.SyscallCoverage = make(map[string]int)
		for name, cc := range callCov {
			snap.SyscallCoverage[name] = len(cc.Cover)
		}
	}

	// Crash summaries with AI scores.
	list, _ := mgr.crashStore.BugList()
	for _, info := range list {
		summary := aitriage.CrashSummary{
			Title:    info.Title,
			Variants: info.NumVariants,
		}
		if tr := aitriage.LoadTriageResult(mgr.cfg.Workdir, info.ID); tr != nil {
			summary.Score = tr.Score
			summary.VulnType = tr.Reasoning.VulnType
		}
		snap.CrashSummaries = append(snap.CrashSummaries, summary)
	}

	// PROBE: Phase 6 — Include DEzzer state and Focus results.
	if ds := f.DEzzerSnapshot(); ds != nil {
		snap.DEzzerStatus = &aitriage.DEzzerStatusData{
			Generation:     ds.Generation,
			BestFitness:    ds.BestFitness,
			OpSuccessRates: ds.OpSuccessRates,
			OpAvgCovGain:   ds.OpAvgCovGain,
			AIBaseWeights:  ds.AIBaseWeights,
			DEDelta:        ds.DEDelta,
			FinalWeights:   ds.FinalWeights,
			TSDelta:        ds.TSDelta,
			DECorrection:   ds.DECorrection,
			Saturated:      ds.Saturated,
			WarmupDone:     ds.WarmupDone,
		}
	}
	for _, fr := range f.FocusResults() {
		snap.FocusResults = append(snap.FocusResults, aitriage.FocusResultData{
			Title:           fr.Title,
			Tier:            fr.Tier,
			TotalIters:      fr.TotalIters,
			NewCoverage:     fr.NewCoverage,
			CoveragePerExec: fr.CoveragePerExec,
			EarlyExit:       fr.EarlyExit,
			OpDistribution:  fr.OpDistribution,
			OpCovGains:      fr.OpCovGains,
		})
	}

	// PROBE: Phase 7b' — Read slab_sites eBPF map for AI strategy.
	snap.SlabSites = readSlabSites()

	return snap
}

func (mgr *Manager) aiOnTriageResult(crashID string, result *aitriage.TriageResult) {
	// If score >= 70 and we have a repro, trigger focus mode.
	if result.Score >= 70 {
		info, err := mgr.crashStore.BugInfo(crashID, false)
		if err != nil {
			log.Logf(1, "PROBE: AI triage: failed to get bug info for %v: %v", crashID, err)
			return
		}
		progs, err := mgr.crashStore.VariantPrograms(info.Title)
		if err != nil {
			log.Logf(1, "PROBE: AI triage: failed to get variant programs for '%v': %v", info.Title, err)
			return
		}
		if len(progs) > 0 {
			if f := mgr.fuzzer.Load(); f != nil {
				p, err := mgr.target.Deserialize(progs[0], prog.NonStrict)
				if err != nil {
					log.Logf(1, "PROBE: AI triage: failed to deserialize program for '%v': %v", info.Title, err)
					return
				}
				if f.AddFocusCandidate(p, info.Title, info.Tier) {
					log.Logf(0, "PROBE: AI focus triggered for '%v' (score=%d)", info.Title, result.Score)
				} else {
					log.Logf(1, "PROBE: AI focus already active, queued '%v' for later", info.Title)
				}
			}
		}
	}
}

func (mgr *Manager) aiOnStrategyResult(result *aitriage.StrategyResult) {
	f := mgr.fuzzer.Load()
	if f == nil {
		return
	}

	// 1. Apply syscall weights to ChoiceTable.
	if len(result.SyscallWeights) > 0 {
		weights := make(map[int]float64)
		var unmatchedNames []string
		for _, sw := range result.SyscallWeights {
			if syscall, ok := mgr.target.SyscallMap[sw.Name]; ok {
				weights[syscall.ID] = sw.Weight
			} else {
				unmatchedNames = append(unmatchedNames, sw.Name)
			}
		}
		if len(weights) > 0 {
			f.ApplyAIWeights(weights)
			log.Logf(0, "PROBE: AI applied %d/%d syscall weights", len(weights), len(result.SyscallWeights))
		}
		if len(unmatchedNames) > 0 {
			log.Logf(0, "PROBE: AI syscall names not found: %v", unmatchedNames)
		}
		result.WeightsApplied = len(weights)
		result.WeightErrors = unmatchedNames
	}

	// 2. Apply seed hints — find corpus programs matching requested syscalls.
	seedsInjected, seedsAccepted := 0, 0
	var seedErrors []string
	for _, hint := range result.SeedHints {
		seedsInjected++
		best := mgr.findCorpusForSyscalls(hint.Syscalls, 2)
		if len(best) == 0 {
			errMsg := fmt.Sprintf("%s: no corpus match for %v", hint.Target, hint.Syscalls)
			log.Logf(0, "PROBE: AI seed hint: %s", errMsg)
			seedErrors = append(seedErrors, errMsg)
			continue
		}
		for _, p := range best {
			f.InjectProgram(p)
			seedsAccepted++
		}
		log.Logf(0, "PROBE: AI seed hint '%s': injected %d programs for %v",
			hint.Target, len(best), hint.Syscalls)
	}
	if seedsInjected > 0 {
		log.Logf(0, "PROBE: AI seed hints: %d hints, %d programs injected", seedsInjected, seedsAccepted)
	}
	result.SeedsInjected = seedsInjected
	result.SeedsAccepted = seedsAccepted
	result.SeedErrors = seedErrors

	// 3. Apply mutation hints to next focus jobs.
	if result.MutationHints.Reason != "" {
		f.SetAIMutationHints(result.MutationHints)
	}

	// 4. Focus targets.
	for _, target := range result.FocusTargets {
		progs, err := mgr.crashStore.VariantPrograms(target.CrashTitle)
		if err != nil {
			log.Logf(1, "PROBE: AI strategy: failed to get variant programs for '%v': %v", target.CrashTitle, err)
			continue
		}
		if len(progs) == 0 {
			continue
		}
		p, err := mgr.target.Deserialize(progs[0], prog.NonStrict)
		if err != nil {
			log.Logf(1, "PROBE: AI strategy: failed to deserialize program for '%v': %v", target.CrashTitle, err)
			continue
		}
		if f.AddFocusCandidate(p, target.CrashTitle, target.Priority) {
			log.Logf(0, "PROBE: AI focus target: '%v' (priority=%d)", target.CrashTitle, target.Priority)
		} else {
			log.Logf(1, "PROBE: AI focus already active, skipped target '%v'", target.CrashTitle)
		}
	}

	// Re-save strategy with applied results (seeds accepted, weight match counts).
	aitriage.SaveStrategyResult(mgr.cfg.Workdir, result)
}

// aiGetAvailableSyscalls returns a sorted list of all enabled syscall names.
func (mgr *Manager) aiGetAvailableSyscalls() []string {
	f := mgr.fuzzer.Load()
	if f == nil {
		return nil
	}
	var names []string
	for sc := range f.Config.EnabledCalls {
		if !sc.Attrs.Disabled {
			names = append(names, sc.Name)
		}
	}
	sort.Strings(names)
	return names
}

// readSlabSites reads the pinned slab_sites eBPF map and returns top-10 sites by activity.
func readSlabSites() []aitriage.SlabSiteData {
	const slabSitesPath = "/sys/fs/bpf/probe/slab_sites"
	m, err := ebpf.LoadPinnedMap(slabSitesPath, nil)
	if err != nil {
		return nil // map not available — graceful skip
	}
	defer m.Close()

	var sites []aitriage.SlabSiteData
	var key uint64
	// site_stats: {alloc_count: u64, free_count: u64} = 16 bytes
	var val [16]byte
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		allocCount := binary.LittleEndian.Uint64(val[0:8])
		freeCount := binary.LittleEndian.Uint64(val[8:16])
		sites = append(sites, aitriage.SlabSiteData{
			CallSite:   key,
			AllocCount: allocCount,
			FreeCount:  freeCount,
		})
	}

	// Sort by total activity (alloc+free) descending, return top 10.
	sort.Slice(sites, func(i, j int) bool {
		return (sites[i].AllocCount + sites[i].FreeCount) > (sites[j].AllocCount + sites[j].FreeCount)
	})
	if len(sites) > 10 {
		sites = sites[:10]
	}
	return sites
}

// findCorpusForSyscalls searches the corpus for programs that contain the most
// of the requested syscalls, returning up to `limit` best matches.
func (mgr *Manager) findCorpusForSyscalls(targetSyscalls []string, limit int) []*prog.Prog {
	targetSet := make(map[string]bool)
	for _, s := range targetSyscalls {
		targetSet[s] = true
	}

	type scored struct {
		prog  *prog.Prog
		score int
	}

	programs := mgr.corpus.Programs()
	var matches []scored
	for _, p := range programs {
		score := 0
		seen := make(map[string]bool)
		for i := range p.Calls {
			name := p.CallName(i)
			if targetSet[name] && !seen[name] {
				score++
				seen[name] = true
			}
		}
		if score > 0 {
			matches = append(matches, scored{p, score})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].score > matches[j].score
	})

	var result []*prog.Prog
	for i := 0; i < limit && i < len(matches); i++ {
		result = append(result, matches[i].prog)
	}
	return result
}

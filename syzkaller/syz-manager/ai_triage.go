// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: AI-guided fuzzing integration for syz-manager (Phase 3).
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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

	triager, err := aitriage.NewTriager(cfg, mgr.cfg.Workdir)
	if err != nil {
		log.Logf(0, "PROBE: AI triage init failed: %v", err)
		return
	}

	// Wire up callbacks.
	triager.GetCrashes = mgr.aiGetCrashes
	triager.GetSnapshot = mgr.aiGetSnapshot
	triager.OnTriageResult = mgr.aiOnTriageResult
	triager.OnStrategyResult = mgr.aiOnStrategyResult

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
	}

	// 2. Inject seed programs.
	seedsInjected, seedsAccepted := 0, 0
	for _, seed := range result.SeedPrograms {
		seedsInjected++
		if err := f.InjectSeed(seed.Code); err != nil {
			log.Logf(0, "PROBE: AI seed parse error: %v", err)
		} else {
			seedsAccepted++
		}
	}
	if seedsInjected > 0 {
		log.Logf(0, "PROBE: AI seeds: %d injected, %d accepted", seedsInjected, seedsAccepted)
	}

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
}

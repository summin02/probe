// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Package aitriage implements AI-guided fuzzing — crash exploitability
// analysis (Step A) and fuzzing strategy generation (Step B) via LLM APIs.
package aitriage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

// TriageResult holds the AI exploitability analysis for a single crash group.
type TriageResult struct {
	Score        int             `json:"score"`
	Confidence   string          `json:"confidence"`
	ExploitClass string          `json:"exploit_class"`
	Reasoning    TriageReasoning `json:"reasoning"`
	BestVariant  string          `json:"best_variant"`
	Summary      string          `json:"summary"`
	FocusHints   []string        `json:"focus_hints,omitempty"`
	Model        string          `json:"model"`
	Provider     string          `json:"provider"`
	Timestamp    time.Time       `json:"timestamp"`
	InputTokens  int             `json:"input_tokens"`
	OutputTokens int             `json:"output_tokens"`
}

type TriageReasoning struct {
	VulnType      string `json:"vuln_type"`
	SlabCache     string `json:"slab_cache"`
	ObjectSize    int    `json:"object_size"`
	Primitive     string `json:"primitive"`
	TimingWindow  string `json:"timing_window"`
	SprayFeasible string `json:"spray_feasible"`
	SprayObjects  string `json:"spray_objects"`
	CrossCache    bool   `json:"cross_cache"`
	Controllable  string `json:"controllable"`
}

// StrategyResult holds the AI fuzzing strategy recommendations.
type StrategyResult struct {
	SyscallWeights  []SyscallWeight `json:"syscall_weights,omitempty"`
	SeedPrograms    []SeedProgram   `json:"seed_programs,omitempty"`
	MutationHints   MutationHints   `json:"mutation_hints"`
	FocusTargets    []FocusTarget   `json:"focus_targets,omitempty"`
	Summary         string          `json:"summary"`
	Model           string          `json:"model"`
	Timestamp       time.Time       `json:"timestamp"`
	InputTokens     int             `json:"input_tokens"`
	OutputTokens    int             `json:"output_tokens"`
	SeedsAccepted   int             `json:"seeds_accepted,omitempty"`
	WeightsApplied  int             `json:"weights_applied,omitempty"`
	SeedErrors      []string        `json:"seed_errors,omitempty"`
	WeightErrors    []string        `json:"weight_errors,omitempty"`
}

type SyscallWeight struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Reason string  `json:"reason"`
}

type SeedProgram struct {
	Code   string `json:"code"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

type MutationHints struct {
	SpliceWeight    float64 `json:"splice_weight"`
	InsertWeight    float64 `json:"insert_weight"`
	MutateArgWeight float64 `json:"mutate_arg_weight"`
	RemoveWeight    float64 `json:"remove_weight"`
	Reason          string  `json:"reason"`
}

type FocusTarget struct {
	CrashTitle string `json:"crash_title"`
	Reason     string `json:"reason"`
	Priority   int    `json:"priority"`
}

// FuzzingSnapshot captures the current fuzzing state for strategy analysis.
type FuzzingSnapshot struct {
	TotalSignal      int            `json:"total_signal"`
	SignalGrowthRate float64        `json:"signal_growth_rate"`
	CoverageByFile   map[string]int `json:"coverage_by_file,omitempty"`
	TotalExecs       int64          `json:"total_execs"`
	ExecsPerSec      float64        `json:"execs_per_sec"`
	CorpusSize       int            `json:"corpus_size"`
	CrashSummaries   []CrashSummary `json:"crash_summaries,omitempty"`
	NewCrashesCount  int            `json:"new_crashes_count"`
	SyscallCoverage  map[string]int `json:"syscall_coverage,omitempty"`
}

type CrashSummary struct {
	Title    string `json:"title"`
	Score    int    `json:"score"`
	VulnType string `json:"vuln_type"`
	Variants int    `json:"variants"`
}

// APICall records a single LLM API call for history tracking.
type APICall struct {
	Time          time.Time `json:"time"`
	Type          string    `json:"type"` // "crash" or "strategy"
	InputTokens   int       `json:"input_tokens"`
	OutputTokens  int       `json:"output_tokens"`
	CostUSD       float64   `json:"cost_usd"`
	Success       bool      `json:"success"`
	ResultSummary string    `json:"result_summary,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// CostTracker tracks cumulative API usage and costs.
type CostTracker struct {
	mu           sync.Mutex
	TotalCalls   int       `json:"total_calls"`
	TotalInput   int       `json:"total_input_tokens"`
	TotalOutput  int       `json:"total_output_tokens"`
	TotalCostUSD float64   `json:"total_cost_usd"`
	TodayCostUSD float64   `json:"today_cost_usd"`
	TodayDate    string    `json:"today_date"`
	TodayCalls   int       `json:"today_calls"`
	TodayInput   int       `json:"today_input_tokens"`
	TodayOutput  int       `json:"today_output_tokens"`
	History      []APICall `json:"history"`
}

const maxHistorySize = 100
const maxLogLines = 200
const krwPerUSD = 1450

// Model pricing: [input_per_1M_tokens, output_per_1M_tokens] in USD.
var modelPricing = map[string][2]float64{
	"claude-sonnet-4-5-20250929": {3.0, 15.0},
	"claude-haiku-4-5-20251001":  {1.0, 5.0},
	"claude-opus-4-5":            {5.0, 25.0},
	"gpt-4o":                     {2.5, 10.0},
	"gpt-4o-mini":                {0.15, 0.6},
}

func (ct *CostTracker) Record(call APICall, model string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Calculate cost.
	pricing, ok := modelPricing[model]
	if ok {
		call.CostUSD = float64(call.InputTokens)*pricing[0]/1e6 + float64(call.OutputTokens)*pricing[1]/1e6
	}

	today := time.Now().Format("2006-01-02")
	if ct.TodayDate != today {
		ct.TodayCostUSD = 0
		ct.TodayCalls = 0
		ct.TodayInput = 0
		ct.TodayOutput = 0
		ct.TodayDate = today
	}

	ct.TotalCalls++
	ct.TotalInput += call.InputTokens
	ct.TotalOutput += call.OutputTokens
	ct.TotalCostUSD += call.CostUSD
	ct.TodayCalls++
	ct.TodayInput += call.InputTokens
	ct.TodayOutput += call.OutputTokens
	ct.TodayCostUSD += call.CostUSD

	ct.History = append(ct.History, call)
	if len(ct.History) > maxHistorySize {
		ct.History = ct.History[len(ct.History)-maxHistorySize:]
	}
}

// CostSnapshot is a mutex-free copy of CostTracker for reading.
type CostSnapshot struct {
	TotalCalls   int
	TotalInput   int
	TotalOutput  int
	TotalCostUSD float64
	TodayCostUSD float64
	TodayDate    string
	TodayCalls   int
	TodayInput   int
	TodayOutput  int
	History      []APICall
}

func (ct *CostTracker) Snapshot() CostSnapshot {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if ct.TodayDate != today {
		ct.TodayCostUSD = 0
		ct.TodayCalls = 0
		ct.TodayInput = 0
		ct.TodayOutput = 0
		ct.TodayDate = today
	}

	snap := CostSnapshot{
		TotalCalls:   ct.TotalCalls,
		TotalInput:   ct.TotalInput,
		TotalOutput:  ct.TotalOutput,
		TotalCostUSD: ct.TotalCostUSD,
		TodayCostUSD: ct.TodayCostUSD,
		TodayDate:    ct.TodayDate,
		TodayCalls:   ct.TodayCalls,
		TodayInput:   ct.TodayInput,
		TodayOutput:  ct.TodayOutput,
	}
	snap.History = make([]APICall, len(ct.History))
	copy(snap.History, ct.History)
	return snap
}

func KRWPerUSD() int { return krwPerUSD }

// LogEntry is a single log line with timestamp.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

// Triager is the main AI triage orchestrator.
type Triager struct {
	cfg       mgrconfig.AITriageConfig
	client    LLMClient
	workdir   string
	cost      *CostTracker
	mu        sync.Mutex
	running   bool
	lastRun   time.Time
	nextBatch time.Time // when the next automatic batch will run
	strategy  *StrategyResult

	// Console log buffer for the /ai dashboard.
	logMu  sync.Mutex
	logBuf []LogEntry

	// Callbacks set by the manager for applying results.
	OnTriageResult   func(crashID string, result *TriageResult)
	OnStrategyResult func(result *StrategyResult)
	GetSnapshot      func() *FuzzingSnapshot
	GetCrashes       func() []CrashForAnalysis
}

// CrashForAnalysis packages crash data needed for AI analysis.
type CrashForAnalysis struct {
	ID          string
	Title       string
	Tier        int
	Report      string // crash report text
	NumVariants int
	HasRepro    bool
}

func NewTriager(cfg mgrconfig.AITriageConfig, workdir string) (*Triager, error) {
	if cfg.APIKey == "" || cfg.Model == "" {
		return nil, fmt.Errorf("ai_triage requires model and api_key")
	}
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	t := &Triager{
		cfg:     cfg,
		client:  client,
		workdir: workdir,
	}
	// Load existing cost tracker from disk.
	t.cost = loadCostTracker(workdir)
	// Recover costs from ai-triage.json files if cost tracker has no history
	// (e.g., previous runs didn't save cost due to bugs).
	if t.cost.TotalCalls == 0 {
		t.recoverCostFromTriageResults()
	}
	return t, nil
}

func (t *Triager) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

func (t *Triager) LastStrategy() *StrategyResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.strategy == nil {
		return nil
	}
	// Return a copy to avoid race with stepB() overwriting the pointer.
	cp := *t.strategy
	return &cp
}

func (t *Triager) Cost() CostSnapshot {
	return t.cost.Snapshot()
}

func (t *Triager) Model() string    { return t.cfg.Model }
func (t *Triager) Provider() string { return detectProvider(t.cfg) }

// logf writes to both the syz-manager log and the console buffer.
func (t *Triager) logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Logf(0, "PROBE: AI: %s", msg)
	t.logMu.Lock()
	t.logBuf = append(t.logBuf, LogEntry{Time: time.Now(), Message: msg})
	if len(t.logBuf) > maxLogLines {
		t.logBuf = t.logBuf[len(t.logBuf)-maxLogLines:]
	}
	t.logMu.Unlock()
}

// LogLines returns the recent console log entries.
func (t *Triager) LogLines() []LogEntry {
	t.logMu.Lock()
	defer t.logMu.Unlock()
	out := make([]LogEntry, len(t.logBuf))
	copy(out, t.logBuf)
	return out
}

// LogLinesJSON returns log entries as JSON bytes (for interface{} access without import).
func (t *Triager) LogLinesJSON() []byte {
	lines := t.LogLines()
	data, _ := json.Marshal(lines)
	return data
}

// CostJSON returns cost tracker data as JSON bytes (for interface{} access without import).
func (t *Triager) CostJSON() []byte {
	snap := t.cost.Snapshot()
	data, _ := json.Marshal(struct {
		TotalCalls   int       `json:"total_calls"`
		TotalInput   int       `json:"total_input_tokens"`
		TotalOutput  int       `json:"total_output_tokens"`
		TotalCostUSD float64   `json:"total_cost_usd"`
		TodayCostUSD float64   `json:"today_cost_usd"`
		TodayCalls   int       `json:"today_calls"`
		TodayInput   int       `json:"today_input_tokens"`
		TodayOutput  int       `json:"today_output_tokens"`
		History      []APICall `json:"history"`
	}{
		TotalCalls:   snap.TotalCalls,
		TotalInput:   snap.TotalInput,
		TotalOutput:  snap.TotalOutput,
		TotalCostUSD: snap.TotalCostUSD,
		TodayCostUSD: snap.TodayCostUSD,
		TodayCalls:   snap.TodayCalls,
		TodayInput:   snap.TodayInput,
		TodayOutput:  snap.TodayOutput,
		History:      snap.History,
	})
	return data
}

// NextBatchSec returns seconds until the next automatic batch.
func (t *Triager) NextBatchSec() int {
	t.mu.Lock()
	nb := t.nextBatch
	t.mu.Unlock()
	if nb.IsZero() {
		return 0
	}
	sec := int(time.Until(nb).Seconds())
	if sec < 0 {
		return 0
	}
	return sec
}

// Run starts the 1-hour batch loop. Call from a goroutine.
func (t *Triager) Run(ctx context.Context) {
	t.logf("Triage started (model=%v, provider=%v)", t.cfg.Model, detectProvider(t.cfg))

	// Run first batch after 2 minutes (let fuzzer warm up).
	firstDelay := 2 * time.Minute
	timer := time.NewTimer(firstDelay)
	defer timer.Stop()

	t.mu.Lock()
	t.nextBatch = time.Now().Add(firstDelay)
	t.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			t.runBatch(ctx)
			nextDelay := 1 * time.Hour
			timer.Reset(nextDelay)
			t.mu.Lock()
			t.nextBatch = time.Now().Add(nextDelay)
			t.mu.Unlock()
		}
	}
}

// RunStepA runs crash analysis on demand (manual trigger).
func (t *Triager) RunStepA(ctx context.Context) {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		t.logf("Already running, skipping manual Step A")
		return
	}
	t.running = true
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		t.running = false
		t.mu.Unlock()
	}()

	t.logf("Manual Step A triggered")
	t.stepA(ctx)
	t.logf("Manual Step A finished")
}

// RunStepB runs strategy generation on demand (manual trigger).
func (t *Triager) RunStepB(ctx context.Context) {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		t.logf("Already running, skipping manual Step B")
		return
	}
	t.running = true
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		t.running = false
		t.mu.Unlock()
	}()

	t.logf("Manual Step B triggered")
	t.stepB(ctx)
	t.logf("Manual Step B finished")
}

func (t *Triager) runBatch(ctx context.Context) {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		t.running = false
		t.lastRun = time.Now()
		t.mu.Unlock()
	}()

	t.logf("Batch cycle starting...")
	t.stepA(ctx)
	t.stepB(ctx)
	t.logf("Batch cycle complete")
}

func (t *Triager) stepA(ctx context.Context) {
	if t.GetCrashes == nil {
		return
	}
	crashes := t.GetCrashes()
	maxTier := t.cfg.MaxTier
	if maxTier == 0 {
		maxTier = 2
	}

	t.logf("[Step A] Scanning crashes... (%d total)", len(crashes))

	// Build list of crashes to analyze.
	var pending []CrashForAnalysis
	for _, c := range crashes {
		if c.Tier > maxTier {
			continue
		}
		// Skip syzkaller-internal bugs that are not real kernel vulnerabilities.
		if isSyzkallerInternalCrash(c.Title) {
			continue
		}
		existing := loadTriageResult(t.workdir, c.ID)
		if existing != nil {
			// Skip unless variants have tripled since last analysis.
			continue
		}
		if c.Report == "" {
			continue
		}
		pending = append(pending, c)
	}

	if len(pending) == 0 {
		t.logf("[Step A] No new crashes to analyze")
		return
	}
	t.logf("[Step A] %d crashes to analyze (tier <= %d)", len(pending), maxTier)

	analyzed := 0
	for i, c := range pending {
		select {
		case <-ctx.Done():
			t.logf("[Step A] Cancelled")
			return
		default:
		}

		t.logf("[Step A] [%d/%d] Analyzing: %s", i+1, len(pending), c.Title)

		result, err := t.analyzeCrash(ctx, c)
		call := APICall{
			Time: time.Now(),
			Type: "crash",
		}
		if err != nil {
			t.logf("[Step A] [%d/%d] FAILED: %v", i+1, len(pending), err)
			call.Success = false
			call.Error = err.Error()
			t.cost.Record(call, t.cfg.Model)
			saveCostTracker(t.workdir, t.cost)
			time.Sleep(3 * time.Second)
			continue
		}

		call.InputTokens = result.InputTokens
		call.OutputTokens = result.OutputTokens
		call.Success = true
		call.ResultSummary = fmt.Sprintf("score=%d", result.Score)
		t.cost.Record(call, t.cfg.Model)
		saveCostTracker(t.workdir, t.cost)

		saveTriageResult(t.workdir, c.ID, result)

		if t.OnTriageResult != nil {
			t.OnTriageResult(c.ID, result)
		}

		analyzed++
		t.logf("[Step A] [%d/%d] Done: %s → score=%d, class=%s, vuln=%s",
			i+1, len(pending), c.Title, result.Score, result.ExploitClass, result.Reasoning.VulnType)

		time.Sleep(3 * time.Second)
	}
	t.logf("[Step A] Complete: %d/%d crashes analyzed", analyzed, len(pending))
}

func (t *Triager) stepB(ctx context.Context) {
	if t.GetSnapshot == nil {
		return
	}
	t.logf("[Step B] Collecting fuzzing snapshot...")
	snapshot := t.GetSnapshot()
	if snapshot == nil {
		t.logf("[Step B] No snapshot available (fuzzer not ready)")
		return
	}

	t.logf("[Step B] Snapshot: signal=%d, execs=%d, corpus=%d, crashes=%d",
		snapshot.TotalSignal, snapshot.TotalExecs, snapshot.CorpusSize, len(snapshot.CrashSummaries))
	t.logf("[Step B] Generating strategy via LLM...")

	result, err := t.generateStrategy(ctx, snapshot)
	call := APICall{
		Time: time.Now(),
		Type: "strategy",
	}
	if err != nil {
		t.logf("[Step B] FAILED: %v", err)
		call.Success = false
		call.Error = err.Error()
		t.cost.Record(call, t.cfg.Model)
		saveCostTracker(t.workdir, t.cost)
		return
	}

	call.InputTokens = result.InputTokens
	call.OutputTokens = result.OutputTokens
	call.Success = true
	call.ResultSummary = "applied"
	t.cost.Record(call, t.cfg.Model)

	t.mu.Lock()
	t.strategy = result
	t.mu.Unlock()

	saveStrategyResult(t.workdir, result)

	if t.OnStrategyResult != nil {
		t.OnStrategyResult(result)
	}

	nWeights := len(result.SyscallWeights)
	nSeeds := len(result.SeedPrograms)
	nFocus := len(result.FocusTargets)
	t.logf("[Step B] Strategy applied: %d syscall weights, %d seeds, %d focus targets",
		nWeights, nSeeds, nFocus)
	saveCostTracker(t.workdir, t.cost)
}

func (t *Triager) analyzeCrash(ctx context.Context, c CrashForAnalysis) (*TriageResult, error) {
	systemPrompt, userPrompt := buildCrashPrompt(c)
	resp, err := t.client.Chat(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	result, err := parseCrashResponse(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	result.Model = t.cfg.Model
	result.Provider = detectProvider(t.cfg)
	result.Timestamp = time.Now()
	result.InputTokens = resp.InputTokens
	result.OutputTokens = resp.OutputTokens
	return result, nil
}

func (t *Triager) generateStrategy(ctx context.Context, snapshot *FuzzingSnapshot) (*StrategyResult, error) {
	systemPrompt, userPrompt := buildStrategyPrompt(snapshot)
	resp, err := t.client.Chat(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	result, err := parseStrategyResponse(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	result.Model = t.cfg.Model
	result.Timestamp = time.Now()
	result.InputTokens = resp.InputTokens
	result.OutputTokens = resp.OutputTokens
	return result, nil
}

func detectProvider(cfg mgrconfig.AITriageConfig) string {
	if cfg.Provider != "" {
		return cfg.Provider
	}
	if strings.HasPrefix(cfg.Model, "claude-") {
		return "anthropic"
	}
	return "openai"
}

// LoadTriageResult loads a cached triage result for a crash from the /ai page.
func LoadTriageResult(workdir, crashID string) *TriageResult {
	return loadTriageResult(workdir, crashID)
}

func loadTriageResult(workdir, crashID string) *TriageResult {
	path := filepath.Join(workdir, "crashes", crashID, "ai-triage.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var result TriageResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return &result
}

func saveTriageResult(workdir, crashID string, result *TriageResult) {
	dir := filepath.Join(workdir, "crashes", crashID)
	path := filepath.Join(dir, "ai-triage.json")
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Logf(0, "PROBE: failed to marshal triage result: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Logf(0, "PROBE: failed to save triage result: %v", err)
	}
}

// SaveStrategyResult saves the strategy result to disk (public for manager callback).
func SaveStrategyResult(workdir string, result *StrategyResult) {
	saveStrategyResult(workdir, result)
}

func saveStrategyResult(workdir string, result *StrategyResult) {
	path := filepath.Join(workdir, "ai-strategy.json")
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Logf(0, "PROBE: failed to marshal strategy result: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Logf(0, "PROBE: failed to save strategy result: %v", err)
	}
}

func loadCostTracker(workdir string) *CostTracker {
	ct := &CostTracker{}
	path := filepath.Join(workdir, "ai-cost.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ct
	}
	if err := json.Unmarshal(data, ct); err != nil {
		log.Logf(0, "PROBE: failed to parse ai-cost.json: %v", err)
	}
	return ct
}

func saveCostTracker(workdir string, ct *CostTracker) {
	ct.mu.Lock()
	data, err := json.MarshalIndent(ct, "", "  ")
	ct.mu.Unlock()
	if err != nil {
		log.Logf(0, "PROBE: failed to marshal cost tracker: %v", err)
		return
	}
	path := filepath.Join(workdir, "ai-cost.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Logf(0, "PROBE: failed to save ai-cost.json: %v", err)
	}
}

// isSyzkallerInternalCrash returns true for crash titles that represent
// syzkaller-internal issues rather than real kernel vulnerabilities.
// These should not be sent to LLM for analysis.
func isSyzkallerInternalCrash(title string) bool {
	lower := strings.ToLower(title)
	for _, pattern := range []string{
		"suppressed report",
		"lost connection to test machine",
		"no output from test machine",
		"test machine is not executing programs",
		"executor failure",
	} {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// recoverCostFromTriageResults scans existing ai-triage.json files and
// reconstructs the cost tracker from their token counts. This handles
// the case where previous runs analyzed crashes but didn't save cost data.
func (t *Triager) recoverCostFromTriageResults() {
	crashDir := filepath.Join(t.workdir, "crashes")
	entries, err := os.ReadDir(crashDir)
	if err != nil {
		return
	}
	recovered := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tr := loadTriageResult(t.workdir, entry.Name())
		if tr == nil || tr.InputTokens == 0 {
			continue
		}
		call := APICall{
			Time:          tr.Timestamp,
			Type:          "crash",
			InputTokens:   tr.InputTokens,
			OutputTokens:  tr.OutputTokens,
			Success:       true,
			ResultSummary: fmt.Sprintf("score=%d (recovered)", tr.Score),
		}
		t.cost.Record(call, tr.Model)
		recovered++
	}
	if recovered > 0 {
		saveCostTracker(t.workdir, t.cost)
		log.Logf(0, "PROBE: AI cost recovered from %d existing triage results", recovered)
	}
}

// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type CoverageInfo struct {
	Modules         []*vminfo.KernelModule
	ReportGenerator *ReportGeneratorWrapper
	CoverFilter     map[uint64]struct{}
}

type HTTPServer struct {
	// To be set before calling Serve.
	Cfg         *mgrconfig.Config
	StartTime   time.Time
	CrashStore  *CrashStore
	DiffStore   *DiffFuzzerStore
	ReproLoop   *ReproLoop
	Pool        *vm.Dispatcher
	Pools       map[string]*vm.Dispatcher
	TogglePause func(paused bool)

	// PROBE: AI triage (Phase 3).
	Triager interface{} // *aitriage.Triager, set by manager; typed as interface to avoid import cycle

	// Can be set dynamically after calling Serve.
	Corpus          atomic.Pointer[corpus.Corpus]
	Fuzzer          atomic.Pointer[fuzzer.Fuzzer]
	Cover           atomic.Pointer[CoverageInfo]
	EnabledSyscalls atomic.Value // map[*prog.Syscall]bool

	// Internal state.
	expertMode bool
	paused     bool
}

func (serv *HTTPServer) Serve(ctx context.Context) error {
	if serv.Cfg.HTTP == "" {
		return fmt.Errorf("starting a disabled HTTP server")
	}
	if serv.Pool != nil {
		serv.Pools = map[string]*vm.Dispatcher{"": serv.Pool}
	}
	handle := func(pattern string, handler func(http.ResponseWriter, *http.Request)) {
		http.Handle(pattern, handlers.CompressHandler(http.HandlerFunc(handler)))
	}
	// keep-sorted start
	handle("/", serv.httpMain)
	handle("/action", serv.httpAction)
	handle("/addcandidate", serv.httpAddCandidate)
	handle("/ai", serv.httpAI)                        // PROBE: AI dashboard
	handle("/ai/analytics", serv.httpAIAnalytics)    // PROBE: AI analytics
	handle("/ai/embeddings", serv.httpAIEmbeddings) // PROBE: AI embeddings dashboard
	handle("/ai/specgen", serv.httpAISpecGen)        // PROBE: AI spec generation
	handle("/ai/triage", serv.httpAITriage)          // PROBE: AI triage
	handle("/ai/crash", serv.httpAICrash)             // PROBE: AI crash detail
	handle("/api/ai/analyze", serv.httpAIAnalyze)     // PROBE: manual Step A
	handle("/api/ai/log", serv.httpAILog)             // PROBE: console log stream
	handle("/api/ai/strategize", serv.httpAIStrategize) // PROBE: manual Step B
	handle("/api/ai/embed", serv.httpAIEmbed)            // PROBE: manual embeddings
	handle("/config", serv.httpConfig)
	handle("/corpus", serv.httpCorpus)
	handle("/corpus.db", serv.httpDownloadCorpus)
	handle("/cover", serv.httpCover)
	handle("/coverprogs", serv.httpPrograms)
	handle("/debuginput", serv.httpDebugInput)
	handle("/file", serv.httpFile)
	handle("/filecover", serv.httpFileCover)
	handle("/filterpcs", serv.httpFilterPCs)
	handle("/funccover", serv.httpFuncCover)
	handle("/input", serv.httpInput)
	handle("/jobs", serv.httpJobs)
	handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP)
	handle("/modulecover", serv.httpModuleCover)
	handle("/modules", serv.modulesInfo)
	handle("/prio", serv.httpPrio)
	handle("/rawcover", serv.httpRawCover)
	handle("/rawcoverfiles", serv.httpRawCoverFiles)
	handle("/stats", serv.httpStats)
	handle("/subsystemcover", serv.httpSubsystemCover)
	handle("/syscalls", serv.httpSyscalls)
	handle("/vm", serv.httpVM)
	handle("/vms", serv.httpVMs)
	// keep-sorted end
	if serv.CrashStore != nil {
		handle("/crash", serv.httpCrash)
		handle("/report", serv.httpReport)
	}
	// Browsers like to request this, without special handler this goes to / handler.
	handle("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {})

	log.Logf(0, "serving http on http://%v", serv.Cfg.HTTP)
	server := &http.Server{Addr: serv.Cfg.HTTP}
	go func() {
		// The http server package unfortunately does not natively take a context.Context.
		// Let's emulate it via server.Shutdown()
		<-ctx.Done()
		server.Close()
	}()

	err := server.ListenAndServe()
	if err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (serv *HTTPServer) httpAction(w http.ResponseWriter, r *http.Request) {
	switch r.FormValue("toggle") {
	case "expert":
		serv.expertMode = !serv.expertMode
	case "pause":
		if serv.TogglePause == nil {
			http.Error(w, "pause is not implemented", http.StatusNotImplemented)
			return
		}
		serv.paused = !serv.paused
		serv.TogglePause(serv.paused)
	}
	http.Redirect(w, r, r.FormValue("url"), http.StatusFound)
}

func (serv *HTTPServer) httpMain(w http.ResponseWriter, r *http.Request) {
	data := &UISummaryData{
		UIPageHeader: serv.pageHeader(r, "syzkaller"),
		Log:          log.CachedLogOutput(),
	}

	level := stat.Simple
	if serv.expertMode {
		level = stat.All
	}
	for _, stat := range stat.Collect(level) {
		data.Stats = append(data.Stats, UIStat{
			Name:  stat.Name,
			Value: stat.Value,
			Hint:  stat.Desc,
			Link:  stat.Link,
		})
	}
	if serv.CrashStore != nil {
		var err error
		if data.Crashes, err = serv.collectCrashes(serv.Cfg.Workdir); err != nil {
			http.Error(w, fmt.Sprintf("failed to collect crashes: %v", err), http.StatusInternalServerError)
			return
		}
	}
	if serv.DiffStore != nil {
		data.PatchedOnly, data.AffectsBoth, data.InProgress = serv.collectDiffCrashes()
	}
	executeTemplate(w, mainTemplate, data)
}

func (serv *HTTPServer) httpConfig(w http.ResponseWriter, r *http.Request) {
	// Deep copy config and mask sensitive fields before exposing.
	cfg := *serv.Cfg
	if cfg.AITriage.APIKey != "" {
		key := cfg.AITriage.APIKey
		if len(key) > 8 {
			cfg.AITriage.APIKey = key[:4] + "..." + key[len(key)-4:]
		} else {
			cfg.AITriage.APIKey = "****"
		}
	}
	serv.jsonPage(w, r, "config", &cfg)
}

func (serv *HTTPServer) jsonPage(w http.ResponseWriter, r *http.Request, title string, data any) {
	text, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode json: %v", err), http.StatusInternalServerError)
		return
	}
	serv.textPage(w, r, title, text)
}

func (serv *HTTPServer) textPage(w http.ResponseWriter, r *http.Request, title string, text []byte) {
	if r.FormValue("raw") != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(text)
		return
	}
	data := &UITextPage{
		UIPageHeader: serv.pageHeader(r, title),
		Text:         text,
	}
	executeTemplate(w, textTemplate, data)
}

func (serv *HTTPServer) httpSyscalls(w http.ResponseWriter, r *http.Request) {
	var calls map[string]*corpus.CallCov
	total := make(map[string]int)
	fuzzerObj := serv.Fuzzer.Load()
	syscallsObj := serv.EnabledSyscalls.Load()
	corpusObj := serv.Corpus.Load()
	if corpusObj != nil && syscallsObj != nil {
		calls = corpusObj.CallCover()
		// Add enabled, but not yet covered calls.
		for call := range syscallsObj.(map[*prog.Syscall]bool) {
			if calls[call.Name] == nil {
				calls[call.Name] = new(corpus.CallCov)
			}
		}
		// Count number of programs that include each call.
		last := make(map[string]*prog.Prog)
		for _, inp := range corpusObj.Items() {
			for _, call := range inp.Prog.Calls {
				name := call.Meta.Name
				if last[name] != inp.Prog {
					total[name]++
				}
				last[name] = inp.Prog
			}
		}
	}
	data := &UISyscallsData{
		UIPageHeader: serv.pageHeader(r, "syscalls"),
	}
	for c, cc := range calls {
		var syscallID *int
		if syscall, ok := serv.Cfg.Target.SyscallMap[c]; ok {
			syscallID = &syscall.ID
		}
		coverOverflows, compsOverflows := 0, 0
		if fuzzerObj != nil {
			idx := len(serv.Cfg.Target.Syscalls)
			if c != prog.ExtraCallName {
				idx = serv.Cfg.Target.SyscallMap[c].ID
			}
			coverOverflows = int(fuzzerObj.Syscalls[idx].CoverOverflows.Load())
			compsOverflows = int(fuzzerObj.Syscalls[idx].CompsOverflows.Load())
		}
		data.Calls = append(data.Calls, UICallType{
			Name:           c,
			ID:             syscallID,
			Inputs:         cc.Count,
			Total:          total[c],
			Cover:          len(cc.Cover),
			CoverOverflows: coverOverflows,
			CompsOverflows: compsOverflows,
		})
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, syscallsTemplate, data)
}

func (serv *HTTPServer) httpStats(w http.ResponseWriter, r *http.Request) {
	html, err := pages.StatsHTML()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := &UITextPage{
		UIPageHeader: serv.pageHeader(r, "stats"),
		HTML:         html,
	}
	executeTemplate(w, textTemplate, data)
}

func (serv *HTTPServer) httpVMs(w http.ResponseWriter, r *http.Request) {
	pool := serv.Pools[r.FormValue("pool")]
	if pool == nil {
		http.Error(w, "no such VM pool is known (yet)", http.StatusInternalServerError)
		return
	}
	data := &UIVMData{
		UIPageHeader: serv.pageHeader(r, "VMs"),
	}
	// TODO: we could also query vmLoop for VMs that are idle (waiting to start reproducing),
	// and query the exact bug that is being reproduced by a VM.
	for id, state := range pool.State() {
		name := fmt.Sprintf("#%d", id)
		info := UIVMInfo{
			Name:  name,
			State: "unknown",
			Since: time.Since(state.LastUpdate),
		}
		switch state.State {
		case dispatcher.StateOffline:
			info.State = "offline"
		case dispatcher.StateBooting:
			info.State = "booting"
		case dispatcher.StateWaiting:
			info.State = "waiting"
		case dispatcher.StateRunning:
			info.State = "running: " + state.Status
		}
		if state.Reserved {
			info.State = "[reserved] " + info.State
		}
		if state.MachineInfo != nil {
			info.MachineInfo = fmt.Sprintf("/vm?type=machine-info&id=%d", id)
		}
		if state.DetailedStatus != nil {
			info.DetailedStatus = fmt.Sprintf("/vm?type=detailed-status&id=%v", id)
		}
		data.VMs = append(data.VMs, info)
	}
	executeTemplate(w, vmsTemplate, data)
}

func (serv *HTTPServer) httpVM(w http.ResponseWriter, r *http.Request) {
	pool := serv.Pools[r.FormValue("pool")]
	if pool == nil {
		http.Error(w, "no such VM pool is known (yet)", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ctTextPlain)
	id, err := strconv.Atoi(r.FormValue("id"))
	infos := pool.State()
	if err != nil || id < 0 || id >= len(infos) {
		http.Error(w, "invalid instance id", http.StatusBadRequest)
		return
	}
	info := infos[id]
	switch r.FormValue("type") {
	case "machine-info":
		if info.MachineInfo != nil {
			w.Write(info.MachineInfo())
		}
	case "detailed-status":
		if info.DetailedStatus != nil {
			w.Write(info.DetailedStatus())
		}
	default:
		w.Write([]byte("unknown info type"))
	}
}

func makeUICrashType(info *BugInfo, startTime time.Time, repros map[string]bool) UICrashType {
	var crashes []UICrash
	for _, crash := range info.Crashes {
		crashes = append(crashes, UICrash{
			CrashInfo: *crash,
			Active:    crash.Time.After(startTime),
		})
	}
	triaged := reproStatus(info.HasRepro, info.HasCRepro, repros[info.Title],
		info.ReproAttempts >= MaxReproAttempts)
	return UICrashType{
		BugInfo:     *info,
		RankTooltip: higherRankTooltip(info.Title, info.TailTitles),
		New:         info.FirstTime.After(startTime),
		Active:      info.LastTime.After(startTime),
		Triaged:     triaged,
		Crashes:     crashes,
	}
}

// PROBE: makeUICrashTypeWithAI populates AI fields if workdir is provided.
func makeUICrashTypeWithAI(info *BugInfo, startTime time.Time, repros map[string]bool, workdir string) UICrashType {
	ct := makeUICrashType(info, startTime, repros)
	if workdir != "" {
		if tr := loadAITriageResult(workdir, info.ID); tr != nil {
			ct.AIScore = tr.Score
			ct.AIScoreColor = aiScoreColor(tr.Score)
			ct.AIVulnType = tr.VulnType
			ct.AIClass = tr.ExploitClass
		}
	}
	return ct
}

// PROBE: aiScoreColor returns a background color for AI score cells.
func aiScoreColor(score int) string {
	if score >= 70 {
		return "#FF8674"
	}
	if score >= 40 {
		return "#FFFFAA"
	}
	if score > 0 {
		return "#C8FFC8"
	}
	return "#F0F0F0"
}

// PROBE: isInternalCrashTitle filters syzkaller-internal crash titles from AI pages.
func isInternalCrashTitle(title string) bool {
	lower := strings.ToLower(title)
	for _, p := range []string{
		"suppressed report",
		"lost connection to test machine",
		"no output from test machine",
		"test machine is not executing programs",
		"executor failure",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// PROBE: aiTriageOnDisk represents the full ai-triage.json on disk.
type aiTriageOnDisk struct {
	Score        int    `json:"score"`
	Confidence   string `json:"confidence"`
	ExploitClass string `json:"exploit_class"`
	Summary      string `json:"summary"`
	BestVariant  string `json:"best_variant"`
	FocusHints   []string `json:"focus_hints"`
	Model        string `json:"model"`
	Provider     string `json:"provider"`
	VulnType     string `json:"-"`
	Reasoning    struct {
		VulnType      string `json:"vuln_type"`
		SlabCache     string `json:"slab_cache"`
		ObjectSize    int    `json:"object_size"`
		Primitive     string `json:"primitive"`
		TimingWindow  string `json:"timing_window"`
		SprayFeasible string `json:"spray_feasible"`
		SprayObjects  string `json:"spray_objects"`
		CrossCache    bool   `json:"cross_cache"`
		Controllable  string `json:"controllable"`
	} `json:"reasoning"`
	Timestamp    time.Time `json:"timestamp"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
}

func loadAITriageResult(workdir, crashID string) *aiTriageOnDisk {
	path := filepath.Join(workdir, "crashes", crashID, "ai-triage.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var result aiTriageOnDisk
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	result.VulnType = result.Reasoning.VulnType
	return &result
}

// higherRankTooltip generates the prioritized list of the titles with higher Rank
// than the firstTitle has.
func higherRankTooltip(firstTitle string, titlesInfo []*report.TitleFreqRank) string {
	baseRank := report.TitlesToImpact(firstTitle)
	res := ""
	for _, ti := range titlesInfo {
		if ti.Rank <= baseRank {
			continue
		}
		res += fmt.Sprintf("[rank %2v, freq %5.1f%%] %s\n",
			ti.Rank,
			100*float32(ti.Count)/float32(ti.Total),
			ti.Title)
	}
	if res != "" {
		return fmt.Sprintf("[rank %2v,  originally] %s\n%s", baseRank, firstTitle, res)
	}
	return res
}

var crashIDRe = regexp.MustCompile(`^\w+$`)

func (serv *HTTPServer) httpCrash(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	if !crashIDRe.MatchString(crashID) {
		http.Error(w, "invalid crash ID", http.StatusBadRequest)
		return
	}
	info, err := serv.CrashStore.BugInfo(crashID, true)
	if err != nil {
		http.Error(w, "failed to read crash info", http.StatusInternalServerError)
		return
	}
	data := UICrashPage{
		UIPageHeader: serv.pageHeader(r, info.Title),
		UICrashType:  makeUICrashTypeWithAI(info, serv.StartTime, nil, serv.Cfg.Workdir),
	}
	executeTemplate(w, crashTemplate, data)
}

func (serv *HTTPServer) httpCorpus(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	data := UICorpusPage{
		UIPageHeader: serv.pageHeader(r, "corpus"),
		Call:         r.FormValue("call"),
		RawCover:     serv.Cfg.RawCover,
	}
	for _, inp := range corpus.Items() {
		if data.Call != "" && data.Call != inp.StringCall() {
			continue
		}
		data.Inputs = append(data.Inputs, UIInput{
			Sig:   inp.Sig,
			Short: inp.Prog.String(),
			Cover: len(inp.Cover),
		})
	}
	sort.Slice(data.Inputs, func(i, j int) bool {
		a, b := data.Inputs[i], data.Inputs[j]
		if a.Cover != b.Cover {
			return a.Cover > b.Cover
		}
		return a.Short < b.Short
	})
	executeTemplate(w, corpusTemplate, data)
}

func (serv *HTTPServer) httpDownloadCorpus(w http.ResponseWriter, r *http.Request) {
	corpus := filepath.Join(serv.Cfg.Workdir, "corpus.db")
	file, err := os.Open(corpus)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to open corpus : %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	buf, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read corpus : %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf)
}

const (
	DoHTML int = iota
	DoSubsystemCover
	DoModuleCover
	DoFuncCover
	DoFileCover
	DoRawCoverFiles
	DoRawCover
	DoFilterPCs
	DoCoverJSONL
	DoCoverPrograms
)

func (serv *HTTPServer) httpCover(w http.ResponseWriter, r *http.Request) {
	if !serv.Cfg.Cover {
		serv.httpCoverFallback(w, r)
		return
	}
	if r.FormValue("jsonl") == "1" {
		serv.httpCoverCover(w, r, DoCoverJSONL)
		return
	}
	serv.httpCoverCover(w, r, DoHTML)
}

func (serv *HTTPServer) httpPrograms(w http.ResponseWriter, r *http.Request) {
	if !serv.Cfg.Cover {
		http.Error(w, "coverage is not enabled", http.StatusInternalServerError)
		return
	}
	if r.FormValue("jsonl") != "1" {
		http.Error(w, "only ?jsonl=1 param is supported", http.StatusBadRequest)
		return
	}
	serv.httpCoverCover(w, r, DoCoverPrograms)
}

func (serv *HTTPServer) httpSubsystemCover(w http.ResponseWriter, r *http.Request) {
	if !serv.Cfg.Cover {
		serv.httpCoverFallback(w, r)
		return
	}
	serv.httpCoverCover(w, r, DoSubsystemCover)
}

func (serv *HTTPServer) httpModuleCover(w http.ResponseWriter, r *http.Request) {
	if !serv.Cfg.Cover {
		serv.httpCoverFallback(w, r)
		return
	}
	serv.httpCoverCover(w, r, DoModuleCover)
}

const ctTextPlain = "text/plain; charset=utf-8"
const ctApplicationJSON = "application/json"

func (serv *HTTPServer) httpCoverCover(w http.ResponseWriter, r *http.Request, funcFlag int) {
	if !serv.Cfg.Cover {
		http.Error(w, "coverage is not enabled", http.StatusInternalServerError)
		return
	}

	coverInfo := serv.Cover.Load()
	if coverInfo == nil {
		http.Error(w, "coverage is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}

	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}

	rg, err := coverInfo.ReportGenerator.Get()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}

	if r.FormValue("flush") != "" {
		defer func() {
			coverInfo.ReportGenerator.Reset()
			debug.FreeOSMemory()
		}()
	}

	var progs []coverProgRaw
	if sig := r.FormValue("input"); sig != "" {
		inp := corpus.Item(sig)
		if inp == nil {
			http.Error(w, "unknown input hash", http.StatusInternalServerError)
			return
		}
		if r.FormValue("update_id") != "" {
			updateID, err := strconv.Atoi(r.FormValue("update_id"))
			if err != nil || updateID < 0 || updateID >= len(inp.Updates) {
				http.Error(w, "bad call_id", http.StatusBadRequest)
				return
			}
			progs = append(progs, coverProgRaw{
				sig:  sig,
				prog: inp.Prog,
				pcs:  CoverToPCs(serv.Cfg, inp.Updates[updateID].RawCover),
			})
		} else {
			progs = append(progs, coverProgRaw{
				sig:  sig,
				prog: inp.Prog,
				pcs:  CoverToPCs(serv.Cfg, inp.Cover),
			})
		}
	} else {
		call := r.FormValue("call")
		for _, inp := range corpus.Items() {
			if call != "" && call != inp.StringCall() {
				continue
			}
			progs = append(progs, coverProgRaw{
				sig:  inp.Sig,
				prog: inp.Prog,
				pcs:  CoverToPCs(serv.Cfg, inp.Cover),
			})
		}
	}

	var coverFilter map[uint64]struct{}
	if r.FormValue("filter") != "" || funcFlag == DoFilterPCs {
		if coverInfo.CoverFilter == nil {
			http.Error(w, "cover is not filtered in config", http.StatusInternalServerError)
			return
		}
		coverFilter = coverInfo.CoverFilter
	}

	params := cover.HandlerParams{
		Progs:  serv.serializeCoverProgs(progs),
		Filter: coverFilter,
		Debug:  r.FormValue("debug") != "",
		Force:  r.FormValue("force") != "",
	}

	type handlerFuncType func(w io.Writer, params cover.HandlerParams) error
	flagToFunc := map[int]struct {
		Do          handlerFuncType
		contentType string
	}{
		DoHTML:           {rg.DoHTML, ""},
		DoSubsystemCover: {rg.DoSubsystemCover, ""},
		DoModuleCover:    {rg.DoModuleCover, ""},
		DoFuncCover:      {rg.DoFuncCover, ctTextPlain},
		DoFileCover:      {rg.DoFileCover, ctTextPlain},
		DoRawCoverFiles:  {rg.DoRawCoverFiles, ctTextPlain},
		DoRawCover:       {rg.DoRawCover, ctTextPlain},
		DoFilterPCs:      {rg.DoFilterPCs, ctTextPlain},
		DoCoverJSONL:     {rg.DoCoverJSONL, ctApplicationJSON},
		DoCoverPrograms:  {rg.DoCoverPrograms, ctApplicationJSON},
	}

	if ct := flagToFunc[funcFlag].contentType; ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	if err := flagToFunc[funcFlag].Do(w, params); err != nil {
		http.Error(w, fmt.Sprintf("failed to generate coverage profile: %v", err), http.StatusInternalServerError)
		return
	}
}

type coverProgRaw struct {
	sig  string
	prog *prog.Prog
	pcs  []uint64
}

// Once the total size of corpus programs exceeds 100MB, skip fs images from it.
const compactProgsCutOff = 100 * 1000 * 1000

func (serv *HTTPServer) serializeCoverProgs(rawProgs []coverProgRaw) []cover.Prog {
	skipImages := false
outerLoop:
	for {
		var flags []prog.SerializeFlag
		if skipImages {
			flags = append(flags, prog.SkipImages)
		}
		totalSize := 0
		var ret []cover.Prog
		for _, item := range rawProgs {
			prog := cover.Prog{
				Sig:  item.sig,
				Data: string(item.prog.Serialize(flags...)),
				PCs:  item.pcs,
			}
			totalSize += len(prog.Data)
			if totalSize > compactProgsCutOff && !skipImages {
				log.Logf(0, "total size of corpus programs is too big, "+
					"full fs image won't be included in the cover reports")
				skipImages = true
				continue outerLoop
			}
			ret = append(ret, prog)
		}
		return ret
	}
}

func (serv *HTTPServer) httpCoverFallback(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	calls := make(map[int][]int)
	for s := range corpus.Signal() {
		id, errno := prog.DecodeFallbackSignal(uint64(s))
		calls[id] = append(calls[id], errno)
	}
	data := &UIFallbackCoverData{
		UIPageHeader: serv.pageHeader(r, "fallback coverage"),
	}
	if obj := serv.EnabledSyscalls.Load(); obj != nil {
		for call := range obj.(map[*prog.Syscall]bool) {
			errnos := calls[call.ID]
			sort.Ints(errnos)
			successful := 0
			for len(errnos) != 0 && errnos[0] == 0 {
				successful++
				errnos = errnos[1:]
			}
			data.Calls = append(data.Calls, UIFallbackCall{
				Name:       call.Name,
				Successful: successful,
				Errnos:     errnos,
			})
		}
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	executeTemplate(w, fallbackCoverTemplate, data)
}

func (serv *HTTPServer) httpFuncCover(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoFuncCover)
}

func (serv *HTTPServer) httpFileCover(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoFileCover)
}

func (serv *HTTPServer) httpPrio(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}

	callName := r.FormValue("call")
	call := serv.Cfg.Target.SyscallMap[callName]
	if call == nil {
		http.Error(w, fmt.Sprintf("unknown call: %v", callName), http.StatusInternalServerError)
		return
	}

	var progs []*prog.Prog
	for _, inp := range corpus.Items() {
		progs = append(progs, inp.Prog)
	}

	var enabled map[*prog.Syscall]bool
	if obj := serv.EnabledSyscalls.Load(); obj != nil {
		enabled = obj.(map[*prog.Syscall]bool)
	}
	prios, generatable := serv.Cfg.Target.CalculatePriorities(progs, enabled)

	data := &UIPrioData{
		UIPageHeader: serv.pageHeader(r, "syscall priorities"),
		Call:         callName,
	}
	for i, p := range prios[call.ID] {
		syscall := serv.Cfg.Target.Syscalls[i]
		if !generatable[syscall] {
			continue
		}
		data.Prios = append(data.Prios, UIPrio{syscall.Name, p})
	}
	sort.Slice(data.Prios, func(i, j int) bool {
		return data.Prios[i].Prio > data.Prios[j].Prio
	})
	executeTemplate(w, prioTemplate, data)
}

func (serv *HTTPServer) httpFile(w http.ResponseWriter, r *http.Request) {
	file := filepath.Clean(r.FormValue("name"))
	if !strings.HasPrefix(file, "crashes/") && !strings.HasPrefix(file, "corpus/") {
		http.Error(w, "oh, oh, oh!", http.StatusInternalServerError)
		return
	}
	data, err := os.ReadFile(filepath.Join(serv.Cfg.Workdir, file))
	if err != nil {
		http.Error(w, "failed to read the file", http.StatusInternalServerError)
		return
	}
	serv.textPage(w, r, "file", data)
}

func (serv *HTTPServer) httpInput(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	inp := corpus.Item(r.FormValue("sig"))
	if inp == nil {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(inp.Prog.Serialize())
}

func (serv *HTTPServer) httpDebugInput(w http.ResponseWriter, r *http.Request) {
	corpus := serv.Corpus.Load()
	if corpus == nil {
		http.Error(w, "the corpus information is not yet available", http.StatusInternalServerError)
		return
	}
	inp := corpus.Item(r.FormValue("sig"))
	if inp == nil {
		http.Error(w, "can't find the input", http.StatusInternalServerError)
		return
	}
	getIDs := func(callID int) []int {
		ret := []int{}
		for id, update := range inp.Updates {
			if update.Call == callID {
				ret = append(ret, id)
			}
		}
		return ret
	}
	var calls []UIRawCallCover
	for pos, line := range strings.Split(string(inp.Prog.Serialize()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		calls = append(calls, UIRawCallCover{
			Sig:       r.FormValue("sig"),
			Call:      line,
			UpdateIDs: getIDs(pos),
		})
	}
	extraIDs := getIDs(-1)
	if len(extraIDs) > 0 {
		calls = append(calls, UIRawCallCover{
			Sig:       r.FormValue("sig"),
			Call:      prog.ExtraCallName,
			UpdateIDs: extraIDs,
		})
	}
	data := UIRawCoverPage{
		UIPageHeader: serv.pageHeader(r, "raw coverage"),
		Calls:        calls,
	}
	executeTemplate(w, rawCoverTemplate, data)
}

func (serv *HTTPServer) modulesInfo(w http.ResponseWriter, r *http.Request) {
	cover := serv.Cover.Load()
	if cover == nil {
		http.Error(w, "info is not ready, please try again later after fuzzer started", http.StatusInternalServerError)
		return
	}
	serv.jsonPage(w, r, "modules", cover.Modules)
}

func (serv *HTTPServer) httpAddCandidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST method supported", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseMultipartForm(20 << 20)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse form: %v", err), http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to retrieve file from form-data: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read file: %v", err), http.StatusBadRequest)
		return
	}
	prog, err := ParseSeed(serv.Cfg.Target, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse seed: %v", err), http.StatusBadRequest)
		return
	}
	if !prog.OnlyContains(serv.Fuzzer.Load().Config.EnabledCalls) {
		http.Error(w, "contains disabled syscall", http.StatusBadRequest)
		return
	}
	var flags fuzzer.ProgFlags
	flags |= fuzzer.ProgMinimized
	flags |= fuzzer.ProgSmashed
	candidates := []fuzzer.Candidate{{
		Prog:  prog,
		Flags: flags,
	}}
	serv.Fuzzer.Load().AddCandidates(candidates)
}

var alphaNumRegExp = regexp.MustCompile(`^[a-zA-Z0-9]*$`)

func isAlphanumeric(s string) bool {
	return alphaNumRegExp.MatchString(s)
}

func (serv *HTTPServer) httpReport(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	if !isAlphanumeric(crashID) {
		http.Error(w, "wrong id", http.StatusBadRequest)
		return
	}

	info, err := serv.CrashStore.Report(crashID)
	if err != nil {
		http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	commitDesc := ""
	if info.Tag != "" {
		commitDesc = fmt.Sprintf(" on commit %s.", info.Tag)
	}
	fmt.Fprintf(w, "Syzkaller hit '%s' bug%s.\n\n", info.Title, commitDesc)
	if len(info.Report) != 0 {
		fmt.Fprintf(w, "%s\n\n", info.Report)
	}
	if len(info.Prog) == 0 && len(info.CProg) == 0 {
		fmt.Fprintf(w, "The bug is not reproducible.\n")
	} else {
		fmt.Fprintf(w, "Syzkaller reproducer:\n%s\n\n", info.Prog)
		if len(info.CProg) != 0 {
			fmt.Fprintf(w, "C reproducer:\n%s\n\n", info.CProg)
		}
	}
}

func (serv *HTTPServer) httpRawCover(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoRawCover)
}

func (serv *HTTPServer) httpRawCoverFiles(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoRawCoverFiles)
}

func (serv *HTTPServer) httpFilterPCs(w http.ResponseWriter, r *http.Request) {
	serv.httpCoverCover(w, r, DoFilterPCs)
}

func (serv *HTTPServer) collectDiffCrashes() (patchedOnly, both, inProgress *UIDiffTable) {
	for _, item := range serv.allDiffCrashes() {
		if item.PatchedOnly() {
			if patchedOnly == nil {
				patchedOnly = &UIDiffTable{Title: "Patched-only"}
			}
			patchedOnly.List = append(patchedOnly.List, item)
		} else if item.AffectsBoth() {
			if both == nil {
				both = &UIDiffTable{Title: "Affects both"}
			}
			both.List = append(both.List, item)
		} else {
			if inProgress == nil {
				inProgress = &UIDiffTable{Title: "In Progress"}
			}
			inProgress.List = append(inProgress.List, item)
		}
	}
	return
}

func (serv *HTTPServer) allDiffCrashes() []UIDiffBug {
	repros := serv.ReproLoop.Reproducing()
	var list []UIDiffBug
	for _, bug := range serv.DiffStore.List() {
		list = append(list, UIDiffBug{
			DiffBug:     bug,
			Reproducing: repros[bug.Title],
		})
	}
	sort.Slice(list, func(i, j int) bool {
		first, second := list[i], list[j]
		firstPatched, secondPatched := first.PatchedOnly(), second.PatchedOnly()
		if firstPatched != secondPatched {
			return firstPatched
		}
		return first.Title < second.Title
	})
	return list
}

func (serv *HTTPServer) collectCrashes(workdir string) ([]UICrashType, error) {
	list, err := serv.CrashStore.BugList()
	if err != nil {
		return nil, err
	}
	repros := serv.ReproLoop.Reproducing()
	var ret []UICrashType
	for _, info := range list {
		ret = append(ret, makeUICrashTypeWithAI(info, serv.StartTime, repros, workdir))
	}
	return ret, nil
}

func (serv *HTTPServer) httpJobs(w http.ResponseWriter, r *http.Request) {
	var list []*fuzzer.JobInfo
	if fuzzer := serv.Fuzzer.Load(); fuzzer != nil {
		list = fuzzer.RunningJobs()
	}
	if key := r.FormValue("id"); key != "" {
		for _, item := range list {
			if item.ID() == key {
				w.Write(item.Bytes())
				return
			}
		}
		http.Error(w, "invalid job id (the job has likely already finished)", http.StatusBadRequest)
		return
	}
	jobType := r.FormValue("type")
	data := UIJobList{
		UIPageHeader: serv.pageHeader(r, fmt.Sprintf("%s jobs", jobType)),
	}
	switch jobType {
	case "triage":
	case "smash":
	case "hints":
	default:
		http.Error(w, "unknown job type", http.StatusBadRequest)
		return
	}
	for _, item := range list {
		if item.Type != jobType {
			continue
		}
		data.Jobs = append(data.Jobs, UIJobInfo{
			ID:    item.ID(),
			Short: item.Name,
			Execs: item.Execs.Load(),
			Calls: strings.Join(item.Calls, ", "),
		})
	}
	sort.Slice(data.Jobs, func(i, j int) bool {
		a, b := data.Jobs[i], data.Jobs[j]
		return a.Short < b.Short
	})
	executeTemplate(w, jobListTemplate, data)
}

func reproStatus(hasRepro, hasCRepro, reproducing, nonReproducible bool) string {
	status := ""
	if hasRepro {
		status = "has repro"
		if hasCRepro {
			status = "has C repro"
		}
	} else if reproducing {
		status = "reproducing"
	} else if nonReproducible {
		status = "non-reproducible"
	}
	return status
}

func executeTemplate(w http.ResponseWriter, templ *template.Template, data any) {
	buf := new(bytes.Buffer)
	if err := templ.Execute(buf, data); err != nil {
		log.Logf(0, "failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

type UISummaryData struct {
	UIPageHeader
	Stats       []UIStat
	Crashes     []UICrashType
	PatchedOnly *UIDiffTable
	AffectsBoth *UIDiffTable
	InProgress  *UIDiffTable
	Log         string
}

type UIDiffTable struct {
	Title string
	List  []UIDiffBug
}

type UIVMData struct {
	UIPageHeader
	VMs []UIVMInfo
}

type UIVMInfo struct {
	Name           string
	State          string
	Since          time.Duration
	MachineInfo    string
	DetailedStatus string
}

type UISyscallsData struct {
	UIPageHeader
	Calls []UICallType
}

type UICrashPage struct {
	UIPageHeader
	UICrashType
}

type UICrashType struct {
	BugInfo
	RankTooltip  string
	New          bool // was first found in the current run
	Active       bool // was found in the current run
	Triaged      string
	Crashes      []UICrash
	AIScore      int    // PROBE: AI exploitability score (0=not analyzed)
	AIScoreColor string // PROBE: background color for score cell
	AIVulnType   string // PROBE: vulnerability type from AI analysis
	AIClass      string // PROBE: exploit class from AI analysis
}

type UICrash struct {
	CrashInfo
	Active bool
}

type UIDiffBug struct {
	DiffBug
	Reproducing bool
}

type UIStat struct {
	Name  string
	Value string
	Hint  string
	Link  string
}

type UICallType struct {
	Name           string
	ID             *int
	Inputs         int
	Total          int
	Cover          int
	CoverOverflows int
	CompsOverflows int
}

type UICorpusPage struct {
	UIPageHeader
	Call     string
	RawCover bool
	Inputs   []UIInput
}

type UIInput struct {
	Sig   string
	Short string
	Cover int
}

type UIPageHeader struct {
	Name      string
	PageTitle string
	// Relative page URL w/o GET parameters (e.g. "/stats").
	URLPath string
	// Relative page URL with GET parameters/fragment/etc (e.g. "/stats?foo=1#bar").
	CurrentURL string
	// syzkaller build git revision and link.
	GitRevision     string
	GitRevisionLink string
	ExpertMode      bool
	Paused          bool
}

func (serv *HTTPServer) pageHeader(r *http.Request, title string) UIPageHeader {
	revision, revisionLink := prog.GitRevisionBase, ""
	if len(revision) > 8 {
		revisionLink = vcs.LogLink(vcs.SyzkallerRepo, revision)
		revision = revision[:8]
	}
	url := r.URL
	url.Scheme = ""
	url.Host = ""
	url.User = nil
	return UIPageHeader{
		Name:            serv.Cfg.Name,
		PageTitle:       title,
		URLPath:         r.URL.Path,
		CurrentURL:      url.String(),
		GitRevision:     revision,
		GitRevisionLink: revisionLink,
		ExpertMode:      serv.expertMode,
		Paused:          serv.paused,
	}
}

func createPage(name string, data any) *template.Template {
	templ := pages.Create(fmt.Sprintf(string(mustReadHTML("common")), mustReadHTML(name)))
	templTypes = append(templTypes, templType{
		templ: templ,
		data:  data,
	})
	return templ
}

type templType struct {
	templ *template.Template
	data  any
}

var templTypes []templType

type UIPrioData struct {
	UIPageHeader
	Call  string
	Prios []UIPrio
}

type UIPrio struct {
	Call string
	Prio int32
}

type UIFallbackCoverData struct {
	UIPageHeader
	Calls []UIFallbackCall
}

type UIFallbackCall struct {
	Name       string
	Successful int
	Errnos     []int
}

type UIRawCoverPage struct {
	UIPageHeader
	Calls []UIRawCallCover
}

type UIRawCallCover struct {
	Sig       string
	Call      string
	UpdateIDs []int
}

type UIJobList struct {
	UIPageHeader
	Jobs []UIJobInfo
}

type UIJobInfo struct {
	ID    string
	Short string
	Calls string
	Execs int32
}

type UITextPage struct {
	UIPageHeader
	Text []byte
	HTML template.HTML
}

// PROBE: AI triage interface for avoiding import cycle.
type aiTriager interface {
	IsRunning() bool
	Model() string
	Provider() string
	Cost() interface{} // returns aitriage.CostTracker
	LastStrategy() interface{}
	RunStepA(ctx context.Context)
	RunStepB(ctx context.Context)
}

func (serv *HTTPServer) httpAI(w http.ResponseWriter, r *http.Request) {
	data := UIAIPageData{
		UIPageHeader: serv.pageHeader(r, "AI"),
	}

	if serv.Triager == nil {
		data.Disabled = true
		data.Model = "none"
		data.Status = "Disabled"
		executeTemplate(w, aiTemplate, &data)
		return
	}

	// Status.
	type triagerStatus interface {
		IsRunning() bool
		NextBatchSec() int
	}
	if t, ok := serv.Triager.(triagerStatus); ok {
		if t.IsRunning() {
			data.Status = "Running..."
		} else {
			data.Status = "Active"
		}
		data.NextBatchSec = t.NextBatchSec()
	} else {
		data.Status = "Active"
	}

	// Model/provider info.
	data.Model = serv.Cfg.AITriage.Model
	data.Provider = serv.Cfg.AITriage.Provider
	if data.Provider == "" {
		if strings.HasPrefix(data.Model, "claude-") {
			data.Provider = "anthropic"
		} else {
			data.Provider = "openai"
		}
	}

	// Claude LLM cost.
	type costProvider interface {
		CostJSON() []byte
	}
	if cp, ok := serv.Triager.(costProvider); ok {
		var cost struct {
			TotalCalls   int     `json:"total_calls"`
			TotalInput   int     `json:"total_input_tokens"`
			TotalOutput  int     `json:"total_output_tokens"`
			TotalCostUSD float64 `json:"total_cost_usd"`
			TodayCostUSD float64 `json:"today_cost_usd"`
			TodayCalls   int     `json:"today_calls"`
			TodayInput   int     `json:"today_input_tokens"`
			TodayOutput  int     `json:"today_output_tokens"`
		}
		if costData := cp.CostJSON(); costData != nil {
			if json.Unmarshal(costData, &cost) == nil {
				data.TotalCalls = cost.TotalCalls
				data.TotalTokens = formatTokens(cost.TotalInput + cost.TotalOutput)
				data.TotalCostUSD = cost.TotalCostUSD
				data.TotalCostKRW = int(cost.TotalCostUSD * 1450)
				data.TodayCalls = cost.TodayCalls
				data.TodayTokens = formatTokens(cost.TodayInput + cost.TodayOutput)
				data.TodayCostUSD = cost.TodayCostUSD
				data.TodayCostKRW = int(cost.TodayCostUSD * 1450)
			}
		}
	}

	// GPT Embedding cost.
	type embCostProvider interface {
		EmbeddingCostJSON() []byte
	}
	if ep, ok := serv.Triager.(embCostProvider); ok {
		var embCost struct {
			TotalCalls   int     `json:"total_calls"`
			TotalInput   int     `json:"total_input_tokens"`
			TotalOutput  int     `json:"total_output_tokens"`
			TotalCostUSD float64 `json:"total_cost_usd"`
			TodayCostUSD float64 `json:"today_cost_usd"`
			TodayCalls   int     `json:"today_calls"`
			TodayInput   int     `json:"today_input_tokens"`
			TodayOutput  int     `json:"today_output_tokens"`
		}
		if embData := ep.EmbeddingCostJSON(); embData != nil {
			if json.Unmarshal(embData, &embCost) == nil {
				data.EmbEnabled = true
				data.EmbTodayCalls = embCost.TodayCalls
				data.EmbTodayTokens = formatTokens(embCost.TodayInput + embCost.TodayOutput)
				data.EmbTodayCostUSD = embCost.TodayCostUSD
				data.EmbTodayCostKRW = int(embCost.TodayCostUSD * 1450)
				data.EmbTotalCalls = embCost.TotalCalls
				data.EmbTotalTokens = formatTokens(embCost.TotalInput + embCost.TotalOutput)
				data.EmbTotalCostUSD = embCost.TotalCostUSD
				data.EmbTotalCostKRW = int(embCost.TotalCostUSD * 1450)
			}
		}
	}

	// Combined totals.
	data.CombinedTotalCostUSD = data.TotalCostUSD + data.EmbTotalCostUSD
	data.CombinedTotalCostKRW = int(data.CombinedTotalCostUSD * 1450)
	data.CombinedTodayCostUSD = data.TodayCostUSD + data.EmbTodayCostUSD
	data.CombinedTodayCostKRW = int(data.CombinedTodayCostUSD * 1450)

	// Quick stats from crash store.
	if serv.CrashStore != nil {
		list, _ := serv.CrashStore.BugList()
		for _, info := range list {
			if isInternalCrashTitle(info.Title) {
				continue
			}
			if tr := loadAITriageResult(serv.Cfg.Workdir, info.ID); tr != nil {
				data.AnalyzedCount++
				if tr.Score >= 70 {
					data.HighRiskCount++
				}
			} else {
				data.PendingCount++
			}
		}
	}

	// SyzGPT stats.
	type syzGPTProvider interface {
		SyzGPTStats() (int, int, int)
	}
	if sp, ok := serv.Triager.(syzGPTProvider); ok {
		gen, valid, inj := sp.SyzGPTStats()
		data.SyzGPTGenerated = gen
		data.SyzGPTValid = valid
		data.SyzGPTInjected = inj
		if gen > 0 {
			data.SyzGPTValidRate = valid * 100 / gen
		}
	}

	// Embedding model info.
	type embModelProvider interface {
		EmbeddingModel() (string, string)
	}
	if mp, ok := serv.Triager.(embModelProvider); ok {
		data.EmbModel, data.EmbProvider = mp.EmbeddingModel()
	}

	// Embeddings stats.
	type embeddingProvider interface {
		EmbeddingsJSON() []byte
	}
	if ep, ok := serv.Triager.(embeddingProvider); ok {
		var ed struct {
			Embeddings []struct{} `json:"embeddings"`
			Clusters   []struct{} `json:"clusters"`
		}
		if raw := ep.EmbeddingsJSON(); raw != nil {
			json.Unmarshal(raw, &ed)
		}
		data.TotalEmbeddings = len(ed.Embeddings)
		data.TotalClusters = len(ed.Clusters)
	}

	// Strategy timestamp.
	strategyPath := filepath.Join(serv.Cfg.Workdir, "ai-strategy.json")
	if stratData, err := os.ReadFile(strategyPath); err == nil {
		var strat struct {
			Timestamp time.Time `json:"timestamp"`
		}
		if json.Unmarshal(stratData, &strat) == nil && !strat.Timestamp.IsZero() {
			data.HasStrategy = true
			data.StrategyTime = strat.Timestamp
		}
	}

	executeTemplate(w, aiTemplate, &data)
}

// httpAITriage serves the /ai/triage page with crash analysis and strategy details.
func (serv *HTTPServer) httpAITriage(w http.ResponseWriter, r *http.Request) {
	data := UIAITriageData{
		UIPageHeader: serv.pageHeader(r, "AI Triage"),
	}

	if serv.Triager == nil {
		data.Disabled = true
		data.Model = "none"
		data.Status = "Disabled"
		executeTemplate(w, aiTriageTemplate, &data)
		return
	}

	// Status.
	type triagerStatus interface {
		IsRunning() bool
		NextBatchSec() int
	}
	if t, ok := serv.Triager.(triagerStatus); ok {
		if t.IsRunning() {
			data.Status = "Running..."
		} else {
			data.Status = "Active"
		}
		data.NextBatchSec = t.NextBatchSec()
	} else {
		data.Status = "Active"
	}

	// Model/provider info.
	data.Model = serv.Cfg.AITriage.Model
	data.Provider = serv.Cfg.AITriage.Provider
	if data.Provider == "" {
		if strings.HasPrefix(data.Model, "claude-") {
			data.Provider = "anthropic"
		} else {
			data.Provider = "openai"
		}
	}

	// Load crash analyses from disk.
	if serv.CrashStore != nil {
		list, _ := serv.CrashStore.BugList()
		for _, info := range list {
			if isInternalCrashTitle(info.Title) {
				continue
			}
			crash := UIAICrash{
				ID:    info.ID,
				Title: info.Title,
			}
			if tr := loadAITriageResult(serv.Cfg.Workdir, info.ID); tr != nil {
				crash.Score = tr.Score
				crash.HasScore = true
				crash.ScoreColor = aiScoreColor(tr.Score)
				crash.ExploitClass = tr.ExploitClass
				crash.VulnType = tr.VulnType
				crash.Summary = tr.Summary
				crash.Confidence = tr.Confidence
				crash.SlabCache = tr.Reasoning.SlabCache
				crash.Primitive = tr.Reasoning.Primitive
				crash.TimingWindow = tr.Reasoning.TimingWindow
				crash.AnalyzedAt = tr.Timestamp
				data.AnalyzedCount++
			} else {
				data.PendingCount++
			}
			data.Crashes = append(data.Crashes, crash)
		}
	}

	// Load strategy from disk.
	strategyPath := filepath.Join(serv.Cfg.Workdir, "ai-strategy.json")
	if stratData, err := os.ReadFile(strategyPath); err == nil {
		var strat struct {
			Summary        string    `json:"summary"`
			Timestamp      time.Time `json:"timestamp"`
			SyscallWeights []struct {
				Name   string  `json:"name"`
				Weight float64 `json:"weight"`
			} `json:"syscall_weights"`
			SeedHints []struct {
				Syscalls []string `json:"syscalls"`
				Target   string   `json:"target"`
				Reason   string   `json:"reason"`
			} `json:"seed_hints"`
			MutationHints struct {
				SpliceWeight    float64 `json:"splice_weight"`
				InsertWeight    float64 `json:"insert_weight"`
				MutateArgWeight float64 `json:"mutate_arg_weight"`
				RemoveWeight    float64 `json:"remove_weight"`
				Reason          string  `json:"reason"`
			} `json:"mutation_hints"`
			FocusTargets []struct {
				CrashTitle string `json:"crash_title"`
				Priority   int    `json:"priority"`
			} `json:"focus_targets"`
			SeedsInjected  int      `json:"seeds_injected"`
			SeedsAccepted  int      `json:"seeds_accepted"`
			WeightsApplied int      `json:"weights_applied"`
			SeedErrors     []string `json:"seed_errors"`
			WeightErrors   []string `json:"weight_errors"`
		}
		if json.Unmarshal(stratData, &strat) == nil {
			data.HasStrategy = true
			data.Strategy.Summary = strat.Summary
			data.Strategy.Timestamp = strat.Timestamp
			for _, sw := range strat.SyscallWeights {
				data.Strategy.SyscallWeights = append(data.Strategy.SyscallWeights, UIAISyscallWeight{
					Name: sw.Name, Weight: sw.Weight,
				})
			}
			for _, sh := range strat.SeedHints {
				data.Strategy.SeedHints = append(data.Strategy.SeedHints, UIAISeedHint{
					Syscalls: sh.Syscalls, Target: sh.Target, Reason: sh.Reason,
				})
			}
			data.Strategy.SeedsInjected = strat.SeedsInjected
			data.Strategy.SeedsAccepted = strat.SeedsAccepted
			data.Strategy.WeightsApplied = strat.WeightsApplied
			data.Strategy.WeightsTotal = len(strat.SyscallWeights)
			data.Strategy.SeedErrors = strat.SeedErrors
			data.Strategy.WeightErrors = strat.WeightErrors
			data.Strategy.MutationSummary = strat.MutationHints.Reason
			if data.Strategy.MutationSummary == "" {
				data.Strategy.MutationSummary = fmt.Sprintf("splice=%.1f insert=%.1f mutate=%.1f remove=%.1f",
					strat.MutationHints.SpliceWeight, strat.MutationHints.InsertWeight,
					strat.MutationHints.MutateArgWeight, strat.MutationHints.RemoveWeight)
			}
			for _, ft := range strat.FocusTargets {
				data.Strategy.FocusTargets = append(data.Strategy.FocusTargets, UIAIFocusTarget{
					CrashTitle: ft.CrashTitle, Priority: ft.Priority,
				})
			}
		}
	}

	// Claude LLM cost.
	type costProvider interface {
		CostJSON() []byte
	}
	if cp, ok := serv.Triager.(costProvider); ok {
		var cost struct {
			TotalCalls   int     `json:"total_calls"`
			TotalInput   int     `json:"total_input_tokens"`
			TotalOutput  int     `json:"total_output_tokens"`
			TotalCostUSD float64 `json:"total_cost_usd"`
			TodayCostUSD float64 `json:"today_cost_usd"`
			TodayCalls   int     `json:"today_calls"`
			TodayInput   int     `json:"today_input_tokens"`
			TodayOutput  int     `json:"today_output_tokens"`
			History      []struct {
				Time          time.Time `json:"time"`
				Type          string    `json:"type"`
				InputTokens   int       `json:"input_tokens"`
				OutputTokens  int       `json:"output_tokens"`
				CostUSD       float64   `json:"cost_usd"`
				Success       bool      `json:"success"`
				ResultSummary string    `json:"result_summary"`
				Error         string    `json:"error"`
			} `json:"history"`
		}
		if costData := cp.CostJSON(); costData != nil {
			if json.Unmarshal(costData, &cost) == nil {
				data.TotalCalls = cost.TotalCalls
				data.TotalTokens = formatTokens(cost.TotalInput + cost.TotalOutput)
				data.TotalCostUSD = cost.TotalCostUSD
				data.TotalCostKRW = int(cost.TotalCostUSD * 1450)
				data.TodayCalls = cost.TodayCalls
				data.TodayTokens = formatTokens(cost.TodayInput + cost.TodayOutput)
				data.TodayCostUSD = cost.TodayCostUSD
				data.TodayCostKRW = int(cost.TodayCostUSD * 1450)

				for i := len(cost.History) - 1; i >= 0; i-- {
					h := cost.History[i]
					if h.Type != "crash" && h.Type != "strategy" {
						continue
					}
					data.History = append(data.History, UIAPICall{
						Time:          h.Time,
						Type:          h.Type,
						Input:         h.InputTokens,
						Output:        h.OutputTokens,
						CostUSD:       h.CostUSD,
						Success:       h.Success,
						ResultSummary: h.ResultSummary,
						Error:         h.Error,
					})
				}
			}
		}
	}

	// SyzGPT stats.
	type syzGPTProvider interface {
		SyzGPTStats() (int, int, int)
	}
	if sp, ok := serv.Triager.(syzGPTProvider); ok {
		gen, valid, inj := sp.SyzGPTStats()
		data.SyzGPTGenerated = gen
		data.SyzGPTValid = valid
		data.SyzGPTInjected = inj
		if gen > 0 {
			data.SyzGPTValidRate = valid * 100 / gen
		}
	}

	executeTemplate(w, aiTriageTemplate, &data)
}

func (serv *HTTPServer) httpAIAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST supported", http.StatusMethodNotAllowed)
		return
	}
	if serv.Triager == nil {
		http.Error(w, "AI triage is disabled", http.StatusBadRequest)
		return
	}
	type stepARunner interface {
		RunStepA(ctx context.Context)
		IsRunning() bool
	}
	if t, ok := serv.Triager.(stepARunner); ok {
		if t.IsRunning() {
			http.Redirect(w, r, "/ai/triage", http.StatusFound)
			return
		}
		go t.RunStepA(context.Background())
	}
	http.Redirect(w, r, "/ai/triage", http.StatusFound)
}

func (serv *HTTPServer) httpAIStrategize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST supported", http.StatusMethodNotAllowed)
		return
	}
	if serv.Triager == nil {
		http.Error(w, "AI triage is disabled", http.StatusBadRequest)
		return
	}
	type stepBRunner interface {
		RunStepB(ctx context.Context)
		IsRunning() bool
	}
	if t, ok := serv.Triager.(stepBRunner); ok {
		if t.IsRunning() {
			http.Redirect(w, r, "/ai/triage", http.StatusFound)
			return
		}
		go t.RunStepB(context.Background())
	}
	http.Redirect(w, r, "/ai/triage", http.StatusFound)
}

func (serv *HTTPServer) httpAIEmbed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST supported", http.StatusMethodNotAllowed)
		return
	}
	if serv.Triager == nil {
		http.Error(w, "AI triage is disabled", http.StatusBadRequest)
		return
	}
	type embRunner interface {
		RunStepEmbeddings(ctx context.Context)
		IsRunning() bool
	}
	if t, ok := serv.Triager.(embRunner); ok {
		if t.IsRunning() {
			http.Redirect(w, r, "/ai/embeddings", http.StatusFound)
			return
		}
		go t.RunStepEmbeddings(context.Background())
	}
	http.Redirect(w, r, "/ai/embeddings", http.StatusFound)
}

func (serv *HTTPServer) httpAICrash(w http.ResponseWriter, r *http.Request) {
	crashID := r.FormValue("id")
	if crashID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	tr := loadAITriageResult(serv.Cfg.Workdir, crashID)
	if tr == nil {
		http.Error(w, "no AI analysis found for this crash", http.StatusNotFound)
		return
	}

	// Get crash title from CrashStore.
	title := crashID
	if serv.CrashStore != nil {
		if info, err := serv.CrashStore.BugInfo(crashID, false); err == nil {
			title = info.Title
		}
	}

	data := UIAICrashPage{
		UIPageHeader:  serv.pageHeader(r, "AI"),
		CrashID:       crashID,
		Title:         title,
		Score:         tr.Score,
		ScoreColor:    aiScoreColor(tr.Score),
		Confidence:    tr.Confidence,
		ExploitClass:  tr.ExploitClass,
		Summary:       tr.Summary,
		BestVariant:   tr.BestVariant,
		FocusHints:    tr.FocusHints,
		Model:         tr.Model,
		Provider:      tr.Provider,
		VulnType:      tr.Reasoning.VulnType,
		SlabCache:     tr.Reasoning.SlabCache,
		ObjectSize:    tr.Reasoning.ObjectSize,
		Primitive:     tr.Reasoning.Primitive,
		TimingWindow:  tr.Reasoning.TimingWindow,
		SprayFeasible: tr.Reasoning.SprayFeasible,
		SprayObjects:  tr.Reasoning.SprayObjects,
		CrossCache:    tr.Reasoning.CrossCache,
		Controllable:  tr.Reasoning.Controllable,
		AnalyzedAt:    tr.Timestamp,
		InputTokens:   tr.InputTokens,
		OutputTokens:  tr.OutputTokens,
	}

	executeTemplate(w, aiCrashTemplate, &data)
}

// httpAILog returns console log entries as JSON for AJAX polling.
// Supports ?filter=triage|embeddings to return only matching lines.
func (serv *HTTPServer) httpAILog(w http.ResponseWriter, r *http.Request) {
	type logEntry struct {
		Time    time.Time `json:"time"`
		Message string    `json:"message"`
	}
	type logResponse struct {
		Running bool       `json:"running"`
		Lines   []logEntry `json:"lines"`
	}

	resp := logResponse{}
	if serv.Triager != nil {
		type logProvider interface {
			IsRunning() bool
		}
		if t, ok := serv.Triager.(logProvider); ok {
			resp.Running = t.IsRunning()
		}
		type rawLogProvider interface {
			LogLinesJSON() []byte
		}
		if t, ok := serv.Triager.(rawLogProvider); ok {
			var lines []logEntry
			if data := t.LogLinesJSON(); data != nil {
				json.Unmarshal(data, &lines)
			}
			// Apply filter if specified.
			if filter := r.FormValue("filter"); filter != "" && filter != "all" {
				var filtered []logEntry
				for _, l := range lines {
					if matchLogFilter(l.Message, filter) {
						filtered = append(filtered, l)
					}
				}
				lines = filtered
			}
			resp.Lines = lines
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// matchLogFilter checks if a log message matches the given filter.
func matchLogFilter(msg, filter string) bool {
	switch filter {
	case "triage":
		return strings.Contains(msg, "[Step A]") ||
			strings.Contains(msg, "[Step B]") ||
			strings.Contains(msg, "[Step C]") ||
			strings.Contains(msg, "[Triage]")
	case "embeddings":
		return strings.Contains(msg, "[Embeddings]")
	default:
		return true
	}
}

func formatTokens(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}

// PROBE: AI dashboard page data types (Phase 3).

type UIAIPageData struct {
	UIPageHeader

	Disabled bool

	// Status.
	Model        string
	Provider     string
	EmbModel     string
	EmbProvider  string
	Status       string
	NextBatchSec int

	// Claude (LLM) Cost.
	TodayCalls   int
	TodayTokens  string
	TodayCostUSD float64
	TodayCostKRW int
	TotalCalls   int
	TotalTokens  string
	TotalCostUSD float64
	TotalCostKRW int

	// GPT Embedding Cost (separate tracking).
	EmbTodayCalls   int
	EmbTodayTokens  string
	EmbTodayCostUSD float64
	EmbTodayCostKRW int
	EmbTotalCalls   int
	EmbTotalTokens  string
	EmbTotalCostUSD float64
	EmbTotalCostKRW int
	EmbEnabled      bool

	// Combined totals.
	CombinedTotalCostUSD float64
	CombinedTotalCostKRW int
	CombinedTodayCostUSD float64
	CombinedTodayCostKRW int

	// Quick stats.
	AnalyzedCount   int
	PendingCount    int
	HighRiskCount   int
	TotalClusters   int
	TotalEmbeddings int

	// SyzGPT stats (Phase 7a).
	SyzGPTGenerated int
	SyzGPTValid     int
	SyzGPTInjected  int
	SyzGPTValidRate int // percentage

	HasStrategy  bool
	StrategyTime time.Time
}

// UIAITriageData is the data struct for /ai/triage page.
type UIAITriageData struct {
	UIPageHeader

	Disabled bool

	// Status.
	Model        string
	Provider     string
	Status       string
	NextBatchSec int

	// Claude (LLM) Cost.
	TodayCalls   int
	TodayTokens  string
	TodayCostUSD float64
	TodayCostKRW int
	TotalCalls   int
	TotalTokens  string
	TotalCostUSD float64
	TotalCostKRW int

	// SyzGPT stats (Phase 7a).
	SyzGPTGenerated int
	SyzGPTValid     int
	SyzGPTInjected  int
	SyzGPTValidRate int // percentage

	// Crash Analysis.
	Crashes       []UIAICrash
	AnalyzedCount int
	PendingCount  int

	// Strategy.
	HasStrategy bool
	Strategy    UIAIStrategy

	// History.
	History []UIAPICall
}

type UIAICrash struct {
	ID           string
	Title        string
	Score        int
	HasScore     bool
	ScoreColor   string
	ExploitClass string
	VulnType     string
	Summary      string
	Confidence   string
	SlabCache    string
	Primitive    string
	TimingWindow string
	AnalyzedAt   time.Time
}

type UIAIStrategy struct {
	Timestamp       time.Time
	Summary         string
	SyscallWeights  []UIAISyscallWeight
	SeedHints       []UIAISeedHint
	SeedsInjected   int
	SeedsAccepted   int
	WeightsApplied  int
	WeightsTotal    int
	SeedErrors      []string
	WeightErrors    []string
	MutationSummary string
	FocusTargets    []UIAIFocusTarget
}

type UIAISyscallWeight struct {
	Name   string
	Weight float64
}

type UIAISeedHint struct {
	Syscalls []string
	Target   string
	Reason   string
}

type UIAIFocusTarget struct {
	CrashTitle string
	Priority   int
}

type UIAPICall struct {
	Time          time.Time
	Type          string
	Input         int
	Output        int
	CostUSD       float64
	Success       bool
	ResultSummary string
	Error         string
}

type UIAICrashPage struct {
	UIPageHeader
	CrashID       string
	Title         string
	Score         int
	ScoreColor    string
	Confidence    string
	ExploitClass  string
	Summary       string
	BestVariant   string
	FocusHints    []string
	Model         string
	Provider      string
	VulnType      string
	SlabCache     string
	ObjectSize    int
	Primitive     string
	TimingWindow  string
	SprayFeasible string
	SprayObjects  string
	CrossCache    bool
	Controllable  string
	AnalyzedAt    time.Time
	InputTokens   int
	OutputTokens  int
}

// PROBE: AI Analytics dashboard data types (Phase 3).

type UIAIAnalyticsData struct {
	UIPageHeader
	Disabled bool

	// Summary cards.
	TotalCostUSD      float64
	TotalCostKRW      int
	TodayCostUSD      float64
	ProjectedMonthUSD float64
	ProjectedMonthKRW int
	AnalyzedCount     int
	HighRiskCount     int
	SuccessRate       float64

	// Section 1: Cost.
	DailyCostJSON      template.JS
	CostBreakdownJSON  template.JS
	CumulativeCostJSON template.JS
	TokenEfficiency    []UITokenEfficiency

	// Cost efficiency.
	CostPerCrash    float64
	CostPerHighRisk float64
	CostPerDay      float64

	// Section 2: Crash.
	ScoreDistJSON    template.JS
	ExploitClassJSON template.JS
	VulnTypes        []UIVulnTypeStat
	AvgScore         float64
	MaxScore         int

	// Section 3: Strategy.
	TotalSeedsInjected  int
	TotalSeedsAccepted  int
	TotalWeightsApplied int
	TotalWeightsTotal   int
	FocusTriggered      int
	StrategyRuns        []UIStrategyRun

	// SyzGPT.
	SyzGPTGenerated int
	SyzGPTValid     int
	SyzGPTInjected  int
	SyzGPTValidRate int

	// Section 4: API.
	AvgCrashTokens    UIAvgTokens
	AvgStrategyTokens UIAvgTokens
	ErrorLog          []UIAPIError
	CallsPerDayJSON   template.JS
	TotalCalls        int

	// Section 5: Crash Timeline.
	CrashTimelineJSON template.JS

	// Section 6: Embedding Analytics.
	EmbCostUSD      float64
	EmbClusters     int
	DedupRatio      float64
	CombinedCostUSD float64
	CombinedCostKRW int
}

type UITokenEfficiency struct {
	Label string
	Input int
	Output int
	Cost  float64
}

type UIVulnTypeStat struct {
	Type  string
	Count int
	Pct   float64
}

type UIStrategyRun struct {
	Time           time.Time
	SeedsInjected  int
	SeedsAccepted  int
	WeightsApplied int
	Summary        string
}

type UIAvgTokens struct {
	AvgInput  int
	AvgOutput int
	Count     int
}

type UIAPIError struct {
	Time  time.Time
	Type  string
	Error string
}

func (serv *HTTPServer) httpAIAnalytics(w http.ResponseWriter, r *http.Request) {
	data := UIAIAnalyticsData{
		UIPageHeader: serv.pageHeader(r, "AI Analytics"),
	}

	if serv.Triager == nil {
		data.Disabled = true
		executeTemplate(w, aiAnalyticsTemplate, &data)
		return
	}

	// Parse analytics data from triager.
	type analyticsProvider interface {
		AnalyticsJSON() []byte
	}
	type costProvider interface {
		CostJSON() []byte
	}

	var ad struct {
		DailyStats   []dailyStat    `json:"daily_stats"`
		TotalCalls   int            `json:"total_calls"`
		TotalInput   int            `json:"total_input_tokens"`
		TotalOutput  int            `json:"total_output_tokens"`
		TotalCostUSD float64        `json:"total_cost_usd"`
		TodayCostUSD float64        `json:"today_cost_usd"`
		TodayCalls   int            `json:"today_calls"`
		History      []historyEntry `json:"history"`
	}
	if ap, ok := serv.Triager.(analyticsProvider); ok {
		json.Unmarshal(ap.AnalyticsJSON(), &ad)
	} else if cp, ok := serv.Triager.(costProvider); ok {
		// Fallback: use CostJSON if AnalyticsJSON not available.
		json.Unmarshal(cp.CostJSON(), &ad)
	}

	data.TotalCostUSD = ad.TotalCostUSD
	data.TotalCostKRW = int(ad.TotalCostUSD * 1450)
	data.TodayCostUSD = ad.TodayCostUSD
	data.TotalCalls = ad.TotalCalls

	// === Section 1: Cost Analytics ===
	serv.buildCostAnalytics(&data, ad.DailyStats, ad.History)

	// === Section 2: Crash Analysis Stats ===
	serv.buildCrashStats(&data)

	// === Section 3: Strategy Effectiveness ===
	serv.buildStrategyStats(&data)

	// === Section 4: API Performance ===
	serv.buildAPIPerformance(&data, ad.DailyStats, ad.History)

	// === Cost Efficiency ===
	if data.AnalyzedCount > 0 {
		data.CostPerCrash = data.TotalCostUSD / float64(data.AnalyzedCount)
	}
	if data.HighRiskCount > 0 {
		data.CostPerHighRisk = data.TotalCostUSD / float64(data.HighRiskCount)
	}
	if len(ad.DailyStats) > 0 {
		data.CostPerDay = data.TotalCostUSD / float64(len(ad.DailyStats))
	}

	// SyzGPT stats.
	type syzGPTProvider interface {
		SyzGPTStats() (int, int, int)
	}
	if sp, ok := serv.Triager.(syzGPTProvider); ok {
		gen, valid, inj := sp.SyzGPTStats()
		data.SyzGPTGenerated = gen
		data.SyzGPTValid = valid
		data.SyzGPTInjected = inj
		if gen > 0 {
			data.SyzGPTValidRate = valid * 100 / gen
		}
	}

	// === Section 5: Crash Timeline ===
	serv.buildCrashTimeline(&data)

	// === Section 6: Embedding Analytics ===
	type embCostProvider interface {
		EmbeddingCostJSON() []byte
	}
	if ep, ok := serv.Triager.(embCostProvider); ok {
		var embCost struct {
			TotalCostUSD float64 `json:"total_cost_usd"`
		}
		if embData := ep.EmbeddingCostJSON(); embData != nil {
			json.Unmarshal(embData, &embCost)
		}
		data.EmbCostUSD = embCost.TotalCostUSD
	}
	type embeddingProvider interface {
		EmbeddingsJSON() []byte
	}
	if ep, ok := serv.Triager.(embeddingProvider); ok {
		var ed struct {
			Embeddings []struct{} `json:"embeddings"`
			Clusters   []struct{} `json:"clusters"`
		}
		if raw := ep.EmbeddingsJSON(); raw != nil {
			json.Unmarshal(raw, &ed)
		}
		data.EmbClusters = len(ed.Clusters)
		totalEmb := len(ed.Embeddings)
		if totalEmb > 0 && data.EmbClusters > 0 {
			data.DedupRatio = (1.0 - float64(data.EmbClusters)/float64(totalEmb)) * 100
		}
	}
	data.CombinedCostUSD = data.TotalCostUSD + data.EmbCostUSD
	data.CombinedCostKRW = int(data.CombinedCostUSD * 1450)

	executeTemplate(w, aiAnalyticsTemplate, &data)
}

// buildCrashTimeline creates timeline JSON data for crash discovery over time.
func (serv *HTTPServer) buildCrashTimeline(data *UIAIAnalyticsData) {
	if serv.CrashStore == nil {
		return
	}
	list, err := serv.CrashStore.BugList()
	if err != nil {
		return
	}

	type timeSlot struct {
		Hour string
		High int
		Med  int
		Low  int
	}
	slots := make(map[string]*timeSlot)
	var slotKeys []string

	for _, info := range list {
		if isInternalCrashTitle(info.Title) {
			continue
		}
		hourKey := info.FirstTime.Format("01/02 15h")
		if _, ok := slots[hourKey]; !ok {
			slots[hourKey] = &timeSlot{Hour: hourKey}
			slotKeys = append(slotKeys, hourKey)
		}
		s := slots[hourKey]
		tr := loadAITriageResult(serv.Cfg.Workdir, info.ID)
		if tr != nil {
			if tr.Score >= 70 {
				s.High++
			} else if tr.Score >= 40 {
				s.Med++
			} else {
				s.Low++
			}
		} else {
			s.Low++
		}
	}

	sort.Strings(slotKeys)
	var rows []string
	for _, k := range slotKeys {
		s := slots[k]
		rows = append(rows, fmt.Sprintf("['%s', %d, %d, %d]", s.Hour, s.High, s.Med, s.Low))
	}
	data.CrashTimelineJSON = template.JS("[" + strings.Join(rows, ",") + "]")
}

func (serv *HTTPServer) httpAIEmbeddings(w http.ResponseWriter, r *http.Request) {
	data := UIAIEmbeddingsData{
		UIPageHeader: serv.pageHeader(r, "AI Embeddings"),
	}

	if serv.Triager == nil {
		data.Disabled = true
		executeTemplate(w, aiEmbeddingsTemplate, &data)
		return
	}

	// Embedding model info.
	type configProvider interface {
		EmbeddingModel() (string, string)
	}
	if cp, ok := serv.Triager.(configProvider); ok {
		data.Model, data.Provider = cp.EmbeddingModel()
	}

	// Embedding cost (today/total split).
	type embCostProvider interface {
		EmbeddingCostJSON() []byte
	}
	if ep, ok := serv.Triager.(embCostProvider); ok {
		var embCost struct {
			TotalCalls   int     `json:"total_calls"`
			TotalInput   int     `json:"total_input_tokens"`
			TotalCostUSD float64 `json:"total_cost_usd"`
			TodayCalls   int     `json:"today_calls"`
			TodayInput   int     `json:"today_input_tokens"`
			TodayCostUSD float64 `json:"today_cost_usd"`
			History      []struct {
				Time        time.Time `json:"time"`
				Type        string    `json:"type"`
				InputTokens int       `json:"input_tokens"`
				CostUSD     float64   `json:"cost_usd"`
				Success     bool      `json:"success"`
				Error       string    `json:"error"`
			} `json:"history"`
		}
		if embData := ep.EmbeddingCostJSON(); embData != nil {
			json.Unmarshal(embData, &embCost)
		}
		data.TodayCalls = embCost.TodayCalls
		data.TodayTokens = formatTokens(embCost.TodayInput)
		data.TodayCostUSD = embCost.TodayCostUSD
		data.TodayCostKRW = int(embCost.TodayCostUSD * 1450)
		data.TotalCalls = embCost.TotalCalls
		data.TotalTokens = formatTokens(embCost.TotalInput)
		data.TotalCostUSD = embCost.TotalCostUSD
		data.TotalCostKRW = int(embCost.TotalCostUSD * 1450)

		// API Call History (most recent first).
		for i := len(embCost.History) - 1; i >= 0; i-- {
			h := embCost.History[i]
			data.History = append(data.History, UIAPICall{
				Time:    h.Time,
				Type:    h.Type,
				Input:   h.InputTokens,
				CostUSD: h.CostUSD,
				Success: h.Success,
				Error:   h.Error,
			})
		}
	}

	// Embedding + cluster data.
	type embeddingProvider interface {
		EmbeddingsJSON() []byte
	}
	if ep, ok := serv.Triager.(embeddingProvider); ok {
		var ed struct {
			Embeddings []struct {
				CrashID   string    `json:"crash_id"`
				Title     string    `json:"title"`
				Tokens    int       `json:"tokens"`
				ClusterID int       `json:"cluster_id"`
				Timestamp time.Time `json:"timestamp"`
			} `json:"embeddings"`
			Clusters []struct {
				ID      int      `json:"id"`
				Title   string   `json:"title"`
				Members []string `json:"members"`
				AvgSim  float64  `json:"avg_sim"`
			} `json:"clusters"`
		}
		if raw := ep.EmbeddingsJSON(); raw != nil {
			json.Unmarshal(raw, &ed)
		}

		data.TotalEmbeddings = len(ed.Embeddings)
		data.TotalClusters = len(ed.Clusters)
		if len(ed.Embeddings) > 0 && len(ed.Clusters) > 0 {
			data.DedupRatio = (1.0 - float64(len(ed.Clusters))/float64(len(ed.Embeddings))) * 100
		}

		for _, emb := range ed.Embeddings {
			data.CrashClusters = append(data.CrashClusters, UICrashClusterRow{
				CrashID:   emb.CrashID,
				Title:     emb.Title,
				ClusterID: emb.ClusterID,
				Tokens:    emb.Tokens,
			})
			if emb.Timestamp.After(time.Time{}) {
				data.LastEmbeddingTime = emb.Timestamp.Format("2006-01-02 15:04:05")
			}
		}

		for _, c := range ed.Clusters {
			row := UIClusterRow{
				ID:       c.ID,
				Title:    c.Title,
				Members:  len(c.Members),
				AvgSim:   c.AvgSim,
				CrashIDs: c.Members,
			}
			if len(c.Members) > data.LargestCluster {
				data.LargestCluster = len(c.Members)
			}
			data.Clusters = append(data.Clusters, row)
		}
	} else {
		data.Disabled = true
	}

	executeTemplate(w, aiEmbeddingsTemplate, &data)
}

// PROBE: Phase 10 — AI Spec Generation dashboard handler.
func (serv *HTTPServer) httpAISpecGen(w http.ResponseWriter, r *http.Request) {
	data := UIAISpecGenData{
		UIPageHeader: serv.pageHeader(r, "AI Spec Gen"),
	}

	cfg := serv.Cfg.AISpecGen
	if cfg.APIKey == "" {
		data.Disabled = true
		executeTemplate(w, aiSpecGenTemplate, &data)
		return
	}

	// Config info.
	data.Provider = cfg.Provider
	data.Model = cfg.Model
	data.APIURL = cfg.APIURL
	data.Status = "Ready"

	// PROBE: Read specgen cost data from workdir/specgen_cost.json.
	costFile := filepath.Join(serv.Cfg.Workdir, "specgen_cost.json")
	if costData, err := os.ReadFile(costFile); err == nil {
		var cost struct {
			TotalCalls        int     `json:"total_calls"`
			TotalInputTokens  int     `json:"total_input_tokens"`
			TotalOutputTokens int     `json:"total_output_tokens"`
			TotalCostUSD      float64 `json:"total_cost_usd"`
			Calls             []struct {
				Time   string  `json:"time"`
				Type   string  `json:"type"`
				Model  string  `json:"model"`
				CostUSD float64 `json:"cost_usd"`
			} `json:"calls"`
		}
		if json.Unmarshal(costData, &cost) == nil {
			data.TotalCalls = cost.TotalCalls
			totalTokens := cost.TotalInputTokens + cost.TotalOutputTokens
			data.TotalTokens = fmt.Sprintf("%dk", totalTokens/1000)
			data.TotalCostUSD = cost.TotalCostUSD
			data.TotalCostKRW = int(cost.TotalCostUSD * 1450)

			// Today's stats.
			today := time.Now().Format("2006-01-02")
			for _, c := range cost.Calls {
				if len(c.Time) >= 10 && c.Time[:10] == today {
					data.TodayCalls++
					data.TodayCostUSD += c.CostUSD
				}
			}
			data.TodayTokens = fmt.Sprintf("%dk", 0) // Approximate from calls
			data.TodayCostKRW = int(data.TodayCostUSD * 1450)
		}
	}

	// PROBE: Read generated spec files from workdir/specgen/.
	specDir := filepath.Join(serv.Cfg.Workdir, "specgen")
	if entries, err := os.ReadDir(specDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			statusFile := filepath.Join(specDir, e.Name(), "status.json")
			spec := UISpecEntry{Driver: e.Name()}
			if sData, err := os.ReadFile(statusFile); err == nil {
				var st struct {
					Status   string `json:"status"`
					Path     string `json:"path"`
					Coverage int    `json:"coverage"`
					Syscalls int    `json:"syscalls"`
					Created  string `json:"created"`
				}
				if json.Unmarshal(sData, &st) == nil {
					spec.Status = st.Status
					spec.Path = st.Path
					spec.Coverage = st.Coverage
					spec.Syscalls = st.Syscalls
					spec.CreatedAt = st.Created
				}
			} else {
				spec.Status = "pending"
			}
			switch spec.Status {
			case "validated":
				spec.StatusColor = "#27ae60"
				data.ValidatedSpecs++
			case "failed":
				spec.StatusColor = "#c0392b"
				data.FailedSpecs++
			default:
				spec.StatusColor = "#f39c12"
				data.PendingSpecs++
			}
			data.TotalSpecs++
			data.Specs = append(data.Specs, spec)
		}
	}

	executeTemplate(w, aiSpecGenTemplate, &data)
}

func (serv *HTTPServer) buildCostAnalytics(data *UIAIAnalyticsData, daily []dailyStat, history []historyEntry) {
	// Daily cost bar chart data: [["Date", "Crash", "Strategy"], ...]
	var dailyCostRows []string
	var cumulativeRows []string
	cumulative := 0.0
	totalCrashCost := 0.0
	totalStrategyCost := 0.0

	for _, d := range daily {
		// Estimate crash vs strategy cost split.
		crashCost := 0.0
		strategyCost := 0.0
		if d.Calls > 0 {
			crashRatio := float64(d.CrashCalls) / float64(d.Calls)
			crashCost = d.CostUSD * crashRatio
			strategyCost = d.CostUSD * (1.0 - crashRatio)
		}
		totalCrashCost += crashCost
		totalStrategyCost += strategyCost
		cumulative += d.CostUSD

		dailyCostRows = append(dailyCostRows,
			fmt.Sprintf("['%s', %.4f, %.4f]", d.Date[5:], crashCost, strategyCost))
		cumulativeRows = append(cumulativeRows,
			fmt.Sprintf("['%s', %.4f]", d.Date[5:], cumulative))
	}

	data.DailyCostJSON = template.JS("[" + strings.Join(dailyCostRows, ",") + "]")
	data.CumulativeCostJSON = template.JS("[" + strings.Join(cumulativeRows, ",") + "]")

	// Cost breakdown pie: crash vs strategy.
	data.CostBreakdownJSON = template.JS(fmt.Sprintf(
		"[['Crash Analysis', %.4f], ['Strategy', %.4f]]", totalCrashCost, totalStrategyCost))

	// Token efficiency.
	crashInput, crashOutput, crashCount := 0, 0, 0
	stratInput, stratOutput, stratCount := 0, 0, 0
	for _, h := range history {
		if h.Type == "crash" {
			crashInput += h.InputTokens
			crashOutput += h.OutputTokens
			crashCount++
		} else if h.Type == "strategy" {
			stratInput += h.InputTokens
			stratOutput += h.OutputTokens
			stratCount++
		}
	}
	if crashCount > 0 {
		crashCost := 0.0
		for _, h := range history {
			if h.Type == "crash" {
				crashCost += h.CostUSD
			}
		}
		data.TokenEfficiency = append(data.TokenEfficiency, UITokenEfficiency{
			Label: "Crash Analysis", Input: crashInput / crashCount, Output: crashOutput / crashCount, Cost: crashCost / float64(crashCount),
		})
	}
	if stratCount > 0 {
		stratCost := 0.0
		for _, h := range history {
			if h.Type == "strategy" {
				stratCost += h.CostUSD
			}
		}
		data.TokenEfficiency = append(data.TokenEfficiency, UITokenEfficiency{
			Label: "Strategy", Input: stratInput / stratCount, Output: stratOutput / stratCount, Cost: stratCost / float64(stratCount),
		})
	}

	// Monthly projection based on recent 7-day average.
	if len(daily) > 0 {
		days := len(daily)
		if days > 7 {
			days = 7
		}
		recentCost := 0.0
		for i := len(daily) - days; i < len(daily); i++ {
			recentCost += daily[i].CostUSD
		}
		avgPerDay := recentCost / float64(days)
		data.ProjectedMonthUSD = avgPerDay * 30
		data.ProjectedMonthKRW = int(data.ProjectedMonthUSD * 1450)
	}
}

// dailyStat is a package-level type alias for the local struct in httpAIAnalytics.
// We define it at method level instead by accepting it as a parameter type.
type dailyStat = struct {
	Date          string  `json:"date"`
	Calls         int     `json:"calls"`
	CrashCalls    int     `json:"crash_calls"`
	StrategyCalls int     `json:"strategy_calls"`
	InputTokens   int     `json:"input_tokens"`
	OutputTokens  int     `json:"output_tokens"`
	CostUSD       float64 `json:"cost_usd"`
	Successes     int     `json:"successes"`
	Failures      int     `json:"failures"`
}

type historyEntry = struct {
	Time          time.Time `json:"time"`
	Type          string    `json:"type"`
	InputTokens   int       `json:"input_tokens"`
	OutputTokens  int       `json:"output_tokens"`
	CostUSD       float64   `json:"cost_usd"`
	Success       bool      `json:"success"`
	ResultSummary string    `json:"result_summary"`
	Error         string    `json:"error"`
}

func (serv *HTTPServer) buildCrashStats(data *UIAIAnalyticsData) {
	if serv.CrashStore == nil {
		return
	}
	list, err := serv.CrashStore.BugList()
	if err != nil {
		return
	}

	// Score distribution buckets: 0-9, 10-19, ..., 90-100.
	buckets := make([]int, 10)
	classCount := make(map[string]int)
	vulnCount := make(map[string]int)
	totalScore := 0
	maxScore := 0
	analyzed := 0
	highRisk := 0

	for _, info := range list {
		if isInternalCrashTitle(info.Title) {
			continue
		}
		tr := loadAITriageResult(serv.Cfg.Workdir, info.ID)
		if tr == nil {
			continue
		}
		analyzed++
		score := tr.Score
		totalScore += score
		if score > maxScore {
			maxScore = score
		}
		if score >= 70 {
			highRisk++
		}
		bucket := score / 10
		if bucket > 9 {
			bucket = 9
		}
		buckets[bucket]++
		if tr.ExploitClass != "" {
			classCount[tr.ExploitClass]++
		}
		if tr.VulnType != "" {
			vulnCount[tr.VulnType]++
		}
	}

	data.AnalyzedCount = analyzed
	data.HighRiskCount = highRisk
	if analyzed > 0 {
		data.AvgScore = float64(totalScore) / float64(analyzed)
	}
	data.MaxScore = maxScore

	// Score distribution chart.
	var scoreDist []string
	labels := []string{"0-9", "10-19", "20-29", "30-39", "40-49", "50-59", "60-69", "70-79", "80-89", "90-100"}
	for i, label := range labels {
		scoreDist = append(scoreDist, fmt.Sprintf("['%s', %d]", label, buckets[i]))
	}
	data.ScoreDistJSON = template.JS("[" + strings.Join(scoreDist, ",") + "]")

	// Exploit class pie chart.
	var classPie []string
	for cls, cnt := range classCount {
		classPie = append(classPie, fmt.Sprintf("['%s', %d]", cls, cnt))
	}
	sort.Strings(classPie)
	data.ExploitClassJSON = template.JS("[" + strings.Join(classPie, ",") + "]")

	// Vuln type table.
	for vt, cnt := range vulnCount {
		pct := 0.0
		if analyzed > 0 {
			pct = float64(cnt) * 100.0 / float64(analyzed)
		}
		data.VulnTypes = append(data.VulnTypes, UIVulnTypeStat{Type: vt, Count: cnt, Pct: pct})
	}
	sort.Slice(data.VulnTypes, func(i, j int) bool {
		return data.VulnTypes[i].Count > data.VulnTypes[j].Count
	})
}

func (serv *HTTPServer) buildStrategyStats(data *UIAIAnalyticsData) {
	// Load all strategy history from workdir.
	stratPath := filepath.Join(serv.Cfg.Workdir, "ai-strategy.json")
	stratData, err := os.ReadFile(stratPath)
	if err != nil {
		return
	}
	var strat struct {
		Summary        string    `json:"summary"`
		Timestamp      time.Time `json:"timestamp"`
		SeedsInjected  int       `json:"seeds_injected"`
		SeedsAccepted  int       `json:"seeds_accepted"`
		WeightsApplied int       `json:"weights_applied"`
		SyscallWeights []struct {
			Name string `json:"name"`
		} `json:"syscall_weights"`
		FocusTargets []struct {
			CrashTitle string `json:"crash_title"`
		} `json:"focus_targets"`
	}
	if json.Unmarshal(stratData, &strat) != nil {
		return
	}
	data.TotalSeedsInjected = strat.SeedsInjected
	data.TotalSeedsAccepted = strat.SeedsAccepted
	data.TotalWeightsApplied = strat.WeightsApplied
	data.TotalWeightsTotal = len(strat.SyscallWeights)
	data.FocusTriggered = len(strat.FocusTargets)

	summary := strat.Summary
	if len(summary) > 120 {
		summary = summary[:120] + "..."
	}
	data.StrategyRuns = append(data.StrategyRuns, UIStrategyRun{
		Time:           strat.Timestamp,
		SeedsInjected:  strat.SeedsInjected,
		SeedsAccepted:  strat.SeedsAccepted,
		WeightsApplied: strat.WeightsApplied,
		Summary:        summary,
	})
}

func (serv *HTTPServer) buildAPIPerformance(data *UIAIAnalyticsData, daily []dailyStat, history []historyEntry) {
	totalSuccess := 0
	totalFail := 0
	crashIn, crashOut, crashN := 0, 0, 0
	stratIn, stratOut, stratN := 0, 0, 0

	for _, h := range history {
		if h.Success {
			totalSuccess++
		} else {
			totalFail++
		}
		if h.Type == "crash" && h.Success {
			crashIn += h.InputTokens
			crashOut += h.OutputTokens
			crashN++
		} else if h.Type == "strategy" && h.Success {
			stratIn += h.InputTokens
			stratOut += h.OutputTokens
			stratN++
		}
		if !h.Success && h.Error != "" {
			data.ErrorLog = append(data.ErrorLog, UIAPIError{
				Time: h.Time, Type: h.Type, Error: h.Error,
			})
		}
	}

	total := totalSuccess + totalFail
	if total > 0 {
		data.SuccessRate = float64(totalSuccess) * 100.0 / float64(total)
	}
	if crashN > 0 {
		data.AvgCrashTokens = UIAvgTokens{AvgInput: crashIn / crashN, AvgOutput: crashOut / crashN, Count: crashN}
	}
	if stratN > 0 {
		data.AvgStrategyTokens = UIAvgTokens{AvgInput: stratIn / stratN, AvgOutput: stratOut / stratN, Count: stratN}
	}

	// Calls per day chart.
	var callRows []string
	for _, d := range daily {
		callRows = append(callRows, fmt.Sprintf("['%s', %d, %d]", d.Date[5:], d.CrashCalls, d.StrategyCalls))
	}
	data.CallsPerDayJSON = template.JS("[" + strings.Join(callRows, ",") + "]")

	// Reverse error log (newest first), cap at 20.
	for i, j := 0, len(data.ErrorLog)-1; i < j; i, j = i+1, j-1 {
		data.ErrorLog[i], data.ErrorLog[j] = data.ErrorLog[j], data.ErrorLog[i]
	}
	if len(data.ErrorLog) > 20 {
		data.ErrorLog = data.ErrorLog[:20]
	}
}

// PROBE: Phase 10 — AI Spec Generation dashboard data.
type UIAISpecGenData struct {
	UIPageHeader
	Disabled bool

	// Config.
	Provider string
	Model    string
	APIURL   string
	Status   string

	// Summary.
	TotalSpecs     int
	ValidatedSpecs int
	FailedSpecs    int
	PendingSpecs   int
	CoverageGain   int

	// Specs table.
	Specs []UISpecEntry

	// LLM Cost.
	TodayCalls   int
	TodayTokens  string
	TodayCostUSD float64
	TodayCostKRW int
	TotalCalls   int
	TotalTokens  string
	TotalCostUSD float64
	TotalCostKRW int
}

type UISpecEntry struct {
	Driver      string
	Path        string
	Status      string // "validated", "failed", "pending"
	StatusColor string
	Coverage    int
	Syscalls    int
	CreatedAt   string
}

// PROBE: Phase 7e — Embeddings dashboard data.
type UIAIEmbeddingsData struct {
	UIPageHeader
	Disabled bool

	// Status.
	Model    string
	Provider string

	TotalEmbeddings   int
	PendingCount      int
	TotalClusters     int
	LargestCluster    int
	LastEmbeddingTime string

	// GPT Embedding cost — today/total split (matching Claude Usage in triage).
	TodayCalls   int
	TodayTokens  string
	TodayCostUSD float64
	TodayCostKRW int
	TotalCalls   int
	TotalTokens  string
	TotalCostUSD float64
	TotalCostKRW int

	// Dedup summary.
	DedupRatio float64 // percentage of crashes deduped

	Clusters      []UIClusterRow
	CrashClusters []UICrashClusterRow

	// API Call History.
	History []UIAPICall
}

type UIClusterRow struct {
	ID       int
	Title    string
	Members  int
	AvgSim   float64
	CrashIDs []string
}

type UICrashClusterRow struct {
	CrashID   string
	Title     string
	ClusterID int
	Tokens    int
}

var (
	mainTemplate          = createPage("main", UISummaryData{})
	syscallsTemplate      = createPage("syscalls", UISyscallsData{})
	vmsTemplate           = createPage("vms", UIVMData{})
	crashTemplate         = createPage("crash", UICrashPage{})
	corpusTemplate        = createPage("corpus", UICorpusPage{})
	prioTemplate          = createPage("prio", UIPrioData{})
	fallbackCoverTemplate = createPage("fallback_cover", UIFallbackCoverData{})
	rawCoverTemplate      = createPage("raw_cover", UIRawCoverPage{})
	jobListTemplate       = createPage("job_list", UIJobList{})
	textTemplate          = createPage("text", UITextPage{})
	aiTemplate            = createPage("ai", UIAIPageData{})                // PROBE: AI dashboard
	aiTriageTemplate      = createPage("aitriage", UIAITriageData{})       // PROBE: AI triage
	aiCrashTemplate       = createPage("aicrash", UIAICrashPage{})         // PROBE: AI crash detail
	aiAnalyticsTemplate   = createPage("aianalytics", UIAIAnalyticsData{}) // PROBE: AI analytics
	aiEmbeddingsTemplate  = createPage("aiembeddings", UIAIEmbeddingsData{}) // PROBE: AI embeddings
	aiSpecGenTemplate     = createPage("aispecgen", UIAISpecGenData{})     // PROBE: AI spec generation
)

//go:embed html/*.html
var htmlFiles embed.FS

func mustReadHTML(name string) []byte {
	data, err := htmlFiles.ReadFile("html/" + name + ".html")
	if err != nil {
		panic(err)
	}
	return data
}

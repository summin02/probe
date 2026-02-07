// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/prog"
)

type CrashStore struct {
	Tag          string
	BaseDir      string
	MaxCrashLogs int
	MaxReproLogs int
}

const reproFileName = "repro.prog"
const cReproFileName = "repro.cprog"
const straceFileName = "strace.log"

const MaxReproAttempts = 3

func NewCrashStore(cfg *mgrconfig.Config) *CrashStore {
	return &CrashStore{
		Tag:          cfg.Tag,
		BaseDir:      cfg.Workdir,
		MaxCrashLogs: cfg.MaxCrashLogs,
		MaxReproLogs: MaxReproAttempts,
	}
}

func ReadCrashStore(workdir string) *CrashStore {
	return &CrashStore{
		BaseDir: workdir,
	}
}

// Returns whether it was the first crash of a kind.
func (cs *CrashStore) SaveCrash(crash *Crash) (bool, error) {
	dir := cs.path(crash.Title)
	osutil.MkdirAll(dir)

	err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(crash.Title+"\n"))
	if err != nil {
		return false, fmt.Errorf("failed to write crash: %w", err)
	}

	// Save up to cs.cfg.MaxCrashLogs reports, overwrite the oldest once we've reached that number.
	// Newer reports are generally more useful. Overwriting is also needed
	// to be able to understand if a particular bug still happens or already fixed.
	oldestI, first := 0, false
	var oldestTime time.Time
	for i := 0; i < cs.MaxCrashLogs; i++ {
		info, err := os.Stat(filepath.Join(dir, fmt.Sprintf("log%v", i)))
		if err != nil {
			oldestI = i
			if i == 0 {
				first = true
			}
			break
		}
		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldestI = i
			oldestTime = info.ModTime()
		}
	}
	writeOrRemove := func(name string, data []byte) {
		filename := filepath.Join(dir, name+fmt.Sprint(oldestI))
		if len(data) == 0 {
			os.Remove(filename)
			return
		}
		osutil.WriteFile(filename, data)
	}
	reps := append([]*report.Report{crash.Report}, crash.TailReports...)
	writeOrRemove("log", crash.Output)
	writeOrRemove("tag", []byte(cs.Tag))
	writeOrRemove("report", report.MergeReportBytes(reps))
	writeOrRemove("machineInfo", crash.MachineInfo)
	if err := report.AddTitleStat(filepath.Join(dir, "title-stat"), reps); err != nil {
		return false, fmt.Errorf("report.AddTitleStat: %w", err)
	}

	return first, nil
}

// PROBE: Variant metadata for tracking different trigger paths to the same crash point.
type VariantInfo struct {
	Title     string     `json:"title"`
	Type      crash.Type `json:"type"`
	Tier      int        `json:"tier"`
	Count     int        `json:"count"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

// PROBE: Maximum number of unique variant programs to keep per crash.
const MaxVariants = 32

// PROBE: SaveVariant saves a trigger program as a variant for the given crash.
// It preserves different trigger paths (syscall sequences) that lead to the same crash point.
// Returns true if this was a new variant.
func (cs *CrashStore) SaveVariant(title string, crashType crash.Type, progData []byte) (bool, error) {
	if len(progData) == 0 {
		return false, nil
	}
	dir := filepath.Join(cs.path(title), "variants")
	osutil.MkdirAll(dir)

	sig := hash.Hash(progData)
	progHash := sig.String()
	progFile := filepath.Join(dir, progHash+".prog")

	// Read existing variant-stat.
	statFile := filepath.Join(dir, "variant-stat.json")
	variants := make(map[string]*VariantInfo)
	if data, err := os.ReadFile(statFile); err == nil {
		json.Unmarshal(data, &variants)
	}

	now := time.Now()
	existing, isKnown := variants[progHash]
	if isKnown {
		// Known variant — update count and last_seen.
		existing.Count++
		existing.LastSeen = now
	} else {
		// New variant — check if we've hit the limit.
		if len(variants) >= MaxVariants {
			return false, nil
		}
		variants[progHash] = &VariantInfo{
			Title:     title,
			Type:      crashType,
			Tier:      crashType.Tier(),
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
		// Save the program file.
		if err := osutil.WriteFile(progFile, progData); err != nil {
			return false, fmt.Errorf("failed to write variant program: %w", err)
		}
	}

	// Write updated variant-stat.
	if err := osutil.WriteJSON(statFile, variants); err != nil {
		return false, fmt.Errorf("failed to write variant stat: %w", err)
	}
	return !isKnown, nil
}

// PROBE: VariantPrograms returns all saved variant programs for a crash.
func (cs *CrashStore) VariantPrograms(title string) ([][]byte, error) {
	dir := filepath.Join(cs.path(title), "variants")
	files, err := osutil.ListDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var progs [][]byte
	for _, f := range files {
		if strings.HasSuffix(f, ".prog") {
			data, err := os.ReadFile(filepath.Join(dir, f))
			if err == nil {
				progs = append(progs, data)
			}
		}
	}
	return progs, nil
}

// PROBE: VariantStats returns the variant metadata for a crash.
func (cs *CrashStore) VariantStats(title string) (map[string]*VariantInfo, error) {
	statFile := filepath.Join(cs.path(title), "variants", "variant-stat.json")
	variants := make(map[string]*VariantInfo)
	data, err := os.ReadFile(statFile)
	if err != nil {
		if os.IsNotExist(err) {
			return variants, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &variants); err != nil {
		return nil, err
	}
	return variants, nil
}

// PROBE: SaveTier3Stat records a Tier 3 crash as statistics only (no logs/reports/repro).
func (cs *CrashStore) SaveTier3Stat(title string, crashType crash.Type) error {
	statFile := filepath.Join(cs.BaseDir, "crashes", "tier3-stat.json")

	stats := make(map[string]*Tier3Entry)
	if data, err := os.ReadFile(statFile); err == nil {
		json.Unmarshal(data, &stats)
	}

	now := time.Now()
	if entry, ok := stats[title]; ok {
		entry.Count++
		entry.LastSeen = now
	} else {
		stats[title] = &Tier3Entry{
			Type:      crashType,
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}
	}
	return osutil.WriteJSON(statFile, stats)
}

// PROBE: Tier3Entry holds statistics for a low-severity crash.
type Tier3Entry struct {
	Type      crash.Type `json:"type"`
	Count     int        `json:"count"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

// PROBE: LoadTier3Stats reads all Tier 3 crash statistics.
func (cs *CrashStore) LoadTier3Stats() (map[string]*Tier3Entry, error) {
	statFile := filepath.Join(cs.BaseDir, "crashes", "tier3-stat.json")
	stats := make(map[string]*Tier3Entry)
	data, err := os.ReadFile(statFile)
	if err != nil {
		if os.IsNotExist(err) {
			return stats, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, err
	}
	return stats, nil
}

func (cs *CrashStore) HasRepro(title string) bool {
	return osutil.IsExist(filepath.Join(cs.path(title), reproFileName))
}

func (cs *CrashStore) MoreReproAttempts(title string) bool {
	dir := cs.path(title)
	for i := 0; i < cs.MaxReproLogs; i++ {
		if !osutil.IsExist(filepath.Join(dir, fmt.Sprintf("repro%v", i))) {
			return true
		}
	}
	return false
}

func (cs *CrashStore) SaveFailedRepro(title string, log []byte) error {
	dir := cs.path(title)
	osutil.MkdirAll(dir)
	for i := 0; i < cs.MaxReproLogs; i++ {
		name := filepath.Join(dir, fmt.Sprintf("repro%v", i))
		if !osutil.IsExist(name) && len(log) > 0 {
			err := osutil.WriteFile(name, log)
			if err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func (cs *CrashStore) SaveRepro(res *ReproResult, progText, cProgText []byte) error {
	repro := res.Repro
	rep := repro.Report
	dir := cs.path(rep.Title)
	osutil.MkdirAll(dir)

	err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title+"\n"))
	if err != nil {
		return fmt.Errorf("failed to write crash: %w", err)
	}
	// TODO: detect and handle errors below as well.
	osutil.WriteFile(filepath.Join(dir, reproFileName), progText)
	if cs.Tag != "" {
		osutil.WriteFile(filepath.Join(dir, "repro.tag"), []byte(cs.Tag))
	}
	if len(rep.Output) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.log"), rep.Output)
	}
	if len(rep.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.report"), rep.Report)
	}
	if len(cProgText) > 0 {
		osutil.WriteFile(filepath.Join(dir, cReproFileName), cProgText)
	}
	var assetErr error
	repro.Prog.ForEachAsset(func(name string, typ prog.AssetType, r io.Reader, c *prog.Call) {
		fileName := filepath.Join(dir, name+".gz")
		if err := osutil.WriteGzipStream(fileName, r); err != nil {
			assetErr = fmt.Errorf("failed to write crash asset: type %d, %w", typ, err)
		}
	})
	if assetErr != nil {
		return assetErr
	}
	if res.Strace != nil {
		// Unlike dashboard reporting, we save strace output separately from the original log.
		if res.Strace.Error != nil {
			osutil.WriteFile(filepath.Join(dir, "strace.error"),
				[]byte(fmt.Sprintf("%v", res.Strace.Error)))
		}
		if len(res.Strace.Output) > 0 {
			osutil.WriteFile(filepath.Join(dir, straceFileName), res.Strace.Output)
		}
	}
	if reproLog := res.Stats.FullLog(); len(reproLog) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.stats"), reproLog)
	}
	return nil
}

type BugReport struct {
	Title  string
	Tag    string
	Prog   []byte
	CProg  []byte
	Report []byte
}

func (cs *CrashStore) Report(id string) (*BugReport, error) {
	dir := filepath.Join(cs.BaseDir, "crashes", id)
	desc, err := os.ReadFile(filepath.Join(dir, "description"))
	if err != nil {
		return nil, err
	}
	tag, _ := os.ReadFile(filepath.Join(dir, "repro.tag"))
	ret := &BugReport{
		Title: strings.TrimSpace(string(desc)),
		Tag:   strings.TrimSpace(string(tag)),
	}
	ret.Prog, _ = os.ReadFile(filepath.Join(dir, reproFileName))
	ret.CProg, _ = os.ReadFile(filepath.Join(dir, cReproFileName))
	ret.Report, _ = os.ReadFile(filepath.Join(dir, "repro.report"))
	return ret, nil
}

type CrashInfo struct {
	Index int
	Log   string // filename relative to the workdir

	// These fields are only set if full=true.
	Tag    string
	Report string // filename relative to workdir
	Time   time.Time
}

type BugInfo struct {
	ID            string
	Title         string
	TailTitles    []*report.TitleFreqRank
	FirstTime     time.Time
	LastTime      time.Time
	HasRepro      bool
	HasCRepro     bool
	StraceFile    string // relative to the workdir
	ReproAttempts int
	Crashes       []*CrashInfo
	Rank          int
	Tier          int                    // PROBE: severity tier (1=Critical, 2=Important, 3=Low)
	NumVariants   int                    // PROBE: number of unique trigger program variants
	Variants      map[string]*VariantInfo // PROBE: variant metadata (only set if full=true)
}

func (cs *CrashStore) BugInfo(id string, full bool) (*BugInfo, error) {
	dir := filepath.Join(cs.BaseDir, "crashes", id)

	ret := &BugInfo{ID: id}
	desc, err := os.ReadFile(filepath.Join(dir, "description"))
	if err != nil {
		return nil, err
	}
	ret.FirstTime, ret.LastTime, err = osutil.FileTimes(filepath.Join(dir, "description"))
	if err != nil {
		return nil, err
	}
	ret.Title = strings.TrimSpace(string(desc))

	// Bug rank may go up over time if we observe higher ranked bugs as a consequence of the first failure.
	ret.Rank = report.TitlesToImpact(ret.Title)
	ret.Tier = report.TitleToTier(ret.Title)
	if titleStat, err := report.ReadStatFile(filepath.Join(dir, "title-stat")); err == nil {
		ret.TailTitles = report.ExplainTitleStat(titleStat)
		for _, ti := range ret.TailTitles {
			ret.Rank = max(ret.Rank, ti.Rank)
			// PROBE: Tier can improve if a higher-ranked variant is found.
			if varTier := report.TitleToTier(ti.Title); varTier < ret.Tier {
				ret.Tier = varTier
			}
		}
	}

	// PROBE: Load variant information.
	if variants, err := cs.VariantStats(ret.Title); err == nil {
		ret.NumVariants = len(variants)
	}

	files, err := osutil.ListDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if strings.HasPrefix(f, "log") {
			index, err := strconv.ParseUint(f[3:], 10, 64)
			if err == nil {
				ret.Crashes = append(ret.Crashes, &CrashInfo{
					Index: int(index),
					Log:   filepath.Join("crashes", id, f),
				})
			}
		} else if f == reproFileName {
			ret.HasRepro = true
		} else if f == cReproFileName {
			ret.HasCRepro = true
		} else if f == straceFileName {
			ret.StraceFile = filepath.Join(dir, f)
		} else if strings.HasPrefix(f, "repro") {
			ret.ReproAttempts++
		}
	}
	if !full {
		return ret, nil
	}
	for _, crash := range ret.Crashes {
		if stat, err := os.Stat(filepath.Join(cs.BaseDir, crash.Log)); err == nil {
			crash.Time = stat.ModTime()
		}
		tag, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("tag%d", crash.Index)))
		crash.Tag = string(tag)
		reportFile := filepath.Join("crashes", id, fmt.Sprintf("report%d", crash.Index))
		if osutil.IsExist(filepath.Join(cs.BaseDir, reportFile)) {
			crash.Report = reportFile
		}
	}
	sort.Slice(ret.Crashes, func(i, j int) bool {
		return ret.Crashes[i].Time.After(ret.Crashes[j].Time)
	})
	// PROBE: Load full variant metadata when full=true.
	if variants, err := cs.VariantStats(ret.Title); err == nil {
		ret.Variants = variants
		ret.NumVariants = len(variants)
	}
	return ret, nil
}

func (cs *CrashStore) BugList() ([]*BugInfo, error) {
	dirs, err := osutil.ListDir(filepath.Join(cs.BaseDir, "crashes"))
	if err != nil {
		if os.IsNotExist(err) {
			// If there were no crashes, it's okay that there's no such folder.
			return nil, nil
		}
		return nil, err
	}
	var ret []*BugInfo
	var lastErr error
	errCount := 0
	for _, dir := range dirs {
		info, err := cs.BugInfo(dir, false)
		if err != nil {
			errCount++
			lastErr = err
			continue
		}
		ret = append(ret, info)
	}
	sort.Slice(ret, func(i, j int) bool {
		return strings.ToLower(ret[i].Title) < strings.ToLower(ret[j].Title)
	})
	if lastErr != nil {
		log.Logf(0, "some stored crashes are inconsistent: %d skipped, last error %v", errCount, lastErr)
	}
	return ret, nil
}

func crashHash(title string) string {
	sig := hash.Hash([]byte(title))
	return sig.String()
}

func (cs *CrashStore) path(title string) string {
	return filepath.Join(cs.BaseDir, "crashes", crashHash(title))
}

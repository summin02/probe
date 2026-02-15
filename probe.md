# PROBE — Custom Syzkaller for Exploit-Oriented Kernel Fuzzing

## Scope

- **Modification target**: `syzkaller/` directory ONLY
- **Linux kernel source**: NEVER modified (kernel .config changes are allowed)
- **Goal**: Transform syzkaller from a general-purpose fuzzer into an exploit-oriented fuzzer that focuses on discovering and validating actually exploitable vulnerabilities

## Target Vulnerability Types

- **UAF (Use-After-Free)**: alloc → use → free → reuse patterns
- **OOB (Out-of-Bounds)**: buffer size/offset boundary violations

## Architecture Overview

```
+------------------------------------------------------+
|                PROBE Custom Syzkaller                 |
+------------------------------------------------------+
|                                                       |
|  [Phase 1] Crash Filtering & Dedup Pipeline           |
|    - Impact score based filtering                     |
|    - Grouping (not deletion) of similar crashes       |
|    - Preserve variant diversity within groups         |
|    - Suppress noise (WARNING, LOCKDEP, INFO_LEAK)     |
|                                                       |
|  [Phase 2] Focus Mode                                 |
|    - High-severity crash triggers focused mutation    |
|    - Hundreds~thousands of iterations (not just 25)   |
|    - Crash-type-specific mutation strategies           |
|    - Variant combination across groups                |
|    - Auto-return on diminishing returns               |
|                                                       |
|  [Phase 3] AI-Guided Fuzzing [DONE]                   |
|    - Multi-provider LLM (Anthropic + OpenAI)          |
|    - Crash exploitability scoring (0-100)             |
|    - Fuzzing strategy: syscall weights, seeds, focus  |
|    - /ai dashboard with cost tracking (USD+KRW)       |
|                                                       |
|  [Phase 4] UAF/OOB Mutation Engine                    |
|    - UAF pattern sequence generation                  |
|    - OOB boundary value focused mutation              |
|    - Custom syscall descriptions (uffd, io_uring etc) |
|                                                       |
|  [Phase 5] eBPF Runtime Monitor                       |
|    - Slab object lifecycle tracking (kprobe-based)    |
|    - Exploitability scoring                           |
|    - Real-time feedback to Focus Mode                 |
|    - No kernel source modification (attach to         |
|      existing kprobes/tracepoints)                    |
|                                                       |
+------------------------------------------------------+
```

## Phase 1: Crash Filtering & Dedup Pipeline [DONE]

**Goal**: Eliminate noise and deduplicate crashes while preserving variant diversity.

**Current problem**: syzkaller treats all crashes equally — WARNING, LOCKDEP, hangs, and KASAN UAF writes all get the same treatment. Duplicate crashes flood the results.

### 1a. Crash Severity Tiers

**Modification targets**:
- `pkg/report/crash/` — crash type classification
- `pkg/manager/` — crash storage and reporting logic

**Implementation**:
- Use existing `impactOrder` ranking in `pkg/report/impact_score.go`
- Add filtering layer in manager: only prioritize crashes with high impact scores
- Crash severity tiers:
  - **Tier 1 (Critical)**: KASANInvalidFree, KASANUseAfterFreeWrite, KASANWrite, KASANUseAfterFreeRead, KASANRead
  - **Tier 2 (Important)**: OOB variants, KFENCEInvalidFree, NullPtrDerefBUG, Warning, Bug, UBSAN, LockdepBug, AtomicSleep, UnexpectedReboot; also the default for any unclassified crash type
  - **Tier 3 (Stats-only)**: LostConnection, SyzFailure, Hang, DoS, MemoryLeak (explicit list only)
- Tier 3 handling: **statistics only** (no logs, no reports, no repro)
  - Record title + count in `tier3-stat.json` (e.g., "WARNING in xxx: 47 times")
  - No disk-heavy storage — only counters
  - Viewable in web dashboard (collapsed section)
  - Never triggers Focus Mode or repro attempts

### 1b. Crash Deduplication Pipeline

**Key principle**: Group, don't delete. Same crash point can have different trigger paths with different exploitability.

```
Crashes (thousands/day)
    |
    +-- Stage 1: Exact duplicate removal
    |       Match: title + stack trace + trigger program hash
    |       Only removes 100% identical crashes
    |
    +-- Stage 2: Grouping (NOT deletion)
    |       Group by: same stack trace / crash point
    |       But PRESERVE different trigger programs (syscall sequences)
    |       → Each group contains multiple variants
    |
    |       Example: "UAF at kfree+0x42" group (5 variants)
    |         ├─ Variant A: close() → read()      (read UAF)
    |         ├─ Variant B: close() → write()     (write UAF) ← more dangerous
    |         ├─ Variant C: close() → ioctl()     (ioctl UAF)
    |         ├─ Variant D: munmap() → read()     (different free path)
    |         └─ Variant E: munmap() → mmap()     (reallocation attempt)
    |
    +-- Stage 3: Impact score filter
    |       Tier 3: statistics only (title + count), no storage
    |       Tier 1/2: proceed to grouping + full storage
    |
    +-- Stage 4: AI analysis (group-level, not per-crash)
            Send: group representative + all variant trigger programs
            → LLM identifies which variant is most exploitable
            → Variant diversity = more options for Focus Mode
```

**Why grouping matters**: Same crash point ≠ same exploitability. A write-UAF and read-UAF at the same location have vastly different exploit potential. Deleting "duplicates" loses attack vectors that Focus Mode needs.

**VariantPrograms cap**: Loading variant programs is capped at `MaxVariants` (100) to prevent excessive disk I/O when a crash group accumulates thousands of variants.

## Phase 2: Focus Mode [DONE]

**Goal**: When a high-severity crash is found, switch to intensive exploitation of that finding.

**Current behavior**: Crash found → triage → minimize → smash (25 mutations) → move on.

**New behavior**:
```
Normal Mode (exploration)
    |
    +-- Crash detected
          |
          +-- Low severity → Standard processing (25x smash)
          |
          +-- High severity (Tier 1) → FOCUS MODE
                |
                +-- 1. Intensive mutation of crash program
                |     +-- 300 iterations (vs 25 in smash)
                |     +-- Standard prog.Mutate() (Phase 4 adds UAF/OOB-specific)
                |
                +-- 2. Diminishing returns exit
                |     +-- 50 consecutive iterations with no new coverage → early exit
                |     +-- Tracks max signal growth for progress detection
                |
                +-- 3. Concurrency limits
                      +-- Max 1 concurrent focus job
                      +-- Pending queue: up to 8 candidates queued while focus active
                      +-- On completion, next pending candidate auto-launches
                      +-- Same crash title never re-focused
                      +-- Alternate(2): 1 focus request per 2 queue polls
```

**Implementation**:
- `pkg/fuzzer/job.go` — `focusJob` type (300 iters, diminishing returns exit)
- `pkg/fuzzer/fuzzer.go` — `focusQueue`, `AddFocusCandidate()`, focus state tracking
- `pkg/fuzzer/cover.go` — `MaxSignalLen()` for progress detection
- `pkg/fuzzer/stats.go` — `statJobsFocus`, `statExecFocus`
- `syz-manager/manager.go` — Tier 1 crash → Focus Mode trigger bridge

**Queue priority** (implemented):
```
1. triageCandidateQueue
2. candidateQueue
3. triageQueue
4. focusQueue (Alternate 2)  ← PROBE: high-severity crash intensive mutation
5. smashQueue (Alternate 3)
6. genFuzz
```

**Logging strategy**:
- Entry: `Logf(0)` — `PROBE: focus mode started for 'X' (tier N)`
- Exit:  `Logf(0)` — `PROBE: focus mode ended for 'X' — iters, new_coverage, exit_reason, duration`
- Mid-session: no logs (internal counters only, summarized at exit)

## Phase 3: AI-Guided Fuzzing — **DONE**

**Goal**: Integrate LLM into the full fuzzing pipeline — crash exploitability analysis, coverage strategy, seed generation, mutation tuning, and Focus target recommendations.

**Architecture**: 2-step batch cycle every 1 hour:
- **Step A**: Crash analysis (individual API calls per crash group, scoring 0-100)
- **Step B**: Fuzzing strategy (single API call with coverage+crash summary, produces syscall weights, seeds, mutation hints, focus targets)

**Model**: Configurable (recommended: Claude Sonnet 4.5, ~$1.25/day). Multi-provider support (Anthropic + OpenAI-compatible).

**Config** (`probe.cfg`):
```json
"ai_triage": {
    "model": "claude-sonnet-4-5-20250929",
    "api_key": "sk-ant-api03-xxx",
    "max_tier": 2
}
```
Provider auto-detected from model name (`claude-*` → Anthropic, otherwise → OpenAI).

### What was implemented

**New package `pkg/aitriage/`**:
- `aitriage.go` — Core types (TriageResult, StrategyResult, CostTracker), Triager with 1-hour batch loop
- `client.go` — LLMClient interface + Anthropic/OpenAI implementations (raw net/http, 3x retry, 60s timeout)
- `prompt_crash.go` — KASAN report parser, crash exploitability prompt (5 criteria, JSON output)
- `prompt_strategy.go` — FuzzingSnapshot collection, strategy prompt (syscall weights, seeds, mutations, focus)

**Strategy application**:
- `prog/prio.go`: `ChoiceTable.ApplyWeights()` — external syscall weight multipliers on cumulative sums
- `pkg/fuzzer/fuzzer.go`: `InjectSeed()` — parse syzkaller program text, inject as triage candidate
- `pkg/fuzzer/fuzzer.go`: `ApplyAIWeights()` — forward weights to ChoiceTable
- Focus targets → `AddFocusCandidate()` for high-score crashes

**Dashboard** (4-tab layout):
- `main.html`: AI Score column on crash table (color-coded: red 70+, yellow 40-69, green 0-39)
- `crash.html`: AI Exploitability Analysis section (score, class, vuln type)
- `ai.html`: `/ai` (Dashboard tab) — summary cards (analyzed, high-risk, pending, clusters, SyzGPT), 3-way cost table (Claude LLM / GPT Embedding / Combined), quick links, full console with real-time polling
- `aitriage.html`: `/ai/triage` (AI Triage tab) — action buttons (Analyze/Strategize), crash exploitability table, strategy details, API call history, filtered console (`[Step A/B/C]`)
- `aiembeddings.html`: `/ai/embeddings` (Embeddings tab) — Embed Now button, summary cards, cluster/embedding tables, filtered console (`[Embeddings]`)
- `aianalytics.html`: `/ai/analytics` (Analytics tab) — Google Charts (cost, score, exploit class, API calls, crash timeline), cost efficiency metrics, SyzGPT performance, embedding analytics
- `aicrash.html`: `/ai/crash?id=` — detailed single crash analysis (back link → `/ai/triage`)
- `common.html`: AI tab in navigation bar (uses `hasPrefix` for sub-path highlighting)

**Manager integration** (`syz-manager/ai_triage.go`):
- Triager initialization from config, background goroutine
- Callbacks: GetCrashes, GetSnapshot, OnTriageResult, OnStrategyResult
- Score >= 70 → auto-trigger Focus Mode
- Manual triggers: POST `/api/ai/analyze`, POST `/api/ai/strategize`

**Graceful degradation**: No `ai_triage` config → triager nil, AI disabled, `/ai` shows "disabled", fuzzing unchanged.

**Operational improvements**:
- **Step A re-analysis**: Crashes are re-analyzed when variant count triples since last analysis (e.g., 5→15 variants), capturing evolving exploit potential as new trigger paths are discovered
- **Cost recovery dedup**: Timestamp-based guard prevents double-counting when recovering cost history from triage result files at startup
- **Auto-refresh**: `/ai` page automatically reloads when LLM batch completes (tracks running→complete transition)

### Cost Estimate (24h, ~126K input + ~58K output tokens)

| Model | 24h USD | 24h KRW | Note |
|-------|---------|---------|------|
| Claude Sonnet 4.5 | $1.25 | ~1,810 | Recommended |
| Claude Haiku 4.5 | $0.42 | ~609 | Budget |
| GPT-4o | $0.90 | ~1,305 | OpenAI |
| GPT-4o-mini | $0.05 | ~73 | Minimum |

## Phase 4: Practical Hardening — **DONE**

**Goal**: Practical improvements to boost UAF/OOB crash discovery before Phase 5.

**Modified files**: `setup/probe.cfg`, `pkg/manager/crash.go`, `pkg/fuzzer/fuzzer.go`, `prog/mutation.go`, `prog/size.go`, `prog/hints.go`

### 4a. kasan_multi_shot + Severity Escalation — **DONE**
- Removed `oops=panic` and added `kasan_multi_shot` to kernel cmdline
- Added `escalateCrashType()`: scans all reports (primary + tail) for the most severe crash type when multiple KASAN reports exist in one execution
- Called from `SaveCrash()` before tier classification

### 4b. Fault Injection × Focus Mode — **DONE**
- When Focus Mode starts for a high-severity crash, also spawns `faultInjectionJob` for each call in the crash program
- Error paths (incomplete cleanup) are a major source of UAFs
- Reuses existing `statExecFaultInject` counter, jobs go through `focusQueue`

### 4c. Hints OOB Boundary Extension — **DONE**
- Extended `checkConstArg()` in `prog/hints.go` to generate boundary±1/±2 variants after standard replacers
- Standard hints generate values that PASS comparisons; OOB variants generate values that FAIL boundary checks (off-by-one/off-by-two)
- Applies `uselessHint` filter to avoid invalid boundary values

### 4d. LenType Priority Boost + OOB-Aware Mutation — **DONE**
- Boosted `LenType` mutation priority from `0.1 * maxPriority` (6.4) to `0.4 * maxPriority` (25.6)
- Added OOB-specific strategy to `mutateSize()` (20% chance): off-by-one above/below, double size, zero size, page-size overshoot
- Strategy uses actual buffer size (from `assignSizesCall`) as reference, `preserve=true` prevents recalculation

## Phase 5: eBPF Runtime Monitor — **DONE**

**Goal**: Real-time kernel heap state tracking for exploitability assessment.

**Constraint**: Runs inside Guest VM, attaches to existing kernel tracepoints. NO kernel source modification.

### Architecture

```
Host (syz-manager)              Guest VM
┌──────────────┐     SCP     ┌──────────────────────────┐
│ bin/          │ ──────────→ │ syz-ebpf-loader          │
│  syz-ebpf-   │             │   loads probe_ebpf.bpf.o  │
│  loader      │             │   pins maps to /sys/fs/bpf│
│  probe_ebpf  │             │   attaches tracepoints    │
│  .bpf.o      │             │   exits                   │
└──────────────┘             └──────────────────────────┘
                                      │
                                      ▼
                             ┌──────────────────────────┐
                             │ Kernel eBPF Programs      │
                             │  trace_kfree → freed_objs │
                             │  trace_kmalloc → reuse    │
                             │  metrics map (pinned)     │
                             └──────────────────────────┘
                                      │
                                      ▼
                             ┌──────────────────────────┐
                             │ syz-executor              │
                             │  ebpf_init() → open map   │
                             │  per-exec: read+reset     │
                             │  UAF score in FlatBuffers  │
                             └──────────────────────────┘
                                      │
                                      ▼
                             Host (fuzzer feedback)
                             ┌──────────────────────────┐
                             │ processResult()           │
                             │  eBPF metrics → stats     │
                             │  UAF score ≥ 70 →         │
                             │    Focus Mode trigger     │
                             └──────────────────────────┘
```

### 5a. BPF C Program — **DONE**
- `executor/ebpf/probe_ebpf.bpf.c` — hooks `tracepoint/kmem/kfree` and `tracepoint/kmem/kmalloc`
- LRU hash map (8192 entries) tracks recently freed pointers with timestamps
- Array map stores per-execution metrics: alloc_count, free_count, reuse_count, rapid_reuse_count, min_reuse_delay_ns, double_free_count, size_mismatch_count
- Detects slab reuse (free→alloc of same pointer) and rapid reuse (< 100us = UAF-favorable)
- **Double-free detection**: kfree checks if ptr already exists in freed_objects (freed twice without intervening alloc)
- **Size-mismatch detection**: kmalloc flags when `bytes_alloc > 2 * bytes_req && bytes_alloc >= 128` (cross-cache/slab waste)

### 5b. BPF Loader — **DONE**
- `tools/syz-ebpf-loader/main.go` — standalone Go binary using `cilium/ebpf`
- Loads BPF ELF object, attaches tracepoints, pins maps+links to `/sys/fs/bpf/probe/`
- Static binary for VM deployment; exits after setup (BPF persists in kernel)

### 5c. FlatBuffers Schema Extension — **DONE**
- Added 8 fields to `ProgInfoRaw` in `pkg/flatrpc/flatrpc.fbs`:
  - `ebpf_alloc_count`, `ebpf_free_count`, `ebpf_reuse_count`, `ebpf_rapid_reuse_count` (uint32)
  - `ebpf_min_reuse_ns` (uint64), `ebpf_uaf_score` (uint32)
  - `ebpf_double_free_count` (uint32, VT=26), `ebpf_size_mismatch_count` (uint32, VT=28)
- Backward compatible: default 0 for old executors
- Manual hand-edit of generated `flatrpc.h` (C++) and `flatrpc.go` (Go) since flatc version mismatch prevents regeneration

### 5d. Executor C++ Integration — **DONE**
- `executor_linux.h`: `ebpf_init()` opens pinned metrics map via raw `bpf()` syscall; `access()` check before `BPF_OBJ_GET` to silently skip when map not yet pinned
- `ebpf_read_and_reset()`: reads metrics + zeros for next execution (atomic)
- `executor.cc`: init on startup (with retry in `execute_one()` for late BPF deployment), clear before execution, child writes metrics to `OutputData` shared memory BEFORE `close_fds()`, runner reads from shared memory in `finish_output()`
- UAF score formula: rapid_reuse > 0 (+50), min_delay < 10us (+30), reuse > 5 (+20), double_free > 0 (=100 override), size_mismatch > 3 (+10), capped at 100

### 5e. Manager Deployment — **DONE**
- Manager copies `syz-ebpf-loader` + `probe_ebpf.bpf.o` to each VM at startup
- Runs loader via shell command chain before executor starts
- bpffs mount added to VM fstab (`tools/trixie/etc/fstab`)
- Graceful degradation: if eBPF fails, executor returns zero metrics, fuzzing continues
- **Bugfix (v1)**: All eBPF command output redirected to `/dev/null` to prevent crash reporter interference
- **Bugfix (v2)**: Root cause was VM image missing bpffs mountpoint + loader hang potential. Fixed: `mkdir -p /sys/fs/bpf` before mount, `timeout 10` on loader to prevent hang blocking executor, loader output saved to `/tmp/probe-ebpf.log` for debugging. VM image fstab updated with bpffs entry. BPF header `accounted` field removed for kernel 6.1.20 compatibility.
- **Bugfix (v3)**: `ebpf_init()` was called too early in `executor.cc` (before shmem fd operations), so `BPF_OBJ_GET` would steal fd 5/6 (`kMaxSignalFd`/`kCoverFilterFd`) when the runner didn't provide coverage filter. The `fcntl()` check then misidentified the BPF map fd as a shmem fd, causing `mmap` to fail on all VMs. Fixed: moved `ebpf_init()` to after all shmem fd operations (`mmap_input`, `mmap_output`, CoverFilter setup) in executor.cc exec mode. Also cleaned up diagnostic code: removed `/tmp/shmem-diag.txt` file writing from `shmem.h`, removed tier3 raw output logging from `manager.go`. Kept improved error message in `shmem.h` (with errno, fd, size info).
- **Bugfix (v4)**: eBPF metrics were always 0 on the Go (manager) side despite BPF programs collecting data. Root cause: `close_fds()` in `common_linux.h` calls `close_range(3, MAX_FDS, 0)` which closes ALL fds >= 3 including the BPF map fd. The eBPF read in `finish_output()` happened AFTER `close_fds()` in a different process (runner), so `BPF_MAP_LOOKUP_ELEM` failed on the already-closed fd. Fixed: (1) exec child reads eBPF metrics BEFORE `close_fds()` and writes them to `OutputData` shared memory via atomic fields, (2) runner's `finish_output()` reads from shared memory instead of calling `ebpf_read_and_reset()` directly, (3) added `ebpf_init()` retry in `execute_one()` for late BPF deployment, (4) added `access()` check in `ebpf_init()` before `BPF_OBJ_GET`. Verified: alloc/free counts non-zero from first execution.
- **Bugfix (v5)**: eBPF UAF score saturated to 100 for ALL programs over time (~5000+ executions). Root cause: `freed_objects` LRU map was never cleared between program executions, so freed pointers from program N appeared as "reuse" in program N+1, causing unbounded accumulation. Fixed: `ebpf_read_and_reset()` now iterates `freed_objects` map with `BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_DELETE_ELEM` loop (all 8192 entries per reset) to clear stale entries. Opened pinned freed_objects map via `ebpf_open_pinned()` helper alongside metrics map.
- **Bugfix (v6)**: Saturation guard in `finish_output()` — if `reuse > 500` (physically impossible per single program execution), suppress scoring entirely. Prevents residual saturation from overwhelming Focus Mode.

### 5f. Fuzzer Feedback — **DONE**
- `processResult()`: tracks `statEbpfAllocs`, `statEbpfReuses`, `statEbpfUafDetected`, `statEbpfDoubleFree`, `statEbpfSizeMismatch` stats
- Non-crashing UAF detection: UAF score ≥ 70 triggers `AddFocusCandidate()` → Focus Mode
- **Double-free Focus**: Any double-free detection triggers Focus Mode
- **Unified eBPF cooldown**: Both UAF and double-free Focus triggers share a single 5-min cooldown (`lastEbpfFocus` timestamp) to prevent Focus over-triggering
- Stats visible in web dashboard: `ebpf reuses` (rate), `ebpf uaf` (count), `ebpf double-free` (count), `ebpf size-mismatch` (rate) — all on `ebpf` graph

### 5g. Stability Hardening — **DONE**
Five production stability fixes applied to fuzzer core:

1. **eBPF saturation guard** (`executor.cc`): `reuse > 500` suppresses UAF scoring. Prevents residual freed_objects accumulation from causing all programs to score 100.
2. **Candidates counter fix** (`fuzzer.go`): `InjectSeed()` and `InjectProgram()` no longer use `progCandidate` flag or increment `statCandidates`. AI-injected seeds are not corpus triage candidates — mixing them caused the counter to go negative over time.
3. **Focus job cooldown** (`fuzzer.go`): `drainFocusPending()` enforces 2-min minimum between consecutive Focus jobs. Stale pending entries cleared on cooldown miss to prevent unbounded growth of the pending queue.
4. **ChoiceTable RWMutex** (`fuzzer.go`): `ctMu` changed from `sync.Mutex` to `sync.RWMutex`. `ChoiceTable()` (read-only, called on every mutation) uses `RLock()` for better concurrency. Writes (`updateChoiceTable`) continue using exclusive `Lock()`.
5. **focusTitles memory cap** (`fuzzer.go`): `focusTitles` dedup map capped at 10,000 entries. When exceeded, map is cleared and refilled from active Focus jobs only, preventing unbounded memory growth in long runs.

### Key Design Decisions
- **Separate loader + executor reads**: Loader handles complex BPF loading (cilium/ebpf), executor does simple map reads (raw bpf() syscall). Clean separation.
- **Tracepoints over kprobes**: `tracepoint/kmem/kfree` and `tracepoint/kmem/kmalloc` are stable ABI.
- **LRU hash map**: freed_objects uses LRU to auto-evict old entries, preventing unbounded growth.
- **Graceful degradation**: If eBPF isn't available, fuzzing continues normally with zero metrics.

### Build
```bash
cd syzkaller
make              # Builds executor with eBPF support
make probe_ebpf   # Builds BPF object + loader to bin/linux_amd64/
```

## Development Rules

1. **Plan before code**: Before implementing each Phase, MUST discuss and agree on a detailed development plan first. No coding without prior discussion.
2. **Update docs**: After significant changes, update both `probe.md` (EN) and `probe_kor.md` (KR), then push to GitHub.
3. **Scope**: Only modify `syzkaller/` directory. Never touch Linux kernel source.

## Implementation Order

| Phase | Component | Difficulty | Impact | Dependencies |
|-------|-----------|-----------|--------|-------------|
| 1 | Crash Filtering & Dedup Pipeline | Low | Immediate noise reduction + variant preservation | None | **DONE** |
| 2 | Focus Mode | Medium | Deep exploitation of high-severity findings | Phase 1 (needs severity tiers) | **DONE** |
| 3 | AI Triage (Claude Haiku 4.5) | Medium | Smart group-level crash analysis | Phase 1 (needs dedup groups), Phase 2 (needs Focus Mode) |
| 4 | Practical Hardening (UAF/OOB) | Medium | Higher vuln discovery rate | None (can parallel with 2-3) | **DONE** |
| 5 | eBPF Runtime Monitor | High | Real-time exploitability feedback | Phase 2 (needs Focus Mode feedback loop) | **DONE** |
| 6 | AI Cost Optimization + Data-Driven Scheduling | Medium | -50% API cost, DEzzer auto-optimization, SyzMini minimization | Phase 3 (needs AI integration) | **DONE** |

**Critical path**: Phase 1 → Phase 2 → Phase 3 (sequential dependency)
**Parallel track**: Phase 4 can start any time independently

## Phase 6: AI Cost Optimization + Data-Driven Scheduling — **DONE**

Phase 6 focuses on AI API cost reduction and data-driven fuzzing optimization. After deep analysis, 2 of the original 6 items were removed (Prompt Caching, Tiered Routing — insufficient benefit) and 2 were significantly redesigned.

### 6a. Batch API Migration — **DONE**

**Goal**: Use Anthropic Message Batches API (`/v1/messages/batches`) for 50% cost reduction on crash analysis. Strategy calls (1/hour) remain synchronous.

**Files modified**: `pkg/aitriage/client.go` (BatchClient interface + Anthropic implementation), `pkg/aitriage/batch.go` (new: state persistence), `pkg/aitriage/aitriage.go` (stepA batch/sync branching)

**Key design**:
- Batch mode activates when: Anthropic provider + 2+ pending crashes
- 30-second polling, 30-minute timeout, then cancel + sync fallback
- Disk persistence (`ai-batch-state.json`) for crash recovery
- Failed batch requests retry synchronously (max 3)
- OpenAI provider always uses sync mode (no batch support)

### 6d'. Per-Source Coverage Metrics — **DONE**

**Goal**: Track coverage gains per source (focus/smash/fuzz) for scheduling optimization data.

**Files modified**: `pkg/fuzzer/stats.go` (3 new stat.Val), `pkg/fuzzer/fuzzer.go` (processResult source attribution)

**Metrics**: `statFocusCovGain`, `statSmashCovGain`, `statFuzzCovGain` — visible on dashboard as "source cov" stacked graph.

### 6e. SyzMini Influence-Based Minimization — **DONE**

**Goal**: Reduce minimization cost by ~60% using influence-based call removal ordering (SyzMini, ATC 2025).

**Files modified**: `prog/minimization.go` (removeCalls Phase 3 with influence probing)

**How it works**: For `MinimizeCorpus` mode, before removing calls sequentially:
1. **Influence probing**: Try removing each call once to check if it breaks the signal (max 30 calls)
2. **Sort**: Removable calls first (influence=0), then non-removable
3. **Remove**: Safe removals first triggers cascade effects, reducing total pred calls

Non-corpus modes (PatchTest, CrashSnapshot) use the original end→begin order.

### 6f. DEzzer — Operator Tracking + DE Optimization — **DONE**

**Goal**: Track per-operator mutation success rates and auto-optimize weights via Differential Evolution.

**Files modified**: `prog/mutation.go` (string return value), `pkg/fuzzer/dezzer.go` (new: DE engine), `pkg/fuzzer/fuzzer.go` (DEzzer integration), `pkg/fuzzer/job.go` (operator capture), `pkg/fuzzer/stats.go` (operator stats)

**3-Layer Architecture**:
```
Layer 1: DefaultMutateOpts (constant)     — Squash:50, Splice:200, ...
Layer 2: AI Base Weights (hourly)         — multiplier set by SetAIMutationHints
Layer 3: DE Delta (real-time, ±20%)       — fine-tuning via DEzzer
Final weights = Default × AI Base × DE Delta
```

**Lazy DE**: Evolves 1 generation every 100 mutation results. Population=10, sliding window=100 per operator. AI reset → population reset.

**mutation.go change**: `Mutate()` and `MutateWithOpts()` now return `string` (operator name). Go allows ignoring return values, so 12+ test callsites and tool callsites need no modification.

### 6f'. Focus Coverage Feedback Loop — **DONE**

**Goal**: Feed focus job results + DEzzer state back into AI strategy prompts.

**Files modified**: `pkg/fuzzer/fuzzer.go` (FocusJobResult, buffer), `pkg/fuzzer/job.go` (result recording), `pkg/aitriage/aitriage.go` (FuzzingSnapshot fields), `pkg/aitriage/prompt_strategy.go` (prompt formatting), `syz-manager/ai_triage.go` (snapshot wiring)

**Prompt formatting**: ≤5 results → full detail; 6-20 → 3 recent detail + aggregate summary (~300 tokens cap).

### Build

```bash
cd syzkaller && make host  # Builds all host tools including syz-manager
```

## Phase 7: Core Detection Enhancement — **DONE**

CO-RE (Compile Once, Run Everywhere) based infrastructure for portable kprobe access, plus 5 sub-tasks enhancing vulnerability detection capabilities.

### 0. CO-RE Infrastructure

**Goal**: Build environment for portable kprobe programs using `vmlinux.h` + libbpf CO-RE headers.

**Changes**:
- Generated `vmlinux.h` from kernel BTF via `bpftool btf dump` (added to `.gitignore`)
- Vendored libbpf headers (`bpf_helpers.h`, `bpf_tracing.h`, `bpf_core_read.h`) into `executor/ebpf/bpf/`
- Rewrote `probe_ebpf.bpf.h` to use `vmlinux.h` instead of manual type definitions
- Build: `clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I executor/ebpf/ -I executor/ebpf/bpf/ -c executor/ebpf/probe_ebpf.bpf.c -o executor/ebpf/probe_ebpf.bpf.o`

### 7d. Privilege Escalation Detection — **DONE**

**Goal**: Detect `commit_creds()` calls via kprobe to identify privilege escalation vulnerabilities.

**Dual strategy**: `commit_creds_count` (all sandboxes, informational) + `priv_esc_count` (uid!=0→uid==0, sandbox_setuid only).

**BPF program**: `kprobe_commit_creds` — CO-RE reads `new_cred->uid.val` and `task->real_cred->uid.val`.

**Scoring**: `priv_esc_count > 0` → UAF score = 100 (top priority); `commit_creds_count > 0` → +5.

**Files modified**: `executor/ebpf/probe_ebpf.bpf.h`, `probe_ebpf.bpf.c`, `executor_linux.h`, `executor.cc`, `flatrpc.fbs`, `flatrpc.go`, `flatrpc.h`, `syz-ebpf-loader/main.go`, `pkg/fuzzer/stats.go`, `pkg/fuzzer/fuzzer.go`

### 7c. Cross-Cache Precise Detection — **DONE**

**Goal**: Replace size-mismatch heuristic with cache-name-based tracking via kprobe on `kmem_cache_free`.

**Design**: `cache_freed` LRU map (ptr → cache_name_hash), `kprobe_cache_free` stores hash on free, `trace_cache_alloc` checks if ptr was freed from a different cache.

**Scoring**: `cross_cache_count > 0` → +20; `cross_cache_count > 3` → +40.

**Files modified**: Same executor/flatrpc pipeline as 7d, plus `cache_freed` BPF map in `probe_ebpf.bpf.c`.

### 7b'. Slab-Pair Boosting — **DONE**

**Goal**: Collect per-call-site alloc/free patterns from eBPF, provide to AI strategy prompts.

**Design**: `slab_sites` LRU_HASH map (512 entries), updated in existing `trace_kmalloc`/`trace_kfree` tracepoints. Manager reads pinned map via cilium/ebpf.

**AI integration**: Strategy prompt includes top-10 slab sites with labels (allocator-only, deallocator-only, over-freeing, under-freeing, balanced).

**Files modified**: `probe_ebpf.bpf.c` (slab_sites map), `syz-ebpf-loader/main.go` (pin), `syz-manager/ai_triage.go` (readSlabSites), `pkg/aitriage/prompt_strategy.go` (prompt section)

### 7e. GPTrace Embedding Dedup — **DONE**

**Goal**: Semantic crash deduplication using OpenAI text-embedding-3-small vectors + cosine similarity clustering.

**Design**: `EmbeddingClient` (separate cost tracker from main LLM), `ClusterState` (agglomerative clustering, threshold=0.85), batch processing in `stepEmbeddings()`.

**Config**: `embedding_model`, `embedding_api_key` fields in `ai_triage` config block. Missing → graceful skip.

**Dashboard**: `/ai/embeddings` page with summary cards (total embeddings, clusters, cost) + cluster table + embedded crashes table. Tab navigation: AI Dashboard / Analytics / Embeddings.

**Files modified**: `pkg/aitriage/embedding.go` (new), `pkg/aitriage/cluster.go` (new), `pkg/aitriage/aitriage.go`, `pkg/mgrconfig/config.go`, `pkg/manager/http.go`, `html/aiembeddings.html` (new), `html/ai.html`

### 7a. SyzGPT Seed Generation — **DONE**

**Goal**: Generate seed programs for low-frequency syscalls (LFS) via LLM to expand coverage.

**Design**: Manager computes LFS list (EnabledCalls with coverage < 3), builds dependency chains using `ForeachCallType` + `ResourceDesc.Ctors`, finds corpus examples. `stepC()` in batch cycle generates up to 10 programs per hour. Programs validated via `prog.Deserialize()` (NonStrict), invalid → discarded.

**Prompt**: System prompt with syzkaller format specification + target syscall args/resources/examples. Response parsed, validated, injected.

**Dashboard**: SyzGPT stats (generated/valid/injected) shown on `/ai` page.

**Files created**: `pkg/aitriage/prompt_syzgpt.go`, `syz-manager/syzgpt.go`
**Files modified**: `pkg/aitriage/aitriage.go` (stepC, callbacks), `syz-manager/ai_triage.go` (wiring), `pkg/fuzzer/stats.go` (stats), `pkg/manager/http.go` (dashboard), `html/ai.html`

### FlatBuffers (Phase 7)

Three new fields added to `ProgInfoRaw`:
- `ebpf_commit_creds_count` (field 13, VT=30)
- `ebpf_priv_esc_count` (field 14, VT=32)
- `ebpf_cross_cache_count` (field 15, VT=34)

`StartObject` changed from 13 to 16. Manual edits in `flatrpc.go` and `flatrpc.h`.

### Build

```bash
# BPF object (requires vmlinux.h — generate first if missing):
# bpftool btf dump file /path/to/vmlinux format c > syzkaller/executor/ebpf/vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I executor/ebpf/ -I executor/ebpf/bpf/ \
    -c executor/ebpf/probe_ebpf.bpf.c \
    -o executor/ebpf/probe_ebpf.bpf.o

cd syzkaller && make host  # Builds all host tools including syz-manager
```

## Phase 6+: Advanced Improvements Roadmap

**Full roadmap**: See `syzkaller/probe_log/improvement_roadmap.md` for detailed descriptions, paper references, and cost projections.

Based on a survey of 30+ papers (CCS/NDSS/ASPLOS/USENIX 2024-2026), 39 applicable techniques were identified and prioritized into 7 phases:

| Phase | Focus | Timeline | Key Techniques | Expected Impact |
|-------|-------|----------|----------------|-----------------|
| 6 | AI Cost Optimization + Scheduling | Week 1 | Batch API, Prompt Caching, Tiered Routing, T-Scheduler, SyzMini, DEzzer | **-80% API cost**, better scheduling |
| 7 | Core Detection Enhancement | Week 2-3 | SyzGPT (DRAG), CountDown (refcount), Cross-cache, Privilege escalation, GPTrace | **+323% vuln detection**, +66% UAF |
| 8 | Mutation & Coverage Innovation | Week 3-4 | MOCK, SeqFuzz, MobFuzz, Coverage feedback, Write-to-freed | **+32% coverage**, 3-4.5x bugs |
| 9 | Advanced Coverage & Detection | Month 2 | KBinCov, Page-level UAF, Context-sensitive, FD lifecycle, Anamnesis | **+87% binary coverage** |
| 10 | Spec Auto-Generation | Month 2-3 | KernelGPT, SyzForge, SyzSpec | **+13-18% coverage**, new syscalls |
| 11 | Concurrency Bugs | Month 3 | LACE, ACTOR, OZZ | **+38% coverage**, race conditions |
| 12 | Advanced Monitoring & Research | Month 3+ | KASLR leak, Quarantine bypass, Snowplow, Big Sleep | Experimental |

### Cost-incurring techniques (require API budget)
- SyzGPT seed generation (+$0.10-0.50/day)
- GPTrace embedding dedup (+$0.01-0.05/day)
- Anamnesis exploit assessment (+$0.50-3.00/day)
- KernelGPT/SyzForge spec generation (+$0.50-2.00/run)

### Non-cost techniques (pure code changes)
- All scheduling improvements (T-Scheduler, DEzzer, MobFuzz)
- All eBPF extensions (refcount, cross-cache, page-level, FD, privilege escalation)
- Mutation improvements (MOCK, SeqFuzz, SyzMini)
- Coverage extensions (KBinCov, context-sensitive)
- Concurrency testing (LACE, ACTOR)

## Related Research

| Paper | Venue | Relevance |
|-------|-------|-----------|
| SyzGPT | ISSTA 2025 | Dependency-based RAG, +323% vuln detection — Phase 7 |
| CountDown | CCS 2024 | Refcount-guided UAF, +66.1% UAFs — Phase 7 |
| MOCK | NDSS 2024 | Context-aware mutation, +32% coverage — Phase 8 |
| Snowplow | ASPLOS 2025 | ML-guided mutation (Google DeepMind), 4.8x speedup — Phase 12 |
| KernelGPT | ASPLOS 2025 | LLM spec generation, 24 bugs, 11 CVEs — Phase 10 |
| GPTrace | ICSE 2026 | LLM embedding crash dedup — Phase 7 |
| KBinCov | CCS 2024 | Binary coverage, +87% — Phase 9 |
| SyzMini | ATC 2025 | Minimization optimization, -60.7% cost — Phase 6 |
| LACE | 2025 | eBPF sched_ext concurrency, +38% coverage — Phase 11 |
| Anamnesis | 2026 | LLM exploit generation, ~$30/exploit — Phase 9 |
| MobFuzz | NDSS 2024 | Multi-objective MAB, 3x bugs — Phase 8 |
| SeqFuzz | Inscrypt 2025 | Effective component inference, 4.5x bugs — Phase 8 |
| SLUBStick | USENIX Sec 2024 | Cross-cache attacks, 99% success — Phase 12 |
| ACTOR | USENIX Sec 2023 | Concurrency testing — Phase 11 |
| SyzScope | USENIX Sec 2022 | 15% of "low-risk" bugs are high-risk — Phase 1+2 motivation |
| GREBE | IEEE S&P 2022 | 6 "unexploitable" → arbitrary code exec — Phase 2 motivation |

## Key Files Reference

| File | Purpose |
|------|---------|
| `prog/mutation.go` | Mutation strategies & weights |
| `prog/generation.go` | Program generation entry point |
| `prog/rand.go` | Integer generation, special values |
| `pkg/fuzzer/fuzzer.go` | Fuzzing loop, queue management |
| `pkg/fuzzer/job.go` | Job types (triage, smash, hints) |
| `pkg/report/report.go` | Crash parsing pipeline |
| `pkg/report/crash/types.go` | Crash type definitions |
| `pkg/report/impact_score.go` | Severity ranking |
| `pkg/report/linux.go` | Linux-specific crash parsing |
| `pkg/manager/` | Manager business logic |
| `sys/linux/*.txt` | Syscall descriptions (syzlang) |
| `executor/executor.cc` | In-VM syscall executor (C++) |
| `executor/ebpf/probe_ebpf.bpf.c` | eBPF heap monitor (BPF C) |
| `tools/syz-ebpf-loader/main.go` | BPF loader binary (Go) |
| `pkg/flatrpc/flatrpc.fbs` | FlatBuffers RPC schema |

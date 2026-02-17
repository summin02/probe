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
|  [Phase 5] eBPF Runtime Monitor [DONE]                |
|    - Slab object lifecycle tracking (kprobe-based)    |
|    - Exploitability scoring                           |
|    - Real-time feedback to Focus Mode                 |
|    - No kernel source modification (attach to         |
|      existing kprobes/tracepoints)                    |
|                                                       |
|  [Phase 7-8] Advanced Mutation & Coverage [DONE]      |
|    - MuoFuzz operator-pair Thompson Sampling          |
|    - SeamFuzz cluster-based TS scheduling             |
|    - MOCK BiGRU syscall prediction (CUDA server)      |
|    - SeqFuzz effective component inference            |
|    - MobFuzz multi-objective optimization             |
|                                                       |
|  [Phase 9-10] AI Spec Generation [DONE]               |
|    - DeepSeek-driven syzlang auto-generation          |
|    - eBPF metric gap analysis                         |
|    - Page/FD/context-sensitive coverage               |
|                                                       |
|  [Phase 11] Performance & Race Detection [DONE]       |
|    - LACE eBPF race detection                         |
|    - MI seed scheduling                               |
|    - LinUCB contextual bandit                         |
|    - Bayesian Optimization (GP)                       |
|    - CUSUM circuit breaker                            |
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

### 6f. DEzzer — Hybrid TS+DE Mutation Optimizer — **DONE**

**Goal**: Track per-operator mutation success rates and auto-optimize weights via Thompson Sampling (primary) + Differential Evolution (secondary).

**Files modified**: `prog/mutation.go` (string return value), `pkg/fuzzer/dezzer.go` (TS+DE hybrid engine), `pkg/fuzzer/fuzzer.go` (DEzzer integration, crash bonus), `pkg/fuzzer/job.go` (operator capture, FeedbackSource), `pkg/fuzzer/stats.go` (operator stats), `pkg/aitriage/aitriage.go` (DEzzerStatusData extended), `pkg/aitriage/prompt_strategy.go` (TS+DE prompt), `syz-manager/ai_triage.go` (snapshot wiring)

**4-Layer Architecture**:
```
Layer 1: DefaultMutateOpts (constant)     — Squash:50, Splice:200, ...
Layer 2: AI Base Weights (hourly)         — multiplier set by SetAIMutationHints
Layer 3: TS Delta (real-time, ±20%)       — per-operator Bayesian adaptation
Layer 4: DE Correction (real-time, ±5%)   — operator synergy search
Final weights = Default × AI Base × TS Delta × DE Correction
```

**Thompson Sampling (primary)**:
- Beta-Bernoulli posteriors per operator (binary success/failure signal)
- Time-based decay (30s intervals, factor 0.9, ~3.3 min half-life)
- Path-weighted feedback: mutateProgRequest=1x, smashJob=2x, focusJob=3x
- IPW correction for selection bias (cap 5x)
- Saturation detection: when mean prob < 0.1%, switches to relative performance mode
- Crash bonus: alpha += 10 for crash-triggering operators

**Differential Evolution (secondary)**:
- ±5% correction range (vs TS ±20%), independent fitness (squared error from ideal)
- Conflict detection: when TS and DE disagree on 3+/5 operators, DE dampened to ±2%
- Population=10, lazy evolution every 100 records, stagnation restart

**Risk Mitigations**:
- Warm-up period: first 1000 records use neutral delta (Default × AI Base only)
- Exploration rounds: every 5000 records, 50 records with neutral delta
- Selective AI reset: small change (Σ|Δ|<0.3) → 30% TS preserve + DE kept; large → full reset
- AI direction hint injection: AI base increase → alpha+2, decrease → beta+2
- Phase 12 ML feature collection: ring buffer of 100K (timestamp, op, gain, source, saturated)

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

## Phase 8: Mutation & Coverage Innovation — DONE

**Goal**: Smarter mutation strategies, multi-objective optimization, and enhanced exploit detection. Total overhead < 3.5%, no additional AI API cost.

**Analysis basis**: Deep code-level review of `prog/mutation.go`, `pkg/fuzzer/dezzer.go`, `pkg/fuzzer/job.go`, and 15+ papers (NDSS/CCS/ICSE/ISSTA 2022-2025). Each technique evaluated for runtime performance impact, realistic effectiveness (not paper maximums), and synergy with existing PROBE architecture.

### 8a. Write-to-freed eBPF Detection — DONE

**Goal**: Detect writes to freed slab objects via `copy_from_user` kprobe — near-certain exploitability signal.

**Design**: kprobe on `_copy_from_user`, cross-reference destination address with `freed_objects` LRU map (Phase 5). Slab-alignment matching (64/128/256 bytes) to handle writes to offsets within freed objects. Epoch filter + 50ms time window to prevent stale false positives.

**Overhead**: < 1.5%. **Expected impact**: Strong exploitability signal for Focus Mode prioritization.

**UAF score contribution**: +30 (1+ writes), +50 (3+ writes). Focus mode triggered on any write-to-freed detection.

**Implementation**: Added to existing `probe_ebpf.bpf.c` (shares `freed_objects` map and `metrics` struct, separate BPF file unnecessary). FlatBuffers field `ebpf_write_to_freed_count` (VT=36, slot 16). Dashboard stat: "ebpf write-to-freed".

**Files modified**: `executor/ebpf/probe_ebpf.bpf.h`, `executor/ebpf/probe_ebpf.bpf.c`, `executor/executor_linux.h`, `executor/executor.cc`, `pkg/flatrpc/flatrpc.fbs`, `pkg/flatrpc/flatrpc.h`, `pkg/flatrpc/flatrpc.go`, `pkg/fuzzer/stats.go`, `pkg/fuzzer/fuzzer.go`, `tools/syz-ebpf-loader/main.go`

### 8b. Operator-Pair Thompson Sampling (MuoFuzz) — DONE

**Goal**: Learn conditional probabilities between consecutive mutation operators — P(next_op success | prev_op).

**Source**: MuoFuzz (FuzzBench/MAGMA). Extends DEzzer from 5 independent distributions to 5×5 = 25 pair distributions.

**Design**: `pairAlpha[prev_op][next_op]`, `pairBeta[prev_op][next_op]` in DEzzer. Fallback to single-op TS when pair data < 50 records. Layered delta: pair TS → cluster TS → global TS (best available data used). `RecordResult` extended with `prevOp` parameter; `GetCurrentWeightsForPair` selects best TS layer. Decay applied uniformly across global/pair/cluster posteriors.

**Overhead**: < 0.1% (25 floats = 400 bytes, O(1) lookup). **Expected impact**: +5-10% mutation efficiency.

**Files modified**: `pkg/fuzzer/dezzer.go` (pair stats, `computePairTSDelta`, `computeTSDeltaLayered`), `pkg/fuzzer/job.go` (prevOp tracking in smashJob/focusJob), `pkg/fuzzer/fuzzer.go` (getAIMutateOpts signature change)

### 8c. Multi-Objective Meta-Bandit (MobFuzz) — DONE

**Goal**: Optimize for multiple objectives (coverage + memory_safety + priv_esc) instead of coverage alone.

**Source**: MobFuzz (NDSS 2022), adapted from user-space AFL to kernel fuzzing using existing eBPF signals.

**Design**: Meta-bandit architecture with independent TS per objective:
- Layer 0: UCB-1 selects objective (coverage / memory_safety / priv_esc) per 100-execution epoch
- Layer 1: Objective-specific operator TS (each objective has its own `objAlpha`/`objBeta` arrays)
- `memory_safety_reward = uaf_score/100 + cross_cache*0.5 + double_free*0.8 + write_to_freed*1.0`
- Dynamic coverage floor: 70% (first 1h) → 50% (1-4h) → 30% (4h+)
- `selectObjective()` forces coverage when fraction drops below floor

**Sparse reward solution**: Each objective has independent TS with own reward signal. `RecordObjectiveReward` called from focusJob with eBPF-derived rewards.

**AI integration**: Objective status (current objective + counts) included in AI strategy prompt via DEzzerStatusData.

**Overhead**: < 0.5%. **Expected impact**: +50-100% high-risk bug discovery.

**Files modified**: `pkg/fuzzer/dezzer.go` (objAlpha/objBeta/objRewards/objCounts, selectObjective UCB-1, epochLeft), `pkg/fuzzer/fuzzer.go` (recordObjectiveReward), `pkg/aitriage/aitriage.go` (DEzzerStatusData extended), `pkg/aitriage/prompt_strategy.go` (objective status in prompt)

### 8d. MOCK Context-Aware Dependency (BiGRU) — DONE

**Goal**: Learn syscall sequence dependencies via BiGRU language model for context-aware mutation.

**Source**: MOCK (NDSS 2024). BiGRU (embed=64, hidden=128, ~1-2MB model). Trains on corpus programs that triggered new coverage. Retrains every 2 hours. Top-k=5 sampling. UCB-1 balances static vs. context-aware mutation.

**Design**: Python subprocess (PyTorch) running as TCP/JSON server (lightweight alternative to gRPC to avoid Go dependency). Go `NgramClient` connects to `tools/mock_model/server.py`. `insertCall()` uses `PredictCall` callback (50% chance) to get BiGRU prediction → `generateParticularCall()` for predicted syscall. Health check every 5s, auto-fallback to ChoiceTable if Python server unavailable. UCB-1 tracks BiGRU vs ChoiceTable success rates with 100-trial cold start exploration.

**Persistent connection fix**: Server uses persistent JSON-line TCP connections (port 50051) with 300s idle timeout. NgramClient in Go maintains a single persistent connection with UCB-1 selection between BiGRU and ChoiceTable strategies.

**Manager integration**: `mockModelRetrainLoop` goroutine triggers retrain every 2 hours via NgramClient.

**Overhead**: < 1% (inference < 1ms via GPU, RTX 3070 Ti). Training: ~30s every 2h (non-blocking). **Expected impact**: +3-12% coverage (paper average).

**Cold start**: First 100 trials alternate BiGRU/ChoiceTable for exploration; after that UCB-1 selects the better strategy.

**Files created**: `tools/mock_model/` (model.py, train.py, server.py, proto/mock.proto, requirements.txt), `pkg/fuzzer/ngram.go` (NgramClient TCP/JSON)
**Files modified**: `prog/mutation.go` (PredictCall callback in MutateOpts + insertCall), `pkg/fuzzer/fuzzer.go` (ngramClient init + PredictCall wiring), `syz-manager/manager.go` (mockModelRetrainLoop)

### 8e. Per-Cluster Thompson Sampling (SeamFuzz) — DONE

**Goal**: Maintain separate DEzzer weights per kernel subsystem cluster.

**Source**: SeamFuzz (ICSE 2023). Programs clustered by dominant syscall subsystem: fs, net, mm, ipc, device, other.

**Design**: `classifyProgram()` uses majority-vote over syscall name prefixes (O(n), < 0.001ms). 6 clusters: ClusterFS/Net/MM/IPC/Device/Other. DEzzer maintains per-cluster `clusterAlpha[6][5]`/`clusterBeta[6][5]` arrays. `computeClusterTSDelta()` computes cluster-specific weights. Fallback to global TS when `clusterCount[c] < 100`. Classification done once per smashJob/focusJob, reused across all iterations.

**Overhead**: < 0.2%. **Expected impact**: +3-8% crash discovery (subsystem-specific optimization).

**Files modified**: `pkg/fuzzer/dezzer.go` (cluster alpha/beta/count, `computeClusterTSDelta`), `pkg/fuzzer/fuzzer.go` (`classifyProgram`, `isFS/isNet/isMM/isIPC/isDevice` helpers), `pkg/fuzzer/job.go` (cluster passed to RecordResult)

### 8f. Effective Component Inference (lightweight SeqFuzz) — DONE

**Goal**: Identify which syscalls in a program are essential for crash reproduction, focus mutation on them.

**Source**: SeqFuzz (Inscrypt 2025) concept, adapted as lightweight dynamic ablation (no static ICFG analysis).

**Design**: Focus job only. `computeAblation()` at focus job start: baseline 3× execution for signal reference, then remove calls one-by-one, execute 3× each. Calls where removal loses >20% signal = essential. `essentialMutate()` blocks mutation of non-essential calls via noMutate map override. 50% chance per iteration: essential-focused mutation vs full-program mutation. Skip ablation if program length < 5. `ablationCache` (map[string][]bool) capped at 1000 entries.

**Overhead**: n_calls × 3 executions at focus job start (< 3s for 20 calls). **Expected impact**: 2-3x focus job efficiency.

**Files modified**: `pkg/fuzzer/fuzzer.go` (`getOrComputeAblation`, `computeAblation`, `essentialMutate`, `ablationMu`/`ablationCache`), `pkg/fuzzer/job.go` (focusJob: essential mask + 50% essential-focused mutation)

### Phase 8 Implementation Order

```
8a (Write-to-freed) → 8b (Op-pair TS) → 8e (Cluster TS) → 8f (Effective Component) → 8d (MOCK BiGRU) → 8c (Multi-obj, last)
```

Rationale: 8a is simplest with immediate value. 8b/8e extend DEzzer incrementally. 8f enhances Focus Mode. 8d requires Python infrastructure. 8c depends on 8a providing new objective signals and all other features being stable.

### Phase 8 Risk Summary

| Risk | Subphase | Prob | Impact | Mitigation |
|------|----------|------|--------|------------|
| copy_from_user overhead | 8a | Med | Med | Address range pre-filter (slab heap only) |
| cache_freed stale entry | 8a | High | Med | 50ms time window + 3-execution statistical confirmation |
| Pair distribution slow convergence | 8b | Med | Low | Single-op fallback when pair data < 50 |
| Objective conflict (coverage vs UAF) | 8c | High | High | Meta-bandit with independent TS per objective, dynamic coverage floor |
| Sparse eBPF reward signals | 8c | High | High | Per-objective epoch ratio (eliminates amplification) |
| DEzzer complexity explosion | 8b+c+e | Med | High | Layered separation + feature flags + incremental activation |
| Python↔Go IPC instability | 8d | Med | High | gRPC + health check + auto-fallback to ChoiceTable |
| Model quality = corpus quality | 8d | Med | Med | UCB-1 auto-balancing + rollback on regression |
| Flaky crash ablation misclassification | 8f | High | Med | 3× repetition + deflake reuse |
| Cumulative overhead | All | Med | Med | Per-feature measurement, disable if > 5% |

### Phase 8 Verification

Each sub-phase: `go build` + `go vet` → 1h fuzzing (exec/sec baseline) → 4h run (crash discovery comparison).

## Phase 9: Advanced Coverage & Detection — DONE

**Goal**: Extend coverage metrics and vulnerability detection with page-level UAF, context-sensitive signals, FD lifecycle tracking, and AI-based exploit assessment.

**Analysis basis**: KBinCov (CCS 2024), Anamnesis (2026), and custom detection heuristics for page-level and FD-based vulnerabilities.

### 9a. Page-Level UAF Detection — DONE

**Goal**: Detect page-level UAF by tracking page alloc/free patterns via eBPF. Extends slab-level UAF detection (Phase 5) to page allocator.

**Design**: eBPF hooks on `tracepoint/kmem/mm_page_alloc` and `tracepoint/kmem/mm_page_free`. Tracks page-order allocations in dedicated BPF map. Score: page reuse within 1ms = high UAF probability.

**New metrics**: `ebpf_page_alloc_count`, `ebpf_page_free_count`, `ebpf_page_uaf_score` in FlatBuffers.

### 9b. Context-Sensitive Coverage — DONE

**Goal**: Augment edge coverage with calling-context sensitivity for deeper signal differentiation.

**Design**: Lightweight hash-based context tracking in signal processing. `pkg/signal/signal.go` modified to incorporate call-site context into signal hashes, enabling coverage distinctions for the same edge reached via different call paths.

### 9c. FD Lifecycle Tracking — DONE

**Goal**: Track file descriptor lifecycle (open/close/dup patterns) via eBPF for FD-reuse vulnerability detection.

**Design**: eBPF programs on `sys_enter_close`, `sys_exit_openat` tracking FD allocation and deallocation patterns. `ebpf_fd_reuse_count` metric added to FlatBuffers. FD reuse within same execution = potential race condition signal.

### 9d. Anamnesis Exploit Assessment — DONE

**Goal**: AI-based exploit feasibility assessment using LLM analysis of crash context, memory layout, and known exploitation patterns.

**Design**: `stepD()` in `pkg/aitriage/aitriage.go` runs after crash analysis. Uses DeepSeek API (primary) for cost-effective assessment. Scoring: 0-100 exploit feasibility. High scores (>=70) auto-trigger Focus Mode with priority boost. Assessment integrated into DEzzer feedback loop (Phase 14: RecordAnamnesisBonus).

**Files**: `pkg/aitriage/aitriage.go` (stepD, assessment types), `pkg/aitriage/specgen.go` (spec generation), `pkg/fuzzer/fuzzer.go` (assessment integration in processResult)

### 9e. Dashboard Enhancements — DONE

**Stats**: `ebpf-uaf`, `ebpf-heap`, `ebpf-race` graph groups (split from single `ebpf` graph in Phase 14 D10). Anamnesis assessment stats on AI dashboard.

---

## Phase 10: AI Spec Auto-Generation — DONE

**Goal**: Automatically generate syzkaller syscall specifications using LLM analysis of kernel source code, covering syscalls not yet described in syzlang.

**Design**: DeepSeek API (primary, cost-effective) for spec generation. SyzSpec approach removed after analysis showed insufficient benefit.

### Architecture

```
Kernel source analysis → Gap identification → LLM spec generation → Validation → Injection

stepD() in aitriage.go:
1. Identify syscalls with low/no coverage (gap analysis)
2. Analyze kernel source for argument types, resource dependencies
3. Generate syzlang specification via LLM
4. Validate generated spec with prog.Deserialize()
5. Inject valid specs into corpus as seed programs
```

### Key Components

**`pkg/aitriage/specgen.go`**: Spec generation engine. Gap analysis, LLM prompt construction, syzlang output parsing and validation. Supports incremental generation (specs accumulated over time).

**`syz-manager/syzgpt.go`**: Manager-side integration. Spec-to-seed pipeline, coverage tracking per generated spec, quality gating (discard specs with no coverage gain after 3 attempts).

**Config**: Uses `ai_triage` config block. DeepSeek model auto-detected from model name prefix. Graceful degradation when API unavailable.

**Cost**: ~$0.50-2.00 per generation run (DeepSeek pricing). Runs as part of hourly batch cycle.

---

## Phase 11: Concurrency & Performance Optimization — DONE

**Goal**: Add concurrency bug detection capabilities (LACE race detection, ACTOR delay injection) and performance optimizations (MI seed scheduling, LinUCB contextual bandit, Bayesian Optimization).

### Wave 1 (11a-11h): P0/P1 Fixes + Track A Performance — DONE

Critical bug fixes and performance improvements identified during Phase 8-10 integration:
- P0 fixes: DEzzer array initialization, CUSUM circuit breaker (3 resets/10min limit), eBPF metric alignment
- P1 fixes: smashJob DEzzer weight application, Focus job feedback loop stability
- Track A: DEzzer TS accuracy improvements, exploration/exploitation balance tuning

### Wave 2 (11i, 11m): LACE Race Detection + MI Seed Scheduling — DONE

**11i. LACE Race Detection**: eBPF-based `sched_switch` tracepoint monitoring for detecting potential race conditions. Tracks concurrent execution patterns and context switch timing. `pkg/fuzzer/schedts.go` implements schedule-aware timing analysis.

**11m. MI (Mutual Information) Seed Scheduling**: Information-theoretic seed prioritization using mutual information between program features and coverage outcomes. `pkg/corpus/mi.go` implements MI-based seed ranking for corpus scheduling optimization.

### Wave 3 (11j): ACTOR + LinUCB + Spectral Graph — DONE

**11j-ACTOR**: Delay injection between syscalls to expose race conditions (ACTOR, USENIX Sec 2023). Implemented.

**11j-LinUCB**: Contextual bandit (LinUCB algorithm) for adaptive delay pattern selection. Code at `pkg/fuzzer/linucb.go` — 4 arms (no delay, random, between-calls, around-locks), 8-dimensional feature vector, Sherman-Morrison incremental inverse update, alpha annealing. Integrated into fuzzing loop.

**11j-Spectral**: Spectral graph analysis for syscall dependency inference. Implemented.

### Wave 4 (11k, 11l): OZZ + Bayesian Optimization — DONE

**11k-OZZ**: `sched_yield` injection for systematic concurrency exploration. Implemented.

**11l-Bayesian Optimization**: `pkg/fuzzer/bayesopt.go` — Bayesian Optimization for automated hyperparameter tuning of DEzzer parameters (decay factor, exploration weight, etc.). Fully integrated.

### Key Files

| File | Purpose |
|------|---------|
| `pkg/fuzzer/schedts.go` | LACE schedule-aware timing analysis |
| `pkg/corpus/mi.go` | Mutual Information seed scheduling |
| `pkg/fuzzer/linucb.go` | LinUCB contextual bandit (4 arms, 8-dim features) |
| `pkg/fuzzer/bayesopt.go` | Bayesian Optimization for hyperparameter tuning |

---

## Phase 12: Comprehensive Performance Tuning — DONE

**Goal**: Systematic performance tuning across 4 tracks: DEzzer precision, context-aware scheduling, Bayesian Optimization refinement, and eBPF infrastructure improvements.

**Analysis basis**: 5-round independent verification (3x risk analysis + 2x cross-check). 7 CRITICAL + 13 HIGH risk items identified and mitigated in final plan.

### Track A: DEzzer/Mutation Precision

- **A2 (D18)**: prevOp fix — `mutateProgRequest` now correctly passes previous operator name to DEzzer pair TS, increasing pair TS utilization from ~5% to ~50%+
- **A4 (D20)**: pairCount decay — `pairCount` and `clusterCount` now decayed in `maybeDecay()` with per-layer factors (pair: factor^0.5, cluster: factor^0.7) to prevent ratio distortion
- **A5 (D23)**: Splice alpha normalization monitoring with 60-second mutual exclusion window against CUSUM resets to prevent double confidence destruction
- **A7**: DEzzer stat reporting fixes for accurate dashboard display

### Track B: Context-Aware TS + Action Space

- **B1**: Cross-product TS (cluster × objective) for fine-grained operator selection
- **B3**: Action space expansion for DEzzer mutation operators

### Track C: Bayesian Optimization Refinement

- **C1**: BO parameter space expansion (LinUCB alpha, decay factors)
- **C2**: BO convergence speed improvement (target: 90% of best value in ≤20 epochs)

### Track D: eBPF/Infrastructure

- **D2**: eBPF map sizes tuning for optimal memory/performance balance

### Verification

Each track verified with soak tests (10-minute standard, 30-minute for high-risk items like A5). Build + test gates between tracks.

---

## Phase 14: Cross-Phase Synergy Integration — DONE

**Goal**: Integrate cross-subsystem synergies across DEzzer, Focus, eBPF, SyzGPT, and Anamnesis. 3-round reviewed plan (Architect R1 → Critic R2 → Architect R3).

**Scope**: 19 items (17 D-items + 14a + 14b) across 5 Waves. 7 items deferred to Phase 15 (14c-14h, D12).

### Wave 1: Foundation (D4, D6, D23, D8, D22, D3, D7) — DONE

- **D4**: `classifyProgram` expanded from 6 to 10 clusters — added ClusterIOURING(6), ClusterBPF(7), ClusterKEYCTL(8), ClusterOther2(9). io_uring removed from isFS(). configVersion=2.
- **D6**: DEzzer verbose log level already at 3 (pre-existing).
- **D23**: Alpha runaway defense-in-depth cap in `maybeDecay()` — caps global+cluster posteriors at 10000.
- **D8**: Write-to-freed alignment already included 512/1024 (pre-existing).
- **D22**: Anamnesis stat naming already consistent (pre-existing).
- **D3**: NgramClient port configurable via `mgrconfig` (was hardcoded).
- **D7**: PageUafThreshold and FdReuseThreshold configurable via `mgrconfig` with defaults.

### Wave 2: Accuracy/Efficiency (D5, D14, D13, D15, D9) — DONE

- **D5**: Removed JSON marshal/unmarshal round-trip from `SetAIMutationHints` — direct type assertion instead. `encoding/json` import removed.
- **D14**: StepB crash hash now includes `totalSignal` for coverage delta differentiation.
- **D13**: Per-type cost tracking (StepB/StepD/LFS calls and costs) in `CostTracker`.
- **D15**: `seen_stacks` periodic clear every 10000 executions via `BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_DELETE_ELEM` loop. New `ebpf_seen_stacks_fd` in executor.
- **D9**: New `RecordAnamnesisBonus(op, cluster, multiplier)` method in DEzzer. Wired in processResult after Anamnesis assessment. Multipliers: 1.2 (score>=40), 1.5 (shouldFocus), 2.0 (tier<=2).

### Wave 3: Focus Optimization (D21, D26, D27, D10) — DONE

- **D21**: `focusTitles` replaced with hash-based `focusDedup` LRU[uint64, bool]. FNV-64a hash of program bytes with trigger-type prefix stripped.
- **D26**: Per-epoch (5-minute) Focus budget tracking with atomic counters. 30% budget cap per epoch. Existing lifetime cap retained as secondary guardrail.
- **D27**: Cross-trigger dedup inherent from D21 design — same program hash skips regardless of trigger type (UAF, double-free, cross-cache).
- **D10**: Dashboard eBPF stats split into three graph groups: `ebpf-uaf`, `ebpf-heap`, `ebpf-race`.

### Wave 4: Training Pipeline (D25) — DONE

- **D25**: MOCK BiGRU training data collection (1/100 sampling rate, JSONL format), incremental training pipeline, vocabulary expansion, checkpoint management. CLI support via `tools/mock_model/train.py`.

### Wave 5a: Phase 10 Synergy (14a, 14b) — DONE

- **14a**: SyzGPT auto seed generation — spec→syzlang→seed pipeline wired from specgen output to syzgpt injection.
- **14b**: Focus auto-concentrate — `TriggerFocusForGap` callback maps spec gaps to clusters, auto-triggers Focus for highest-gap clusters. Implemented in `syz-manager/ai_triage.go`.

### Deferred to Phase 15

14c (DEzzer saturation targeting), 14d (CrashSpec feedback), 14e (SpecDEzzer MAB), 14f (Anamnesis→spec refinement), 14g (SyzSpec→MOCK BiGRU), 14h (eBPF-Spec runtime reasoning). These require significant new infrastructure not yet available.

---

## Phase 6+: Advanced Improvements Roadmap

**Full roadmap**: See `syzkaller/probe_log/improvement_roadmap.md` for detailed descriptions, paper references, and cost projections.

Based on a survey of 30+ papers (CCS/NDSS/ASPLOS/USENIX 2022-2026), 39 applicable techniques were identified and prioritized into 7 phases:

| Phase | Focus | Timeline | Key Techniques | Expected Impact | Status |
|-------|-------|----------|----------------|-----------------|--------|
| 6 | AI Cost Optimization + Scheduling | Week 1 | Batch API, Prompt Caching, Tiered Routing, T-Scheduler, SyzMini, DEzzer | **-80% API cost**, better scheduling | **DONE** |
| 7 | Core Detection Enhancement | Week 2-3 | SyzGPT (DRAG), CountDown (refcount), Cross-cache, Privilege escalation, GPTrace | **+323% vuln detection**, +66% UAF | **DONE** |
| 8 | Mutation & Coverage Innovation | Week 3-4 | Write-to-freed, Op-pair TS, Multi-obj MAB, MOCK BiGRU, Cluster TS, Effective Component | **+3-12% coverage**, 2-3x high-risk bugs | **DONE** |
| 9 | Advanced Coverage & Detection | Month 2 | KBinCov, Page-level UAF, Context-sensitive, FD, Anamnesis | **+87% binary coverage** | **DONE** |
| 10 | Spec Auto-Generation | Month 2-3 | DeepSeek spec generation, SyzGPT seeds | **+13-18% coverage**, new syscalls | **DONE** |
| 11 | Concurrency & Performance | Month 3 | LACE, MI scheduling, LinUCB, BayesOpt | **+38% coverage**, race conditions | **DONE** |
| 12 | Comprehensive Performance Tuning | Month 3+ | DEzzer precision, BO refinement, eBPF tuning | **Systematic optimization** | **DONE** |
| 14 | Cross-Phase Synergy | Month 3+ | DEzzer-Focus-eBPF-SyzGPT-Anamnesis integration | **Cross-subsystem optimization** | **DONE** |

### Cost-incurring techniques (require API budget)
- SyzGPT seed generation (+$0.10-0.50/day)
- GPTrace embedding dedup (+$0.01-0.05/day)
- Anamnesis exploit assessment (+$0.50-3.00/day)
- KernelGPT/SyzForge spec generation (+$0.50-2.00/run)

### Non-cost techniques (pure code changes)
- All scheduling improvements (T-Scheduler, DEzzer, MobFuzz multi-obj)
- All eBPF extensions (refcount, cross-cache, page-level, FD, privilege escalation, write-to-freed)
- Mutation improvements (MOCK BiGRU, Op-pair TS, Cluster TS, Effective Component, SyzMini)
- Coverage extensions (KBinCov, context-sensitive)
- Concurrency testing (LACE, ACTOR)

## Related Research

| Paper | Venue | Relevance |
|-------|-------|-----------|
| SyzGPT | ISSTA 2025 | Dependency-based RAG, +323% vuln detection — Phase 7 |
| CountDown | CCS 2024 | Refcount-guided UAF, +66.1% UAFs — Phase 7 |
| MOCK | NDSS 2024 | Context-aware BiGRU mutation, +3-12% coverage avg — Phase 8d |
| MuoFuzz | FuzzBench 2024 | Operator-pair sequence learning — Phase 8b |
| MobFuzz | NDSS 2022 | Multi-objective MAB, 3x bugs (user-space, adapted) — Phase 8c |
| SeamFuzz | ICSE 2023 | Per-cluster Thompson Sampling — Phase 8e |
| SeqFuzz | Inscrypt 2025 | Effective component inference (lightweight adaptation) — Phase 8f |
| SyzAgent | 2025 | LLM choice table updates — Phase 3 enhancement |
| SyzMutateX | DMIT 2025 | LLM-driven mutation + UCB energy, +15.8% coverage — Future |
| Snowplow | ASPLOS 2025 | ML-guided mutation (Google DeepMind), 4.8x speedup — Phase 12 |
| KernelGPT | ASPLOS 2025 | LLM spec generation, 24 bugs, 11 CVEs — Phase 10 |
| GPTrace | ICSE 2026 | LLM embedding crash dedup — Phase 7 |
| KBinCov | CCS 2024 | Binary coverage, +87% — Phase 9 |
| SyzMini | ATC 2025 | Minimization optimization, -60.7% cost — Phase 6 |
| LACE | 2025 | eBPF sched_ext concurrency, +38% coverage — Phase 11 |
| Anamnesis | 2026 | LLM exploit generation, ~$30/exploit — Phase 9 |
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
| `executor/ebpf/probe_ebpf.bpf.c` | eBPF heap monitor + write-to-freed (Phase 5/7/8a, unified) |
| `pkg/fuzzer/dezzer.go` | DEzzer TS+DE optimizer (pair/cluster/meta-bandit) |
| `pkg/aitriage/specgen.go` | AI spec generation engine (Phase 10) |
| `pkg/fuzzer/schedts.go` | LACE schedule-aware timing (Phase 11) |
| `pkg/corpus/mi.go` | MI seed scheduling (Phase 11) |
| `pkg/fuzzer/linucb.go` | LinUCB contextual bandit (Phase 11) |
| `pkg/fuzzer/bayesopt.go` | Bayesian Optimization (Phase 11/12) |
| `pkg/fuzzer/lru.go` | Generic LRU cache implementation |
| `syz-manager/syzgpt.go` | SyzGPT seed generation manager |
| `syz-manager/ai_triage.go` | AI triage manager integration |
| `tools/mock_model/` | MOCK BiGRU model service (Python) — Phase 8d |
| `tools/syz-ebpf-loader/main.go` | BPF loader binary (Go) |
| `pkg/flatrpc/flatrpc.fbs` | FlatBuffers RPC schema |

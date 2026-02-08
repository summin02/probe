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
|  [Phase 3] AI Triage + Focus Guide                    |
|    - Claude Haiku 4.5 for crash analysis              |
|    - Mutation strategy suggestions for Focus Mode     |
|    - Group-level analysis (not per-crash)             |
|    - Post-crash analysis (no hot-loop overhead)       |
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
  - **Tier 2 (Important)**: OOB variants, KFENCEInvalidFree, NullPtrDerefBUG
  - **Tier 3 (Low)**: WARNING, LOCKDEP, MemoryLeak, Hang, KCSAN
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

## Phase 3: AI Triage + Focus Guide

**Goal**: Use LLM for crash exploitability analysis and Focus Mode mutation strategy.

**Model**: Claude Haiku 4.5 (via Anthropic API)
- Rationale: Crash report analysis is structured text processing — small, fast model is sufficient
- Managed by same provider as development tools (Anthropic) for convenience
- Cost is negligible after dedup pipeline reduces to ~3-5 groups/day

**Application points** (no hot-loop overhead):

### 3a. Crash Exploitability Analysis (Group-Level)
```
Crash group detected → Group representative + all variant programs sent to LLM
  → "This UAF in nft_set_elem can be exploited via
     same-slab reallocation, privilege escalation possible.
     Variant B (write path) is most dangerous.
     Variant D's free path combined with B's write
     could yield a more reliable exploit."
  → Exploitability score + reasoning
  → Informs Focus Mode entry decision + which variant to prioritize
```

### 3b. Focus Mode Strategy
```
Focus Mode entry → crash program + context sent to LLM
  → "To deepen this UAF:
     1. Add ioctl(SET_FLAG) before close()
     2. Try buffer sizes at PAGE_SIZE multiples
     3. Add concurrent read() from another thread"
  → Mutation hints fed to focusJob
```

### 3c. Cost Estimate

| Scenario | LLM Calls/Day | Monthly Cost (Haiku 4.5) |
|----------|---------------|--------------------------|
| Low volume | 3-5 groups | ~$0.80 |
| Medium volume | 10-15 groups | ~$2.50 |
| High volume | 30-50 groups | ~$8.00 |

Input per call: ~1,500 tokens (KASAN report + stack trace + variant list)
Output per call: ~750 tokens (analysis + score + strategy)

**Modification targets**:
- New module in `pkg/` or `syz-manager/` for LLM integration
- Focus Mode job to accept external mutation hints

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

## Phase 5: eBPF Runtime Monitor

**Goal**: Real-time kernel heap state tracking for exploitability assessment.

**Constraint**: Runs inside Guest VM, attaches to existing kernel functions via kprobes/tracepoints. NO kernel source modification.

### Monitoring targets
- `kprobe/kmalloc`, `kprobe/kfree` — track slab object lifecycle
- `kprobe/copy_from_user`, `kprobe/copy_to_user` — detect OOB access patterns
- slab allocator tracepoints — cache reuse detection

### Feedback loop
```
eBPF detects:
  "Object freed, then same slab cache reallocated 42us later"
  → High exploitability signal
  → Fed back to fuzzer as priority signal

eBPF detects:
  "Write to reallocated object from different context"
  → Critical signal → intensify Focus Mode

eBPF detects:
  "Free without reallocation, read-only access"
  → Low exploitability → deprioritize
```

**Modification targets**:
- New eBPF module (BPF C programs + loader)
- `executor/` — integration with syz-executor in Guest VM
- `pkg/fuzzer/fuzzer.go` — `signalPrio()` extended with eBPF signals

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
| 5 | eBPF Runtime Monitor | High | Real-time exploitability feedback | Phase 2 (needs Focus Mode feedback loop) |

**Critical path**: Phase 1 → Phase 2 → Phase 3 (sequential dependency)
**Parallel track**: Phase 4 can start any time independently

## Related Research

| Paper | Venue | Relevance |
|-------|-------|-----------|
| CountDown | CCS 2024 | UAF-specific fuzzing (refcount-based), 66.1% more UAFs — Phase 4 reference |
| FUZE | USENIX Sec 2018 | Kernel UAF exploit generation automation — Phase 5 exploitability criteria |
| ACTOR | USENIX Sec 2023 | Action-based fuzzing (alloc/free actions), 41 unknown bugs — Phase 4 reference |
| SyzScope | USENIX Sec 2022 | 15% of "low-risk" bugs are actually high-risk — Phase 1+2 motivation |
| GREBE | IEEE S&P 2022 | Turned 6 "unexploitable" bugs into arbitrary code execution — Phase 2 variant discovery |
| SYZVEGAS | USENIX Sec 2021 | RL-based seed scheduling, 38.7% coverage improvement — Phase 2 scheduling reference |
| HEALER | SOSP 2021 | Syscall relation learning, 28% coverage improvement — Phase 4 dependency mutations |
| KernelGPT | ASPLOS 2025 | LLM for syscall description generation, 24 new bugs, 11 CVEs — Phase 3+4 LLM usage |

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

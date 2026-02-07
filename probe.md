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

## Phase 2: Focus Mode

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
          +-- High severity → FOCUS MODE
                |
                +-- 1. Intensive mutation of crash program
                |     +-- Syscall argument micro-variations
                |     +-- Call ordering/timing permutations
                |     +-- Related syscall substitution
                |     +-- UAF: vary free↔reuse gap
                |     +-- OOB: explore size boundaries
                |
                +-- 2. Variant discovery & combination
                |     +-- Upgrade read-UAF → write-UAF
                |     +-- Expand 1-byte OOB → larger OOB
                |     +-- Find different vulns in same code path
                |     +-- Cross-combine variants from same group
                |     |     (e.g., Variant D's free path
                |     |      + Variant B's write pattern)
                |
                +-- 3. Exit on diminishing returns
                      +-- N consecutive iterations with no new findings
```

**Modification targets**:
- `pkg/fuzzer/job.go` — add `focusJob` type
- `pkg/fuzzer/fuzzer.go` — add `focusQueue` with high priority

**Queue priority** (updated):
```
1. triageCandidateQueue
2. candidateQueue
3. triageQueue
4. focusQueue            ← NEW: high-severity crash intensive mutation
5. smashQueue
6. genFuzz
```

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

## Phase 4: UAF/OOB Mutation Engine

**Goal**: Add mutation strategies specifically designed to trigger UAF and OOB.

**Modification targets**:
- `prog/mutation.go` — new mutation types + weight adjustments
- `prog/rand.go` — boundary value generation
- `sys/linux/*.txt` — enhanced syscall descriptions

### 4a. UAF-Targeted Mutations
- **Resource lifecycle mutation**: insert free → reuse sequences
  - `open/socket/mmap` → use → `close/munmap` → reuse same fd/ptr
- **Timing mutation**: vary number of calls between free and reuse
- New weight in `MutateOpts`: `UAFPatternWeight`

### 4b. OOB-Targeted Mutations
- **Boundary value injection**: prioritize 0, -1, PAGE_SIZE-1, PAGE_SIZE+1, INT_MAX for size/offset args
- **LenType priority boost**: raise from 1.0 (current) to higher — length fields are key OOB triggers
- **Buffer size mismatch**: deliberately create inconsistency between declared and actual buffer sizes
- Add OOB-specific values to `specialInts` in `prog/rand.go`

### 4c. Enhanced Syscall Descriptions
Focus on interfaces with complex memory management:
- `sys/linux/uffd.txt` (currently 95 lines) — expand with fault-timing patterns
- `sys/linux/io_uring.txt` — add deeper op-specific lifecycle descriptions
- netfilter/nftables object chaining patterns

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
| 2 | Focus Mode | Medium | Deep exploitation of high-severity findings | Phase 1 (needs severity tiers) |
| 3 | AI Triage (Claude Haiku 4.5) | Medium | Smart group-level crash analysis | Phase 1 (needs dedup groups), Phase 2 (needs Focus Mode) |
| 4 | UAF/OOB Mutation Engine | Medium-High | Higher vuln discovery rate | None (can parallel with 2-3) |
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

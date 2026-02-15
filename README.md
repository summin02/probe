# PROBE

**Exploit-oriented kernel fuzzer** built on top of Google's [syzkaller](https://github.com/google/syzkaller).

PROBE transforms syzkaller from a general-purpose coverage-guided fuzzer into one that actively hunts for **exploitable** vulnerabilities (UAF, OOB, double-free, privilege escalation) using eBPF runtime monitoring, AI-guided analysis, and adaptive mutation scheduling.

## Key Features

### eBPF Runtime Monitor
- **Slab lifecycle tracking** via tracepoint/kprobe hooks (`kfree`, `kmalloc`, `commit_creds`, `kmem_cache_free`, `_copy_from_user`)
- Real-time detection of: slab reuse, rapid reuse (<100us), double-free, cross-cache reallocation, privilege escalation (uid 0 transition), write-to-freed
- Per-execution **UAF exploitability score** (0-100) fed back to fuzzer
- CO-RE (Compile Once, Run Everywhere) portable kprobes via vmlinux.h
- Zero kernel source modification -- attaches to existing kernel interfaces

### AI-Guided Fuzzing
- Multi-provider LLM integration (Anthropic Claude / OpenAI)
- Crash exploitability scoring and classification (0-100, 5 criteria)
- Adaptive fuzzing strategy: syscall weight tuning, seed generation, mutation hints
- GPTrace embedding-based crash deduplication
- SyzGPT dependency-aware seed generation (DRAG pattern)
- Web dashboard with cost tracking (USD/KRW)
- Batch API + prompt caching for cost optimization

### Focus Mode
- High-severity crash triggers intensive mutation (300 iterations vs 25)
- Automatic diminishing-returns exit (50 consecutive no-progress iterations)
- Fault injection integration for error-path UAF discovery
- Concurrency-limited queue with priority scheduling

### Crash Filtering & Deduplication
- 3-tier severity classification (Critical / Important / Stats-only)
- Group-based deduplication preserving variant diversity
- Same crash point with different trigger paths = different exploit potential

### Adaptive Mutation Scheduling
- **DEzzer**: Hybrid Thompson Sampling + Differential Evolution optimizer
- Per-source coverage tracking (mutate / smash / focus)
- Data-driven mutation operator weight adjustment

### Exploit-Oriented Hardening
- `kasan_multi_shot` for multi-report KASAN execution
- OOB boundary mutation (off-by-one/two, double size, page overshoot)
- LenType priority boost for size-related mutations
- Hints OOB boundary extension (boundary +/- 1, +/- 2)

## Architecture

```
Host (syz-manager)                Guest VM (QEMU)
+--------------------------+      +----------------------------------+
| Manager                  |      | eBPF Programs (pinned)           |
|  - AI Triage (LLM)      |      |  kfree/kmalloc tracepoints       |
|  - Crash dedup/grouping  |      |  commit_creds kprobe             |
|  - Focus Mode scheduler  |      |  kmem_cache_free kprobe          |
|  - Web dashboard         |      |  _copy_from_user kprobe          |
|  - DEzzer optimizer      |      |  metrics + freed_objects maps    |
+--------------------------+      +----------------------------------+
         |                                    |
         v                                    v
+--------------------------+      +----------------------------------+
| Fuzzer                   |      | syz-executor                     |
|  - Coverage feedback     |      |  Read eBPF metrics per-exec      |
|  - UAF/OOB scoring       |      |  UAF score computation           |
|  - Focus triggering      |      |  FlatBuffers serialization       |
|  - TS weight selection   |      |  Syscall execution               |
+--------------------------+      +----------------------------------+
```

## Requirements

### System
- **OS**: Ubuntu/Debian (tested on Ubuntu 24.04+)
- **Architecture**: x86_64
- **RAM**: 16GB+ recommended (10GB allocated to QEMU VMs)
- **Disk**: 50GB+ free space
- **Virtualization**: KVM support (`/dev/kvm`)

### Software
- GCC, G++, Make, Flex, Bison
- Clang, LLVM, LLD (for eBPF compilation)
- QEMU (`qemu-system-x86`, `qemu-utils`, `qemu-kvm`)
- Go 1.24+ (installed automatically by setup script)
- Python 3 (for rootfs image creation)
- `debootstrap` (for Debian rootfs)
- `libelf-dev`, `libssl-dev`, `libncurses-dev`, `dwarves`

### Optional
- **LLM API key** (Anthropic or OpenAI) for AI-guided fuzzing
- **eBPF**: Requires `CONFIG_BPF=y`, `CONFIG_KPROBES=y` in target kernel

## Quick Start

```bash
# 1. Clone
git clone https://github.com/xmin-02/probe.git
cd probe

# 2. Full automated setup (kernel build + QEMU image + syzkaller + config)
sudo ./build_probe.sh

# 3. Run the fuzzer
cd syzkaller/setup && ./probe.sh
# Or: sudo syzkaller/bin/syz-manager -config syzkaller/setup/probe.cfg
```

The web dashboard is available at `http://127.0.0.1:56741`.

### AI Configuration (Optional)

Add to `syzkaller/setup/probe.cfg`:
```json
{
    "ai_triage": {
        "model": "claude-sonnet-4-5-20250929",
        "api_key": "your-api-key-here"
    }
}
```

Without `ai_triage` config, PROBE runs with all other features enabled -- AI is gracefully disabled.

### Kernel Config Requirements

The target kernel should be built with:
```
CONFIG_KASAN=y              # Kernel Address Sanitizer (UAF/OOB detection)
CONFIG_KASAN_INLINE=y       # Inline instrumentation (faster)
CONFIG_DEBUG_INFO=y          # Debug symbols for crash reports
CONFIG_KCOV=y               # Coverage guidance
CONFIG_BPF=y                # eBPF support
CONFIG_KPROBES=y            # kprobe-based eBPF programs
```

Recommended kernel cmdline (set in `probe.cfg`):
```
kasan_multi_shot panic_on_warn=1 ftrace_dump_on_oops=orig_cpu
```

## Build Commands

```bash
# Go environment (if not using build_probe.sh)
export GOROOT=$PWD/goroot GOPATH=$PWD/gopath PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Build syzkaller
cd syzkaller
make              # All components
make host         # Host tools only (syz-manager, etc.)
make executor     # Executor only (C++)

# Run tests
make test         # All tests
go test ./pkg/fuzzer/...   # Specific package
```

## Implementation Status

| Feature | Description | Status |
|---------|------------|--------|
| Crash Filtering & Dedup | 3-tier severity, group-based dedup | Done |
| Focus Mode | Intensive mutation on high-severity crashes | Done |
| AI-Guided Fuzzing | LLM crash analysis, strategy, seed generation | Done |
| Exploit-Oriented Hardening | KASAN multi-shot, OOB mutation, fault injection | Done |
| eBPF Runtime Monitor | Slab tracking, UAF/double-free/cross-cache detection | Done |
| AI Cost Optimization | Batch API, prompt caching, tiered routing | Done |
| DEzzer Scheduler | Thompson Sampling + DE hybrid optimizer | Done |
| CO-RE Detection | Portable kprobes (commit_creds, kmem_cache_free) | Done |
| SyzGPT Seeds | Dependency-aware seed generation via LLM | Done |
| GPTrace Dedup | Embedding-based crash cluster deduplication | Done |
| Write-to-freed Detection | copy_from_user kprobe for freed slab writes | Done |
| Operator-Pair TS | Conditional mutation operator probabilities | Planned |
| Cluster TS | Per-subsystem mutation weights | Planned |
| Effective Component | Crash-essential syscall inference via ablation | Planned |
| Context-Aware Mutation | BiGRU language model for syscall dependencies | Planned |
| Multi-Objective Optimization | Meta-bandit (coverage + memory safety + priv-esc) | Planned |
| Binary Coverage | KBinCov binary-level coverage tracking | Planned |
| Syscall Spec Generation | LLM-driven syzlang spec auto-generation | Planned |
| Concurrency Testing | eBPF sched_ext for race condition detection | Planned |

Full technical plan: [`probe.md`](probe.md) (English) / [`probe_kor.md`](probe_kor.md) (Korean)

## Web Dashboard

PROBE extends syzkaller's web interface with:

- **Crash table**: AI exploitability score column (color-coded)
- **`/ai`**: AI dashboard -- analysis summary, cost tracking, real-time console
- **`/ai/triage`**: Crash exploitability analysis, strategy details
- **`/ai/embeddings`**: GPTrace crash dedup clusters
- **`/ai/analytics`**: Cost trends, score distribution charts
- **eBPF stats**: `ebpf reuses`, `ebpf uaf`, `ebpf double-free`, `ebpf cross-cache`, `ebpf write-to-freed`, `ebpf priv-esc`

## Project Structure

```
build_probe.sh              # Automated full-stack setup script
probe.md / probe_kor.md     # Technical plan (EN/KR)
syzkaller/                  # Modified syzkaller (all PROBE changes here)
  executor/
    executor.cc             # Syscall executor + eBPF integration
    ebpf/
      probe_ebpf.bpf.c     # eBPF programs (tracepoint + kprobe)
      probe_ebpf.bpf.h     # Shared metrics structure
  pkg/
    aitriage/               # AI-guided fuzzing (LLM client, prompts)
    fuzzer/
      fuzzer.go             # Fuzzing loop + eBPF feedback
      job.go                # Focus mode, smash, triage jobs
      dezzer.go             # DEzzer TS+DE optimizer
      stats.go              # Dashboard statistics
    flatrpc/                # FlatBuffers RPC (executor <-> manager)
    manager/                # Manager business logic
  tools/
    syz-ebpf-loader/        # BPF loader for VM deployment
  setup/
    probe.cfg               # Fuzzer configuration
```

## Related Research

PROBE integrates and adapts techniques from the following kernel fuzzing and security research:

| Paper | Venue | Key Contribution |
|-------|-------|------------------|
| SyzScope | USENIX Security 2022 | 15% of "low-risk" bugs are actually high-risk; exploit-oriented crash re-evaluation |
| GREBE | IEEE S&P 2022 | 6 "unexploitable" bugs → arbitrary code execution; variant diversity motivation |
| MobFuzz | NDSS 2022 | Multi-objective MAB optimization, 3x bug discovery (user-space, adapted for kernel) |
| ACTOR | USENIX Security 2023 | Concurrency-aware kernel testing framework |
| SeamFuzz | ICSE 2023 | Per-cluster Thompson Sampling for mutation scheduling |
| CountDown | CCS 2024 | Refcount-guided UAF detection, +66.1% UAF discovery |
| KBinCov | CCS 2024 | Binary-level coverage tracking, +87% coverage |
| MOCK | NDSS 2024 | Context-aware BiGRU mutation model, +3-12% coverage |
| MuoFuzz | FuzzBench 2024 | Operator-pair sequence learning for mutation |
| SLUBStick | USENIX Security 2024 | Cross-cache attacks with 99% success rate |
| SyzGPT | ISSTA 2025 | Dependency-based RAG seed generation, +323% vulnerability detection |
| Snowplow | ASPLOS 2025 | ML-guided mutation scheduling (Google DeepMind), 4.8x speedup |
| KernelGPT | ASPLOS 2025 | LLM-driven syscall spec generation, 24 bugs, 11 CVEs |
| SyzMini | USENIX ATC 2025 | Program minimization optimization, -60.7% cost |
| SyzAgent | 2025 | LLM-driven choice table updates for syscall selection |
| SyzMutateX | DMIT 2025 | LLM-driven mutation + UCB energy scheduling, +15.8% coverage |
| LACE | 2025 | eBPF sched_ext concurrency testing, +38% coverage |
| SeqFuzz | Inscrypt 2025 | Effective component inference via dynamic ablation |
| SyzForge | 2025 | Automated syzlang specification synthesis |
| SyzSpec | 2025 | Syscall specification inference from kernel source |
| OZZ | 2025 | Order-aware concurrency fuzzing for race conditions |
| GPTrace | ICSE 2026 | LLM embedding-based crash deduplication |
| Anamnesis | 2026 | LLM-driven exploit generation and assessment |
| Big Sleep | 2026 | Google DeepMind automated vulnerability research |

## Constraints

- All modifications are within the `syzkaller/` directory only
- Linux kernel source is never modified (kernel `.config` changes are allowed)
- eBPF programs attach to existing kernel interfaces (tracepoints, kprobes)

## License

Based on [syzkaller](https://github.com/google/syzkaller) (Apache 2.0).

---

# PROBE (한국어)

Google [syzkaller](https://github.com/google/syzkaller) 기반의 **익스플로잇 지향 커널 퍼저**.

PROBE는 syzkaller를 범용 커버리지 기반 퍼저에서, eBPF 런타임 모니터링과 AI 분석, 적응형 뮤테이션 스케줄링을 활용하여 **실제 익스플로잇 가능한** 취약점(UAF, OOB, double-free, 권한 상승)을 적극적으로 탐지하는 퍼저로 확장합니다.

## 주요 기능

### eBPF 런타임 모니터
- tracepoint/kprobe 후킹(`kfree`, `kmalloc`, `commit_creds`, `kmem_cache_free`, `_copy_from_user`)을 통한 **slab 생명주기 추적**
- 실시간 탐지: slab 재사용, 빠른 재사용(<100us), double-free, cross-cache 재할당, 권한 상승(uid 0 전환), write-to-freed
- 실행 단위 **UAF 익스플로잇 가능성 점수** (0-100)를 퍼저에 피드백
- CO-RE (Compile Once, Run Everywhere) vmlinux.h 기반 포터블 kprobe
- 커널 소스 수정 없음 -- 기존 커널 인터페이스에 어태치

### AI 기반 퍼징
- 멀티 프로바이더 LLM 연동 (Anthropic Claude / OpenAI)
- 크래시 익스플로잇 가능성 점수화 및 분류 (0-100, 5개 기준)
- 적응형 퍼징 전략: 시스콜 가중치 조정, 시드 생성, 뮤테이션 힌트
- GPTrace 임베딩 기반 크래시 중복 제거
- SyzGPT 의존성 기반 시드 생성 (DRAG 패턴)
- 비용 추적 웹 대시보드 (USD/KRW)
- Batch API + 프롬프트 캐싱으로 비용 최적화

### Focus Mode
- 고위험 크래시 발견 시 집중 뮤테이션 (25회 → 300회)
- 자동 수확체감 종료 (50회 연속 진전 없으면 조기 종료)
- 에러 경로 UAF 탐색을 위한 fault injection 연동
- 동시성 제한 큐 + 우선순위 스케줄링

### 크래시 필터링 & 중복 제거
- 3단계 심각도 분류 (Critical / Important / Stats-only)
- 변형 다양성을 보존하는 그룹 기반 중복 제거
- 동일 크래시 지점이라도 트리거 경로가 다르면 = 다른 익스플로잇 가능성

### 적응형 뮤테이션 스케줄링
- **DEzzer**: Thompson Sampling + Differential Evolution 하이브리드 옵티마이저
- 소스별 커버리지 추적 (mutate / smash / focus)
- 데이터 기반 뮤테이션 연산자 가중치 조정

### 익스플로잇 지향 강화
- `kasan_multi_shot`으로 다중 KASAN 리포트 실행
- OOB 경계 뮤테이션 (off-by-one/two, 2배 크기, 페이지 오버슈트)
- LenType 우선순위 강화로 크기 관련 뮤테이션 증가
- Hints OOB 경계 확장 (경계값 +/- 1, +/- 2)

## 아키텍처

```
호스트 (syz-manager)               게스트 VM (QEMU)
+--------------------------+      +----------------------------------+
| Manager                  |      | eBPF 프로그램 (pinned)            |
|  - AI Triage (LLM)      |      |  kfree/kmalloc tracepoint        |
|  - 크래시 중복제거/그룹핑   |      |  commit_creds kprobe             |
|  - Focus Mode 스케줄러    |      |  kmem_cache_free kprobe          |
|  - 웹 대시보드            |      |  _copy_from_user kprobe          |
|  - DEzzer 옵티마이저      |      |  metrics + freed_objects 맵      |
+--------------------------+      +----------------------------------+
         |                                    |
         v                                    v
+--------------------------+      +----------------------------------+
| Fuzzer                   |      | syz-executor                     |
|  - 커버리지 피드백         |      |  eBPF 메트릭 실행별 읽기          |
|  - UAF/OOB 점수화         |      |  UAF 점수 계산                   |
|  - Focus 트리거           |      |  FlatBuffers 직렬화              |
|  - TS 가중치 선택          |      |  시스콜 실행                     |
+--------------------------+      +----------------------------------+
```

## 요구사항

### 시스템
- **OS**: Ubuntu/Debian (Ubuntu 24.04+ 에서 테스트됨)
- **아키텍처**: x86_64
- **RAM**: 16GB 이상 권장 (QEMU VM에 10GB 할당)
- **디스크**: 50GB 이상 여유 공간
- **가상화**: KVM 지원 (`/dev/kvm`)

### 소프트웨어
- GCC, G++, Make, Flex, Bison
- Clang, LLVM, LLD (eBPF 컴파일용)
- QEMU (`qemu-system-x86`, `qemu-utils`, `qemu-kvm`)
- Go 1.24+ (설치 스크립트가 자동 설치)
- Python 3 (rootfs 이미지 생성용)
- `debootstrap` (Debian rootfs용)
- `libelf-dev`, `libssl-dev`, `libncurses-dev`, `dwarves`

### 선택사항
- **LLM API 키** (Anthropic 또는 OpenAI) -- AI 기반 퍼징용
- **eBPF**: 대상 커널에서 `CONFIG_BPF=y`, `CONFIG_KPROBES=y` 필요

## 빠른 시작

```bash
# 1. 클론
git clone https://github.com/xmin-02/probe.git
cd probe

# 2. 전체 자동 설치 (커널 빌드 + QEMU 이미지 + syzkaller + 설정)
sudo ./build_probe.sh

# 3. 퍼저 실행
cd syzkaller/setup && ./probe.sh
# 또는: sudo syzkaller/bin/syz-manager -config syzkaller/setup/probe.cfg
```

웹 대시보드: `http://127.0.0.1:56741`

### AI 설정 (선택사항)

`syzkaller/setup/probe.cfg`에 추가:
```json
{
    "ai_triage": {
        "model": "claude-sonnet-4-5-20250929",
        "api_key": "your-api-key-here"
    }
}
```

`ai_triage` 설정이 없으면 AI 기능만 비활성화되고 나머지 기능은 정상 작동합니다.

### 커널 설정 요구사항

대상 커널 빌드 시 필요한 옵션:
```
CONFIG_KASAN=y              # 커널 주소 새니타이저 (UAF/OOB 탐지)
CONFIG_KASAN_INLINE=y       # 인라인 계측 (더 빠름)
CONFIG_DEBUG_INFO=y          # 크래시 리포트용 디버그 심볼
CONFIG_KCOV=y               # 커버리지 가이던스
CONFIG_BPF=y                # eBPF 지원
CONFIG_KPROBES=y            # kprobe 기반 eBPF 프로그램
```

권장 커널 cmdline (`probe.cfg`에 설정):
```
kasan_multi_shot panic_on_warn=1 ftrace_dump_on_oops=orig_cpu
```

## 빌드 명령어

```bash
# Go 환경 설정 (build_probe.sh를 사용하지 않는 경우)
export GOROOT=$PWD/goroot GOPATH=$PWD/gopath PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# syzkaller 빌드
cd syzkaller
make              # 전체 컴포넌트
make host         # 호스트 도구만 (syz-manager 등)
make executor     # executor만 (C++)

# 테스트 실행
make test         # 전체 테스트
go test ./pkg/fuzzer/...   # 특정 패키지
```

## 구현 현황

| 기능 | 설명 | 상태 |
|------|------|------|
| 크래시 필터링 & 중복 제거 | 3단계 심각도, 그룹 기반 dedup | 완료 |
| Focus Mode | 고위험 크래시 집중 뮤테이션 | 완료 |
| AI 기반 퍼징 | LLM 크래시 분석, 전략, 시드 생성 | 완료 |
| 익스플로잇 지향 강화 | KASAN multi-shot, OOB 뮤테이션, fault injection | 완료 |
| eBPF 런타임 모니터 | Slab 추적, UAF/double-free/cross-cache 탐지 | 완료 |
| AI 비용 최적화 | Batch API, 프롬프트 캐싱, 단계적 라우팅 | 완료 |
| DEzzer 스케줄러 | Thompson Sampling + DE 하이브리드 옵티마이저 | 완료 |
| CO-RE 탐지 | 포터블 kprobe (commit_creds, kmem_cache_free) | 완료 |
| SyzGPT 시드 | LLM 의존성 기반 시드 생성 | 완료 |
| GPTrace Dedup | 임베딩 기반 크래시 클러스터 중복 제거 | 완료 |
| Write-to-freed 탐지 | copy_from_user kprobe로 freed slab 쓰기 탐지 | 완료 |
| 연산자-쌍 TS | 조건부 뮤테이션 연산자 확률 | 계획됨 |
| 클러스터 TS | 커널 서브시스템별 뮤테이션 가중치 | 계획됨 |
| 유효 컴포넌트 추론 | ablation 기반 크래시 필수 시스콜 식별 | 계획됨 |
| 컨텍스트 인식 뮤테이션 | BiGRU 언어 모델 기반 시스콜 의존성 | 계획됨 |
| 다목적 최적화 | 메타-밴딧 (커버리지 + 메모리 안전 + 권한 상승) | 계획됨 |
| 바이너리 커버리지 | KBinCov 바이너리 레벨 커버리지 추적 | 계획됨 |
| 시스콜 스펙 자동 생성 | LLM 기반 syzlang 스펙 자동 생성 | 계획됨 |
| 동시성 테스트 | eBPF sched_ext 기반 레이스 컨디션 탐지 | 계획됨 |

상세 기술 문서: [`probe.md`](probe.md) (영문) / [`probe_kor.md`](probe_kor.md) (한국어)

## 웹 대시보드

PROBE는 syzkaller 웹 인터페이스를 다음과 같이 확장합니다:

- **크래시 테이블**: AI 익스플로잇 가능성 점수 컬럼 (색상 코드)
- **`/ai`**: AI 대시보드 -- 분석 요약, 비용 추적, 실시간 콘솔
- **`/ai/triage`**: 크래시 익스플로잇 가능성 분석, 전략 상세
- **`/ai/embeddings`**: GPTrace 크래시 중복 제거 클러스터
- **`/ai/analytics`**: 비용 추이, 점수 분포 차트
- **eBPF 통계**: `ebpf reuses`, `ebpf uaf`, `ebpf double-free`, `ebpf cross-cache`, `ebpf write-to-freed`, `ebpf priv-esc`

## 프로젝트 구조

```
build_probe.sh              # 전체 환경 자동 설치 스크립트
probe.md / probe_kor.md     # 기술 문서 (영문/한국어)
syzkaller/                  # 수정된 syzkaller (모든 PROBE 변경사항)
  executor/
    executor.cc             # 시스콜 executor + eBPF 연동
    ebpf/
      probe_ebpf.bpf.c     # eBPF 프로그램 (tracepoint + kprobe)
      probe_ebpf.bpf.h     # 공유 메트릭 구조체
  pkg/
    aitriage/               # AI 기반 퍼징 (LLM 클라이언트, 프롬프트)
    fuzzer/
      fuzzer.go             # 퍼징 루프 + eBPF 피드백
      job.go                # Focus mode, smash, triage 작업
      dezzer.go             # DEzzer TS+DE 옵티마이저
      stats.go              # 대시보드 통계
    flatrpc/                # FlatBuffers RPC (executor <-> manager)
    manager/                # Manager 비즈니스 로직
  tools/
    syz-ebpf-loader/        # VM 배포용 BPF 로더
  setup/
    probe.cfg               # 퍼저 설정 파일
```

## 관련 연구

PROBE는 아래 커널 퍼징 및 보안 연구의 기술을 통합/적용합니다:

| 논문 | 학회 | 주요 기여 |
|------|------|----------|
| SyzScope | USENIX Security 2022 | "저위험" 버그의 15%가 실제로는 고위험; 익스플로잇 관점 크래시 재평가 |
| GREBE | IEEE S&P 2022 | "익스플로잇 불가" 버그 6개 → 임의 코드 실행; 변형 다양성의 중요성 |
| MobFuzz | NDSS 2022 | 다목적 MAB 최적화, 버그 발견 3배 (유저스페이스, 커널 적응) |
| ACTOR | USENIX Security 2023 | 동시성 인식 커널 테스트 프레임워크 |
| SeamFuzz | ICSE 2023 | 클러스터별 Thompson Sampling 뮤테이션 스케줄링 |
| CountDown | CCS 2024 | 참조 카운트 기반 UAF 탐지, UAF 발견 +66.1% |
| KBinCov | CCS 2024 | 바이너리 레벨 커버리지 추적, 커버리지 +87% |
| MOCK | NDSS 2024 | 컨텍스트 인식 BiGRU 뮤테이션 모델, 커버리지 +3-12% |
| MuoFuzz | FuzzBench 2024 | 뮤테이션 연산자-쌍 시퀀스 학습 |
| SLUBStick | USENIX Security 2024 | Cross-cache 공격 99% 성공률 |
| SyzGPT | ISSTA 2025 | 의존성 기반 RAG 시드 생성, 취약점 탐지 +323% |
| Snowplow | ASPLOS 2025 | ML 기반 뮤테이션 스케줄링 (Google DeepMind), 4.8배 속도 향상 |
| KernelGPT | ASPLOS 2025 | LLM 기반 시스콜 스펙 생성, 24개 버그, 11 CVE |
| SyzMini | USENIX ATC 2025 | 프로그램 최소화 최적화, 비용 -60.7% |
| SyzAgent | 2025 | LLM 기반 choice table 업데이트 |
| SyzMutateX | DMIT 2025 | LLM 기반 뮤테이션 + UCB 에너지 스케줄링, 커버리지 +15.8% |
| LACE | 2025 | eBPF sched_ext 동시성 테스트, 커버리지 +38% |
| SeqFuzz | Inscrypt 2025 | 동적 ablation 기반 유효 컴포넌트 추론 |
| SyzForge | 2025 | syzlang 스펙 자동 합성 |
| SyzSpec | 2025 | 커널 소스 기반 시스콜 스펙 추론 |
| OZZ | 2025 | 순서 인식 동시성 퍼징 (레이스 컨디션) |
| GPTrace | ICSE 2026 | LLM 임베딩 기반 크래시 중복 제거 |
| Anamnesis | 2026 | LLM 기반 익스플로잇 생성 및 평가 |
| Big Sleep | 2026 | Google DeepMind 자동화 취약점 연구 |

## 제약 사항

- 모든 수정은 `syzkaller/` 디렉토리 내에서만 수행
- 리눅스 커널 소스는 수정하지 않음 (커널 `.config` 변경은 허용)
- eBPF 프로그램은 기존 커널 인터페이스(tracepoint, kprobe)에 어태치

## 라이선스

[syzkaller](https://github.com/google/syzkaller) 기반 (Apache 2.0).

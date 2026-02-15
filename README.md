# PROBE

**Exploit-oriented kernel fuzzer** built on top of Google's [syzkaller](https://github.com/google/syzkaller).

PROBE transforms syzkaller from a general-purpose coverage-guided fuzzer into one that actively hunts for **exploitable** vulnerabilities (UAF, OOB, double-free, privilege escalation) using eBPF runtime monitoring, AI-guided analysis, and adaptive mutation scheduling.

## Key Features

### eBPF Runtime Monitor (Phase 5/7/8a)
- **Slab lifecycle tracking** via tracepoint/kprobe hooks (`kfree`, `kmalloc`, `commit_creds`, `kmem_cache_free`, `_copy_from_user`)
- Real-time detection of: slab reuse, rapid reuse (<100us), double-free, cross-cache reallocation, privilege escalation (uid 0 transition), write-to-freed
- Per-execution **UAF exploitability score** (0-100) fed back to fuzzer
- Zero kernel source modification -- attaches to existing kernel interfaces

### AI-Guided Fuzzing (Phase 3)
- Multi-provider LLM integration (Anthropic Claude / OpenAI)
- Crash exploitability scoring and classification
- Adaptive fuzzing strategy: syscall weight tuning, seed generation, mutation hints
- GPTrace embedding-based crash deduplication
- SyzGPT dependency-aware seed generation
- Web dashboard with cost tracking (USD/KRW)

### Focus Mode (Phase 2)
- High-severity crash triggers intensive mutation (300 iterations vs 25)
- Automatic diminishing-returns exit (50 consecutive no-progress iterations)
- Fault injection integration for error-path UAF discovery
- Concurrency-limited queue with priority scheduling

### Crash Filtering & Dedup (Phase 1)
- 3-tier severity classification (Critical / Important / Stats-only)
- Group-based deduplication preserving variant diversity
- Same crash point with different trigger paths = different exploit potential

### Adaptive Mutation Scheduling (Phase 6)
- **DEzzer**: Hybrid Thompson Sampling + Differential Evolution optimizer
- Per-source coverage tracking (mutate / smash / focus)
- Data-driven mutation operator weight adjustment

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

| Phase | Description | Status |
|-------|------------|--------|
| 1 | Crash Filtering & Dedup Pipeline | Done |
| 2 | Focus Mode | Done |
| 3 | AI-Guided Fuzzing (LLM integration) | Done |
| 4 | Practical Hardening (KASAN, fault injection, OOB) | Done |
| 5 | eBPF Runtime Monitor | Done |
| 6 | AI Cost Optimization + Data-Driven Scheduling (DEzzer) | Done |
| 7 | Core Detection Enhancement (CO-RE kprobes) | Done |
| 8a | Write-to-freed eBPF Detection | Done |
| 8b-8f | Mutation & Coverage Innovation | Planned |
| 9-12 | Advanced Coverage, Spec Generation, Concurrency | Planned |

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

PROBE integrates techniques from 30+ kernel fuzzing papers:

| Paper | Venue | Technique |
|-------|-------|-----------|
| SyzGPT | ISSTA 2025 | Dependency-based seed generation |
| CountDown | CCS 2024 | Refcount-guided UAF detection |
| GPTrace | ICSE 2026 | LLM embedding crash dedup |
| MobFuzz | NDSS 2022 | Multi-objective optimization |
| SeamFuzz | ICSE 2023 | Per-cluster Thompson Sampling |
| Snowplow | ASPLOS 2025 | ML-guided mutation scheduling |
| KernelGPT | ASPLOS 2025 | LLM syscall spec generation |
| SyzScope | USENIX Sec 2022 | Exploit-oriented crash analysis |

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

### eBPF 런타임 모니터 (Phase 5/7/8a)
- tracepoint/kprobe 후킹(`kfree`, `kmalloc`, `commit_creds`, `kmem_cache_free`, `_copy_from_user`)을 통한 **slab 생명주기 추적**
- 실시간 탐지: slab 재사용, 빠른 재사용(<100us), double-free, cross-cache 재할당, 권한 상승(uid 0 전환), write-to-freed
- 실행 단위 **UAF 익스플로잇 가능성 점수** (0-100)를 퍼저에 피드백
- 커널 소스 수정 없음 -- 기존 커널 인터페이스에 어태치

### AI 기반 퍼징 (Phase 3)
- 멀티 프로바이더 LLM 연동 (Anthropic Claude / OpenAI)
- 크래시 익스플로잇 가능성 점수화 및 분류
- 적응형 퍼징 전략: 시스콜 가중치 조정, 시드 생성, 뮤테이션 힌트
- GPTrace 임베딩 기반 크래시 중복 제거
- SyzGPT 의존성 기반 시드 생성
- 비용 추적 웹 대시보드 (USD/KRW)

### Focus Mode (Phase 2)
- 고위험 크래시 발견 시 집중 뮤테이션 (25회 → 300회)
- 자동 수확체감 종료 (50회 연속 진전 없으면 조기 종료)
- 에러 경로 UAF 탐색을 위한 fault injection 연동
- 동시성 제한 큐 + 우선순위 스케줄링

### 크래시 필터링 & 중복 제거 (Phase 1)
- 3단계 심각도 분류 (Critical / Important / Stats-only)
- 변형 다양성을 보존하는 그룹 기반 중복 제거
- 동일 크래시 지점이라도 트리거 경로가 다르면 = 다른 익스플로잇 가능성

### 적응형 뮤테이션 스케줄링 (Phase 6)
- **DEzzer**: Thompson Sampling + Differential Evolution 하이브리드 옵티마이저
- 소스별 커버리지 추적 (mutate / smash / focus)
- 데이터 기반 뮤테이션 연산자 가중치 조정

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

| Phase | 설명 | 상태 |
|-------|------|------|
| 1 | 크래시 필터링 & 중복 제거 파이프라인 | 완료 |
| 2 | Focus Mode | 완료 |
| 3 | AI 기반 퍼징 (LLM 연동) | 완료 |
| 4 | 실전 강화 (KASAN, fault injection, OOB) | 완료 |
| 5 | eBPF 런타임 모니터 | 완료 |
| 6 | AI 비용 최적화 + 데이터 기반 스케줄링 (DEzzer) | 완료 |
| 7 | 핵심 탐지 강화 (CO-RE kprobe) | 완료 |
| 8a | Write-to-freed eBPF 탐지 | 완료 |
| 8b-8f | 뮤테이션 & 커버리지 혁신 | 계획됨 |
| 9-12 | 고급 커버리지, 스펙 자동생성, 동시성 | 계획됨 |

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

PROBE는 30편 이상의 커널 퍼징 논문 기술을 통합합니다:

| 논문 | 학회 | 기술 |
|------|------|------|
| SyzGPT | ISSTA 2025 | 의존성 기반 시드 생성 |
| CountDown | CCS 2024 | 참조 카운트 기반 UAF 탐지 |
| GPTrace | ICSE 2026 | LLM 임베딩 크래시 중복 제거 |
| MobFuzz | NDSS 2022 | 다목적 최적화 |
| SeamFuzz | ICSE 2023 | 클러스터별 Thompson Sampling |
| Snowplow | ASPLOS 2025 | ML 기반 뮤테이션 스케줄링 |
| KernelGPT | ASPLOS 2025 | LLM 시스콜 스펙 생성 |
| SyzScope | USENIX Sec 2022 | 익스플로잇 지향 크래시 분석 |

## 제약 사항

- 모든 수정은 `syzkaller/` 디렉토리 내에서만 수행
- 리눅스 커널 소스는 수정하지 않음 (커널 `.config` 변경은 허용)
- eBPF 프로그램은 기존 커널 인터페이스(tracepoint, kprobe)에 어태치

## 라이선스

[syzkaller](https://github.com/google/syzkaller) 기반 (Apache 2.0).

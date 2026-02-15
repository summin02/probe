# PROBE — 익스플로잇 지향 커널 퍼징을 위한 커스텀 시즈칼러

## 범위

- **수정 대상**: `syzkaller/` 디렉토리만
- **리눅스 커널 소스**: 절대 수정하지 않음 (커널 .config 변경은 허용)
- **목표**: 시즈칼러를 범용 퍼저에서 실제 익스플로잇 가능한 취약점 발견에 집중하는 퍼저로 전환

## 타겟 취약점 유형

- **UAF (Use-After-Free)**: alloc → use → free → reuse 패턴
- **OOB (Out-of-Bounds)**: 버퍼 크기/오프셋 경계 위반

## 아키텍처 개요

```
+------------------------------------------------------+
|                PROBE 커스텀 시즈칼러                    |
+------------------------------------------------------+
|                                                       |
|  [Phase 1] 크래시 필터링 & 중복 제거 파이프라인         |
|    - Impact score 기반 필터링                          |
|    - 유사 크래시 그룹핑 (삭제가 아닌 그룹화)            |
|    - 그룹 내 변종 다양성 보존                          |
|    - 노이즈 억제 (WARNING, LOCKDEP, INFO_LEAK)         |
|                                                       |
|  [Phase 2] 포커스 모드                                 |
|    - 고위험 크래시 → 집중 뮤테이션 전환                  |
|    - 수백~수천 회 반복 (기존 25회가 아닌)                |
|    - 크래시 유형별 특화 뮤테이션 전략                    |
|    - 그룹 내 변종 간 크로스 조합                        |
|    - 수확 체감 시 자동 복귀                             |
|                                                       |
|  [Phase 3] AI 가이드 퍼징 [완료]                       |
|    - 멀티 프로바이더 LLM (Anthropic + OpenAI)          |
|    - 크래시 익스플로잇 점수화 (0-100)                   |
|    - 퍼징 전략: syscall 가중치, 시드, 포커스            |
|    - /ai 대시보드 + 비용 추적 (USD+KRW)                |
|                                                       |
|  [Phase 4] UAF/OOB 뮤테이션 엔진                       |
|    - UAF 패턴 시퀀스 생성                               |
|    - OOB 경계값 집중 뮤테이션                           |
|    - 커스텀 시즈콜 기술 (uffd, io_uring 등)             |
|                                                       |
|  [Phase 5] eBPF 런타임 모니터                          |
|    - Slab 오브젝트 생명주기 추적 (kprobe 기반)          |
|    - 익스플로잇 가능성 스코어링                         |
|    - 포커스 모드에 실시간 피드백                         |
|    - 커널 소스 수정 불필요 (기존 kprobe/tracepoint 활용) |
|                                                       |
+------------------------------------------------------+
```

## Phase 1: 크래시 필터링 & 중복 제거 파이프라인 [완료]

**목표**: 노이즈 제거 및 크래시 중복 처리, 동시에 변종 다양성 보존.

**현재 문제**: 시즈칼러는 모든 크래시를 동등하게 취급 — WARNING, LOCKDEP, hang, KASAN UAF write 모두 같은 처리를 받음. 중복 크래시가 결과를 범람시킴.

### 1a. 크래시 심각도 등급

**수정 대상**:
- `pkg/report/crash/` — 크래시 유형 분류
- `pkg/manager/` — 크래시 저장 및 리포팅 로직

**구현 방식**:
- `pkg/report/impact_score.go`의 기존 `impactOrder` 랭킹 활용
- manager에 필터링 레이어 추가: impact score가 높은 크래시만 우선 처리
- 크래시 심각도 등급:
  - **Tier 1 (치명적)**: KASANInvalidFree, KASANUseAfterFreeWrite, KASANWrite, KASANUseAfterFreeRead, KASANRead
  - **Tier 2 (중요)**: OOB 변형, KFENCEInvalidFree, NullPtrDerefBUG, Warning, Bug, UBSAN, LockdepBug, AtomicSleep, UnexpectedReboot; 미분류 크래시 유형의 기본값
  - **Tier 3 (통계만)**: LostConnection, SyzFailure, Hang, DoS, MemoryLeak (명시적 목록만)
- Tier 3 처리: **통계만 기록** (로그 없음, 리포트 없음, repro 없음)
  - `tier3-stat.json`에 타이틀 + 카운트만 기록 (예: "WARNING in xxx: 47회")
  - 디스크 부담 없음 — 카운터만 유지
  - 웹 대시보드에서 접힌 상태로 확인 가능
  - 포커스 모드 및 repro 시도 절대 트리거하지 않음

### 1b. 크래시 중복 제거 파이프라인

**핵심 원칙**: 삭제가 아닌 그룹화. 같은 크래시 지점이라도 트리거 경로가 다르면 익스플로잇 가능성이 다름.

```
크래시 발생 (하루 수천 건)
    |
    +-- 1단계: 완전 동일 제거
    |       매칭: 타이틀 + 스택 트레이스 + 트리거 프로그램 해시
    |       100% 동일한 크래시만 제거
    |
    +-- 2단계: 그룹핑 (삭제가 아님)
    |       기준: 같은 스택 트레이스 / 크래시 지점
    |       단, 트리거 프로그램(syscall 시퀀스)이 다르면 별도 보존
    |       → 각 그룹에 다수의 변종 포함
    |
    |       예시: "kfree+0x42에서 UAF" 그룹 (5개 변종)
    |         ├─ 변종 A: close() → read()      (read UAF)
    |         ├─ 변종 B: close() → write()     (write UAF) ← 더 위험
    |         ├─ 변종 C: close() → ioctl()     (ioctl UAF)
    |         ├─ 변종 D: munmap() → read()     (다른 해제 경로)
    |         └─ 변종 E: munmap() → mmap()     (재할당 시도)
    |
    +-- 3단계: Impact score 필터
    |       Tier 3: 통계만 기록 (타이틀 + 카운트), 저장 없음
    |       Tier 1/2: 그룹핑 + 전체 저장으로 진행
    |
    +-- 4단계: AI 분석 (그룹 단위, 크래시 개별이 아닌)
            전송: 그룹 대표 + 모든 변종 트리거 프로그램
            → LLM이 어떤 변종이 가장 익스플로잇 가능한지 판별
            → 변종 다양성 = 포커스 모드에 더 많은 옵션
```

**그룹핑이 중요한 이유**: 같은 크래시 지점 ≠ 같은 익스플로잇 가능성. 같은 위치의 write-UAF와 read-UAF는 익스플로잇 잠재력이 완전히 다름. "중복"을 삭제하면 포커스 모드에 필요한 공격 벡터를 잃게 됨.

**VariantPrograms 제한**: 변종 프로그램 로딩은 `MaxVariants` (100개)로 제한하여 크래시 그룹에 수천 개 변종이 쌓였을 때 과도한 디스크 I/O 방지.

## Phase 2: 포커스 모드 [완료]

**목표**: 고위험 크래시 발견 시 해당 발견을 집중적으로 파고드는 모드로 전환.

**현재 동작**: 크래시 발견 → 트리아지 → 최소화 → smash (25회 뮤테이션) → 다음으로 이동.

**새로운 동작**:
```
일반 모드 (탐색)
    |
    +-- 크래시 감지
          |
          +-- 저위험 → 기존 처리 (25회 smash)
          |
          +-- 고위험 (Tier 1) → 포커스 모드 진입
                |
                +-- 1. 크래시 프로그램 집중 뮤테이션
                |     +-- 300회 반복 (smash의 25회 대비)
                |     +-- 기본 prog.Mutate() 사용 (Phase 4에서 UAF/OOB 특화 추가)
                |
                +-- 2. 수확 체감 시 조기 탈출
                |     +-- 50회 연속 새 커버리지 없으면 조기 종료
                |     +-- max signal 증가 추적으로 진행 상황 감지
                |
                +-- 3. 동시성 제한
                      +-- 동시 실행 최대 1개 focus job
                      +-- 대기 큐: focus 실행 중 최대 8개 후보 대기
                      +-- 완료 시 다음 대기 후보 자동 시작
                      +-- 같은 크래시 타이틀 재포커스 불가
                      +-- Alternate(2): 큐 폴링 2회당 focus 1회
```

**구현 파일**:
- `pkg/fuzzer/job.go` — `focusJob` 타입 (300회 반복, 수확 체감 종료)
- `pkg/fuzzer/fuzzer.go` — `focusQueue`, `AddFocusCandidate()`, focus 상태 관리
- `pkg/fuzzer/cover.go` — `MaxSignalLen()` 진행 감지용
- `pkg/fuzzer/stats.go` — `statJobsFocus`, `statExecFocus`
- `syz-manager/manager.go` — Tier 1 크래시 → 포커스 모드 트리거 브릿지

**큐 우선순위** (구현):
```
1. triageCandidateQueue
2. candidateQueue
3. triageQueue
4. focusQueue (Alternate 2)  ← PROBE: 고위험 크래시 집중 뮤테이션
5. smashQueue (Alternate 3)
6. genFuzz
```

**로그 전략**:
- 진입: `Logf(0)` — `PROBE: focus mode started for 'X' (tier N)`
- 탈출: `Logf(0)` — `PROBE: focus mode ended for 'X' — iters, new_coverage, exit_reason, duration`
- 중간: 로그 없음 (내부 카운터만 추적, 탈출 시 요약 출력)

## Phase 3: AI 가이드 퍼징 — **완료**

**목표**: LLM을 퍼징 전체 과정에 통합 — 크래시 익스플로잇 분석, 커버리지 전략, 시드 생성, 뮤테이션 튜닝, Focus 타겟 추천.

**아키텍처**: 1시간 배치 사이클, 2단계 분석:
- **Step A**: 크래시 분석 (크래시 그룹별 개별 API 호출, 0-100 점수)
- **Step B**: 퍼징 전략 (커버리지+크래시 요약 기반 1회 호출, syscall 가중치/시드/뮤테이션 힌트/포커스 타겟 생성)

**모델**: 설정 가능 (권장: Claude Sonnet 4.5, ~1,810원/일). 멀티 프로바이더 지원 (Anthropic + OpenAI 호환).

**설정** (`probe.cfg`):
```json
"ai_triage": {
    "model": "claude-sonnet-4-5-20250929",
    "api_key": "sk-ant-api03-xxx",
    "max_tier": 2
}
```
프로바이더 자동 감지: `claude-*` → Anthropic, 그 외 → OpenAI.

### 구현 내용

**신규 패키지 `pkg/aitriage/`**:
- `aitriage.go` — 핵심 타입 (TriageResult, StrategyResult, CostTracker), 1시간 배치 루프 Triager
- `client.go` — LLMClient 인터페이스 + Anthropic/OpenAI 구현 (raw net/http, 3회 재시도, 60초 타임아웃)
- `prompt_crash.go` — KASAN 리포트 파서, 크래시 익스플로잇 프롬프트 (5대 기준, JSON 출력)
- `prompt_strategy.go` — FuzzingSnapshot 수집, 전략 프롬프트 (syscall 가중치, 시드, 뮤테이션, 포커스)

**전략 적용**:
- `prog/prio.go`: `ChoiceTable.ApplyWeights()` — 외부 syscall 가중치 보정
- `pkg/fuzzer/fuzzer.go`: `InjectSeed()` — syzkaller 프로그램 텍스트 파싱 후 triage 큐 주입
- `pkg/fuzzer/fuzzer.go`: `ApplyAIWeights()` — ChoiceTable에 가중치 전달
- Focus 타겟 → 고점수 크래시에 `AddFocusCandidate()` 호출

**대시보드** (4탭 레이아웃):
- `main.html`: 크래시 테이블에 AI Score 컬럼 (색상 코딩: 빨강 70+, 노랑 40-69, 초록 0-39)
- `crash.html`: AI 익스플로잇 분석 섹션 (점수, 클래스, 취약점 유형)
- `ai.html`: `/ai` (Dashboard 탭) — 요약 카드 (분석됨, 고위험, 대기, 클러스터, SyzGPT), 3분할 비용 테이블 (Claude LLM / GPT Embedding / 합산), 바로가기 링크, 전체 콘솔 실시간 폴링
- `aitriage.html`: `/ai/triage` (AI Triage 탭) — 액션 버튼 (Analyze/Strategize), 크래시 익스플로잇 테이블, 전략 상세, API 호출 히스토리, 필터 콘솔 (`[Step A/B/C]`)
- `aiembeddings.html`: `/ai/embeddings` (Embeddings 탭) — Embed Now 버튼, 요약 카드, 클러스터/임베딩 테이블, 필터 콘솔 (`[Embeddings]`)
- `aianalytics.html`: `/ai/analytics` (Analytics 탭) — Google Charts (비용, 점수, exploit class, API 호출, 크래시 타임라인), 비용 효율 지표, SyzGPT 성능, 임베딩 분석
- `aicrash.html`: `/ai/crash?id=` — 개별 크래시 상세 분석 (뒤로가기 → `/ai/triage`)
- `common.html`: 네비게이션 바 AI 탭 (`hasPrefix`로 하위 경로 하이라이팅)

**매니저 통합** (`syz-manager/ai_triage.go`):
- Config에서 Triager 초기화, 백그라운드 고루틴 실행
- 콜백: GetCrashes, GetSnapshot, OnTriageResult, OnStrategyResult
- Score >= 70 → 자동 Focus Mode 트리거
- 수동 트리거: POST `/api/ai/analyze`, POST `/api/ai/strategize`

**Graceful Degradation**: `ai_triage` 설정 없음 → triager nil, AI 비활성, `/ai`에 "disabled" 표시, 퍼징 정상.

**운영 개선사항**:
- **Step A 재분석**: 변종 수가 이전 분석 대비 3배가 되면 크래시를 재분석 (예: 5→15 변종), 새로운 트리거 경로 발견에 따른 진화하는 익스플로잇 가능성 반영
- **비용 복구 중복 방지**: 시작 시 triage 결과 파일에서 비용 히스토리 복구할 때 타임스탬프 기반 가드로 이중 카운팅 방지
- **자동 새로고침**: `/ai` 페이지가 LLM 배치 완료 시 자동 새로고침 (running→complete 전환 추적)

### 비용 추정 (24시간, ~126K input + ~58K output 토큰)

| 모델 | 24시간 USD | 24시간 KRW | 비고 |
|------|-----------|-----------|------|
| Claude Sonnet 4.5 | $1.25 | ~1,810원 | 권장 |
| Claude Haiku 4.5 | $0.42 | ~609원 | 가성비 |
| GPT-4o | $0.90 | ~1,305원 | OpenAI |
| GPT-4o-mini | $0.05 | ~73원 | 최저가 |

## Phase 4: Practical Hardening — **완료**

**목표**: Phase 5 전 UAF/OOB 크래시 발견율을 높이기 위한 실용적 개선.

**수정 파일**: `setup/probe.cfg`, `pkg/manager/crash.go`, `pkg/fuzzer/fuzzer.go`, `prog/mutation.go`, `prog/size.go`, `prog/hints.go`

### 4a. kasan_multi_shot + 심각도 에스컬레이션 — **완료**
- 커널 cmdline에서 `oops=panic` 제거, `kasan_multi_shot` 추가
- `escalateCrashType()` 추가: 한 실행에서 여러 KASAN 리포트가 존재할 때 전체 리포트(primary + tail)를 스캔하여 가장 심각한 타입으로 에스컬레이션
- `SaveCrash()`에서 tier 분류 전에 호출

### 4b. Fault Injection × Focus Mode — **완료**
- 고위험 크래시로 Focus Mode가 시작될 때 크래시 프로그램의 각 call에 대해 `faultInjectionJob`도 함께 스폰
- 에러 경로(불완전한 cleanup)가 UAF의 주요 원인
- 기존 `statExecFaultInject` 카운터 재사용, `focusQueue`를 통해 실행

### 4c. Hints OOB 경계 확장 — **완료**
- `prog/hints.go`의 `checkConstArg()`를 확장하여 표준 replacer 뒤에 boundary±1/±2 변형 생성
- 표준 hints는 비교를 통과하는 값을 생성; OOB 변형은 경계 검사를 실패하는 값 생성 (off-by-one/off-by-two)
- `uselessHint` 필터를 적용하여 잘못된 boundary 값 방지

### 4d. LenType 우선순위 상향 + OOB 인식 뮤테이션 — **완료**
- `LenType` 뮤테이션 우선순위를 `0.1 * maxPriority` (6.4)에서 `0.4 * maxPriority` (25.6)로 상향
- `mutateSize()`에 OOB 특화 전략 추가 (20% 확률): off-by-one 상/하, 2배 크기, 0 크기, 페이지 크기 오버슈트
- 실제 버퍼 크기(`assignSizesCall`에서 계산)를 기준으로 사용, `preserve=true`로 재계산 방지

## Phase 5: eBPF 런타임 모니터 — **완료**

**목표**: 익스플로잇 가능성 평가를 위한 실시간 커널 힙 상태 추적.

**제약**: Guest VM 내부에서 실행, tracepoint를 통해 기존 커널 함수에 attach. 커널 소스 수정 없음.

### 아키텍처

```
호스트 (syz-manager)              Guest VM
┌──────────────┐     SCP     ┌──────────────────────────┐
│ bin/          │ ──────────→ │ syz-ebpf-loader          │
│  syz-ebpf-   │             │   probe_ebpf.bpf.o 로드    │
│  loader      │             │   맵을 /sys/fs/bpf에 고정   │
│  probe_ebpf  │             │   tracepoint 연결          │
│  .bpf.o      │             │   종료 (BPF는 커널에 유지)   │
└──────────────┘             └──────────────────────────┘
                                      │
                                      ▼
                             ┌──────────────────────────┐
                             │ 커널 eBPF 프로그램          │
                             │  trace_kfree → freed_objs │
                             │  trace_kmalloc → 재사용 감지│
                             │  metrics 맵 (고정)         │
                             └──────────────────────────┘
                                      │
                                      ▼
                             ┌──────────────────────────┐
                             │ syz-executor              │
                             │  ebpf_init() → 맵 열기     │
                             │  실행당: read+reset        │
                             │  UAF 점수를 FlatBuffers에   │
                             └──────────────────────────┘
                                      │
                                      ▼
                             호스트 (퍼저 피드백)
                             ┌──────────────────────────┐
                             │ processResult()           │
                             │  eBPF 메트릭 → 통계        │
                             │  UAF 점수 ≥ 70 →          │
                             │    포커스 모드 트리거       │
                             └──────────────────────────┘
```

### 5a. BPF C 프로그램 — **완료**
- `executor/ebpf/probe_ebpf.bpf.c` — `tracepoint/kmem/kfree`와 `tracepoint/kmem/kmalloc` 후킹
- LRU 해시 맵 (8192 엔트리)으로 최근 해제된 포인터와 타임스탬프 추적
- Array 맵에 실행당 메트릭 저장: alloc_count, free_count, reuse_count, rapid_reuse_count, min_reuse_delay_ns, double_free_count, size_mismatch_count
- Slab 재사용 (같은 포인터의 free→alloc) 및 빠른 재사용 (< 100μs = UAF 유리 조건) 감지
- **Double-free 탐지**: kfree에서 ptr이 이미 freed_objects에 존재하면 이중 해제 (alloc 없이 두 번 free)
- **Size-mismatch 탐지**: kmalloc에서 `bytes_alloc > 2 × bytes_req && bytes_alloc >= 128`이면 cross-cache/slab 낭비 감지

### 5b. BPF 로더 — **완료**
- `tools/syz-ebpf-loader/main.go` — `cilium/ebpf`를 사용하는 독립 Go 바이너리
- BPF ELF 오브젝트 로드, tracepoint 연결, 맵+링크를 `/sys/fs/bpf/probe/`에 고정
- VM 배포용 정적 바이너리; 셋업 후 종료 (BPF는 커널에 지속)

### 5c. FlatBuffers 스키마 확장 — **완료**
- `pkg/flatrpc/flatrpc.fbs`의 `ProgInfoRaw`에 8개 필드 추가:
  - `ebpf_alloc_count`, `ebpf_free_count`, `ebpf_reuse_count`, `ebpf_rapid_reuse_count` (uint32)
  - `ebpf_min_reuse_ns` (uint64), `ebpf_uaf_score` (uint32)
  - `ebpf_double_free_count` (uint32, VT=26), `ebpf_size_mismatch_count` (uint32, VT=28)
- 하위 호환: 구버전 executor에서는 기본값 0
- flatc 버전 불일치로 재생성 불가하여 `flatrpc.h` (C++) + `flatrpc.go` (Go) 수동 편집

### 5d. Executor C++ 통합 — **완료**
- `executor_linux.h`: `ebpf_init()`으로 고정된 메트릭 맵을 raw `bpf()` syscall로 열기; `BPF_OBJ_GET` 전 `access()` 검사로 맵 미존재 시 무소음 건너뛰기
- `ebpf_read_and_reset()`: 메트릭 읽기 + 다음 실행을 위해 초기화 (원자적)
- `executor.cc`: 시작 시 init (늦은 BPF 배포를 위한 `execute_one()`의 재시도 포함), 실행 전 clear, 자식 프로세스가 `close_fds()` 전에 메트릭을 `OutputData` 공유 메모리에 기록, runner가 `finish_output()`에서 공유 메모리에서 읽기
- UAF 점수 산식: rapid_reuse > 0 (+50), min_delay < 10μs (+30), reuse > 5 (+20), double_free > 0 (=100 강제), size_mismatch > 3 (+10), 최대 100 캡

### 5e. Manager 배포 — **완료**
- Manager가 VM 시작 시 `syz-ebpf-loader` + `probe_ebpf.bpf.o`를 각 VM에 복사
- Executor 시작 전 셸 명령 체인으로 로더 실행
- VM fstab에 bpffs 마운트 추가 (`tools/trixie/etc/fstab`)
- 그레이스풀 디그레이데이션: eBPF 실패 시 executor는 0 메트릭 반환, 퍼징 계속
- **버그 수정 (v1)**: 모든 eBPF 명령 출력을 `/dev/null`로 리다이렉트하여 crash reporter 간섭 방지
- **버그 수정 (v2)**: 근본 원인은 VM 이미지에 bpffs 마운트포인트 부재 + 로더 행(hang) 가능성. 수정: mount 전 `mkdir -p /sys/fs/bpf`, 로더에 `timeout 10`으로 행 방지, 로더 출력을 `/tmp/probe-ebpf.log`에 저장하여 디버깅 가능. VM 이미지 fstab에 bpffs 항목 추가. BPF 헤더에서 커널 6.1.20 호환성을 위해 `accounted` 필드 제거.
- **버그 수정 (v3)**: `executor.cc`에서 `ebpf_init()`이 shmem fd 연산보다 먼저 호출되어, runner가 coverage filter를 제공하지 않을 때 `BPF_OBJ_GET`이 fd 5/6 (`kMaxSignalFd`/`kCoverFilterFd`)을 가로챔. `fcntl()` 검사가 BPF map fd를 shmem fd로 오인하여 모든 VM에서 `mmap` 실패 유발. 수정: executor.cc exec 모드에서 `ebpf_init()` 호출을 모든 shmem fd 연산(`mmap_input`, `mmap_output`, CoverFilter 설정) 이후로 이동. 진단 코드 정리: `shmem.h`에서 `/tmp/shmem-diag.txt` 파일 쓰기 제거, `manager.go`에서 tier3 원시 출력 로깅 제거. `shmem.h`의 개선된 에러 메시지(errno, fd, size 정보 포함)는 유지.
- **버그 수정 (v4)**: Go(manager) 측에서 eBPF 메트릭이 항상 0으로 표시. BPF 프로그램은 데이터를 수집하고 있었음. 근본 원인: `common_linux.h`의 `close_fds()`가 `close_range(3, MAX_FDS, 0)`을 호출하여 BPF map fd를 포함한 fd >= 3 전부 닫음. `finish_output()`의 eBPF 읽기가 다른 프로세스(runner)에서 `close_fds()` 이후에 실행되어 이미 닫힌 fd에 대해 `BPF_MAP_LOOKUP_ELEM`이 실패. 수정: (1) exec 자식 프로세스가 `close_fds()` 전에 eBPF 메트릭을 읽어 `OutputData` 공유 메모리의 atomic 필드에 기록, (2) runner의 `finish_output()`이 `ebpf_read_and_reset()` 직접 호출 대신 공유 메모리에서 읽기, (3) 늦은 BPF 배포를 위해 `execute_one()`에 `ebpf_init()` 재시도 추가, (4) `ebpf_init()`에서 `BPF_OBJ_GET` 전 `access()` 검사 추가. 검증 완료: 첫 실행부터 alloc/free 카운트 비-0 확인.
- **버그 수정 (v5)**: eBPF UAF 점수가 시간이 지나면 모든 프로그램에서 100으로 포화 (~5000회 이상 실행 후). 근본 원인: `freed_objects` LRU 맵이 프로그램 실행 간에 초기화되지 않아, 프로그램 N에서 해제된 포인터가 프로그램 N+1에서 "재사용"으로 감지되어 무한 축적. 수정: `ebpf_read_and_reset()`에서 `BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_DELETE_ELEM` 루프 (리셋당 8192 엔트리 전체)로 `freed_objects` 맵을 클리어. `ebpf_open_pinned()` 헬퍼로 metrics 맵과 함께 고정된 freed_objects 맵도 열기.
- **버그 수정 (v6)**: `finish_output()`에 포화 방지 가드 추가 — `reuse > 500`이면 (단일 프로그램 실행에서 물리적으로 불가능한 수치) UAF 점수 산출을 억제. 잔여 freed_objects 축적이 Focus 모드를 과도하게 트리거하는 것을 방지.

### 5f. 퍼저 피드백 — **완료**
- `processResult()`: `statEbpfAllocs`, `statEbpfReuses`, `statEbpfUafDetected`, `statEbpfDoubleFree`, `statEbpfSizeMismatch` 통계 추적
- 비크래시 UAF 감지: UAF 점수 ≥ 70이면 `AddFocusCandidate()` → 포커스 모드 트리거
- **Double-free Focus**: double-free 감지 시 포커스 모드 트리거
- **통합 eBPF 쿨다운**: UAF와 double-free Focus 트리거가 단일 5분 쿨다운 (`lastEbpfFocus` 타임스탬프)을 공유하여 Focus 과다 트리거 방지
- 웹 대시보드에서 통계 확인: `ebpf reuses` (비율), `ebpf uaf` (카운트), `ebpf double-free` (카운트), `ebpf size-mismatch` (비율) — 모두 `ebpf` 그래프

### 5g. 안정성 강화 — **완료**
프로덕션 안정성을 위한 5가지 수정 사항:

1. **eBPF 포화 가드** (`executor.cc`): `reuse > 500`이면 UAF 점수 산출 억제. 잔여 freed_objects 축적으로 모든 프로그램이 100점으로 평가되는 문제 방지.
2. **Candidates 카운터 수정** (`fuzzer.go`): `InjectSeed()`와 `InjectProgram()`에서 `progCandidate` 플래그 및 `statCandidates` 증가 제거. AI 주입 시드는 코퍼스 트리아지 후보가 아님 — 혼합 시 시간 경과에 따라 카운터가 음수로 전환되는 버그 유발.
3. **Focus 작업 쿨다운** (`fuzzer.go`): `drainFocusPending()`에 연속 Focus 작업 간 최소 2분 간격 적용. 쿨다운 미충족 시 오래된 pending 엔트리를 제거하여 pending 큐의 무한 성장 방지.
4. **ChoiceTable RWMutex** (`fuzzer.go`): `ctMu`를 `sync.Mutex`에서 `sync.RWMutex`로 변경. `ChoiceTable()` (읽기 전용, 매 뮤테이션마다 호출)이 `RLock()`을 사용하여 동시성 향상. 쓰기(`updateChoiceTable`)는 배타적 `Lock()` 유지.
5. **focusTitles 메모리 캡** (`fuzzer.go`): `focusTitles` 중복 제거 맵을 10,000개 항목으로 제한. 초과 시 맵을 초기화하고 활성 Focus 작업에서만 재충전하여 장시간 실행 시 무한 메모리 성장 방지.

### 주요 설계 결정
- **로더와 executor 분리**: 로더가 복잡한 BPF 로딩 처리 (cilium/ebpf), executor는 간단한 맵 읽기 (raw bpf() syscall)
- **kprobe 대신 tracepoint**: `tracepoint/kmem/kfree`, `tracepoint/kmem/kmalloc`는 안정적인 ABI
- **LRU 해시 맵**: freed_objects가 LRU로 오래된 엔트리 자동 제거, 무한 성장 방지
- **그레이스풀 디그레이데이션**: eBPF 미사용 시 정상적으로 0 메트릭으로 퍼징 계속

### 빌드
```bash
cd syzkaller
make              # eBPF 지원 포함 executor 빌드
make probe_ebpf   # BPF 오브젝트 + 로더를 bin/linux_amd64/에 빌드
```

## 개발 규칙

1. **코드 전에 계획 먼저**: 각 Phase 구현 전, 반드시 세부 개발 계획을 상의하고 합의한 후 구현 시작. 상의 없이 코딩 금지.
2. **문서 업데이트**: 주요 변경 후 `probe.md` (EN) + `probe_kor.md` (KR) 모두 업데이트 후 GitHub 푸시.
3. **범위**: `syzkaller/` 디렉토리만 수정. 리눅스 커널 소스 절대 불가.

## 구현 순서

| Phase | 구성요소 | 난이도 | 효과 | 의존성 |
|-------|---------|--------|------|--------|
| 1 | 크래시 필터링 & 중복 제거 파이프라인 | 낮음 | 즉각적 노이즈 감소 + 변종 다양성 보존 | 없음 | **완료** |
| 2 | 포커스 모드 | 중간 | 고위험 발견 사항 심화 탐색 | Phase 1 (심각도 등급 필요) | **완료** |
| 3 | AI 트리아지 (Claude Haiku 4.5) | 중간 | 스마트 그룹 단위 크래시 분석 | Phase 1 (중복 제거 그룹 필요), Phase 2 (포커스 모드 필요) |
| 4 | Practical Hardening (UAF/OOB) | 중간 | 취약점 발견율 향상 | 없음 (2-3과 병렬 가능) | **완료** |
| 5 | eBPF 런타임 모니터 | 높음 | 실시간 익스플로잇 가능성 피드백 | Phase 2 (포커스 모드 피드백 루프 필요) | **완료** |
| 6 | AI 비용 최적화 + 데이터 기반 스케줄링 | 중간 | -50% API 비용, DEzzer 자동 최적화, SyzMini 최소화 | Phase 3 (AI 통합 필요) | **완료** |

**크리티컬 패스**: Phase 1 → Phase 2 → Phase 3 (순차 의존성)
**병렬 트랙**: Phase 4는 독립적으로 언제든 시작 가능

## Phase 6: AI 비용 최적화 + 데이터 기반 스케줄링 — **완료**

심층 분석 후 원래 6개 항목 중 2개 제거 (Prompt Caching, Tiered Routing — 효과 미미), 2개 대폭 변경.

### 6a. Batch API 마이그레이션 — **완료**

**목표**: Anthropic Batch API로 crash 분석 비용 50% 절감. Strategy 호출(1회/시간)은 동기 유지.

**수정 파일**: `pkg/aitriage/client.go` (BatchClient 인터페이스 + Anthropic 구현), `pkg/aitriage/batch.go` (신규: 상태 영속성), `pkg/aitriage/aitriage.go` (stepA 배치/동기 분기)

**핵심 설계**:
- 배치 조건: Anthropic provider + 2개 이상 pending
- 30초 폴링, 30분 타임아웃 → 취소 후 동기 폴백
- 디스크 영속성(`ai-batch-state.json`)으로 매니저 크래시 복구
- 실패 요청은 동기 재시도 (최대 3건)
- OpenAI는 항상 동기 모드

### 6d'. Per-Source 커버리지 메트릭 — **완료**

**목표**: focus/smash/fuzz 소스별 커버리지 게인 추적. 대시보드 표시.

**수정 파일**: `pkg/fuzzer/stats.go` (3개 stat.Val 추가), `pkg/fuzzer/fuzzer.go` (processResult 소스 귀속)

### 6e. SyzMini 영향 기반 최소화 — **완료**

**목표**: 영향도 기반 호출 제거 순서로 최소화 비용 ~60% 감소 (SyzMini, ATC 2025).

**수정 파일**: `prog/minimization.go` (removeCalls Phase 3에 influence probing 추가)

**원리**: MinimizeCorpus 모드에서 각 call을 1회 시험 제거 → 안전한 것부터 제거 → 연쇄 제거 효과.

### 6f. DEzzer — Operator별 추적 + DE 최적화 — **완료**

**목표**: mutation operator별 성과 실시간 추적 + DE 알고리즘 자동 가중치 최적화.

**수정 파일**: `prog/mutation.go` (반환값 string 추가), `pkg/fuzzer/dezzer.go` (신규: DE 엔진), `pkg/fuzzer/fuzzer.go` (DEzzer 통합), `pkg/fuzzer/job.go` (operator 캡처), `pkg/fuzzer/stats.go` (operator 통계)

**3계층 아키텍처**: Default × AI Base × DE Delta (±20%).
Lazy DE: 100회마다 1세대 진화, population=10, sliding window=100.

### 6f'. Focus 커버리지 피드백 루프 — **완료**

**목표**: Focus job 결과 + DEzzer 상태를 AI strategy 프롬프트에 피드백.

**수정 파일**: `pkg/fuzzer/fuzzer.go` (FocusJobResult), `pkg/fuzzer/job.go` (결과 기록), `pkg/aitriage/aitriage.go` (FuzzingSnapshot 확장), `pkg/aitriage/prompt_strategy.go` (프롬프트 포맷), `syz-manager/ai_triage.go` (스냅샷 연결)

### 빌드

```bash
cd syzkaller && make host  # 모든 호스트 도구 빌드 (syz-manager 포함)
```

## Phase 7: 핵심 탐지력 강화 (CO-RE 기반) — **완료**

CO-RE (Compile Once, Run Everywhere) 기반 인프라로 이식 가능한 kprobe 접근 + 5개 서브태스크로 취약점 탐지 능력 강화.

### 0. CO-RE 인프라 구축

**목표**: `vmlinux.h` + libbpf CO-RE 헤더로 이식 가능한 kprobe 빌드 환경 구축.

**변경사항**:
- `bpftool btf dump`으로 커널 BTF에서 `vmlinux.h` 생성 (`.gitignore` 추가)
- libbpf 헤더 3개 벤더링 (`executor/ebpf/bpf/`)
- `probe_ebpf.bpf.h` 재작성: 수동 타입 정의 제거 → `vmlinux.h` include

### 7d. 권한 상승 탐지 — **완료**

**목표**: `commit_creds()` kprobe로 권한 상승 자동 탐지.

**이중 전략**: `commit_creds_count` (전체, 정보용) + `priv_esc_count` (uid≠0→uid=0, sandbox_setuid 전용).

**BPF**: `kprobe_commit_creds` — CO-RE로 `new_cred->uid.val`, `task->real_cred->uid.val` 읽기.

**스코어링**: `priv_esc_count > 0` → score=100; `commit_creds_count > 0` → +5.

### 7c. Cross-Cache 정밀 탐지 — **완료**

**목표**: size_mismatch 휴리스틱을 cache명 기반 추적으로 대체.

**설계**: `cache_freed` LRU 맵 (ptr→cache_name_hash), `kprobe_cache_free`로 해시 저장, `trace_cache_alloc`에서 다른 cache 재할당 탐지.

**스코어링**: `cross_cache_count > 0` → +20; `> 3` → +40.

### 7b'. Slab-Pair 부스팅 — **완료**

**목표**: call_site별 alloc/free 패턴 수집 → AI 전략 프롬프트 반영.

**설계**: `slab_sites` LRU_HASH 맵 (512개), 기존 tracepoint에서 업데이트. Manager가 cilium/ebpf로 읽기.

**AI 통합**: 상위 10개 사이트의 할당/해제 비율 + 패턴 라벨 제공 (allocator-only, over-freeing 등).

### 7e. GPTrace 임베딩 기반 크래시 Dedup — **완료**

**목표**: OpenAI text-embedding-3-small로 크래시 벡터화 → 코사인 유사도 클러스터링.

**설계**: `EmbeddingClient` (LLM과 별도 비용 추적), `ClusterState` (응집 클러스터링, threshold=0.85), `stepEmbeddings()`에서 배치 처리.

**설정**: `ai_triage` 블록에 `embedding_model`, `embedding_api_key`. 미설정 → 기존 title dedup 유지.

**대시보드**: `/ai/embeddings` 페이지 (임베딩 현황, 클러스터 테이블, 비용 추적). 탭 네비게이션 추가.

### 7a. SyzGPT 시드 생성 — **완료**

**목표**: 저빈도 syscall(LFS)에 대한 LLM 시드 프로그램 생성으로 커버리지 확대.

**설계**: Manager가 LFS 목록 계산 (커버리지 < 3인 enabled syscall), `ForeachCallType` + `ResourceDesc.Ctors`로 의존성 체인 구축, corpus 예시 검색. `stepC()`에서 시간당 최대 10개 생성. `prog.Deserialize()`로 엄격 검증, 무효 → 폐기.

**프롬프트**: syzkaller 형식 명세 + 타겟 syscall 인자/리소스/예시. 응답 파싱 → 검증 → 주입.

**대시보드**: `/ai` 페이지에 SyzGPT 통계 (생성/유효/주입 수) 표시.

**생성 파일**: `pkg/aitriage/prompt_syzgpt.go`, `syz-manager/syzgpt.go`
**수정 파일**: `pkg/aitriage/aitriage.go`, `syz-manager/ai_triage.go`, `pkg/fuzzer/stats.go`, `pkg/manager/http.go`, `html/ai.html`

### FlatBuffers (Phase 7)

`ProgInfoRaw`에 3개 필드 추가:
- `ebpf_commit_creds_count` (필드 13, VT=30)
- `ebpf_priv_esc_count` (필드 14, VT=32)
- `ebpf_cross_cache_count` (필드 15, VT=34)

`StartObject` 13→16. `flatrpc.go` + `flatrpc.h` 수동 편집.

### 빌드

```bash
# BPF 오브젝트 (vmlinux.h 필요 — 없으면 먼저 생성):
# bpftool btf dump file /path/to/vmlinux format c > syzkaller/executor/ebpf/vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I executor/ebpf/ -I executor/ebpf/bpf/ \
    -c executor/ebpf/probe_ebpf.bpf.c \
    -o executor/ebpf/probe_ebpf.bpf.o

cd syzkaller && make host
```

## Phase 6+: 고급 개선 로드맵

**상세 로드맵**: `syzkaller/probe_log/improvement_roadmap.md` 참조 (기술 상세, 논문 레퍼런스, 비용 예측 포함).

30+ 논문 (CCS/NDSS/ASPLOS/USENIX 2024-2026) 서베이 결과 39개 적용 가능 기술을 식별하고 7개 Phase로 우선순위화:

| Phase | 초점 | 일정 | 핵심 기술 | 예상 효과 |
|-------|------|------|----------|----------|
| 6 | AI 비용 최적화 + 스케줄링 | 1주차 | Batch API, Prompt Caching, Tiered Routing, T-Scheduler, SyzMini, DEzzer | **API 비용 -80%**, 스케줄링 개선 |
| 7 | 핵심 탐지력 강화 | 2-3주차 | SyzGPT (DRAG), CountDown (refcount), Cross-cache, 권한상승, GPTrace | **취약점 탐지 +323%**, UAF +66% |
| 8 | 뮤테이션 & 커버리지 혁신 | 3-4주차 | MOCK, SeqFuzz, MobFuzz, 커버리지 피드백, Write-to-freed | **커버리지 +32%**, 버그 3-4.5x |
| 9 | 고급 커버리지 & 탐지 | 2개월 | KBinCov, Page-level UAF, Context-sensitive, FD, Anamnesis | **바이너리 커버리지 +87%** |
| 10 | 스펙 자동 생성 | 2-3개월 | KernelGPT, SyzForge, SyzSpec | **커버리지 +13-18%**, 새 syscall |
| 11 | 동시성 버그 | 3개월 | LACE, ACTOR, OZZ | **커버리지 +38%**, 레이스 컨디션 |
| 12 | 고급 모니터링 & 연구 | 3개월+ | KASLR leak, Quarantine bypass, Snowplow, Big Sleep | 실험적 |

### 비용 발생 기술 (API 예산 필요)
- SyzGPT 시드 생성 (+$0.10-0.50/일)
- GPTrace 임베딩 디덥 (+$0.01-0.05/일)
- Anamnesis 익스플로잇 평가 (+$0.50-3.00/일)
- KernelGPT/SyzForge 스펙 생성 (+$0.50-2.00/회)

### 무비용 기술 (순수 코드 변경)
- 모든 스케줄링 개선 (T-Scheduler, DEzzer, MobFuzz)
- 모든 eBPF 확장 (refcount, cross-cache, page-level, FD, 권한상승)
- 뮤테이션 개선 (MOCK, SeqFuzz, SyzMini)
- 커버리지 확장 (KBinCov, context-sensitive)
- 동시성 테스팅 (LACE, ACTOR)

## 관련 연구

| 논문 | 학회 | PROBE 관련성 |
|------|------|-------------|
| SyzGPT | ISSTA 2025 | 의존성 기반 RAG, 취약점 탐지 +323% — Phase 7 |
| CountDown | CCS 2024 | Refcount 기반 UAF, +66.1% UAF — Phase 7 |
| MOCK | NDSS 2024 | 컨텍스트 인식 뮤테이션, 커버리지 +32% — Phase 8 |
| Snowplow | ASPLOS 2025 | ML 뮤테이션 (Google DeepMind), 4.8x 가속 — Phase 12 |
| KernelGPT | ASPLOS 2025 | LLM 스펙 생성, 24 버그, 11 CVE — Phase 10 |
| GPTrace | ICSE 2026 | LLM 임베딩 크래시 디덥 — Phase 7 |
| KBinCov | CCS 2024 | 바이너리 커버리지, +87% — Phase 9 |
| SyzMini | ATC 2025 | 최소화 최적화, 비용 -60.7% — Phase 6 |
| LACE | 2025 | eBPF sched_ext 동시성, 커버리지 +38% — Phase 11 |
| Anamnesis | 2026 | LLM 익스플로잇 생성, ~$30/exploit — Phase 9 |
| MobFuzz | NDSS 2024 | 다목적 MAB, 버그 3x — Phase 8 |
| SeqFuzz | Inscrypt 2025 | 유효 컴포넌트 추론, 버그 4.5x — Phase 8 |
| SLUBStick | USENIX Sec 2024 | Cross-cache 공격, 99% 성공률 — Phase 12 |
| ACTOR | USENIX Sec 2023 | 동시성 테스팅 — Phase 11 |
| SyzScope | USENIX Sec 2022 | "저위험" 버그의 15%가 실제 고위험 — Phase 1+2 동기 |
| GREBE | IEEE S&P 2022 | "익스플로잇 불가" 6개를 코드 실행으로 — Phase 2 동기 |

## 주요 파일 참조

| 파일 | 용도 |
|------|------|
| `prog/mutation.go` | 뮤테이션 전략 및 가중치 |
| `prog/generation.go` | 프로그램 생성 진입점 |
| `prog/rand.go` | 정수 생성, 특수 값 |
| `pkg/fuzzer/fuzzer.go` | 퍼징 루프, 큐 관리 |
| `pkg/fuzzer/job.go` | Job 타입 (triage, smash, hints) |
| `pkg/report/report.go` | 크래시 파싱 파이프라인 |
| `pkg/report/crash/types.go` | 크래시 유형 정의 |
| `pkg/report/impact_score.go` | 심각도 랭킹 |
| `pkg/report/linux.go` | 리눅스 전용 크래시 파싱 |
| `pkg/manager/` | 매니저 비즈니스 로직 |
| `sys/linux/*.txt` | Syscall 기술 (syzlang) |
| `executor/executor.cc` | VM 내 syscall 실행기 (C++) |
| `executor/ebpf/probe_ebpf.bpf.c` | eBPF 힙 모니터 (BPF C) |
| `tools/syz-ebpf-loader/main.go` | BPF 로더 바이너리 (Go) |
| `pkg/flatrpc/flatrpc.fbs` | FlatBuffers RPC 스키마 |

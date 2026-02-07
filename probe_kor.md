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
|  [Phase 3] AI 트리아지 + 포커스 가이드                  |
|    - Claude Haiku 4.5로 크래시 분석                     |
|    - 포커스 모드용 뮤테이션 전략 제안                    |
|    - 그룹 단위 분석 (크래시 개별이 아닌)                |
|    - 크래시 후 분석 (퍼징 루프 오버헤드 없음)            |
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

## Phase 1: 크래시 필터링 & 중복 제거 파이프라인

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
  - **Tier 2 (중요)**: OOB 변형, KFENCEInvalidFree, NullPtrDerefBUG
  - **Tier 3 (낮음)**: WARNING, LOCKDEP, MemoryLeak, Hang, KCSAN
- Tier 3 크래시는 별도 저장, 포커스 모드를 트리거하지 않음

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
    |       Tier 3는 포커스 모드 파이프라인에서 제외
    |
    +-- 4단계: AI 분석 (그룹 단위, 크래시 개별이 아닌)
            전송: 그룹 대표 + 모든 변종 트리거 프로그램
            → LLM이 어떤 변종이 가장 익스플로잇 가능한지 판별
            → 변종 다양성 = 포커스 모드에 더 많은 옵션
```

**그룹핑이 중요한 이유**: 같은 크래시 지점 ≠ 같은 익스플로잇 가능성. 같은 위치의 write-UAF와 read-UAF는 익스플로잇 잠재력이 완전히 다름. "중복"을 삭제하면 포커스 모드에 필요한 공격 벡터를 잃게 됨.

## Phase 2: 포커스 모드

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
          +-- 고위험 → 포커스 모드 진입
                |
                +-- 1. 크래시 프로그램 집중 뮤테이션
                |     +-- syscall 인자 미세 변형
                |     +-- 호출 순서/타이밍 순열
                |     +-- 관련 syscall 치환
                |     +-- UAF: free↔reuse 간격 조절
                |     +-- OOB: 크기 경계 탐색
                |
                +-- 2. 변종 탐색 & 조합
                |     +-- read-UAF → write-UAF 업그레이드
                |     +-- 1바이트 OOB → 더 큰 OOB로 확장
                |     +-- 같은 코드 경로에서 다른 취약점 발견
                |     +-- 같은 그룹 내 변종 간 크로스 조합
                |     |     (예: 변종 D의 해제 경로
                |     |      + 변종 B의 write 패턴)
                |
                +-- 3. 수확 체감 시 탈출
                      +-- N회 연속 새로운 발견 없으면 복귀
```

**수정 대상**:
- `pkg/fuzzer/job.go` — `focusJob` 타입 추가
- `pkg/fuzzer/fuzzer.go` — `focusQueue`를 높은 우선순위로 추가

**큐 우선순위** (변경):
```
1. triageCandidateQueue
2. candidateQueue
3. triageQueue
4. focusQueue            ← 신규: 고위험 크래시 집중 뮤테이션
5. smashQueue
6. genFuzz
```

## Phase 3: AI 트리아지 + 포커스 가이드

**목표**: LLM을 활용한 크래시 익스플로잇 가능성 분석 및 포커스 모드 뮤테이션 전략 수립.

**모델**: Claude Haiku 4.5 (Anthropic API)
- 선정 근거: 크래시 리포트 분석은 구조화된 텍스트 처리 — 소형/고속 모델로 충분
- 개발 도구와 같은 제공사(Anthropic)로 관리 편의성 확보
- 중복 제거 파이프라인으로 하루 3~5개 그룹만 분석하므로 비용 무시 가능

**적용 지점** (퍼징 루프 오버헤드 없음):

### 3a. 크래시 익스플로잇 가능성 분석 (그룹 단위)
```
크래시 그룹 감지 → 그룹 대표 + 모든 변종 프로그램을 LLM에 전달
  → "이 UAF는 nft_set_elem에서 발생, 같은 slab 재할당으로
     익스플로잇 가능, 권한 상승 가능성 높음.
     변종 B(write 경로)가 가장 위험.
     변종 D의 해제 경로와 B의 write를 조합하면
     더 안정적인 익스플로잇 가능."
  → 익스플로잇 가능성 스코어 + 근거
  → 포커스 모드 진입 여부 + 우선 변종 결정에 활용
```

### 3b. 포커스 모드 전략
```
포커스 모드 진입 → 크래시 프로그램 + 컨텍스트를 LLM에 전달
  → "이 UAF를 심화하려면:
     1. close() 전에 ioctl(SET_FLAG) 추가
     2. 버퍼 크기를 PAGE_SIZE 배수로 시도
     3. 다른 스레드에서 동시에 read() 호출"
  → 뮤테이션 힌트를 focusJob에 전달
```

### 3c. 비용 추정

| 시나리오 | LLM 호출 수/일 | 월간 비용 (Haiku 4.5) |
|----------|---------------|----------------------|
| 저볼륨 | 3~5개 그룹 | ~$0.80 |
| 중볼륨 | 10~15개 그룹 | ~$2.50 |
| 고볼륨 | 30~50개 그룹 | ~$8.00 |

호출당 입력: ~1,500 토큰 (KASAN 리포트 + 스택 트레이스 + 변종 목록)
호출당 출력: ~750 토큰 (분석 + 스코어 + 전략)

**수정 대상**:
- `pkg/` 또는 `syz-manager/`에 LLM 통합 모듈 신규 생성
- 포커스 모드 job이 외부 뮤테이션 힌트를 수용하도록 수정

## Phase 4: UAF/OOB 뮤테이션 엔진

**목표**: UAF와 OOB를 유발하도록 특화된 뮤테이션 전략 추가.

**수정 대상**:
- `prog/mutation.go` — 새 뮤테이션 타입 + 가중치 조정
- `prog/rand.go` — 경계값 생성
- `sys/linux/*.txt` — 강화된 syscall 기술

### 4a. UAF 타겟 뮤테이션
- **리소스 생명주기 뮤테이션**: free → reuse 시퀀스 삽입
  - `open/socket/mmap` → 사용 → `close/munmap` → 같은 fd/ptr 재사용
- **타이밍 뮤테이션**: free와 reuse 사이의 호출 수 변형
- `MutateOpts`에 새 가중치: `UAFPatternWeight`

### 4b. OOB 타겟 뮤테이션
- **경계값 주입**: 크기/오프셋 인자에 0, -1, PAGE_SIZE-1, PAGE_SIZE+1, INT_MAX 우선 적용
- **LenType 우선순위 상향**: 현재 1.0에서 상향 — 길이 필드는 핵심 OOB 트리거
- **버퍼 크기 불일치**: 선언된 크기와 실제 버퍼 크기 간 의도적 불일치 생성
- `prog/rand.go`의 `specialInts`에 OOB 특화 값 추가

### 4c. 강화된 시즈콜 기술
복잡한 메모리 관리가 있는 인터페이스에 집중:
- `sys/linux/uffd.txt` (현재 95줄) — fault-timing 패턴으로 확장
- `sys/linux/io_uring.txt` — op별 생명주기 기술 심화
- netfilter/nftables 오브젝트 체이닝 패턴

## Phase 5: eBPF 런타임 모니터

**목표**: 익스플로잇 가능성 평가를 위한 실시간 커널 힙 상태 추적.

**제약**: Guest VM 내부에서 실행, kprobe/tracepoint를 통해 기존 커널 함수에 attach. 커널 소스 수정 없음.

### 모니터링 대상
- `kprobe/kmalloc`, `kprobe/kfree` — slab 오브젝트 생명주기 추적
- `kprobe/copy_from_user`, `kprobe/copy_to_user` — OOB 접근 패턴 감지
- slab 할당자 tracepoint — 캐시 재사용 감지

### 피드백 루프
```
eBPF 감지:
  "오브젝트 해제 후 42μs만에 같은 slab 캐시에서 재할당"
  → 높은 익스플로잇 가능성 신호
  → 퍼저에 우선순위 신호로 피드백

eBPF 감지:
  "다른 컨텍스트에서 재할당된 오브젝트에 write 발생"
  → 치명적 신호 → 포커스 모드 강화

eBPF 감지:
  "재할당 없이 read-only 접근"
  → 낮은 익스플로잇 가능성 → 우선순위 하향
```

**수정 대상**:
- 새 eBPF 모듈 (BPF C 프로그램 + 로더)
- `executor/` — Guest VM 내 syz-executor와 통합
- `pkg/fuzzer/fuzzer.go` — `signalPrio()`에 eBPF 신호 확장

## 구현 순서

| Phase | 구성요소 | 난이도 | 효과 | 의존성 |
|-------|---------|--------|------|--------|
| 1 | 크래시 필터링 & 중복 제거 파이프라인 | 낮음 | 즉각적 노이즈 감소 + 변종 다양성 보존 | 없음 |
| 2 | 포커스 모드 | 중간 | 고위험 발견 사항 심화 탐색 | Phase 1 (심각도 등급 필요) |
| 3 | AI 트리아지 (Claude Haiku 4.5) | 중간 | 스마트 그룹 단위 크래시 분석 | Phase 1 (중복 제거 그룹 필요), Phase 2 (포커스 모드 필요) |
| 4 | UAF/OOB 뮤테이션 엔진 | 중간~높음 | 취약점 발견율 향상 | 없음 (2-3과 병렬 가능) |
| 5 | eBPF 런타임 모니터 | 높음 | 실시간 익스플로잇 가능성 피드백 | Phase 2 (포커스 모드 피드백 루프 필요) |

**크리티컬 패스**: Phase 1 → Phase 2 → Phase 3 (순차 의존성)
**병렬 트랙**: Phase 4는 독립적으로 언제든 시작 가능

## 관련 연구

| 논문 | 학회 | PROBE 관련성 |
|------|------|-------------|
| CountDown | CCS 2024 | UAF 특화 퍼징 (refcount 기반), 66.1% 더 많은 UAF — Phase 4 참고 |
| FUZE | USENIX Sec 2018 | 커널 UAF 익스플로잇 생성 자동화 — Phase 5 익스플로잇 가능성 기준 |
| ACTOR | USENIX Sec 2023 | 액션 기반 퍼징 (alloc/free 액션), 41개 미발견 버그 — Phase 4 참고 |
| SyzScope | USENIX Sec 2022 | "저위험" 버그의 15%가 실제 고위험 — Phase 1+2 동기 |
| GREBE | IEEE S&P 2022 | "익스플로잇 불가" 6개 버그를 임의 코드 실행으로 전환 — Phase 2 변종 탐색 근거 |
| SYZVEGAS | USENIX Sec 2021 | RL 기반 시드 스케줄링, 38.7% 커버리지 향상 — Phase 2 스케줄링 참고 |
| HEALER | SOSP 2021 | syscall 관계 학습, 28% 커버리지 향상 — Phase 4 의존성 뮤테이션 |
| KernelGPT | ASPLOS 2025 | LLM으로 시즈콜 자동 생성, 24개 신규 버그, 11 CVE — Phase 3+4 LLM 활용 |

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

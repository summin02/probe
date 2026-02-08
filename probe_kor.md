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
  - **Tier 2 (중요)**: OOB 변형, KFENCEInvalidFree, NullPtrDerefBUG
  - **Tier 3 (낮음)**: WARNING, LOCKDEP, MemoryLeak, Hang, KCSAN
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

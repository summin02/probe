# Syzkaller OOB Fuzzer 커스터마이징

커널 소스 수정 없이 Syzkaller만 커스터마이징하여 Out-of-Bounds (OOB) 메모리 접근 버그를 탐지하는 퍼징 환경

## 📋 프로젝트 개요

이 프로젝트는 Linux 커널을 수정하지 않고 Syzkaller 퍼저만을 커스터마이징하여:
- 가상 시스템콜을 통한 OOB 시나리오 생성
- 변이기(mutator)의 경계값 편향 강화
- OOB 읽기/쓰기 패턴 자동 탐지

를 구현한 커스텀 퍼징 파이프라인입니다.

## 🎯 주요 특징

### 1. 가상 시스템콜 (Virtual Syscalls)
커널 수정 없이 executor 레벨에서 구현된 4개의 커스텀 시스템콜:

- `syz_oob_alloc(size, flags)` - mmap 기반 버퍼 할당
- `syz_oob_write(buf, offset, data, count)` - 경계 체크 후 의도적 OOB 허용
- `syz_oob_read(buf, offset, data, count)` - 경계 넘는 읽기 시도
- `syz_oob_boundary_test(buf, size, offset, count)` - 직접적인 경계 테스트

### 2. 경계값 편향 변이기 (Boundary-Biased Mutator)
`prog/mutation.go`의 `mutateInt()` 함수 강화:

**적용된 경계값 전략:**
- 기본 경계: -1, 0, 1, 255, 256, 512, 1024, 2048, 4096
- 정수 오버플로우: `TypeBitSize` 기반 max/min 근처 값
- Power-of-2 경계: `±1` 변형
- 음수 오프셋: 큰 양수로 해석되는 값
- **50% 확률**로 경계값 우선 적용

### 3. OOB 탐지 패턴 (Detection Patterns)
`pkg/report/linux.go`에 8가지 OOB 패턴 추가:

```go
"syz_oob_write: potential OOB detected"
"syz_oob_read: potential OOB detected"
"syz_oob_boundary_test: offset beyond buffer"
"syz_oob_boundary_test: access beyond buffer boundary"
// ... 등
\`\`\`

## 📂 수정된 파일 목록

### 1. Syscall 정의
**파일:** \`sys/linux/custom_oob.txt\` (신규)
\`\`\`
resource oob_buf[intptr]

syz_oob_alloc(size int32[1:4096], flags int32) oob_buf
syz_oob_write(buf oob_buf, offset int32[0:4096], data ptr[in, array[int8]], count int32[1:2048])
syz_oob_read(buf oob_buf, offset int32[0:4096], data ptr[out, array[int8]], count int32[1:2048])
syz_oob_boundary_test(buf oob_buf, buf_size int32[1:1024], access_offset int32[0:2048], access_size int32[1:512])
\`\`\`

**변경 사항:**
- Resource type \`oob_buf\` 정의
- 4개 시스템콜 시그니처
- 범위 제약 설정 (경계값 테스트 유도)

---

### 2. Executor 구현
**파일:** \`executor/common_linux.h\` (수정)

**추가 위치:** 파일 끝부분 (약 160줄)

**핵심 코드:**
\`\`\`c
#if SYZ_EXECUTOR

// Global storage - 반드시 extern \"C\" 블록 밖에 위치
static void* oob_buffers[16] = {0};
static size_t oob_buffer_sizes[16] = {0};

#ifdef __cplusplus
extern \"C\" {
#endif

long syz_oob_alloc(volatile long size, volatile long flags) {
    void* buf = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    // ... 슬롯 관리 및 debug 로깅
}

long syz_oob_write(volatile long buf_ptr, volatile long offset, 
                   volatile long data_ptr, volatile long count) {
    if ((size_t)(offset + count) > buf_size) {
        debug(\"OOB detected: buf_size=%zu, offset=%ld, count=%ld\\n\", ...);
        // 의도적으로 계속 진행하여 OOB 트리거
    }
    memcpy(buf + offset, data, count);
}
// ... 나머지 함수들

#ifdef __cplusplus
}
#endif

#endif
\`\`\`

**변경 사항:**
- \`extern \"C\"\` 링키지 추가 (C++/C 연동)
- Static 변수는 extern \"C\" 블록 밖에 배치 (중요!)
- mmap 기반 버퍼 할당
- 16개 버퍼 동시 관리
- 모든 경계 위반에 debug 로그 출력

---

### 3. Syscall 테이블
**파일:** \`executor/syscalls.h\` (자동생성 후 수정)

**수정 위치:** Line 12864-12875 (Linux amd64 섹션)

**추가 코드:**
\`\`\`cpp
#if GOARCH_amd64
#ifdef __cplusplus
extern \"C\" {
#endif
long syz_oob_alloc(volatile long, volatile long);
long syz_oob_write(volatile long, volatile long, volatile long, volatile long);
long syz_oob_read(volatile long, volatile long, volatile long, volatile long);
long syz_oob_boundary_test(volatile long, volatile long, volatile long, volatile long);
#ifdef __cplusplus
}
#endif
\`\`\`

**주의:** 이 파일은 \`make generate\` 실행 시 재생성되므로 Python 스크립트(\`/tmp/fix_syscalls.py\`)로 수정 필요

---

### 4. 변이기 강화
**파일:** \`prog/mutation.go\` (수정)

**수정 위치:** mutateInt 함수 내부

**추가된 로직:**
\`\`\`go
func mutateInt(arg *ConstArg, r *randGen, p *Prog) bool {
    // OOB 후보 검사
    isOOBCandidate := (strings.Contains(arg.Type().Name(), \"offset\") ||
                       strings.Contains(arg.Type().Name(), \"size\") ||
                       strings.Contains(arg.Type().Name(), \"count\"))
    
    if isOOBCandidate && r.oneOf(2) {  // 50% 확률
        // 경계값 우선 적용
        boundaryValues := []uint64{0, 1, 255, 256, 512, 1024, 2048, 4096}
        
        switch r.Intn(5) {
        case 0: // 기본 경계값
            arg.Val = boundaryValues[r.Intn(len(boundaryValues))]
        case 1: // 타입 오버플로우
            bitSize := arg.Type().TypeBitSize()
            maxVal := uint64((1 << bitSize) - 1)
            arg.Val = maxVal - uint64(r.Intn(10))
        case 2: // Power-of-2 ±1
            power := uint64(1 << r.Intn(13))
            arg.Val = power + uint64(r.Intn(3)) - 1
        case 3: // 음수 오프셋 (큰 양수로 표현)
            arg.Val = uint64(^uint64(r.Intn(4096)))
        case 4: // 작은 랜덤 변화
            arg.Val += uint64(r.Int63n(16) - 8)
        }
        return true
    }
    // 기존 변이 로직...
}
\`\`\`

**변경 효과:**
- offset/size/count 관련 인자에 경계값 편향 50% 적용
- 5가지 경계값 전략 조합
- 기존 랜덤 변이와 혼합

---

### 5. 크래시 탐지
**파일:** \`pkg/report/linux.go\` (수정)

**추가 패턴:**
\`\`\`go
{
    title: compile(\"syz_oob\"),
    formats: []oopsFormat{
        {
            title: compile(\"syz_oob_write: potential OOB detected\"),
            report: compile(\`buf_size=(?P<buf_size>\\d+).*offset=(?P<offset>\\d+).*count=(?P<count>\\d+)\`),
        },
        {
            title: compile(\"syz_oob_read: potential OOB detected\"),
            report: compile(\`buf_size=(?P<buf_size>\\d+).*offset=(?P<offset>\\d+).*count=(?P<count>\\d+)\`),
        },
        // ... 총 8개 패턴
    },
}
\`\`\`

**추출 정보:**
- \`buf_size\`, \`offset\`, \`count\` 파라미터
- OOB 발생 위치 및 유형

---

### 6. 설정 파일
**파일:** \`oob_fuzzer.cfg\` (신규)

\`\`\`json
{
    \"target\": \"linux/amd64\",
    \"http\": \"127.0.0.1:56741\",
    \"workdir\": \"/usr/src/kernel/workdir\",
    \"kernel_obj\": \"/usr/src/kernel/linux-6.17.8\",
    \"image\": \"/usr/src/kernel/image/bullseye.img\",
    \"sshkey\": \"/usr/src/kernel/image/bullseye.id_rsa\",
    \"syzkaller\": \"/usr/src/kernel/syzkaller\",
    \"procs\": 8,
    \"type\": \"qemu\",
    \"vm\": {
        \"count\": 2,
        \"kernel\": \"/usr/src/kernel/linux-6.17.8/arch/x86/boot/bzImage\",
        \"cpu\": 2,
        \"mem\": 2048
    },
    \"enable_syscalls\": [
        \"syz_oob_alloc\",
        \"syz_oob_write\", 
        \"syz_oob_read\",
        \"syz_oob_boundary_test\"
    ],
    \"sandbox\": \"none\",
    \"cover\": false
}
\`\`\`

**주요 설정:**
- 커널 6.17.8 사용
- QEMU VM 2개 (각 2 CPU, 2GB RAM)
- OOB syscall만 활성화
- Coverage 비활성화 (빠른 테스트)

---

## 🔧 빌드 과정

### 1. 시스템콜 생성
\`\`\`bash
cd /usr/src/kernel/syzkaller
export PATH=/usr/src/kernel/goroot/bin:\$PATH

make generate
\`\`\`

**결과:** \`sys/linux/gen/\` 디렉토리에 custom_oob 관련 Go 파일 생성

### 2. Executor 빌드
\`\`\`bash
# syscalls.h 수정 (자동생성 파일이므로 스크립트 사용)
sudo python3 /tmp/fix_syscalls.py

make executor
\`\`\`

**결과:** \`bin/linux_amd64/syz-executor\` 바이너리 생성

### 3. 전체 빌드
\`\`\`bash
make
\`\`\`

**생성 바이너리:**
- \`bin/syz-manager\` - 퍼저 오케스트레이터
- \`bin/syz-fuzzer\` - 실제 퍼징 엔진
- \`bin/syz-execprog\` - 단일 프로그램 실행
- \`bin/syz-prog2c\` - 프로그램 → C 코드 변환

---

## 🚀 실행 방법

### 테스트 프로그램 작성
**파일:** \`test_oob.prog\`
\`\`\`
syz_oob_alloc(0x100, 0x0)
syz_oob_write(r0, 0xf0, &(0x7f0000000000)=\"deadbeef\", 0x20)
syz_oob_read(r0, 0x100, &(0x7f0000001000), 0x50)
syz_oob_boundary_test(r0, 0x100, 0xf8, 0x20)
\`\`\`

### 단일 프로그램 실행
\`\`\`bash
./bin/syz-execprog -executor=./bin/linux_amd64/syz-executor -procs=1 -repeat=0 test_oob.prog
\`\`\`

### 퍼저 실행
\`\`\`bash
sudo ./bin/syz-manager -config oob_fuzzer.cfg
\`\`\`

**모니터링:** http://127.0.0.1:56741

---

## 📊 결과 분석

### Corpus 수집
**위치:** \`workdir/corpus.db\`

OOB를 유발하는 입력 케이스가 자동으로 수집됩니다.

### 크래시 리포트
**위치:** \`workdir/crashes/\`

각 크래시는 다음을 포함:
- \`description\` - OOB 패턴 요약
- \`log\` - 전체 실행 로그 (debug 메시지 포함)
- \`report\` - 구조화된 리포트
- \`prog\` - 재현 가능한 프로그램

### Debug 로그 예시
\`\`\`
syz_oob_alloc: allocated buffer 0x7f1234567000 size 256 at slot 0
syz_oob_write: potential OOB detected - buf_size=256, offset=240, count=32
syz_oob_write: wrote 32 bytes at offset 240
syz_oob_boundary_test: buf_size=256, access_offset=248, access_size=32
syz_oob_boundary_test: access beyond buffer boundary
\`\`\`

---

## 🔍 주요 제약사항

### 1. 자동 생성 파일
**문제:** \`executor/syscalls.h\`는 \`make generate\`로 재생성  
**해결:** Python 스크립트로 빌드 시마다 패치
\`\`\`bash
sudo python3 /tmp/fix_syscalls.py
\`\`\`

### 2. Resource Type 제약
Syzkaller는 시스템콜 반환 타입이 제한적:
- \`fd\` (파일 디스크립터)
- 커스텀 \`resource\` 타입
- \`intptr\` 등

일반 포인터를 직접 반환할 수 없어 \`resource oob_buf[intptr]\` 우회 사용

### 3. Executor 내부 버퍼 관리
16개 슬롯 제한으로 동시에 최대 16개 버퍼만 관리 가능

---

## 📈 개선 방향

### 단기
1. ✅ Executor 빌드 오류 수정 (완료)
2. VM 부팅 안정화
3. Coverage 활성화 후 효율성 측정

### 중기
1. \`syz-sysgen\` 수정하여 syscalls.h 자동 패치
2. 더 많은 OOB 시나리오 추가 (use-after-free, double-free 등)
3. KASAN 통합으로 커널 레벨 탐지 강화

### 장기
1. 다른 아키텍처 지원 (arm64, riscv64)
2. Machine Learning 기반 변이 전략
3. Differential fuzzing (정상 버퍼 vs OOB 버퍼 비교)

---

## 🐛 디버깅 팁

### Executor 심볼 확인
\`\`\`bash
nm ./bin/linux_amd64/syz-executor | grep syz_oob
# 기대 결과:
# 000000000012abcd T syz_oob_alloc
# 000000000012abde T syz_oob_write
# 000000000012abef T syz_oob_read
# 000000000012ac00 T syz_oob_boundary_test
\`\`\`

### 전처리 출력 확인
\`\`\`bash
g++ -E -DGOOS_linux=1 -DGOARCH_amd64=1 -DSYZ_EXECUTOR=1 \\
    -I. -Iexecutor/_include executor/executor.cc -o /tmp/preprocessed.cc

# OOB 함수 구현 확인
grep -A20 'syz_oob_alloc' /tmp/preprocessed.cc
\`\`\`

### 컴파일 에러 해결
**linkage conflict 발생 시:**
- \`common_linux.h\`의 static 변수들이 extern \"C\" 블록 **밖**에 있는지 확인
- 함수 정의만 extern \"C\" 블록 **안**에 위치

**sign-compare 에러:**
\`\`\`c
// 잘못된 코드
if (offset + count > buf_size)

// 올바른 코드
if ((size_t)(offset + count) > buf_size)
\`\`\`

---

## 📚 참고 자료

- [Syzkaller 공식 문서](https://github.com/google/syzkaller/tree/master/docs)
- [Syscall 정의 문법](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md)
- [Executor 구조](https://github.com/google/syzkaller/blob/master/docs/internals.md)
- [프로그램 변이](https://github.com/google/syzkaller/blob/master/docs/mutation.md)

---

## 💾 백업 및 복원

### 변경사항 백업
\`\`\`bash
cd /usr/src/kernel/syzkaller
tar -czf ~/syzkaller_oob_backup_\$(date +%Y%m%d).tar.gz \\
    sys/linux/custom_oob.txt \\
    executor/common_linux.h \\
    prog/mutation.go \\
    pkg/report/linux.go \\
    oob_fuzzer.cfg
\`\`\`

### 원본 복원
\`\`\`bash
cd /usr/src/kernel
rm -rf syzkaller
cp -r syzkaller_bak syzkaller
\`\`\`

---

## 🔧 빌드 자동화 스크립트

### 전체 빌드 스크립트
**파일:** \`build_oob_fuzzer.sh\`
\`\`\`bash
#!/bin/bash
set -e

cd /usr/src/kernel/syzkaller
export PATH=/usr/src/kernel/goroot/bin:\$PATH

echo \"[1/4] Generating syscall definitions...\"
make generate

echo \"[2/4] Patching syscalls.h...\"
sudo python3 /tmp/fix_syscalls.py

echo \"[3/4] Building executor...\"
make executor

echo \"[4/4] Building full syzkaller...\"
make

echo \"✅ Build complete!\"
echo \"Verify symbols: nm ./bin/linux_amd64/syz-executor | grep syz_oob\"
\`\`\`

---

## 👤 작성자

- Kernel Fuzzing Research
- 작성일: 2025-11-23
- 환경: Ubuntu 24.04 (WSL2), Linux Kernel 6.17.8

---

## 📝 라이센스

Syzkaller는 Apache 2.0 라이센스를 따릅니다.  
이 커스터마이징은 연구 및 교육 목적으로만 사용하세요.

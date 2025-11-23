# Syzkaller OOB Fuzzer

Out-of-Bounds (OOB) 메모리 접근 버그 탐지를 위한 Syzkaller 커스터마이징 프로젝트

## 🎯 프로젝트 개요

이 프로젝트는 **커널 소스 수정 없이** Syzkaller만 커스터마이징하여 OOB 버그를 효과적으로 탐지합니다.

**주요 특징:**
- ✅ 4개 커스텀 시스템콜 (`syz_oob_alloc/write/read/boundary_test`)
- ✅ 경계값 편향 mutation (50% 확률로 경계값 우선 생성)
- ✅ 8개 전용 타입 (power-of-2, boundary, negative offsets)
- ✅ 11개 syscall variants (`$safe`, `$oob`, `$negative`)
- ✅ 검증된 1000x OOB 생성 (3 bytes → 3054 bytes)

## 🚀 빠른 시작

### 사전 요구사항
```bash
# Ubuntu 24.04 (WSL2 지원)
sudo apt update
sudo apt install -y build-essential flex bison bc libssl-dev libelf-dev \
    python3 git wget debootstrap qemu-system-x86
```

### 1단계: 설치
```bash
git clone https://github.com/summin02/probe.git
cd probe
chmod +x setup.sh
./setup.sh
```

`setup.sh`가 자동으로:
- Syzkaller 클론 (Google 공식 저장소)
- Go 1.24 다운로드 및 설치
- 커스텀 패치 적용
- 초기 설정 완료

### 2단계: 빌드
```bash
chmod +x build.sh
./build.sh
```

### 3단계: 실행
```bash
chmod +x run.sh
./run.sh
```

## 📁 프로젝트 구조

```
syzkaller-oob-fuzzer/
├── README.md                    # 본 파일
├── setup.sh                     # 자동 설치 스크립트
├── build.sh                     # 빌드 스크립트
├── run.sh                       # 실행 스크립트
├── configs/
│   └── oob_fuzzer.cfg.template # Fuzzer 설정 템플릿
├── patches/
│   ├── custom_oob.txt          # Syscall 정의
│   ├── common_linux.h.patch    # Executor 패치
│   └── mutation.go.patch       # Mutation 패치
├── docs/
│   └── TECHNICAL.md            # 상세 기술 문서
└── scripts/
    └── apply_patches.sh        # 패치 적용 스크립트
```

## 🎉 실제 동작 예시

**생성된 극단적 OOB 테스트:**
```c
r0 = syz_oob_alloc(0x3, 0x9)              // 3바이트 버퍼
syz_oob_write(r0, 0x7d7, &(...), 0x417)   // 2007 offset + 1047 count
// → 3054 bytes 접근 시도 (1018배 OOB!)
```

## 📖 상세 문서

- **[docs/TECHNICAL.md](docs/TECHNICAL.md)** - 구현 상세, 아키텍처, 트러블슈팅 (전체 문서)

## 🤝 기여

Pull Request 환영합니다!

## 📜 라이센스

Apache 2.0 - Syzkaller 라이센스를 따릅니다.

## 👤 작성자

**Kernel Fuzzing Research**
- GitHub: [@summin02](https://github.com/summin02)
- 버전: v2.0
- 작성일: 2025-11-24


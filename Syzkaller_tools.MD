# Syzkaller Tools 스크립트 가이드

Syzkaller 프로젝트의 `tools/` 디렉토리에 있는 쉘 스크립트들에 대한 설명서입니다.

---

## 목차

1. [코드 검증 스크립트](#코드-검증-스크립트)
2. [이미지 생성 스크립트](#이미지-생성-스크립트)
3. [유틸리티 스크립트](#유틸리티-스크립트)

---

## 코드 검증 스크립트

CI/CD 파이프라인에서 코드 품질과 일관성을 검증하는 데 사용되는 스크립트들입니다.

### check-commits.sh

**기능**: 커밋 메시지 형식 검증

Pull Request에 포함된 커밋 메시지가 프로젝트의 규칙을 준수하는지 검사합니다.

**검사 규칙**:
- 제목 형식: `main/affected/package: short change description`
- 제목은 소문자로 시작하고 마침표로 끝나야 함
- 본문의 각 줄은 120자를 초과할 수 없음
- `Revert "` 로 시작하는 커밋은 예외 처리
- dependabot 자동 생성 커밋은 검사 제외

**사용법**:
```bash
./check-commits.sh
```

**환경 변수**:
- `GITHUB_PR_HEAD_SHA`: PR의 HEAD SHA
- `GITHUB_PR_COMMITS`: PR에 포함된 커밋 수

---

### check-copyright.sh

**기능**: Apache 2.0 저작권 헤더 검증

소스 파일에 필수 저작권 고지 및 라이센스 헤더가 포함되어 있는지 확인합니다.

**검사 대상 확장자**: `.go`, `.sh`, `.cc`, `.c`, `.h`, `.S`, `.py`, `.yaml`, `.fbs`, `Dockerfile`

**검사 내용**:
- `Copyright 20XX syzkaller project authors. All rights reserved.`
- `Use of this source code is governed by Apache 2 LICENSE...`

**예외 처리**:
- `Code generated` 주석이 있는 자동 생성 파일
- Git에서 추적되지 않는 파일

**사용법**:
```bash
./check-copyright.sh
```

---

### check-html.sh

**기능**: HTML 파일 공백 일관성 검사

HTML 파일에서 탭과 스페이스의 혼용을 감지합니다.

**검사 규칙**:
- 파일 내에서 탭과 스페이스 중 하나만 사용해야 함
- `Commit.Date` 패턴이 포함된 줄은 예외 처리

**사용법**:
```bash
./check-html.sh
```

---

### check-language.sh

**기능**: 포용적 언어 사용 검사

코드에서 구식 또는 비포용적 용어를 찾아 대체어를 제안합니다.

**감지 용어 및 권장 대체어**:
| 감지 용어 | 권장 대체어 |
|-----------|-------------|
| `blacklist/whitelist` | `block/allow/ignore/skip` |
| `slave` | `leader/follower/coordinator/worker/parent/helper` |

**검사 대상 확장자**: `.go`, `.sh`, `.c`, `.md`, `.S`, `.py`, `.yaml`

**사용법**:
```bash
./check-language.sh
```

---

### check-shebang.sh

**기능**: Shebang 이식성 검사

실행 가능한 파일의 shebang이 이식 가능한 형식인지 확인합니다.

**허용되는 형식**:
- `#!/bin/sh`
- `#!/usr/bin/env [interpreter]`

**사용법**:
```bash
./check-shebang.sh
```

---

### check-syzos.sh

**기능**: SYZOS 게스트 섹션 데이터 재배치 검사

`syz-executor` 바이너리에서 "guest" ELF 섹션 내 문제가 될 수 있는 데이터 재배치를 검증합니다.

**지원 아키텍처**: `amd64`, `arm64`

**검사 내용**:
- **amd64**: RIP 상대 주소 지정 명령어 검사
- **arm64**: `adrp` 명령어 검사

**사용법**:
```bash
TARGETOS=linux TARGETARCH=amd64 ./check-syzos.sh
```

**환경 변수**:
- `TARGETOS`: 대상 OS (linux 필수)
- `TARGETARCH`: 대상 아키텍처 (amd64 또는 arm64)

---

### check-whitespace.sh

**기능**: 공백 스타일 검사

파일의 공백 관련 문제를 감지합니다.

**검사 항목**:
- 줄 끝의 불필요한 공백 (trailing whitespace)
- 파일 끝의 불필요한 빈 줄

**검사 대상 확장자**: `.sh`, `.S`, `.py`, `.yaml`, `.md`

**사용법**:
```bash
./check-whitespace.sh
```

---

## 이미지 생성 스크립트

커널 퍼징을 위한 VM 디스크 이미지를 생성하는 스크립트들입니다.

### create-image.sh

**기능**: Debian 기반 최소 Linux 디스크 이미지 생성

Syzkaller 커널 퍼징에 최적화된 Debian Linux 디스크 이미지를 자동 생성합니다.

**주요 작업**:
- debootstrap을 사용한 Debian 시스템 부트스트랩
- SSH 키 생성 및 비밀번호 없는 root 접근 설정
- 네트워킹 및 파일시스템 마운트 구성
- 선택적 perf 도구 빌드

**사용법**:
```bash
./create-image.sh [옵션]
```

**주요 옵션**:
| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-a, --arch` | 대상 아키텍처 | 호스트 아키텍처 |
| `-d, --distribution` | Debian 릴리스 버전 | trixie |
| `-f, --feature` | 패키지 세트 (minimal/full) | minimal |
| `-o, --output` | 출력 파일명 접두사 | - |
| `-p, --add-perf` | perf 도구 포함 | - |
| `-s, --seek` | 디스크 이미지 크기(MB) | 2048 |
| `-h, --help` | 도움말 표시 | - |

**환경 변수**:
- `ADD_PACKAGE`: 추가로 설치할 패키지 (쉼표 구분)
- `KERNEL`: 커널 소스 트리 경로 (`-p` 사용 시 필수)
- `http_proxy`, `https_proxy`, `ftp_proxy`, `no_proxy`: 프록시 설정

**출력 파일**:
- `<output>/`: 루트 파일시스템 디렉토리
- `<output>.img`: 부팅 가능한 디스크 이미지
- `<output>.id_rsa`, `<output>.id_rsa.pub`: SSH 키 쌍

---

### create-buildroot-image.sh

**기능**: Buildroot 기반 Linux 이미지 생성

다양한 CPU 아키텍처를 위한 최소 Linux 시스템 이미지를 Buildroot를 사용하여 생성합니다.

**지원 아키텍처**: `amd64`, `arm64`, `arm`, `riscv64`, `s390x`, `mips64le`, `ppc64le`

**사용법**:
```bash
TARGETARCH={아키텍처} [NOMAKE=yes] ./create-buildroot-image.sh
```

**환경 변수**:
| 변수 | 설명 | 기본값 |
|------|------|--------|
| `TARGETARCH` | CPU 아키텍처 (필수) | amd64 |
| `NOMAKE` | `yes` 설정 시 빌드 없이 설정만 수행 | - |
| `LINUX_VERSION` | 커널 버전 | 6.18.6 |
| `LINUX_KERNEL_CONFIG` | 커스텀 커널 설정 파일 경로 | - |

**출력**:
- **amd64/arm64**: `output/images/disk.img` (부팅 가능)
- **기타 아키텍처**: `output/images/rootfs.ext4` (QEMU 주입용)

**요구사항**: 커널 버전 4.19 이상

---

### create-gce-image.sh

**기능**: Google Compute Engine용 디스크 이미지 생성

GCE에서 Syzkaller를 실행하기 위한 최소 부팅 가능 디스크 이미지를 생성합니다.

**사용법**:
```bash
./create-gce-image.sh /userspace/path /path/to/kernel [arch]
```

**인자**:
| 인자 | 설명 |
|------|------|
| 1 | Debian 기반 사용자 공간 파일시스템 경로 |
| 2 | 커널 이미지 경로 (bzImage 또는 zImage) |
| 3 | 아키텍처 (선택, 기본값: amd64) |

**지원 아키텍처**: `386`, `amd64`, `s390x`, `ppc64le`

**환경 변수**:
- `SYZ_SYSCTL_FILE`: `/etc/sysctl.conf`에 추가할 내용이 담긴 파일
- `SYZ_CMDLINE_FILE`: 커널 명령줄에 추가할 내용이 담긴 파일
- `MKE2FS_CONFIG`: mkfs.ext4 설정

**출력**: `disk.raw`

**GCE 업로드**:
```bash
tar -Sczf disk.tar.gz disk.raw
gsutil cp disk.tar.gz gs://my-images/image.tar.gz
```

---

### create-ec2-rootfs.sh

**기능**: Amazon EC2용 루트 파일시스템 이미지 생성

Amazon Linux 2023 컨테이너에서 EC2 또는 QEMU 테스트 환경용 루트 파일시스템을 생성합니다.

**사용법**:
```bash
./create-ec2-rootfs.sh [옵션]
```

**옵션**:
| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-f, --format` | 파일시스템 유형 (ext4/xfs) | ext4 |
| `-n, --name` | 출력 이미지 파일명 | rootfs.ext4 |
| `-p, --platform` | 컨테이너 플랫폼 아키텍처 | linux/amd64 |
| `-s, --size` | 파일시스템 크기 | 1G |
| `-h, --help` | 도움말 표시 | - |

**예시**:
```bash
./create-ec2-rootfs.sh -f xfs -n rootfs.xfs -s 2G
```

**특징**:
- 기존 이미지가 있으면 재생성 없이 크기만 확장
- systemd 네트워킹 및 DHCP 설정
- 비밀번호 없는 SSH root 접근 활성화

---

### create-openbsd-gce-ci.sh

**기능**: GCE용 OpenBSD 이미지 생성

Syzkaller가 사전 설치된 OpenBSD Google Compute Engine 디스크 이미지를 자동 생성합니다.

**주요 작업**:
1. OpenBSD 스냅샷 ISO 다운로드
2. 개발 도구 포함 커스텀 설치 패키지 생성 (bash, GCC, Git, Go, LLVM 등)
3. 자동 설치 스크립트로 ISO 패치
4. QEMU를 사용한 자동 설치 실행
5. GCE 배포용 디스크 이미지 압축

**사용법**:
```bash
./create-openbsd-gce-ci.sh [release_number]
```

**환경 변수**:
- `MIRROR`: CDN 미러 URL (기본값: `cdn.openbsd.org`)

**요구사항**: QEMU, expect, growisofs

---

### create-openbsd-vmm-worker.sh

**기능**: OpenBSD VMM 워커 이미지 생성

Syzkaller 커널 퍼저 실행을 위한 최소 OpenBSD 디스크 이미지를 생성합니다.

**주요 작업**:
1. OpenBSD 스냅샷 ISO 다운로드
2. SSH 설정, sysctl 튜닝, 네트워크 설정이 포함된 커스텀 설치 세트 생성
3. 자동 설치를 위한 ISO 패치
4. QEMU와 expect를 사용한 자동 설치

**사용법**:
```bash
./create-openbsd-vmm-worker.sh [RELNO]
```

**인자**:
- `RELNO` (선택): OpenBSD 릴리스 번호 (기본값: 자동 감지)

**환경 변수**:
- `MIRROR`: OpenBSD 미러 URL (기본값: `cdn.openbsd.org`)

**출력**: `worker_disk.raw` (1500MB 부팅 가능 디스크 이미지)

---

## 유틸리티 스크립트

기타 Syzkaller 관련 유틸리티 스크립트들입니다.

### demo_setup.sh

**기능**: Syzkaller 데모 환경 자동 설치

Syzkaller 커널 퍼징 도구의 완전한 설치 및 설정을 자동화합니다.

**주요 작업**:
1. apt-get을 통한 의존성 설치 (빌드 도구, QEMU, KVM 지원)
2. Go 1.10.1 및 GCC 7 다운로드/설치
3. Debian Wheezy VM 이미지 및 SSH 키 다운로드
4. GitHub에서 syzkaller 빌드
5. Linux 커널 (v4.13) 컴파일
6. 퍼징 매니저 설정 파일 생성
7. syz-manager 실행

**사용법**:
```bash
./demo_setup.sh
```

**요구사항**:
- BIOS 및 커널에서 KVM 활성화
- root/sudo 권한
- 인터넷 연결 (약 2GB 다운로드)

**대상 시스템**: Ubuntu 16.04, Debian

**출력**:
- 퍼저 실행 시 웹 UI 접근: `http://localhost:20000`

---

### gvisor-smoke-test.sh

**기능**: gVisor에서 Syzkaller 스모크 테스트 실행

Google의 경량 컨테이너 런타임 샌드박스인 gVisor에서 Syzkaller 스모크 테스트를 설정하고 실행합니다.

**주요 작업**:
1. 임시 작업 디렉토리 생성
2. syzkaller 설정 파일 생성 (Linux x86_64, gVisor VM)
3. 커널 바이너리 준비 (다운로드 또는 사용자 제공)
4. 스모크 테스트 모드로 syzkaller 매니저 실행

**사용법**:
```bash
./gvisor-smoke-test.sh
```

**환경 변수**:
- `GVISOR_VMLINUX_PATH` (선택): 커스텀 커널 바이너리 경로. 미설정 시 최신 gVisor 릴리스 커널 다운로드

**요구사항**:
- sudo 권한
- curl
- `./bin/` 디렉토리에 Syzkaller 바이너리

---

### syz-bq.sh

**기능**: BigQuery 커버리지 데이터 병합 관리

지정된 기간의 커버리지 데이터를 대시보드 시스템으로 병합하기 위해 Linux 커널 리포지토리를 준비하고 병합을 조율합니다.

**사용법**:
```bash
./syz-bq.sh -w <작업디렉토리> -d <일수> -t <날짜> -n <네임스페이스> \
            -r <리포지토리> -b <브랜치> -c <클라이언트>
```

**필수 인자**:
| 플래그 | 설명 |
|--------|------|
| `-w` | 작업 디렉토리 경로 |
| `-d` | 커버리지 분석 기간 (일) |
| `-t` | 대상 날짜 (YYYY-MM-DD 형식) |
| `-n` | BigQuery 네임스페이스/테이블명 |
| `-r` | Git 리포지토리 URL |
| `-b` | Git 브랜치명 |
| `-c` | 대시보드 클라이언트 식별자 |

**예시**:
```bash
./syz-bq.sh -w /tmp/work -d 7 -t 2024-01-15 -n my_namespace \
  -r https://github.com/torvalds/linux -b master -c my_client
```

**요구사항**: `bq` (BigQuery CLI), `git`

---

### syz-reproducers.sh

**기능**: 커널 버그 재현자 다운로드 및 빌드

Syzkaller 프로젝트의 아티팩트 저장소에서 커널 버그 재현자를 다운로드하고 컴파일합니다.

**주요 작업**:
1. Google 아티팩트 스토리지에서 재현자 압축 파일 다운로드
2. 대상 디렉토리에 압축 해제
3. 병렬 컴파일 (최대 128개 동시 프로세스)로 C 프로그램을 정적 바이너리로 빌드
4. 32비트/64비트 요구사항 자동 감지
5. 결과 통계 보고

**사용법**:
```bash
./syz-reproducers.sh <대상_디렉토리>
```

**예시**:
```bash
./syz-reproducers.sh ./syzkaller_reproducers
```

**요구사항**: `wget`, `tar`, `gcc`

**출력**:
- 다운로드된 재현자 총 개수
- 성공적으로 컴파일된 재현자 개수

---

## 요약 테이블

| 스크립트 | 카테고리 | 주요 기능 |
|----------|----------|-----------|
| `check-commits.sh` | 검증 | 커밋 메시지 형식 검사 |
| `check-copyright.sh` | 검증 | Apache 2.0 라이센스 헤더 검사 |
| `check-html.sh` | 검증 | HTML 파일 공백 일관성 검사 |
| `check-language.sh` | 검증 | 포용적 언어 사용 검사 |
| `check-shebang.sh` | 검증 | Shebang 이식성 검사 |
| `check-syzos.sh` | 검증 | SYZOS 게스트 섹션 검사 |
| `check-whitespace.sh` | 검증 | 공백 스타일 검사 |
| `create-image.sh` | 이미지 | Debian 디스크 이미지 생성 |
| `create-buildroot-image.sh` | 이미지 | Buildroot 이미지 생성 |
| `create-gce-image.sh` | 이미지 | GCE용 이미지 생성 |
| `create-ec2-rootfs.sh` | 이미지 | EC2용 루트 파일시스템 생성 |
| `create-openbsd-gce-ci.sh` | 이미지 | GCE용 OpenBSD 이미지 생성 |
| `create-openbsd-vmm-worker.sh` | 이미지 | OpenBSD VMM 워커 이미지 생성 |
| `demo_setup.sh` | 유틸리티 | Syzkaller 데모 환경 설치 |
| `gvisor-smoke-test.sh` | 유틸리티 | gVisor 스모크 테스트 |
| `syz-bq.sh` | 유틸리티 | BigQuery 커버리지 병합 |
| `syz-reproducers.sh` | 유틸리티 | 버그 재현자 다운로드/빌드 |

---

## 참고 자료

- [Syzkaller GitHub Repository](https://github.com/google/syzkaller)
- [Syzkaller Documentation](https://github.com/google/syzkaller/blob/master/docs/README.md)

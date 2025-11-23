#!/bin/bash
set -e

echo "========================================="
echo "Syzkaller OOB Fuzzer 설치 시작"
echo "========================================="

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 현재 디렉토리
PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$PROJ_DIR/workspace"

echo -e "${GREEN}[1/7]${NC} 작업 디렉토리 생성..."
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo -e "${GREEN}[2/7]${NC} Syzkaller 클론..."
if [ ! -d "syzkaller" ]; then
    git clone https://github.com/google/syzkaller
    echo "✓ Syzkaller 클론 완료"
else
    echo "✓ Syzkaller 이미 존재"
fi

echo -e "${GREEN}[3/7]${NC} Go 1.24 다운로드..."
if [ ! -d "go" ]; then
    wget -q https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
    tar -xzf go1.24.0.linux-amd64.tar.gz
    rm go1.24.0.linux-amd64.tar.gz
    echo "✓ Go 설치 완료"
else
    echo "✓ Go 이미 설치됨"
fi

export PATH="$WORK_DIR/go/bin:$PATH"
export GOROOT="$WORK_DIR/go"

echo -e "${GREEN}[4/7]${NC} Linux 커널 다운로드 (간소화 버전)..."
if [ ! -d "linux" ]; then
    echo "※ 커널은 직접 준비하거나 기존 커널을 사용하세요"
    echo "  예: /usr/src/linux-6.17.8"
fi

echo -e "${GREEN}[5/7]${NC} 패치 적용..."
cd syzkaller

# custom_oob.txt 복사
cp "$PROJ_DIR/patches/custom_oob.txt" sys/linux/

# common_linux.h 패치 적용
if [ -f "$PROJ_DIR/patches/common_linux.h.patch" ]; then
    patch -p1 < "$PROJ_DIR/patches/common_linux.h.patch" || echo "패치 이미 적용됨"
fi

# mutation.go 패치 적용
if [ -f "$PROJ_DIR/patches/mutation.go.patch" ]; then
    patch -p1 < "$PROJ_DIR/patches/mutation.go.patch" || echo "패치 이미 적용됨"
fi

echo "✓ 패치 적용 완료"

echo -e "${GREEN}[6/7]${NC} 설정 파일 생성..."
cd "$WORK_DIR"
cp "$PROJ_DIR/configs/oob_fuzzer.cfg.template" oob_fuzzer.cfg

# 경로 자동 업데이트
sed -i "s|WORK_DIR_PLACEHOLDER|$WORK_DIR|g" oob_fuzzer.cfg

echo "✓ 설정 파일 생성 완료"

echo -e "${GREEN}[7/7]${NC} 초기화 완료!"

echo ""
echo "========================================="
echo -e "${GREEN}✅ 설치 완료!${NC}"
echo "========================================="
echo ""
echo "다음 단계:"
echo "  1. ./build.sh - 빌드"
echo "  2. ./run.sh - 실행"
echo ""
echo "작업 디렉토리: $WORK_DIR"
echo "========================================="

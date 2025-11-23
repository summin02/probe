#!/bin/bash
set -e

GREEN='\033[0;32m'
NC='\033[0m'

PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$PROJ_DIR/workspace"
SYZ_DIR="$WORK_DIR/syzkaller"

if [ ! -d "$SYZ_DIR" ]; then
    echo "❌ Syzkaller가 없습니다. 먼저 ./setup.sh를 실행하세요."
    exit 1
fi

export PATH="$WORK_DIR/go/bin:$PATH"
export GOROOT="$WORK_DIR/go"

cd "$SYZ_DIR"

echo "========================================="
echo "Syzkaller OOB Fuzzer 빌드"
echo "========================================="

echo -e "${GREEN}[1/4]${NC} Syscall 정의 생성..."
make generate
echo "✓ 생성 완료"

echo -e "${GREEN}[2/4]${NC} Executor 빌드..."
make executor
echo "✓ Executor 빌드 완료"

echo -e "${GREEN}[3/4]${NC} 전체 빌드..."
make
echo "✓ 전체 빌드 완료"

echo -e "${GREEN}[4/4]${NC} 심볼 확인..."
SYMBOLS=$(nm bin/linux_amd64/syz-executor 2>/dev/null | grep -c syz_oob || echo "0")
echo "✓ OOB 심볼: $SYMBOLS개 발견"

echo ""
echo "========================================="
echo -e "${GREEN}✅ 빌드 완료!${NC}"
echo "========================================="
echo ""
echo "다음 단계:"
echo "  ./run.sh - Fuzzer 실행"
echo ""

#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$PROJ_DIR/workspace"
SYZ_DIR="$WORK_DIR/syzkaller"
CFG_FILE="$WORK_DIR/oob_fuzzer.cfg"

if [ ! -f "$SYZ_DIR/bin/syz-manager" ]; then
    echo "❌ syz-manager가 없습니다. 먼저 ./build.sh를 실행하세요."
    exit 1
fi

if [ ! -f "$CFG_FILE" ]; then
    echo "❌ 설정 파일이 없습니다. ./setup.sh를 다시 실행하세요."
    exit 1
fi

export PATH="$WORK_DIR/go/bin:$PATH"

echo "========================================="
echo "Syzkaller OOB Fuzzer 실행"
echo "========================================="

# 기존 프로세스 종료
if pgrep -f syz-manager > /dev/null; then
    echo -e "${YELLOW}기존 fuzzer 종료 중...${NC}"
    sudo pkill -9 syz-manager || true
    sleep 2
fi

# 작업 디렉토리 생성
mkdir -p "$WORK_DIR/workdir"

cd "$SYZ_DIR"

echo -e "${GREEN}Fuzzer 시작...${NC}"
echo ""
echo "설정 파일: $CFG_FILE"
echo "작업 디렉토리: $WORK_DIR/workdir"
echo ""

sudo ./bin/syz-manager -config "$CFG_FILE" &
FUZZER_PID=$!

sleep 3

if ps -p $FUZZER_PID > /dev/null; then
    echo ""
    echo "========================================="
    echo -e "${GREEN}✅ Fuzzer 실행 중!${NC}"
    echo "========================================="
    echo ""
    echo "웹 UI: http://127.0.0.1:56741"
    echo "PID: $FUZZER_PID"
    echo ""
    echo "종료: sudo kill $FUZZER_PID"
    echo "로그: tail -f $WORK_DIR/workdir/syz-manager.log"
    echo "========================================="
else
    echo "❌ Fuzzer 시작 실패"
    echo "로그 확인: cat $WORK_DIR/workdir/syz-manager.log"
    exit 1
fi

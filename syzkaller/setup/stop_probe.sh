#!/bin/bash
echo "Stopping PROBE fuzzer and MOCK BiGRU server..."
sudo pkill -9 syz-manager 2>/dev/null
pkill -f "python.*server.py" 2>/dev/null
echo "Done."

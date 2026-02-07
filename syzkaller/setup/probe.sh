#!/bin/bash
sudo pkill -9 syz-manager
echo "Starting PROBE fuzzer with probe.cfg"
/home/sumin/probe/syzkaller/bin/syz-manager -config /home/sumin/probe/syzkaller/setup/probe.cfg 2>&1 | tee /home/sumin/probe/syzkaller/probe_log/probe_run.log

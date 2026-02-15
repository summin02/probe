// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: BPF type definitions for kernel heap monitoring and vulnerability detection.
// Phase 7: CO-RE (Compile Once, Run Everywhere) — uses vmlinux.h + libbpf headers
// for portable kprobe access to kernel structures (cred, kmem_cache, etc.).

#ifndef PROBE_EBPF_BPF_H
#define PROBE_EBPF_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Shared metrics structure (read by executor).
// Phase 5 fields (8) + Phase 7 fields (3).
struct probe_metrics {
	__u64 alloc_count;
	__u64 free_count;
	__u64 reuse_count;       // slab reuses detected
	__u64 rapid_reuse_count; // reuses < 100us
	__u64 min_reuse_delay_ns; // fastest reuse (lower = more exploitable)
	__u64 double_free_count;      // double-free detected
	__u64 size_mismatch_count;    // heuristic cross-cache
	__u64 execution_start_ns;     // epoch for stale filtering
	// Phase 7:
	__u64 commit_creds_count;     // 7d: commit_creds() calls
	__u64 priv_esc_count;         // 7d: uid!=0 → uid==0 transitions
	__u64 cross_cache_count;      // 7c: precise cross-cache (different kmem_cache)
};

// 7b': Per-call-site alloc/free statistics for AI strategy.
struct site_stats {
	__u64 alloc_count;
	__u64 free_count;
};

#endif // PROBE_EBPF_BPF_H

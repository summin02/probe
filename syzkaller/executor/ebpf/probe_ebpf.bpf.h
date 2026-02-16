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

// PERF_MAX_STACK_DEPTH is a #define in uapi/linux/perf_event.h,
// not exported via BTF/vmlinux.h. Define it for stack_traces map.
#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

// Shared metrics structure (read by executor).
// Phase 5 fields (8) + Phase 7 fields (3) + Phase 8a fields (1) + Phase 9b fields (3) + Phase 9d fields (3) + Phase 9c fields (1).
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
	// Phase 8a:
	__u64 write_to_freed_count;   // 8a: writes to freed slab objects via copy_from_user
	// Phase 9b: Page-level UAF / Dirty Pagetable detection
	__u64 page_alloc_count;          // 9b: mm_page_alloc tracepoint hits
	__u64 page_free_count;           // 9b: mm_page_free tracepoint hits
	__u64 page_reuse_count;          // 9b: freed page reallocated within execution
	// Phase 9d: FD lifecycle tracking
	__u64 fd_install_count;          // 9d: __fd_install kprobe hits
	__u64 fd_close_count;            // 9d: close_fd kprobe hits
	__u64 fd_reuse_count;            // 9d: recently-closed FD number reused
	// Phase 9c: Context-sensitive coverage
	__u64 context_unique_stacks;     // 9c: unique (event, stack_id) pairs observed
};

// 7b': Per-call-site alloc/free statistics for AI strategy.
struct site_stats {
	__u64 alloc_count;
	__u64 free_count;
};

#endif // PROBE_EBPF_BPF_H

// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: eBPF program for kernel heap monitoring.
// Hooks kmem/kfree and kmem/kmalloc tracepoints to track slab object lifecycle
// and detect rapid slab reuse (UAF-favorable pattern).
//
// Build:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//       -c executor/probe_ebpf.bpf.c -o executor/probe_ebpf.bpf.o

#include "probe_ebpf.bpf.h"

// Recently freed objects: ptr → free_timestamp (ktime_ns).
// LRU hash auto-evicts old entries, preventing unbounded growth.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64);
} freed_objects SEC(".maps");

// Per-execution metrics (single entry, read+reset by executor between programs).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct probe_metrics);
} metrics SEC(".maps");

// Hook: tracepoint/kmem/kfree
// Record freed object pointer with timestamp. Detect double-free.
SEC("tracepoint/kmem/kfree")
int trace_kfree(struct trace_event_raw_kfree *ctx)
{
	__u64 ptr = (__u64)ctx->ptr;
	if (ptr == 0)
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);

	// Double-free: ptr already in freed_objects (freed without intervening alloc)
	__u64 *existing = bpf_map_lookup_elem(&freed_objects, &ptr);
	if (existing && m)
		__sync_fetch_and_add(&m->double_free_count, 1);

	__u64 ts = bpf_ktime_get_ns();

	// Record this freed pointer with its timestamp
	bpf_map_update_elem(&freed_objects, &ptr, &ts, BPF_ANY);

	// Update free count in metrics
	if (m)
		__sync_fetch_and_add(&m->free_count, 1);

	return 0;
}

// Hook: tracepoint/kmem/kmalloc
// Check if the returned pointer was recently freed → slab reuse detected.
// Also detect size mismatch (cross-cache potential).
SEC("tracepoint/kmem/kmalloc")
int trace_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
	__u64 ptr = (__u64)ctx->ptr;
	if (ptr == 0)
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m)
		return 0;

	// Increment alloc count
	__sync_fetch_and_add(&m->alloc_count, 1);

	// Size mismatch: alloc >> req suggests cross-cache or slab waste
	__u64 req = (__u64)ctx->bytes_req;
	__u64 alloc = (__u64)ctx->bytes_alloc;
	if (req > 0 && alloc > 2 * req && alloc >= 128)
		__sync_fetch_and_add(&m->size_mismatch_count, 1);

	// Check if this pointer was recently freed (slab reuse)
	__u64 *free_ts = bpf_map_lookup_elem(&freed_objects, &ptr);
	if (!free_ts)
		return 0;

	// Epoch filter: ignore freed pointers from previous program executions.
	// execution_start_ns is set by the executor before each program runs.
	// If the free happened before the current execution started, it's
	// cross-program contamination — not a real reuse within this program.
	__u64 exec_start = m->execution_start_ns;
	if (exec_start > 0 && *free_ts < exec_start) {
		bpf_map_delete_elem(&freed_objects, &ptr);
		return 0;
	}

	// Slab reuse detected (within current execution)!
	__u64 now = bpf_ktime_get_ns();
	__u64 delay = now - *free_ts;

	__sync_fetch_and_add(&m->reuse_count, 1);

	// Rapid reuse: < 100 microseconds (100,000 ns)
	if (delay < 100000)
		__sync_fetch_and_add(&m->rapid_reuse_count, 1);

	// Track minimum reuse delay (lower = more exploitable).
	// Use compare-and-swap loop for atomic min.
	__u64 cur_min = m->min_reuse_delay_ns;
	if (cur_min == 0 || delay < cur_min) {
		// Best-effort atomic min (CAS may fail under contention, that's OK)
		__sync_val_compare_and_swap(&m->min_reuse_delay_ns, cur_min, delay);
	}

	// Remove from freed_objects to avoid double-counting
	bpf_map_delete_elem(&freed_objects, &ptr);

	return 0;
}

char _license[] SEC("license") = "GPL";

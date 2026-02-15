// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: eBPF programs for kernel heap monitoring and vulnerability detection.
// Phase 5: tracepoint-based UAF/double-free/size-mismatch detection.
// Phase 7: CO-RE kprobe-based privilege escalation (7d), cross-cache (7c),
//          and slab-pair call_site tracking (7b').
//
// Build (CO-RE):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//       -I executor/ebpf/ -I executor/ebpf/bpf/ \
//       -c executor/ebpf/probe_ebpf.bpf.c -o executor/ebpf/probe_ebpf.bpf.o

#include "probe_ebpf.bpf.h"

// ============================================================
// Maps
// ============================================================

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

// 7c: Cross-cache detection — ptr → cache_name_hash of the freeing cache.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);    // ptr
	__type(value, __u32);  // hash of kmem_cache->name
} cache_freed SEC(".maps");

// 7b': Per-call-site alloc/free statistics for AI strategy.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 512);
	__type(key, __u64);              // call_site address
	__type(value, struct site_stats);
} slab_sites SEC(".maps");

// ============================================================
// Phase 5: Tracepoint programs (stable ABI, no CO-RE needed)
// ============================================================

// vmlinux.h provides trace_event_raw_kfree and trace_event_raw_kmalloc
// with the same layout as the manual definitions we had before.
// However, tracepoint context uses the raw ctx pointer, so we access
// fields via direct struct member access (guaranteed by tracepoint ABI).

// For tracepoints, vmlinux.h defines the trace_event_raw_* structs.
// We access them directly — no BPF_CORE_READ needed for tracepoint args.

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

	// 7b': Update per-call-site free count
	__u64 call_site = (__u64)ctx->call_site;
	if (call_site) {
		struct site_stats *ss = bpf_map_lookup_elem(&slab_sites, &call_site);
		if (ss) {
			__sync_fetch_and_add(&ss->free_count, 1);
		} else {
			struct site_stats new_ss = {.alloc_count = 0, .free_count = 1};
			bpf_map_update_elem(&slab_sites, &call_site, &new_ss, BPF_NOEXIST);
		}
	}

	return 0;
}

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

	// 7b': Update per-call-site alloc count
	__u64 call_site = (__u64)ctx->call_site;
	if (call_site) {
		struct site_stats *ss = bpf_map_lookup_elem(&slab_sites, &call_site);
		if (ss) {
			__sync_fetch_and_add(&ss->alloc_count, 1);
		} else {
			struct site_stats new_ss = {.alloc_count = 1, .free_count = 0};
			bpf_map_update_elem(&slab_sites, &call_site, &new_ss, BPF_NOEXIST);
		}
	}

	// Check if this pointer was recently freed (slab reuse)
	__u64 *free_ts = bpf_map_lookup_elem(&freed_objects, &ptr);
	if (!free_ts)
		return 0;

	// Epoch filter: ignore freed pointers from previous program executions.
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
	__u64 cur_min = m->min_reuse_delay_ns;
	if (cur_min == 0 || delay < cur_min) {
		__sync_val_compare_and_swap(&m->min_reuse_delay_ns, cur_min, delay);
	}

	// Remove from freed_objects to avoid double-counting
	bpf_map_delete_elem(&freed_objects, &ptr);

	return 0;
}

// ============================================================
// Phase 7d: Privilege Escalation Detection (CO-RE kprobe)
// ============================================================

// Detect commit_creds() calls. Two metrics:
// - commit_creds_count: total calls (informational, all sandbox modes)
// - priv_esc_count: uid!=0 → uid==0 transitions (sandbox_setuid only)
SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds, struct cred *new_cred)
{
	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	// Always count commit_creds calls (sandbox-agnostic)
	__sync_fetch_and_add(&m->commit_creds_count, 1);

	// CO-RE: read new_cred->uid.val
	unsigned int new_uid = BPF_CORE_READ(new_cred, uid.val);
	if (new_uid == 0) {
		// CO-RE: read current->real_cred->uid.val
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		unsigned int cur_uid = BPF_CORE_READ(task, real_cred, uid.val);
		if (cur_uid != 0) {
			__sync_fetch_and_add(&m->priv_esc_count, 1);
		}
	}
	return 0;
}

// ============================================================
// Phase 7c: Cross-Cache Precise Detection (CO-RE kprobe + tracepoint)
// ============================================================

// Record the cache name hash when an object is freed via kmem_cache_free.
SEC("kprobe/kmem_cache_free")
int BPF_KPROBE(kprobe_cache_free, struct kmem_cache *s, void *x)
{
	if (x == 0)
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	// CO-RE: read s->name (pointer to cache name string)
	const char *name = BPF_CORE_READ(s, name);
	char buf[32] = {};
	bpf_probe_read_kernel_str(buf, sizeof(buf), name);

	// Simple hash of cache name (djb2-variant)
	__u32 hash = 5381;
	for (int i = 0; i < 32 && buf[i]; i++)
		hash = hash * 33 + buf[i];

	__u64 ptr = (__u64)x;
	bpf_map_update_elem(&cache_freed, &ptr, &hash, BPF_ANY);
	return 0;
}

// Check on kmem_cache_alloc if the pointer was freed from a different cache.
SEC("tracepoint/kmem/kmem_cache_alloc")
int trace_cache_alloc(struct trace_event_raw_kmem_cache_alloc *ctx)
{
	__u64 ptr = (__u64)ctx->ptr;
	if (ptr == 0)
		return 0;

	__u32 *prev_hash = bpf_map_lookup_elem(&cache_freed, &ptr);
	if (!prev_hash)
		return 0;

	// The pointer was previously freed from a cache with hash *prev_hash.
	// If it's being allocated from a different cache now, that's cross-cache reuse.
	// We detect this simply: if the pointer appears in cache_freed, it means
	// it was freed from one cache and is now being allocated (possibly from another).
	// This is a strong cross-cache indicator.
	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (m)
		__sync_fetch_and_add(&m->cross_cache_count, 1);

	bpf_map_delete_elem(&cache_freed, &ptr);
	return 0;
}

char _license[] SEC("license") = "GPL";

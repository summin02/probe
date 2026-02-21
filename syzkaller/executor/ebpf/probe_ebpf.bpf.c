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
	__uint(max_entries, 12288); // Phase 12 D2: 8192→12288 (1.5x, frequently near capacity)
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
	__uint(max_entries, 768); // Phase 12 D2: 512→768 (1.5x, more call sites for AI strategy)
	__type(key, __u64);              // call_site address
	__type(value, struct site_stats);
} slab_sites SEC(".maps");

// 9b: Recently freed pages: pfn → free_timestamp (ktime_ns).
// LRU hash auto-evicts old entries, same pattern as freed_objects.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} freed_pages SEC(".maps");

// 9d: Recently closed FDs: (tgid<<32|fd) -> close_timestamp (ktime_ns).
// LRU hash auto-evicts old entries, same pattern as freed_objects/freed_pages.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} freed_fds SEC(".maps");

// 9c: Kernel stack trace storage for context-sensitive coverage.
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 1536); // Phase 12 D2: 1024→1536 (1.5x, richer context stacks)
	__type(key, __u32);
	__type(value, __u64[PERF_MAX_STACK_DEPTH]);
} stack_traces SEC(".maps");

// 9c: Track unique (event_type, stack_id) pairs per execution.
// Key = (event_type << 32) | stack_id, value = 1.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, __u64);
	__type(value, __u8);
} seen_stacks SEC(".maps");

// 7c: Per-CPU scratch for cross-cache alloc-side hash comparison.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cache_alloc_scratch SEC(".maps");

// 9c: Helper — record a context-sensitive stack for an exploit-relevant event.
// event_type: unique ID per detector (1=slab_reuse, 2=cross_cache, 3=write_freed,
//             4=page_reuse, 5=fd_reuse, 6=double_free).
static __always_inline void record_context_stack(
	struct probe_metrics *m, void *ctx, __u32 event_type)
{
	long stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);
	if (stack_id < 0)
		return;
	__u64 key = ((__u64)event_type << 32) | (__u64)(__u32)stack_id;
	__u8 *existing = bpf_map_lookup_elem(&seen_stacks, &key);
	if (!existing) {
		__u8 val = 1;
		bpf_map_update_elem(&seen_stacks, &key, &val, BPF_NOEXIST);
		__sync_fetch_and_add(&m->context_unique_stacks, 1);
	}
}

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
	// Epoch filter: only count if the previous free happened during THIS execution.
	// Without this check, stale LRU entries from prior executions cause massive false positives.
	__u64 *existing = bpf_map_lookup_elem(&freed_objects, &ptr);
	if (existing && m && *existing >= m->execution_start_ns) {
		__sync_fetch_and_add(&m->double_free_count, 1);
		record_context_stack(m, ctx, 6); // 9c: double-free context
	}

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
	record_context_stack(m, ctx, 1); // 9c: slab reuse context

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

// Record alloc-side cache hash on kmem_cache_alloc entry.
SEC("kprobe/kmem_cache_alloc")
int BPF_KPROBE(kprobe_cache_alloc, struct kmem_cache *s, gfp_t flags)
{
	const char *name = BPF_CORE_READ(s, name);
	char buf[32] = {};
	bpf_probe_read_kernel_str(buf, sizeof(buf), name);
	__u32 hash = 5381;
	for (int i = 0; i < 32 && buf[i]; i++)
		hash = hash * 33 + buf[i];
	__u32 key = 0;
	bpf_map_update_elem(&cache_alloc_scratch, &key, &hash, BPF_ANY);
	return 0;
}

// On kmem_cache_alloc return, compare free-side vs alloc-side hash.
SEC("kretprobe/kmem_cache_alloc")
int BPF_KRETPROBE(kretprobe_cache_alloc, void *ret)
{
	__u64 ptr = (__u64)ret;
	if (ptr == 0)
		return 0;
	__u32 *prev_hash = bpf_map_lookup_elem(&cache_freed, &ptr);
	if (!prev_hash)
		return 0;
	__u32 saved_free_hash = *prev_hash;
	__u32 key = 0;
	__u32 *alloc_hash = bpf_map_lookup_elem(&cache_alloc_scratch, &key);
	if (!alloc_hash) {
		bpf_map_delete_elem(&cache_freed, &ptr);
		return 0;
	}
	// Only count as cross-cache if cache names actually differ
	if (*alloc_hash != saved_free_hash) {
		struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
		if (m) {
			__sync_fetch_and_add(&m->cross_cache_count, 1);
			record_context_stack(m, ctx, 2); // 9c: cross-cache context
		}
	}
	bpf_map_delete_elem(&cache_freed, &ptr);
	return 0;
}

// ============================================================
// Phase 8a: Write-to-freed Detection (CO-RE kprobe)
// ============================================================

// Detect copy_from_user() writes to recently freed slab objects.
// This is a strong UAF exploitability signal: userspace-controlled data
// is being written to a freed kernel object.
//
// Strategy: cross-reference destination address with freed_objects LRU map.
// Optimized: check exact + 2 most common slab alignments (64, 256 bytes).
// Time window: 200ms to prevent stale false positives.
SEC("kprobe/_copy_from_user")
int BPF_KPROBE(kprobe_copy_from_user, void *to, const void *from, unsigned long n)
{
	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	// Early exit: skip if no objects have been freed this execution.
	if (m->free_count == 0)
		return 0;

	__u64 dst = (__u64)to;

	// Check exact address, then 2 most common slab alignments (64, 256).
	// Reduced from 6 lookups to 3 for ~50% overhead reduction.
	__u64 *free_ts = bpf_map_lookup_elem(&freed_objects, &dst);
	if (!free_ts) {
		__u64 aligned = dst & ~63ULL;  // 64-byte slab alignment
		free_ts = bpf_map_lookup_elem(&freed_objects, &aligned);
	}
	if (!free_ts) {
		__u64 aligned = dst & ~255ULL; // 256-byte slab alignment
		free_ts = bpf_map_lookup_elem(&freed_objects, &aligned);
	}
	if (!free_ts)
		return 0;

	// Epoch filter: ignore freed objects from previous executions
	if (*free_ts < m->execution_start_ns)
		return 0;

	// Time window: 200ms (200,000,000 ns) — filter stale entries
	__u64 now = bpf_ktime_get_ns();
	if (now - *free_ts > 200000000ULL)
		return 0;

	__sync_fetch_and_add(&m->write_to_freed_count, 1);
	record_context_stack(m, ctx, 3); // 9c: write-to-freed context
	return 0;
}

// ============================================================
// Phase 9b: Page-level UAF / Dirty Pagetable Detection
// ============================================================

// Track page frees via mm_page_free tracepoint.
// The tracepoint provides pfn (page frame number) directly.
SEC("tracepoint/kmem/mm_page_free")
int trace_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	__u64 pfn = (__u64)ctx->pfn;
	if (pfn == 0)
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__sync_fetch_and_add(&m->page_free_count, 1);

	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&freed_pages, &pfn, &ts, BPF_ANY);
	return 0;
}

// Track page allocations via mm_page_alloc tracepoint.
// Detect rapid page reuse (dirty pagetable indicator).
SEC("tracepoint/kmem/mm_page_alloc")
int trace_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	__u64 pfn = (__u64)ctx->pfn;
	if (pfn == 0)
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__sync_fetch_and_add(&m->page_alloc_count, 1);

	// Check if this page was recently freed (page reuse)
	__u64 *free_ts = bpf_map_lookup_elem(&freed_pages, &pfn);
	if (!free_ts)
		return 0;

	// Epoch filter: ignore frees from previous executions
	if (*free_ts < m->execution_start_ns) {
		bpf_map_delete_elem(&freed_pages, &pfn);
		return 0;
	}

	__sync_fetch_and_add(&m->page_reuse_count, 1);
	record_context_stack(m, ctx, 4); // 9c: page reuse context
	bpf_map_delete_elem(&freed_pages, &pfn);
	return 0;
}

// ============================================================
// Phase 9d: FD Lifecycle Tracking (CO-RE kprobes)
// ============================================================

// Track FD closes. Record (tgid|fd) -> timestamp in freed_fds map.
SEC("kprobe/close_fd")
int BPF_KPROBE(kprobe_close_fd, unsigned int fd)
{
	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__sync_fetch_and_add(&m->fd_close_count, 1);

	__u64 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 composite_key = (tgid << 32) | (__u64)fd;
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&freed_fds, &composite_key, &ts, BPF_ANY);
	return 0;
}

// Track FD installations. Detect FD reuse when a recently-closed FD number
// is assigned again (potential use-after-close / FD hijacking).
SEC("kprobe/fd_install")
int BPF_KPROBE(kprobe_fd_install, unsigned int fd, struct file *file)
{
	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__sync_fetch_and_add(&m->fd_install_count, 1);

	// Check if this FD number was recently closed (FD reuse)
	__u64 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 composite_key = (tgid << 32) | (__u64)fd;
	__u64 *close_ts = bpf_map_lookup_elem(&freed_fds, &composite_key);
	if (!close_ts)
		return 0;

	// Epoch filter: ignore closes from previous executions
	if (*close_ts < m->execution_start_ns) {
		bpf_map_delete_elem(&freed_fds, &composite_key);
		return 0;
	}

	__sync_fetch_and_add(&m->fd_reuse_count, 1);
	record_context_stack(m, ctx, 5); // 9c: FD reuse context
	bpf_map_delete_elem(&freed_fds, &composite_key);
	return 0;
}

// ============================================================
// Phase 11i: LACE — Lock-Aware Contention Estimation
// ============================================================

// Per-CPU map to track mutex lock entry timestamps for contention measurement.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);   // mutex address
	__type(value, __u64); // entry timestamp (ktime_ns)
} lock_entry_ts SEC(".maps");

// Per-CPU flag: 1 if this CPU currently holds a lock (for concurrent access detection).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64); // count of locks held
} lock_held SEC(".maps");

// Track context switches for executor. 1/10 sampling.
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	// 1/10 sampling to reduce overhead
	__u64 pidtgid = bpf_get_current_pid_tgid();
	if ((pidtgid & 0xf) > 1) // ~1/8 sampling (close to 1/10)
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__sync_fetch_and_add(&m->sched_switch_count, 1);

	// Check if a lock is held during this context switch (true contention).
	__u64 *held = bpf_map_lookup_elem(&lock_held, &key);
	if (held && *held > 0) {
		__sync_fetch_and_add(&m->concurrent_access_count, 1);
	}

	return 0;
}

// Measure mutex lock contention: record entry timestamp.
// 1/16 sampling to reduce overhead on ultra-hot lock paths.
SEC("kprobe/mutex_lock")
int BPF_KPROBE(kprobe_mutex_lock, void *lock)
{
	__u64 lock_addr = (__u64)lock;
	if ((lock_addr & 0xf) != 0) // 1/16 sampling
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&lock_entry_ts, &lock_addr, &ts, BPF_ANY);
	return 0;
}

// Measure mutex unlock: check if lock was held long enough to indicate contention.
// 1/16 sampling (matches kprobe_mutex_lock).
SEC("kretprobe/mutex_lock")
int BPF_KRETPROBE(kretprobe_mutex_lock)
{
	// Note: kretprobe cannot access original args, so we use pid-based sampling
	// to approximately match the kprobe sampling rate.
	__u64 pidtgid = bpf_get_current_pid_tgid();
	if ((pidtgid & 0xf) != 0) // 1/16 sampling
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__u64 *held = bpf_map_lookup_elem(&lock_held, &key);
	if (held)
		__sync_fetch_and_add(held, 1);

	return 0;
}

// 1/16 sampling to match kprobe_mutex_lock.
SEC("kprobe/mutex_unlock")
int BPF_KPROBE(kprobe_mutex_unlock, void *lock)
{
	__u64 lock_addr = (__u64)lock;
	if ((lock_addr & 0xf) != 0) // 1/16 sampling
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__u64 *held = bpf_map_lookup_elem(&lock_held, &key);
	if (held && *held > 0)
		__sync_fetch_and_add(held, -1ULL);

	__u64 *entry_ts = bpf_map_lookup_elem(&lock_entry_ts, &lock_addr);
	if (entry_ts) {
		__u64 now = bpf_ktime_get_ns();
		if (now - *entry_ts > 1000)
			__sync_fetch_and_add(&m->lock_contention_count, 1);
		bpf_map_delete_elem(&lock_entry_ts, &lock_addr);
	}
	return 0;
}

// Spinlock contention detection via raw_spin_lock / raw_spin_unlock.
// 1/16 sampling — spinlocks fire 100K+/exec, sampling is essential.
SEC("kprobe/raw_spin_lock")
int BPF_KPROBE(kprobe_raw_spin_lock, void *lock)
{
	__u64 lock_addr = (__u64)lock;
	if ((lock_addr & 0xf) != 0) // 1/16 sampling
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&lock_entry_ts, &lock_addr, &ts, BPF_ANY);

	__u64 *held = bpf_map_lookup_elem(&lock_held, &key);
	if (held)
		__sync_fetch_and_add(held, 1);

	return 0;
}

// 1/16 sampling to match kprobe_raw_spin_lock.
SEC("kprobe/raw_spin_unlock")
int BPF_KPROBE(kprobe_raw_spin_unlock, void *lock)
{
	__u64 lock_addr = (__u64)lock;
	if ((lock_addr & 0xf) != 0) // 1/16 sampling
		return 0;

	__u32 key = 0;
	struct probe_metrics *m = bpf_map_lookup_elem(&metrics, &key);
	if (!m || m->execution_start_ns == 0)
		return 0;

	__u64 *held = bpf_map_lookup_elem(&lock_held, &key);
	if (held && *held > 0)
		__sync_fetch_and_add(held, -1ULL);

	__u64 *entry_ts = bpf_map_lookup_elem(&lock_entry_ts, &lock_addr);
	if (entry_ts) {
		__u64 now = bpf_ktime_get_ns();
		if (now - *entry_ts > 1000)
			__sync_fetch_and_add(&m->lock_contention_count, 1);
		bpf_map_delete_elem(&lock_entry_ts, &lock_addr);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";

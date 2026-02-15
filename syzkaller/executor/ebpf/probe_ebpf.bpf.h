// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Minimal BPF type definitions for heap monitoring.
// Instead of full vmlinux.h, we define only the tracepoint argument structures
// we need for kmem/kmalloc and kmem/kfree tracepoints.

#ifndef PROBE_EBPF_BPF_H
#define PROBE_EBPF_BPF_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef int __s32;
typedef long long __s64;

// BPF helper definitions
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

// BPF map types
enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_LRU_HASH = 9,
};

// BPF map flags
enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

// BPF map definition macros
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

// Tracepoint common fields (from /sys/kernel/debug/tracing/events/kmem/kmalloc/format)
// Common fields are: type, flags, preempt_count, pid
struct trace_event_raw_common {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
};

// /sys/kernel/debug/tracing/events/kmem/kmalloc/format (kernel 6.1.20):
//   field:unsigned long call_site;  offset:8;  size:8;  signed:0;
//   field:const void * ptr;         offset:16; size:8;  signed:0;
//   field:size_t bytes_req;         offset:24; size:8;  signed:0;
//   field:size_t bytes_alloc;       offset:32; size:8;  signed:0;
//   field:unsigned long gfp_flags;  offset:40; size:8;  signed:0;
//   field:int node;                 offset:48; size:4;  signed:1;
struct trace_event_raw_kmalloc {
	struct trace_event_raw_common __common;
	unsigned long call_site;
	const void *ptr;
	unsigned long bytes_req;
	unsigned long bytes_alloc;
	unsigned long gfp_flags;
	int node;
};

// /sys/kernel/debug/tracing/events/kmem/kfree/format:
//   field:unsigned long call_site;  offset:8;  size:8;  signed:0;
//   field:const void * ptr;         offset:16; size:8;  signed:0;
struct trace_event_raw_kfree {
	struct trace_event_raw_common __common;
	unsigned long call_site;
	const void *ptr;
};

// BPF helper function IDs
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_map_delete_elem 3
#define BPF_FUNC_ktime_get_ns 5

// BPF helper prototypes
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

// Shared metrics structure (read by executor)
struct probe_metrics {
	__u64 alloc_count;
	__u64 free_count;
	__u64 reuse_count;       // slab reuses detected
	__u64 rapid_reuse_count; // reuses < 100us
	__u64 min_reuse_delay_ns; // fastest reuse (lower = more exploitable)
	__u64 double_free_count;      // double-free detected (ptr freed twice without alloc)
	__u64 size_mismatch_count;    // cross-cache: bytes_alloc > 2 * bytes_req
	__u64 execution_start_ns;     // epoch: set by executor before each program, used to filter stale freed_objects
};

// License string
#define LICENSE_STR "GPL"

#endif // PROBE_EBPF_BPF_H

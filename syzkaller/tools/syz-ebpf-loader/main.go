// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: syz-ebpf-loader loads BPF programs for kernel heap monitoring
// and vulnerability detection (Phase 5 tracepoints + Phase 7 kprobes).
// It loads probe_ebpf.bpf.o, attaches to tracepoints and kprobes,
// and pins maps + links to /sys/fs/bpf/probe/ so they persist after this process exits.
//
// Usage:
//   syz-ebpf-loader <path-to-probe_ebpf.bpf.o>

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const pinDir = "/sys/fs/bpf/probe"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <probe_ebpf.bpf.o>\n", os.Args[0])
		os.Exit(1)
	}
	bpfObj := os.Args[1]

	if err := run(bpfObj); err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: eBPF loader failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "PROBE: eBPF heap monitor loaded and pinned to %s\n", pinDir)
}

func run(bpfObj string) error {
	// Create pin directory
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return fmt.Errorf("create pin dir: %w", err)
	}

	// Load BPF object from ELF file
	spec, err := ebpf.LoadCollectionSpec(bpfObj)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	// Load into kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}
	defer coll.Close()

	// Pin maps so executor can access them
	metricsMap := coll.Maps["metrics"]
	if metricsMap == nil {
		return fmt.Errorf("metrics map not found in BPF object")
	}
	metricsPin := filepath.Join(pinDir, "metrics")
	os.Remove(metricsPin)
	if err := metricsMap.Pin(metricsPin); err != nil {
		return fmt.Errorf("pin metrics map: %w", err)
	}

	freedMap := coll.Maps["freed_objects"]
	if freedMap == nil {
		return fmt.Errorf("freed_objects map not found in BPF object")
	}
	freedPin := filepath.Join(pinDir, "freed_objects")
	os.Remove(freedPin)
	if err := freedMap.Pin(freedPin); err != nil {
		return fmt.Errorf("pin freed_objects map: %w", err)
	}

	// 7c: Pin cache_freed map
	if cacheFreedMap := coll.Maps["cache_freed"]; cacheFreedMap != nil {
		pin := filepath.Join(pinDir, "cache_freed")
		os.Remove(pin)
		if err := cacheFreedMap.Pin(pin); err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: pin cache_freed map: %v\n", err)
		}
	}

	// 7b': Pin slab_sites map (read by manager for AI strategy)
	if slabSitesMap := coll.Maps["slab_sites"]; slabSitesMap != nil {
		pin := filepath.Join(pinDir, "slab_sites")
		os.Remove(pin)
		if err := slabSitesMap.Pin(pin); err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: pin slab_sites map: %v\n", err)
		}
	}

	// 9b: Pin freed_pages map
	if freedPagesMap := coll.Maps["freed_pages"]; freedPagesMap != nil {
		pin := filepath.Join(pinDir, "freed_pages")
		os.Remove(pin)
		if err := freedPagesMap.Pin(pin); err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: pin freed_pages map: %v\n", err)
		}
	}

	// 9d: Pin freed_fds map
	if freedFdsMap := coll.Maps["freed_fds"]; freedFdsMap != nil {
		pin := filepath.Join(pinDir, "freed_fds")
		os.Remove(pin)
		if err := freedFdsMap.Pin(pin); err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: pin freed_fds map: %v\n", err)
		}
	}

	// Attach Phase 5 tracepoints
	kfreeProg := coll.Programs["trace_kfree"]
	if kfreeProg == nil {
		return fmt.Errorf("trace_kfree program not found")
	}
	kfreeLink, err := link.Tracepoint("kmem", "kfree", kfreeProg, nil)
	if err != nil {
		return fmt.Errorf("attach kfree tracepoint: %w", err)
	}

	kmallocProg := coll.Programs["trace_kmalloc"]
	if kmallocProg == nil {
		return fmt.Errorf("trace_kmalloc program not found")
	}
	kmallocLink, err := link.Tracepoint("kmem", "kmalloc", kmallocProg, nil)
	if err != nil {
		kfreeLink.Close()
		return fmt.Errorf("attach kmalloc tracepoint: %w", err)
	}

	// Pin Phase 5 tracepoint links
	kfreeLinkPin := filepath.Join(pinDir, "link_kfree")
	os.Remove(kfreeLinkPin)
	if err := kfreeLink.Pin(kfreeLinkPin); err != nil {
		return fmt.Errorf("pin kfree link: %w", err)
	}

	kmallocLinkPin := filepath.Join(pinDir, "link_kmalloc")
	os.Remove(kmallocLinkPin)
	if err := kmallocLink.Pin(kmallocLinkPin); err != nil {
		return fmt.Errorf("pin kmalloc link: %w", err)
	}

	// Phase 7d: Attach kprobe/commit_creds (graceful skip on failure)
	if prog := coll.Programs["kprobe_commit_creds"]; prog != nil {
		kp, err := link.Kprobe("commit_creds", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: kprobe commit_creds failed: %v (priv-esc detection disabled)\n", err)
		} else {
			pin := filepath.Join(pinDir, "link_commit_creds")
			os.Remove(pin)
			if err := kp.Pin(pin); err != nil {
				fmt.Fprintf(os.Stderr, "PROBE: warning: pin commit_creds link: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "PROBE: kprobe/commit_creds attached (priv-esc detection enabled)\n")
		}
	}

	// Phase 7c: Attach kprobe/kmem_cache_free (graceful skip on failure)
	if prog := coll.Programs["kprobe_cache_free"]; prog != nil {
		kp, err := link.Kprobe("kmem_cache_free", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: kprobe kmem_cache_free failed: %v (cross-cache detection disabled)\n", err)
		} else {
			pin := filepath.Join(pinDir, "link_cache_free")
			os.Remove(pin)
			if err := kp.Pin(pin); err != nil {
				fmt.Fprintf(os.Stderr, "PROBE: warning: pin cache_free link: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "PROBE: kprobe/kmem_cache_free attached (cross-cache detection enabled)\n")
		}
	}

	// Phase 7c: Attach tracepoint/kmem/kmem_cache_alloc (graceful skip on failure)
	if prog := coll.Programs["trace_cache_alloc"]; prog != nil {
		tp, err := link.Tracepoint("kmem", "kmem_cache_alloc", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: tracepoint kmem_cache_alloc failed: %v\n", err)
		} else {
			pin := filepath.Join(pinDir, "link_cache_alloc")
			os.Remove(pin)
			if err := tp.Pin(pin); err != nil {
				fmt.Fprintf(os.Stderr, "PROBE: warning: pin cache_alloc link: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "PROBE: tracepoint/kmem/kmem_cache_alloc attached\n")
		}
	}

	// Phase 8a: Attach kprobe/_copy_from_user (graceful skip on failure)
	if prog := coll.Programs["kprobe_copy_from_user"]; prog != nil {
		kp, err := link.Kprobe("_copy_from_user", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: kprobe _copy_from_user failed: %v (write-to-freed detection disabled)\n", err)
		} else {
			pin := filepath.Join(pinDir, "link_copy_from_user")
			os.Remove(pin)
			if err := kp.Pin(pin); err != nil {
				fmt.Fprintf(os.Stderr, "PROBE: warning: pin copy_from_user link: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "PROBE: kprobe/_copy_from_user attached (write-to-freed detection enabled)\n")
		}
	}

	// Phase 9b: Attach tracepoint/kmem/mm_page_free (graceful skip on failure)
	if prog := coll.Programs["trace_page_free"]; prog != nil {
		tp, err := link.Tracepoint("kmem", "mm_page_free", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: tracepoint mm_page_free failed: %v (page UAF detection disabled)\n", err)
		} else {
			pin := filepath.Join(pinDir, "link_page_free")
			os.Remove(pin)
			if err := tp.Pin(pin); err != nil {
				fmt.Fprintf(os.Stderr, "PROBE: warning: pin page_free link: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "PROBE: tracepoint/kmem/mm_page_free attached (page UAF detection enabled)\n")
		}
	}

	// Phase 9b: Attach tracepoint/kmem/mm_page_alloc (graceful skip on failure)
	if prog := coll.Programs["trace_page_alloc"]; prog != nil {
		tp, err := link.Tracepoint("kmem", "mm_page_alloc", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: tracepoint mm_page_alloc failed: %v\n", err)
		} else {
			pin := filepath.Join(pinDir, "link_page_alloc")
			os.Remove(pin)
			if err := tp.Pin(pin); err != nil {
				fmt.Fprintf(os.Stderr, "PROBE: warning: pin page_alloc link: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "PROBE: tracepoint/kmem/mm_page_alloc attached\n")
		}
	}

	// 9c: Pin stack_traces map
	if stackMap := coll.Maps["stack_traces"]; stackMap != nil {
		pin := filepath.Join(pinDir, "stack_traces")
		os.Remove(pin)
		if err := stackMap.Pin(pin); err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: pin stack_traces map: %v\n", err)
		}
	}

	// 9c: Pin seen_stacks map
	if seenMap := coll.Maps["seen_stacks"]; seenMap != nil {
		pin := filepath.Join(pinDir, "seen_stacks")
		os.Remove(pin)
		if err := seenMap.Pin(pin); err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: pin seen_stacks map: %v\n", err)
		}
	}

	// Phase 9d: Attach kprobe/close_fd (graceful skip on failure)
	if prog := coll.Programs["kprobe_close_fd"]; prog != nil {
		kp, err := link.Kprobe("close_fd", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: kprobe close_fd failed: %v (FD tracking disabled)\n", err)
		} else {
			pin := filepath.Join(pinDir, "link_close_fd")
			os.Remove(pin)
			if err := kp.Pin(pin); err != nil {
				fmt.Fprintf(os.Stderr, "PROBE: warning: pin close_fd link: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "PROBE: kprobe/close_fd attached (FD close tracking enabled)\n")
		}
	}

	// Phase 9d: Attach kprobe/fd_install (graceful skip on failure)
	if prog := coll.Programs["kprobe_fd_install"]; prog != nil {
		kp, err := link.Kprobe("fd_install", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PROBE: warning: kprobe fd_install failed: %v (FD reuse detection disabled)\n", err)
		} else {
			pin := filepath.Join(pinDir, "link_fd_install")
			os.Remove(pin)
			if err := kp.Pin(pin); err != nil {
				fmt.Fprintf(os.Stderr, "PROBE: warning: pin fd_install link: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "PROBE: kprobe/fd_install attached (FD reuse detection enabled)\n")
		}
	}

	// Success — BPF programs are attached and pinned, loader can exit
	return nil
}

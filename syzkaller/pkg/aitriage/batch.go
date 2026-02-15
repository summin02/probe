// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 6 — Batch API state management for Anthropic Message Batches.
// Provides disk persistence for batch state recovery across manager restarts.
package aitriage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// BatchState tracks the state of an in-flight batch request.
type BatchState struct {
	BatchID    string       `json:"batch_id"`
	Status     string       `json:"status"` // pending, submitted, polling, done, failed
	SubmitTime time.Time    `json:"submit_time"`
	Requests   []BatchEntry `json:"requests"`
}

// BatchEntry maps a crash ID to its batch request.
type BatchEntry struct {
	CrashID string `json:"crash_id"`
	Title   string `json:"title"`
}

const batchStateFile = "ai-batch-state.json"

// loadBatchState loads any in-flight batch state from disk.
func loadBatchState(workdir string) *BatchState {
	path := filepath.Join(workdir, batchStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var state BatchState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Logf(0, "PROBE: AI batch state parse error: %v", err)
		return nil
	}
	return &state
}

// saveBatchState saves the batch state to disk for crash recovery.
func saveBatchState(workdir string, state *BatchState) {
	path := filepath.Join(workdir, batchStateFile)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Logf(0, "PROBE: AI batch state marshal error: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Logf(0, "PROBE: AI batch state save error: %v", err)
	}
}

// clearBatchState removes the batch state file after completion.
func clearBatchState(workdir string) {
	path := filepath.Join(workdir, batchStateFile)
	os.Remove(path)
}

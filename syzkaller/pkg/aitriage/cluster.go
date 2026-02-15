// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 7e — Hierarchical agglomerative clustering for crash dedup.
// Clusters crash reports by cosine similarity of their embedding vectors.

package aitriage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	clusterThreshold   = 0.85 // cosine similarity threshold for merging
	clusterStateFile   = "ai-clusters.json"
	maxEmbeddingsPer   = 500 // max embeddings to keep
)

// CrashEmbedding stores a crash report's embedding vector.
type CrashEmbedding struct {
	CrashID   string    `json:"crash_id"`
	Title     string    `json:"title"`
	Vector    []float32 `json:"vector"`
	Tokens    int       `json:"tokens"`
	Timestamp time.Time `json:"timestamp"`
	ClusterID int       `json:"cluster_id"`
}

// CrashCluster groups semantically similar crashes.
type CrashCluster struct {
	ID        int      `json:"id"`
	Title     string   `json:"title"`      // representative title (first member)
	Members   []string `json:"members"`    // crash IDs
	AvgSim    float64  `json:"avg_sim"`    // average pairwise similarity
}

// ClusterState holds all embeddings and clusters, persisted to disk.
type ClusterState struct {
	mu         sync.Mutex
	workdir    string
	Embeddings []CrashEmbedding `json:"embeddings"`
	Clusters   []CrashCluster   `json:"clusters"`
	NextID     int              `json:"next_id"`
}

// NewClusterState loads or creates cluster state.
func NewClusterState(workdir string) *ClusterState {
	cs := &ClusterState{workdir: workdir, NextID: 1}
	cs.load()
	return cs
}

func (cs *ClusterState) load() {
	path := filepath.Join(cs.workdir, clusterStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	json.Unmarshal(data, cs)
}

func (cs *ClusterState) save() {
	path := filepath.Join(cs.workdir, clusterStateFile)
	data, _ := json.MarshalIndent(cs, "", "  ")
	os.WriteFile(path, data, 0644)
}

// AddEmbedding adds a crash embedding and re-clusters.
func (cs *ClusterState) AddEmbedding(emb CrashEmbedding) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Check if already embedded.
	for _, e := range cs.Embeddings {
		if e.CrashID == emb.CrashID {
			return
		}
	}

	cs.Embeddings = append(cs.Embeddings, emb)

	// Cap embeddings.
	if len(cs.Embeddings) > maxEmbeddingsPer {
		cs.Embeddings = cs.Embeddings[len(cs.Embeddings)-maxEmbeddingsPer:]
	}

	cs.recluster()
	cs.save()
}

// recluster performs single-linkage agglomerative clustering.
func (cs *ClusterState) recluster() {
	n := len(cs.Embeddings)
	if n == 0 {
		cs.Clusters = nil
		return
	}

	// Initialize each embedding as its own cluster.
	clusterOf := make([]int, n)
	for i := range clusterOf {
		clusterOf[i] = i
	}

	// Find root of union-find.
	var find func(int) int
	find = func(i int) int {
		if clusterOf[i] != i {
			clusterOf[i] = find(clusterOf[i])
		}
		return clusterOf[i]
	}

	// Merge clusters with similarity above threshold.
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			sim := CosineSimilarity(cs.Embeddings[i].Vector, cs.Embeddings[j].Vector)
			if sim >= clusterThreshold {
				ri, rj := find(i), find(j)
				if ri != rj {
					clusterOf[rj] = ri
				}
			}
		}
	}

	// Build cluster map.
	clusterMap := make(map[int][]int) // root → member indices
	for i := range cs.Embeddings {
		root := find(i)
		clusterMap[root] = append(clusterMap[root], i)
	}

	// Build cluster list.
	cs.Clusters = nil
	cs.NextID = 1
	for _, members := range clusterMap {
		cluster := CrashCluster{
			ID:    cs.NextID,
			Title: cs.Embeddings[members[0]].Title,
		}
		cs.NextID++

		for _, idx := range members {
			cluster.Members = append(cluster.Members, cs.Embeddings[idx].CrashID)
			cs.Embeddings[idx].ClusterID = cluster.ID
		}

		// Compute average pairwise similarity.
		if len(members) > 1 {
			totalSim := 0.0
			pairs := 0
			for i := 0; i < len(members); i++ {
				for j := i + 1; j < len(members); j++ {
					totalSim += CosineSimilarity(
						cs.Embeddings[members[i]].Vector,
						cs.Embeddings[members[j]].Vector,
					)
					pairs++
				}
			}
			if pairs > 0 {
				cluster.AvgSim = totalSim / float64(pairs)
			}
		} else {
			cluster.AvgSim = 1.0
		}

		cs.Clusters = append(cs.Clusters, cluster)
	}
}

// GetClusterForCrash returns the cluster ID for a crash, or 0 if not clustered.
func (cs *ClusterState) GetClusterForCrash(crashID string) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for _, e := range cs.Embeddings {
		if e.CrashID == crashID {
			return e.ClusterID
		}
	}
	return 0
}

// Snapshot returns a mutex-free copy for reading.
func (cs *ClusterState) Snapshot() ([]CrashEmbedding, []CrashCluster) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	embs := make([]CrashEmbedding, len(cs.Embeddings))
	copy(embs, cs.Embeddings)
	clusters := make([]CrashCluster, len(cs.Clusters))
	copy(clusters, cs.Clusters)
	return embs, clusters
}

// PendingCrashes returns crash IDs that don't have embeddings yet.
func (cs *ClusterState) PendingCrashes(crashes []CrashForAnalysis) []CrashForAnalysis {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	embedded := make(map[string]bool)
	for _, e := range cs.Embeddings {
		embedded[e.CrashID] = true
	}

	var pending []CrashForAnalysis
	for _, c := range crashes {
		if !embedded[c.ID] {
			pending = append(pending, c)
		}
	}
	return pending
}

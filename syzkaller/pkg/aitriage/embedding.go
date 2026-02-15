// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 7e — GPTrace embedding-based crash dedup.
// Uses OpenAI text-embedding-3-small (or compatible) to vectorize crash reports
// and cluster them by cosine similarity.

package aitriage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
)

// EmbeddingClient handles embedding API calls with independent cost tracking.
type EmbeddingClient struct {
	mu       sync.Mutex
	apiKey   string
	apiURL   string
	model    string
	provider string
	cost     *CostTracker
}

// NewEmbeddingClient creates a client for embedding API calls.
// Returns nil if embedding is not configured (graceful degradation).
func NewEmbeddingClient(cfg mgrconfig.AITriageConfig) *EmbeddingClient {
	if cfg.EmbeddingAPIKey == "" {
		return nil
	}
	model := cfg.EmbeddingModel
	if model == "" {
		model = "text-embedding-3-small"
	}
	provider := cfg.EmbeddingProvider
	if provider == "" {
		provider = "openai"
	}
	apiURL := cfg.EmbeddingAPIURL
	if apiURL == "" {
		apiURL = "https://api.openai.com/v1/embeddings"
	}
	return &EmbeddingClient{
		apiKey:   cfg.EmbeddingAPIKey,
		apiURL:   apiURL,
		model:    model,
		provider: provider,
		cost:     &CostTracker{},
	}
}

// Embedding pricing: [input_per_1M_tokens] in USD (embeddings have no output tokens).
var embeddingPricing = map[string]float64{
	"text-embedding-3-small": 0.02,
	"text-embedding-3-large": 0.13,
	"text-embedding-ada-002": 0.10,
}

// Embed sends text to the embedding API and returns the vector.
func (ec *EmbeddingClient) Embed(text string) ([]float32, int, error) {
	reqBody := map[string]interface{}{
		"input": text,
		"model": ec.model,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal embedding request: %w", err)
	}

	req, err := http.NewRequest("POST", ec.apiURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, 0, fmt.Errorf("create embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ec.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("embedding API call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read embedding response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, 0, fmt.Errorf("embedding API error %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	var result struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, 0, fmt.Errorf("parse embedding response: %w", err)
	}
	if len(result.Data) == 0 || len(result.Data[0].Embedding) == 0 {
		return nil, 0, fmt.Errorf("empty embedding response")
	}

	tokens := result.Usage.TotalTokens

	// Record cost (separate from main LLM cost tracker).
	call := APICall{
		Time:        time.Now(),
		Type:        "embedding",
		InputTokens: tokens,
		Success:     true,
	}
	pricing, ok := embeddingPricing[ec.model]
	if ok {
		call.CostUSD = float64(tokens) * pricing / 1e6
	}
	ec.cost.Record(call, ec.model)

	return result.Data[0].Embedding, tokens, nil
}

// Cost returns a snapshot of embedding-specific costs.
func (ec *EmbeddingClient) Cost() CostSnapshot {
	return ec.cost.Snapshot()
}

// PreprocessCrashReport normalizes a crash report for embedding:
// - Remove hex addresses (kernel-specific, not semantically meaningful)
// - Normalize offsets to generic markers
// - Extract function name sequences
func PreprocessCrashReport(report string) string {
	// Remove hex addresses (0xffff..., 0x0000...).
	hexAddr := regexp.MustCompile(`0x[0-9a-fA-F]{8,16}`)
	text := hexAddr.ReplaceAllString(report, "ADDR")

	// Remove raw pointer values like ffff888012345678.
	rawPtr := regexp.MustCompile(`\b[0-9a-fA-F]{16}\b`)
	text = rawPtr.ReplaceAllString(text, "PTR")

	// Normalize offsets like +0x1a3/0x2f0 → +OFFSET.
	offset := regexp.MustCompile(`\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+`)
	text = offset.ReplaceAllString(text, "+OFFSET")

	// Collapse multiple spaces/newlines.
	spaces := regexp.MustCompile(`\s+`)
	text = spaces.ReplaceAllString(text, " ")

	// Truncate to ~2000 chars for embedding (model context limit).
	if len(text) > 2000 {
		text = text[:2000]
	}

	return strings.TrimSpace(text)
}

// CosineSimilarity computes cosine similarity between two vectors.
func CosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}
	denom := math.Sqrt(normA) * math.Sqrt(normB)
	if denom == 0 {
		return 0
	}
	return dot / denom
}

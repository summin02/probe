// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aitriage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
)

// LLMClient provides a unified interface for LLM API calls.
type LLMClient interface {
	Chat(ctx context.Context, systemPrompt, userPrompt string) (*LLMResponse, error)
}

type LLMResponse struct {
	Content      string
	InputTokens  int
	OutputTokens int
}

func NewClient(cfg mgrconfig.AITriageConfig) (LLMClient, error) {
	provider := cfg.Provider
	if provider == "" {
		if strings.HasPrefix(cfg.Model, "claude-") {
			provider = "anthropic"
		} else {
			provider = "openai"
		}
	}
	switch provider {
	case "anthropic":
		baseURL := cfg.APIURL
		if baseURL == "" {
			baseURL = "https://api.anthropic.com"
		}
		return &anthropicClient{
			apiKey:  cfg.APIKey,
			model:   cfg.Model,
			baseURL: baseURL,
		}, nil
	case "openai":
		baseURL := cfg.APIURL
		if baseURL == "" {
			baseURL = "https://api.openai.com"
		}
		return &openaiClient{
			apiKey:  cfg.APIKey,
			model:   cfg.Model,
			baseURL: baseURL,
		}, nil
	default:
		return nil, fmt.Errorf("unknown AI provider: %v", provider)
	}
}

// --- Anthropic Client ---

type anthropicClient struct {
	apiKey  string
	model   string
	baseURL string
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	System      string             `json:"system"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (c *anthropicClient) Chat(ctx context.Context, systemPrompt, userPrompt string) (*LLMResponse, error) {
	reqBody := anthropicRequest{
		Model:       c.model,
		MaxTokens:   4096,
		Temperature: 0.2,
		System:      systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userPrompt},
		},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	var resp anthropicResponse
	err = doRequestWithRetry(ctx, c.baseURL+"/v1/messages", data, map[string]string{
		"x-api-key":         c.apiKey,
		"anthropic-version":  "2023-06-01",
		"content-type":       "application/json",
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("anthropic API error: %v", resp.Error.Message)
	}
	if len(resp.Content) == 0 {
		return nil, fmt.Errorf("anthropic returned empty content")
	}
	return &LLMResponse{
		Content:      resp.Content[0].Text,
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
	}, nil
}

// --- OpenAI Client ---

type openaiClient struct {
	apiKey  string
	model   string
	baseURL string
}

type openaiRequest struct {
	Model       string           `json:"model"`
	MaxTokens   int              `json:"max_tokens"`
	Temperature float64          `json:"temperature"`
	Messages    []openaiMessage  `json:"messages"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (c *openaiClient) Chat(ctx context.Context, systemPrompt, userPrompt string) (*LLMResponse, error) {
	reqBody := openaiRequest{
		Model:       c.model,
		MaxTokens:   4096,
		Temperature: 0.2,
		Messages: []openaiMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	var resp openaiResponse
	err = doRequestWithRetry(ctx, c.baseURL+"/v1/chat/completions", data, map[string]string{
		"Authorization": "Bearer " + c.apiKey,
		"Content-Type":  "application/json",
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("openai API error: %v", resp.Error.Message)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("openai returned no choices")
	}
	return &LLMResponse{
		Content:      resp.Choices[0].Message.Content,
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}, nil
}

// --- Anthropic Batch Client ---

// BatchClient provides the Anthropic Message Batches API interface.
type BatchClient interface {
	CreateBatch(ctx context.Context, requests []BatchRequest) (string, error) // returns batchID
	CheckBatch(ctx context.Context, batchID string) (*BatchStatus, error)
	GetBatchResults(ctx context.Context, batchID string) ([]BatchResult, error)
	CancelBatch(ctx context.Context, batchID string) error
}

type BatchRequest struct {
	CustomID     string
	SystemPrompt string
	UserPrompt   string
}

type BatchStatus struct {
	ID            string
	Status        string // "in_progress", "ended", "expired", "canceling"
	RequestCounts struct {
		Processing int
		Succeeded  int
		Errored    int
		Canceled   int
		Expired    int
	}
}

type BatchResult struct {
	CustomID     string
	Success      bool
	Content      string
	InputTokens  int
	OutputTokens int
	Error        string
}

// NewBatchClient creates a BatchClient if the provider is Anthropic. Returns nil for other providers.
func NewBatchClient(cfg mgrconfig.AITriageConfig) BatchClient {
	provider := cfg.Provider
	if provider == "" {
		if strings.HasPrefix(cfg.Model, "claude-") {
			provider = "anthropic"
		}
	}
	if provider != "anthropic" {
		return nil
	}
	baseURL := cfg.APIURL
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	return &anthropicBatchClient{
		apiKey:  cfg.APIKey,
		model:   cfg.Model,
		baseURL: baseURL,
	}
}

type anthropicBatchClient struct {
	apiKey  string
	model   string
	baseURL string
}

type anthropicBatchCreateRequest struct {
	Requests []anthropicBatchRequestItem `json:"requests"`
}

type anthropicBatchRequestItem struct {
	CustomID string                 `json:"custom_id"`
	Params   anthropicBatchParams   `json:"params"`
}

type anthropicBatchParams struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	System      string             `json:"system"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicBatchCreateResponse struct {
	ID            string `json:"id"`
	ProcessingStatus string `json:"processing_status"`
	RequestCounts struct {
		Processing int `json:"processing"`
		Succeeded  int `json:"succeeded"`
		Errored    int `json:"errored"`
		Canceled   int `json:"canceled"`
		Expired    int `json:"expired"`
	} `json:"request_counts"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (c *anthropicBatchClient) CreateBatch(ctx context.Context, requests []BatchRequest) (string, error) {
	items := make([]anthropicBatchRequestItem, len(requests))
	for i, r := range requests {
		items[i] = anthropicBatchRequestItem{
			CustomID: r.CustomID,
			Params: anthropicBatchParams{
				Model:       c.model,
				MaxTokens:   4096,
				Temperature: 0.2,
				System:      r.SystemPrompt,
				Messages: []anthropicMessage{
					{Role: "user", Content: r.UserPrompt},
				},
			},
		}
	}

	reqBody := anthropicBatchCreateRequest{Requests: items}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	var resp anthropicBatchCreateResponse
	err = doHTTPRequest(ctx, "POST", c.baseURL+"/v1/messages/batches", data, c.headers(), &resp)
	if err != nil {
		return "", fmt.Errorf("batch create: %w", err)
	}
	if resp.Error != nil {
		return "", fmt.Errorf("batch create API error: %v", resp.Error.Message)
	}
	if resp.ID == "" {
		return "", fmt.Errorf("batch create: empty batch ID")
	}
	return resp.ID, nil
}

func (c *anthropicBatchClient) CheckBatch(ctx context.Context, batchID string) (*BatchStatus, error) {
	var resp anthropicBatchCreateResponse
	err := doHTTPRequest(ctx, "GET", c.baseURL+"/v1/messages/batches/"+batchID, nil, c.headers(), &resp)
	if err != nil {
		return nil, fmt.Errorf("batch check: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("batch check API error: %v", resp.Error.Message)
	}
	status := &BatchStatus{
		ID:     resp.ID,
		Status: resp.ProcessingStatus,
	}
	status.RequestCounts.Processing = resp.RequestCounts.Processing
	status.RequestCounts.Succeeded = resp.RequestCounts.Succeeded
	status.RequestCounts.Errored = resp.RequestCounts.Errored
	status.RequestCounts.Canceled = resp.RequestCounts.Canceled
	status.RequestCounts.Expired = resp.RequestCounts.Expired
	return status, nil
}

// anthropicBatchResultItem represents a single result in the batch results JSONL.
type anthropicBatchResultItem struct {
	CustomID string `json:"custom_id"`
	Result   struct {
		Type    string `json:"type"`
		Message struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		} `json:"message"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	} `json:"result"`
}

func (c *anthropicBatchClient) GetBatchResults(ctx context.Context, batchID string) ([]BatchResult, error) {
	url := c.baseURL + "/v1/messages/batches/" + batchID + "/results"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.headers() {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("batch results fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("batch results HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Batch results come as JSONL (one JSON object per line).
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("batch results read: %w", err)
	}

	var results []BatchResult
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var item anthropicBatchResultItem
		if err := json.Unmarshal(line, &item); err != nil {
			continue // skip malformed lines
		}
		br := BatchResult{CustomID: item.CustomID}
		if item.Result.Type == "succeeded" && item.Result.Error == nil {
			br.Success = true
			if len(item.Result.Message.Content) > 0 {
				br.Content = item.Result.Message.Content[0].Text
			}
			br.InputTokens = item.Result.Message.Usage.InputTokens
			br.OutputTokens = item.Result.Message.Usage.OutputTokens
		} else {
			br.Success = false
			if item.Result.Error != nil {
				br.Error = item.Result.Error.Message
			} else {
				br.Error = fmt.Sprintf("result type: %s", item.Result.Type)
			}
		}
		results = append(results, br)
	}
	return results, nil
}

func (c *anthropicBatchClient) CancelBatch(ctx context.Context, batchID string) error {
	url := c.baseURL + "/v1/messages/batches/" + batchID + "/cancel"
	return doHTTPRequest(ctx, "POST", url, nil, c.headers(), &struct{}{})
}

func (c *anthropicBatchClient) headers() map[string]string {
	return map[string]string{
		"x-api-key":         c.apiKey,
		"anthropic-version":  "2023-06-01",
		"content-type":       "application/json",
	}
}

// --- Shared HTTP helpers ---

// doHTTPRequest performs a single HTTP request (GET or POST) with JSON body/response.
func doHTTPRequest(ctx context.Context, method, url string, body []byte, headers map[string]string, result any) error {
	client := &http.Client{Timeout: 60 * time.Second}
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	if result != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, result)
	}
	return nil
}

// --- Shared HTTP helper with retry ---

func doRequestWithRetry(ctx context.Context, url string, body []byte, headers map[string]string, result any) error {
	client := &http.Client{Timeout: 60 * time.Second}
	backoffs := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}

	var lastErr error
	for attempt := 0; attempt <= 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffs[attempt-1]):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
			continue
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}

		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
		return nil
	}
	return fmt.Errorf("all retries failed: %w", lastErr)
}

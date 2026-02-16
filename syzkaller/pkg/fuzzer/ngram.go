// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 8d — MOCK BiGRU gRPC client for context-aware syscall prediction.
//
// Communicates with the Python BiGRU model server (tools/mock_model/server.py)
// via a simple JSON-over-TCP protocol to avoid gRPC dependency in the main Go module.
//
// Fallback: if the server is unavailable, returns nil → caller uses ChoiceTable.
package fuzzer

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	ngramDefaultAddr     = "127.0.0.1:50051"
	ngramDialTimeout     = 2 * time.Second
	ngramReadTimeout     = 500 * time.Millisecond
	ngramHealthInterval  = 5 * time.Second
	ngramMinConfidence   = 0.10 // minimum confidence to use BiGRU prediction
)

// NgramClient is a lightweight TCP/JSON client for the MOCK BiGRU server.
// Uses a simple JSON-line protocol to avoid pulling gRPC as a Go dependency.
type NgramClient struct {
	mu      sync.Mutex
	addr    string
	healthy bool
	lastCheck time.Time
	done    chan struct{}

	// UCB-1 tracking: BiGRU vs ChoiceTable performance.
	bigruWins   int64
	bigruTrials int64
	ctWins      int64
	ctTrials    int64

	logf func(level int, msg string, args ...any)
}

// ngramRequest is the JSON request sent to the Python server.
type ngramRequest struct {
	Method string   `json:"method"`
	Calls  []string `json:"calls,omitempty"`
	Dir    string   `json:"dir,omitempty"`
}

// ngramResponse is the JSON response from the Python server.
type ngramResponse struct {
	Call       string  `json:"call"`
	Confidence float64 `json:"confidence"`
	Healthy    bool    `json:"healthy"`
	Error      string  `json:"error,omitempty"`
}

// NewNgramClient creates a new MOCK BiGRU client.
func NewNgramClient(addr string, logf func(level int, msg string, args ...any)) *NgramClient {
	if addr == "" {
		addr = ngramDefaultAddr
	}
	c := &NgramClient{
		addr: addr,
		logf: logf,
		done: make(chan struct{}),
	}
	go c.healthLoop()
	return c
}

// PredictNextCall returns the BiGRU's predicted next syscall given a context.
// Returns ("", 0, nil) if the server is unavailable or confidence is too low.
func (c *NgramClient) PredictNextCall(calls []string) (string, float64, error) {
	c.mu.Lock()
	healthy := c.healthy
	c.mu.Unlock()

	if !healthy || len(calls) == 0 {
		return "", 0, nil
	}

	resp, err := c.send(ngramRequest{Method: "predict", Calls: calls})
	if err != nil {
		c.mu.Lock()
		c.healthy = false
		c.mu.Unlock()
		return "", 0, nil // silent fallback
	}

	if resp.Error != "" || resp.Confidence < ngramMinConfidence {
		return "", 0, nil
	}

	return resp.Call, resp.Confidence, nil
}

// RecordBiGRUResult records whether the BiGRU's prediction led to success.
func (c *NgramClient) RecordBiGRUResult(success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bigruTrials++
	if success {
		c.bigruWins++
	}
}

// RecordCTResult records whether the ChoiceTable's selection led to success.
func (c *NgramClient) RecordCTResult(success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctTrials++
	if success {
		c.ctWins++
	}
}

// ShouldUseBiGRU returns true if UCB-1 favors using BiGRU over ChoiceTable.
// Returns false if the server is unhealthy or BiGRU has insufficient data.
func (c *NgramClient) ShouldUseBiGRU() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.healthy {
		return false
	}

	// Cold start: always use ChoiceTable until both have at least 100 trials.
	if c.bigruTrials < 100 || c.ctTrials < 100 {
		// 50% chance to use BiGRU during exploration.
		return c.bigruTrials <= c.ctTrials
	}

	// UCB-1 comparison.
	bigruRate := float64(c.bigruWins) / float64(c.bigruTrials)
	ctRate := float64(c.ctWins) / float64(c.ctTrials)
	return bigruRate >= ctRate
}

// Healthy returns whether the MOCK server is reachable.
func (c *NgramClient) Healthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.healthy
}

// Retrain triggers a model retrain on the server side.
func (c *NgramClient) Retrain(corpusDir string) error {
	resp, err := c.send(ngramRequest{Method: "retrain", Dir: corpusDir})
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("retrain failed: %s", resp.Error)
	}
	return nil
}

func (c *NgramClient) send(req ngramRequest) (*ngramResponse, error) {
	conn, err := net.DialTimeout("tcp", c.addr, ngramDialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(ngramReadTimeout))

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var resp ngramResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Stop terminates the healthLoop goroutine.
func (c *NgramClient) Stop() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

func (c *NgramClient) healthLoop() {
	for {
		select {
		case <-c.done:
			return
		case <-time.After(ngramHealthInterval):
		}
		resp, err := c.send(ngramRequest{Method: "health"})
		c.mu.Lock()
		if err != nil {
			c.healthy = false
		} else {
			c.healthy = resp.Healthy
		}
		c.lastCheck = time.Now()
		c.mu.Unlock()
	}
}

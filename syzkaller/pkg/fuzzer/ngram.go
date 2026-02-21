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
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	ngramDefaultAddr      = "127.0.0.1:50051"
	ngramDialTimeout      = 2 * time.Second
	ngramReadTimeout      = 200 * time.Millisecond
	ngramHealthInterval   = 5 * time.Second
	ngramMinConfidence    = 0.10 // minimum confidence to use BiGRU prediction
	ngramMaxFailures      = 3   // consecutive failures before bypass
	ngramBypassCooldown   = 10 * time.Second
	ngramTCPKeepAlive     = 15 * time.Second
	ngramCacheSize        = 256 // LRU cache for prediction results
	ngramCacheTTL         = 30 * time.Second // cache entry TTL
)

// NgramClient is a lightweight TCP/JSON client for the MOCK BiGRU server.
// Uses a persistent TCP connection with JSON-line protocol to avoid per-call
// dial overhead and gRPC dependency.
type NgramClient struct {
	mu      sync.Mutex
	addr    string
	healthy bool
	lastCheck time.Time
	done    chan struct{}

	// Persistent connection fields.
	conn        net.Conn
	connMu      sync.Mutex // separate lock for connection to avoid holding mu during I/O
	reader      *bufio.Scanner
	failCount   int
	bypassUntil time.Time

	// UCB-1 tracking: BiGRU vs ChoiceTable performance.
	bigruWins   int64
	bigruTrials int64
	ctWins      int64
	ctTrials    int64

	// Prediction cache: avoids synchronous TCP on mutation hot path.
	predCache   map[string]predCacheEntry
	predCacheMu sync.RWMutex

	logf func(level int, msg string, args ...any)
}

// predCacheEntry stores a cached prediction result with TTL.
type predCacheEntry struct {
	call       string
	confidence float64
	ts         time.Time
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
		addr:      addr,
		logf:      logf,
		done:      make(chan struct{}),
		predCache: make(map[string]predCacheEntry, ngramCacheSize),
	}
	go c.healthLoop()
	return c
}

// PredictNextCall returns the BiGRU's predicted next syscall given a context.
// Uses LRU cache to avoid synchronous TCP on mutation hot path.
// Returns ("", 0, nil) if the server is unavailable or confidence is too low.
func (c *NgramClient) PredictNextCall(calls []string) (string, float64, error) {
	c.mu.Lock()
	healthy := c.healthy
	c.mu.Unlock()

	if !healthy || len(calls) == 0 {
		return "", 0, nil
	}

	// Cache lookup: use last 3 calls as key (covers most context).
	cacheKey := c.makeCacheKey(calls)
	c.predCacheMu.RLock()
	if entry, ok := c.predCache[cacheKey]; ok && time.Since(entry.ts) < ngramCacheTTL {
		c.predCacheMu.RUnlock()
		return entry.call, entry.confidence, nil
	}
	c.predCacheMu.RUnlock()

	// Cache miss: synchronous TCP call.
	resp, err := c.send(ngramRequest{Method: "predict", Calls: calls})
	if err != nil {
		c.mu.Lock()
		c.healthy = false
		c.mu.Unlock()
		return "", 0, nil
	}

	if resp.Error != "" || resp.Confidence < ngramMinConfidence {
		return "", 0, nil
	}

	// Store in cache.
	c.predCacheMu.Lock()
	if len(c.predCache) >= ngramCacheSize {
		// Evict oldest entries (simple: clear half).
		count := 0
		for k := range c.predCache {
			delete(c.predCache, k)
			count++
			if count >= ngramCacheSize/2 {
				break
			}
		}
	}
	c.predCache[cacheKey] = predCacheEntry{
		call:       resp.Call,
		confidence: resp.Confidence,
		ts:         time.Now(),
	}
	c.predCacheMu.Unlock()

	return resp.Call, resp.Confidence, nil
}

// makeCacheKey creates a cache key from the last few calls in context.
func (c *NgramClient) makeCacheKey(calls []string) string {
	n := len(calls)
	if n > 3 {
		calls = calls[n-3:]
	}
	return strings.Join(calls, "|")
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

	// UCB-1 comparison with exploration bonus.
	totalTrials := float64(c.bigruTrials + c.ctTrials)
	bigruRate := float64(c.bigruWins) / float64(c.bigruTrials)
	ctRate := float64(c.ctWins) / float64(c.ctTrials)
	bigruUCB := bigruRate + math.Sqrt(2*math.Log(totalTrials)/float64(c.bigruTrials))
	ctUCB := ctRate + math.Sqrt(2*math.Log(totalTrials)/float64(c.ctTrials))
	return bigruUCB >= ctUCB
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

// connect establishes or re-establishes the persistent TCP connection.
// Must be called with connMu held.
func (c *NgramClient) connect() error {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.reader = nil
	}

	dialer := net.Dialer{
		Timeout:   ngramDialTimeout,
		KeepAlive: ngramTCPKeepAlive,
	}
	conn, err := dialer.Dial("tcp", c.addr)
	if err != nil {
		return err
	}
	c.conn = conn
	c.reader = bufio.NewScanner(conn)
	c.reader.Buffer(make([]byte, 0, 8192), 8192)
	c.failCount = 0
	return nil
}

func (c *NgramClient) send(req ngramRequest) (*ngramResponse, error) {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	// Check bypass: if too many consecutive failures, skip until cooldown.
	if c.failCount >= ngramMaxFailures && time.Now().Before(c.bypassUntil) {
		return nil, fmt.Errorf("bypassed: %d consecutive failures, cooldown until %v",
			c.failCount, c.bypassUntil)
	}

	// Establish connection if needed.
	if c.conn == nil {
		if err := c.connect(); err != nil {
			c.failCount++
			if c.failCount >= ngramMaxFailures {
				c.bypassUntil = time.Now().Add(ngramBypassCooldown)
			}
			return nil, err
		}
	}

	// Try send+recv, reconnect once on error.
	resp, err := c.sendOnConn(req)
	if err != nil {
		// Connection may be stale; reconnect and retry once.
		if connErr := c.connect(); connErr != nil {
			c.failCount++
			if c.failCount >= ngramMaxFailures {
				c.bypassUntil = time.Now().Add(ngramBypassCooldown)
			}
			return nil, connErr
		}
		resp, err = c.sendOnConn(req)
		if err != nil {
			c.failCount++
			if c.failCount >= ngramMaxFailures {
				c.bypassUntil = time.Now().Add(ngramBypassCooldown)
			}
			return nil, err
		}
	}

	c.failCount = 0
	return resp, nil
}

// sendOnConn performs the actual write+read on the current connection.
// Must be called with connMu held.
func (c *NgramClient) sendOnConn(req ngramRequest) (*ngramResponse, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("no connection")
	}

	c.conn.SetDeadline(time.Now().Add(ngramReadTimeout))

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if _, err := c.conn.Write(data); err != nil {
		return nil, err
	}

	if !c.reader.Scan() {
		if err := c.reader.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("connection closed by server")
	}

	var resp ngramResponse
	if err := json.Unmarshal(c.reader.Bytes(), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Stop terminates the healthLoop goroutine and closes the persistent connection.
func (c *NgramClient) Stop() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.reader = nil
	}
	c.connMu.Unlock()
}

func (c *NgramClient) healthLoop() {
	var checkCount int
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
		checkCount++
		// Log UCB-1 status every ~60s (12 checks * 5s interval).
		if checkCount%12 == 0 {
			bigruRate, ctRate := 0.0, 0.0
			if c.bigruTrials > 0 {
				bigruRate = float64(c.bigruWins) / float64(c.bigruTrials) * 100
			}
			if c.ctTrials > 0 {
				ctRate = float64(c.ctWins) / float64(c.ctTrials) * 100
			}
			c.logf(0, "PROBE: N-gram UCB-1 status: healthy=%v, BiGRU=%d/%d (%.1f%%), CT=%d/%d (%.1f%%)",
				c.healthy, c.bigruWins, c.bigruTrials, bigruRate,
				c.ctWins, c.ctTrials, ctRate)
		}
		c.mu.Unlock()
	}
}

// Package metrics provides timing and concurrency metrics for gitscan.
package metrics

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics tracks timing and concurrency statistics.
type Metrics struct {
	mu sync.RWMutex

	// Counters
	TotalScans       atomic.Int64
	ActiveScans      atomic.Int64
	CacheHits        atomic.Int64
	CacheMisses      atomic.Int64
	CloneErrors      atomic.Int64
	ScanErrors       atomic.Int64
	PeakConcurrent   atomic.Int64
	BlockedRequests  atomic.Int64 // Suspicious method requests blocked

	// Timing histograms (in milliseconds)
	cloneTimes []int64
	scanTimes  []int64
	totalTimes []int64

	// Start time
	StartTime time.Time
}

// New creates a new Metrics instance.
func New() *Metrics {
	return &Metrics{
		StartTime:  time.Now(),
		cloneTimes: make([]int64, 0, 1000),
		scanTimes:  make([]int64, 0, 1000),
		totalTimes: make([]int64, 0, 1000),
	}
}

// ScanStarted marks the beginning of a scan and returns a done function.
func (m *Metrics) ScanStarted() func() {
	m.TotalScans.Add(1)
	current := m.ActiveScans.Add(1)

	// Update peak concurrent scans
	for {
		peak := m.PeakConcurrent.Load()
		if current <= peak || m.PeakConcurrent.CompareAndSwap(peak, current) {
			break
		}
	}

	startTime := time.Now()
	return func() {
		m.ActiveScans.Add(-1)
		m.RecordTotalTime(time.Since(startTime))
	}
}

// RecordCloneTime records a clone duration.
func (m *Metrics) RecordCloneTime(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cloneTimes = append(m.cloneTimes, d.Milliseconds())
	// Keep only last 1000 samples
	if len(m.cloneTimes) > 1000 {
		m.cloneTimes = m.cloneTimes[1:]
	}
}

// RecordScanTime records a scan duration.
func (m *Metrics) RecordScanTime(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanTimes = append(m.scanTimes, d.Milliseconds())
	if len(m.scanTimes) > 1000 {
		m.scanTimes = m.scanTimes[1:]
	}
}

// RecordTotalTime records a total request duration.
func (m *Metrics) RecordTotalTime(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalTimes = append(m.totalTimes, d.Milliseconds())
	if len(m.totalTimes) > 1000 {
		m.totalTimes = m.totalTimes[1:]
	}
}

// Stats returns timing statistics for a slice of durations.
func stats(times []int64) map[string]int64 {
	if len(times) == 0 {
		return map[string]int64{"count": 0, "min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0}
	}

	// Copy and sort for percentiles
	sorted := make([]int64, len(times))
	copy(sorted, times)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var sum int64
	for _, t := range sorted {
		sum += t
	}

	return map[string]int64{
		"count": int64(len(sorted)),
		"min":   sorted[0],
		"max":   sorted[len(sorted)-1],
		"avg":   sum / int64(len(sorted)),
		"p50":   sorted[len(sorted)*50/100],
		"p95":   sorted[len(sorted)*95/100],
		"p99":   sorted[len(sorted)*99/100],
	}
}

// Snapshot returns a point-in-time snapshot of all metrics.
type Snapshot struct {
	Uptime          string            `json:"uptime"`
	TotalScans      int64             `json:"total_scans"`
	ActiveScans     int64             `json:"active_scans"`
	PeakConcurrent  int64             `json:"peak_concurrent"`
	CacheHits       int64             `json:"cache_hits"`
	CacheMisses     int64             `json:"cache_misses"`
	CacheHitRate    float64           `json:"cache_hit_rate"`
	CloneErrors     int64             `json:"clone_errors"`
	ScanErrors      int64             `json:"scan_errors"`
	BlockedRequests int64             `json:"blocked_requests"`
	CloneTimesMs    map[string]int64  `json:"clone_times_ms"`
	ScanTimesMs     map[string]int64  `json:"scan_times_ms"`
	TotalTimesMs    map[string]int64  `json:"total_times_ms"`
}

// GetSnapshot returns current metrics snapshot.
func (m *Metrics) GetSnapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hits := m.CacheHits.Load()
	misses := m.CacheMisses.Load()
	var hitRate float64
	if hits+misses > 0 {
		hitRate = float64(hits) / float64(hits+misses) * 100
	}

	return Snapshot{
		Uptime:          time.Since(m.StartTime).Round(time.Second).String(),
		TotalScans:      m.TotalScans.Load(),
		ActiveScans:     m.ActiveScans.Load(),
		PeakConcurrent:  m.PeakConcurrent.Load(),
		CacheHits:       hits,
		CacheMisses:     misses,
		CacheHitRate:    hitRate,
		CloneErrors:     m.CloneErrors.Load(),
		ScanErrors:      m.ScanErrors.Load(),
		BlockedRequests: m.BlockedRequests.Load(),
		CloneTimesMs:    stats(m.cloneTimes),
		ScanTimesMs:     stats(m.scanTimes),
		TotalTimesMs:    stats(m.totalTimes),
	}
}

// IncrementBlockedRequests increments the blocked requests counter.
func (m *Metrics) IncrementBlockedRequests() {
	m.BlockedRequests.Add(1)
}

// JSON returns metrics as JSON.
func (m *Metrics) JSON() ([]byte, error) {
	return json.MarshalIndent(m.GetSnapshot(), "", "  ")
}

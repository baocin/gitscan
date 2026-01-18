package metrics

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestNewMetrics(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.StartTime.IsZero() {
		t.Error("StartTime not initialized")
	}
}

func TestScanStarted(t *testing.T) {
	m := New()

	// Start a scan
	done := m.ScanStarted()
	if m.TotalScans.Load() != 1 {
		t.Errorf("TotalScans = %d, want 1", m.TotalScans.Load())
	}
	if m.ActiveScans.Load() != 1 {
		t.Errorf("ActiveScans = %d, want 1", m.ActiveScans.Load())
	}
	if m.PeakConcurrent.Load() != 1 {
		t.Errorf("PeakConcurrent = %d, want 1", m.PeakConcurrent.Load())
	}

	// Complete the scan
	time.Sleep(10 * time.Millisecond) // Ensure some duration is recorded
	done()

	if m.ActiveScans.Load() != 0 {
		t.Errorf("ActiveScans = %d, want 0 after done", m.ActiveScans.Load())
	}
	if m.TotalScans.Load() != 1 {
		t.Errorf("TotalScans = %d, want 1 (unchanged)", m.TotalScans.Load())
	}
}

func TestConcurrentScans(t *testing.T) {
	m := New()
	numScans := 10

	var wg sync.WaitGroup
	wg.Add(numScans)

	// Start all scans concurrently
	dones := make([]func(), numScans)
	var mu sync.Mutex

	for i := 0; i < numScans; i++ {
		go func(idx int) {
			done := m.ScanStarted()
			mu.Lock()
			dones[idx] = done
			mu.Unlock()
			wg.Done()
		}(i)
	}

	wg.Wait()

	// All scans should be active
	if m.ActiveScans.Load() != int64(numScans) {
		t.Errorf("ActiveScans = %d, want %d", m.ActiveScans.Load(), numScans)
	}
	if m.PeakConcurrent.Load() != int64(numScans) {
		t.Errorf("PeakConcurrent = %d, want %d", m.PeakConcurrent.Load(), numScans)
	}

	// Complete all scans
	for _, done := range dones {
		done()
	}

	if m.ActiveScans.Load() != 0 {
		t.Errorf("ActiveScans = %d, want 0 after all done", m.ActiveScans.Load())
	}
	if m.TotalScans.Load() != int64(numScans) {
		t.Errorf("TotalScans = %d, want %d", m.TotalScans.Load(), numScans)
	}
}

func TestPeakConcurrentTracking(t *testing.T) {
	m := New()

	// Start 3 scans
	done1 := m.ScanStarted()
	done2 := m.ScanStarted()
	done3 := m.ScanStarted()

	if m.PeakConcurrent.Load() != 3 {
		t.Errorf("PeakConcurrent = %d, want 3", m.PeakConcurrent.Load())
	}

	// Complete one scan
	done1()

	if m.ActiveScans.Load() != 2 {
		t.Errorf("ActiveScans = %d, want 2", m.ActiveScans.Load())
	}

	// Peak should still be 3
	if m.PeakConcurrent.Load() != 3 {
		t.Errorf("PeakConcurrent = %d, want 3 (unchanged)", m.PeakConcurrent.Load())
	}

	// Start 2 more scans (total 4 active)
	done4 := m.ScanStarted()
	done5 := m.ScanStarted()

	if m.PeakConcurrent.Load() != 4 {
		t.Errorf("PeakConcurrent = %d, want 4", m.PeakConcurrent.Load())
	}

	done2()
	done3()
	done4()
	done5()

	if m.ActiveScans.Load() != 0 {
		t.Errorf("ActiveScans = %d, want 0", m.ActiveScans.Load())
	}
}

func TestRecordCloneTime(t *testing.T) {
	m := New()

	m.RecordCloneTime(100 * time.Millisecond)
	m.RecordCloneTime(200 * time.Millisecond)
	m.RecordCloneTime(300 * time.Millisecond)

	snapshot := m.GetSnapshot()
	if snapshot.CloneTimesMs["count"] != 3 {
		t.Errorf("clone count = %d, want 3", snapshot.CloneTimesMs["count"])
	}
	if snapshot.CloneTimesMs["min"] != 100 {
		t.Errorf("clone min = %d, want 100", snapshot.CloneTimesMs["min"])
	}
	if snapshot.CloneTimesMs["max"] != 300 {
		t.Errorf("clone max = %d, want 300", snapshot.CloneTimesMs["max"])
	}
	if snapshot.CloneTimesMs["avg"] != 200 {
		t.Errorf("clone avg = %d, want 200", snapshot.CloneTimesMs["avg"])
	}
}

func TestRecordScanTime(t *testing.T) {
	m := New()

	m.RecordScanTime(50 * time.Millisecond)
	m.RecordScanTime(100 * time.Millisecond)

	snapshot := m.GetSnapshot()
	if snapshot.ScanTimesMs["count"] != 2 {
		t.Errorf("scan count = %d, want 2", snapshot.ScanTimesMs["count"])
	}
	if snapshot.ScanTimesMs["min"] != 50 {
		t.Errorf("scan min = %d, want 50", snapshot.ScanTimesMs["min"])
	}
	if snapshot.ScanTimesMs["max"] != 100 {
		t.Errorf("scan max = %d, want 100", snapshot.ScanTimesMs["max"])
	}
}

func TestCacheHitRate(t *testing.T) {
	m := New()

	m.CacheHits.Add(3)
	m.CacheMisses.Add(7)

	snapshot := m.GetSnapshot()
	if snapshot.CacheHits != 3 {
		t.Errorf("CacheHits = %d, want 3", snapshot.CacheHits)
	}
	if snapshot.CacheMisses != 7 {
		t.Errorf("CacheMisses = %d, want 7", snapshot.CacheMisses)
	}
	if snapshot.CacheHitRate != 30.0 {
		t.Errorf("CacheHitRate = %f, want 30.0", snapshot.CacheHitRate)
	}
}

func TestErrorCounters(t *testing.T) {
	m := New()

	m.CloneErrors.Add(2)
	m.ScanErrors.Add(1)

	snapshot := m.GetSnapshot()
	if snapshot.CloneErrors != 2 {
		t.Errorf("CloneErrors = %d, want 2", snapshot.CloneErrors)
	}
	if snapshot.ScanErrors != 1 {
		t.Errorf("ScanErrors = %d, want 1", snapshot.ScanErrors)
	}
}

func TestJSON(t *testing.T) {
	m := New()

	m.TotalScans.Add(5)
	m.CacheHits.Add(3)
	m.RecordCloneTime(100 * time.Millisecond)

	data, err := m.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Check key fields exist
	if _, ok := result["total_scans"]; !ok {
		t.Error("Missing total_scans in JSON")
	}
	if _, ok := result["uptime"]; !ok {
		t.Error("Missing uptime in JSON")
	}
	if _, ok := result["clone_times_ms"]; !ok {
		t.Error("Missing clone_times_ms in JSON")
	}
}

func TestStatsWithEmptySlice(t *testing.T) {
	result := stats([]int64{})
	if result["count"] != 0 {
		t.Errorf("count = %d, want 0", result["count"])
	}
	if result["min"] != 0 {
		t.Errorf("min = %d, want 0", result["min"])
	}
}

func TestStatsPercentiles(t *testing.T) {
	// Create 100 samples: 1, 2, 3, ..., 100
	times := make([]int64, 100)
	for i := range times {
		times[i] = int64(i + 1)
	}

	result := stats(times)

	if result["count"] != 100 {
		t.Errorf("count = %d, want 100", result["count"])
	}
	if result["min"] != 1 {
		t.Errorf("min = %d, want 1", result["min"])
	}
	if result["max"] != 100 {
		t.Errorf("max = %d, want 100", result["max"])
	}
	// Percentiles use 0-indexed array access: sorted[len*pct/100]
	// For 100 items: p50 = sorted[50] = 51, p95 = sorted[95] = 96, p99 = sorted[99] = 100
	if result["p50"] != 51 {
		t.Errorf("p50 = %d, want 51", result["p50"])
	}
	if result["p95"] != 96 {
		t.Errorf("p95 = %d, want 96", result["p95"])
	}
	if result["p99"] != 100 {
		t.Errorf("p99 = %d, want 100", result["p99"])
	}
}

func TestSlidingWindow(t *testing.T) {
	m := New()

	// Record more than 1000 samples
	for i := 0; i < 1100; i++ {
		m.RecordCloneTime(time.Duration(i) * time.Millisecond)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.cloneTimes) != 1000 {
		t.Errorf("cloneTimes length = %d, want 1000", len(m.cloneTimes))
	}

	// Verify the oldest samples were dropped (first 100)
	// The remaining samples should start from 100
	if m.cloneTimes[0] != 100 {
		t.Errorf("first sample = %d, want 100", m.cloneTimes[0])
	}
}

// BenchmarkConcurrentScanStarted benchmarks concurrent scan tracking
func BenchmarkConcurrentScanStarted(b *testing.B) {
	m := New()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			done := m.ScanStarted()
			done()
		}
	})
}

// BenchmarkRecordCloneTime benchmarks clone time recording
func BenchmarkRecordCloneTime(b *testing.B) {
	m := New()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.RecordCloneTime(100 * time.Millisecond)
		}
	})
}

package tunnel

import (
	"sync"
	"time"
)

// SpeedSample is a single speed measurement.
type SpeedSample struct {
	Timestamp time.Time `json:"timestamp"`
	RxBytes   int64     `json:"rx_bytes"`
	TxBytes   int64     `json:"tx_bytes"`
	RxSpeed   int64     `json:"rx_speed"` // bytes/sec
	TxSpeed   int64     `json:"tx_speed"` // bytes/sec
}

// SessionHistory records a completed tunnel session.
type SessionHistory struct {
	TunnelName string    `json:"tunnel_name"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	TotalRx    int64     `json:"total_rx"`
	TotalTx    int64     `json:"total_tx"`
	Duration   string    `json:"duration"`
}

// StatsCollector collects speed samples for graphing.
type StatsCollector struct {
	mu       sync.Mutex
	samples  []SpeedSample
	maxLen   int
	lastRx   int64
	lastTx   int64
	lastTime time.Time
}

// NewStatsCollector creates a collector keeping the last N samples.
func NewStatsCollector(maxSamples int) *StatsCollector {
	return &StatsCollector{
		maxLen: maxSamples,
	}
}

// Record records a new data point and calculates speed.
func (c *StatsCollector) Record(rxBytes, txBytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	sample := SpeedSample{
		Timestamp: now,
		RxBytes:   rxBytes,
		TxBytes:   txBytes,
	}

	if !c.lastTime.IsZero() {
		elapsed := now.Sub(c.lastTime).Seconds()
		if elapsed > 0 {
			sample.RxSpeed = int64(float64(rxBytes-c.lastRx) / elapsed)
			sample.TxSpeed = int64(float64(txBytes-c.lastTx) / elapsed)
			if sample.RxSpeed < 0 {
				sample.RxSpeed = 0
			}
			if sample.TxSpeed < 0 {
				sample.TxSpeed = 0
			}
		}
	}

	c.lastRx = rxBytes
	c.lastTx = txBytes
	c.lastTime = now

	c.samples = append(c.samples, sample)
	if len(c.samples) > c.maxLen {
		c.samples = c.samples[len(c.samples)-c.maxLen:]
	}
}

// Samples returns the current speed history.
func (c *StatsCollector) Samples() []SpeedSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]SpeedSample, len(c.samples))
	copy(result, c.samples)
	return result
}

// Reset clears all samples.
func (c *StatsCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples = nil
	c.lastRx = 0
	c.lastTx = 0
	c.lastTime = time.Time{}
}

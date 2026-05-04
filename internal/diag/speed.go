package diag

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SpeedTestResult holds download/upload speed test results.
type SpeedTestResult struct {
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
	LatencyMs    float64 `json:"latency_ms"`
	Error        string  `json:"error,omitempty"`
}

// RunSpeedTest performs a simple download speed test.
// Uses a public HTTP endpoint to measure throughput. The caller
// passes a context so the GUI can cancel mid-test (e.g. user closes
// the diagnostics tab) without leaving a 10MB download draining in
// the background.
func RunSpeedTest(ctx context.Context) *SpeedTestResult {
	result := &SpeedTestResult{}

	// Measure latency first
	start := time.Now()
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://www.google.com", nil)
	if err != nil {
		result.Error = fmt.Sprintf("connectivity check setup: %v", err)
		return result
	}
	resp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		result.Error = fmt.Sprintf("connectivity check failed: %v", err)
		return result
	}
	resp.Body.Close()
	result.LatencyMs = float64(time.Since(start).Milliseconds())

	// Download test — Cloudflare speed test endpoint (10 MB). Wrap
	// the per-request context with a 30s deadline so a slow link
	// can't stretch the test forever, but a faster outer ctx
	// cancellation still preempts.
	dlCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	testURL := "https://speed.cloudflare.com/__down?bytes=10000000"
	dlReq, err := http.NewRequestWithContext(dlCtx, http.MethodGet, testURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("download test setup: %v", err)
		return result
	}

	start = time.Now()
	dlResp, err := http.DefaultClient.Do(dlReq)
	if err != nil {
		result.Error = fmt.Sprintf("download test failed: %v", err)
		return result
	}
	defer dlResp.Body.Close()

	bytes, _ := io.Copy(io.Discard, dlResp.Body)
	elapsed := time.Since(start).Seconds()

	if elapsed > 0 && bytes > 0 {
		result.DownloadMbps = float64(bytes) * 8 / elapsed / 1_000_000
	}

	// Upload test skipped for simplicity (would need a server to accept data)
	result.UploadMbps = 0

	return result
}

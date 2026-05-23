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
	// Truncated is set when the download hit the time cap before the
	// full sample arrived. DownloadMbps is still populated with the
	// partial-stream throughput (useful as a lower bound), but the GUI
	// should label it as "≥X Mbps (incomplete)" rather than a precise
	// measurement.
	Truncated bool `json:"truncated,omitempty"`
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

	// Download test. We pick a 10 MB target on the assumption of
	// "broadband" links (≥10 Mbps → ≤8 s). On an LTE-grade 1 Mbps link
	// that would take 80 s, far past any reasonable diagnostic budget.
	// Strategy: ask for 10 MB but cap the read at 60 seconds AND
	// 10 MB whichever comes first. If we hit the time cap we report
	// the partial throughput instead of timing-out with no result.
	const targetBytes = 10_000_000
	const maxDuration = 60 * time.Second
	dlCtx, cancel := context.WithTimeout(ctx, maxDuration)
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

	// LimitReader prevents pathological misconfigured servers from
	// streaming forever; ctx already provides the time cap.
	bytes, copyErr := io.Copy(io.Discard, io.LimitReader(dlResp.Body, targetBytes))
	elapsed := time.Since(start).Seconds()

	// Distinguish "completed download" from "timed out mid-stream".
	// Truncated = true when ctx deadline expired AND we got partial
	// data — the GUI uses this to label the result as a lower bound
	// rather than a precise measurement.
	if dlCtx.Err() == context.DeadlineExceeded && bytes < targetBytes {
		result.Truncated = true
	} else if copyErr != nil && copyErr != io.EOF {
		// Real I/O error (connection reset, etc.) — surface it.
		result.Error = fmt.Sprintf("download stream error: %v", copyErr)
	}

	if elapsed > 0 && bytes > 0 {
		result.DownloadMbps = float64(bytes) * 8 / elapsed / 1_000_000
	}

	// Upload test skipped for simplicity (would need a server to accept data)
	result.UploadMbps = 0

	return result
}

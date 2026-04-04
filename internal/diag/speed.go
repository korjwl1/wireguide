package diag

import (
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
// Uses a public HTTP endpoint to measure throughput.
func RunSpeedTest() *SpeedTestResult {
	result := &SpeedTestResult{}

	// Measure latency first
	start := time.Now()
	resp, err := http.Head("https://www.google.com")
	if err != nil {
		result.Error = fmt.Sprintf("connectivity check failed: %v", err)
		return result
	}
	resp.Body.Close()
	result.LatencyMs = float64(time.Since(start).Milliseconds())

	// Download test — use a known file
	// Cloudflare speed test endpoint (100MB)
	testURL := "https://speed.cloudflare.com/__down?bytes=10000000" // 10MB
	client := &http.Client{Timeout: 30 * time.Second}

	start = time.Now()
	dlResp, err := client.Get(testURL)
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

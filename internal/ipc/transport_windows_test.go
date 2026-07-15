//go:build windows

package ipc

// The tests in this package stand up their own pipe listener in-process.
// `go test` normally runs unelevated, so that pipe is owned by the user SID
// rather than SY/BA and Dial's verifyPipeOwner would reject every
// connection. Accept a self-owned pipe for the duration of the test binary
// so the RPC/framing tests exercise the real transport instead of being
// skipped -- there is no CI job running them elevated.
func init() { allowSelfOwnedPipes = true }

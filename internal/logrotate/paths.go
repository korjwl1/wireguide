package logrotate

// Helper log locations and rotation limits, kept in one place so the
// LaunchDaemon plist, the helper and the packaging scripts agree.
const (
	// HelperLogPath is the macOS helper's own rotated log (slog output).
	HelperLogPath = "/var/log/wireguide-helper.log"
	// HelperStderrPath is where launchd captures the helper's raw
	// stdout/stderr on macOS: panics and runtime output only. launchd
	// appends to it; the helper neither rotates nor trims it.
	HelperStderrPath = "/var/log/wireguide-helper.stderr.log"

	// WindowsLogName is the rotated slog file the Windows helper writes
	// under its data directory when WIREGUIDE_HELPER_STDERR=1.
	WindowsLogName = "helper-stderr.log"
	// WindowsPanicLogName receives the Windows helper's raw stderr (runtime
	// fatal errors, panics) under the same opt-in. It is not rotated per
	// write; the main package only moves it aside to .1 at startup when it
	// is already larger than HelperLogMaxBytes.
	WindowsPanicLogName = "helper-stderr.panic.log"

	// HelperLogMaxBytes is the nominal per-file rotation threshold, checked
	// before each write; HelperLogMaxFiles is how many numbered siblings
	// (.1 ... .N) are kept besides the live file. Steady-state usage is about
	// MaxBytes x (MaxFiles+1), but this is not a hard disk cap: a single
	// Write larger than MaxBytes is written whole, an oversized existing log
	// is kept as the .1 sibling, and the raw stderr/panic capture is not
	// rotated per write.
	HelperLogMaxBytes int64 = 10 << 20
	HelperLogMaxFiles       = 5
)

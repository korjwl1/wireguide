package logrotate

// Helper log locations and rotation limits, kept in one place so the
// LaunchDaemon plist, the helper and the packaging scripts agree.
const (
	// HelperLogPath is the macOS helper's own rotated log (slog output).
	HelperLogPath = "/var/log/wireguide-helper.log"
	// HelperStderrPath is where launchd captures the helper's raw
	// stdout/stderr on macOS: panics and runtime output only.
	HelperStderrPath = "/var/log/wireguide-helper.stderr.log"

	// WindowsLogName is the rotated slog file the Windows helper writes
	// under its data directory when WIREGUIDE_HELPER_STDERR=1.
	WindowsLogName = "helper-stderr.log"
	// WindowsPanicLogName receives the Windows helper's raw stderr (runtime
	// fatal errors, panics) under the same opt-in. It is not rotated per
	// write; see the main package for its startup trimming.
	WindowsPanicLogName = "helper-stderr.panic.log"

	// HelperLogMaxBytes and HelperLogMaxFiles bound each rotated helper log:
	// the live file plus up to MaxFiles numbered siblings (.1 ... .N).
	HelperLogMaxBytes int64 = 10 << 20
	HelperLogMaxFiles       = 5
)

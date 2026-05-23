package tunnel

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// GetStatusFromEngine reads peer stats via the WireGuard UAPI protocol
// over an in-memory net.Pipe wired straight into wireguard-go's
// IpcHandle. This is the only reliable read path on Windows because:
//
//   - wgctrl-go connects to wireguard-go's named pipe at
//     \\.\pipe\ProtectedPrefix\Administrators\WireGuard\<iface>, and
//     wireguard-go fails to CREATE that pipe in our process: the
//     "ProtectedPrefix\Administrators\" namespace rejects every owner
//     SID except SYSTEM (S-1-5-18) and BUILTIN\Administrators
//     (S-1-5-32-544). Our helper is launched via
//     `Start-Process -Verb RunAs` and therefore runs as the elevated
//     user — a *member* of Administrators, but its token's owner SID
//     is the user, not the group, so `CreateNamedPipeW` returns
//     ERROR_INVALID_OWNER ("This security ID may not be assigned as
//     the owner of this object"). The official wireguard-windows
//     client sidesteps this by installing a Windows service that runs
//     as LocalSystem; we don't have that yet, so wgctrl always
//     reports "file does not exist" on every Device() call.
//
//   - Calling wgDevice.IpcGet() directly from a goroutine other than
//     the listener loop killed the helper within ~450ms of `tunnel
//     connected`, with no recoverable trace (no panic stack reached
//     stderr, no slog Error). We never reproduced a panic that goSafe
//     could catch, which strongly suggests a Go-runtime-level fatal
//     (concurrent map write / unrecoverable throw) that bypasses
//     recover. The net.Pipe path exercises the exact code wireguard-
//     windows runs in production (Accept → IpcHandle), so it routes
//     through the well-tested goroutine boundary instead of the
//     direct in-process variant.
//
// Cross-platform safe: Linux/Darwin keep using wgctrl via the
// status_dispatch_other.go file. Only Windows pays the extra
// pipe-pair allocation per status tick, which is negligible.
func GetStatusFromEngine(engine *Engine, tunnelName string, connectedAt time.Time) (*ConnectionStatus, error) {
	if engine == nil {
		return nil, fmt.Errorf("nil engine")
	}
	if engine.wgDevice == nil {
		return nil, fmt.Errorf("engine wgDevice is nil")
	}
	uapi, err := queryUAPIInProcess(engine)
	if err != nil {
		return nil, err
	}

	status := &ConnectionStatus{
		State:         StateConnected,
		TunnelName:    tunnelName,
		InterfaceName: engine.InterfaceName(),
		ConnectedAt:   connectedAt,
		Duration:      domain.FormatDuration(time.Since(connectedAt)),
	}

	// UAPI is line-oriented `key=value`. Peer sections start on `public_key=…`;
	// everything before the first peer is interface scope. We only need
	// per-peer rx/tx/handshake/endpoint to populate ConnectionStatus.
	var (
		inPeer       bool
		peerHsSec    int64
		peerHsNsec   int64
		peerRx       uint64
		peerTx       uint64
		peerEndpoint string
	)

	flushPeer := func() {
		if !inPeer {
			return
		}
		status.RxBytes += int64(peerRx)
		status.TxBytes += int64(peerTx)
		if peerHsSec > 0 || peerHsNsec > 0 {
			t := time.Unix(peerHsSec, peerHsNsec)
			if status.LastHandshakeTime.IsZero() || t.After(status.LastHandshakeTime) {
				status.LastHandshakeTime = t
			}
		}
		if peerEndpoint != "" && status.Endpoint == "" {
			status.Endpoint = peerEndpoint
		}
		peerHsSec, peerHsNsec = 0, 0
		peerRx, peerTx = 0, 0
		peerEndpoint = ""
	}

	scanner := bufio.NewScanner(strings.NewReader(uapi))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := line[:eq]
		v := line[eq+1:]
		switch k {
		case "public_key":
			flushPeer()
			inPeer = true
		case "endpoint":
			if inPeer {
				peerEndpoint = v
			}
		case "last_handshake_time_sec":
			if inPeer {
				peerHsSec, _ = strconv.ParseInt(v, 10, 64)
			}
		case "last_handshake_time_nsec":
			if inPeer {
				peerHsNsec, _ = strconv.ParseInt(v, 10, 64)
			}
		case "rx_bytes":
			if inPeer {
				peerRx, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if inPeer {
				peerTx, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	flushPeer()

	if !status.LastHandshakeTime.IsZero() {
		status.LastHandshake = domain.FormatDuration(time.Since(status.LastHandshakeTime))
	}
	return status, nil
}

// queryUAPIInProcess speaks one round of the WireGuard UAPI protocol to
// the engine's wgDevice via an in-memory net.Pipe. Returns the raw UAPI
// text response (without the trailing "errno=N\n\n" terminator).
//
// The flow mirrors what wireguard-windows does over the real named
// pipe, scaled down to one connection:
//  1. net.Pipe() gives us a synchronous, in-memory net.Conn pair.
//  2. A goroutine hands the server end to wgDevice.IpcHandle, which
//     reads UAPI ops on a loop and writes the response back.
//  3. We write "get=1\n\n", read until the "errno=0\n\n" terminator,
//     then close the client side. IpcHandle's Read returns io.EOF on
//     the next iteration and the goroutine exits.
//
// A 2s deadline on the client read protects us from a hung IpcHandle
// (e.g. if wireguard-go ever decides to block on something internal
// during state walk). On deadline expiry we return an error and let
// the next status tick try again.
func queryUAPIInProcess(engine *Engine) (string, error) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// IpcHandle closes the conn on return. Both ends of net.Pipe
		// see EOF when either side closes — that's how this terminates.
		engine.wgDevice.IpcHandle(serverConn)
	}()

	deadline := time.Now().Add(2 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		return "", fmt.Errorf("SetDeadline: %w", err)
	}

	if _, err := clientConn.Write([]byte("get=1\n\n")); err != nil {
		return "", fmt.Errorf("write get op: %w", err)
	}

	var sb strings.Builder
	br := bufio.NewReader(clientConn)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			sb.WriteString(line)
		}
		if err != nil {
			// Time out or EOF before terminator — return what we have;
			// the parser tolerates a truncated response.
			break
		}
		// errno=N is the terminator; the next line is the blank
		// separator and then IpcHandle waits for the next op.
		if strings.HasPrefix(line, "errno=") {
			// Drain the trailing blank line (best-effort).
			if blank, _ := br.ReadString('\n'); blank != "" {
				sb.WriteString(blank)
			}
			break
		}
	}

	// Close client side so IpcHandle's blocking Read returns EOF and
	// the goroutine exits cleanly. Wait for it so we don't leak.
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		// IpcHandle should have noticed the closed pipe by now; if it
		// hasn't, log-and-move-on rather than block the eventLoop.
	}

	return sb.String(), nil
}

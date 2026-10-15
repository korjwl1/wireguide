# VPN connection indicators on application icons

User-requested follow-up, refs #30/#48. Green means at least one tunnel is
in the helper's `connected` state, matching the tray's connection indicator.
An open GUI, pending restoration or a connecting tunnel alone is not green.
The handshake indicator in the tray menu remains separate.

## Implementation

| Platform | Native mechanism | Scope |
|---|---|---|
| macOS | `NSApplication.applicationIconImage`, reset to nil when disconnected | Running application's Dock image. Icon Services handles Retina scaling and color profiles. |
| Windows | `ITaskbarList3.SetOverlayIcon`, NULL icon to clear | Running taskbar button, including grouped/pinned buttons when the shell enables overlays. Taskbar/Explorer recreation messages reapply the current state. |
| Linux / GTK3 | `gtk_window_set_icon` with a decoded, owned pixbuf | Window managers that display the window's dynamic icon. Some desktops, especially Wayland shells using the static desktop-file icon, ignore this image. |

Linux therefore does **not** have a universal green-dot guarantee across
desktop environments. GTK4 is also outside this pinned GTK3 production path.
No installed icon file or user's icon theme is rewritten to force a badge;
that could leave a false connected icon after a crash. Windows' shell can
disable overlays, for example with legacy small-taskbar-icon settings.
Existing close-to-tray behavior is preserved: if the shell removes a running
Dock/taskbar entry, its static pinned launcher is not a live status display.

The pinned Wails `App.SetIcon` is empty on Windows and only caches the image
for future Linux windows. Its macOS implementation also retains an unowned
Go pointer into a later native dispatch. This feature uses small explicit
native adapters instead of relying on those paths.

The application image keeps the original W tile and adds a green disc with
a white outline in the lower-right corner. The green is the tray's existing
RGB `(52, 199, 89)`. Windows supplies the same disc as a transparent native
overlay, whose placement and scaling are controlled by the shell.

Images are prepared once. Status callbacks only update a small state model;
the GUI-thread queue coalesces changes and waits for runtime readiness.
Steady-state 1 Hz status updates do not decode images or call shell APIs.
No polling or disk writes are added. Shell/window recreation forces a fresh
apply; failures are logged without a per-tick retry loop. Shutdown discards
queued connected updates and explicitly resets the icon once.

Both tray and app icon now consume connected rows rather than the broader
`ActiveTunnels` work list, which also contains connecting tunnels. The
frontend and history still receive the complete original DTO. A detected
helper outage clears the indicators without inventing a history disconnect;
fresh restored status repopulates them. This uses the existing health monitor.

Native ownership is bounded: AppKit retains/releases its image, GTK retains
the current pixbuf and the loader is always closed/unreffed, and Windows
destroys each temporary HICON after the shell copies it. COM creation, use
and release occur in the same GUI-thread apartment.

## Verification

- Complete local Go race suite and vet passed.
- Tests cover startup coalescing, updates during native apply, sibling
  survival, connecting/error states, shutdown, shell refresh and outage
  clearing without changing history. Rendering checks preserve base pixels
  outside the badge and the Windows overlay's transparent background.
- Actual AppKit test on macOS 26.3.1 arm64: 25 On/Off cycles, visible green
  pixel classification and exact default-image restoration — PASS (1.55 s).
  The initial fixture incorrectly sampled unscaled coordinates and compared
  raw RGB across a color-profile conversion; neither failure is claimed as
  a product defect. The final fixture samples normalized Retina coordinates.
- [CI 38720536179](https://github.com/korjwl1/wireguide/actions/runs/38720536179)
  on `6112c1a` passed Windows, macOS and Linux. Linux runs a real GTK/Xvfb
  fixture using the production native bridge: 25 On/Off cycles and exact
  base restoration. Windows tests create/destroy a real native HICON and
  exercise registered taskbar-recreation messages. Ordinary CI does not
  establish a visible Windows taskbar or every Linux desktop's behavior.

This is indicator verification, not a new live VPN/WAN test. The AppKit and
GTK fixtures do not start a VPN or privileged helper. Actual Windows shell
display and individual Wayland desktop support remain environment checks.

## Local application

The macOS `/Applications/WireGuide.app` and ignored workspace bundle were
updated, retaining private `.backup` copies. The existing settings and saved
profile hashes were unchanged. No VPN was connected during the update, and
the existing compatible helper is reused; this feature changes only GUI code.

Private installation evidence: `/private/tmp/wg-connection-icon-m1q3da1f`.
Source/test/build logs and the rendered connected PNG are in SSD scratch
under `wireguide-connection-icon-*` / `application-connected.png`.

## API references

- [Apple applicationIconImage](https://developer.apple.com/documentation/appkit/nsapplication/applicationiconimage)
- [Microsoft SetOverlayIcon](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-itaskbarlist3-setoverlayicon)
- [GTK3 Window.set_icon](https://docs.gtk.org/gtk3/method.Window.set_icon.html)
- Pinned Wails v3.0.0-alpha.74 source: `application_*`, `linux_cgo.go`,
  `mainthread_*` and `w32/taskbar.go` in the local module cache.

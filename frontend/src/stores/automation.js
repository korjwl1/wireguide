import { writable } from 'svelte/store';

// Live automation decision (Wails: GetAutomationPreview). One poller feeds
// the Automation editor strip and the chips on the tunnel list / hero card.
export const automationPreview = writable(null);
// Wall-clock time of the last successful poll, shown as "checked HH:MM:SS"
// where polling is slow (Windows/Linux).
export const automationCheckedAt = writable(0);
// Location Services hint for an unreadable Wi-Fi name: 'denied' when the
// GUI process is on Wi-Fi but cannot read its name (CheckSSIDPermission),
// 'unknown' otherwise. Only fetched while the preview reports an
// unreadable Wi-Fi name, so a healthy network costs nothing.
export const locationAuth = writable('unknown');

const IS_MAC = typeof navigator !== 'undefined' && /Mac/i.test(navigator.platform || navigator.userAgent || '');
// 2 s on macOS while the window is visible (a settle countdown / manual
// latch should feel live); 30 s elsewhere.
export const AUTOMATION_POLL_MS = IS_MAC ? 2000 : 30000;

let timer = null;
let service = null;
let lastJSON = '';
let inflight = false;
// Set while the window is hidden to the tray (Go "window_visibility"
// event). document.visibilityState alone does not cover that case on
// every platform.
let windowHidden = false;

export async function refreshAutomationPreview() {
  if (!service || inflight) return;
  inflight = true;
  try {
    const p = await service.GetAutomationPreview();
    if (p && p.ssid_unknown) {
      try {
        const s = await service.CheckSSIDPermission();
        locationAuth.set(s && s.has_wifi && !s.has_permission ? 'denied' : 'unknown');
      } catch (_) { locationAuth.set('unknown'); }
    }
    const json = JSON.stringify(p);
    // Only notify subscribers on a real change; a 2 s poll of an idle
    // network would otherwise re-render every chip each tick.
    if (json !== lastJSON) {
      lastJSON = json;
      automationPreview.set(p);
    }
    automationCheckedAt.set(Date.now());
  } catch (_) {
    // Older helper / transient IPC failure: hide the strip rather than
    // show stale state.
    if (lastJSON !== '') {
      lastJSON = '';
      automationPreview.set(null);
    }
  } finally {
    inflight = false;
  }
}

function schedule() {
  if (timer) clearInterval(timer);
  timer = setInterval(() => {
    if (!windowHidden && document.visibilityState === 'visible') refreshAutomationPreview();
  }, AUTOMATION_POLL_MS);
}

function onVisibility() {
  if (!windowHidden && document.visibilityState === 'visible') refreshAutomationPreview();
}

// setAutomationWindowVisible pauses polling while the window is hidden to
// the tray and refreshes immediately when it is shown again.
export function setAutomationWindowVisible(visible) {
  windowHidden = !visible;
  if (visible) refreshAutomationPreview();
}

// A focused window is a visible one. The Go side reports reopen through
// "window_visibility", but a missed event must not leave polling paused
// for the rest of the session, so focus re-arms it as a safety net.
function onFocus() {
  setAutomationWindowVisible(true);
}

export function startAutomationPolling(TunnelService) {
  stopAutomationPolling();
  service = TunnelService;
  refreshAutomationPreview();
  schedule();
  document.addEventListener('visibilitychange', onVisibility);
  if (typeof window !== 'undefined') window.addEventListener('focus', onFocus);
}

export function stopAutomationPolling() {
  if (timer) clearInterval(timer);
  timer = null;
  document.removeEventListener('visibilitychange', onVisibility);
  if (typeof window !== 'undefined') window.removeEventListener('focus', onFocus);
  service = null;
  lastJSON = '';
  windowHidden = false;
}

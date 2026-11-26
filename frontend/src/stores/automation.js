import { derived, writable } from 'svelte/store';

// Live automation decision (Wails: GetAutomationPreview). One poller feeds
// the Automation editor strip and the chips on the tunnel list / hero card.
//
// Cadence contract: the poller is a self-rescheduling timeout, not a fixed
// interval. It runs at AUTOMATION_POLL_MS (fast) only while the last
// successful preview was available and listed at least one rule-bearing
// tunnel (`tunnels` non-empty), because only then is there a countdown or
// verdict worth keeping live. Otherwise (no rules, unavailable, or the last
// call failed) it ticks at AUTOMATION_IDLE_POLL_MS so rules added from the
// CLI are still noticed. Nothing is polled while the window is hidden: a
// refresh requested while hidden is skipped, because showing or focusing
// the window always refreshes.
export const automationPreview = writable(null);
export const automationVerdicts = derived(automationPreview, (preview) => {
  const byName = new Map();
  for (const verdict of preview?.tunnels || []) {
    if (!byName.has(verdict.name)) byName.set(verdict.name, verdict);
  }
  return byName;
});
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
// Slow cadence used while there is nothing to keep live.
export const AUTOMATION_IDLE_POLL_MS = 30000;

let timer = null;
let service = null;
let lastJSON = '';
let inflight = false;
// Set while the window is hidden to the tray (Go "window_visibility"
// event). document.visibilityState alone does not cover that case on
// every platform.
let windowHidden = false;
// True when the last successful preview warrants the fast cadence.
let wantFast = false;
// Bumped on every start/stop so a refresh that straddles a restart cannot
// re-arm the timer of the new chain.
let generation = 0;
// A refresh arrived while one was in flight (e.g. right after a rules save);
// run once more when it lands so that result is not stale.
let rerun = false;
let lastStatus = null;

export function refreshAutomationStatus(status) {
  const next = new Map((status?.tunnels || []).map(t => [t.tunnel_name, t.state]));
  for (const name of status?.active_tunnels || []) {
    if (!next.has(name)) next.set(name, 'connected');
  }
  if (status?.tunnel_name && !next.has(status.tunnel_name)) next.set(status.tunnel_name, status.state);
  next.set('', status?.state);
  if (lastStatus && next.size === lastStatus.size && [...next].every(([name, state]) => lastStatus.has(name) && lastStatus.get(name) === state)) return;
  lastStatus = next;
  refreshAutomationPreview();
}

function isHidden() {
  return windowHidden || document.visibilityState !== 'visible';
}

export async function refreshAutomationPreview() {
  if (!service) return;
  if (isHidden()) return;
  if (inflight) { rerun = true; return; }
  inflight = true;
  const gen = generation;
  const currentService = service;
  const current = () => gen === generation && service === currentService;
  try {
    const p = await currentService.GetAutomationPreview();
    if (!current()) return;
    if (p && p.ssid_unknown) {
      try {
        const s = await currentService.CheckSSIDPermission();
        if (!current()) return;
        locationAuth.set(s && s.has_wifi && !s.has_permission ? 'denied' : 'unknown');
      } catch (_) {
        if (!current()) return;
        locationAuth.set('unknown');
      }
    }
    wantFast = !!(p && p.available && p.has_negated_rules && !p.settled);
    const json = JSON.stringify(p);
    // Only notify subscribers on a real change; a 2 s poll of an idle
    // network would otherwise re-render every chip each tick.
    if (json !== lastJSON) {
      lastJSON = json;
      automationPreview.set(p);
    }
    automationCheckedAt.set(Date.now());
  } catch (_) {
    if (!current()) return;
    wantFast = false;
    // Older helper / transient IPC failure: hide the strip rather than
    // show stale state.
    if (lastJSON !== '') {
      lastJSON = '';
      automationPreview.set(null);
    }
  } finally {
    // A stop/start since this call began owns inflight now.
    if (gen === generation) inflight = false;
    // Re-arm from the fresh result so a switch between cadences (first rule
    // added, last rule removed) takes effect now, not a full tick later.
    if (service && gen === generation) {
      schedule();
      if (rerun) { rerun = false; refreshAutomationPreview(); }
    }
  }
}

function schedule() {
  if (timer) clearTimeout(timer);
  timer = null;
  if (!service || isHidden()) return;
  timer = setTimeout(() => {
    timer = null;
    if (!service) return;
    if (!isHidden() && !inflight) refreshAutomationPreview();
    // Keep the chain alive while hidden (a no-op tick); a refresh that ran
    // above re-arms it itself once it completes.
    if (!inflight && !timer) schedule();
  }, wantFast ? AUTOMATION_POLL_MS : AUTOMATION_IDLE_POLL_MS);
}

function onVisibility() {
  if (!isHidden()) refreshAutomationPreview();
  else schedule();
}

// setAutomationWindowVisible pauses polling while the window is hidden to
// the tray and refreshes immediately when it is shown again.
export function setAutomationWindowVisible(visible) {
  windowHidden = !visible;
  if (visible) refreshAutomationPreview();
  else schedule();
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
  generation++;
  wantFast = false;
  refreshAutomationPreview();
  if (!timer) schedule();
  document.addEventListener('visibilitychange', onVisibility);
  if (typeof window !== 'undefined') window.addEventListener('focus', onFocus);
}

export function stopAutomationPolling() {
  generation++;
  inflight = false;
  if (timer) clearTimeout(timer);
  timer = null;
  document.removeEventListener('visibilitychange', onVisibility);
  if (typeof window !== 'undefined') window.removeEventListener('focus', onFocus);
  service = null;
  lastJSON = '';
  windowHidden = false;
  wantFast = false;
  rerun = false;
  lastStatus = null;
}

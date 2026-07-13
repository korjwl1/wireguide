<script>
  import { onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import TunnelList from './lib/TunnelList.svelte';
  import TunnelDetail from './lib/TunnelDetail.svelte';
  import ConflictWarning from './lib/ConflictWarning.svelte';
  import ConfigEditor from './lib/ConfigEditor.svelte';
  import Settings from './lib/Settings.svelte';
  import LogViewer from './lib/LogViewer.svelte';
  import History from './lib/History.svelte';
  import DNSLeakTest from './lib/DNSLeakTest.svelte';
  import RouteVisualization from './lib/RouteVisualization.svelte';
  import StatsDashboard from './lib/StatsDashboard.svelte';
  import UpdateNotice from './lib/UpdateNotice.svelte';
  import { tunnels, selectedTunnel, refreshTunnels, refreshStatus, subscribeToEvents, unsubscribe, initialLoad, connectionStatus } from './stores/tunnels.js';
  import { applyTheme, initThemeWatcher } from './stores/theme.js';
  import { startLogListener, stopLogListener } from './stores/logs.js';
  import { compactList, listSort, listActiveOnTop } from './stores/ui.js';
  import { errText } from './lib/errors.js';
  import { t, setLanguage, detectLanguage } from './i18n/index.js';
  import { TunnelService } from '../bindings/github.com/korjwl1/wireguide/internal/app';
  import Icon from './lib/Icon.svelte';

  // View state
  let currentView = 'tunnels'; // 'tunnels' | 'history' | 'dnsleak' | 'routes' | 'logs'


  // Modal state
  let showEditor = false;
  let showSettings = false;
  let showConflictWarning = false;
  let showZipResult = false;
  let zipResults = [];
  let conflictList = [];
  let pendingConnectName = '';
  let editName = '';
  let editorContent = '';
  let editorOriginalName = ''; // preserved across bind updates for rename detection
  let editorErrors = [];
  let toast = '';
  let toastTimer = null;
  let updateInfo = null;
  // updateState mirrors GetUpdateState() — brew detection + persisted
  // last-checked timestamp. Loaded once at startup; refreshed by the
  // Settings → About "Check now" flow.
  let updateState = null;
  let filesDroppedUnsub = null;
  let helperUnsub = null;
  let helperResetUnsub = null;
  let wifiSsidUnsub = null;
  let autoConnectedUnsub = null;
  let criticalErrorUnsub = null;
  let updateUnsub = null;
  let criticalErrors = []; // array of { where, detail, at } — shown as a persistent banner

  // App-level ESC handler: close the editor modal. ConfigEditor wraps
  // a CodeMirror instance whose own keymaps may handle ESC for things
  // like closing autocomplete dropdowns; we register in CAPTURE phase
  // so we close the modal as soon as the editor isn't doing something
  // else with ESC. stopPropagation prevents CodeMirror from also
  // running its handler when we've decided to close.
  function appEscHandler(e) {
    if (e.key !== 'Escape') return;
    if (showEditor) {
      showEditor = false;
      e.preventDefault();
      e.stopPropagation();
    }
  }
  if (typeof window !== 'undefined') {
    window.addEventListener('keydown', appEscHandler, { capture: true });
    onDestroy(() => window.removeEventListener('keydown', appEscHandler, { capture: true }));
  }

  onMount(async () => {
    // Load and apply saved theme before loading other data.
    // applyTheme sets the data-theme attribute AND the resolvedTheme store
    // that CodeMirror subscribes to for its own light/dark swap.
    try {
      const s = await TunnelService.GetSettings();
      applyTheme(s?.theme || 'system');
      compactList.set(s?.compact_list ?? false);
      listSort.set(s?.list_sort || 'name_asc');
      listActiveOnTop.set(s?.list_active_on_top ?? true);
      // Apply persisted language. 'auto' means "follow OS locale" — we
      // resolve that via detectLanguage(). Without this, launching the
      // app always showed the detected language even if the user had
      // explicitly picked Korean before.
      const lang = s?.language || 'auto';
      setLanguage(lang === 'auto' ? detectLanguage() : lang);
    } catch (e) {
      applyTheme('system');
    }
    initThemeWatcher();

    // Start piping backend log events into the LogViewer store BEFORE
    // initialLoad so the first slog records (tunnel list scan, etc.) are
    // captured. Idempotent.
    startLogListener();

    await initialLoad(TunnelService);
    subscribeToEvents();
    // Remember the network we launched on (covers Ethernet, which fires
    // no wifi_ssid event) so the Automation "this network" pick-list has
    // it available.
    TunnelService.RecordCurrentNetwork().catch(() => {});
    // Refresh status once on launch — the helper's eventLoop only
    // BROADCASTS on diff, so a fresh GUI subscriber connecting to a
    // long-running helper would otherwise see no status events
    // until the next state change. Without this, the tray and detail
    // pane lie about connection state for an unbounded window.
    try {
      await refreshStatus(TunnelService);
    } catch (_) {
      /* helper may be mid-restart; status will arrive via events */
    }

    // Update notifications now come from the Go-side scheduler via the
    // 'update-available' Wails event (see internal/update/scheduler.go).
    // The scheduler handles cadence (24h ±10%), jitter, ETag caching,
    // and dev-build skip — none of which the launch-only check we used
    // to do here could provide. See research-update-patterns for the
    // rationale (wireguard-windows, VS Code, Obsidian cadences).
    updateUnsub = Events.On('update-available', (event) => {
      const info = event.data || {};
      if (!info?.available) return;
      // Backend already filters out dismissed + already-notified versions
      // (see scheduler.maybeNotify), so every emit here is a fresh
      // banner the user should see.
      updateInfo = info;
    });
    try {
      updateState = await TunnelService.GetUpdateState();
    } catch (_) { /* GetUpdateState is best-effort UI hint */ }

    // Wails v3 native file drop — HTML5 dragdrop doesn't work in WebKit.
    // Event payload: { files: string[], details: {...} }
    filesDroppedUnsub = Events.On('files-dropped', async (event) => {
      const payload = event.data || {};
      const paths = payload.files || [];
      for (const path of paths) {
        const lower = path.toLowerCase();
        if (lower.endsWith('.conf')) {
          await importFromPath(path);
        } else if (lower.endsWith('.zip')) {
          await importZipFromPath(path);
        } else if (/\.(png|jpe?g|webp)$/.test(lower)) {
          await importQRFromPath(path);
        } else {
          showToast('Only .conf, .zip, and QR image files are supported');
        }
      }
    });

    // Helper health events (crash detection)
    helperUnsub = Events.On('helper', (event) => {
      const { alive, message } = event.data || {};
      if (!alive) {
        showToast('⚠ ' + (message || 'Helper process disconnected'));
      } else {
        showToast('Helper reconnected');
      }
    });

    // Helper reset — the GUI's IPC client was swapped after a helper
    // restart. Local caches may be stale; re-fetch everything AND
    // close any in-flight modals whose state references something
    // the new helper may not have. ConflictWarning's pendingConnectName
    // for instance can point at a tunnel the helper just lost.
    helperResetUnsub = Events.On('helper_reset', async () => {
      showConflictWarning = false;
      conflictList = [];
      pendingConnectName = '';
      // Critical errors from the OLD helper are no longer relevant —
      // the new helper started clean. Clearing here prevents stale
      // banners from staying visible after a recovery.
      criticalErrors = [];
      await initialLoad(TunnelService);
      await refreshStatus(TunnelService);
    });

    // Wi-Fi SSID change events are still broadcast by the helper for
    // observability, but rule evaluation now lives in the helper
    // itself (internal/helper/wifi_rules_darwin.go). That keeps
    // auto-connect / auto-disconnect working when the GUI is fully
    // quit — the helper has KeepAlive=true and runs the rules
    // independently. We just show a brief toast here so the user
    // sees what happened.
    wifiSsidUnsub = Events.On('wifi_ssid', (event) => {
      const { new_ssid } = event.data || {};
      if (new_ssid) {
        showToast(`Wi-Fi: ${new_ssid}`);
      }
      // Passively remember the network we just joined so the Automation
      // editor's "this network" pick-list accumulates as the user roams,
      // not only when they open the editor.
      TunnelService.RecordCurrentNetwork().catch(() => {});
    });

    // Helper auto-connected a tunnel via Wi-Fi rules.
    // EventStatus broadcast handles tunnel state/status update within 1s.
    // Only need to apply firewall settings here (same as after manual connect).
    autoConnectedUnsub = Events.On('auto_connected', async () => {
      await applyFirewallSettings();
    });

    // Critical helper-side failures (background goroutine exceeded its
    // restart budget). Show as a persistent banner — these mean some
    // helper subsystem (status broadcast, latency probe, wifi rules)
    // is permanently dead and the user should restart the helper.
    criticalErrorUnsub = Events.On('critical_error', (event) => {
      const { where, detail } = event.data || {};
      const next = [...criticalErrors, {
        where: where || 'unknown',
        detail: detail || '',
        at: new Date().toLocaleTimeString(),
      }];
      // Cap at the 5 most recent entries. A storm of helper goSafe
      // give-ups (e.g. multiple loops failing on a shared dependency)
      // would otherwise fill the screen with banners and freeze the UI.
      criticalErrors = next.slice(-5);
    });
  });

  onDestroy(() => {
    unsubscribe();
    stopLogListener();
    if (filesDroppedUnsub) filesDroppedUnsub();
    if (helperUnsub) helperUnsub();
    if (helperResetUnsub) helperResetUnsub();
    if (wifiSsidUnsub) wifiSsidUnsub();
    if (autoConnectedUnsub) autoConnectedUnsub();
    if (criticalErrorUnsub) criticalErrorUnsub();
    if (updateUnsub) updateUnsub();
    if (toastTimer) clearTimeout(toastTimer);
  });

  function dismissCriticalError(idx) {
    criticalErrors = criticalErrors.filter((_, i) => i !== idx);
  }

  function showToast(msg) {
    if (toastTimer) clearTimeout(toastTimer);
    toast = msg;
    toastTimer = setTimeout(() => { toast = ''; toastTimer = null; }, 3000);
  }

  // sanitizeImportName maps an arbitrary filename stem to something
  // ValidateTunnelName will accept — letters, digits, '-', '_', spaces only.
  // Phone screenshots and shared QR images often have names like
  // "Some QR (1).png" or "WG · backup.png" that the validator would reject;
  // refusing the import outright is worse UX than auto-cleaning the name.
  function sanitizeImportName(raw) {
    if (!raw) return 'tunnel';
    let s = raw.replace(/[^A-Za-z0-9\-_ ]+/g, '-')
               .replace(/-{2,}/g, '-')
               .replace(/^[-\s]+|[-\s]+$/g, '');
    if (s.length > 64) s = s.slice(0, 64).replace(/[-\s]+$/g, '');
    return s || 'tunnel';
  }

  // Generate a unique tunnel name by appending -1, -2, etc. if needed.
  // The base is sanitised first so callers can pass a raw filename stem.
  async function uniqueName(baseName) {
    const cleaned = sanitizeImportName(baseName);
    if (!(await TunnelService.TunnelExists(cleaned))) return cleaned;
    for (let i = 1; i < 1000; i++) {
      const candidate = `${cleaned}-${i}`;
      if (!(await TunnelService.TunnelExists(candidate))) return candidate;
    }
    return cleaned + '-' + Date.now();
  }

  // Show zip import result modal.
  function showZipResults(results) {
    zipResults = results;
    showZipResult = true;
    if (results.some(r => !r.error)) {
      refreshTunnels(TunnelService);
    }
  }

  // Import a .zip from a filesystem path (used by native file drop).
  async function importZipFromPath(path) {
    try {
      const results = await TunnelService.ImportZip(path);
      showZipResults(results);
    } catch (e) {
      showToast('Import failed: ' + errText(e));
    }
  }

  // Import a .zip from a browser File object (used by file picker).
  // Wails serialises []byte as a base64 JSON string, so we must encode manually.
  // btoa(String.fromCharCode(...bytes)) blows the call stack on large files, so
  // we process in 8 KB chunks.
  async function importZipFromFile(file) {
    if (!file) return;
    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let binary = '';
      const CHUNK = 8192;
      for (let i = 0; i < bytes.length; i += CHUNK) {
        binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
      }
      const results = await TunnelService.ImportZipData(btoa(binary));
      showZipResults(results);
    } catch (e) {
      showToast('Import failed: ' + errText(e));
    }
  }

  // Import from a file path (used by native file drop).
  async function importFromPath(path) {
    try {
      const content = await TunnelService.ReadFile(path);
      const errors = await TunnelService.ValidateConfig(content);
      if (errors && errors.length > 0) {
        showToast('Invalid config: ' + errors[0]);
        return;
      }
      const baseName = await TunnelService.BaseName(path);
      const name = await uniqueName(baseName);
      await TunnelService.ImportConfig(name, content);
      showToast(`Imported "${name}"`);
      await refreshTunnels(TunnelService);
    } catch (e) {
      showToast("Import failed: " + errText(e));
    }
  }

  // Import a QR-coded WireGuard config from an image at a filesystem path
  // (native file drop). Backend reads the file directly so we don't have to
  // shuttle the bytes through JS for the common drop path.
  async function importQRFromPath(path) {
    try {
      const baseName = await TunnelService.BaseName(path);
      const name = await uniqueName(baseName || 'tunnel');
      await TunnelService.ImportQRFromPath(path, name);
      showToast(`Imported "${name}"`);
      await refreshTunnels(TunnelService);
    } catch (e) {
      showToast('QR import failed: ' + errText(e));
    }
  }

  // Import from a browser File object representing an image with a QR code.
  // Encodes the bytes as base64 (Wails serialises []byte that way) using the
  // same chunked approach as importZipFromFile to avoid call-stack blowups.
  async function importQRFromFile(file) {
    if (!file) return;
    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let binary = '';
      const CHUNK = 8192;
      for (let i = 0; i < bytes.length; i += CHUNK) {
        binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
      }
      const baseName = file.name.replace(/\.[^.]+$/, '') || 'tunnel';
      const name = await uniqueName(baseName);
      await TunnelService.ImportQRFromBytes(btoa(binary), name);
      showToast(`Imported "${name}"`);
      await refreshTunnels(TunnelService);
    } catch (e) {
      showToast('QR import failed: ' + errText(e));
    }
  }

  // Import from a browser File object (used by file picker button).
  async function importFile(file) {
    if (!file) return;
    const baseName = file.name.replace(/\.conf$/i, '');
    const content = await file.text();
    try {
      const errors = await TunnelService.ValidateConfig(content);
      if (errors && errors.length > 0) {
        showToast('Invalid config: ' + errors[0]);
        return;
      }
      const name = await uniqueName(baseName);
      await TunnelService.ImportConfig(name, content);
      showToast(`Imported "${name}"`);
      await refreshTunnels(TunnelService);
    } catch (e) {
      showToast("Import failed: " + errText(e));
    }
  }

  async function handleImportOpen() {
    // Directly open the native file picker — no modal needed.
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.conf,.zip,.png,.jpg,.jpeg,.webp';
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const lower = file.name.toLowerCase();
      if (lower.endsWith('.zip')) {
        await importZipFromFile(file);
      } else if (/\.(png|jpe?g|webp)$/.test(lower)) {
        await importQRFromFile(file);
      } else {
        await importFile(file);
      }
    };
    input.click();
  }

  let editorIsNew = false;

  async function handleNewTunnelOpen() {
    editName = '';
    editorContent = ''; // ConfigEditor will generate template when isNew + empty
    editorErrors = [];
    editorIsNew = true;
    showEditor = true;
  }

  // editGen serializes rapid Edit clicks: a slow GetConfigText for
  // tunnel A that resolves AFTER the user has clicked Edit on tunnel
  // B would otherwise overwrite editorContent with A's content while
  // editorOriginalName already points at B — leading to RenameTunnel
  // being called against the wrong tunnel on save.
  let editGen = 0;
  async function handleEdit(e) {
    const myGen = ++editGen;
    const name = e.detail;
    try {
      const content = await TunnelService.GetConfigText(name);
      // If a newer Edit click arrived while we were awaiting, drop
      // this stale resolution.
      if (myGen !== editGen) return;
      editName = name;
      editorOriginalName = name;
      editorContent = content;
      editorErrors = [];
      editorIsNew = false;
      showEditor = true;
    } catch (err) {
      if (myGen !== editGen) return;
      // Surface the failure as a toast so the user knows why the
      // editor didn't open. Silently console.error'ing left them
      // clicking Edit repeatedly with no feedback.
      showToast(`Edit failed: ${errText(err)}`);
    }
  }

  async function doSave(e) {
    const { name: saveName, content: saveContent } = e.detail;
    // Capture the original name into a local at the top of doSave —
    // editorOriginalName is reset by handleEdit on every Edit click,
    // and an Edit on a *different* tunnel arriving while UpdateConfig
    // is in flight would otherwise make the rollback rename to the
    // wrong target.
    const originalName = editorOriginalName;
    editorErrors = [];

    if (!saveName) {
      editorErrors = [$t('editor.name_required')];
      return;
    }

    try {
      const errors = await TunnelService.ValidateConfig(saveContent);
      if (errors && errors.length > 0) {
        editorErrors = errors;
        return;
      }
      if (editorIsNew) {
        await TunnelService.ImportConfig(saveName, saveContent);
      } else {
        const renamed = saveName !== originalName;
        if (renamed) {
          await TunnelService.RenameTunnel(originalName, saveName);
        }
        try {
          await TunnelService.UpdateConfig(saveName, saveContent);
        } catch (err) {
          // UpdateConfig failed AFTER the rename succeeded. Roll
          // the rename back so the file system matches the user's
          // mental model. If rollback itself fails (e.g. the
          // original name now collides with another freshly-imported
          // tunnel), surface BOTH errors so the user understands the
          // genuinely-broken state.
          if (renamed) {
            try {
              await TunnelService.RenameTunnel(saveName, originalName);
            } catch (rollbackErr) {
              showToast(`Rename rollback failed: ${errText(rollbackErr)}`);
            }
          }
          throw err;
        }
        if (renamed) {
          selectedTunnel.update(sel => sel ? { ...sel, name: saveName } : sel);
        }
      }
      showEditor = false;
      await refreshTunnels(TunnelService);
    } catch (err) {
      editorErrors = [errText(err)];
    }
  }

  async function handleRefresh() {
    await refreshTunnels(TunnelService);
  }

  async function handleExport(e) {
    const name = e.detail;
    try {
      const path = await TunnelService.ExportTunnel(name);
      if (path) {
        showToast(`Exported to ${path}`);
      }
    } catch (err) {
      showToast('Export failed: ' + err.toString());
    }
  }

  // Apply kill switch and DNS protection based on saved settings.
  // Called after any successful connect (manual or auto).
  async function applyFirewallSettings() {
    try {
      const s = await TunnelService.GetSettings();
      if (s?.kill_switch) await TunnelService.SetKillSwitch(true);
      if (s?.dns_protection) await TunnelService.SetDNSProtection(true);
    } catch (e) {
      console.warn('auto-apply firewall settings failed:', e);
    }
  }

  // Actually perform the connect RPC (after all warnings have been resolved).
  async function doConnectFinal(name) {
    try {
      await TunnelService.Connect(name);
      await refreshTunnels(TunnelService);
      await refreshStatus(TunnelService);
      await applyFirewallSettings();
    } catch (e) {
      showToast("Connect failed: " + errText(e));
    }
  }

  // Check for routing conflicts before connecting. If conflicts exist, show
  // the ConflictWarning dialog; otherwise proceed directly.
  async function doConnect(name) {
    try {
      const conflicts = await TunnelService.CheckConflicts(name);
      if (conflicts && conflicts.length > 0) {
        conflictList = conflicts;
        pendingConnectName = name;
        showConflictWarning = true;
        return;
      }
    } catch (e) {
      // Non-fatal — if the conflict check itself fails, proceed anyway.
      console.warn('conflict check failed:', e);
    }
    await doConnectFinal(name);
  }

  async function handleConflictProceed() {
    showConflictWarning = false;
    await doConnectFinal(pendingConnectName);
  }

  function handleConflictCancel() {
    showConflictWarning = false;
    conflictList = [];
  }

  async function handleConnect(e) {
    const { name } = e.detail;
    await doConnect(name);
  }

  async function handleUpdate() {
    try {
      await TunnelService.RunUpdate(updateInfo);
    } catch (e) {
      showToast('Update failed: ' + (e?.message || e));
    }
  }

  async function handleDismissUpdate(version) {
    try {
      await TunnelService.DismissUpdate(version);
    } catch (_) { /* dismissal is best-effort */ }
    updateInfo = null;
  }
</script>

<!-- The `$: $locale` subscription in the script block lets every `$t(...)`
     call inside this template re-evaluate on language change. Modals are
     separate components mounted conditionally below; they pick up the new
     language on their next open (deliberate — otherwise changing language
     mid-interaction would destroy the modal). -->
<div class="app" class:modal-open={showSettings || showEditor || showConflictWarning || showZipResult} data-file-drop-target={!(showSettings || showEditor || showConflictWarning || showZipResult) && currentView === 'tunnels' ? true : undefined}>
  <!-- Wails adds .file-drop-target-active class to .app when dragging files.
       We only render the overlay when drop-target is actually active — i.e.
       on the tunnels view with no modal open — so it can never steal clicks
       from modals. The data-file-drop-target attribute above also removes
       the drop affordance entirely in those states so Wails doesn't even
       detect the drag. -->
  {#if currentView === 'tunnels' && !(showSettings || showEditor || showConflictWarning || showZipResult)}
    <div class="drop-overlay">
      <div class="drop-overlay-content">
        <div class="drop-icon">
          <Icon name="download" size={40} strokeWidth={1.5} />
        </div>
        <div class="drop-text">{$t('tunnel.drop_overlay')}</div>
      </div>
    </div>
  {/if}

  {#if toast}
    <div class="toast">{toast}</div>
  {/if}

  {#if criticalErrors.length > 0}
    <div class="critical-banner" role="alert">
      <div class="critical-banner-title">⚠ Helper subsystem failure</div>
      {#each criticalErrors as e, i}
        <div class="critical-banner-row">
          <span class="critical-banner-where">{e.where}</span>
          <span class="critical-banner-detail">{e.detail}</span>
          <span class="critical-banner-time">{e.at}</span>
          <button class="critical-banner-close" on:click={() => dismissCriticalError(i)} aria-label="Dismiss">×</button>
        </div>
      {/each}
      <div class="critical-banner-hint">Restart the app to recover the affected subsystem.</div>
    </div>
  {/if}

  <div class="layout">
    <nav class="sidebar">
      <div class="brand-area">
        <img class="brand-mark" src="/wireguide.svg" alt="WireGuide" width="38" height="38" />
        <div class="brand-text">
          <span class="brand-name">WireGuide</span>
          <span class="brand-tagline">WireGuard VPN</span>
        </div>
      </div>

      <div class="nav-group">
        <button class="nav-item" class:active={currentView === 'tunnels'} on:click={() => currentView = 'tunnels'}>
          <span class="nav-icon-box">
            <Icon name="shield" size={15} strokeWidth={2} />
          </span>
          <span class="nav-label">{$t('nav.tunnels')}</span>
          {#if ($connectionStatus?.active_tunnels || []).length > 0}
            <span class="nav-badge">{($connectionStatus.active_tunnels).length}</span>
          {/if}
        </button>
        <button class="nav-item" class:active={currentView === 'history'} on:click={() => currentView = 'history'}>
          <span class="nav-icon-box">
            <Icon name="clock" size={15} strokeWidth={2} />
          </span>
          <span class="nav-label">{$t('nav.history')}</span>
        </button>
      </div>

      <div class="nav-group">
        <span class="nav-group-label">{$t('nav.tools')}</span>
        <button class="nav-item" class:active={currentView === 'dnsleak'} on:click={() => currentView = 'dnsleak'}>
          <span class="nav-icon-box">
            <Icon name="activity" size={15} strokeWidth={2} />
          </span>
          <span class="nav-label">{$t('tools.tab_dns_leak')}</span>
        </button>
        <button class="nav-item" class:active={currentView === 'routes'} on:click={() => currentView = 'routes'}>
          <span class="nav-icon-box">
            <Icon name="network" size={15} strokeWidth={2} />
          </span>
          <span class="nav-label">{$t('tools.tab_routes')}</span>
        </button>
        <button class="nav-item" class:active={currentView === 'logs'} on:click={() => currentView = 'logs'}>
          <span class="nav-icon-box">
            <Icon name="terminal" size={15} strokeWidth={2} />
          </span>
          <span class="nav-label">{$t('nav.logs')}</span>
        </button>
      </div>

      <div class="nav-spacer"></div>

      <div class="nav-footer">
        <button class="nav-item" on:click={() => showSettings = true}>
          <span class="nav-icon-box">
            <Icon name="settings" size={15} strokeWidth={2} />
          </span>
          <span class="nav-label">{$t('nav.settings')}</span>
        </button>
      </div>
    </nav>

    <!-- Main content -->
    <div class="main-content">
      <UpdateNotice
        {updateInfo}
        onInstall={handleUpdate}
        onDismiss={handleDismissUpdate} />

      {#if currentView === 'tunnels'}
        <div class="tunnels-view">
          <div class="tunnel-list-pane">
            <TunnelList on:import={handleImportOpen} on:new={handleNewTunnelOpen} />
          </div>
          <div class="tunnel-detail-pane">
            {#if $selectedTunnel}
              <TunnelDetail {TunnelService}
                on:edit={handleEdit}
                on:export={handleExport}
                on:connect={handleConnect}
                on:refresh={handleRefresh} />
              {#if $connectionStatus?.state === 'connected' && $connectionStatus?.tunnel_name === $selectedTunnel?.name}
                <div class="stats-section">
                  <StatsDashboard />
                </div>
              {/if}
            {:else}
              <div class="empty-detail">
                <div class="empty-icon-wrap">
                  <Icon name="shield" size={48} strokeWidth={1.25} className="empty-shield" />
                </div>
                <p class="empty-title">{$t('tunnel.no_selection')}</p>
                <div class="empty-actions">
                  <button class="btn-primary" on:click={handleNewTunnelOpen}>
                    <Icon name="plus" size={13} strokeWidth={2} />
                    {$t('tunnel.new_tunnel')}
                  </button>
                  <button class="btn-secondary" on:click={handleImportOpen} title={$t('tunnel.import_hint')}>
                    <Icon name="download" size={13} strokeWidth={2} />
                    {$t('tunnel.import')}
                  </button>
                </div>
                <div class="empty-drop-hint">
                  <Icon name="download" size={12} strokeWidth={1.75} />
                  <span>{$t('tunnel.drop_hint')}</span>
                </div>
              </div>
            {/if}
          </div>
        </div>
      {:else if currentView === 'dnsleak'}
        <div class="tool-view">
          <DNSLeakTest />
        </div>
      {:else if currentView === 'routes'}
        <div class="tool-view">
          <RouteVisualization />
        </div>
      {:else if currentView === 'logs'}
        <div class="logs-view">
          <LogViewer />
        </div>
      {:else if currentView === 'history'}
        <div class="logs-view">
          <History {TunnelService} />
        </div>
      {/if}
    </div>
  </div>

  <!-- Modals -->
  {#if showEditor}
    <div class="modal-backdrop" on:click={() => showEditor = false}>
      <div class="modal modal-editor" on:click|stopPropagation
        role="dialog" aria-modal="true"
        aria-label={editorIsNew ? $t('tunnel.new_tunnel') : $t('tunnel.edit')}>
        <ConfigEditor
          bind:content={editorContent}
          bind:name={editName}
          errors={editorErrors}
          isNew={editorIsNew}
          nameEditable={true}
          on:save={doSave}
          on:cancel={() => showEditor = false} />
      </div>
    </div>
  {/if}

  {#if showSettings}
    <Settings {TunnelService} onClose={() => showSettings = false} {updateInfo} onInstall={handleUpdate} />
  {/if}

  {#if showConflictWarning}
    <ConflictWarning
      conflicts={conflictList}
      on:proceed={handleConflictProceed}
      on:cancel={handleConflictCancel} />
  {/if}

  {#if showZipResult}
    <div class="modal-backdrop" on:click={() => showZipResult = false}>
      <div class="modal modal-zip-result" on:click|stopPropagation
        role="dialog" aria-modal="true" aria-labelledby="zip-result-title">
        <h3 id="zip-result-title">{$t('import.zip_result_title')}</h3>
        <div class="zip-result-list">
          {#each zipResults as r}
            <div class="zip-result-row">
              <span class="zip-result-icon" class:zip-ok={!r.error} class:zip-err={!!r.error}>{r.error ? '✕' : '✓'}</span>
              <span class="zip-result-name" class:zip-err={!!r.error}>{r.name}</span>
              {#if r.error}<span class="zip-result-msg">{r.error}</span>{/if}
            </div>
          {/each}
        </div>
        <div class="zip-result-footer">
          <span class="zip-result-summary">
            {#if zipResults.some(r => !!r.error)}
              {$t('import.zip_summary', { ok: zipResults.filter(r => !r.error).length, fail: zipResults.filter(r => !!r.error).length })}
            {:else}
              {$t('import.zip_summary_ok', { ok: zipResults.length })}
            {/if}
          </span>
          <button class="btn-primary" on:click={() => showZipResult = false}>{$t('import.zip_ok')}</button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  :global(body) {
    margin: 0;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1.38;
    overflow: hidden;
  }
  .app {
    width: 100vw;
    height: 100vh;
    position: relative;
  }

  /* ---------- Drop overlay ----------
   * IMPORTANT: this sits at z-index 1000 and covers the full viewport.
   * `pointer-events: none` is NOT enough on WebKit — a compositing layer
   * created by `backdrop-filter` on a full-viewport element intercepts
   * custom <button> clicks (form controls like <select>/<input> use a
   * separate native event path and still work, which is why the bug
   * looked inconsistent: modal selects worked, modal close buttons
   * didn't). We use `visibility: hidden` by default so the element is
   * completely removed from hit-testing until a drag is actually in
   * progress. `visibility` still transitions with opacity because we
   * only toggle it on the active class.
   */
  .drop-overlay {
    position: fixed;
    inset: 0;
    background: var(--drop-overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: none;
    z-index: 1000;
    opacity: 0;
    visibility: hidden;
  }
  @media (prefers-reduced-motion: no-preference) {
    .drop-overlay { transition: opacity var(--dur-base) var(--ease-out); }
  }
  :global(.file-drop-target-active) > .drop-overlay {
    opacity: 1;
    visibility: visible;
    backdrop-filter: blur(10px) saturate(180%);
    -webkit-backdrop-filter: blur(10px) saturate(180%);
  }
  .drop-overlay-content {
    padding: var(--space-10) var(--space-12);
    background: var(--bg-primary);
    border: 2px dashed var(--accent);
    border-radius: var(--radius-lg);
    text-align: center;
    box-shadow: var(--shadow-lg);
  }
  .drop-icon {
    color: var(--accent);
    margin-bottom: var(--space-2);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .drop-text {
    font: var(--text-title-3);
    color: var(--text-primary);
  }

  /* ---------- Layout ---------- */
  .layout {
    display: flex;
    height: 100%;
  }

  /* ========== SIDEBAR — Material Design Navigation Drawer + Apple Settings hybrid ========== */
  /* Subtle tonal shift from list pane: blends 7% of text color into the base.
   * In dark mode this lifts the sidebar slightly (macOS translucent sidebar
   * feel); in light mode it darkens slightly (Mac Finder sidebar feel). No
   * hard divider line needed — the bg difference IS the hierarchy cue. */
  .sidebar {
    width: 200px;
    background: color-mix(in srgb, var(--bg-secondary) 93%, var(--text-primary));
    display: flex;
    flex-direction: column;
    padding-top: 52px;
    flex-shrink: 0;
  }

  /* ===== Brand area: gradient icon tile + name + tagline ===== */
  .brand-area {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px 18px 16px;
  }
  /* Actual WireGuide logo bitmap. drop-shadow follows the squircle alpha
   * shape (unlike box-shadow which would draw a rectangle). */
  .brand-mark {
    width: 38px;
    height: 38px;
    flex-shrink: 0;
    object-fit: contain;
    filter: drop-shadow(0 6px 14px color-mix(in srgb, var(--accent) 35%, transparent));
    image-rendering: -webkit-optimize-contrast;
  }
  .brand-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
    gap: 1px;
  }
  .brand-name {
    font: 700 14px/18px var(--font-sans);
    color: var(--text-primary);
    letter-spacing: -0.01em;
  }
  .brand-tagline {
    font: 500 10px/13px var(--font-sans);
    color: var(--text-muted);
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }

  /* ===== Nav groups =====
   * No hard dividers — the all-caps section label + spacing carry the
   * hierarchy (macOS Settings.app sidebar pattern). A 0.5px line stretching
   * from edge to edge of a 200px sidebar reads as heavier than intended
   * and competes with the tonal-shift on the sidebar itself. */
  .nav-group {
    padding: 0 8px;
  }
  .nav-group + .nav-group {
    margin-top: 14px;
  }
  .nav-group-label {
    display: block;
    padding: 6px 10px 4px;
    font: 600 10px/13px var(--font-sans);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    user-select: none;
  }

  /* ===== Nav items — bigger, with icon container boxes ===== */
  .nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    height: 42px;
    padding: 0 8px;
    margin-bottom: 1px;
    background: transparent;
    border: 0;
    border-radius: 10px;
    color: var(--text-secondary);
    font: 500 13px/18px var(--font-sans);
    cursor: pointer;
    text-align: left;
    position: relative;
  }
  @media (prefers-reduced-motion: no-preference) {
    .nav-item, .nav-icon-box {
      transition: background-color 140ms ease, color 140ms ease, box-shadow 200ms ease, transform 140ms ease;
    }
  }
  .nav-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .nav-item:hover .nav-icon-box {
    background: color-mix(in srgb, var(--text-muted) 18%, transparent);
    color: var(--text-primary);
  }
  .nav-item:active:not(.active) {
    background: var(--bg-active);
  }

  /* Icon container: 28×28 rounded tile — Apple Music / Settings style */
  .nav-icon-box {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 8px;
    background: color-mix(in srgb, var(--text-muted) 12%, transparent);
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .nav-label {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    letter-spacing: -0.005em;
  }

  /* Connection count badge on Tunnels row */
  .nav-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 20px;
    height: 18px;
    padding: 0 6px;
    border-radius: 9px;
    background: var(--green);
    color: #fff;
    font: 700 10px/1 var(--font-sans);
    box-shadow: 0 0 8px color-mix(in srgb, var(--green) 50%, transparent);
    flex-shrink: 0;
  }

  /* Active state: tonal pill (MD3 secondary container) + filled icon tile */
  .nav-item.active {
    background: color-mix(in srgb, var(--accent) 14%, var(--bg-secondary));
    color: var(--accent);
    font-weight: 700;
  }
  .nav-item.active .nav-icon-box {
    background: var(--accent);
    color: #fff;
    box-shadow: 0 2px 6px color-mix(in srgb, var(--accent) 32%, transparent);
  }

  .nav-spacer { flex: 1; }

  /* Footer — natural padding, no hard divider (whitespace separates) */
  .nav-footer {
    padding: 4px 8px 10px;
  }

  /* ---------- Main content ---------- */
  .main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .tunnels-view {
    display: flex;
    flex: 1;
    overflow: hidden;
  }
  .tunnel-list-pane {
    width: 240px;
    border-right: 0.5px solid var(--border);
    overflow-y: auto;
    background: var(--bg-secondary);
  }
  .tunnel-detail-pane {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    background: var(--bg-primary);
  }
  .stats-section {
    padding: 0 var(--space-6) var(--space-4);
  }

  /* ---------- Empty state ---------- */
  .empty-detail {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    flex: 1;
    color: var(--text-secondary);
    gap: var(--space-3);
    font: var(--text-body);
    padding: var(--space-8);
  }
  .empty-icon-wrap {
    color: var(--text-muted);
    opacity: 0.5;
    margin-bottom: var(--space-1);
  }
  :global(.empty-shield) {
    display: block;
  }
  .empty-title {
    font: var(--text-callout);
    color: var(--text-secondary);
  }
  .empty-actions {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-1);
  }
  /* Drop affordance: small dashed pill below the primary actions so users
   * see at idle that this region accepts dragged files. The full-viewport
   * .drop-overlay (above) only appears during an active drag — this hint
   * communicates the capability beforehand. */
  .empty-drop-hint {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-top: var(--space-3);
    padding: 6px 12px;
    border: 1px dashed color-mix(in srgb, var(--text-muted) 55%, transparent);
    border-radius: 999px;
    color: var(--text-muted);
    font: var(--text-footnote);
    line-height: 1;
  }
  @media (prefers-reduced-motion: no-preference) {
    .empty-drop-hint {
      transition: border-color var(--dur-base, 200ms) var(--ease-out, ease),
                  color var(--dur-base, 200ms) var(--ease-out, ease);
    }
  }
  :global(.file-drop-target-active) .empty-drop-hint {
    border-color: var(--accent);
    color: var(--accent);
  }
  .btn-primary {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 28px;
    padding: 0 var(--space-3);
    background: var(--accent);
    border: 0;
    border-radius: var(--radius-sm);
    color: var(--text-inverse);
    cursor: pointer;
    font: var(--text-headline);
  }
  .btn-primary:hover { filter: brightness(1.08); }
  .btn-primary:active { filter: brightness(0.94); }
  .btn-secondary {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 28px;
    padding: 0 var(--space-3);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    cursor: pointer;
    font: var(--text-headline);
  }
  .btn-secondary:hover { background: var(--bg-hover); }
  .btn-secondary:active { background: var(--bg-active); }
  @media (prefers-reduced-motion: no-preference) {
    .btn-primary, .btn-secondary {
      transition: background-color var(--dur-fast) var(--ease-out),
                  filter var(--dur-fast) var(--ease-out);
    }
  }

  /* ---------- Tool view (individual tool panel) ---------- */
  .tool-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding-top: 52px;
    overflow: hidden;
  }

  .logs-view {
    flex: 1;
    min-height: 0;
    padding-top: 52px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* ---------- Critical helper-failure banner (top-centre, persistent) ---------- */
  .critical-banner {
    position: fixed;
    top: var(--space-3);
    left: 50%;
    transform: translateX(-50%);
    padding: var(--space-3) var(--space-4);
    background: rgba(220, 60, 60, 0.96);
    color: white;
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
    z-index: 400;
    max-width: 640px;
    min-width: 320px;
    font: var(--text-body);
  }
  .critical-banner-title {
    font-weight: 600;
    margin-bottom: var(--space-2);
  }
  .critical-banner-row {
    display: flex;
    align-items: baseline;
    gap: var(--space-2);
    padding: var(--space-1) 0;
    font-size: 0.875rem;
  }
  .critical-banner-where {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-weight: 600;
    flex: 0 0 auto;
  }
  .critical-banner-detail {
    flex: 1 1 auto;
    word-break: break-word;
    opacity: 0.9;
  }
  .critical-banner-time {
    flex: 0 0 auto;
    font-size: 0.75rem;
    opacity: 0.75;
  }
  .critical-banner-close {
    flex: 0 0 auto;
    background: none;
    border: none;
    color: white;
    font-size: 1.125rem;
    cursor: pointer;
    padding: 0 var(--space-2);
    line-height: 1;
  }
  .critical-banner-hint {
    margin-top: var(--space-2);
    font-size: 0.75rem;
    opacity: 0.85;
  }

  /* ---------- Toast (bottom-centre) ---------- */
  .toast {
    position: fixed;
    bottom: var(--space-6);
    left: 50%;
    transform: translateX(-50%);
    padding: var(--space-3) var(--space-4);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--text-primary);
    font: var(--text-body);
    box-shadow: var(--shadow-md);
    z-index: 300;
    max-width: 480px;
    white-space: normal;
    word-break: break-word;
  }

  /* ---------- Modal (shared) ---------- */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    /* NOTE: no backdrop-filter here. WebKit has a known compositing bug
     * where a child element's box-shadow "bleeds" through the parent's
     * backdrop-filter pass, producing a grey halo around the modal's
     * rounded corners (especially visible at modal open/close transitions).
     * The opaque overlay is enough to separate the modal from the app
     * behind it — blur costs clarity for no visual gain here. */
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }
  .modal {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: 14px;
    padding: 22px 24px 18px;
    width: 560px;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: var(--shadow-lg);
  }
  .modal-editor {
    width: 760px;
    height: 500px;
    padding: 0;
    overflow: hidden;
    resize: both;
    min-width: 520px;
    min-height: 360px;
    max-width: calc(100vw - 40px);
    max-height: calc(100vh - 40px);
    border-radius: 14px;
  }
  .modal-zip-result {
    max-width: 90vw;
    max-height: 70vh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  /* Use .modal.modal-zip-result h3 (specificity 0,3,1) to beat
     .modal h3 (0,2,1 after Svelte scoping) which appears later. */
  .modal.modal-zip-result h3 {
    margin: 0;
    flex-shrink: 0;
  }
  .zip-result-list {
    /* flex: 1 + min-height: 0 is the correct pattern for a scrollable
       child inside a max-height flex container. Without min-height: 0
       the child refuses to shrink below its content size, causing the
       outer container to overflow and clip content instead of scroll. */
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .zip-result-footer {
    flex-shrink: 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-3);
  }
  .zip-result-row {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 13px;
    color: var(--text-primary);
  }
  .zip-result-icon {
    flex-shrink: 0;
    font-size: 11px;
  }
  .zip-ok { color: var(--green); }
  .zip-err { color: var(--red); }
  .zip-result-name {
    font-weight: 500;
    word-break: break-all;
  }
  .zip-result-msg {
    color: var(--text-secondary);
    font-size: 12px;
    word-break: break-word;
  }
  .zip-result-summary {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .modal h3 {
    margin: 0 0 var(--space-4);
    color: var(--text-primary);
    font: var(--text-title-2);
  }
  .modal label {
    display: block;
    margin: var(--space-3) 0 var(--space-1);
    font: var(--text-subheadline);
    color: var(--text-secondary);
  }
  .modal input[type="text"] {
    width: 100%;
    height: 24px;
    padding: 0 var(--space-2);
    background: var(--bg-input);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font: var(--text-body);
    box-sizing: border-box;
    outline: none;
  }
  .modal input[type="text"]:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--blue-tint);
  }
  .hint {
    font: var(--text-footnote);
    color: var(--text-secondary);
    margin: 0 0 var(--space-3);
  }
  .btn-file-select {
    width: 100%;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px dashed var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font: var(--text-body);
    cursor: pointer;
    margin-bottom: var(--space-2);
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn-file-select {
      transition: background-color var(--dur-fast) var(--ease-out),
                  border-color var(--dur-fast) var(--ease-out);
    }
  }
  .btn-file-select:hover {
    background: var(--bg-hover);
    border-color: var(--accent);
  }
  .preview {
    margin: var(--space-3) 0;
    padding: var(--space-3);
    background: var(--editor-bg);
    border: 0.5px solid var(--editor-border);
    border-radius: var(--radius-sm);
    font: 10px/14px var(--font-mono);
    color: var(--text-secondary);
    max-height: 200px;
    overflow-y: auto;
    white-space: pre-wrap;
  }
  .errors {
    margin: var(--space-2) 0;
    padding: var(--space-2) var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: var(--radius-sm);
  }
  .errors p {
    margin: var(--space-1) 0;
    color: var(--error-text);
    font: var(--text-body);
  }
  .modal-footer {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
    margin-top: var(--space-4);
  }
  .btn {
    height: 28px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: var(--radius-sm);
    font: var(--text-headline);
    cursor: pointer;
    color: var(--text-primary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-connect {
    background: var(--accent);
    color: var(--text-inverse);
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn, .btn-connect {
      transition: background-color var(--dur-fast) var(--ease-out),
                  filter var(--dur-fast) var(--ease-out);
    }
  }
  .btn-connect:hover:not(:disabled) { filter: brightness(1.08); }
  .btn-connect:active:not(:disabled) { filter: brightness(0.94); }
</style>

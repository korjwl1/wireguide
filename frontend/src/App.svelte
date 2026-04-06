<script>
  import { onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import TunnelList from './lib/TunnelList.svelte';
  import TunnelDetail from './lib/TunnelDetail.svelte';
  import ScriptWarning from './lib/ScriptWarning.svelte';
  import ConflictWarning from './lib/ConflictWarning.svelte';
  import ConfigEditor from './lib/ConfigEditor.svelte';
  import Settings from './lib/Settings.svelte';
  import LogViewer from './lib/LogViewer.svelte';
  import Diagnostics from './lib/Diagnostics.svelte';
  import DNSLeakTest from './lib/DNSLeakTest.svelte';
  import RouteVisualization from './lib/RouteVisualization.svelte';
  import StatsDashboard from './lib/StatsDashboard.svelte';
  import UpdateNotice from './lib/UpdateNotice.svelte';
  import { tunnels, selectedTunnel, refreshTunnels, refreshStatus, subscribeToEvents, unsubscribe, initialLoad, connectionStatus } from './stores/tunnels.js';
  import { applyTheme, initThemeWatcher } from './stores/theme.js';
  import { startLogListener, stopLogListener } from './stores/logs.js';
  import { errText } from './lib/errors.js';
  import { t, setLanguage, detectLanguage } from './i18n/index.js';
  import { TunnelService } from '../bindings/github.com/korjwl1/wireguide/internal/app';

  // View state
  let currentView = 'tunnels'; // 'tunnels' | 'tools' | 'settings' | 'logs'
  let toolsTab = 'diagnostics'; // 'diagnostics' | 'dnsleak' | 'routes'

  // Modal state
  let showEditor = false;
  let showSettings = false;
  let showScriptWarning = false;
  let showConflictWarning = false;
  let conflictList = [];
  let scriptWarningScripts = [];
  let pendingConnectName = '';
  let pendingScriptsAllowed = false;
  let editName = '';
  let editorContent = '';
  let editorErrors = [];
  let toast = '';
  let toastTimer = null;
  let updateInfo = null;
  let filesDroppedUnsub = null;
  let helperUnsub = null;
  let helperResetUnsub = null;

  onMount(async () => {
    // Load and apply saved theme before loading other data.
    // applyTheme sets the data-theme attribute AND the resolvedTheme store
    // that CodeMirror subscribes to for its own light/dark swap.
    try {
      const s = await TunnelService.GetSettings();
      applyTheme(s?.theme || 'system');
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

    // Auto-check for updates (non-blocking, best-effort)
    try {
      const info = await TunnelService.CheckForUpdate();
      if (info?.available) updateInfo = info;
    } catch (e) {
      // Silent — update check failure should never block the app
    }

    // Wails v3 native file drop — HTML5 dragdrop doesn't work in WebKit.
    // Event payload: { files: string[], details: {...} }
    filesDroppedUnsub = Events.On('files-dropped', async (event) => {
      const payload = event.data || {};
      const paths = payload.files || [];
      for (const path of paths) {
        if (path.toLowerCase().endsWith('.conf')) {
          await importFromPath(path);
        } else {
          showToast('Only .conf files are supported');
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
    // restart. Local caches may be stale; re-fetch everything.
    helperResetUnsub = Events.On('helper_reset', async () => {
      await initialLoad(TunnelService);
      await refreshStatus(TunnelService);
    });
  });

  onDestroy(() => {
    unsubscribe();
    stopLogListener();
    if (filesDroppedUnsub) filesDroppedUnsub();
    if (helperUnsub) helperUnsub();
    if (helperResetUnsub) helperResetUnsub();
    if (toastTimer) clearTimeout(toastTimer);
  });

  function showToast(msg) {
    if (toastTimer) clearTimeout(toastTimer);
    toast = msg;
    toastTimer = setTimeout(() => { toast = ''; toastTimer = null; }, 3000);
  }

  // Generate a unique tunnel name by appending -1, -2, etc. if needed.
  async function uniqueName(baseName) {
    if (!(await TunnelService.TunnelExists(baseName))) return baseName;
    for (let i = 1; i < 1000; i++) {
      const candidate = `${baseName}-${i}`;
      if (!(await TunnelService.TunnelExists(candidate))) return candidate;
    }
    return baseName + '-' + Date.now();
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
    input.onchange = async (e) => {
      const file = e.target.files[0];
      await importFile(file);
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

  async function handleEdit(e) {
    editName = e.detail;
    try {
      editorContent = await TunnelService.GetConfigText(editName);
      editorErrors = [];
      editorIsNew = false;
      showEditor = true;
    } catch (err) {
      console.error(err);
    }
  }

  async function doSave(e) {
    const { name: saveName, content: saveContent } = e.detail;
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
        // If name changed, rename first then update content
        if (saveName !== editName) {
          await TunnelService.RenameTunnel(editName, saveName);
        }
        await TunnelService.UpdateConfig(saveName, saveContent);
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

  // Actually perform the connect RPC (after all warnings have been resolved).
  async function doConnectFinal(name, scriptsAllowed) {
    try {
      await TunnelService.Connect(name, scriptsAllowed);
      await refreshTunnels(TunnelService);
      await refreshStatus(TunnelService);
    } catch (e) {
      showToast("Connect failed: " + errText(e));
    }
  }

  // Check for routing conflicts before connecting. If conflicts exist, show
  // the ConflictWarning dialog; otherwise proceed directly.
  async function doConnect(name, scriptsAllowed) {
    try {
      const conflicts = await TunnelService.CheckConflicts(name);
      if (conflicts && conflicts.length > 0) {
        conflictList = conflicts;
        pendingConnectName = name;
        pendingScriptsAllowed = scriptsAllowed;
        showConflictWarning = true;
        return;
      }
    } catch (e) {
      // Non-fatal — if the conflict check itself fails, proceed anyway.
      console.warn('conflict check failed:', e);
    }
    await doConnectFinal(name, scriptsAllowed);
  }

  async function handleConflictProceed() {
    showConflictWarning = false;
    await doConnectFinal(pendingConnectName, pendingScriptsAllowed);
  }

  function handleConflictCancel() {
    showConflictWarning = false;
    conflictList = [];
  }

  async function handleConnect(e) {
    const { name, hasScripts } = e.detail;
    if (hasScripts) {
      try {
        const detail = await TunnelService.GetTunnelDetail(name);
        const scripts = [];
        const iface = detail?.Interface;
        if (iface?.PreUp) scripts.push({ Hook: 'PreUp', Command: iface.PreUp });
        if (iface?.PostUp) scripts.push({ Hook: 'PostUp', Command: iface.PostUp });
        if (iface?.PreDown) scripts.push({ Hook: 'PreDown', Command: iface.PreDown });
        if (iface?.PostDown) scripts.push({ Hook: 'PostDown', Command: iface.PostDown });
        scriptWarningScripts = scripts;
        pendingConnectName = name;
        showScriptWarning = true;
      } catch (err) {
        console.error(err);
      }
    } else {
      await doConnect(name, false);
    }
  }

  async function handleScriptAllow() {
    showScriptWarning = false;
    await doConnect(pendingConnectName, true);
  }

  async function handleScriptDeny() {
    showScriptWarning = false;
    await doConnect(pendingConnectName, false);
  }

  async function handleUpdate() {
    try {
      await TunnelService.RunUpdate(updateInfo);
    } catch (e) {
      showToast('Update failed: ' + (e?.message || e));
    }
  }
</script>

<!-- The `$: $locale` subscription in the script block lets every `$t(...)`
     call inside this template re-evaluate on language change. Modals are
     separate components mounted conditionally below; they pick up the new
     language on their next open (deliberate — otherwise changing language
     mid-interaction would destroy the modal). -->
<div class="app" class:modal-open={showSettings || showEditor || showScriptWarning || showConflictWarning} data-file-drop-target={!(showSettings || showEditor || showScriptWarning || showConflictWarning) && currentView === 'tunnels' ? true : undefined}>
  <!-- Wails adds .file-drop-target-active class to .app when dragging files.
       We only render the overlay when drop-target is actually active — i.e.
       on the tunnels view with no modal open — so it can never steal clicks
       from modals. The data-file-drop-target attribute above also removes
       the drop affordance entirely in those states so Wails doesn't even
       detect the drag. -->
  {#if currentView === 'tunnels' && !(showSettings || showEditor || showScriptWarning || showConflictWarning)}
    <div class="drop-overlay">
      <div class="drop-overlay-content">
        <div class="drop-icon">↓</div>
        <div class="drop-text">{$t('tunnel.drop_overlay')}</div>
      </div>
    </div>
  {/if}

  {#if toast}
    <div class="toast">{toast}</div>
  {/if}

  <div class="layout">
    <nav class="sidebar">
      <div class="app-title">WireGuide</div>
      <button class="nav-item" class:active={currentView === 'tunnels'} on:click={() => currentView = 'tunnels'}>
        <span class="nav-icon">◎</span> {$t('nav.tunnels')}
      </button>
      <button class="nav-item" class:active={currentView === 'tools'} on:click={() => currentView = 'tools'}>
        <span class="nav-icon">◈</span> {$t('nav.tools')}
      </button>
      <button class="nav-item" class:active={currentView === 'logs'} on:click={() => currentView = 'logs'}>
        <span class="nav-icon">≡</span> {$t('nav.logs')}
      </button>

      <div class="nav-spacer"></div>

      <div class="nav-footer">
        <button class="nav-item" on:click={() => showSettings = true}>
          <span class="nav-icon">⚙</span> {$t('nav.settings')}
        </button>
      </div>
    </nav>

    <!-- Main content -->
    <div class="main-content">
      <UpdateNotice {updateInfo} onInstall={handleUpdate} onDismiss={() => updateInfo = null} />

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
                <p>{$t('tunnel.no_selection')}</p>
                <div class="empty-actions">
                  <button class="btn-primary" on:click={handleNewTunnelOpen}>+ {$t('tunnel.new_tunnel')}</button>
                  <button class="btn-secondary" on:click={handleImportOpen}>↓ {$t('tunnel.import')}</button>
                </div>
              </div>
            {/if}
          </div>
        </div>
      {:else if currentView === 'tools'}
        <div class="tools-view">
          <div class="tools-tabs">
            <button class:active={toolsTab === 'diagnostics'} on:click={() => toolsTab = 'diagnostics'}>{$t('tools.tab_diagnostics')}</button>
            <button class:active={toolsTab === 'dnsleak'} on:click={() => toolsTab = 'dnsleak'}>{$t('tools.tab_dns_leak')}</button>
            <button class:active={toolsTab === 'routes'} on:click={() => toolsTab = 'routes'}>{$t('tools.tab_routes')}</button>
          </div>
          <div class="tools-content">
            {#if toolsTab === 'diagnostics'}
              <Diagnostics />
            {:else if toolsTab === 'dnsleak'}
              <DNSLeakTest />
            {:else if toolsTab === 'routes'}
              <RouteVisualization />
            {/if}
          </div>
        </div>
      {:else if currentView === 'logs'}
        <div class="logs-view">
          <LogViewer />
        </div>
      {/if}
    </div>
  </div>

  <!-- Modals -->
  {#if showEditor}
    <div class="modal-backdrop" on:click={() => showEditor = false}>
      <div class="modal modal-editor" on:click|stopPropagation>
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
    <Settings {TunnelService} onClose={() => showSettings = false} />
  {/if}

  {#if showScriptWarning}
    <ScriptWarning
      scripts={scriptWarningScripts}
      tunnelName={pendingConnectName}
      on:allow={handleScriptAllow}
      on:deny={handleScriptDeny} />
  {/if}

  {#if showConflictWarning}
    <ConflictWarning
      conflicts={conflictList}
      on:proceed={handleConflictProceed}
      on:cancel={handleConflictCancel} />
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
    font-size: 40px;
    color: var(--accent);
    margin-bottom: var(--space-2);
    line-height: 1;
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

  /* ---------- Sidebar (macOS source-list style) ---------- */
  .sidebar {
    width: 200px;
    background: var(--bg-secondary);
    border-right: 0.5px solid var(--border);
    display: flex;
    flex-direction: column;
    padding-top: 52px; /* traffic-light clearance */
  }
  .app-title {
    padding: var(--space-2) var(--space-4) var(--space-4);
    font: 500 10px/13px var(--font-sans);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .nav-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    height: var(--row-std);
    padding: 0 var(--space-2) 0 var(--space-4);
    margin: 0 var(--space-2);
    background: transparent;
    border: 0;
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    font: var(--text-body);
    cursor: pointer;
    text-align: left;
  }
  @media (prefers-reduced-motion: no-preference) {
    .nav-item {
      transition: background-color var(--dur-fast) var(--ease-out),
                  color var(--dur-fast) var(--ease-out);
    }
  }
  .nav-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .nav-item.active {
    background: var(--bg-selected);
    color: var(--text-primary);
    font-weight: 500;
  }
  .nav-icon {
    font-size: 13px;
    width: 18px;
    text-align: center;
    opacity: 0.9;
  }
  .nav-spacer {
    flex: 1;
  }

  /* Sidebar footer — hairline divider defines a dedicated Settings region.
   * The button inside fills the ENTIRE footer area (no horizontal margin,
   * flush edges, taller height) so anywhere the user clicks below the
   * separator line registers as a Settings tap. Drawing a separator and
   * then making only a narrow pill clickable would be a broken affordance. */
  .nav-footer {
    border-top: 0.5px solid var(--border);
    display: flex;
    flex-direction: column;
  }
  .nav-footer .nav-item {
    /* Override the default .nav-item pill treatment — in the footer the
     * button IS the full-width bar, not a floating rounded item. */
    margin: 0;
    width: 100%;
    height: 44px;
    padding: 0 var(--space-4);
    border-radius: 0;
  }
  .nav-footer .nav-item:hover {
    background: var(--bg-hover);
  }
  .nav-footer .nav-item:active {
    background: var(--bg-active);
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
    gap: var(--space-4);
    font: var(--text-body);
  }
  .empty-actions {
    display: flex;
    gap: var(--space-2);
  }
  .btn-primary {
    height: 28px;
    padding: 0 var(--space-4);
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
    height: 28px;
    padding: 0 var(--space-4);
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

  /* ---------- Tools view (tab bar + content) ---------- */
  .tools-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding-top: 52px;
  }
  .tools-tabs {
    display: flex;
    gap: var(--space-1);
    padding: 0 var(--space-4);
    border-bottom: 0.5px solid var(--border);
  }
  .tools-tabs button {
    height: 32px;
    padding: 0 var(--space-3);
    background: transparent;
    border: 0;
    border-bottom: 2px solid transparent;
    color: var(--text-secondary);
    cursor: pointer;
    font: var(--text-body);
  }
  @media (prefers-reduced-motion: no-preference) {
    .tools-tabs button {
      transition: color var(--dur-fast) var(--ease-out),
                  border-color var(--dur-fast) var(--ease-out);
    }
  }
  .tools-tabs button:hover { color: var(--text-primary); }
  .tools-tabs button.active {
    color: var(--text-primary);
    border-bottom-color: var(--accent);
    font-weight: 500;
  }
  .tools-content {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-4);
  }

  .logs-view {
    flex: 1;
    padding-top: 52px;
    display: flex;
    flex-direction: column;
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
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    width: 440px;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: var(--shadow-lg);
  }
  .modal-editor {
    width: 640px;
    height: 520px;
    padding: 0;
    overflow: hidden;
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

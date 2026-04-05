<script>
  import { onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import TunnelList from './lib/TunnelList.svelte';
  import TunnelDetail from './lib/TunnelDetail.svelte';
  import ScriptWarning from './lib/ScriptWarning.svelte';
  import ConfigEditor from './lib/ConfigEditor.svelte';
  import Settings from './lib/Settings.svelte';
  import LogViewer from './lib/LogViewer.svelte';
  import Diagnostics from './lib/Diagnostics.svelte';
  import DNSLeakTest from './lib/DNSLeakTest.svelte';
  import RouteVisualization from './lib/RouteVisualization.svelte';
  import StatsDashboard from './lib/StatsDashboard.svelte';
  import NewTunnelDialog from './lib/NewTunnelDialog.svelte';
  import { tunnels, selectedTunnel, refreshTunnels, subscribeToEvents, unsubscribe, initialLoad, connectionStatus } from './stores/tunnels.js';
  import { TunnelService } from '../bindings/github.com/korjwl1/wireguide/internal/app';

  // View state
  let currentView = 'tunnels'; // 'tunnels' | 'tools' | 'settings' | 'logs'
  let toolsTab = 'diagnostics'; // 'diagnostics' | 'dnsleak' | 'routes'

  // Modal state
  let showNewTunnel = false;
  let showEditor = false;
  let showSettings = false;
  let showScriptWarning = false;
  let scriptWarningScripts = [];
  let pendingConnectName = '';
  let editName = '';
  let editorContent = '';
  let editorErrors = [];
  let toast = '';
  let filesDroppedUnsub = null;

  onMount(async () => {
    // Load and apply saved theme before loading other data
    try {
      const s = await TunnelService.GetSettings();
      const theme = s?.Theme || 'system';
      document.documentElement.setAttribute('data-theme', theme);
    } catch (e) {
      document.documentElement.setAttribute('data-theme', 'system');
    }

    await initialLoad(TunnelService);
    subscribeToEvents();

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
  });

  onDestroy(() => {
    unsubscribe();
    if (filesDroppedUnsub) filesDroppedUnsub();
  });

  function showToast(msg) {
    toast = msg;
    setTimeout(() => { toast = ''; }, 3000);
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
      showToast('Import failed: ' + e.toString());
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
      showToast('Import failed: ' + e.toString());
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

  async function handleNewTunnelOpen() {
    showNewTunnel = true;
  }

  async function handleNewTunnelSave(e) {
    const { name, content } = e.detail;
    try {
      const errors = await TunnelService.ValidateConfig(content);
      if (errors && errors.length > 0) {
        return { errors };
      }
      await TunnelService.ImportConfig(name, content);
      showNewTunnel = false;
      await refreshTunnels(TunnelService);
    } catch (err) {
      console.error(err);
    }
  }

  async function handleEdit(e) {
    editName = e.detail;
    try {
      editorContent = await TunnelService.GetConfigText(editName);
      editorErrors = [];
      showEditor = true;
    } catch (err) {
      console.error(err);
    }
  }

  async function doSave() {
    editorErrors = [];
    try {
      const errors = await TunnelService.ValidateConfig(editorContent);
      if (errors && errors.length > 0) {
        editorErrors = errors;
        return;
      }
      await TunnelService.UpdateConfig(editName, editorContent);
      showEditor = false;
      await refreshTunnels(TunnelService);
    } catch (err) {
      editorErrors = [err.toString()];
    }
  }

  async function handleRefresh() {
    await refreshTunnels(TunnelService);
  }

  async function handleExport(e) {
    const name = e.detail;
    try {
      const content = await TunnelService.ExportConfig(name);
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name + '.conf';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('export error:', err);
    }
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
      await TunnelService.Connect(name, false);
      await refreshTunnels(TunnelService);
    }
  }

  async function handleScriptAllow() {
    showScriptWarning = false;
    try {
      await TunnelService.Connect(pendingConnectName, true);
      await refreshTunnels(TunnelService);
    } catch (e) { console.error(e); }
  }

  async function handleScriptDeny() {
    showScriptWarning = false;
    try {
      await TunnelService.Connect(pendingConnectName, false);
      await refreshTunnels(TunnelService);
    } catch (e) { console.error(e); }
  }
</script>

<div class="app" data-file-drop-target>
  <!-- Wails adds .file-drop-target-active class to .app when dragging files -->
  <div class="drop-overlay">
    <div class="drop-overlay-content">
      <div class="drop-icon">↓</div>
      <div class="drop-text">Drop .conf file to import</div>
    </div>
  </div>

  {#if toast}
    <div class="toast">{toast}</div>
  {/if}

  <div class="layout">
    <!-- Sidebar navigation -->
    <nav class="sidebar">
      <div class="app-title">WireGuide</div>
      <button class="nav-item" class:active={currentView === 'tunnels'} on:click={() => currentView = 'tunnels'}>
        <span class="nav-icon">◎</span> Tunnels
      </button>
      <button class="nav-item" class:active={currentView === 'tools'} on:click={() => currentView = 'tools'}>
        <span class="nav-icon">⚙</span> Tools
      </button>
      <button class="nav-item" class:active={currentView === 'logs'} on:click={() => currentView = 'logs'}>
        <span class="nav-icon">≡</span> Logs
      </button>

      <div class="nav-spacer"></div>

      <button class="nav-item" on:click={() => showSettings = true}>
        <span class="nav-icon">⚙</span> Settings
      </button>
    </nav>

    <!-- Main content -->
    <div class="main-content">
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
              {#if $selectedTunnel?.is_connected && $connectionStatus?.state === 'connected'}
                <div class="stats-section">
                  <StatsDashboard />
                </div>
              {/if}
            {:else}
              <div class="empty-detail">
                <p>Select a tunnel or create a new one</p>
                <div class="empty-actions">
                  <button class="btn-primary" on:click={handleNewTunnelOpen}>+ New Tunnel</button>
                  <button class="btn-secondary" on:click={handleImportOpen}>Import .conf</button>
                </div>
              </div>
            {/if}
          </div>
        </div>
      {:else if currentView === 'tools'}
        <div class="tools-view">
          <div class="tools-tabs">
            <button class:active={toolsTab === 'diagnostics'} on:click={() => toolsTab = 'diagnostics'}>Diagnostics</button>
            <button class:active={toolsTab === 'dnsleak'} on:click={() => toolsTab = 'dnsleak'}>DNS Leak Test</button>
            <button class:active={toolsTab === 'routes'} on:click={() => toolsTab = 'routes'}>Routes</button>
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
  {#if showNewTunnel}
    <NewTunnelDialog {TunnelService}
      on:save={handleNewTunnelSave}
      on:close={() => showNewTunnel = false} />
  {/if}

  {#if showEditor}
    <div class="modal-backdrop" on:click={() => showEditor = false}>
      <div class="modal modal-editor" on:click|stopPropagation>
        <ConfigEditor
          bind:content={editorContent}
          errors={editorErrors}
          on:save={(e) => { editorContent = e.detail; doSave(); }}
          on:cancel={() => showEditor = false} />
      </div>
    </div>
  {/if}

  {#if showSettings}
    <Settings {TunnelService} on:close={() => showSettings = false} />
  {/if}

  {#if showScriptWarning}
    <ScriptWarning
      scripts={scriptWarningScripts}
      tunnelName={pendingConnectName}
      on:allow={handleScriptAllow}
      on:deny={handleScriptDeny} />
  {/if}
</div>

<style>
  :global(body) {
    margin: 0;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    overflow: hidden;
  }
  .app {
    width: 100vw;
    height: 100vh;
    position: relative;
  }
  /* Drop overlay — hidden by default, shown when Wails adds .file-drop-target-active */
  .drop-overlay {
    position: fixed;
    inset: 0;
    background: rgba(15, 52, 96, 0.75);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: none;
    z-index: 1000;
    opacity: 0;
    transition: opacity 150ms ease;
  }
  :global(.file-drop-target-active) > .drop-overlay {
    opacity: 1;
  }
  .drop-overlay-content {
    padding: 48px 64px;
    background: var(--bg-primary);
    border: 3px dashed var(--green);
    border-radius: 16px;
    text-align: center;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
  }
  .drop-icon {
    font-size: 48px;
    color: var(--green);
    margin-bottom: 12px;
    line-height: 1;
  }
  .drop-text {
    font-size: 18px;
    color: var(--text-primary);
    font-weight: 500;
  }
  .layout {
    display: flex;
    height: 100%;
  }
  .sidebar {
    width: 180px;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding-top: 52px; /* macOS titlebar space */
  }
  .app-title {
    padding: 8px 16px 16px;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .nav-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 16px;
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    text-align: left;
    transition: background 150ms;
  }
  .nav-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .nav-item.active {
    background: var(--bg-active);
    color: var(--text-primary);
  }
  .nav-icon {
    font-size: 14px;
    width: 16px;
    text-align: center;
  }
  .nav-spacer {
    flex: 1;
  }
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
    border-right: 1px solid var(--border);
    overflow-y: auto;
  }
  .tunnel-detail-pane {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }
  .stats-section {
    padding: 0 24px 16px;
  }
  .empty-detail {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    flex: 1;
    color: var(--text-muted);
    gap: 16px;
  }
  .empty-actions {
    display: flex;
    gap: 8px;
  }
  .btn-primary {
    padding: 8px 16px;
    background: var(--green);
    border: none;
    border-radius: 6px;
    color: #fff;
    cursor: pointer;
    font-size: 13px;
  }
  .btn-secondary {
    padding: 8px 16px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 13px;
  }

  /* Tools view */
  .tools-view {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding-top: 52px;
  }
  .tools-tabs {
    display: flex;
    gap: 4px;
    padding: 0 16px;
    border-bottom: 1px solid var(--border);
  }
  .tools-tabs button {
    padding: 8px 16px;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 13px;
  }
  .tools-tabs button.active {
    color: var(--text-primary);
    border-bottom-color: var(--accent);
  }
  .tools-content {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
  }

  .logs-view {
    flex: 1;
    padding-top: 52px;
    display: flex;
    flex-direction: column;
  }

  .toast {
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    padding: 12px 20px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 13px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    z-index: 300;
  }

  /* Modal */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }
  .modal {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    width: 420px;
    max-height: 80vh;
    overflow-y: auto;
  }
  .modal-editor { width: 600px; height: 500px; padding: 0; overflow: hidden; }
  .modal h3 { margin: 0 0 16px; color: var(--text-primary); }
  .modal label {
    display: block;
    margin: 12px 0 4px;
    font-size: 12px;
    color: var(--text-secondary);
  }
  .modal input[type="text"] {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 14px;
    box-sizing: border-box;
  }
  .hint {
    font-size: 12px;
    color: var(--text-secondary);
    margin: 0 0 12px;
  }
  .btn-file-select {
    width: 100%;
    padding: 10px;
    background: var(--bg-card);
    border: 1px dashed var(--border);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 13px;
    cursor: pointer;
    margin-bottom: 8px;
  }
  .btn-file-select:hover {
    background: var(--bg-hover);
    border-color: var(--accent);
  }
  .preview {
    margin: 12px 0;
    padding: 12px;
    background: #0d0d1a;
    border-radius: 6px;
    font-size: 11px;
    font-family: monospace;
    color: #aaa;
    max-height: 200px;
    overflow-y: auto;
    white-space: pre-wrap;
  }
  .errors {
    margin: 8px 0;
    padding: 8px 12px;
    background: var(--error-bg);
    border: 1px solid var(--red);
    border-radius: 6px;
  }
  .errors p { margin: 4px 0; color: #ff7675; font-size: 13px; }
  .modal-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-top: 16px;
  }
  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
    color: var(--text-primary);
  }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-connect { background: var(--green); color: #fff; }
  .btn-connect:hover:not(:disabled) { background: #00a884; }
</style>

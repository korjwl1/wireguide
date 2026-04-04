<script>
  import { onMount, onDestroy } from 'svelte';
  import TunnelList from './lib/TunnelList.svelte';
  import TunnelDetail from './lib/TunnelDetail.svelte';
  import ScriptWarning from './lib/ScriptWarning.svelte';
  import ConfigEditor from './lib/ConfigEditor.svelte';
  import Settings from './lib/Settings.svelte';
  import { tunnels, selectedTunnel, refreshTunnels, startPolling, stopPolling } from './stores/tunnels.js';
  import { TunnelService } from '../bindings/github.com/korjwl1/wireguide/internal/app';

  let showImport = false;
  let showEditor = false;
  let showSettings = false;
  let showScriptWarning = false;
  let scriptWarningScripts = [];
  let pendingConnectName = '';
  let editName = '';
  let importName = '';
  let importContent = '';
  let importErrors = [];
  let editorContent = '';
  let editorErrors = [];
  let dragOver = false;

  onMount(async () => {
    await refreshTunnels(TunnelService);
    startPolling(TunnelService);
  });

  onDestroy(() => {
    stopPolling();
  });

  async function handleImportOpen() {
    showImport = true;
    importName = '';
    importContent = '';
    importErrors = [];
  }

  async function handleFileDrop(e) {
    e.preventDefault();
    dragOver = false;
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    importName = file.name.replace(/\.conf$/, '');
    importContent = await file.text();
    showImport = true;
    importErrors = [];
  }

  async function handleFileSelect() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.conf';
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      importName = file.name.replace(/\.conf$/, '');
      importContent = await file.text();
      importErrors = [];
    };
    input.click();
  }

  async function handleClipboard() {
    try {
      importContent = await navigator.clipboard.readText();
      importName = 'clipboard-import';
      importErrors = [];
    } catch (e) {
      importErrors = ['Cannot read clipboard'];
    }
  }

  async function doImport() {
    if (!importName || !importContent) return;
    importErrors = [];
    try {
      const errors = await TunnelService.ValidateConfig(importContent);
      if (errors && errors.length > 0) {
        importErrors = errors;
        return;
      }
      await TunnelService.ImportConfig(importName, importContent);
      showImport = false;
      await refreshTunnels(TunnelService);
    } catch (e) {
      importErrors = [e.toString()];
    }
  }

  async function handleEdit(e) {
    editName = e.detail;
    try {
      editorContent = await TunnelService.GetConfigText(editName);
      editorErrors = [];
      showEditor = true;
    } catch (e) {
      console.error(e);
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
    } catch (e) {
      editorErrors = [e.toString()];
    }
  }

  async function handleRefresh() {
    await refreshTunnels(TunnelService);
  }

  async function handleExport(e) {
    const name = e.detail;
    try {
      const content = await TunnelService.ExportConfig(name);
      // Create a downloadable blob
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name + '.conf';
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('export error:', e);
    }
  }

  async function handleConnect(e) {
    const { name, hasScripts } = e.detail;
    if (hasScripts) {
      // Load script details and show warning
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
    } catch (e) {
      console.error(e);
    }
  }

  async function handleScriptDeny() {
    showScriptWarning = false;
    try {
      await TunnelService.Connect(pendingConnectName, false);
      await refreshTunnels(TunnelService);
    } catch (e) {
      console.error(e);
    }
  }
</script>

<div class="app"
  on:dragover|preventDefault={() => dragOver = true}
  on:dragleave={() => dragOver = false}
  on:drop={handleFileDrop}
>
  {#if dragOver}
    <div class="drop-overlay">
      <p>Drop .conf file to import</p>
    </div>
  {/if}

  <div class="layout">
    <div class="sidebar">
      <TunnelList on:import={handleImportOpen} />
    </div>
    <div class="main">
      <TunnelDetail {TunnelService} on:edit={handleEdit} on:export={handleExport} on:connect={handleConnect} on:refresh={handleRefresh} />
    </div>
  </div>

  <!-- Import Dialog -->
  {#if showImport}
    <div class="modal-backdrop" on:click={() => showImport = false}>
      <div class="modal" on:click|stopPropagation>
        <h3>Import Tunnel</h3>
        <div class="import-actions">
          <button class="btn-sm" on:click={handleFileSelect}>Select File</button>
          <button class="btn-sm" on:click={handleClipboard}>From Clipboard</button>
        </div>
        <label>
          Tunnel Name
          <input type="text" bind:value={importName} placeholder="my-vpn" />
        </label>
        {#if importContent}
          <pre class="preview">{importContent.substring(0, 300)}{importContent.length > 300 ? '...' : ''}</pre>
        {/if}
        {#if importErrors.length > 0}
          <div class="errors">
            {#each importErrors as err}
              <p>{err}</p>
            {/each}
          </div>
        {/if}
        <div class="modal-footer">
          <button class="btn btn-connect" on:click={doImport} disabled={!importContent || !importName}>Import</button>
          <button class="btn btn-secondary" on:click={() => showImport = false}>Cancel</button>
        </div>
      </div>
    </div>
  {/if}

  <!-- Editor Dialog (CodeMirror 6) -->
  {#if showEditor}
    <div class="modal-backdrop" on:click={() => showEditor = false}>
      <div class="modal modal-editor" on:click|stopPropagation>
        <ConfigEditor
          bind:content={editorContent}
          errors={editorErrors}
          on:save={(e) => { editorContent = e.detail; doSave(); }}
          on:cancel={() => showEditor = false}
        />
      </div>
    </div>
  {/if}

  <!-- Settings -->
  {#if showSettings}
    <Settings {TunnelService} on:close={() => showSettings = false} />
  {/if}

  <!-- Script Warning Dialog -->
  {#if showScriptWarning}
    <ScriptWarning
      scripts={scriptWarningScripts}
      tunnelName={pendingConnectName}
      on:allow={handleScriptAllow}
      on:deny={handleScriptDeny}
    />
  {/if}
</div>

<style>
  :global(body) {
    margin: 0;
    background: #1a1a2e;
    color: #e0e0e0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    overflow: hidden;
  }
  .app {
    width: 100vw;
    height: 100vh;
    position: relative;
  }
  .layout {
    display: flex;
    height: 100%;
  }
  .sidebar {
    width: 240px;
    min-width: 200px;
    background: #12122a;
  }
  .main {
    flex: 1;
    display: flex;
  }
  .drop-overlay {
    position: absolute;
    inset: 0;
    background: rgba(15, 52, 96, 0.85);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    border: 3px dashed #00b894;
    border-radius: 8px;
    margin: 8px;
  }
  .drop-overlay p {
    font-size: 18px;
    color: #00b894;
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
    background: #1a1a2e;
    border: 1px solid #2a2a4a;
    border-radius: 12px;
    padding: 24px;
    width: 420px;
    max-height: 80vh;
    overflow-y: auto;
  }
  .modal-wide { width: 560px; }
  .modal-editor { width: 600px; height: 500px; padding: 0; overflow: hidden; }
  .modal h3 {
    margin: 0 0 16px;
    color: #e0e0e0;
  }
  .modal label {
    display: block;
    margin: 12px 0 4px;
    font-size: 12px;
    color: #8888aa;
  }
  .modal input[type="text"] {
    width: 100%;
    padding: 8px 12px;
    background: #16213e;
    border: 1px solid #2a2a4a;
    border-radius: 6px;
    color: #e0e0e0;
    font-size: 14px;
    box-sizing: border-box;
  }
  .import-actions {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
  }
  .btn-sm {
    padding: 6px 12px;
    background: #2a2a4a;
    border: none;
    border-radius: 6px;
    color: #e0e0e0;
    font-size: 12px;
    cursor: pointer;
  }
  .btn-sm:hover { background: #3a3a5a; }
  .preview {
    margin: 12px 0;
    padding: 12px;
    background: #0d0d1a;
    border-radius: 6px;
    font-size: 11px;
    font-family: monospace;
    color: #aaa;
    overflow-x: auto;
    white-space: pre-wrap;
    max-height: 200px;
    overflow-y: auto;
  }
  .errors {
    margin: 8px 0;
    padding: 8px 12px;
    background: #d6303122;
    border: 1px solid #d63031;
    border-radius: 6px;
  }
  .errors p {
    margin: 4px 0;
    color: #ff7675;
    font-size: 13px;
  }
  .modal-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-top: 16px;
  }
  .editor {
    width: 100%;
    padding: 12px;
    background: #0d0d1a;
    border: 1px solid #2a2a4a;
    border-radius: 6px;
    color: #e0e0e0;
    font-family: monospace;
    font-size: 13px;
    resize: vertical;
    box-sizing: border-box;
    outline: none;
  }
  .editor:focus { border-color: #0f3460; }

  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
    color: #e0e0e0;
  }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-connect { background: #00b894; color: #fff; }
  .btn-connect:hover:not(:disabled) { background: #00a884; }
  .btn-secondary { background: #2a2a4a; }
  .btn-secondary:hover { background: #3a3a5a; }
</style>

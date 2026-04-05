<script>
  import { selectedTunnel, connectionStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';
  import { createEventDispatcher } from 'svelte';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  let detail = null;
  let loading = false;
  let error = '';

  $: if ($selectedTunnel) loadDetail($selectedTunnel.name);

  async function loadDetail(name) {
    try {
      detail = await TunnelService.GetTunnelDetail(name);
    } catch (e) {
      detail = null;
    }
  }

  function connect() {
    dispatch('connect', {
      name: $selectedTunnel.name,
      hasScripts: $selectedTunnel.has_scripts
    });
  }

  async function disconnect() {
    error = '';
    loading = true;
    try {
      await TunnelService.Disconnect();
    } catch (e) {
      error = e.toString();
    }
    loading = false;
  }

  async function deleteTunnel() {
    if ($selectedTunnel.is_connected) {
      error = t('confirm.disconnect_first');
      return;
    }
    if (confirm(t('confirm.delete_message', { name: $selectedTunnel.name }))) {
      try {
        await TunnelService.DeleteTunnel($selectedTunnel.name);
        selectedTunnel.set(null);
        dispatch('refresh');
      } catch (e) {
        error = e.toString();
      }
    }
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  $: isConnected = $selectedTunnel?.is_connected;
  $: status = $connectionStatus;

  let renaming = false;
  let renameValue = '';

  function startRename() {
    if (isConnected) {
      error = t('confirm.disconnect_first');
      return;
    }
    renameValue = $selectedTunnel.name;
    renaming = true;
  }

  async function commitRename() {
    const oldName = $selectedTunnel.name;
    const newName = renameValue.trim();
    renaming = false;
    if (!newName || newName === oldName) return;
    try {
      await TunnelService.RenameTunnel(oldName, newName);
      selectedTunnel.set({ ...$selectedTunnel, name: newName });
      dispatch('refresh');
    } catch (e) {
      error = e.toString();
    }
  }

  function cancelRename() {
    renaming = false;
  }
</script>

<div class="detail-panel">
  {#if !$selectedTunnel}
    <div class="no-selection">
      <p>{t('tunnel.no_tunnels')}</p>
    </div>
  {:else}
    <div class="detail-header" class:connected={isConnected}>
      {#if renaming}
        <input
          class="rename-input"
          type="text"
          bind:value={renameValue}
          on:blur={commitRename}
          on:keydown={(e) => {
            if (e.key === 'Enter') commitRename();
            if (e.key === 'Escape') cancelRename();
          }}
          autofocus
        />
      {:else}
        <h2 on:dblclick={startRename} title="Double-click to rename">{$selectedTunnel.name}</h2>
        <button class="btn-rename" on:click={startRename} title="Rename">✎</button>
      {/if}
      <span class="state-badge" class:on={isConnected} class:connecting={status.state === 'connecting'}>
        {#if isConnected}
          {t('app.connected')}
        {:else if status.state === 'connecting'}
          {t('app.connecting')}
        {:else}
          {t('app.disconnected')}
        {/if}
      </span>
    </div>

    {#if isConnected && status.state === 'connected'}
      <div class="stats-grid">
        <div class="stat">
          <span class="stat-label">{t('tunnel.rx')}</span>
          <span class="stat-value down">{formatBytes(status.rx_bytes || 0)}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{t('tunnel.tx')}</span>
          <span class="stat-value up">{formatBytes(status.tx_bytes || 0)}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{t('tunnel.handshake')}</span>
          <span class="stat-value">{status.handshake_age || '-'}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{t('tunnel.duration')}</span>
          <span class="stat-value">{status.duration || '-'}</span>
        </div>
      </div>
    {/if}

    <div class="detail-info">
      {#if $selectedTunnel.endpoint}
        <div class="info-row">
          <span class="label">{t('tunnel.endpoint')}</span>
          <span class="value">{$selectedTunnel.endpoint}</span>
        </div>
      {/if}
      {#if detail}
        {#each detail.Peers || [] as peer}
          <div class="info-row">
            <span class="label">{t('tunnel.allowed_ips')}</span>
            <span class="value">{(peer.AllowedIPs || []).join(', ')}</span>
          </div>
          <div class="info-row">
            <span class="label">{t('tunnel.public_key')}</span>
            <span class="value mono">{peer.PublicKey?.substring(0, 20)}...</span>
          </div>
        {/each}
        {#if detail.Interface?.DNS?.length}
          <div class="info-row">
            <span class="label">DNS</span>
            <span class="value">{detail.Interface.DNS.join(', ')}</span>
          </div>
        {/if}
      {/if}
    </div>

    {#if error}
      <div class="error-msg">{error}</div>
    {/if}

    <div class="actions">
      {#if isConnected}
        <button class="btn btn-disconnect" on:click={disconnect} disabled={loading}>
          {t('tunnel.disconnect')}
        </button>
      {:else}
        <button class="btn btn-connect" on:click={connect} disabled={loading}>
          {loading ? t('app.connecting') : t('tunnel.connect')}
        </button>
      {/if}
      <button class="btn btn-secondary" on:click={() => dispatch('edit', $selectedTunnel.name)}>
        {t('tunnel.edit')}
      </button>
      <button class="btn btn-secondary" on:click={() => dispatch('export', $selectedTunnel.name)}>
        {t('tunnel.export')}
      </button>
      <button class="btn btn-danger" on:click={deleteTunnel}>
        {t('tunnel.delete')}
      </button>
    </div>
  {/if}
</div>

<style>
  .detail-panel {
    flex: 1;
    padding: 16px 24px;
    padding-top: 52px;
    overflow-y: auto;
  }
  .no-selection {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-muted);
  }
  .detail-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .detail-header h2 {
    margin: 0;
    font-size: 20px;
    color: var(--text-primary);
    cursor: pointer;
  }
  .btn-rename {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 14px;
    opacity: 0.6;
  }
  .btn-rename:hover {
    background: var(--bg-hover);
    opacity: 1;
  }
  .rename-input {
    font-size: 20px;
    padding: 4px 8px;
    background: var(--bg-input);
    border: 1px solid var(--accent);
    border-radius: 4px;
    color: var(--text-primary);
    outline: none;
    flex: 1;
    max-width: 300px;
  }
  .state-badge {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 12px;
    background: var(--bg-card);
    color: var(--text-muted);
    transition: background 300ms ease, color 300ms ease;
  }
  .state-badge.on {
    background: rgba(0, 184, 148, 0.15);
    color: var(--green);
  }
  .state-badge.connecting {
    background: rgba(253, 203, 110, 0.15);
    color: var(--yellow);
    animation: pulse 1.5s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  .stats-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 20px;
  }
  .stat {
    background: var(--bg-card);
    border-radius: 8px;
    padding: 12px;
  }
  .stat-label {
    display: block;
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    margin-bottom: 4px;
  }
  .stat-value {
    font-size: 18px;
    font-weight: 600;
    color: var(--text-primary);
  }
  .stat-value.down { color: var(--green); }
  .stat-value.up { color: var(--blue); }
  .detail-info {
    margin-bottom: 20px;
  }
  .info-row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  .label { color: var(--text-secondary); }
  .value { color: var(--text-primary); text-align: right; }
  .value.mono { font-family: monospace; font-size: 12px; }
  .error-msg {
    padding: 8px 12px;
    margin-bottom: 12px;
    background: var(--error-bg);
    border: 1px solid var(--red);
    border-radius: 6px;
    color: var(--red);
    font-size: 13px;
  }
  .actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
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
  .btn-connect:hover:not(:disabled) { opacity: 0.9; }
  .btn-disconnect { background: var(--red); color: #fff; }
  .btn-disconnect:hover:not(:disabled) { opacity: 0.9; }
  .btn-secondary { background: var(--bg-card); border: 1px solid var(--border); }
  .btn-secondary:hover { background: var(--bg-hover); }
  .btn-danger { background: transparent; color: var(--red); border: 1px solid var(--red); }
  .btn-danger:hover { background: var(--error-bg); }
</style>

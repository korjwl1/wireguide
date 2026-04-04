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
</script>

<div class="detail-panel">
  {#if !$selectedTunnel}
    <div class="no-selection">
      <p>{t('tunnel.no_tunnels')}</p>
    </div>
  {:else}
    <div class="detail-header" class:connected={isConnected}>
      <h2>{$selectedTunnel.name}</h2>
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
    color: #555;
  }
  .detail-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
    padding-bottom: 16px;
    border-bottom: 1px solid #2a2a4a;
  }
  .detail-header h2 {
    margin: 0;
    font-size: 20px;
    color: #e0e0e0;
  }
  .state-badge {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 12px;
    background: #333;
    color: #888;
    transition: background 300ms ease, color 300ms ease;
  }
  .state-badge.on {
    background: #00b89422;
    color: #00b894;
  }
  .state-badge.connecting {
    background: #fdcb6e22;
    color: #fdcb6e;
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
    background: #16213e;
    border-radius: 8px;
    padding: 12px;
  }
  .stat-label {
    display: block;
    font-size: 11px;
    color: #8888aa;
    text-transform: uppercase;
    margin-bottom: 4px;
  }
  .stat-value {
    font-size: 18px;
    font-weight: 600;
    color: #e0e0e0;
  }
  .stat-value.down { color: #00b894; }
  .stat-value.up { color: #74b9ff; }
  .detail-info {
    margin-bottom: 20px;
  }
  .info-row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #1a1a3a;
    font-size: 13px;
  }
  .label { color: #8888aa; }
  .value { color: #e0e0e0; text-align: right; }
  .value.mono { font-family: monospace; font-size: 12px; }
  .error-msg {
    padding: 8px 12px;
    margin-bottom: 12px;
    background: #d6303122;
    border: 1px solid #d63031;
    border-radius: 6px;
    color: #ff7675;
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
    color: #e0e0e0;
  }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-connect { background: #00b894; color: #fff; }
  .btn-connect:hover:not(:disabled) { background: #00a884; }
  .btn-disconnect { background: #d63031; color: #fff; }
  .btn-disconnect:hover:not(:disabled) { background: #c0392b; }
  .btn-secondary { background: #2a2a4a; }
  .btn-secondary:hover { background: #3a3a5a; }
  .btn-danger { background: transparent; color: #d63031; border: 1px solid #d63031; }
  .btn-danger:hover { background: #d6303122; }
</style>

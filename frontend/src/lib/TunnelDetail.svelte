<script>
  import { selectedTunnel, connectionStatus, refreshTunnels, refreshStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';
  import { createEventDispatcher, tick, onDestroy } from 'svelte';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  let detail = null;
  let loading = false;
  let error = '';

  $: if ($selectedTunnel) loadDetail($selectedTunnel.name);

  // Single source of truth for "is this tunnel currently active?" —
  // combine the selected-tunnel flag with the live connection status so the
  // UI can't show a stale "connected" chip briefly after disconnect.
  $: isConnected = $selectedTunnel?.is_connected
    && $connectionStatus?.state === 'connected'
    && $connectionStatus?.tunnel_name === $selectedTunnel?.name;
  $: status = $connectionStatus;

  async function loadDetail(name) {
    try {
      detail = await TunnelService.GetTunnelDetail(name);
    } catch (e) {
      detail = null;
    }
  }

  function connect() {
    dispatch('connect', {
      name: $selectedTunnel.name
    });
  }

  async function disconnect() {
    error = '';
    loading = true;
    try {
      await TunnelService.Disconnect();
      // Don't wait for event stream — refresh immediately.
      await refreshTunnels(TunnelService);
      await refreshStatus(TunnelService);
    } catch (e) {
      error = errText(e);
    }
    loading = false;
  }

  let showDeleteConfirm = false;
  let deleteConfirmBtn = null;

  async function askDelete() {
    if (isConnected) {
      error = $t('confirm.disconnect_first');
      return;
    }
    showDeleteConfirm = true;
    // Auto-focus the confirm button so Enter confirms, Escape cancels,
    // and a stray Space press doesn't accidentally trigger the No button.
    await tick();
    deleteConfirmBtn?.focus();
  }

  async function confirmDelete() {
    showDeleteConfirm = false;
    try {
      await TunnelService.DeleteTunnel($selectedTunnel.name);
      selectedTunnel.set(null);
      dispatch('refresh');
    } catch (e) {
      error = errText(e);
    }
  }

  function cancelDelete() {
    showDeleteConfirm = false;
  }

  // Global ESC handler — closes whichever modal is open.
  function handleKeydown(e) {
    if (e.key !== 'Escape') return;
    if (showDeleteConfirm) cancelDelete();
    else if (renaming) cancelRename();
  }
  if (typeof window !== 'undefined') {
    window.addEventListener('keydown', handleKeydown);
    onDestroy(() => window.removeEventListener('keydown', handleKeydown));
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  let renaming = false;
  let renameValue = '';

  function startRename() {
    if (isConnected) {
      error = $t('confirm.disconnect_first');
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
      error = errText(e);
    }
  }

  function cancelRename() {
    renaming = false;
  }
</script>

<div class="detail-panel">
  {#if !$selectedTunnel}
    <div class="no-selection">
      <p>{$t('tunnel.no_tunnels')}</p>
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
        <h2 on:dblclick={startRename} title={$t('tunnel.rename_hint')}>{$selectedTunnel.name}</h2>
        <button class="btn-rename" on:click={startRename} title="Rename">✎</button>
      {/if}
      <span class="state-badge" class:on={isConnected} class:connecting={status.state === 'connecting'}>
        {#if isConnected}
          {$t('app.connected')}
        {:else if status.state === 'connecting'}
          {$t('app.connecting')}
        {:else}
          {$t('app.disconnected')}
        {/if}
      </span>
    </div>

    {#if isConnected && status.state === 'connected'}
      <div class="stats-grid">
        <div class="stat">
          <span class="stat-label">{$t('tunnel.rx')}</span>
          <span class="stat-value down">{formatBytes(status.rx_bytes || 0)}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.tx')}</span>
          <span class="stat-value up">{formatBytes(status.tx_bytes || 0)}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.handshake')}</span>
          <span class="stat-value">{status.last_handshake || '-'}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.duration')}</span>
          <span class="stat-value">{status.duration || '-'}</span>
        </div>
      </div>
    {/if}

    <div class="detail-info">
      {#if $selectedTunnel.endpoint}
        <div class="info-row">
          <span class="label">{$t('tunnel.endpoint')}</span>
          <span class="value">{$selectedTunnel.endpoint}</span>
        </div>
      {/if}
      {#if detail}
        {#each detail.Peers || [] as peer}
          <div class="info-row">
            <span class="label">{$t('tunnel.allowed_ips')}</span>
            <span class="value">{(peer.AllowedIPs || []).join(', ')}</span>
          </div>
          <div class="info-row">
            <span class="label">{$t('tunnel.public_key')}</span>
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
          {$t('tunnel.disconnect')}
        </button>
      {:else}
        <button class="btn btn-connect" on:click={connect} disabled={loading}>
          {loading ? $t('app.connecting') : $t('tunnel.connect')}
        </button>
      {/if}
      <button class="btn btn-secondary" on:click={() => dispatch('edit', $selectedTunnel.name)}>
        {$t('tunnel.edit')}
      </button>
      <button class="btn btn-secondary" on:click={() => dispatch('export', $selectedTunnel.name)}>
        {$t('tunnel.export')}
      </button>
      <button class="btn btn-danger" on:click={askDelete}>
        {$t('tunnel.delete')}
      </button>
    </div>
  {/if}
</div>

{#if showDeleteConfirm}
  <div class="confirm-backdrop" on:click={cancelDelete}>
    <div class="confirm-dialog" on:click|stopPropagation>
      <h3>{$t('confirm.delete_title')}</h3>
      <p>{$t('confirm.delete_message', { name: $selectedTunnel.name })}</p>
      <div class="confirm-footer">
        <button class="btn btn-disconnect" bind:this={deleteConfirmBtn} on:click={confirmDelete}>{$t('confirm.yes')}</button>
        <button class="btn btn-secondary" on:click={cancelDelete}>{$t('confirm.no')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  /* ---------- Layout ---------- */
  .detail-panel {
    flex: 1;
    padding: var(--space-6) var(--space-6);
    padding-top: 52px; /* clears the macOS traffic-light inset */
    overflow-y: auto;
  }
  .no-selection {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-muted);
    font: var(--text-body);
  }

  /* ---------- Header: title + rename + state badge ---------- */
  .detail-header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-5);
    padding-bottom: var(--space-4);
    border-bottom: 0.5px solid var(--border);
  }
  .detail-header h2 {
    margin: 0;
    font: var(--text-title-1);
    color: var(--text-primary);
    cursor: text;
  }
  .btn-rename {
    background: transparent;
    border: 0;
    color: var(--text-secondary);
    cursor: pointer;
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-xs);
    font: var(--text-body);
    opacity: 0.65;
  }
  .btn-rename:hover {
    background: var(--bg-hover);
    opacity: 1;
  }
  .rename-input {
    font: var(--text-title-1);
    padding: 2px var(--space-2);
    background: var(--bg-input);
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    outline: none;
    flex: 1;
    max-width: 320px;
    box-shadow: 0 0 0 3px var(--blue-tint);
  }

  /* ---------- State badge (connected / connecting / disconnected) ---------- */
  .state-badge {
    padding: 2px var(--space-2);
    border-radius: var(--radius-xs);
    font: var(--text-footnote);
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    background: var(--bg-card);
    color: var(--text-muted);
  }
  @media (prefers-reduced-motion: no-preference) {
    .state-badge {
      transition: background-color var(--dur-base) var(--ease-out),
                  color var(--dur-base) var(--ease-out);
    }
  }
  .state-badge.on {
    background: var(--green-tint);
    color: var(--green);
  }
  .state-badge.connecting {
    background: var(--yellow-tint);
    color: var(--yellow);
  }
  @media (prefers-reduced-motion: no-preference) {
    .state-badge.connecting {
      animation: pulse 1.6s ease-in-out infinite;
    }
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%      { opacity: 0.55; }
  }

  /* ---------- Stats grid ---------- */
  .stats-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-2);
    margin-bottom: var(--space-5);
  }
  .stat {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-md);
    padding: var(--space-3);
  }
  .stat-label {
    display: block;
    font: var(--text-footnote);
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: var(--space-1);
  }
  .stat-value {
    font: 600 17px/22px var(--font-sans);
    font-feature-settings: "tnum";   /* tabular numerals for stable alignment */
    color: var(--text-primary);
  }
  .stat-value.down { color: var(--stats-rx); }
  .stat-value.up   { color: var(--stats-tx); }

  /* ---------- Info rows ---------- */
  .detail-info {
    margin-bottom: var(--space-5);
  }
  .info-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: var(--space-4);
    padding: var(--space-2) 0;
    border-bottom: 0.5px solid var(--border);
    font: var(--text-body);
  }
  .info-row:last-child { border-bottom: 0; }
  .label { color: var(--text-secondary); flex-shrink: 0; }
  .value {
    color: var(--text-primary);
    text-align: right;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .value.mono {
    font-family: var(--font-mono);
    font-size: 11px;
  }

  /* ---------- Error message ---------- */
  .error-msg {
    padding: var(--space-2) var(--space-3);
    margin-bottom: var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-body);
  }

  /* ---------- Actions (button row) ---------- */
  .actions {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
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
  @media (prefers-reduced-motion: no-preference) {
    .btn {
      transition: background-color var(--dur-fast) var(--ease-out),
                  filter var(--dur-fast) var(--ease-out),
                  border-color var(--dur-fast) var(--ease-out);
    }
  }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-connect {
    background: var(--accent);
    color: var(--text-inverse);
  }
  .btn-connect:hover:not(:disabled) { filter: brightness(1.08); }
  .btn-connect:active:not(:disabled) { filter: brightness(0.94); }
  .btn-disconnect {
    background: var(--red);
    color: var(--text-inverse);
  }
  .btn-disconnect:hover:not(:disabled) { filter: brightness(1.08); }
  .btn-disconnect:active:not(:disabled) { filter: brightness(0.94); }
  .btn-secondary {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
  }
  .btn-secondary:hover { background: var(--bg-hover); }
  .btn-secondary:active { background: var(--bg-active); }
  .btn-danger {
    background: transparent;
    color: var(--red);
    border: 0.5px solid var(--red);
  }
  .btn-danger:hover { background: var(--error-bg); }

  /* ---------- Delete confirmation dialog ---------- */
  .confirm-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 400;
  }
  .confirm-dialog {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    width: 380px;
    box-shadow: var(--shadow-md);
  }
  .confirm-dialog h3 {
    margin: 0 0 var(--space-2);
    color: var(--text-primary);
    font: var(--text-title-3);
  }
  .confirm-dialog p {
    margin: 0 0 var(--space-4);
    color: var(--text-secondary);
    font: var(--text-body);
  }
  .confirm-footer {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
  }
</style>

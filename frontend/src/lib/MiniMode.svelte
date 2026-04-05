<script>
  import { connectionStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';
  import { createEventDispatcher } from 'svelte';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  $: status = $connectionStatus;
  $: isConnected = status?.state === 'connected';

  async function toggle() {
    if (isConnected) {
      await TunnelService.Disconnect();
    } else {
      dispatch('connect');
    }
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  }

  function expand() {
    dispatch('expand');
  }
</script>

<div class="mini" class:connected={isConnected}>
  <div class="mini-header" style="-webkit-app-region: drag">
    <span class="mini-dot" class:on={isConnected}></span>
    <span class="mini-name">{status?.tunnel_name || 'WireGuide'}</span>
    <button class="mini-expand" on:click={expand} style="-webkit-app-region: no-drag">↗</button>
  </div>

  {#if isConnected}
    <div class="mini-stats">
      <span>↓ {formatBytes(status.rx_bytes)}</span>
      <span>↑ {formatBytes(status.tx_bytes)}</span>
    </div>
  {/if}

  <button class="mini-toggle" class:on={isConnected} on:click={toggle}>
    {isConnected ? $t('tunnel.disconnect') : $t('tunnel.connect')}
  </button>
</div>

<style>
  .mini {
    width: 200px;
    padding: 12px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .mini-header {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .mini-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
    transition: background 300ms;
  }
  .mini-dot.on {
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
  }
  .mini-name {
    flex: 1;
    font-size: 13px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .mini-expand {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 14px;
    padding: 0;
  }
  .mini-stats {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    color: var(--text-secondary);
  }
  .mini-toggle {
    width: 100%;
    padding: 6px;
    border: none;
    border-radius: 6px;
    font-size: 12px;
    cursor: pointer;
    background: var(--accent);
    color: var(--text-primary);
    transition: background 200ms;
  }
  .mini-toggle.on {
    background: var(--red);
    color: var(--text-inverse);
  }
</style>

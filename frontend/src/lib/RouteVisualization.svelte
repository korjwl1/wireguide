<script>
  import { t } from '../i18n/index.js';
  import { TunnelService } from '../../bindings/github.com/korjwl1/wireguide/internal/app';
  import { onMount } from 'svelte';

  let routes = [];
  let loading = false;
  let error = '';

  async function loadRoutes() {
    loading = true;
    error = '';
    try {
      routes = (await TunnelService.GetRoutingTable()) || [];
    } catch (e) {
      error = e?.message || String(e);
    }
    loading = false;
  }

  function isVPN(iface) {
    return iface.startsWith('WireGuide-') || iface.startsWith('utun') || iface.startsWith('wg') || iface.startsWith('tun');
  }

  onMount(loadRoutes);
</script>

<div class="route-viz">
  <div class="page-toolbar">
    <h2 class="page-title">{$t('tools.route_title')}</h2>
    <div class="toolbar-actions">
      <span class="legend-inline">
        <span class="legend-item"><span class="dot vpn-dot"></span>{$t('tools.route_legend_vpn')}</span>
        <span class="legend-item"><span class="dot direct-dot"></span>{$t('tools.route_legend_direct')}</span>
      </span>
      <button class="btn-action" on:click={loadRoutes} disabled={loading}>
        {loading ? '…' : $t('tools.route_reload')}
      </button>
    </div>
  </div>

  <div class="page-body">
    <p class="page-description">{$t('tools.route_desc')}</p>

    {#if error}
      <div class="error-msg">{error}</div>
    {/if}

    {#if routes.length > 0}
      <div class="route-table">
        <div class="route-header">
          <span>{$t('tools.route_header_dest')}</span>
          <span>{$t('tools.route_header_gateway')}</span>
          <span>{$t('tools.route_header_iface')}</span>
        </div>
        {#each routes as route}
          <div class="route-row" class:vpn={isVPN(route.interface)}>
            <span class="dest">{route.destination}</span>
            <span class="gw">{route.gateway || '-'}</span>
            <span class="iface" class:vpn-iface={isVPN(route.interface)}>
              {route.interface}
              {#if isVPN(route.interface)}
                <span class="vpn-badge">{$t('tools.route_vpn_badge')}</span>
              {/if}
            </span>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>

<style>
  .route-viz {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }

  /* Toolbar — matches History/LogViewer pattern. */
  .page-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-2) var(--space-4);
    border-bottom: 0.5px solid var(--border);
    gap: var(--space-2);
    flex-shrink: 0;
  }
  .page-title {
    margin: 0;
    font: var(--text-headline);
    color: var(--text-primary);
  }
  .toolbar-actions {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
  .legend-inline {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    font: var(--text-footnote);
    color: var(--text-secondary);
  }
  .legend-item { display: inline-flex; align-items: center; gap: 5px; }
  .dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .vpn-dot { background: var(--green); }
  .direct-dot { background: var(--text-muted); }

  .btn-action {
    height: 22px;
    padding: 0 var(--space-2);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-xs);
    color: var(--text-secondary);
    font: var(--text-footnote);
    cursor: pointer;
  }
  .btn-action:hover:not(:disabled) { background: var(--bg-hover); }
  .btn-action:disabled { opacity: 0.5; cursor: progress; }

  .page-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: var(--space-4) var(--space-4) var(--space-5);
    display: flex;
    flex-direction: column;
  }
  .page-description {
    margin: 0 0 var(--space-3);
    font: var(--text-body);
    color: var(--text-secondary);
    line-height: 1.5;
    max-width: 640px;
  }

  .route-table {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-md);
    overflow-y: auto;
    flex: 1;
    min-height: 0;
  }
  .route-header {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    padding: var(--space-2) var(--space-3);
    font: var(--text-footnote);
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-bottom: 0.5px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--bg-card);
    z-index: 1;
  }
  .route-row {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    padding: var(--space-1) var(--space-3);
    font: var(--text-body);
    font-family: var(--font-mono);
    border-bottom: 0.5px solid var(--border);
  }
  .route-row:last-child { border-bottom: 0; }
  .route-row.vpn { background: color-mix(in srgb, var(--green) 6%, transparent); }
  .dest { color: var(--text-primary); }
  .gw { color: var(--text-secondary); }
  .iface { color: var(--text-secondary); display: flex; align-items: center; gap: var(--space-1); }
  .vpn-iface { color: var(--green); }
  .vpn-badge {
    padding: 1px var(--space-1);
    background: var(--green);
    color: var(--text-inverse);
    border-radius: var(--radius-xs);
    font: var(--text-footnote);
    font-weight: 600;
  }
  .error-msg {
    margin-bottom: var(--space-3);
    padding: var(--space-2) var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid color-mix(in srgb, var(--red) 35%, transparent);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-body);
  }
</style>

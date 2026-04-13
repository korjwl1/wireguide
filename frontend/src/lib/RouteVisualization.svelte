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
    return iface.startsWith('utun') || iface.startsWith('wg') || iface.startsWith('tun');
  }

  onMount(loadRoutes);
</script>

<div class="route-viz">
  <div class="page-header">
    <h3>{$t('tools.route_title')}</h3>
    <p class="description">{$t('tools.route_desc')}</p>
  </div>
  <button class="btn-load" on:click={loadRoutes} disabled={loading}>
    {loading ? '…' : $t('tools.route_reload')}
  </button>

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

    <div class="legend">
      <span class="legend-item"><span class="dot vpn-dot"></span> {$t('tools.route_legend_vpn')}</span>
      <span class="legend-item"><span class="dot direct-dot"></span> {$t('tools.route_legend_direct')}</span>
    </div>
  {/if}
</div>

<style>
  .route-viz {
    padding: var(--space-6);
    padding-top: var(--space-5);
    display: flex;
    flex-direction: column;
    height: 100%;
    box-sizing: border-box;
  }
  .page-header {
    margin-bottom: var(--space-5);
    padding-bottom: var(--space-4);
    border-bottom: 0.5px solid var(--border);
  }
  h3 {
    margin: 0 0 var(--space-1);
    font: var(--text-title-2);
    color: var(--text-primary);
  }
  .description {
    margin: 0;
    font: var(--text-body);
    color: var(--text-secondary);
    line-height: 1.5;
  }
  .btn-load {
    height: 28px;
    padding: 0 var(--space-3);
    background: var(--accent);
    border: none;
    border-radius: var(--radius-sm);
    color: var(--text-inverse);
    cursor: pointer;
    font: var(--text-headline);
  }
  .route-table {
    margin-top: var(--space-3);
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
    padding: var(--space-1) var(--space-3);
    font: var(--text-subheadline);
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
  .route-row.vpn { background: var(--green-tint); }
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
  .legend {
    display: flex;
    gap: var(--space-4);
    margin-top: var(--space-2);
    font: var(--text-callout);
    color: var(--text-secondary);
  }
  .legend-item { display: flex; align-items: center; gap: var(--space-1); }
  .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .vpn-dot { background: var(--green); }
  .direct-dot { background: var(--text-muted); }
  .error-msg {
    margin-top: var(--space-3);
    padding: var(--space-2) var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-body);
  }
</style>

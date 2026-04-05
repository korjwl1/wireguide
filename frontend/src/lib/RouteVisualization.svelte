<script>
  import { t } from '../i18n/index.js';

  let routes = [];
  let loading = false;

  async function loadRoutes() {
    loading = true;
    // Would call TunnelService.GetRoutingTable() via Wails binding
    routes = [
      { destination: 'default', gateway: '192.168.1.1', interface: 'en0', flags: 'UGSc' },
      { destination: '0.0.0.0/1', gateway: '', interface: 'utun4', flags: 'USc' },
      { destination: '128.0.0.0/1', gateway: '', interface: 'utun4', flags: 'USc' },
      { destination: '10.0.0.0/24', gateway: '', interface: 'utun4', flags: 'USc' },
      { destination: '192.168.1.0/24', gateway: 'link#6', interface: 'en0', flags: 'UCSc' },
    ];
    loading = false;
  }

  function isVPN(iface) {
    return iface.startsWith('utun') || iface.startsWith('wg') || iface.startsWith('tun');
  }
</script>

<div class="route-viz">
  <h4>{$t('tools.route_title')}</h4>
  <button class="btn-load" on:click={loadRoutes} disabled={loading}>
    {loading ? '…' : $t('tools.route_reload')}
  </button>

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
  .route-viz { padding: 8px 0; }
  h4 {
    font-size: 12px; color: var(--text-secondary);
    text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;
  }
  .btn-load {
    padding: 8px 16px; background: var(--accent); border: none;
    border-radius: 6px; color: var(--text-primary); cursor: pointer; font-size: 13px;
  }
  .route-table {
    margin-top: 12px; background: var(--bg-card); border-radius: 8px; overflow: hidden;
  }
  .route-header {
    display: grid; grid-template-columns: 1fr 1fr 1fr;
    padding: 6px 12px; font-size: 11px; color: var(--text-secondary);
    text-transform: uppercase; border-bottom: 1px solid var(--border);
  }
  .route-row {
    display: grid; grid-template-columns: 1fr 1fr 1fr;
    padding: 6px 12px; font-size: 13px; font-family: monospace;
    border-bottom: 1px solid var(--border);
  }
  .route-row.vpn { background: var(--green-tint); }
  .dest { color: var(--text-primary); }
  .gw { color: var(--text-secondary); }
  .iface { color: var(--text-secondary); display: flex; align-items: center; gap: 4px; }
  .vpn-iface { color: var(--green); }
  .vpn-badge {
    font-size: 9px; padding: 1px 4px; background: var(--green);
    color: var(--text-inverse); border-radius: 3px; font-family: sans-serif;
  }
  .legend {
    display: flex; gap: 16px; margin-top: 8px; font-size: 12px; color: var(--text-secondary);
  }
  .legend-item { display: flex; align-items: center; gap: 4px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; }
  .vpn-dot { background: var(--green); }
  .direct-dot { background: var(--text-muted); }
</style>

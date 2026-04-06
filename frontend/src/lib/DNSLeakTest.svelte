<script>
  import { t } from '../i18n/index.js';

  let result = null;
  let loading = false;

  async function runTest() {
    loading = true;
    // Would call TunnelService.RunDNSLeakTest() via Wails binding
    result = {
      leaked: false,
      dns_servers: [
        { ip: '1.1.1.1', hostname: 'one.one.one.one', is_vpn: true },
      ],
      test_domain: 'wireguide-test-123456.example.com'
    };
    loading = false;
  }
</script>

<div class="dns-test">
  <h3>{$t('tools.dns_leak_title')}</h3>
  <p class="description">{$t('tools.dns_leak_desc')}</p>
  <button class="btn-test" on:click={runTest} disabled={loading}>
    {loading ? $t('tools.dns_leak_checking') : $t('tools.dns_leak_run')}
  </button>

  {#if result}
    <div class="result" class:leaked={result.leaked} class:safe={!result.leaked}>
      <div class="status-icon">{result.leaked ? '⚠' : '✓'}</div>
      <div class="status-text">
        {result.leaked ? $t('tools.dns_leak_leaked') : $t('tools.dns_leak_safe')}
      </div>
    </div>

    <div class="server-list">
      <h5>{$t('tools.dns_servers_detected')}</h5>
      {#each result.dns_servers as server}
        <div class="server" class:vpn={server.is_vpn} class:leak={!server.is_vpn}>
          <span class="server-ip">{server.ip}</span>
          <span class="server-host">{server.hostname || ''}</span>
          <span class="server-badge">{server.is_vpn ? 'VPN' : '!'}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .dns-test { padding: 16px; }
  h3 { margin-bottom: 4px; }
  h4 {
    font-size: 12px; color: var(--text-secondary);
    text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px;
  }
  .description {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 12px;
    line-height: 1.5;
  }
  .btn-test {
    padding: 8px 16px; background: var(--accent); border: none;
    border-radius: 6px; color: #fff; cursor: pointer; font-size: 13px;
  }
  .result {
    display: flex; align-items: center; gap: 8px; padding: 12px;
    border-radius: 8px; margin: 12px 0;
  }
  .result.safe { background: var(--green-tint); border: 1px solid var(--green); }
  .result.leaked { background: var(--error-bg); border: 1px solid var(--red); }
  .status-icon { font-size: 20px; }
  .safe .status-text { color: var(--green); }
  .leaked .status-text { color: var(--red); }
  .server-list { margin-top: 8px; }
  h5 { font-size: 11px; color: var(--text-secondary); margin-bottom: 4px; }
  .server {
    display: flex; gap: 8px; align-items: center; padding: 4px 8px;
    background: var(--bg-card); border-radius: 4px; margin-bottom: 2px; font-size: 13px;
  }
  .server-ip { font-family: monospace; }
  .server-host { color: var(--text-secondary); flex: 1; }
  .server-badge {
    padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600;
  }
  .vpn .server-badge { background: var(--green); color: var(--text-inverse); }
  .leak .server-badge { background: var(--red); color: var(--text-inverse); }
</style>

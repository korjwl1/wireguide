<script>
  import { t } from '../i18n/index.js';
  import { TunnelService } from '../../bindings/github.com/korjwl1/wireguide/internal/app';

  let result = null;
  let loading = false;
  let error = '';

  async function runTest() {
    loading = true;
    error = '';
    result = null;
    try {
      result = await TunnelService.RunDNSLeakTest();
    } catch (e) {
      error = e?.message || String(e);
    }
    loading = false;
  }
</script>

<div class="dns-test">
  <div class="page-header">
    <h3>{$t('tools.dns_leak_title')}</h3>
    <p class="description">{$t('tools.dns_leak_desc')}</p>
  </div>
  <button class="btn-test" on:click={runTest} disabled={loading}>
    {loading ? $t('tools.dns_leak_checking') : $t('tools.dns_leak_run')}
  </button>

  {#if error}
    <div class="error-msg">{error}</div>
  {/if}

  {#if result}
    <div class="result" class:leaked={result.leaked} class:safe={!result.leaked}>
      <div class="status-icon">{result.leaked ? '⚠' : '✓'}</div>
      <div class="status-text">
        {result.leaked ? $t('tools.dns_leak_leaked') : $t('tools.dns_leak_safe')}
      </div>
    </div>

    <div class="server-list">
      <h5>{$t('tools.dns_servers_detected')}</h5>
      {#each result.dns_servers || [] as server}
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
  .dns-test {
    padding: var(--space-6);
    padding-top: var(--space-5);
    max-width: 600px;
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
  .btn-test {
    height: 28px;
    padding: 0 var(--space-3);
    background: var(--accent);
    border: none;
    border-radius: var(--radius-sm);
    color: var(--text-inverse);
    cursor: pointer;
    font: var(--text-headline);
  }
  .result {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    margin: var(--space-3) 0;
  }
  .result.safe { background: var(--green-tint); border: 0.5px solid var(--green); }
  .result.leaked { background: var(--error-bg); border: 0.5px solid var(--red); }
  .status-icon { font-size: 18px; line-height: 1; }
  .safe .status-text { color: var(--green); font: var(--text-headline); }
  .leaked .status-text { color: var(--red); font: var(--text-headline); }
  .server-list {
    margin-top: var(--space-2);
    max-height: 300px;
    overflow-y: auto;
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm);
    padding: var(--space-1);
  }
  h5 {
    font: var(--text-subheadline);
    color: var(--text-secondary);
    margin-bottom: var(--space-1);
  }
  .server {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    padding: var(--space-1) var(--space-2);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-xs);
    margin-bottom: 2px;
    font: var(--text-body);
  }
  .server-ip { font-family: var(--font-mono); }
  .server-host { color: var(--text-secondary); flex: 1; }
  .server-badge {
    padding: 1px var(--space-2);
    border-radius: var(--radius-xs);
    font: var(--text-footnote);
    font-weight: 600;
  }
  .vpn .server-badge { background: var(--green); color: var(--text-inverse); }
  .leak .server-badge { background: var(--red); color: var(--text-inverse); }
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

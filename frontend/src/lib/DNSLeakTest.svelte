<script>
  import { t } from '../i18n/index.js';
  import { TunnelService } from '../../bindings/github.com/korjwl1/wireguide/internal/app';

  let result = null;
  let loading = false;
  let error = '';

  // Split-mode check failed: no leak verdict, but the tunnel resolver is
  // missing for some match domains (or the check could not run).
  $: splitFailed = !!result && !result.leaked && !!result.split_mode &&
    (!!result.error || (result.missing_match_domains || []).length > 0);

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
  <div class="page-toolbar">
    <h2 class="page-title">{$t('tools.dns_leak_title')}</h2>
  </div>

  <div class="page-body">
    <p class="page-description">{$t('tools.dns_leak_desc')}</p>

    <button class="btn-run" on:click={runTest} disabled={loading}>
      {loading ? $t('tools.dns_leak_checking') : $t('tools.dns_leak_run')}
    </button>

    {#if error}
      <div class="error-msg">{error}</div>
    {/if}

    {#if result}
      <div class="result" class:leaked={result.leaked} class:warn={splitFailed} class:safe={!result.leaked && !splitFailed}>
        <div class="status-icon">{result.leaked || splitFailed ? '⚠' : '✓'}</div>
        <div class="status-text">
          {result.leaked ? $t('tools.dns_leak_leaked') : splitFailed ? $t('tools.dns_leak_split_failed') : result.split_mode ? $t('tools.dns_leak_split') : $t('tools.dns_leak_safe')}
        </div>
      </div>

      {#if splitFailed}
        <div class="error-msg">
          {#if result.error}<div>{result.error}</div>{/if}
          {#if (result.missing_match_domains || []).length > 0}
            <ul class="missing">
              {#each result.missing_match_domains as d}<li>{d}</li>{/each}
            </ul>
          {/if}
        </div>
      {/if}

      <div class="server-section">
        <div class="section-label">{$t('tools.dns_servers_detected')}</div>
        <div class="server-list">
          {#each result.dns_servers || [] as server}
            <div class="server" class:vpn={server.is_vpn} class:leak={!server.is_vpn && !result.split_mode}>
              <span class="server-ip">{server.ip}</span>
              <span class="server-host">{server.hostname || ''}</span>
              <span class="server-badge">{server.is_vpn ? 'VPN' : result.split_mode ? '' : '!'}</span>
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .dns-test {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }

  /* Toolbar — matches History/LogViewer pattern: 0.5px bottom rule,
   * text-headline title, small action buttons on the right. */
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
  .page-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: var(--space-4) var(--space-4) var(--space-5);
    max-width: 640px;
  }
  .page-description {
    margin: 0 0 var(--space-3);
    font: var(--text-body);
    color: var(--text-secondary);
    line-height: 1.5;
  }
  .btn-run {
    height: 28px;
    padding: 0 var(--space-4);
    background: var(--accent);
    border: 0;
    border-radius: var(--radius-sm);
    color: var(--text-inverse);
    cursor: pointer;
    font: var(--text-headline);
  }
  .btn-run:hover:not(:disabled) { filter: brightness(1.08); }
  .btn-run:active:not(:disabled) { filter: brightness(0.94); }
  .btn-run:disabled { opacity: 0.6; cursor: progress; }
  @media (prefers-reduced-motion: no-preference) {
    .btn-run { transition: filter var(--dur-fast, 140ms) var(--ease-out, ease); }
  }

  .result {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    margin: var(--space-3) 0;
  }
  .result.safe { background: var(--green-tint); border: 0.5px solid color-mix(in srgb, var(--green) 35%, transparent); }
  .result.leaked { background: var(--error-bg); border: 0.5px solid color-mix(in srgb, var(--red) 35%, transparent); }
  .result.warn { background: var(--error-bg); border: 0.5px solid color-mix(in srgb, var(--orange, var(--red)) 35%, transparent); }
  .warn .status-text { color: var(--orange, var(--red)); font: var(--text-headline); }
  .missing { margin: var(--space-1) 0 0; padding-left: var(--space-4); font-family: var(--font-mono); }
  .status-icon { font-size: 18px; line-height: 1; }
  .safe .status-text { color: var(--green); font: var(--text-headline); }
  .leaked .status-text { color: var(--red); font: var(--text-headline); }

  .server-section {
    margin-top: var(--space-4);
  }
  .section-label {
    font: var(--text-footnote);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-secondary);
    margin: 0 var(--space-1) var(--space-2);
  }
  /* No outer border on the list — each .server card already has its own
   * border, so an outer wrapper would create a visible double rule. */
  .server-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    max-height: 300px;
    overflow-y: auto;
  }
  .server {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    padding: var(--space-2) var(--space-3);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm);
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
    border: 0.5px solid color-mix(in srgb, var(--red) 35%, transparent);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-body);
  }
</style>

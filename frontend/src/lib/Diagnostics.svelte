<script>
  import { t } from '../i18n/index.js';

  let cidrInput = '';
  let cidrResult = null;
  let pingEndpoint = '';
  let pingResult = null;
  let speedResult = null;
  let loading = { cidr: false, ping: false, speed: false };

  // These would call Go backend via Wails bindings in production
  function calcCIDR() {
    loading.cidr = true;
    // Placeholder — would call TunnelService.CalculateCIDR(cidrInput)
    try {
      const parts = cidrInput.split('/');
      const prefix = parseInt(parts[1] || '32');
      const hosts = prefix >= 31 ? (prefix === 32 ? 1 : 2) : Math.pow(2, 32 - prefix) - 2;
      cidrResult = {
        cidr: cidrInput,
        network: parts[0],
        prefix_len: prefix,
        total_hosts: hosts,
      };
    } catch (e) {
      cidrResult = { error: 'Invalid CIDR' };
    }
    loading.cidr = false;
  }

  function runPing() {
    loading.ping = true;
    pingResult = { host: pingEndpoint, reachable: false, latency_ms: 0, error: 'Run from backend (requires Go)' };
    loading.ping = false;
  }

  function runSpeed() {
    loading.speed = true;
    speedResult = { download_mbps: 0, error: 'Run from backend (requires Go HTTP client)' };
    loading.speed = false;
  }
</script>

<div class="diag">
  <h3>{$t('tools.net_diag_title')}</h3>

  <!-- CIDR Calculator -->
  <section>
    <h4>{$t('tools.cidr_calc_title')}</h4>
    <div class="input-row">
      <input type="text" bind:value={cidrInput} placeholder={$t('tools.cidr_placeholder')}
        on:keydown={(e) => e.key === 'Enter' && calcCIDR()} />
      <button on:click={calcCIDR}>{$t('tools.calculate')}</button>
    </div>
    {#if cidrResult}
      {#if cidrResult.error}
        <p class="error">{cidrResult.error}</p>
      {:else}
        <div class="result-grid">
          <span class="label">{$t('tools.network')}</span><span>{cidrResult.network}</span>
          <span class="label">{$t('tools.prefix')}</span><span>/{cidrResult.prefix_len}</span>
          <span class="label">{$t('tools.hosts')}</span><span>{cidrResult.total_hosts?.toLocaleString()}</span>
        </div>
      {/if}
    {/if}
  </section>

  <!-- Ping Test -->
  <section>
    <h4>{$t('tools.endpoint_reach_title')}</h4>
    <div class="input-row">
      <input type="text" bind:value={pingEndpoint} placeholder={$t('tools.endpoint_placeholder')}
        on:keydown={(e) => e.key === 'Enter' && runPing()} />
      <button on:click={runPing} disabled={loading.ping}>{loading.ping ? $t('tools.pinging') : $t('tools.ping')}</button>
    </div>
    {#if pingResult}
      <div class="result-grid">
        <span class="label">{$t('tools.host')}</span><span>{pingResult.host}</span>
        <span class="label">{$t('tools.reachable')}</span>
        <span class:green={pingResult.reachable} class:red={!pingResult.reachable}>
          {pingResult.reachable ? '✓' : '✗'}
        </span>
        {#if pingResult.latency_ms}
          <span class="label">{$t('tools.latency')}</span><span>{pingResult.latency_ms.toFixed(1)} ms</span>
        {/if}
      </div>
    {/if}
  </section>

  <!-- Speed Test -->
  <section>
    <h4>{$t('tools.speed_test_title')}</h4>
    <button class="btn-speed" on:click={runSpeed} disabled={loading.speed}>
      {loading.speed ? '…' : $t('tools.run_speed_test')}
    </button>
    {#if speedResult}
      <div class="result-grid">
        <span class="label">{$t('tools.download_speed')}</span>
        <span>{speedResult.download_mbps ? speedResult.download_mbps.toFixed(1) + ' Mbps' : '-'}</span>
        {#if speedResult.error}
          <span class="label">{$t('tools.note')}</span><span class="muted">{speedResult.error}</span>
        {/if}
      </div>
    {/if}
  </section>
</div>

<style>
  .diag { padding: 16px; }
  h3 { margin-bottom: 16px; }
  section { margin-bottom: 20px; }
  h4 {
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }
  .input-row {
    display: flex;
    gap: 4px;
  }
  .input-row input {
    flex: 1;
    padding: 6px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-primary);
    font-family: monospace;
    font-size: 13px;
  }
  .input-row button, .btn-speed {
    padding: 6px 12px;
    background: var(--accent);
    border: none;
    border-radius: 4px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 13px;
  }
  .btn-speed:disabled { opacity: 0.5; }
  .result-grid {
    display: grid;
    grid-template-columns: 80px 1fr;
    gap: 4px 8px;
    margin-top: 8px;
    font-size: 13px;
    padding: 8px;
    background: var(--bg-card);
    border-radius: 6px;
  }
  .label { color: var(--text-secondary); }
  .green { color: var(--green); }
  .red { color: var(--red); }
  .muted { color: var(--text-muted); font-size: 12px; }
  .error { color: var(--red); font-size: 13px; margin-top: 4px; }
</style>

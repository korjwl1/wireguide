<script>
  import { t } from '../i18n/index.js';

  let pingEndpoint = '';
  let pingResult = null;
  let loading = false;

  function runPing() {
    loading = true;
    pingResult = { host: pingEndpoint, reachable: false, latency_ms: 0, error: 'Run from backend (requires Go)' };
    loading = false;
  }
</script>

<div class="diag">
  <h3>{$t('tools.net_diag_title')}</h3>
  <p class="description">{$t('tools.net_diag_desc')}</p>

  <section>
    <h4>{$t('tools.endpoint_reach_title')}</h4>
    <p class="hint">{$t('tools.ping_desc')}</p>
    <div class="input-row">
      <input type="text" bind:value={pingEndpoint} placeholder={$t('tools.endpoint_placeholder')}
        on:keydown={(e) => e.key === 'Enter' && runPing()} />
      <button on:click={runPing} disabled={loading}>{loading ? $t('tools.pinging') : $t('tools.ping')}</button>
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
</div>

<style>
  .diag { padding: 16px; }
  h3 { margin-bottom: 4px; }
  .description {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 16px;
    line-height: 1.5;
  }
  section { margin-bottom: 20px; }
  h4 {
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 4px;
  }
  .hint {
    font-size: 12px;
    color: var(--text-muted);
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
  .input-row button {
    padding: 6px 12px;
    background: var(--accent);
    border: none;
    border-radius: 4px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 13px;
  }
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
</style>

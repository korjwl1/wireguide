<script>
  import { onMount, onDestroy } from 'svelte';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';

  export let TunnelService;
  export let tunnelName;
  let enabled = false;
  let targets = '';
  let interval = 30;
  let failures = 3;
  let loading = true;
  let saving = false;
  let error = '';
  let saved = false;
  let disposed = false;

  onMount(async () => {
    try {
      const config = await TunnelService.GetTunnelPingHealth(tunnelName);
      if (disposed) return;
      enabled = config.enabled;
      targets = (config.targets || []).join('\n');
      interval = config.interval_seconds;
      failures = config.failure_threshold;
    } catch (e) {
      if (!disposed) error = errText(e);
    } finally {
      if (!disposed) loading = false;
    }
  });
  onDestroy(() => { disposed = true; });

  async function save() {
    saving = true;
    error = '';
    saved = false;
    try {
      await TunnelService.SaveTunnelPingHealth(tunnelName, {
        enabled,
        targets: targets.split(/[\n,]+/).map(value => value.trim()).filter(Boolean),
        interval_seconds: Number(interval),
        failure_threshold: Number(failures),
      });
      if (!disposed) saved = true;
    } catch (e) {
      if (!disposed) error = errText(e);
    } finally {
      if (!disposed) saving = false;
    }
  }
</script>

<details class="ping-health">
  <summary>{$t('ping_health.title')}</summary>
  <form on:submit|preventDefault={save} on:input={() => { saved = false; }}>
    <fieldset disabled={loading || saving}>
      <label class="enable">
        <input type="checkbox" bind:checked={enabled} />
        <span>{$t('ping_health.enable')}</span>
      </label>
      <p class="hint">{$t('ping_health.description')}</p>
      <label for="ping-health-targets">{$t('ping_health.targets')}</label>
      <textarea id="ping-health-targets" bind:value={targets} rows="3" maxlength="240"
        spellcheck="false" placeholder="10.0.0.1&#10;10.0.0.2" aria-describedby="ping-target-hint"></textarea>
      <p id="ping-target-hint" class="hint">{$t('ping_health.targets_hint')}</p>
      <div class="timing">
        <label for="ping-health-interval">
          {$t('ping_health.interval')}
          <input id="ping-health-interval" type="number" min="10" max="300" step="1" required bind:value={interval} />
        </label>
        <label for="ping-health-failures">
          {$t('ping_health.failures')}
          <input id="ping-health-failures" type="number" min="1" max="10" step="1" required bind:value={failures} />
        </label>
      </div>
      <p class="hint">{$t('ping_health.cooldown')}</p>
      <div class="actions">
        <button type="submit">{$t(saving ? 'ping_health.saving' : 'ping_health.save')}</button>
        <span role="status">{loading ? $t('ping_health.loading') : saved ? $t('ping_health.saved') : ''}</span>
      </div>
    </fieldset>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  </form>
</details>

<style>
  .ping-health { margin-top: 20px; border-top: 1px solid var(--border); padding-top: 16px; }
  summary { cursor: pointer; font-size: 13px; font-weight: 600; color: var(--text-primary); padding: 4px 0; }
  form { margin-top: 12px; }
  fieldset { border: 0; padding: 0; margin: 0; min-width: 0; }
  label { display: block; font-size: 12px; font-weight: 500; color: var(--text-primary); }
  .enable { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--red); }
  textarea, input[type="number"] { display: block; width: 100%; box-sizing: border-box; padding: 8px 10px; margin-top: 6px; border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); background: var(--bg-card); font: inherit; }
  textarea { resize: vertical; min-height: 76px; font-family: var(--font-mono, monospace); }
  .hint { font-size: 12px; line-height: 1.5; color: var(--text-secondary); margin: 6px 0 12px; }
  .timing { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .actions { display: flex; align-items: center; gap: 12px; }
  button { padding: 8px 14px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-card); color: var(--text-primary); font: inherit; font-size: 12px; cursor: pointer; }
  button:hover:enabled { background: var(--bg-input); }
  :disabled { opacity: 0.6; cursor: default; }
  span[role="status"] { color: var(--text-secondary); font-size: 12px; }
  .error { color: var(--red); font-size: 12px; overflow-wrap: anywhere; }
  :is(summary, input, textarea, button):focus-visible { outline: 2px solid var(--red); outline-offset: 2px; }
  @media (max-width: 560px) { .timing { grid-template-columns: 1fr; gap: 10px; } }
</style>

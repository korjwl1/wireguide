<script>
  // Global Wi-Fi master settings (enable + trusted SSIDs).
  // Per-tunnel auto-connect SSIDs are edited inside each tunnel's
  // detail panel — the data lives at rules.per_tunnel[tunnelName] but
  // this component never touches it.
  import { createEventDispatcher } from 'svelte';
  import { t } from '../i18n/index.js';

  export let rules = {
    enabled: false,
    trusted_ssids: [],
    per_tunnel: {},
  };

  const dispatch = createEventDispatcher();
  let newTrusted = '';

  function emit() {
    dispatch('change', rules);
  }

  function addTrusted() {
    const v = newTrusted.trim();
    if (!v) return;
    if (!rules.trusted_ssids.includes(v)) {
      rules.trusted_ssids = [...rules.trusted_ssids, v];
      emit();
    }
    newTrusted = '';
  }

  function removeTrusted(ssid) {
    rules.trusted_ssids = rules.trusted_ssids.filter(s => s !== ssid);
    emit();
  }
</script>

<div class="wifi-rules">
  <div class="setting-row">
    <label>{$t('wifi_rules.title')}</label>
    <input type="checkbox" bind:checked={rules.enabled} on:change={emit} />
  </div>
  <p class="setting-hint">{$t('wifi_rules.hint')}</p>

  {#if rules.enabled}
    <h5>{$t('wifi_rules.trusted_ssids')}</h5>
    <p class="setting-hint">{$t('wifi_rules.trusted_hint')}</p>
    <div class="list">
      {#each rules.trusted_ssids as ssid}
        <div class="list-item">
          <span>{ssid}</span>
          <button class="remove" on:click={() => removeTrusted(ssid)}>✕</button>
        </div>
      {/each}
    </div>
    <div class="add-row">
      <input
        placeholder={$t('wifi_rules.ssid_placeholder')}
        bind:value={newTrusted}
        on:keydown={(e) => e.key === 'Enter' && addTrusted()} />
      <button on:click={addTrusted}>{$t('wifi_rules.add')}</button>
    </div>

    <p class="per_tunnel-pointer">{$t('wifi_rules.per_tunnel_location')}</p>
  {/if}
</div>

<style>
  .wifi-rules { padding: 8px 0; }
  .setting-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 0;
  }
  h5 {
    margin: 16px 0 4px;
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .setting-hint {
    font-size: 12px;
    color: var(--text-muted);
    margin: 0 0 8px;
  }
  .list-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 4px 8px;
    background: var(--bg-card);
    border-radius: 4px;
    margin-bottom: 2px;
    font-size: 13px;
  }
  .remove {
    background: none;
    border: none;
    color: var(--red);
    cursor: pointer;
    font-size: 14px;
  }
  .add-row {
    display: flex;
    gap: 4px;
    margin-top: 4px;
  }
  .add-row input {
    flex: 1;
    padding: 4px 8px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-primary);
    font-size: 13px;
  }
  .add-row button {
    padding: 4px 10px;
    background: var(--accent);
    border: none;
    border-radius: 4px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 12px;
  }
  .per_tunnel-pointer {
    margin: 16px 0 0;
    font-size: 12px;
    color: var(--text-muted);
    font-style: italic;
  }
  input[type="checkbox"] { accent-color: var(--green); }
</style>

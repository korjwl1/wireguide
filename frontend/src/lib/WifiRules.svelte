<script>
  import { createEventDispatcher } from 'svelte';
  import { t } from '../i18n/index.js';

  export let rules = {
    enabled: false,
    default_tunnel: '',
    auto_connect_untrusted: false,
    trusted_ssids: [],
    ssid_tunnel_map: {}
  };
  export let tunnelNames = [];

  const dispatch = createEventDispatcher();
  let newTrusted = '';
  let newSSID = '';
  let newSSIDTunnel = '';

  function addTrusted() {
    if (!newTrusted.trim()) return;
    if (!rules.trusted_ssids.includes(newTrusted.trim())) {
      rules.trusted_ssids = [...rules.trusted_ssids, newTrusted.trim()];
      dispatch('change', rules);
    }
    newTrusted = '';
  }

  function removeTrusted(ssid) {
    rules.trusted_ssids = rules.trusted_ssids.filter(s => s !== ssid);
    dispatch('change', rules);
  }

  function addMapping() {
    if (!newSSID.trim() || !newSSIDTunnel) return;
    rules.ssid_tunnel_map = { ...rules.ssid_tunnel_map, [newSSID.trim()]: newSSIDTunnel };
    dispatch('change', rules);
    newSSID = '';
    newSSIDTunnel = '';
  }

  function removeMapping(ssid) {
    const { [ssid]: _, ...rest } = rules.ssid_tunnel_map;
    rules.ssid_tunnel_map = rest;
    dispatch('change', rules);
  }
</script>

<div class="wifi-rules">
  <div class="setting-row">
    <label>WiFi Auto-connect</label>
    <input type="checkbox" bind:checked={rules.enabled} on:change={() => dispatch('change', rules)} />
  </div>

  {#if rules.enabled}
    <div class="setting-row">
      <label>Connect on untrusted WiFi</label>
      <input type="checkbox" bind:checked={rules.auto_connect_untrusted} on:change={() => dispatch('change', rules)} />
    </div>

    <div class="setting-row">
      <label>Default tunnel</label>
      <select bind:value={rules.default_tunnel} on:change={() => dispatch('change', rules)}>
        <option value="">None</option>
        {#each tunnelNames as name}
          <option value={name}>{name}</option>
        {/each}
      </select>
    </div>

    <h5>Trusted SSIDs (VPN off)</h5>
    <div class="list">
      {#each rules.trusted_ssids as ssid}
        <div class="list-item">
          <span>{ssid}</span>
          <button class="remove" on:click={() => removeTrusted(ssid)}>x</button>
        </div>
      {/each}
    </div>
    <div class="add-row">
      <input placeholder="SSID name" bind:value={newTrusted} on:keydown={(e) => e.key === 'Enter' && addTrusted()} />
      <button on:click={addTrusted}>Add</button>
    </div>

    <h5>SSID → Tunnel mapping</h5>
    <div class="list">
      {#each Object.entries(rules.ssid_tunnel_map) as [ssid, tunnel]}
        <div class="list-item">
          <span>{ssid} → {tunnel}</span>
          <button class="remove" on:click={() => removeMapping(ssid)}>x</button>
        </div>
      {/each}
    </div>
    <div class="add-row">
      <input placeholder="SSID" bind:value={newSSID} />
      <select bind:value={newSSIDTunnel}>
        <option value="">Tunnel</option>
        {#each tunnelNames as name}
          <option value={name}>{name}</option>
        {/each}
      </select>
      <button on:click={addMapping}>Add</button>
    </div>
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
    margin: 12px 0 4px;
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
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
  }
  .add-row {
    display: flex;
    gap: 4px;
    margin-top: 4px;
  }
  .add-row input, .add-row select {
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
  select { min-width: 80px; }
  input[type="checkbox"] { accent-color: var(--green); }
</style>

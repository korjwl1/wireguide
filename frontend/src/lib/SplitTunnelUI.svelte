<script>
  import { createEventDispatcher } from 'svelte';
  import { t } from '../i18n/index.js';

  export let allowedIPs = [];
  const dispatch = createEventDispatcher();

  let mode = 'all'; // 'all' or 'custom'
  let customIPs = [];
  let newIP = '';

  // Detect mode from existing AllowedIPs
  $: {
    const hasAll = allowedIPs.some(ip => ip === '0.0.0.0/0' || ip === '::/0');
    mode = hasAll ? 'all' : 'custom';
    if (mode === 'custom') {
      customIPs = [...allowedIPs];
    }
  }

  function setMode(m) {
    mode = m;
    if (m === 'all') {
      dispatch('change', ['0.0.0.0/0', '::/0']);
    } else {
      dispatch('change', customIPs.length ? customIPs : []);
    }
  }

  function addSubnet() {
    const ip = newIP.trim();
    if (!ip) return;
    // Basic CIDR validation
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(ip) &&
        !/^[0-9a-fA-F:]+\/\d{1,3}$/.test(ip)) {
      return;
    }
    if (!customIPs.includes(ip)) {
      customIPs = [...customIPs, ip];
      dispatch('change', customIPs);
    }
    newIP = '';
  }

  function removeSubnet(ip) {
    customIPs = customIPs.filter(i => i !== ip);
    dispatch('change', customIPs);
  }

  function handleKeydown(e) {
    if (e.key === 'Enter') addSubnet();
  }
</script>

<div class="split-tunnel">
  <div class="mode-selector">
    <button class:active={mode === 'all'} on:click={() => setMode('all')}>
      All Traffic (0.0.0.0/0)
    </button>
    <button class:active={mode === 'custom'} on:click={() => setMode('custom')}>
      Custom Subnets
    </button>
  </div>

  {#if mode === 'custom'}
    <div class="subnet-list">
      {#each customIPs as ip}
        <div class="subnet-item">
          <code>{ip}</code>
          <button class="remove-btn" on:click={() => removeSubnet(ip)}>x</button>
        </div>
      {/each}
      {#if customIPs.length === 0}
        <p class="empty">No subnets added</p>
      {/if}
    </div>
    <div class="add-subnet">
      <input type="text" bind:value={newIP} placeholder="10.0.0.0/24"
        on:keydown={handleKeydown} />
      <button on:click={addSubnet}>Add</button>
    </div>
  {/if}
</div>

<style>
  .split-tunnel { margin: 12px 0; }
  .mode-selector {
    display: flex;
    gap: 4px;
    margin-bottom: 8px;
  }
  .mode-selector button {
    flex: 1;
    padding: 8px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 13px;
  }
  .mode-selector button.active {
    background: var(--accent);
    color: var(--text-primary);
    border-color: var(--accent);
  }
  .subnet-list { margin-bottom: 8px; }
  .subnet-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 8px;
    background: var(--bg-card);
    border-radius: 4px;
    margin-bottom: 4px;
  }
  .subnet-item code { font-size: 13px; color: var(--text-primary); }
  .remove-btn {
    background: none;
    border: none;
    color: var(--red);
    cursor: pointer;
    font-size: 14px;
  }
  .empty { color: var(--text-muted); font-size: 13px; text-align: center; padding: 8px; }
  .add-subnet {
    display: flex;
    gap: 4px;
  }
  .add-subnet input {
    flex: 1;
    padding: 6px 8px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-primary);
    font-family: monospace;
    font-size: 13px;
  }
  .add-subnet button {
    padding: 6px 12px;
    background: var(--accent);
    border: none;
    border-radius: 4px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 13px;
  }
</style>

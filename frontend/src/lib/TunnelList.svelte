<script>
  import { createEventDispatcher } from 'svelte';
  import { tunnels, selectedTunnel } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';

  const dispatch = createEventDispatcher();
  let search = '';

  $: filtered = ($tunnels || []).filter(tun =>
    tun.name.toLowerCase().includes(search.toLowerCase())
  );

  function select(tun) {
    selectedTunnel.set(tun);
  }
</script>

<div class="tunnel-list">
  <div class="list-header">
    <h2>{t('tunnel.list_title')}</h2>
  </div>

  <div class="search-box">
    <input type="text" placeholder={t('tunnel.search')} bind:value={search} />
  </div>

  <div class="list-items">
    {#if filtered.length === 0 && search === ''}
      <div class="empty-state">
        <p>{t('tunnel.no_tunnels')}</p>
        <p class="hint">{t('tunnel.drop_hint')}</p>
      </div>
    {:else}
      {#each filtered as tun}
        <button
          class="tunnel-item"
          class:active={$selectedTunnel?.name === tun.name}
          class:connected={tun.is_connected}
          on:click={() => select(tun)}
        >
          <span class="status-dot" class:on={tun.is_connected}></span>
          <span class="tunnel-name">{tun.name}</span>
        </button>
      {/each}
    {/if}
  </div>

  <div class="list-footer">
    <button class="btn-new" on:click={() => dispatch('new')}>
      + New Tunnel
    </button>
    <button class="btn-import" on:click={() => dispatch('import')}>
      ↓ {t('tunnel.import')}
    </button>
  </div>
</div>

<style>
  .tunnel-list {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .list-header {
    padding: 16px;
  }
  .list-header h2 {
    margin: 0;
    font-size: 14px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .search-box {
    padding: 0 12px 8px;
  }
  .search-box input {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 13px;
    outline: none;
    box-sizing: border-box;
  }
  .search-box input:focus {
    border-color: var(--accent);
  }
  .list-items {
    flex: 1;
    overflow-y: auto;
    padding: 0 8px;
  }
  .tunnel-item {
    display: flex;
    align-items: center;
    width: 100%;
    padding: 10px 12px;
    margin-bottom: 2px;
    background: transparent;
    border: none;
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 14px;
    cursor: pointer;
    text-align: left;
    transition: background 150ms;
  }
  .tunnel-item:hover {
    background: var(--bg-hover);
  }
  .tunnel-item.active {
    background: var(--bg-active);
  }
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
    margin-right: 10px;
    flex-shrink: 0;
    transition: background 300ms ease, box-shadow 300ms ease;
  }
  .status-dot.on {
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
  }
  .tunnel-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .empty-state {
    padding: 24px 16px;
    text-align: center;
    color: var(--text-muted);
  }
  .empty-state .hint {
    font-size: 12px;
    margin-top: 8px;
    color: var(--text-muted);
  }
  .list-footer {
    padding: 12px;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .btn-new, .btn-import {
    width: 100%;
    padding: 8px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
  }
  .btn-new {
    background: var(--green);
    color: #fff;
  }
  .btn-new:hover { opacity: 0.9; }
  .btn-import {
    background: var(--accent);
    color: var(--text-primary);
  }
  .btn-import:hover {
    opacity: 0.9;
  }
</style>

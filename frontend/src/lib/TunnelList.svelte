<script>
  import { createEventDispatcher } from 'svelte';
  import { tunnels, selectedTunnel, connectionStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';

  const dispatch = createEventDispatcher();
  let search = '';

  $: filtered = ($tunnels || []).filter(tun =>
    tun.name.toLowerCase().includes(search.toLowerCase())
  );

  // Connected indicator comes from the live status event, not the stale
  // `is_connected` flag on the list item — that way the dot transitions in
  // real time when a tunnel comes up.
  $: activeName =
    $connectionStatus?.state === 'connected'
      ? $connectionStatus?.tunnel_name
      : null;

  function select(tun) {
    selectedTunnel.set(tun);
  }
</script>

<div class="tunnel-list">
  <div class="list-header">
    <h2>{$t('tunnel.list_title')}</h2>
  </div>

  <div class="search-box">
    <input type="text" placeholder={$t('tunnel.search')} bind:value={search} />
  </div>

  <div class="list-items">
    {#if filtered.length === 0 && search === ''}
      <div class="empty-state">
        <p>{$t('tunnel.no_tunnels')}</p>
        <p class="hint">{$t('tunnel.drop_hint')}</p>
      </div>
    {:else}
      {#each filtered as tun}
        <button
          class="tunnel-item"
          class:active={$selectedTunnel?.name === tun.name}
          class:connected={activeName === tun.name}
          on:click={() => select(tun)}
        >
          <span class="status-dot" class:on={activeName === tun.name}></span>
          <span class="tunnel-name">{tun.name}</span>
        </button>
      {/each}
    {/if}
  </div>

  <div class="list-footer">
    <button class="btn btn-primary" on:click={() => dispatch('new')}>
      + {$t('tunnel.new_tunnel')}
    </button>
    <button class="btn btn-secondary" on:click={() => dispatch('import')}>
      ↓ {$t('tunnel.import')}
    </button>
  </div>
</div>

<style>
  .tunnel-list {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: var(--bg-secondary);
  }

  /* --- Section header (uppercase caption style from HIG) --- */
  .list-header {
    padding: var(--space-4) var(--space-4) var(--space-2);
  }
  .list-header h2 {
    margin: 0;
    font: 500 10px/13px var(--font-sans);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  /* --- Search box (AppKit rounded text field) --- */
  .search-box {
    padding: 0 var(--space-3) var(--space-2);
  }
  .search-box input {
    width: 100%;
    height: 24px;
    padding: 0 var(--space-2);
    background: var(--bg-input);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font: var(--text-body);
    outline: none;
    box-sizing: border-box;
    transition: border-color var(--dur-fast) var(--ease-out),
                box-shadow var(--dur-fast) var(--ease-out);
  }
  .search-box input::placeholder {
    color: var(--text-muted);
  }
  .search-box input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--blue-tint);
  }

  /* --- List rows (28px AppKit standard) --- */
  .list-items {
    flex: 1;
    overflow-y: auto;
    padding: 0 var(--space-2) var(--space-2);
  }
  .tunnel-item {
    display: flex;
    align-items: center;
    width: 100%;
    height: var(--row-std);
    padding: 0 var(--space-2);
    margin-bottom: 1px;
    background: transparent;
    border: none;
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font: var(--text-body);
    cursor: pointer;
    text-align: left;
  }
  @media (prefers-reduced-motion: no-preference) {
    .tunnel-item {
      transition: background-color var(--dur-fast) var(--ease-out);
    }
    .status-dot {
      transition: background-color var(--dur-base) var(--ease-out),
                  box-shadow var(--dur-base) var(--ease-out);
    }
  }
  .tunnel-item:hover {
    background: var(--bg-hover);
  }
  .tunnel-item.active {
    background: var(--bg-selected);
  }
  .tunnel-item.active .tunnel-name {
    font-weight: 600;
  }

  /* --- Connection dot --- */
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
    margin-right: var(--space-2);
    flex-shrink: 0;
  }
  .status-dot.on {
    background: var(--green);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--green) 25%, transparent);
  }

  .tunnel-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font: var(--text-body);
  }

  /* --- Empty state --- */
  .empty-state {
    padding: var(--space-8) var(--space-4);
    text-align: center;
    color: var(--text-muted);
  }
  .empty-state p {
    font: var(--text-body);
  }
  .empty-state .hint {
    font: var(--text-footnote);
    margin-top: var(--space-2);
  }

  /* --- Footer buttons --- */
  .list-footer {
    padding: var(--space-3);
    border-top: 0.5px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .btn {
    width: 100%;
    height: 28px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: var(--radius-sm);
    font: var(--text-headline);
    cursor: pointer;
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn {
      transition: background-color var(--dur-fast) var(--ease-out),
                  filter var(--dur-fast) var(--ease-out);
    }
  }
  .btn-primary {
    background: var(--accent);
    color: var(--text-inverse);
  }
  .btn-primary:hover { filter: brightness(1.08); }
  .btn-primary:active { filter: brightness(0.94); }
  .btn-secondary {
    background: var(--bg-card);
    color: var(--text-primary);
    border: 0.5px solid var(--border);
  }
  .btn-secondary:hover { background: var(--bg-hover); }
  .btn-secondary:active { background: var(--bg-active); }
</style>

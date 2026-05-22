<script>
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  import { tunnels, selectedTunnel, connectionStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';

  const dispatch = createEventDispatcher();
  let search = '';

  $: filtered = ($tunnels || []).filter(tun =>
    tun.name.toLowerCase().includes(search.toLowerCase())
  );

  // Connected indicators from active_tunnels array (multi-tunnel aware).
  $: activeSet = new Set($connectionStatus?.active_tunnels || []);
  // Build a map of tunnel name → has handshake for dot color.
  $: tunnelHandshakes = (() => {
    const map = {};
    const tunnelStatuses = $connectionStatus?.tunnels || [];
    for (const ts of tunnelStatuses) {
      map[ts.tunnel_name] = !!ts.last_handshake;
    }
    // Primary tunnel status
    if ($connectionStatus?.tunnel_name) {
      map[$connectionStatus.tunnel_name] = !!$connectionStatus.last_handshake;
    }
    return map;
  })();

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
        <Icon name="shield-off" size={28} strokeWidth={1.5} className="empty-icon" />
        <p>{$t('tunnel.no_tunnels')}</p>
        <p class="hint">{$t('tunnel.drop_hint')}</p>
      </div>
    {:else}
      {#each filtered as tun}
        <button
          class="tunnel-item"
          class:active={$selectedTunnel?.name === tun.name}
          class:connected={activeSet.has(tun.name)}
          on:click={() => select(tun)}
        >
          <span class="status-dot" class:on={activeSet.has(tun.name) && tunnelHandshakes[tun.name]} class:warning={activeSet.has(tun.name) && !tunnelHandshakes[tun.name]}></span>
          <span class="tunnel-name">{tun.name}</span>
        </button>
      {/each}
    {/if}
  </div>

  <div class="list-footer">
    <button class="btn btn-primary" on:click={() => dispatch('new')}>
      <Icon name="plus" size={13} strokeWidth={2.25} />
      {$t('tunnel.new_tunnel')}
    </button>
    <button class="btn btn-secondary" on:click={() => dispatch('import')} title={$t('tunnel.import_hint')}>
      <Icon name="download" size={13} strokeWidth={2} />
      {$t('tunnel.import')}
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

  /* --- List rows (36px — Fitts's Law: larger targets reduce error rate) --- */
  .list-items {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 0 var(--space-2) var(--space-2);
  }
  .tunnel-item {
    display: flex;
    align-items: center;
    width: 100%;
    height: 36px;
    padding: 0 var(--space-2);
    margin-bottom: 1px;
    background: transparent;
    border: none;
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font: var(--text-body);
    cursor: pointer;
    text-align: left;
    position: relative;
    overflow: hidden;
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

  /* Connected left-edge accent pill — inspired by Linear's active indicator */
  .tunnel-item.connected::before {
    content: '';
    position: absolute;
    left: 0;
    top: 50%;
    transform: translateY(-50%);
    width: 3px;
    height: 18px;
    background: var(--green);
    border-radius: 0 2px 2px 0;
  }
  .tunnel-item.connected {
    padding-left: calc(var(--space-2) + 3px);
  }

  /* --- Connection dot --- */
  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: color-mix(in srgb, var(--text-muted) 50%, transparent);
    margin-right: var(--space-2);
    flex-shrink: 0;
  }

  @keyframes dot-pulse {
    0%, 100% {
      box-shadow: 0 0 0 0 color-mix(in srgb, var(--green) 55%, transparent);
    }
    55% {
      box-shadow: 0 0 0 5px color-mix(in srgb, var(--green) 0%, transparent);
    }
  }
  .status-dot.on {
    background: var(--green);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--green) 25%, transparent);
  }
  @media (prefers-reduced-motion: no-preference) {
    .status-dot.on {
      animation: dot-pulse 2.4s ease-out infinite;
    }
  }
  .status-dot.warning {
    background: var(--orange, #FF9500);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--orange, #FF9500) 25%, transparent);
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
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-2);
  }
  :global(.empty-icon) {
    opacity: 0.4;
    margin-bottom: var(--space-1);
  }
  .empty-state p {
    font: var(--text-body);
  }
  .empty-state .hint {
    font: var(--text-footnote);
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
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
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

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
    <h2 class="list-title">{$t('tunnel.list_title')}</h2>
    {#if ($tunnels || []).length > 0}
      <span class="list-count">{($tunnels || []).length}</span>
    {/if}
  </div>

  <div class="search-wrap">
    <span class="search-icon"><Icon name="search" size={13} strokeWidth={2} /></span>
    <input
      type="text"
      class="search-input"
      placeholder={$t('tunnel.search')}
      bind:value={search} />
    {#if search}
      <button class="search-clear" on:click={() => search = ''} aria-label="Clear search">
        <Icon name="x" size={11} strokeWidth={2.5} />
      </button>
    {/if}
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
          aria-current={$selectedTunnel?.name === tun.name ? 'true' : undefined}
          on:click={() => select(tun)}
        >
          <span class="status-dot"
            class:on={activeSet.has(tun.name) && tunnelHandshakes[tun.name]}
            class:warning={activeSet.has(tun.name) && !tunnelHandshakes[tun.name]}></span>
          <div class="tunnel-text">
            <span class="tunnel-name">{tun.name}</span>
            {#if tun.endpoint}
              <span class="tunnel-meta">{tun.endpoint}</span>
            {/if}
          </div>
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

  /* --- Section header (title + count badge) --- */
  .list-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 16px 10px;
    gap: 8px;
  }
  .list-title {
    margin: 0;
    font: 700 10px/13px var(--font-sans);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }
  .list-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 16px;
    padding: 0 6px;
    border-radius: 8px;
    background: color-mix(in srgb, var(--text-muted) 16%, transparent);
    color: var(--text-muted);
    font: 700 10px/1 var(--font-sans);
  }

  /* --- Search input with icon + clear button --- */
  .search-wrap {
    position: relative;
    padding: 0 12px 10px;
  }
  .search-icon {
    position: absolute;
    left: 21px;
    top: 50%;
    transform: translateY(calc(-50% - 5px));
    color: var(--text-muted);
    display: flex;
    align-items: center;
    pointer-events: none;
  }
  .search-input {
    width: 100%;
    height: 30px;
    padding: 0 30px 0 30px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 8px;
    color: var(--text-primary);
    font: 13px/18px var(--font-sans);
    outline: none;
    box-sizing: border-box;
  }
  @media (prefers-reduced-motion: no-preference) {
    .search-input {
      transition: border-color 140ms ease, box-shadow 140ms ease, background 140ms ease;
    }
  }
  .search-input::placeholder { color: var(--text-muted); }
  .search-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
    background: var(--bg-primary);
  }
  .search-clear {
    position: absolute;
    right: 18px;
    top: 50%;
    transform: translateY(calc(-50% - 5px));
    width: 18px;
    height: 18px;
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: color-mix(in srgb, var(--text-muted) 22%, transparent);
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .search-clear:hover {
    background: color-mix(in srgb, var(--text-muted) 36%, transparent);
    color: var(--text-primary);
  }

  /* --- List items: card-style with name + endpoint --- */
  .list-items {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 0 var(--space-2) var(--space-2);
  }
  .tunnel-item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    min-height: 52px;
    padding: 8px 10px;
    margin-bottom: 2px;
    background: transparent;
    border: 0;
    border-radius: 10px;
    color: var(--text-primary);
    font: var(--text-body);
    cursor: pointer;
    text-align: left;
    position: relative;
    overflow: hidden;
  }
  @media (prefers-reduced-motion: no-preference) {
    .tunnel-item {
      transition: background-color var(--dur-fast) var(--ease-out),
                  border-color var(--dur-fast) var(--ease-out);
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
    background: color-mix(in srgb, var(--accent) 12%, transparent);
  }
  .tunnel-item.active .tunnel-name {
    font-weight: 600;
    color: var(--text-primary);
  }

  /* Connected left-edge accent pill */
  .tunnel-item.connected::before {
    content: '';
    position: absolute;
    left: 0;
    top: 50%;
    transform: translateY(-50%);
    width: 3px;
    height: 26px;
    background: var(--green);
    border-radius: 0 2px 2px 0;
  }

  /* --- Connection dot (left of name) --- */
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: color-mix(in srgb, var(--text-muted) 50%, transparent);
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

  /* --- Tunnel text block: name on top, endpoint below --- */
  .tunnel-text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .tunnel-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font: 500 13px/18px var(--font-sans);
    color: var(--text-primary);
    letter-spacing: -0.005em;
  }
  .tunnel-meta {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font: 400 11px/14px var(--font-mono);
    color: var(--text-muted);
    letter-spacing: 0.01em;
  }

  /* --- Empty state --- */
  .empty-state {
    padding: 48px 20px;
    text-align: center;
    color: var(--text-muted);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
  }
  :global(.empty-icon) {
    opacity: 0.4;
    margin-bottom: 4px;
  }
  .empty-state p {
    font: 500 13px/18px var(--font-sans);
    margin: 0;
  }
  .empty-state .hint {
    font: 11px/15px var(--font-sans);
    color: var(--text-muted);
  }

  /* --- Footer buttons (primary gradient + secondary card, no hard divider) --- */
  .list-footer {
    padding: 8px 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .btn {
    width: 100%;
    height: 34px;
    padding: 0 12px;
    border: 0;
    border-radius: 10px;
    font: 600 12px/16px var(--font-sans);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    letter-spacing: -0.005em;
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn {
      transition: background-color 140ms ease, filter 140ms ease,
                  border-color 140ms ease, transform 140ms ease,
                  box-shadow 140ms ease;
    }
  }
  .btn-primary {
    background: var(--accent);
    color: #fff;
    box-shadow:
      0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
      0 1px 2px rgba(0,0,0,0.08);
  }
  .btn-primary:hover {
    background: color-mix(in srgb, #fff 8%, var(--accent));
    transform: translateY(-1px);
    box-shadow:
      0 4px 12px color-mix(in srgb, var(--accent) 32%, transparent),
      0 1px 2px rgba(0,0,0,0.10);
  }
  .btn-primary:active { background: color-mix(in srgb, #000 8%, var(--accent)); transform: translateY(0); }
  .btn-secondary {
    background: var(--bg-card);
    color: var(--text-primary);
    border: 0.5px solid var(--border);
  }
  .btn-secondary:hover {
    background: var(--bg-hover);
    border-color: color-mix(in srgb, var(--accent) 30%, var(--border));
  }
  .btn-secondary:active { background: var(--bg-active); }
</style>

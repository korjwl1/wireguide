<script>
 import { modal, backdrop } from './modal.js';
  import { onMount } from 'svelte';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';

  export let TunnelService;

  let sessions = [];
  let loading = true;
  let confirmingClear = false;
  let error = '';
  let expandedId = null;

  onMount(load);

  async function load() {
    loading = true;
    error = '';
    try {
      sessions = (await TunnelService.GetConnectionHistory()) || [];
    } catch (e) {
      sessions = [];
      error = errText(e);
    }
    loading = false;
  }

  async function clearAll() {
    try {
      await TunnelService.ClearConnectionHistory();
      sessions = [];
      expandedId = null;
    } catch (e) {
      error = errText(e);
    }
    confirmingClear = false;
  }

  // Local-day buckets so the timeline reads as Today / Yesterday / older days.
  // toLocaleDateString uses the user's locale for older entries — matches how
  // macOS Finder lists "Date Modified".
  function bucketLabel(d) {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const sd = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    const diff = Math.round((today - sd) / 86400000);
    if (diff === 0) return $t('history.today');
    if (diff === 1) return $t('history.yesterday');
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  $: groups = (() => {
    const out = [];
    let cur = null;
    for (const s of sessions) {
      const start = new Date(s.start_time);
      const label = bucketLabel(start);
      if (!cur || cur.label !== label) {
        cur = { label, items: [] };
        out.push(cur);
      }
      cur.items.push(s);
    }
    return out;
  })();

  function formatTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  function formatDateTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function formatDuration(sec) {
    if (!sec || sec < 0) return '0s';
    const s = Math.floor(sec);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const ss = s % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${ss}s`;
    return `${ss}s`;
  }

  function formatBytes(n) {
    if (!n || n < 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function reasonLabel(reason) {
    switch (reason) {
      case 'user': return $t('history.reason_user');
      case 'reconnect': return $t('history.reason_reconnect');
      case 'app_quit': return $t('history.reason_app_quit');
      case 'health_check': return $t('history.reason_health_check');
      case 'error': return $t('history.reason_error');
      default: return $t('history.reason_user');
    }
  }

  function toggle(id) {
    expandedId = expandedId === id ? null : id;
  }
</script>

<div class="history-view">
  <div class="history-toolbar">
    <h2 class="history-title">{$t('history.title')}</h2>
    <div class="history-actions">
      <button class="btn-action" on:click={load}>{$t('history.refresh')}</button>
      {#if sessions.length > 0}
        <button class="btn-action btn-danger" on:click={() => confirmingClear = true}>{$t('history.clear')}</button>
      {/if}
    </div>
  </div>

  {#if error}
    <div class="history-error">{error}</div>
  {/if}

  <div class="history-body">
    {#if loading}
      <div class="empty"></div>
    {:else if sessions.length === 0}
      <div class="empty">{$t('history.no_history')}</div>
    {:else}
      {#each groups as group (group.label)}
        <div class="group">
          <div class="group-label">{group.label}</div>
          <div class="group-items">
            {#each group.items as s (s.id)}
              {@const active = !s.end_time}
              <button
                class="session-row"
                class:expanded={expandedId === s.id}
                on:click={() => toggle(s.id)}>
                <div class="row-main">
                  <span class="tunnel-name">{s.tunnel_name}</span>
                  <span class="row-time">{formatTime(s.start_time)}</span>
                </div>
                <div class="row-aside">
                  {#if active}
                    <span class="active-badge">
                      <span class="active-dot"></span>{$t('history.active')}
                    </span>
                  {:else}
                    <span class="duration">{formatDuration(s.duration_sec)}</span>
                  {/if}
                  <span class="stat-pill pill-rx" title={$t('tunnel.rx')}>↓ {formatBytes(s.rx_bytes)}</span>
                  <span class="stat-pill pill-tx" title={$t('tunnel.tx')}>↑ {formatBytes(s.tx_bytes)}</span>
                </div>
              </button>
              {#if expandedId === s.id}
                <div class="session-details">
                  <div class="detail-row">
                    <span class="detail-label">{$t('tunnel.status')}</span>
                    <span class="detail-value">
                      {#if active}
                        <span class="active-dot small"></span>{$t('history.active')}
                      {:else}
                        {reasonLabel(s.disconnect_reason)}
                      {/if}
                    </span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">{$t('history.started')}</span>
                    <span class="detail-value">{formatDateTime(s.start_time)}</span>
                  </div>
                  {#if s.end_time}
                    <div class="detail-row">
                      <span class="detail-label">{$t('history.ended')}</span>
                      <span class="detail-value">{formatDateTime(s.end_time)}</span>
                    </div>
                  {/if}
                  <div class="detail-row">
                    <span class="detail-label">{$t('tunnel.duration')}</span>
                    <span class="detail-value">{active ? '–' : formatDuration(s.duration_sec)}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">{$t('tunnel.rx')}</span>
                    <span class="detail-value">{formatBytes(s.rx_bytes)}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">{$t('tunnel.tx')}</span>
                    <span class="detail-value">{formatBytes(s.tx_bytes)}</span>
                  </div>
                </div>
              {/if}
            {/each}
          </div>
        </div>
      {/each}
    {/if}
  </div>
</div>

{#if confirmingClear}
  <div class="confirm-backdrop" use:backdrop={() => confirmingClear = false}>
    <div class="confirm-dialog" use:modal={() => confirmingClear = false} role="dialog" aria-modal="true" aria-label={$t('history.confirm_clear_title')} tabindex="-1">
      <h3>{$t('history.confirm_clear_title')}</h3>
      <p>{$t('history.confirm_clear_message')}</p>
      <div class="confirm-footer">
        <button class="btn btn-disconnect" on:click={clearAll}>{$t('history.clear')}</button>
        <button class="btn btn-secondary" on:click={() => confirmingClear = false}>{$t('confirm.no')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .history-view {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }
  .history-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-2) var(--space-4);
    border-bottom: 0.5px solid var(--border);
    gap: var(--space-2);
    flex-shrink: 0;
  }
  .history-title {
    margin: 0;
    font: var(--text-headline);
    color: var(--text-primary);
  }
  .history-actions {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .btn-action {
    height: 22px;
    padding: 0 var(--space-2);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-xs);
    color: var(--text-secondary);
    font: var(--text-footnote);
    cursor: pointer;
  }
  .btn-action:hover { background: var(--bg-hover); }
  .btn-action.btn-danger {
    color: var(--red);
    border-color: color-mix(in srgb, var(--red) 40%, var(--border));
  }
  .btn-action.btn-danger:hover {
    background: color-mix(in srgb, var(--red) 12%, transparent);
  }

  .history-error {
    margin: var(--space-2) var(--space-4);
    padding: var(--space-2) var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-footnote);
  }

  .history-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: var(--space-3) var(--space-4) var(--space-5);
  }
  .empty {
    padding: var(--space-8);
    text-align: center;
    color: var(--text-muted);
    font: var(--text-body);
  }

  .group { margin-bottom: var(--space-4); }
  .group-label {
    font: var(--text-footnote);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-secondary);
    margin: var(--space-2) var(--space-1);
  }
  .group-items {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .session-row {
    width: 100%;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm, 6px);
    color: var(--text-primary);
    padding: var(--space-2) var(--space-3);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    cursor: pointer;
    text-align: left;
    transition: background-color 80ms ease, border-color 80ms ease;
  }
  .session-row:hover { background: var(--bg-hover); }
  .session-row.expanded {
    background: var(--bg-hover);
    border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
  }

  .row-main {
    display: flex;
    align-items: baseline;
    gap: var(--space-3);
    min-width: 0;
    flex: 1;
  }
  .tunnel-name {
    font: var(--text-body);
    font-weight: 600;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .row-time {
    font: var(--text-footnote);
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }
  .row-aside {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-shrink: 0;
  }
  .duration {
    font: var(--text-footnote);
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
    min-width: 48px;
    text-align: right;
  }
  .active-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--green);
    font: var(--text-footnote);
    font-weight: 600;
  }
  .active-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--green) 60%, transparent);
    animation: pulse-dot 1.6s ease-out infinite;
  }
  .active-dot.small {
    width: 6px;
    height: 6px;
  }
  @keyframes pulse-dot {
    0%   { box-shadow: 0 0 0 0 color-mix(in srgb, var(--green) 60%, transparent); }
    70%  { box-shadow: 0 0 0 6px color-mix(in srgb, var(--green) 0%, transparent); }
    100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--green) 0%, transparent); }
  }
  @media (prefers-reduced-motion: reduce) {
    .active-dot { animation: none; }
  }

  .stat-pill {
    padding: 1px var(--space-2);
    background: var(--bg-secondary, var(--bg-primary));
    border: 0.5px solid var(--border);
    border-radius: 100px;
    font: var(--text-footnote);
    color: var(--text-secondary);
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
    min-width: 70px;
    text-align: center;
  }
  .pill-rx {
    background: var(--stats-rx-fill, color-mix(in srgb, var(--stats-rx) 12%, transparent));
    border-color: color-mix(in srgb, var(--stats-rx) 30%, transparent);
    color: var(--stats-rx);
  }
  .pill-tx {
    background: var(--stats-tx-fill, color-mix(in srgb, var(--stats-tx) 12%, transparent));
    border-color: color-mix(in srgb, var(--stats-tx) 30%, transparent);
    color: var(--stats-tx);
  }

  .session-details {
    border: 0.5px solid var(--border);
    border-top: 0;
    border-bottom-left-radius: var(--radius-sm, 6px);
    border-bottom-right-radius: var(--radius-sm, 6px);
    padding: var(--space-2) var(--space-3) var(--space-3);
    background: var(--bg-primary);
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: -1px; /* overlap the row's bottom border so it reads as one card */
  }
  .detail-row {
    display: flex;
    justify-content: space-between;
    gap: var(--space-3);
    font: var(--text-body);
    padding: 2px 0;
  }
  .detail-label {
    color: var(--text-secondary);
    font: var(--text-footnote);
  }
  .detail-value {
    color: var(--text-primary);
    text-align: right;
    font: var(--text-footnote);
    font-variant-numeric: tabular-nums;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  /* Confirm-clear modal — mirrors the existing delete-confirmation modal
     pattern in TunnelDetail so the UI feels consistent. */
  .confirm-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    backdrop-filter: blur(2px);
  }
  .confirm-dialog {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-md, 8px);
    padding: var(--space-4);
    width: 320px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }
  .confirm-dialog h3 {
    margin: 0 0 var(--space-2);
    font: var(--text-headline);
    color: var(--text-primary);
  }
  .confirm-dialog p {
    margin: 0 0 var(--space-3);
    color: var(--text-secondary);
    font: var(--text-body);
    line-height: 1.5;
  }
  .confirm-footer {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
  }
  .btn {
    height: 28px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: var(--radius-sm);
    font: var(--text-headline);
    cursor: pointer;
    color: var(--text-primary);
  }
  .btn-disconnect {
    background: var(--red);
    color: #fff;
  }
  .btn-secondary {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    color: var(--text-primary);
  }
</style>

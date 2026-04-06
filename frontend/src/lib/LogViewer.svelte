<script>
  import { afterUpdate, onMount } from 'svelte';
  import { logs, clearLogs } from '../stores/logs.js';
  import { t } from '../i18n/index.js';

  let filter = 'all';
  let autoScroll = true;
  let logContainer;
  let prevLogsLen = 0;
  let shouldScroll = true;
  let copyFeedback = false;

  const levels = ['debug', 'info', 'warn', 'error'];
  const levelRank = { debug: 0, info: 1, warn: 2, error: 3 };

  $: filtered = ($logs || []).filter((entry) => {
    if (filter === 'all') return true;
    return (levelRank[entry.level] ?? 1) >= (levelRank[filter] ?? 1);
  });

  $: {
    const len = ($logs || []).length;
    if (len !== prevLogsLen) {
      shouldScroll = true;
      prevLogsLen = len;
    }
  }

  onMount(() => {
    if (logContainer) logContainer.scrollTop = logContainer.scrollHeight;
  });

  afterUpdate(() => {
    if (autoScroll && shouldScroll && logContainer) {
      logContainer.scrollTop = logContainer.scrollHeight;
      shouldScroll = false;
    }
  });

  function clear() {
    clearLogs();
  }

  function formatTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return `${h}:${m}:${s}.${ms}`;
  }

  function formatEntry(entry) {
    return `${formatTime(entry.time)}\t${entry.source}\t${entry.level.toUpperCase()}\t${entry.message}`;
  }

  async function copyAll() {
    const text = filtered.map(formatEntry).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      copyFeedback = true;
      setTimeout(() => copyFeedback = false, 1500);
    } catch (e) {
      console.error('copy failed:', e);
    }
  }

  // Intercept native copy to format grid cells as tab-separated text
  // instead of the browser's default (which often collapses grid columns
  // into a single line or adds weird spacing).
  function handleCopy(e) {
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed) return;

    // Walk all .log-entry elements that intersect the selection range
    if (!logContainer) return;
    const entries = logContainer.querySelectorAll('.log-entry');
    const lines = [];
    for (const row of entries) {
      if (sel.containsNode(row, true)) {
        const time = row.querySelector('.log-time')?.textContent || '';
        const source = row.querySelector('.log-source')?.textContent || '';
        const level = row.querySelector('.log-level')?.textContent || '';
        const msg = row.querySelector('.log-msg')?.textContent || '';
        lines.push(`${time}\t${source}\t${level}\t${msg}`);
      }
    }
    if (lines.length > 0) {
      e.preventDefault();
      e.clipboardData.setData('text/plain', lines.join('\n'));
    }
  }
</script>

<div class="log-viewer">
  <div class="log-toolbar">
    <div class="log-filters">
      <button class:active={filter === 'all'} on:click={() => filter = 'all'}>{$t('log.filter_all')}</button>
      {#each levels as lvl}
        <button class:active={filter === lvl} class="level-{lvl}" on:click={() => filter = lvl}>
          {lvl.toUpperCase()}
        </button>
      {/each}
    </div>
    <div class="log-actions">
      <label>
        <input type="checkbox" bind:checked={autoScroll} /> {$t('log.auto_scroll')}
      </label>
      <button class="btn-action" on:click={copyAll}>
        {copyFeedback ? '✓' : $t('log.copy')}
      </button>
      <button class="btn-action" on:click={clear}>{$t('log.clear')}</button>
    </div>
  </div>

  <div class="log-entries" bind:this={logContainer} on:copy={handleCopy}>
    {#each filtered as entry, i (i)}
      <div class="log-entry level-{entry.level}">
        <span class="log-time">{formatTime(entry.time)}</span>
        <span class="log-source">{entry.source}</span>
        <span class="log-level">{entry.level.toUpperCase()}</span>
        <span class="log-msg">{entry.message}</span>
      </div>
    {/each}
    {#if filtered.length === 0}
      <div class="log-empty">{$t('log.no_entries')}</div>
    {/if}
  </div>
</div>

<style>
  .log-viewer {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }
  .log-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-2) var(--space-4);
    border-bottom: 0.5px solid var(--border);
    gap: var(--space-2);
  }
  .log-filters {
    display: flex;
    gap: var(--space-1);
  }
  .log-filters button {
    height: 22px;
    padding: 0 var(--space-2);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-xs);
    color: var(--text-secondary);
    font: 10px/1 var(--font-sans);
    font-weight: 600;
    letter-spacing: 0.04em;
    cursor: pointer;
  }
  .log-filters button:hover { background: var(--bg-hover); }
  .log-filters button.active {
    background: var(--accent);
    color: var(--text-inverse);
    border-color: transparent;
  }
  .log-actions {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    font: var(--text-footnote);
    color: var(--text-secondary);
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

  .log-entries {
    flex: 1;
    height: 0;
    overflow-y: auto;
    padding: var(--space-2);
    font: 11px/1.5 var(--font-mono);
    background: var(--log-bg);
    contain: content;
    /* Ensure text is selectable — the global button reset or other rules
     * might set user-select: none. Log content MUST be selectable for
     * copy-paste into bug reports. */
    user-select: text;
    -webkit-user-select: text;
    cursor: text;
  }
  .log-entry {
    display: grid;
    grid-template-columns: 90px 55px 55px minmax(0, 1fr);
    gap: var(--space-2);
    padding: 2px var(--space-2);
    border-bottom: 0.5px solid var(--log-border);
    align-items: baseline;
  }
  .log-time,
  .log-source,
  .log-level,
  .log-msg { min-width: 0; }
  .log-time  { color: var(--text-muted); font-variant-numeric: tabular-nums; }
  .log-source{ color: var(--text-secondary); font-style: italic; }
  .log-level { font-weight: 700; }
  .log-msg   {
    color: var(--text-primary);
    overflow-wrap: anywhere;
    white-space: pre-wrap;
  }

  .level-debug .log-level { color: var(--text-muted); }
  .level-info  .log-level { color: var(--blue); }
  .level-warn  .log-level { color: var(--yellow); }
  .level-error .log-level { color: var(--red); }
  .level-error .log-msg   { color: var(--error-text); }

  .log-empty {
    padding: var(--space-8);
    text-align: center;
    color: var(--text-muted);
    font: var(--text-body);
  }
</style>

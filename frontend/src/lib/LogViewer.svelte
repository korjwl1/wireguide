<script>
  import { onMount, onDestroy } from 'svelte';
  import { t } from '../i18n/index.js';

  let logs = [];
  let filter = 'all';
  let autoScroll = true;
  let logContainer;

  const levels = ['debug', 'info', 'warn', 'error'];

  // Simulate log collection (in production, this would stream from daemon via gRPC)
  let interval;
  onMount(() => {
    addLog('info', 'Log viewer started');
  });

  onDestroy(() => {
    if (interval) clearInterval(interval);
  });

  export function addLog(level, message) {
    const entry = {
      time: new Date().toLocaleTimeString(),
      level,
      message,
    };
    logs = [...logs, entry].slice(-500); // Keep last 500 entries
    if (autoScroll && logContainer) {
      requestAnimationFrame(() => {
        logContainer.scrollTop = logContainer.scrollHeight;
      });
    }
  }

  $: filtered = filter === 'all'
    ? logs
    : logs.filter(l => levels.indexOf(l.level) >= levels.indexOf(filter));

  function clear() {
    logs = [];
  }
</script>

<div class="log-viewer">
  <div class="log-toolbar">
    <div class="log-filters">
      <button class:active={filter === 'all'} on:click={() => filter = 'all'}>All</button>
      {#each levels as lvl}
        <button class:active={filter === lvl} class="level-{lvl}" on:click={() => filter = lvl}>
          {lvl.toUpperCase()}
        </button>
      {/each}
    </div>
    <div class="log-actions">
      <label>
        <input type="checkbox" bind:checked={autoScroll} /> Auto-scroll
      </label>
      <button class="btn-clear" on:click={clear}>Clear</button>
    </div>
  </div>

  <div class="log-entries" bind:this={logContainer}>
    {#each filtered as entry}
      <div class="log-entry level-{entry.level}">
        <span class="log-time">{entry.time}</span>
        <span class="log-level">{entry.level.toUpperCase().padEnd(5)}</span>
        <span class="log-msg">{entry.message}</span>
      </div>
    {/each}
    {#if filtered.length === 0}
      <div class="log-empty">No log entries</div>
    {/if}
  </div>
</div>

<style>
  .log-viewer {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .log-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .log-filters {
    display: flex;
    gap: 4px;
  }
  .log-filters button {
    padding: 3px 8px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
  }
  .log-filters button.active {
    background: var(--accent);
    color: var(--text-primary);
    border-color: var(--accent);
  }
  .log-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: var(--text-secondary);
  }
  .btn-clear {
    padding: 3px 8px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
  }
  .log-entries {
    flex: 1;
    overflow-y: auto;
    padding: 4px;
    font-family: monospace;
    font-size: 12px;
    background: #0a0a18;
  }
  .log-entry {
    padding: 2px 8px;
    display: flex;
    gap: 8px;
    border-bottom: 1px solid #1a1a2a;
  }
  .log-time { color: var(--text-muted); min-width: 80px; }
  .log-level { min-width: 50px; font-weight: 600; }
  .level-debug .log-level { color: var(--text-secondary); }
  .level-info .log-level { color: var(--blue); }
  .level-warn .log-level { color: var(--yellow); }
  .level-error .log-level { color: var(--red); }
  .log-msg { color: var(--text-primary); word-break: break-all; }
  .log-empty {
    padding: 24px;
    text-align: center;
    color: var(--text-muted);
  }
</style>

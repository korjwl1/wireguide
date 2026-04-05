<script>
  import { createEventDispatcher } from 'svelte';
  import { t } from '../i18n/index.js';

  export let scripts = [];
  export let tunnelName = '';

  const dispatch = createEventDispatcher();
</script>

<div class="modal-backdrop" on:click={() => dispatch('deny')}>
  <div class="modal" on:click|stopPropagation>
    <h3>{$t('scripts.warning_title')}</h3>
    <p class="warning-text">{$t('scripts.warning_message')}</p>

    <div class="script-list">
      {#each scripts as script}
        <div class="script-item">
          <span class="hook">{script.Hook}</span>
          <code class="command">{script.Command}</code>
        </div>
      {/each}
    </div>

    <div class="modal-footer">
      <button class="btn btn-allow" on:click={() => dispatch('allow')}>
        {$t('scripts.allow')}
      </button>
      <button class="btn btn-deny" on:click={() => dispatch('deny')}>
        {$t('scripts.deny')}
      </button>
    </div>
    <p class="deny-note">{$t('scripts.denied_note')}</p>
  </div>
</div>

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 300;
  }
  .modal {
    background: var(--bg-primary);
    border: 1px solid var(--red);
    border-radius: 12px;
    padding: 24px;
    width: 480px;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: var(--shadow-md);
  }
  h3 {
    margin: 0 0 8px;
    color: var(--red);
  }
  .warning-text {
    color: var(--text-secondary);
    font-size: 14px;
    margin-bottom: 16px;
  }
  .script-list {
    background: var(--warn-item-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 16px;
  }
  .script-item {
    margin-bottom: 8px;
  }
  .script-item:last-child {
    margin-bottom: 0;
  }
  .hook {
    display: block;
    font-size: 11px;
    color: var(--yellow);
    text-transform: uppercase;
    margin-bottom: 2px;
  }
  .command {
    display: block;
    font-size: 13px;
    color: var(--text-primary);
    font-family: monospace;
    word-break: break-all;
  }
  .modal-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }
  .btn {
    padding: 8px 20px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
  }
  .btn-allow {
    background: var(--yellow);
    color: var(--bg-primary);
    font-weight: 600;
  }
  .btn-allow:hover { opacity: 0.9; }
  .btn-deny {
    background: var(--bg-card);
    color: var(--text-primary);
    border: 1px solid var(--border);
  }
  .btn-deny:hover { background: var(--bg-hover); }
  .deny-note {
    margin-top: 12px;
    font-size: 11px;
    color: var(--text-muted);
    text-align: center;
  }
</style>

<script>
  import { createEventDispatcher } from 'svelte';
  import { t } from '../i18n/index.js';

  export let conflicts = [];
  const dispatch = createEventDispatcher();
</script>

<div class="modal-backdrop" on:click={() => dispatch('cancel')}>
  <div class="modal" on:click|stopPropagation>
    <h3>{$t('conflict.title')}</h3>

    <div class="conflict-list">
      {#each conflicts as conflict}
        <div class="conflict-item">
          <div class="conflict-header">
            <span class="iface">{conflict.interface_name}</span>
            <span class="owner">({conflict.owner})</span>
          </div>
          <div class="overlap-list">
            {#each conflict.overlapping_ips as overlap}
              <code class="overlap">{overlap}</code>
            {/each}
          </div>
        </div>
      {/each}
    </div>

    <p class="warning-text">{$t('conflict.message')}</p>

    <div class="modal-footer">
      <button class="btn btn-warn" on:click={() => dispatch('proceed')}>
        {$t('conflict.proceed')}
      </button>
      <button class="btn btn-cancel" on:click={() => dispatch('cancel')}>
        {$t('conflict.cancel')}
      </button>
    </div>
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
    border: 1px solid var(--yellow);
    border-radius: 12px;
    padding: 24px;
    width: 480px;
    box-shadow: var(--shadow-md);
  }
  h3 { color: var(--yellow); margin: 0 0 16px; }
  .conflict-item {
    background: var(--warn-item-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 8px;
  }
  .conflict-header { margin-bottom: 4px; }
  .iface { font-weight: 600; color: var(--text-primary); }
  .owner { color: var(--text-secondary); font-size: 13px; margin-left: 4px; }
  .overlap {
    display: block;
    font-size: 12px;
    color: var(--yellow);
    margin-top: 2px;
  }
  .warning-text {
    font-size: 13px;
    color: var(--text-secondary);
    margin: 12px 0;
  }
  .modal-footer { display: flex; gap: 8px; justify-content: flex-end; }
  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
  }
  .btn-warn { background: var(--yellow); color: var(--bg-primary); font-weight: 600; }
  .btn-cancel { background: var(--bg-card); color: var(--text-primary); }
</style>

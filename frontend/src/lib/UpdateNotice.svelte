<script>
  import { t } from '../i18n/index.js';
  import { connectionStatus } from '../stores/tunnels.js';

  export let updateInfo = null;
  export let onInstall = null;
  export let onDismiss = null;

  let installing = false;
  let showConfirm = false;

  function requestInstall() {
    // If VPN is connected, show confirmation with warning
    if ($connectionStatus?.state === 'connected') {
      showConfirm = true;
    } else {
      doInstall();
    }
  }

  async function doInstall() {
    showConfirm = false;
    installing = true;
    if (onInstall) await onInstall();
    installing = false;
  }
</script>

{#if updateInfo?.available}
  <div class="update-banner">
    <div class="update-info">
      <strong>{$t('update.available', { version: updateInfo.version })}</strong>
      <span class="current">{$t('update.current', { version: updateInfo.current_version })}</span>
    </div>
    <div class="update-actions">
      <button class="btn-update" on:click={requestInstall} disabled={installing}>
        {installing ? $t('update.updating') : $t('update.update_now')}
      </button>
      <a href={updateInfo.release_url} target="_blank" class="btn-notes">{$t('update.release_notes')}</a>
      {#if onDismiss}
        <button class="btn-dismiss" on:click={onDismiss}>×</button>
      {/if}
    </div>
  </div>

  {#if showConfirm}
    <div class="confirm-backdrop" on:click={() => showConfirm = false}>
      <div class="confirm-dialog" on:click|stopPropagation role="dialog">
        <h3>{$t('update.confirm_title')}</h3>
        <p>{$t('update.vpn_warning')}</p>
        <div class="confirm-actions">
          <button class="btn-proceed" on:click={doInstall}>{$t('update.proceed')}</button>
          <button class="btn-cancel" on:click={() => showConfirm = false}>{$t('update.cancel')}</button>
        </div>
      </div>
    </div>
  {/if}
{/if}

<style>
  .update-banner {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 16px;
    background: var(--green-tint);
    border: 1px solid var(--green);
    border-radius: 8px;
    margin: 8px 16px;
  }
  .update-info { font-size: 13px; }
  .current { color: var(--text-secondary); font-size: 12px; margin-left: 4px; }
  .update-actions { display: flex; gap: 8px; align-items: center; }
  .btn-update {
    padding: 4px 12px;
    background: var(--green);
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
  }
  .btn-update:disabled { opacity: 0.5; cursor: wait; }
  .btn-notes {
    padding: 4px 12px;
    color: var(--text-secondary);
    font-size: 12px;
    text-decoration: none;
  }
  .btn-notes:hover { color: var(--text-primary); }
  .btn-dismiss {
    background: none; border: none; color: var(--text-muted);
    cursor: pointer; font-size: 16px; padding: 0 4px;
  }

  .confirm-backdrop {
    position: fixed; inset: 0;
    background: var(--overlay-bg);
    display: flex; align-items: center; justify-content: center;
    z-index: 1000;
  }
  .confirm-dialog {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    max-width: 400px;
    box-shadow: var(--shadow-md);
  }
  .confirm-dialog h3 { margin: 0 0 12px; }
  .confirm-dialog p {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.5;
    margin: 0 0 16px;
  }
  .confirm-actions { display: flex; gap: 8px; justify-content: flex-end; }
  .btn-proceed {
    padding: 6px 16px; background: var(--green); color: #fff;
    border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;
  }
  .btn-cancel {
    padding: 6px 16px; background: var(--bg-card); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-size: 13px;
  }
</style>

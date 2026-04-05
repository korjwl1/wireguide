<script>
  import { t } from '../i18n/index.js';

  export let updateInfo = null;
  export let onInstall = null;

  function install() {
    if (onInstall) onInstall();
  }
</script>

{#if updateInfo?.available}
  <div class="update-banner">
    <div class="update-text">
      <strong>{$t('update.available', { version: updateInfo.version })}</strong>
      <span class="current">({$t('update.current', { version: updateInfo.current_version })})</span>
    </div>
    <div class="update-actions">
      <button class="btn-update" on:click={install}>{$t('update.update_now')}</button>
      <a href={updateInfo.release_url} target="_blank" class="btn-notes">{$t('update.release_notes')}</a>
    </div>
  </div>
{/if}

<style>
  .update-banner {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 16px;
    background: var(--yellow-tint);
    border: 1px solid var(--yellow);
    border-radius: 8px;
    margin: 8px 0;
  }
  .update-text { font-size: 13px; }
  .current { color: var(--text-secondary); font-size: 12px; margin-left: 4px; }
  .update-actions { display: flex; gap: 8px; }
  .btn-update {
    padding: 4px 12px;
    background: var(--yellow);
    color: var(--bg-primary);
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
  }
  .btn-notes {
    padding: 4px 12px;
    color: var(--text-secondary);
    font-size: 12px;
    text-decoration: none;
  }
  .btn-notes:hover { color: var(--text-primary); }
</style>

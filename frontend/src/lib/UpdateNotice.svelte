<script>
  export let updateInfo = null;
  export let onInstall = null;

  function install() {
    if (onInstall) onInstall();
  }
</script>

{#if updateInfo?.available}
  <div class="update-banner">
    <div class="update-text">
      <strong>Update available: v{updateInfo.version}</strong>
      <span class="current">(current: v{updateInfo.current_version})</span>
    </div>
    <div class="update-actions">
      <button class="btn-update" on:click={install}>Update Now</button>
      <a href={updateInfo.release_url} target="_blank" class="btn-notes">Release Notes</a>
    </div>
  </div>
{/if}

<style>
  .update-banner {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 16px;
    background: rgba(253, 203, 110, 0.1);
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
    color: #1a1a2e;
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

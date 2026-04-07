<script>
  import { t } from '../i18n/index.js';
  import { connectionStatus } from '../stores/tunnels.js';

  export let updateInfo = null;
  export let onInstall = null;

  let installing = false;
  let showConfirm = false;

  // Check if this version was previously dismissed
  $: dismissed = (() => { try { return updateInfo?.version && localStorage.getItem('wireguide_skip_version') === updateInfo.version; } catch { return false; } })();
  $: showPopup = updateInfo?.available && !dismissed;

  function requestInstall() {
    if ($connectionStatus?.state === 'connected') {
      showConfirm = true;
    } else {
      doInstall();
    }
  }

  async function doInstall() {
    if (installing) return;
    showConfirm = false;
    installing = true;
    if (onInstall) await onInstall();
    installing = false;
  }

  function dismiss() {
    // Save dismissed version so popup doesn't show again for this version
    try {
      if (updateInfo?.version) {
        localStorage.setItem('wireguide_skip_version', updateInfo.version);
      }
    } catch { /* localStorage unavailable */ }
  }
</script>

{#if showPopup}
  <div class="popup-backdrop" on:mousedown|self={dismiss}>
    <div class="popup" role="dialog" aria-modal="true" on:mousedown|stopPropagation>
      <div class="popup-header">
        <img src="/appicon.png" alt="WireGuide" class="popup-icon" />
        <div>
          <div class="popup-title">{$t('update.available', { version: updateInfo.version })}</div>
          <span class="popup-current">{$t('update.current', { version: updateInfo.current_version })}</span>
        </div>
      </div>

      {#if updateInfo.release_notes}
        <div class="popup-notes-label">{$t('update.release_notes')}</div>
        <div class="popup-notes">{updateInfo.release_notes}</div>
      {/if}

      <div class="popup-actions">
        <button class="btn-update" on:click={requestInstall} disabled={installing}>
          {installing ? $t('update.updating') : $t('update.update_now')}
        </button>
        <button class="btn-skip" on:click={dismiss}>{$t('update.skip')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showConfirm}
  <div class="popup-backdrop" on:mousedown|self={() => showConfirm = false}>
    <div class="popup" on:mousedown|stopPropagation role="dialog" aria-modal="true">
      <h3>{$t('update.confirm_title')}</h3>
      <p class="confirm-msg">{$t('update.vpn_warning')}</p>
      <div class="popup-actions">
        <button class="btn-update" on:click={doInstall}>{$t('update.proceed')}</button>
        <button class="btn-skip" on:click={() => showConfirm = false}>{$t('update.cancel')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .popup-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 300;
  }
  @media (prefers-color-scheme: dark) {
    .popup-backdrop { background: rgba(0,0,0,0.55); }
  }
  .popup {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
    width: 380px;
    box-shadow: var(--shadow-md, 0 4px 12px rgba(0,0,0,0.12));
  }
  .popup-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }
  .popup-icon {
    width: 48px;
    height: 48px;
    border-radius: 10px;
  }
  .popup-title {
    font: 600 14px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
  }
  .popup-current {
    font: 400 11px/14px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
  }
  .popup-notes-label {
    font: 600 11px/14px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 4px;
  }
  .popup-notes {
    font: 400 12px/16px var(--font-mono, ui-monospace, "SF Mono", Menlo, monospace);
    color: var(--text-secondary);
    margin-bottom: 16px;
    max-height: 140px;
    overflow-y: auto;
    white-space: pre-wrap;
    background: var(--bg-secondary, #F5F5F7);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
  }
  .popup-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }
  .btn-update {
    height: 28px;
    padding: 0 16px;
    background: var(--accent, #007AFF);
    color: var(--text-inverse, #fff);
    border: none;
    border-radius: 6px;
    font: 500 13px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
  }
  .btn-update:hover { filter: brightness(1.08); }
  .btn-update:active { filter: brightness(0.94); }
  .btn-update:disabled { opacity: 0.5; cursor: wait; }
  .btn-update:focus-visible {
    outline: 2px solid var(--accent, #007AFF);
    outline-offset: 2px;
  }
  .btn-skip {
    height: 28px;
    padding: 0 16px;
    background: var(--bg-secondary, #F5F5F7);
    color: var(--text-primary);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    font: 400 13px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
  }
  .btn-skip:hover { background: var(--bg-hover); }
  .btn-skip:focus-visible {
    outline: 2px solid var(--accent, #007AFF);
    outline-offset: 2px;
  }
  h3 {
    margin: 0 0 8px;
    font: 600 15px/20px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
  }
  .confirm-msg {
    font: 400 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    margin: 0 0 16px;
  }

  @media (prefers-reduced-motion: no-preference) {
    .btn-update, .btn-skip {
      transition: filter 120ms cubic-bezier(0.2, 0, 0.1, 1),
                  background-color 120ms cubic-bezier(0.2, 0, 0.1, 1);
    }
  }
</style>

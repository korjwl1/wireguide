<script>
  import { onDestroy, onMount } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import { t } from '../i18n/index.js';
  import { connectionStatus } from '../stores/tunnels.js';

  // Dismissible top-of-window banner — *not* a modal — matching the
  // VS Code / Tailscale / Bitwarden convention (see
  // research-update-patterns). Modal popups on update are a textbook
  // anti-pattern: GitHub Desktop #16057, Mozilla bug 1557660, Jakob
  // Nielsen "Top 10 UI Annoyances" all flag them.
  export let updateInfo = null;
  export let onInstall = null;
  export let onDismiss = null;

  let installing = false;
  let showConfirm = false;
  let showNotes = false;
  // Live phase from the backend ("refresh" → brew update, "install" →
  // brew upgrade). The tap refresh alone can take 75+ s; without this the
  // button sat on a static label long enough to read as a hang.
  let phase = '';
  let errorMsg = '';
  let unsubProgress = null;

  onMount(() => {
    unsubProgress = Events.On('update_progress', (e) => { phase = e?.data?.phase || ''; });
  });
  onDestroy(() => { if (unsubProgress) unsubProgress(); });

  $: phaseLabel = phase === 'refresh' ? $t('update.progress_refresh')
    : phase === 'install' ? $t('update.progress_install')
    : '';

  $: visible = !!updateInfo?.available;

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
    errorMsg = '';
    try {
      if (onInstall) await onInstall();
      // Success without the cask postflight killing us should be
      // impossible now (RunUpdate verifies the on-disk version), so
      // reaching here means the process survives only briefly.
    } catch (e) {
      errorMsg = ($t('update.install_failed') || 'Update failed') + ': ' + (e?.message || e);
    } finally {
      installing = false;
      phase = '';
    }
  }

  function dismiss() {
    if (onDismiss) onDismiss(updateInfo?.version);
  }
</script>

{#if visible}
  <div class="banner" role="status">
    <img src="/appicon.png" alt="" class="banner-icon" />

    <div class="banner-text">
      <div class="banner-title">
        {$t('update.available', { version: updateInfo.version })}
      </div>
      <div class="banner-sub">
        {$t('update.current', { version: updateInfo.current_version })}
        {#if updateInfo.release_notes}
          <button class="banner-link" on:click={() => showNotes = !showNotes}>
            {showNotes ? $t('update.hide_notes') : $t('update.release_notes')}
          </button>
        {/if}
      </div>
      {#if showNotes && updateInfo.release_notes}
        <div class="banner-notes">{updateInfo.release_notes}</div>
      {/if}
      {#if installing && phaseLabel}
        <div class="banner-phase">{phaseLabel}</div>
      {/if}
      {#if errorMsg}
        <div class="banner-error">{errorMsg}</div>
      {/if}
    </div>

    <div class="banner-actions">
      <button class="btn-update" on:click={requestInstall} disabled={installing}>
        {installing ? $t('update.updating') : $t('update.update_now')}
      </button>
      <button class="btn-dismiss" on:click={dismiss} title={$t('update.skip')}>×</button>
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
  .banner {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 10px 14px;
    background: color-mix(in srgb, var(--accent) 8%, var(--bg-secondary));
    border-bottom: 0.5px solid color-mix(in srgb, var(--accent) 30%, var(--border));
    color: var(--text-primary);
  }
  .banner-icon {
    width: 28px;
    height: 28px;
    border-radius: 6px;
    flex-shrink: 0;
    margin-top: 2px;
  }
  .banner-text { flex: 1; min-width: 0; }
  .banner-title {
    font: 600 13px/17px var(--font-sans);
    letter-spacing: -0.005em;
  }
  .banner-sub {
    font: 400 11px/15px var(--font-sans);
    color: var(--text-secondary);
    display: flex;
    gap: 8px;
    align-items: baseline;
  }
  .banner-link {
    background: none;
    border: 0;
    padding: 0;
    color: var(--accent);
    font: inherit;
    text-decoration: underline;
    cursor: pointer;
  }
  .banner-phase {
    margin-top: 4px;
    font: 400 11px/15px var(--font-sans);
    color: var(--accent);
  }
  .banner-error {
    margin-top: 4px;
    font: 400 11px/15px var(--font-sans);
    color: var(--error-text, #ff3b30);
    white-space: pre-wrap;
  }
  .banner-notes {
    margin-top: 6px;
    font: 400 12px/16px var(--font-mono, ui-monospace, "SF Mono", Menlo, monospace);
    color: var(--text-secondary);
    white-space: pre-wrap;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    max-height: 160px;
    overflow-y: auto;
  }
  .banner-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }
  .btn-update {
    height: 28px;
    padding: 0 14px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 6px;
    font: 600 12px/16px var(--font-sans);
    cursor: pointer;
  }
  .btn-update:hover { filter: brightness(1.08); }
  .btn-update:active { filter: brightness(0.94); }
  .btn-update:disabled { opacity: 0.5; cursor: wait; }
  .btn-update:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .btn-dismiss {
    width: 22px;
    height: 22px;
    background: transparent;
    color: var(--text-secondary);
    border: 0;
    border-radius: 6px;
    font: 400 16px/22px var(--font-sans);
    cursor: pointer;
    text-align: center;
  }
  .btn-dismiss:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* Confirm-while-connected dialog stays modal — that's the right
     pattern for a confirmation, not for the initial notice. */
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
    box-shadow: 0 4px 12px rgba(0,0,0,0.12);
  }
  .popup-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }
  .btn-skip {
    height: 28px;
    padding: 0 16px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    font: 400 13px var(--font-sans);
    cursor: pointer;
  }
  .btn-skip:hover { background: var(--bg-hover); }
  h3 { margin: 0 0 8px; font: 600 15px/20px var(--font-sans); }
  .confirm-msg {
    font: 400 13px/18px var(--font-sans);
    color: var(--text-secondary);
    margin: 0 0 16px;
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn-update, .btn-skip, .btn-dismiss {
      transition: filter 120ms ease, background-color 120ms ease;
    }
  }
</style>

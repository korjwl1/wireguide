<script>
  import { t } from '../i18n/index.js';

  export let message = '';
  export let onRetry = null;
  export let busy = false;
</script>

<div class="error-notice" role="alert">
  <span>{message}</span>
  {#if onRetry}
    <button type="button" disabled={busy} on:click={onRetry}>{$t('settings.retry')}</button>
  {/if}
</div>

<style>
  .error-notice {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin: 8px 0;
    flex-shrink: 0;
    color: var(--error-text, #ff453a);
    font: 400 12px/1.5 var(--font-sans);
    overflow-wrap: anywhere;
  }
  span { flex: 1; min-width: 0; }
  button {
    flex-shrink: 0;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    padding: 3px 8px;
    cursor: pointer;
    white-space: nowrap;
  }
  button:disabled { opacity: 0.5; cursor: default; }
  button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
</style>

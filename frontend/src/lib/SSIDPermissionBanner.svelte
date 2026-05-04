<script>
  // Shows a persistent banner when Location Services permission is needed
  // to read the current Wi-Fi SSID. Polls every 2s and auto-dismisses
  // once permission is granted.
  import { onDestroy } from 'svelte';
  import { t } from '../i18n/index.js';

  export let TunnelService;

  // tri-state: null = not yet checked, true = ok, false = denied
  let permissionOk = null;
  let pollTimer = null;

  async function check() {
    if (!TunnelService) return;
    try {
      const s = await TunnelService.CheckSSIDPermission();
      // No WiFi hardware → no issue, don't show banner
      if (!s.has_wifi) { permissionOk = true; return; }
      permissionOk = s.has_permission;
      if (!permissionOk) startPolling();
    } catch (_) {
      permissionOk = true; // fail open — don't block the UI
    }
  }

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(async () => {
      try {
        const s = await TunnelService.CheckSSIDPermission();
        if (!s.has_wifi || s.has_permission) {
          permissionOk = true;
          clearInterval(pollTimer);
          pollTimer = null;
        }
      } catch (_) {}
    }, 2000);
  }

  function openSettings() {
    TunnelService.OpenLocationSettings();
  }

  check();

  onDestroy(() => {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  });
</script>

{#if permissionOk === false}
  <div class="permission-banner" role="alert">
    <div class="banner-icon">⚠</div>
    <div class="banner-body">
      <p class="banner-title">{$t('wifi_permission.title')}</p>
      <p class="banner-desc">{$t('wifi_permission.desc')}</p>
    </div>
    <button class="banner-btn" on:click={openSettings}>
      {$t('wifi_permission.open_settings')}
    </button>
  </div>
{/if}

<style>
  .permission-banner {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-3);
    background: color-mix(in srgb, var(--accent-yellow, #FF9500) 10%, transparent);
    border: 0.5px solid var(--accent-yellow, #FF9500);
    border-radius: var(--radius-sm, 6px);
    margin-bottom: var(--space-3);
  }
  .banner-icon {
    font-size: 16px;
    line-height: 1.4;
    color: var(--accent-yellow, #FF9500);
    flex-shrink: 0;
  }
  .banner-body {
    flex: 1;
    min-width: 0;
  }
  .banner-title {
    font: var(--text-body);
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 2px;
  }
  .banner-desc {
    font: var(--text-footnote);
    color: var(--text-secondary);
    margin: 0;
  }
  .banner-btn {
    flex-shrink: 0;
    padding: 0 var(--space-3);
    min-height: 28px;
    background: var(--accent, #007AFF);
    border: none;
    border-radius: var(--radius-sm, 6px);
    color: #fff;
    font: var(--text-body);
    cursor: pointer;
    white-space: nowrap;
    align-self: center;
  }
  .banner-btn:hover { filter: brightness(1.08); }
</style>

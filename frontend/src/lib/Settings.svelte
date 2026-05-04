<script>
  import { onDestroy, onMount } from 'svelte';
  import { t, setLanguage, getLanguage, detectLanguage } from '../i18n/index.js';
  import { applyTheme } from '../stores/theme.js';
  import { connectionStatus, tunnels } from '../stores/tunnels.js';
  import WifiRules from './WifiRules.svelte';

  export let TunnelService;
  export let onClose = () => {};
  export let updateInfo = null;
  export let onInstall = null;

  let aboutUpdating = false;
  let aboutShowVpnWarn = false;

  function aboutRequestUpdate() {
    if ($connectionStatus?.state === 'connected') {
      aboutShowVpnWarn = true;
    } else {
      doAboutUpdate();
    }
  }

  async function doAboutUpdate() {
    aboutShowVpnWarn = false;
    aboutUpdating = true;
    try {
      if (onInstall) await onInstall();
    } finally {
      aboutUpdating = false;
    }
  }

  let activeTab = 'general';
  let settings = {
    language: getLanguage(),
    theme: 'system',
    auto_start: false,
    kill_switch: false,
    dns_protection: false,
    health_check: false,
    pin_interface: false,
    log_level: 'info',
    tray_icon_style: 'color',
    wifi_rules: {
      enabled: false,
      trusted_ssids: [],
      per_tunnel: {},
    },
  };
  $: tunnelNames = ($tunnels || []).map(t => t.name);
  let loaded = false;
  let appVersion = '';

  async function load() {
    try {
      const s = await TunnelService.GetSettings();
      if (s) {
        settings.language = s.language || 'auto';
        settings.theme = s.theme || 'system';
        settings.auto_start = s.auto_start ?? false;
        settings.kill_switch = s.kill_switch ?? false;
        settings.dns_protection = s.dns_protection ?? false;
        settings.health_check = s.health_check ?? false;
        settings.pin_interface = s.pin_interface ?? false;
        settings.log_level = s.log_level || 'info';
        settings.tray_icon_style = s.tray_icon_style || 'color';
        if (s.wifi_rules) {
          settings.wifi_rules = {
            enabled: s.wifi_rules.enabled ?? false,
            trusted_ssids: s.wifi_rules.trusted_ssids || [],
            per_tunnel: s.wifi_rules.per_tunnel || {},
          };
        }
      }
    } catch (e) {
      console.error('load settings:', e);
    }
    loaded = true;
  }
  load();

  async function save() {
    // Re-fetch the freshest settings.json before writing so per-tunnel
    // wifi rule edits made in TunnelDetail (which calls SaveSettings
    // independently with its own modified per_tunnel map) aren't
    // silently overwritten by our stale snapshot. We own the global
    // wifi_rules fields (enabled, trusted_ssids); per_tunnel is owned
    // by TunnelDetail, so we merge the disk's value forward.
    let perTunnel = settings.wifi_rules?.per_tunnel || {};
    try {
      const fresh = await TunnelService.GetSettings();
      if (fresh?.wifi_rules?.per_tunnel) {
        perTunnel = fresh.wifi_rules.per_tunnel;
      }
    } catch (_) {
      // Best-effort merge; fall back to our last-known per_tunnel.
    }
    try {
      await TunnelService.SaveSettings({
        language: settings.language,
        theme: settings.theme,
        tray_icon_style: settings.tray_icon_style,
        auto_start: settings.auto_start,
        kill_switch: settings.kill_switch,
        dns_protection: settings.dns_protection,
        health_check: settings.health_check,
        pin_interface: settings.pin_interface,
        log_level: settings.log_level,
        wifi_rules: {
          enabled: settings.wifi_rules?.enabled ?? false,
          trusted_ssids: settings.wifi_rules?.trusted_ssids || [],
          per_tunnel: perTunnel,
        },
      });
    } catch (e) {
      console.error('save settings:', e);
    }
  }

  let saveTimer = null;
  function scheduleSave() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveTimer = null;
      save();
    }, 300);
  }

  function onThemeChange(e) {
    settings.theme = e.target.value;
    applyTheme(settings.theme);
    scheduleSave();
  }

  function onLanguageChange(e) {
    settings.language = e.target.value;
    const resolved = settings.language === 'auto' ? detectLanguage() : settings.language;
    setLanguage(resolved);
    scheduleSave();
  }

  function onAutoStartChange(e) {
    settings.auto_start = e.target.checked;
    scheduleSave();
  }

  function onLogLevelChange(e) {
    settings.log_level = e.target.value;
    TunnelService.SetLogLevel(settings.log_level).catch((err) => {
      console.error('SetLogLevel failed:', err);
    });
    scheduleSave();
  }

  function onKillSwitchChange(e) {
    settings.kill_switch = e.target.checked;
    if ($connectionStatus?.state === 'connected') {
      TunnelService.SetKillSwitch(settings.kill_switch).catch((err) => {
        console.error('SetKillSwitch failed:', err);
        settings.kill_switch = !settings.kill_switch;
      });
    }
    scheduleSave();
  }

  function onDnsProtectionChange(e) {
    settings.dns_protection = e.target.checked;
    if ($connectionStatus?.state === 'connected') {
      TunnelService.SetDNSProtection(settings.dns_protection).catch((err) => {
        console.error('SetDNSProtection failed:', err);
        settings.dns_protection = !settings.dns_protection;
      });
    }
    scheduleSave();
  }

  function onPinInterfaceChange(e) {
    settings.pin_interface = e.target.checked;
    TunnelService.SetPinInterface(settings.pin_interface).catch((err) => {
      console.error('SetPinInterface failed:', err);
      settings.pin_interface = !settings.pin_interface;
    });
    scheduleSave();
  }

  function onHealthCheckChange(e) {
    settings.health_check = e.target.checked;
    TunnelService.SetHealthCheck(settings.health_check).catch((err) => {
      console.error('SetHealthCheck failed:', err);
      settings.health_check = !settings.health_check;
    });
    scheduleSave();
  }

  onDestroy(() => {
    window.removeEventListener('keydown', onKeyDown);
    if (saveTimer) {
      clearTimeout(saveTimer);
      save();
    }
  });

  function stopEvent(e) { e.stopPropagation(); }

  function handleBackdropMousedown(e) {
    if (e.target === e.currentTarget) close();
  }

  function close() {
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = null;
      save();
    }
    onClose();
  }

  function onKeyDown(e) {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    }
  }

  // Register the listener synchronously and tear it down via
  // onDestroy. An `onMount(async ...)` callback returns a Promise,
  // not a cleanup function, so the cleanup we used to put after the
  // `await` was silently dropped — every Settings open leaked another
  // window-level keydown listener that called save() on stale state.
  onMount(() => {
    window.addEventListener('keydown', onKeyDown);
    (async () => {
      try { appVersion = await TunnelService.GetVersion(); } catch (_) {}
    })();
  });
</script>

<div class="modal-backdrop" on:mousedown={handleBackdropMousedown}>
  <div class="modal" on:mousedown={stopEvent} role="dialog" aria-modal="true" aria-labelledby="settings-title">
    <h3 id="settings-title">{$t('settings.title')}</h3>

    <div class="settings-layout">
      <nav class="settings-sidebar" role="tablist" aria-label="Settings sections">
        <button role="tab" aria-selected={activeTab === 'general'} class:active={activeTab === 'general'} on:click={() => activeTab = 'general'}>
          {$t('settings.general')}
        </button>
        <button role="tab" aria-selected={activeTab === 'advanced'} class:active={activeTab === 'advanced'} on:click={() => activeTab = 'advanced'}>
          {$t('settings.advanced')}
        </button>
        <button role="tab" aria-selected={activeTab === 'wifi_rules'} class:active={activeTab === 'wifi_rules'} on:click={() => activeTab = 'wifi_rules'}>
          {$t('settings.wifi_rules')}
        </button>
        <button role="tab" aria-selected={activeTab === 'about'} class:active={activeTab === 'about'} on:click={() => activeTab = 'about'}>
          {$t('settings.about')}
        </button>
      </nav>

      <div class="settings-content" role="tabpanel">
        {#if activeTab === 'general'}
          <div class="setting-row">
            <label for="theme-select">{$t('settings.theme')}</label>
            <select id="theme-select" value={settings.theme} on:change={onThemeChange}>
              <option value="dark">{$t('settings.theme_dark')}</option>
              <option value="light">{$t('settings.theme_light')}</option>
              <option value="system">{$t('settings.theme_system')}</option>
            </select>
          </div>

          <div class="setting-row">
            <label for="lang-select">{$t('settings.language')}</label>
            <select id="lang-select" value={settings.language} on:change={onLanguageChange}>
              <option value="auto">{$t('settings.lang_auto')}</option>
              <option value="en">English</option>
              <option value="ko">한국어</option>
              <option value="ja">日本語</option>
            </select>
          </div>

          <div class="setting-row">
            <label for="auto-start">{$t('settings.auto_start')}</label>
            <input id="auto-start" type="checkbox" checked={settings.auto_start} on:change={onAutoStartChange} />
          </div>

        {:else if activeTab === 'advanced'}
          <div class="setting-row">
            <label for="log-level">{$t('settings.log_level')}</label>
            <select id="log-level" value={settings.log_level} on:change={onLogLevelChange}>
              <option value="debug">{$t('settings.log_level_debug')}</option>
              <option value="info">{$t('settings.log_level_info')}</option>
              <option value="warn">{$t('settings.log_level_warn')}</option>
              <option value="error">{$t('settings.log_level_error')}</option>
            </select>
          </div>

          <div class="setting-row">
            <label for="kill-switch">{$t('settings.kill_switch')}</label>
            <input id="kill-switch" type="checkbox"
              checked={settings.kill_switch}
              on:change={onKillSwitchChange} />
          </div>
          <p class="setting-hint">{$t('settings.kill_switch_hint')}</p>

          <div class="setting-row">
            <label for="dns-protection">{$t('settings.dns_protection')}</label>
            <input id="dns-protection" type="checkbox"
              checked={settings.dns_protection}
              on:change={onDnsProtectionChange} />
          </div>
          <p class="setting-hint">{$t('settings.dns_protection_hint')}</p>

          <div class="setting-row">
            <label for="health-check">{$t('settings.health_check')}</label>
            <input id="health-check" type="checkbox"
              checked={settings.health_check}
              on:change={onHealthCheckChange} />
          </div>
          <p class="setting-hint">{$t('settings.health_check_hint')}</p>

          <div class="setting-row">
            <label for="pin-interface">{$t('settings.pin_interface')}</label>
            <input id="pin-interface" type="checkbox"
              checked={settings.pin_interface}
              on:change={onPinInterfaceChange} />
          </div>
          <p class="setting-hint">{$t('settings.pin_interface_hint')}</p>

        {:else if activeTab === 'wifi_rules'}
          <WifiRules
            rules={settings.wifi_rules}
            on:change={(e) => { settings.wifi_rules = e.detail; scheduleSave(); }} />

        {:else if activeTab === 'about'}
          <div class="about-section">
            <div class="about-header">
              <img src="/appicon.png" alt="WireGuide" class="about-icon" />
              <div>
                <div class="about-name">WireGuide</div>
                <div class="about-version-row">
                  <span class="about-version">{appVersion ? `v${appVersion}` : ''}</span>
                  {#if updateInfo?.available}
                    <span class="update-dot"></span>
                    <span class="update-badge">{$t('update.available', { version: updateInfo.version })}</span>
                    <button class="link-btn" on:click={aboutRequestUpdate} disabled={aboutUpdating}>
                      {aboutUpdating ? $t('update.updating') : $t('update.update_now')}
                    </button>
                  {:else}
                    <span class="about-uptodate">— {$t('settings.up_to_date')}</span>
                  {/if}
                </div>
              </div>
            </div>

            <p class="about-desc">{$t('settings.about_desc')}</p>

            {#if aboutShowVpnWarn}
              <div class="about-vpn-warn">
                <p>{$t('update.vpn_warning')}</p>
                <div class="about-warn-actions">
                  <button class="link-btn" on:click={doAboutUpdate}>{$t('update.proceed')}</button>
                  <button class="link-btn" on:click={() => aboutShowVpnWarn = false}>{$t('update.cancel')}</button>
                </div>
              </div>
            {/if}

            <div class="about-links">
              <button class="link-btn" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1/wireguide')}>GitHub</button>
              <button class="link-btn" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1/wireguide/issues')}>{$t('settings.about_issues')}</button>
              <button class="link-btn" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1/wireguide/blob/main/LICENSE')}>{$t('settings.about_license')}</button>
            </div>
          </div>
        {/if}
      </div>
    </div>

    <div class="modal-footer">
      <button type="button" class="btn-close" on:mousedown|stopPropagation={close}>{$t('settings.close')}</button>
    </div>
  </div>
</div>

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }
  @media (prefers-color-scheme: dark) {
    .modal-backdrop { background: rgba(0,0,0,0.55); }
  }
  .modal {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px 12px;
    width: 520px;
    box-shadow: var(--shadow-md, 0 4px 12px rgba(0,0,0,0.12), 0 16px 48px rgba(0,0,0,0.08));
  }
  h3 {
    margin: 0 0 16px;
    font: 600 15px/20px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
    letter-spacing: -0.005em;
  }

  /* Split layout */
  .settings-layout {
    display: flex;
    gap: 16px;
    height: 320px;
  }

  /* Sidebar */
  .settings-sidebar {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 100px;
    border-right: 0.5px solid var(--border);
    padding-right: 12px;
  }
  .settings-sidebar button {
    display: flex;
    align-items: center;
    padding: 6px 8px;
    background: none;
    border: none;
    border-radius: 4px;
    color: var(--text-secondary);
    font: 500 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
    text-align: left;
    min-height: 28px;
  }
  .settings-sidebar button:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .settings-sidebar button.active {
    background: var(--bg-selected, rgba(0,122,255,0.10));
    color: var(--text-primary);
    font-weight: 600;
  }
  .settings-sidebar button:focus,
  .settings-sidebar button:focus-visible {
    outline: none;
  }

  /* Content */
  .settings-content {
    flex: 1;
    min-width: 0;
    overflow-y: auto;
  }

  .setting-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 4px 0;
    min-height: 28px;
  }
  label {
    font: 400 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
  }
  .setting-hint {
    margin: 2px 0 8px;
    padding: 0;
    font: 400 11px/14px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    letter-spacing: 0.02em;
  }
  select {
    -webkit-appearance: none;
    appearance: none;
    height: 28px;
    padding: 0 28px 0 12px;
    background-color: var(--bg-input);
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%233C3C43' stroke-opacity='.56' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 9px center;
    border: 1px solid rgba(60, 60, 67, 0.5);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 13px;
    font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
  }
  :global([data-theme="dark"]) select {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%23FFFFFF' stroke-opacity='.55' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
    border-color: rgba(84, 84, 88, 0.72);
  }
  select:hover {
    background-color: var(--bg-hover);
  }
  select:focus,
  select:focus-visible {
    outline: none;
    box-shadow: none;
  }
  input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: var(--green, #34C759);
    min-width: 16px;
  }
  input[type="checkbox"]:focus,
  input[type="checkbox"]:focus-visible {
    outline: none;
    box-shadow: none;
  }

  /* About tab */
  .about-section {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .about-header {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .about-icon {
    width: 48px;
    height: 48px;
    border-radius: 10px;
  }
  .about-name {
    font: 600 15px/20px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
  }
  .about-version-row {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .about-version {
    font: 400 11px/14px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
  }
  .about-divider {
    border: none;
    border-top: 0.5px solid var(--border);
    margin: 8px 0;
  }
  .about-desc {
    font: 400 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    margin: 0;
  }
  .about-links {
    display: flex;
    gap: 16px;
  }
  .update-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent, #007AFF);
  }
  .update-badge {
    font: 500 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--accent, #007AFF);
  }
  .about-uptodate {
    font: 400 11px/14px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
  }
  .about-vpn-warn {
    background: var(--bg-secondary, #F5F5F7);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 8px;
  }
  .about-vpn-warn p {
    font: 400 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-secondary);
    margin: 0 0 6px;
  }
  .about-warn-actions {
    display: flex;
    gap: 12px;
  }
  .link-btn {
    font: 400 12px/16px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--accent, #007AFF);
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
  }
  .link-btn:hover { text-decoration: underline; }
  .link-btn:disabled { opacity: 0.5; cursor: wait; text-decoration: none; }
  .link-btn:focus,
  .link-btn:focus-visible {
    outline: none;
  }

  /* Footer */
  .modal-footer {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    margin-top: 16px;
    padding-top: 12px;
    border-top: 0.5px solid var(--border);
  }
  .btn-close {
    min-width: 72px;
    height: 28px;
    padding: 0 16px;
    background: var(--accent, #007AFF);
    color: var(--text-inverse, #fff);
    border: 0;
    border-radius: 6px;
    font: 500 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
  }
  .btn-close:hover { filter: brightness(1.08); }
  .btn-close:active { filter: brightness(0.94); }
  .btn-close:focus,
  .btn-close:focus-visible {
    outline: none;
  }

  @media (prefers-reduced-motion: no-preference) {
    .settings-sidebar button {
      transition: background-color 120ms cubic-bezier(0.2, 0, 0.1, 1),
                  color 120ms cubic-bezier(0.2, 0, 0.1, 1);
    }
    .btn-close {
      transition: filter 120ms cubic-bezier(0.2, 0, 0.1, 1);
    }
  }
</style>

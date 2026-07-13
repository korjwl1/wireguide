<script>
  import { onDestroy, onMount } from 'svelte';
  import { t, setLanguage, getLanguage, detectLanguage } from '../i18n/index.js';
  import { applyTheme } from '../stores/theme.js';
  import { connectionStatus, tunnels } from '../stores/tunnels.js';
  import { compactList } from '../stores/ui.js';
  import WifiRules from './WifiRules.svelte';
  import Icon from './Icon.svelte';

  export let TunnelService;
  export let onClose = () => {};
  export let updateInfo = null;
  export let onInstall = null;

  let aboutUpdating = false;
  let aboutShowVpnWarn = false;
  // updateState mirrors UpdateState DTO from GetUpdateState. Used by the
  // About tab to show last-checked timestamp + brew detection + an
  // explicit "Check now" button (the launch-only check we used to do
  // could leave About showing "up to date" for days after a release).
  let updateState = null;
  let aboutChecking = false;
  let aboutCheckResult = '';
  // nowTick drives formatLastChecked re-evaluation. Without this, opening
  // Settings and leaving it on the About tab for 10 minutes would still
  // show "just now". Updated every 60 s by an interval started in
  // onMount and torn down in onDestroy.
  let nowTick = Date.now();
  let nowTimer = null;

  async function refreshUpdateState() {
    try { updateState = await TunnelService.GetUpdateState(); } catch (_) {}
  }

  // Last *attempted* manual check, including failures — used to throttle
  // rapid-click. Distinct from updateState.last_check_unix which only
  // tracks *successful* checks (the scheduler's contract).
  let lastManualCheckMs = 0;
  const MANUAL_CHECK_MIN_INTERVAL_MS = 5000;

  async function aboutCheckNow() {
    if (aboutChecking) return;
    // Rate-limit guard. Without this, holding-down "Check now" sends a
    // request per response-time interval (~few hundred ms) and burns the
    // 60-req/hour anonymous GitHub quota for everyone behind the same
    // public IP. The 5 s floor lines up with what a frustrated human can
    // tolerate; a programmatic caller will hit it harmlessly.
    const now = Date.now();
    if (now - lastManualCheckMs < MANUAL_CHECK_MIN_INTERVAL_MS) {
      return;
    }
    lastManualCheckMs = now;
    aboutChecking = true;
    aboutCheckResult = '';
    try {
      const info = await TunnelService.CheckForUpdate();
      await refreshUpdateState();
      if (info?.available) {
        // New version found: the green "up to date" pill flips to the
        // "Update" pill automatically (driven by `updateInfo`), so the
        // pill itself is the success indicator — no extra result line.
        // updateInfo is always declared (export let updateInfo = null);
        // assigning here mutates the prop so the parent's binding sees it.
        updateInfo = info;
      }
      // Up-to-date result is *not* mirrored to aboutCheckResult on
      // purpose: the pill already says "최신 버전입니다", and adding a
      // second identical message below the row causes the UI to shift
      // every time the user clicks "Check now". The "Last checked"
      // timestamp flipping to "just now" is the silent feedback that
      // the click actually did something.
    } catch (e) {
      aboutCheckResult = ($t('update.check_failed') || 'Check failed') + ': ' + (e?.message || e);
    } finally {
      aboutChecking = false;
    }
  }

  // `_tick` parameter forces Svelte to re-run this whenever nowTick
  // changes (every 60 s). Without it, Svelte couldn't tell the result
  // depends on time and would cache the first evaluation forever.
  function formatLastChecked(unix, _tick) {
    if (!unix) {
      // First-launch placeholder: when auto-check is on and the scheduler
      // hasn't fired its first tick yet (30–120 s after startup), show
      // a "scheduled" hint instead of the misleading "Never checked".
      // Dev builds never schedule, so they still get "Never checked".
      if (updateState?.auto_enabled && !updateState?.is_dev_build) {
        return $t('update.first_check_scheduled');
      }
      return $t('update.never_checked');
    }
    const diff = Math.max(0, Date.now() / 1000 - unix);
    let time;
    if (diff < 60) {
      time = $t('update.time_just_now');
    } else if (diff < 3600) {
      time = $t('update.time_minutes_ago', { n: Math.floor(diff / 60) });
    } else if (diff < 86400) {
      time = $t('update.time_hours_ago', { n: Math.floor(diff / 3600) });
    } else {
      time = $t('update.time_days_ago', { n: Math.floor(diff / 86400) });
    }
    return $t('update.last_checked', { time });
  }


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
    auto_update_check: true,
    compact_list: false,
    wifi_rules: {
      trusted_ssids: [],
      per_tunnel: {},
    },
  };
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
        settings.compact_list = s.compact_list ?? false;
        // Legacy settings.json predates this field — *bool null on
        // the Go side becomes undefined here; default to true to match
        // Settings.AutoUpdateCheckEnabled() semantics.
        settings.auto_update_check = (s.auto_update_check === false) ? false : true;
        if (s.wifi_rules) {
          settings.wifi_rules = {
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
    // silently overwritten. We own only `trusted_ssids` in wifi_rules;
    // `per_tunnel` belongs to TunnelDetail. If the fresh fetch fails
    // (helper restarting, IPC flake) we abort rather than write our
    // potentially-stale per_tunnel snapshot — a deferred save is far
    // better than clobbering the user's per-tunnel edits.
    let fresh;
    try {
      fresh = await TunnelService.GetSettings();
    } catch (e) {
      console.warn('settings save aborted: fresh fetch failed (will retry on next change)', e);
      return;
    }
    const perTunnel = fresh?.wifi_rules?.per_tunnel || {};
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
        auto_update_check: settings.auto_update_check,
        compact_list: settings.compact_list,
        // List-ordering prefs are owned by the tunnel-list header, not
        // this screen — carry them from the fresh fetch so saving any
        // Settings toggle doesn't wipe them back to defaults.
        list_sort: fresh?.list_sort || 'name_asc',
        list_active_on_top: fresh?.list_active_on_top ?? true,
        wifi_rules: {
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

  function onCompactListChange(e) {
    settings.compact_list = e.target.checked;
    // Update the shared store so the tunnel list re-renders immediately,
    // then persist.
    compactList.set(settings.compact_list);
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
    // Always forward to the helper, regardless of connection state.
    // The previous `if connected` gate meant that toggling off while
    // the tunnel was already disconnected updated settings.json but
    // left the WFP filters in place — internet stayed blocked until
    // a reboot. The helper itself decides what to do based on its
    // current tunnel set.
    settings.kill_switch = e.target.checked;
    TunnelService.SetKillSwitch(settings.kill_switch).catch((err) => {
      console.error('SetKillSwitch failed:', err);
      settings.kill_switch = !settings.kill_switch;
    });
    scheduleSave();
  }

  function onDnsProtectionChange(e) {
    // Same rationale as the kill-switch toggle: always send the IPC so
    // that a "disable while disconnected" doesn't leave stale WFP
    // DNS block filters in place.
    settings.dns_protection = e.target.checked;
    TunnelService.SetDNSProtection(settings.dns_protection).catch((err) => {
      console.error('SetDNSProtection failed:', err);
      settings.dns_protection = !settings.dns_protection;
    });
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
    if (nowTimer) clearInterval(nowTimer);
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
    // 60 s tick so the "Last checked Nm ago" line keeps current while
    // the Settings modal is open. Cleanup is in onDestroy above.
    nowTimer = setInterval(() => { nowTick = Date.now(); }, 60000);
    (async () => {
      try { appVersion = await TunnelService.GetVersion(); } catch (_) {}
      await refreshUpdateState();
    })();
  });
</script>

<div class="modal-backdrop" on:mousedown={handleBackdropMousedown}>
  <div class="modal" on:mousedown={stopEvent} role="dialog" aria-modal="true" aria-labelledby="settings-title">
    <h3 id="settings-title">{$t('settings.title')}</h3>

    <div class="settings-layout">
      <nav class="settings-sidebar" role="tablist" aria-label="Settings sections">
        <button role="tab" aria-selected={activeTab === 'general'} class:active={activeTab === 'general'} on:click={() => activeTab = 'general'}>
          <Icon name="settings" size={14} strokeWidth={1.75} />
          <span>{$t('settings.general')}</span>
        </button>
        <button role="tab" aria-selected={activeTab === 'advanced'} class:active={activeTab === 'advanced'} on:click={() => activeTab = 'advanced'}>
          <Icon name="wrench" size={14} strokeWidth={1.75} />
          <span>{$t('settings.advanced')}</span>
        </button>
        <button role="tab" aria-selected={activeTab === 'wifi_rules'} class:active={activeTab === 'wifi_rules'} on:click={() => activeTab = 'wifi_rules'}>
          <Icon name="wifi" size={14} strokeWidth={1.75} />
          <span>{$t('settings.wifi_rules')}</span>
        </button>
        <button role="tab" aria-selected={activeTab === 'about'} class:active={activeTab === 'about'} on:click={() => activeTab = 'about'}>
          <Icon name="info" size={14} strokeWidth={1.75} />
          <span>{$t('settings.about')}</span>
        </button>
      </nav>

      <div class="settings-content" role="tabpanel">
        {#if activeTab === 'general'}
          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_appearance')}</h4>
            <div class="settings-card">
              <div class="setting-row">
                <label class="setting-label" for="theme-select">{$t('settings.theme')}</label>
                <select id="theme-select" value={settings.theme} on:change={onThemeChange}>
                  <option value="dark">{$t('settings.theme_dark')}</option>
                  <option value="light">{$t('settings.theme_light')}</option>
                  <option value="system">{$t('settings.theme_system')}</option>
                </select>
              </div>
              <div class="setting-row">
                <label class="setting-label" for="lang-select">{$t('settings.language')}</label>
                <select id="lang-select" value={settings.language} on:change={onLanguageChange}>
                  <option value="auto">{$t('settings.lang_auto')}</option>
                  <option value="en">English</option>
                  <option value="ko">한국어</option>
                  <option value="ja">日本語</option>
                </select>
              </div>
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="compact-list">{$t('settings.compact_list')}</label>
                  <p class="setting-desc">{$t('settings.compact_list_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="compact-list" type="checkbox" checked={settings.compact_list} on:change={onCompactListChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_startup')}</h4>
            <div class="settings-card">
              <div class="setting-row">
                <label class="setting-label" for="auto-start">{$t('settings.auto_start')}</label>
                <label class="toggle">
                  <input id="auto-start" type="checkbox" checked={settings.auto_start} on:change={onAutoStartChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_updates')}</h4>
            <div class="settings-card">
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="auto-update">{$t('settings.auto_update_check')}</label>
                  <p class="setting-desc">{$t('settings.auto_update_check_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="auto-update" type="checkbox" bind:checked={settings.auto_update_check} on:change={scheduleSave} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

        {:else if activeTab === 'advanced'}
          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_security')}</h4>
            <div class="settings-card">
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="kill-switch">{$t('settings.kill_switch')}</label>
                  <p class="setting-desc">{$t('settings.kill_switch_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="kill-switch" type="checkbox"
                    checked={settings.kill_switch}
                    on:change={onKillSwitchChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="dns-protection">{$t('settings.dns_protection')}</label>
                  <p class="setting-desc">{$t('settings.dns_protection_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="dns-protection" type="checkbox"
                    checked={settings.dns_protection}
                    on:change={onDnsProtectionChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_connection')}</h4>
            <div class="settings-card">
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="health-check">{$t('settings.health_check')}</label>
                  <p class="setting-desc">{$t('settings.health_check_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="health-check" type="checkbox"
                    checked={settings.health_check}
                    on:change={onHealthCheckChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
              <div class="setting-row setting-row--toggle">
                <div class="setting-info">
                  <label class="setting-label" for="pin-interface">{$t('settings.pin_interface')}</label>
                  <p class="setting-desc">{$t('settings.pin_interface_hint')}</p>
                </div>
                <label class="toggle">
                  <input id="pin-interface" type="checkbox"
                    checked={settings.pin_interface}
                    on:change={onPinInterfaceChange} />
                  <span class="toggle-track"></span>
                </label>
              </div>
            </div>
          </div>

          <div class="settings-section">
            <h4 class="section-title">{$t('settings.section_logging')}</h4>
            <div class="settings-card">
              <div class="setting-row">
                <label class="setting-label" for="log-level">{$t('settings.log_level')}</label>
                <select id="log-level" value={settings.log_level} on:change={onLogLevelChange}>
                  <option value="debug">{$t('settings.log_level_debug')}</option>
                  <option value="info">{$t('settings.log_level_info')}</option>
                  <option value="warn">{$t('settings.log_level_warn')}</option>
                  <option value="error">{$t('settings.log_level_error')}</option>
                </select>
              </div>
            </div>
          </div>

        {:else if activeTab === 'wifi_rules'}
          <WifiRules
            rules={settings.wifi_rules}
            {TunnelService}
            on:change={(e) => { settings.wifi_rules = e.detail; scheduleSave(); }} />

        {:else if activeTab === 'about'}
          <div class="about-tab">
            <div class="about-hero">
              <img src="/wireguide.svg" alt="WireGuide" class="about-logo" />
              <div class="about-hero-text">
                <h2 class="about-name">WireGuide</h2>
                <p class="about-tagline-text">{$t('settings.about_tagline')}</p>
                <div class="about-pills">
                  <span class="pill pill-version">{appVersion ? `v${appVersion}` : 'v—'}</span>
                  {#if updateInfo?.available}
                    <button class="pill pill-update" on:click={aboutRequestUpdate} disabled={aboutUpdating}>
                      <span class="pill-dot"></span>
                      {aboutUpdating ? $t('update.updating') : $t('update.update_now')}
                    </button>
                  {:else}
                    <span class="pill pill-ok">
                      <Icon name="check" size={11} strokeWidth={2.5} />
                      {$t('settings.up_to_date')}
                    </span>
                  {/if}
                </div>
                <div class="about-check-row">
                  <button class="check-btn" on:click={aboutCheckNow} disabled={aboutChecking}>
                    {aboutChecking ? $t('update.checking') : $t('update.check_now')}
                  </button>
                  <span class="check-meta">{formatLastChecked(updateState?.last_check_unix, nowTick)}</span>
                </div>
                {#if updateState?.is_dev_build}
                  <!-- Explains why "Never checked" sticks even on a healthy install:
                       dev builds intentionally skip the auto-check loop so local
                       iteration doesn't burn the GitHub API quota. Manual button
                       still works, hence the "use the button" framing. -->
                  <div class="check-hint">{$t('update.dev_build_hint')}</div>
                {:else if updateState && !updateState.auto_enabled}
                  <div class="check-hint">{$t('update.auto_off_hint')}</div>
                {/if}
                {#if aboutCheckResult}
                  <div class="check-result">{aboutCheckResult}</div>
                {/if}
              </div>
            </div>

            <p class="about-desc-paragraph">{$t('settings.about_desc')}</p>

            {#if aboutShowVpnWarn}
              <div class="about-vpn-warn">
                <Icon name="triangle-alert" size={16} strokeWidth={2} />
                <div class="vpn-warn-body">
                  <p>{$t('update.vpn_warning')}</p>
                  <div class="vpn-warn-actions">
                    <button class="warn-btn warn-proceed" on:click={doAboutUpdate}>{$t('update.proceed')}</button>
                    <button class="warn-btn warn-cancel" on:click={() => aboutShowVpnWarn = false}>{$t('update.cancel')}</button>
                  </div>
                </div>
              </div>
            {/if}

            <div class="about-links">
              <button class="link-btn" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1/wireguide')}>GitHub</button>
              <button class="link-btn" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1/wireguide/releases')}>{$t('settings.about_releases')}</button>
              <button class="link-btn" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1/wireguide/issues')}>{$t('settings.about_issues')}</button>
              <button class="link-btn" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1/wireguide/blob/main/LICENSE')}>{$t('settings.about_license')}</button>
            </div>

            <p class="about-credits-line">{$t('settings.about_credits')}</p>
          </div>
        {/if}
      </div>
    </div>

    <div class="modal-footer">
      <div class="footer-info">
        <span class="footer-credit-label">{$t('settings.about_made_by')}</span>
        <button class="footer-link" on:click={() => TunnelService.OpenURL('https://github.com/korjwl1')}>@korjwl1</button>
        <span class="footer-sep">·</span>
        <span class="footer-credit-text">{$t('settings.about_footer_copyright')}</span>
      </div>
      <button type="button" class="btn-close" on:mousedown|stopPropagation={close}>{$t('settings.close')}</button>
    </div>
  </div>
</div>

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg, rgba(0,0,0,0.45));
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }
  .modal {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: 14px;
    padding: 20px 22px 14px;
    width: 720px;
    height: 520px;
    display: flex;
    flex-direction: column;
    box-shadow: var(--shadow-lg);
    overflow: hidden;
    box-sizing: border-box;
  }
  h3 {
    margin: 0 0 14px;
    font: 700 16px/22px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
    letter-spacing: -0.01em;
    flex-shrink: 0;
  }

  /* Split layout — fixed height with internal scroll */
  .settings-layout {
    display: flex;
    gap: 16px;
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }

  /* Sidebar — sits on the same modal surface as the content area.
     No background panel, no border. Visual hierarchy comes from
     the active tab item's own fill + content-area structure
     (Linear / Notion / macOS System Settings pattern). */
  .settings-sidebar {
    display: flex;
    flex-direction: column;
    gap: 2px;
    width: 148px;
    flex-shrink: 0;
    padding: 0 6px 0 0;
    overflow-y: auto;
  }
  .settings-sidebar button {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 8px 10px;
    background: none;
    border: none;
    border-radius: 8px;
    color: var(--text-secondary);
    font: 500 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    cursor: pointer;
    text-align: left;
    min-height: 34px;
    width: 100%;
    letter-spacing: -0.005em;
  }
  .settings-sidebar button :global(.icon) {
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .settings-sidebar button:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .settings-sidebar button:hover :global(.icon) {
    color: var(--text-primary);
  }
  /* Active state: neutral gray fill + bold primary text + accent ICON.
     macOS HIG sidebar pattern — only the icon carries brand color,
     the row itself stays calm so the user's eye lands on content,
     not the active nav row. */
  .settings-sidebar button.active {
    background: var(--bg-active);
    color: var(--text-primary);
    font-weight: 600;
  }
  .settings-sidebar button.active :global(.icon) {
    color: var(--accent);
  }
  .settings-sidebar button:focus,
  .settings-sidebar button:focus-visible {
    outline: none;
  }
  @media (prefers-reduced-motion: no-preference) {
    .settings-sidebar button {
      transition: background-color 140ms ease, color 140ms ease;
    }
  }

  /* Content area — independent scroll */
  .settings-content {
    flex: 1;
    min-width: 0;
    overflow-y: auto;
    padding-right: 4px;
  }
  .settings-content::-webkit-scrollbar { width: 8px; }
  .settings-content::-webkit-scrollbar-track { background: transparent; }
  .settings-content::-webkit-scrollbar-thumb {
    background-color: color-mix(in srgb, var(--text-muted) 40%, transparent);
    border-radius: 4px;
    border: 2px solid transparent;
    background-clip: content-box;
  }
  .settings-content::-webkit-scrollbar-thumb:hover {
    background-color: var(--text-muted);
  }

  /* ---- Section + Card layout (M3 / iOS Settings style) ---- */
  .settings-section {
    margin-bottom: var(--space-4, 12px);
  }
  .section-title {
    margin: 0 0 6px var(--space-1, 4px);
    font: 500 10px/13px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .settings-card {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }

  /* Setting rows inside cards — spacing alone separates (no hairlines).
     The card surface itself is the grouping cue (Linear / Notion pattern). */
  .setting-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 11px 14px;
    gap: var(--space-3);
  }
  .setting-row + .setting-row {
    padding-top: 3px;
  }
  .setting-row--toggle {
    align-items: flex-start;
    padding: 12px 14px;
  }
  .setting-row--toggle + .setting-row--toggle {
    padding-top: 4px;
  }
  .setting-info {
    flex: 1;
    min-width: 0;
  }
  .setting-label {
    display: block;
    font: 400 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-primary);
    cursor: pointer;
  }
  .setting-desc {
    margin: 3px 0 0;
    padding: 0;
    font: 400 11px/15px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-muted);
    letter-spacing: 0.01em;
  }

  /* ---- Toggle switch (34×20px, 200ms slide) ---- */
  .toggle {
    position: relative;
    display: inline-block;
    width: 34px;
    height: 20px;
    flex-shrink: 0;
    cursor: pointer;
    margin-top: 1px;
  }
  .toggle input {
    opacity: 0;
    width: 0;
    height: 0;
    position: absolute;
  }
  .toggle-track {
    position: absolute;
    inset: 0;
    background: color-mix(in srgb, var(--text-muted) 35%, var(--bg-input));
    border-radius: 10px;
    border: 0.5px solid color-mix(in srgb, var(--border) 60%, transparent);
  }
  .toggle-track::before {
    content: '';
    position: absolute;
    width: 16px;
    height: 16px;
    left: 2px;
    top: 2px;
    background: #fff;
    border-radius: 50%;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.25);
  }
  @media (prefers-reduced-motion: no-preference) {
    .toggle-track {
      transition: background-color 200ms ease, border-color 200ms ease;
    }
    .toggle-track::before {
      transition: transform 200ms ease;
    }
  }
  .toggle input:checked + .toggle-track {
    background: var(--green);
    border-color: var(--green);
  }
  .toggle input:checked + .toggle-track::before {
    transform: translateX(14px);
  }
  .toggle input:focus-visible + .toggle-track {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
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

  /* ========== About tab — redesigned ========== */
  .about-tab {
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .about-hero {
    display: flex;
    align-items: center;
    gap: 18px;
    padding: 4px 0 4px;
  }
  .about-logo {
    width: 64px;
    height: 64px;
    flex-shrink: 0;
    filter: drop-shadow(0 4px 12px color-mix(in srgb, var(--accent) 28%, transparent));
  }
  .about-hero-text {
    flex: 1;
    min-width: 0;
  }
  .about-name {
    margin: 0;
    font: 700 22px/28px var(--font-sans);
    color: var(--text-primary);
    letter-spacing: -0.02em;
  }
  .about-tagline-text {
    margin: 2px 0 10px;
    font: 500 13px/18px var(--font-sans);
    color: var(--text-secondary);
    letter-spacing: -0.005em;
  }
  .about-pills {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font: 600 11px/14px var(--font-sans);
    padding: 4px 10px;
    border-radius: 999px;
    letter-spacing: 0.02em;
  }
  .pill-version {
    color: var(--text-secondary);
    background: color-mix(in srgb, var(--text-muted) 18%, transparent);
    font-feature-settings: "tnum";
  }
  .pill-ok {
    color: var(--green);
    background: color-mix(in srgb, var(--green) 16%, transparent);
  }
  .pill-update {
    color: #fff;
    background: var(--accent);
    border: 0;
    cursor: pointer;
    box-shadow: 0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
                0 1px 2px rgba(0,0,0,0.08);
  }
  @media (prefers-reduced-motion: no-preference) {
    .pill-update { transition: background-color 140ms ease, transform 140ms ease, box-shadow 140ms ease; }
  }
  .pill-update:hover:not(:disabled) {
    background: color-mix(in srgb, #fff 8%, var(--accent));
    transform: translateY(-1px);
  }
  .pill-update:disabled { opacity: 0.65; cursor: wait; }

  .about-check-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 8px;
  }
  .check-btn {
    height: 24px;
    padding: 0 10px;
    font: 500 11px/14px var(--font-sans);
    color: var(--text-primary);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
  }
  .check-btn:hover:not(:disabled) { background: var(--bg-hover); }
  .check-btn:disabled { opacity: 0.6; cursor: wait; }
  .check-meta {
    font: 400 11px/14px var(--font-sans);
    color: var(--text-secondary);
    font-feature-settings: "tnum";
  }
  .check-result {
    margin-top: 6px;
    font: 400 11px/15px var(--font-sans);
    color: var(--text-secondary);
  }
  .check-hint {
    margin-top: 6px;
    font: 400 11px/15px var(--font-sans);
    color: var(--text-muted, var(--text-secondary));
    font-style: italic;
  }
  .pill-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #fff;
  }

  .about-desc-paragraph {
    margin: 18px 0 16px;
    font: 13px/20px var(--font-sans);
    color: var(--text-secondary);
    letter-spacing: -0.005em;
  }

  /* VPN warn inline alert card */
  .about-vpn-warn {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    background: color-mix(in srgb, var(--orange, #FF9500) 10%, var(--bg-card));
    border: 0.5px solid color-mix(in srgb, var(--orange, #FF9500) 35%, var(--border));
    border-radius: 10px;
    padding: 12px 14px;
    margin-bottom: 14px;
    color: var(--orange, #FF9500);
  }
  .vpn-warn-body {
    flex: 1;
    min-width: 0;
  }
  .about-vpn-warn p {
    margin: 0 0 8px;
    font: 12px/16px var(--font-sans);
    color: var(--text-primary);
  }
  .vpn-warn-actions {
    display: flex;
    gap: 8px;
  }
  .warn-btn {
    height: 26px;
    padding: 0 12px;
    border: 0;
    border-radius: 7px;
    font: 600 11px/14px var(--font-sans);
    cursor: pointer;
  }
  .warn-proceed {
    background: var(--orange, #FF9500);
    color: #fff;
  }
  .warn-cancel {
    background: transparent;
    color: var(--text-secondary);
  }
  .warn-cancel:hover { background: var(--bg-hover); }

  /* Simple text-link row (original style — restored). */
  .about-links {
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    margin-bottom: 18px;
  }
  .link-btn {
    font: 500 12px/16px var(--font-sans);
    color: var(--accent);
    background: none;
    border: 0;
    padding: 0;
    cursor: pointer;
    letter-spacing: -0.005em;
  }
  .link-btn:hover { text-decoration: underline; }
  .link-btn:disabled { opacity: 0.5; cursor: wait; text-decoration: none; }
  .link-btn:focus, .link-btn:focus-visible { outline: none; }

  /* Quiet credit line at the very bottom of the About tab. */
  .about-credits-line {
    margin: 4px 0 0;
    font: 11px/15px var(--font-sans);
    color: var(--text-muted);
  }

  /* ========== Modal footer — credits row + close button on one line ==========
     The credit info shows in every tab now (not just About) — persistent
     identity reminder. justify-content: space-between pins the credit
     block to the left and the close button to the right. */
  .modal-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    margin-top: 14px;
    padding-top: 4px;
    flex-shrink: 0;
  }
  .footer-info {
    display: flex;
    align-items: baseline;
    gap: 5px;
    flex-wrap: wrap;
    min-width: 0;
    font: 11px/15px var(--font-sans);
    color: var(--text-muted);
    letter-spacing: 0.01em;
  }
  .footer-credit-label,
  .footer-credit-text { color: var(--text-muted); }
  .footer-sep { opacity: 0.55; }
  .footer-link {
    background: none;
    border: 0;
    padding: 0;
    cursor: pointer;
    font: inherit;
    color: var(--accent);
    letter-spacing: -0.005em;
  }
  .footer-link:hover { text-decoration: underline; }
  .footer-link:focus, .footer-link:focus-visible { outline: none; }
  .btn-close {
    min-width: 84px;
    height: 32px;
    padding: 0 18px;
    background: var(--accent);
    color: #fff;
    border: 0;
    border-radius: 10px;
    font: 600 13px/18px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    letter-spacing: -0.005em;
    cursor: pointer;
    box-shadow:
      0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
      0 1px 2px rgba(0,0,0,0.08);
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn-close {
      transition: background-color 140ms ease, box-shadow 140ms ease, transform 140ms ease;
    }
  }
  .btn-close:hover {
    background: color-mix(in srgb, #fff 8%, var(--accent));
    transform: translateY(-1px);
    box-shadow:
      0 4px 10px color-mix(in srgb, var(--accent) 30%, transparent),
      0 1px 2px rgba(0,0,0,0.10);
  }
  .btn-close:active { background: color-mix(in srgb, #000 8%, var(--accent)); transform: translateY(0); }
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

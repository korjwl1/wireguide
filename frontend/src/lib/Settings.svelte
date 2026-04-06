<script>
  import { onDestroy, onMount } from 'svelte';
  import { t, setLanguage, getLanguage, detectLanguage } from '../i18n/index.js';
  import { applyTheme } from '../stores/theme.js';
  import { connectionStatus } from '../stores/tunnels.js';

  export let TunnelService;
  // Prop callback instead of createEventDispatcher. Dispatcher requires the
  // parent to wire `on:close={...}`, and earlier builds had a subtle bug
  // where clicks on custom buttons in the modal weren't reaching the parent
  // handler (while <select>/<input> native controls still worked). Passing
  // onClose as a plain prop sidesteps the dispatcher entirely — the button
  // just calls the parent's state mutator directly.
  export let onClose = () => {};


  // Field names here match the Go JSON tags on storage.Settings exactly.
  // The Wails binding generator uses the JSON tags (snake_case), not the
  // Go struct field names — using PascalCase here previously meant theme
  // changes never persisted across restarts.
  let settings = {
    language: getLanguage(),
    theme: 'system',
    auto_start: false,
    kill_switch: false,
    dns_protection: false,
    log_level: 'info',
    tray_icon_style: 'color',
  };
  let loaded = false;

  async function load() {
    try {
      const s = await TunnelService.GetSettings();
      if (s) {
        settings.language = s.language || 'auto';
        settings.theme = s.theme || 'system';
        settings.auto_start = s.auto_start ?? false;
        settings.kill_switch = s.kill_switch ?? false;
        settings.dns_protection = s.dns_protection ?? false;
        settings.log_level = s.log_level || 'info';
        settings.tray_icon_style = s.tray_icon_style || 'color';
      }
    } catch (e) {
      console.error('load settings:', e);
    }
    loaded = true;
  }
  load();

  async function save() {
    try {
      await TunnelService.SaveSettings({
        language: settings.language,
        theme: settings.theme,
        tray_icon_style: settings.tray_icon_style,
        auto_start: settings.auto_start,
        kill_switch: settings.kill_switch,
        dns_protection: settings.dns_protection,
        log_level: settings.log_level,
      });
    } catch (e) {
      console.error('save settings:', e);
    }
  }

  // Debounced save: toggling several checkboxes in quick succession should
  // result in ONE write, not N writes. 300ms feels instant yet collapses
  // the typical click burst.
  let saveTimer = null;
  function scheduleSave() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveTimer = null;
      save();
    }, 300);
  }

  // Explicit handlers instead of `$:` reactive blocks. The reactive
  // approach depended on Svelte tracking settings.<field> writes via
  // bind:value, which turned out to be unreliable inside a nested modal
  // component — theme/language changes weren't propagating to applyTheme
  // at all. With on:change handlers the flow is dead simple: user picks
  // an option → we mutate the local state, immediately apply the side
  // effect, and schedule the debounced save.
  function onThemeChange(e) {
    settings.theme = e.target.value;
    applyTheme(settings.theme);
    scheduleSave();
  }

  function onLanguageChange(e) {
    settings.language = e.target.value;
    // 'auto' means "follow the OS locale" — resolve it to a concrete
    // language and push that to the locale store, otherwise picking Auto
    // would leave the store at whatever language was set before (the bug
    // the user just hit: picking Auto did nothing).
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
    // Push log level IMMEDIATELY, not via debounced save — user is
    // probably switching to Debug because they're diagnosing something
    // right now; a 300ms delay drops the records they care about.
    TunnelService.SetLogLevel(settings.log_level).catch((err) => {
      console.error('SetLogLevel failed:', err);
    });
    scheduleSave();
  }

  function onKillSwitchChange(e) {
    settings.kill_switch = e.target.checked;
    // Save the preference only. Actual activation happens automatically
    // when VPN connects (handled in App.svelte's connect flow).
    // If VPN is currently connected, apply immediately too.
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

  // Ensure a pending save is flushed before the modal closes. Otherwise
  // quickly toggling and immediately clicking close could lose the last write.
  onDestroy(() => {
    if (saveTimer) {
      clearTimeout(saveTimer);
      save();
    }
  });

  function stopEvent(e) {
    e.stopPropagation();
  }

  function handleBackdropMousedown(e) {
    // Only close if the press landed directly on the backdrop, not on
    // something that bubbled up from inside the modal. Using mousedown
    // instead of click so the handler fires before any native form
    // control can swallow the event.
    if (e.target === e.currentTarget) {
      close();
    }
  }

  function close() {
    // Flush any pending debounced save before closing so the last change
    // isn't lost. save() is async but we don't need to await — the IPC
    // round-trip can finish after the modal is gone.
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = null;
      save();
    }
    onClose();
  }

  // ESC to close — standard modal affordance. Window-level listener so it
  // works regardless of which element currently holds focus (selects etc.).
  function onKeyDown(e) {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    }
  }
  onMount(() => {
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  });
</script>

<!-- Backdrop click closes; inner modal stops propagation via a concrete
     handler (not a modifier-only on:click, which has been flaky in some
     Svelte compile paths). -->
<div class="modal-backdrop" on:mousedown={handleBackdropMousedown}>
  <div class="modal" on:mousedown={stopEvent} role="dialog" aria-modal="true" aria-labelledby="settings-title">
    <h3 id="settings-title">{$t('settings.title')}</h3>

    <section>
      <h4>{$t('settings.general')}</h4>

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
    </section>

    <section>
      <h4>{$t('settings.advanced')}</h4>

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
    </section>

    <div class="modal-footer">
      <button type="button" class="btn-close" on:mousedown|stopPropagation={close}>{$t('settings.close')}</button>
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
    z-index: 200;
  }
  .modal {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px 24px;
    width: 420px;
    max-height: 80vh;
    overflow-y: auto;
  }
  h3 {
    margin: 0 0 16px;
    font-size: 16px;
    font-weight: 600;
  }
  .modal-footer {
    display: flex;
    justify-content: flex-end;
    margin-top: 20px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
  }
  /* Explicit padding/size — the global `button { padding: 0 }` reset is
   * only beaten by class specificity, so we make sure this button has a
   * real hit area regardless. */
  .btn-close {
    min-width: 80px;
    height: 32px;
    padding: 0 18px;
    background: var(--accent);
    color: var(--text-inverse);
    border: 0;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }
  .btn-close:hover { opacity: 0.9; }
  section { margin-bottom: 20px; }
  section:last-of-type { margin-bottom: 0; }
  h4 {
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 0 0 8px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--border);
  }
  .setting-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 0;
  }
  label { font-size: 13px; color: var(--text-primary); }
  .setting-hint {
    margin: 4px 0 0;
    padding: 0;
    font-size: 11px;
    color: var(--text-secondary);
    line-height: 1.4;
  }
  select {
    padding: 4px 8px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-primary);
    font-size: 13px;
  }
  input[type="checkbox"] {
    width: 18px;
    height: 18px;
    accent-color: var(--green);
  }
</style>

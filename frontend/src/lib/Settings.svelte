<script>
  import { createEventDispatcher } from 'svelte';
  import { t, setLanguage, getLanguage } from '../i18n/index.js';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  let settings = {
    language: getLanguage(),
    theme: 'system',
    autoReconnect: true,
    killSwitch: false,
    dnsProtection: false,
    logLevel: 'info',
    autoStart: false,
  };
  let loaded = false;

  async function load() {
    try {
      const s = await TunnelService.GetSettings();
      if (s) {
        settings.language = s.Language || 'auto';
        settings.theme = s.Theme || 'system';
        settings.autoReconnect = s.AutoReconnect ?? true;
        settings.killSwitch = s.KillSwitch ?? false;
        settings.dnsProtection = s.DNSProtection ?? false;
        settings.logLevel = s.LogLevel || 'info';
      }
    } catch (e) {
      console.error('load settings:', e);
    }
    loaded = true;
  }
  load();

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  async function save() {
    try {
      await TunnelService.SaveSettings({
        Language: settings.language,
        Theme: settings.theme,
        TrayIconStyle: 'color',
        AutoReconnect: settings.autoReconnect,
        KillSwitch: settings.killSwitch,
        DNSProtection: settings.dnsProtection,
        LogLevel: settings.logLevel,
      });
    } catch (e) {
      console.error('save settings:', e);
    }
  }

  // Reactive: apply theme whenever it changes
  $: applyTheme(settings.theme);

  // Reactive: set language + save whenever settings change (after initial load)
  $: if (loaded) {
    if (settings.language && settings.language !== 'auto') {
      setLanguage(settings.language);
    }
    save();
  }

  function close() {
    dispatch('close');
  }
</script>

<div class="modal-backdrop" on:click={close}>
  <div class="modal" on:click|stopPropagation>
    <h3>{t('settings.title')}</h3>

    <section>
      <h4>{t('settings.general')}</h4>

      <div class="setting-row">
        <label>{t('settings.theme')}</label>
        <select bind:value={settings.theme}>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
          <option value="system">System</option>
        </select>
      </div>

      <div class="setting-row">
        <label>{t('settings.language')}</label>
        <select bind:value={settings.language}>
          <option value="auto">Auto</option>
          <option value="en">English</option>
          <option value="ko">한국어</option>
          <option value="ja">日本語</option>
        </select>
      </div>

      <div class="setting-row">
        <label>{t('settings.auto_start')}</label>
        <input type="checkbox" bind:checked={settings.autoStart} />
      </div>
    </section>

    <section>
      <h4>{t('settings.connection')}</h4>

      <div class="setting-row">
        <label>{t('settings.auto_reconnect')}</label>
        <input type="checkbox" bind:checked={settings.autoReconnect} />
      </div>
    </section>

    <section>
      <h4>{t('settings.advanced')}</h4>

      <div class="setting-row">
        <label>{t('settings.log_level')}</label>
        <select bind:value={settings.logLevel}>
          <option value="debug">Debug</option>
          <option value="info">Info</option>
          <option value="warn">Warn</option>
          <option value="error">Error</option>
        </select>
      </div>
    </section>

    <div class="modal-footer">
      <button class="btn btn-close" on:click={close}>OK</button>
    </div>
  </div>
</div>

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }
  .modal {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    width: 400px;
    max-height: 80vh;
    overflow-y: auto;
  }
  h3 { margin-bottom: 16px; }
  section { margin-bottom: 16px; }
  h4 {
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--border);
  }
  .setting-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 0;
  }
  label { font-size: 14px; }
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
  .modal-footer {
    display: flex;
    justify-content: flex-end;
    margin-top: 16px;
  }
  .btn-close {
    padding: 8px 24px;
    background: var(--accent);
    border: none;
    border-radius: 6px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 13px;
  }
  .btn-close:hover { opacity: 0.9; }
</style>

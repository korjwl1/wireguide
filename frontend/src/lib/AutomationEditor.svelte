<script>
  // Per-tunnel Automation rule editor (issue #12). Each rule is an
  // ordered condition→action: on a matching network the tunnel is
  // connected or disconnected. Connect and disconnect conditions are set
  // independently (just add rules with the action you want). Persisted to
  // Settings.automation.per_tunnel_rules[tunnelName]; the whole settings
  // object is re-fetched and spread on save so other screens' edits (and
  // other tunnels' rules) are never clobbered.
  import Icon from './Icon.svelte';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';
  import SSIDPermissionBanner from './SSIDPermissionBanner.svelte';

  export let TunnelService;
  export let tunnelName = '';
  export let open = false;

  let rules = [];
  let loadedFor = '';
  let knownSSIDs = [];
  let currentSSID = '';
  let currentSubnets = [];
  let saveError = '';

  // Reload whenever the modal opens for a (possibly different) tunnel.
  $: if (open && tunnelName && loadedFor !== tunnelName) {
    load(tunnelName);
  }

  async function load(name) {
    loadedFor = name;
    saveError = '';
    try {
      const s = await TunnelService.GetSettings();
      const per = s?.automation?.per_tunnel_rules || {};
      // Deep-copy so edits don't mutate the fetched object before save.
      rules = (per[name] || []).map(r => ({
        when: { type: r.when?.type || 'ssid', ssid: r.when?.ssid || '', subnet: r.when?.subnet || '' },
        do: r.do || 'connect',
      }));
    } catch (e) {
      rules = [];
      console.error('automation load:', e);
    }
    try {
      const r = await TunnelService.GetKnownSSIDs();
      knownSSIDs = r?.known || [];
      currentSSID = r?.current || '';
    } catch (_) {}
    try {
      currentSubnets = (await TunnelService.GetCurrentSubnets()) || [];
    } catch (_) { currentSubnets = []; }
  }

  function addRule() {
    rules = [...rules, { when: { type: 'ssid', ssid: '', subnet: '' }, do: 'connect' }];
  }
  function removeRule(i) {
    rules = rules.filter((_, idx) => idx !== i);
    save();
  }

  // Drop rules whose condition has no value (an empty ssid/subnet would
  // never match and just clutters the set) before persisting.
  function cleaned() {
    return rules.filter(r => {
      if (r.when.type === 'none_match') return true;
      if (r.when.type === 'ssid') return r.when.ssid.trim() !== '';
      if (r.when.type === 'subnet') return r.when.subnet.trim() !== '';
      return false;
    }).map(r => ({
      when: r.when.type === 'ssid'
        ? { type: 'ssid', ssid: r.when.ssid.trim() }
        : r.when.type === 'subnet'
          ? { type: 'subnet', subnet: r.when.subnet.trim() }
          : { type: 'none_match' },
      do: r.do,
    }));
  }

  let saveTimer = null;
  function save() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(doSave, 300);
  }
  async function doSave() {
    saveTimer = null;
    saveError = '';
    const name = tunnelName;
    try {
      const s = await TunnelService.GetSettings();
      const automation = s?.automation || { per_tunnel_rules: {} };
      automation.per_tunnel_rules = automation.per_tunnel_rules || {};
      const c = cleaned();
      if (c.length === 0) {
        delete automation.per_tunnel_rules[name];
      } else {
        automation.per_tunnel_rules[name] = c;
      }
      await TunnelService.SaveSettings({ ...s, automation });
    } catch (e) {
      saveError = errText(e);
      console.error('automation save:', e);
    }
  }

  function close() {
    open = false;
    loadedFor = '';
  }
</script>

{#if open}
  <div class="am-backdrop" on:click={close}>
    <div class="am-dialog" on:click|stopPropagation role="dialog" aria-modal="true" aria-label={$t('automation.title')}>
      <div class="am-header">
        <div class="am-icon"><Icon name="wifi" size={18} strokeWidth={2} /></div>
        <div class="am-header-text">
          <h3>{$t('automation.title')}</h3>
          <p class="am-sub">{tunnelName}</p>
        </div>
        <button class="am-close" on:click={close} aria-label="Close"><Icon name="x" size={16} strokeWidth={2} /></button>
      </div>
      <p class="am-hint">{$t('automation.hint')}</p>

      <SSIDPermissionBanner {TunnelService} />

      <div class="am-rules">
        {#if rules.length === 0}
          <div class="am-empty">{$t('automation.empty')}</div>
        {:else}
          {#each rules as rule, i}
            <div class="am-rule">
              <select class="am-do" bind:value={rule.do} on:change={save} aria-label={$t('automation.action')}>
                <option value="connect">{$t('automation.connect')}</option>
                <option value="disconnect">{$t('automation.disconnect')}</option>
              </select>
              <span class="am-when">{$t('automation.when')}</span>
              <select class="am-type" bind:value={rule.when.type} on:change={save} aria-label={$t('automation.condition')}>
                <option value="ssid">{$t('automation.cond_ssid')}</option>
                <option value="subnet">{$t('automation.cond_subnet')}</option>
                <option value="none_match">{$t('automation.cond_none')}</option>
              </select>
              {#if rule.when.type === 'ssid'}
                <input
                  class="am-val"
                  list="am-ssid-list"
                  placeholder={currentSSID || $t('automation.ssid_placeholder')}
                  bind:value={rule.when.ssid}
                  on:input={save} on:change={save} />
              {:else if rule.when.type === 'subnet'}
                <input
                  class="am-val"
                  list="am-subnet-list"
                  placeholder={currentSubnets[0] || '10.0.0.0/24'}
                  bind:value={rule.when.subnet}
                  on:input={save} on:change={save} />
              {:else}
                <span class="am-val am-val-none">{$t('automation.cond_none_desc')}</span>
              {/if}
              <button class="am-remove" on:click={() => removeRule(i)} aria-label="remove rule"><Icon name="x" size={12} strokeWidth={2} /></button>
            </div>
          {/each}
        {/if}
      </div>

      <datalist id="am-ssid-list">
        {#each knownSSIDs as s}<option value={s}></option>{/each}
      </datalist>
      <datalist id="am-subnet-list">
        {#each currentSubnets as sn}<option value={sn}>{$t('automation.subnet_current')}</option>{/each}
      </datalist>

      {#if saveError}<div class="am-error">{saveError}</div>{/if}

      <button class="am-add" on:click={addRule}>
        <Icon name="plus" size={13} strokeWidth={2.25} /> {$t('automation.add_rule')}
      </button>
    </div>
  </div>
{/if}

<style>
  .am-backdrop {
    position: fixed; inset: 0; z-index: 1000;
    background: color-mix(in srgb, #000 45%, transparent);
    display: flex; align-items: center; justify-content: center;
    padding: 24px;
  }
  .am-dialog {
    width: 100%; max-width: 560px; max-height: 80vh; overflow-y: auto;
    background: var(--bg-elevated, var(--bg-secondary));
    border: 1px solid var(--border);
    border-radius: 14px; padding: 20px;
    box-shadow: 0 16px 48px rgba(0,0,0,0.35);
  }
  .am-header { display: flex; align-items: center; gap: 12px; }
  .am-icon {
    width: 36px; height: 36px; border-radius: 9px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    background: color-mix(in srgb, var(--accent) 15%, transparent);
    color: var(--accent);
  }
  .am-header-text { flex: 1; min-width: 0; }
  .am-header-text h3 { margin: 0; font: 600 15px/1.2 var(--font-sans); color: var(--text-primary); }
  .am-sub { margin: 2px 0 0; font: 400 12px/1.2 var(--font-mono); color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .am-close { background: transparent; border: 0; color: var(--text-muted); cursor: pointer; padding: 4px; border-radius: 6px; }
  .am-close:hover { background: var(--bg-hover); color: var(--text-primary); }
  .am-hint { margin: 12px 0; font: 400 12px/1.5 var(--font-sans); color: var(--text-secondary); }
  .am-rules { display: flex; flex-direction: column; gap: 8px; margin: 8px 0; }
  .am-empty { padding: 16px; text-align: center; font: 400 12px var(--font-sans); color: var(--text-muted); border: 1px dashed var(--border); border-radius: 8px; }
  .am-rule { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .am-rule select, .am-rule input {
    font: 400 12px var(--font-sans); color: var(--text-primary);
    background: var(--bg-primary); border: 1px solid var(--border);
    border-radius: 7px; padding: 5px 7px;
  }
  .am-do { font-weight: 600; }
  .am-when { font: 400 11px var(--font-sans); color: var(--text-muted); }
  .am-val { flex: 1; min-width: 120px; }
  .am-val-none { color: var(--text-muted); border: 0 !important; background: transparent !important; }
  .am-remove { background: transparent; border: 0; color: var(--text-muted); cursor: pointer; padding: 4px; border-radius: 6px; flex-shrink: 0; }
  .am-remove:hover { background: color-mix(in srgb, var(--red, #ff3b30) 18%, transparent); color: var(--red, #ff3b30); }
  .am-add {
    display: inline-flex; align-items: center; gap: 6px; margin-top: 10px;
    font: 500 12px var(--font-sans); color: var(--accent);
    background: transparent; border: 1px dashed color-mix(in srgb, var(--accent) 45%, transparent);
    border-radius: 8px; padding: 7px 12px; cursor: pointer;
  }
  .am-add:hover { background: color-mix(in srgb, var(--accent) 10%, transparent); }
  .am-error { margin-top: 8px; font: 400 12px var(--font-sans); color: var(--error-text, #ff453a); }
</style>

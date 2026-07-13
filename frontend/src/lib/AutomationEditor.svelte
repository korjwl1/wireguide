<script>
  // Per-tunnel Automation rule editor (issue #12). Each rule is an
  // ordered condition→action: on a matching network the tunnel is
  // connected or disconnected. Connect and disconnect conditions are set
  // independently (just add rules with the action you want). Persisted to
  // Settings.automation.per_tunnel_rules[tunnelName]; the whole settings
  // object is re-fetched and spread on save so other screens' edits (and
  // other tunnels' rules) are never clobbered.
  import { afterUpdate } from 'svelte';
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
  let currentSubnets = [];      // autocomplete suggestions for the subnet field
  let currentGatewayMAC = '';   // autocomplete suggestion for the MAC field
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
        when: {
          type: r.when?.type || 'network',
          ssid: r.when?.ssid || '',
          subnet: r.when?.subnet || '',
          gateway_mac: r.when?.gateway_mac || '',
        },
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
    try {
      currentGatewayMAC = (await TunnelService.GetCurrentNetwork())?.gateway_mac || '';
    } catch (_) { currentGatewayMAC = ''; }
  }

  const MAX_RULES = 50;
  function addRule() {
    if (rules.length >= MAX_RULES) return;
    rules = [...rules, { when: { type: 'network', ssid: '', subnet: '', gateway_mac: '' }, do: 'connect' }];
    save();
  }

  function removeRule(i) {
    rules = rules.filter((_, idx) => idx !== i);
    save();
  }

  // Lightweight format validation for user feedback. The engine is
  // already safe against garbage (a bad CIDR / MAC simply never matches,
  // never panics, never reaches a shell), but without this a malformed
  // value would save and silently never fire — so mark it invalid so the
  // user can fix it. Empty is "incomplete", not "invalid".
  // A MAC is valid in any common style — colon, dash, or no separator —
  // as long as it reduces to exactly 12 hex digits. The engine compares
  // canonically (separator/case-insensitive), and we normalise on commit.
  function macHex(v) { return (v || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase(); }
  function macInvalid(v) { const s = (v || '').trim(); return s !== '' && macHex(s).length !== 12; }
  // Canonical form: lower-case, colon-separated (b0:38:6c:54:8b:ab).
  function macCanon(v) {
    const h = macHex(v);
    if (h.length !== 12) return (v || '').trim(); // leave as-is so the user can keep fixing
    return h.match(/.{2}/g).join(':');
  }
  function onMacChange(rule) {
    rule.when.gateway_mac = macCanon(rule.when.gateway_mac);
    rules = rules;
    save();
  }
  function cidrInvalid(v) {
    const s = (v || '').trim();
    if (s === '') return false;
    const m = s.match(/^([^/]+)\/(\d{1,3})$/);
    if (!m) return true;
    const prefix = Number(m[2]);
    const ip = m[1];
    if (ip.includes(':')) return prefix < 0 || prefix > 128; // IPv6 — trust the notation
    const octets = ip.split('.');
    if (octets.length !== 4) return true;
    if (octets.some(o => o === '' || !/^\d+$/.test(o) || Number(o) > 255)) return true;
    return prefix < 0 || prefix > 32;
  }

  // Drag-to-reorder with LIVE reordering: as the cursor passes over
  // another row the list re-sorts in real time (the standard sortable-
  // list feel), the dragged row is dimmed, and the browser's drag image
  // is the whole row. Rule order IS priority — the engine applies the
  // first matching rule (top wins) — so this both reorders and re-prioritises.
  let dragIndex = null;
  function onDragStart(e, i) {
    dragIndex = i;
    e.dataTransfer.effectAllowed = 'move';
    try { e.dataTransfer.setData('text/plain', String(i)); } catch (_) {}
    // Ghost = the full row (drag starts from the handle, so inputs stay usable).
    const row = e.currentTarget.closest('.am-rule');
    if (row) {
      try { e.dataTransfer.setDragImage(row, 24, row.offsetHeight / 2); } catch (_) {}
    }
  }
  function onRowDragOver(e, i) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragIndex === null || dragIndex === i) return;
    // Move the dragged item to this row's position, live.
    const arr = [...rules];
    const [moved] = arr.splice(dragIndex, 1);
    arr.splice(i, 0, moved);
    rules = arr;
    dragIndex = i;
  }
  function onDragEnd() {
    if (dragIndex !== null) { dragIndex = null; save(); }
  }

  // Scroll affordance: show a fade at the top/bottom of the rule list
  // only when there's hidden content in that direction, so it's obvious
  // the list scrolls. Recomputed after every render and on scroll.
  let rulesEl;
  let canScrollUp = false;
  let canScrollDown = false;
  function updateScroll() {
    if (!rulesEl) return;
    canScrollUp = rulesEl.scrollTop > 2;
    canScrollDown = rulesEl.scrollTop + rulesEl.clientHeight < rulesEl.scrollHeight - 2;
  }
  afterUpdate(updateScroll);

  // Drop rules whose condition has no value before persisting.
  function cleaned() {
    return rules.filter(r => {
      if (r.when.type === 'none_match') return true;
      if (r.when.type === 'ssid') return r.when.ssid.trim() !== '';
      if (r.when.type === 'subnet') return r.when.subnet.trim() !== '';
      if (r.when.type === 'network') return r.when.gateway_mac.trim() !== '';
      return false;
    }).map(r => {
      let when;
      if (r.when.type === 'ssid') when = { type: 'ssid', ssid: r.when.ssid.trim() };
      else if (r.when.type === 'subnet') when = { type: 'subnet', subnet: r.when.subnet.trim() };
      else if (r.when.type === 'network') when = { type: 'network', gateway_mac: macCanon(r.when.gateway_mac) };
      else when = { type: 'none_match' };
      return { when, do: r.do };
    });
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

      <div class="am-rules-wrap">
        <div class="am-fade am-fade-top" class:show={canScrollUp}>
          <span class="am-chevron am-chevron-up"><Icon name="chevron-down" size={15} strokeWidth={2.5} /></span>
        </div>
        <div class="am-rules" bind:this={rulesEl} on:scroll={updateScroll}>
        {#if rules.length === 0}
          <div class="am-empty">{$t('automation.empty')}</div>
        {:else}
          {#each rules as rule, i (rule)}
            <div class="am-rule" class:am-dragging={dragIndex === i}
              on:dragover={(e) => onRowDragOver(e, i)}
              on:dragend={onDragEnd}>
              <span class="am-handle" draggable="true" title={$t('automation.drag_hint')}
                on:dragstart={(e) => onDragStart(e, i)}>⋮⋮</span>
              <span class="am-priority">{i + 1}</span>
              <select class="am-do" bind:value={rule.do} on:change={save} aria-label={$t('automation.action')}>
                <option value="connect">{$t('automation.connect')}</option>
                <option value="disconnect">{$t('automation.disconnect')}</option>
              </select>
              <span class="am-when">{$t('automation.when')}</span>
              <select class="am-type" bind:value={rule.when.type} on:change={save} aria-label={$t('automation.condition')}>
                <option value="network">{$t('automation.cond_network')}</option>
                <option value="subnet">{$t('automation.cond_subnet')}</option>
                <option value="ssid">{$t('automation.cond_ssid')}</option>
                <option value="none_match">{$t('automation.cond_none')}</option>
              </select>
              {#if rule.when.type === 'network'}
                <input
                  class="am-val" class:am-invalid={macInvalid(rule.when.gateway_mac)}
                  list="am-mac-list"
                  placeholder={currentGatewayMAC || $t('automation.mac_placeholder')}
                  title={macInvalid(rule.when.gateway_mac) ? $t('automation.mac_invalid') : ''}
                  bind:value={rule.when.gateway_mac}
                  on:input={save} on:change={() => onMacChange(rule)} />
              {:else if rule.when.type === 'subnet'}
                <input
                  class="am-val" class:am-invalid={cidrInvalid(rule.when.subnet)}
                  list="am-subnet-list"
                  placeholder={currentSubnets[0] || '192.168.0.0/24'}
                  title={cidrInvalid(rule.when.subnet) ? $t('automation.subnet_invalid') : ''}
                  bind:value={rule.when.subnet}
                  on:input={save} on:change={save} />
              {:else if rule.when.type === 'ssid'}
                <input
                  class="am-val"
                  list="am-ssid-list"
                  placeholder={currentSSID || $t('automation.ssid_placeholder')}
                  bind:value={rule.when.ssid}
                  on:input={save} on:change={save} />
              {:else}
                <span class="am-val am-val-none">{$t('automation.cond_none_desc')}</span>
              {/if}
              <button class="am-remove" on:click={() => removeRule(i)} aria-label="remove rule"><Icon name="x" size={12} strokeWidth={2} /></button>
            </div>
          {/each}
        {/if}
        </div>
        <div class="am-fade am-fade-bottom" class:show={canScrollDown}>
          <span class="am-chevron"><Icon name="chevron-down" size={15} strokeWidth={2.5} /></span>
        </div>
      </div>

      <datalist id="am-ssid-list">
        {#each knownSSIDs as s}<option value={s}></option>{/each}
      </datalist>
      <datalist id="am-subnet-list">
        {#each currentSubnets as sn}<option value={sn}></option>{/each}
      </datalist>
      <datalist id="am-mac-list">
        {#if currentGatewayMAC}<option value={currentGatewayMAC}></option>{/if}
      </datalist>

      {#if saveError}<div class="am-error">{saveError}</div>{/if}

      <button class="am-add" on:click={addRule} disabled={rules.length >= MAX_RULES}>
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
    /* Fixed size — the dialog never grows/shrinks with the rule count.
       Rules scroll inside .am-rules; a few rules just leave empty space. */
    width: 100%; max-width: 560px; height: 540px; max-height: 88vh;
    display: flex; flex-direction: column;
    background: var(--bg-elevated, var(--bg-secondary));
    border: 1px solid var(--border);
    border-radius: 14px; padding: 20px;
    box-shadow: 0 16px 48px rgba(0,0,0,0.35);
  }
  .am-header { display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
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
  .am-hint { margin: 12px 0; font: 400 12px/1.5 var(--font-sans); color: var(--text-secondary); flex-shrink: 0; }
  /* The one scrolling region: fills the space between the fixed header
     and the fixed add-button, so the dialog stays a constant size. The
     wrap hosts the top/bottom scroll-affordance fades. */
  .am-rules-wrap { flex: 1; min-height: 0; position: relative; display: flex; }
  .am-rules { flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; margin: 4px 0; padding-right: 4px; }
  .am-fade {
    position: absolute; left: 0; right: 4px; height: 52px; pointer-events: none;
    opacity: 0; z-index: 2;
    display: flex; justify-content: center;
  }
  @media (prefers-reduced-motion: no-preference) {
    .am-fade { transition: opacity 140ms ease; }
    .am-chevron { animation: am-bob 1.4s ease-in-out infinite; }
  }
  .am-fade.show { opacity: 1; }
  /* Stronger, taller gradient — stays near-solid at the edge so hidden
     rows are clearly cut off, not just barely tinted. */
  .am-fade-top {
    top: 0; align-items: flex-start; padding-top: 2px;
    background: linear-gradient(to bottom,
      var(--bg-elevated, var(--bg-secondary)) 0%,
      color-mix(in srgb, var(--bg-elevated, var(--bg-secondary)) 88%, transparent) 45%,
      transparent 100%);
  }
  .am-fade-bottom {
    bottom: 0; align-items: flex-end; padding-bottom: 2px;
    background: linear-gradient(to top,
      var(--bg-elevated, var(--bg-secondary)) 0%,
      color-mix(in srgb, var(--bg-elevated, var(--bg-secondary)) 88%, transparent) 45%,
      transparent 100%);
  }
  .am-chevron { color: var(--accent); display: inline-flex; }
  .am-chevron-up { transform: rotate(180deg); }
  @keyframes am-bob {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(3px); }
  }
  .am-chevron-up { animation: am-bob-up 1.4s ease-in-out infinite; }
  @keyframes am-bob-up {
    0%, 100% { transform: rotate(180deg) translateY(0); }
    50% { transform: rotate(180deg) translateY(3px); }
  }
  .am-empty { padding: 16px; text-align: center; font: 400 12px var(--font-sans); color: var(--text-muted); border: 1px dashed var(--border); border-radius: 8px; }
  .am-rule {
    display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
    padding: 6px; border: 1px solid transparent; border-radius: 9px;
  }
  .am-rule.am-dragging { opacity: 0.35; }
  @media (prefers-reduced-motion: no-preference) {
    .am-rule { transition: opacity 120ms ease; }
  }
  .am-handle {
    cursor: grab; color: var(--text-muted); font: 700 12px/1 var(--font-sans);
    letter-spacing: -2px; padding: 0 2px; user-select: none; flex-shrink: 0;
  }
  .am-handle:active { cursor: grabbing; }
  .am-priority {
    flex-shrink: 0; width: 18px; height: 18px; border-radius: 50%;
    display: inline-flex; align-items: center; justify-content: center;
    font: 600 10px var(--font-sans); color: var(--text-secondary);
    background: color-mix(in srgb, var(--text-muted) 18%, transparent);
  }
  .am-rule select, .am-rule input {
    font: 400 12px var(--font-sans); color: var(--text-primary);
    background: var(--bg-primary); border: 1px solid var(--border);
    border-radius: 7px; padding: 5px 7px;
  }
  .am-do { font-weight: 600; }
  .am-when { font: 400 11px var(--font-sans); color: var(--text-muted); }
  .am-val { flex: 1; min-width: 120px; }
  .am-val-none { color: var(--text-muted); border: 0 !important; background: transparent !important; }
  .am-rule input.am-invalid {
    border-color: var(--error-text, #ff453a);
    background: color-mix(in srgb, var(--error-text, #ff453a) 8%, var(--bg-primary));
  }
  .am-val-network { flex: 1; min-width: 120px; display: inline-flex; align-items: baseline; gap: 6px; font: 400 12px var(--font-sans); color: var(--text-primary); }
  .am-mac { font: 400 10px var(--font-mono); color: var(--text-muted); }
  .am-usecurrent {
    font: 500 11px var(--font-sans); color: var(--accent);
    background: color-mix(in srgb, var(--accent) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
    border-radius: 7px; padding: 4px 9px; cursor: pointer; flex-shrink: 0; white-space: nowrap;
  }
  .am-usecurrent:hover { background: color-mix(in srgb, var(--accent) 18%, transparent); }
  .am-remove { background: transparent; border: 0; color: var(--text-muted); cursor: pointer; padding: 4px; border-radius: 6px; flex-shrink: 0; }
  .am-remove:hover { background: color-mix(in srgb, var(--red, #ff3b30) 18%, transparent); color: var(--red, #ff3b30); }
  .am-add {
    display: inline-flex; align-self: flex-start; align-items: center; gap: 6px;
    margin-top: 12px; flex-shrink: 0;
    font: 500 12px var(--font-sans); color: var(--accent);
    background: transparent; border: 1px dashed color-mix(in srgb, var(--accent) 45%, transparent);
    border-radius: 8px; padding: 7px 12px; cursor: pointer;
  }
  .am-add:hover:not(:disabled) { background: color-mix(in srgb, var(--accent) 10%, transparent); }
  .am-add:disabled { opacity: 0.45; cursor: not-allowed; }
  .am-error { margin-top: 8px; font: 400 12px var(--font-sans); color: var(--error-text, #ff453a); flex-shrink: 0; }
</style>

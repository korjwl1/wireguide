<script>
  // Trusted-network list for Wi-Fi rules.
  // On these SSIDs all auto-managed tunnels disconnect automatically.
  // Per-tunnel auto-connect SSIDs live in each tunnel's detail panel.
  import { createEventDispatcher, onMount } from 'svelte';
  import { t } from '../i18n/index.js';
  import SSIDPermissionBanner from './SSIDPermissionBanner.svelte';

  export let rules = {
    trusted_ssids: [],
    per_tunnel: {},
  };
  export let TunnelService = null;

  const dispatch = createEventDispatcher();
  let newTrusted = '';
  let knownSSIDs = [];
  let currentSSID = '';
  let suggestionsOpen = false;
  let suggestionFocusIndex = -1;
  let addInput = null;

  onMount(async () => {
    if (!TunnelService) return;
    try {
      const r = await TunnelService.GetKnownSSIDs();
      knownSSIDs = r?.known || [];
      currentSSID = r?.current || '';
    } catch (_) {}
  });

  $: filteredSuggestions = (() => {
    const q = (newTrusted || '').trim().toLowerCase();
    const seen = new Set(rules.trusted_ssids || []);
    const candidates = [
      ...(currentSSID && !seen.has(currentSSID) ? [currentSSID] : []),
      ...(knownSSIDs || []).filter(s => !seen.has(s) && s !== currentSSID),
    ];
    return (q ? candidates.filter(s => s.toLowerCase().includes(q)) : candidates).slice(0, 10);
  })();

  function pickSuggestion(ssid) {
    addTrusted(ssid);
    newTrusted = '';
    suggestionsOpen = false;
    suggestionFocusIndex = -1;
  }

  function onInputKeydown(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (suggestionFocusIndex >= 0 && filteredSuggestions[suggestionFocusIndex]) {
        pickSuggestion(filteredSuggestions[suggestionFocusIndex]);
      } else {
        addManual();
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (filteredSuggestions.length > 0) {
        suggestionsOpen = true;
        suggestionFocusIndex = (suggestionFocusIndex + 1) % filteredSuggestions.length;
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (filteredSuggestions.length > 0) {
        suggestionsOpen = true;
        suggestionFocusIndex = suggestionFocusIndex <= 0
          ? filteredSuggestions.length - 1
          : suggestionFocusIndex - 1;
      }
    } else if (e.key === 'Escape') {
      if (suggestionsOpen) {
        e.stopPropagation();
        suggestionsOpen = false;
        suggestionFocusIndex = -1;
      }
    }
  }

  function addManual() {
    if (!newTrusted.trim()) return;
    addTrusted(newTrusted);
    newTrusted = '';
    addInput?.focus();
  }

  function emit() {
    dispatch('change', rules);
  }

  function addTrusted(ssid) {
    const v = (ssid || '').trim();
    if (!v) return;
    if (!rules.trusted_ssids.includes(v)) {
      rules.trusted_ssids = [...rules.trusted_ssids, v];
      emit();
    }
  }

  function removeTrusted(ssid) {
    rules.trusted_ssids = rules.trusted_ssids.filter(s => s !== ssid);
    emit();
  }
</script>

<div class="wifi-rules">
  <SSIDPermissionBanner {TunnelService} />
  <p class="section-hint">{$t('wifi_rules.trusted_hint')}</p>

  <div class="add-row">
    <div class="combo">
      <input
        bind:this={addInput}
        type="text"
        role="combobox"
        aria-expanded={suggestionsOpen}
        aria-autocomplete="list"
        autocomplete="off"
        placeholder={$t('wifi_rules.ssid_placeholder')}
        bind:value={newTrusted}
        on:click={() => { suggestionsOpen = true; }}
        on:focus={() => { suggestionsOpen = true; }}
        on:blur={() => { setTimeout(() => { suggestionsOpen = false; suggestionFocusIndex = -1; }, 120); }}
        on:input={() => { suggestionsOpen = true; suggestionFocusIndex = -1; }}
        on:keydown={onInputKeydown} />
      {#if suggestionsOpen && filteredSuggestions.length > 0}
        <ul class="combo-dropdown" role="listbox">
          {#each filteredSuggestions as ssid, i}
            <li
              class="combo-option"
              class:focused={i === suggestionFocusIndex}
              role="option"
              aria-selected={i === suggestionFocusIndex}
              on:mousedown|preventDefault={() => pickSuggestion(ssid)}>
              <span class="combo-name">{ssid}</span>
              {#if ssid === currentSSID}
                <span class="current-badge">{$t('tunnel.wifi_current')}</span>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </div>
    <button on:click={addManual} disabled={!newTrusted.trim()}>{$t('wifi_rules.add')}</button>
  </div>

  <div class="list-block">
    {#if rules.trusted_ssids.length === 0}
      <div class="empty-row">{$t('wifi_rules.no_trusted')}</div>
    {:else}
      <ul class="list-rows">
        {#each rules.trusted_ssids as ssid}
          <li class="list-row">
            <span class="row-name">{ssid}</span>
            {#if ssid === currentSSID}
              <span class="current-badge">{$t('tunnel.wifi_current')}</span>
            {/if}
            <button class="row-remove" on:click={() => removeTrusted(ssid)} aria-label="remove {ssid}">✕</button>
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</div>

<style>
  .wifi-rules { padding: 4px 2px; }
  .section-hint {
    font: 11px/15px var(--font-sans, -apple-system, BlinkMacSystemFont, sans-serif);
    color: var(--text-muted);
    margin: 0 0 12px;
    letter-spacing: 0.01em;
  }
  .add-row {
    display: flex;
    gap: 8px;
    align-items: stretch;
    margin-bottom: 12px;
  }
  .combo {
    flex: 1;
    position: relative;
  }
  .combo input {
    width: 100%;
    height: 32px;
    padding: 0 12px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 8px;
    color: var(--text-primary);
    font: 13px/18px var(--font-sans);
    outline: none;
    box-sizing: border-box;
  }
  @media (prefers-reduced-motion: no-preference) {
    .combo input { transition: border-color 140ms ease, box-shadow 140ms ease, background 140ms ease; }
  }
  .combo input:focus-visible {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
    background: var(--bg-primary);
  }
  .combo-dropdown {
    list-style: none;
    margin: 4px 0 0;
    padding: 4px;
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 10px;
    box-shadow: var(--shadow-md);
    max-height: 220px;
    overflow-y: auto;
    z-index: 500;
  }
  .combo-option {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 10px;
    border-radius: 6px;
    cursor: pointer;
    color: var(--text-primary);
    font: 13px/18px var(--font-sans);
    min-height: 30px;
  }
  .combo-option:hover,
  .combo-option.focused {
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent);
  }
  .combo-name { flex: 1; }
  .add-row button {
    padding: 0 16px;
    height: 32px;
    background: var(--accent);
    border: 0;
    border-radius: 8px;
    color: #fff;
    font: 600 13px/18px var(--font-sans);
    letter-spacing: -0.005em;
    cursor: pointer;
    white-space: nowrap;
    box-shadow:
      0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
      0 1px 2px rgba(0,0,0,0.08);
  }
  @media (prefers-reduced-motion: no-preference) {
    .add-row button { transition: background-color 140ms ease, transform 140ms ease, box-shadow 140ms ease; }
  }
  .add-row button:hover:not(:disabled) {
    background: color-mix(in srgb, #fff 8%, var(--accent));
    transform: translateY(-1px);
    box-shadow:
      0 4px 8px color-mix(in srgb, var(--accent) 30%, transparent),
      0 1px 2px rgba(0,0,0,0.10);
  }
  .add-row button:disabled { opacity: 0.4; cursor: not-allowed; box-shadow: none; }

  .list-block {
    border: 0.5px solid var(--border);
    border-radius: 10px;
    background: var(--bg-card);
    height: 200px;
    overflow-y: scroll;
  }
  .list-block::-webkit-scrollbar { width: 8px; }
  .list-block::-webkit-scrollbar-track { background: transparent; }
  .list-block::-webkit-scrollbar-thumb {
    background-color: color-mix(in srgb, var(--text-muted) 40%, transparent);
    border-radius: 4px;
    border: 2px solid transparent;
    background-clip: content-box;
  }
  .list-block::-webkit-scrollbar-thumb:hover { background-color: var(--text-muted); }
  .empty-row {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    font: 11px/15px var(--font-sans);
    color: var(--text-muted);
    font-style: italic;
  }
  .list-rows {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .list-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 9px 14px;
    border-bottom: 0.5px solid var(--border);
    font: 13px/18px var(--font-sans);
    color: var(--text-primary);
    min-height: 36px;
  }
  .list-row:last-child { border-bottom: none; }
  .row-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .row-remove {
    background: transparent;
    border: 0;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 13px;
    padding: 4px 8px;
    border-radius: 6px;
    min-width: 24px;
    min-height: 24px;
  }
  .row-remove:hover {
    background: color-mix(in srgb, var(--red) 14%, transparent);
    color: var(--red);
  }
  .current-badge {
    font: 700 10px/1 var(--font-sans);
    color: var(--green);
    padding: 3px 8px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--green) 16%, transparent);
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }
</style>

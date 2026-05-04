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
      ...(knownSSIDs || []).filter(s => !seen.has(s)),
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
    font: var(--text-footnote);
    color: var(--text-secondary);
    margin: 0 0 var(--space-3);
  }
  .add-row {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    margin-bottom: var(--space-3);
  }
  .combo {
    flex: 1;
    position: relative;
  }
  .combo input {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm, 6px);
    color: var(--text-primary);
    font: var(--text-body);
    min-height: 28px;
    box-sizing: border-box;
  }
  .combo input:focus-visible {
    outline: 2px solid var(--accent-blue, #007AFF);
    outline-offset: 0;
    border-color: var(--accent-blue, #007AFF);
  }
  .combo-dropdown {
    list-style: none;
    margin: 4px 0 0;
    padding: 4px;
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm, 6px);
    box-shadow: var(--shadow-md);
    max-height: 200px;
    overflow-y: auto;
    z-index: 500;
  }
  .combo-option {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-primary);
    font: var(--text-body);
    min-height: 28px;
  }
  .combo-option:hover,
  .combo-option.focused {
    background: color-mix(in srgb, var(--accent-blue, #007AFF) 12%, transparent);
  }
  .combo-name { flex: 1; }
  .add-row button {
    padding: 0 var(--space-3);
    min-height: 28px;
    background: var(--accent, #007AFF);
    border: none;
    border-radius: var(--radius-sm, 6px);
    color: #fff;
    font: var(--text-body);
    cursor: pointer;
    white-space: nowrap;
  }
  .add-row button:disabled { opacity: 0.4; cursor: not-allowed; }
  .list-block {
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm, 6px);
    background: var(--bg-card);
    height: 160px;
    overflow-y: scroll;
  }
  .list-block::-webkit-scrollbar { width: 8px; }
  .list-block::-webkit-scrollbar-track { background: transparent; }
  .list-block::-webkit-scrollbar-thumb {
    background-color: color-mix(in srgb, var(--text-muted) 50%, transparent);
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
    font: var(--text-footnote);
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
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-bottom: 0.5px solid var(--border);
    font: var(--text-body);
    color: var(--text-primary);
    min-height: 32px;
  }
  .list-row:last-child { border-bottom: none; }
  .row-name { flex: 1; }
  .row-remove {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 13px;
    padding: 4px 8px;
    border-radius: 4px;
    min-width: 24px;
    min-height: 24px;
  }
  .row-remove:hover {
    background: color-mix(in srgb, var(--accent-red, #FF3B30) 14%, transparent);
    color: var(--accent-red, #FF3B30);
  }
  .current-badge {
    font: var(--text-caption);
    font-weight: 600;
    color: var(--accent-green, #34C759);
    padding: 1px 8px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--accent-green, #34C759) 14%, transparent);
  }
</style>

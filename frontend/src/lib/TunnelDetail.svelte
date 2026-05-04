<script>
  import { selectedTunnel, connectionStatus, refreshTunnels, refreshStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';
  import { createEventDispatcher, tick, onDestroy } from 'svelte';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  let detail = null;
  let loading = false;
  let error = '';

  // Per-tunnel Wi-Fi auto-connect rules. Loaded from Settings.WifiRules.PerTunnel
  // for the currently-selected tunnel; mutations here SaveSettings the
  // entire object back. Global trusted SSIDs live in Settings → Wi-Fi 규칙.
  let wifiSsids = [];
  let newWifiSsid = '';
  let showWifiModal = false;
  let wifiAddInput = null;
  let knownSSIDs = [];
  let currentSSID = '';
  let suggestionsOpen = false;
  let suggestionFocusIndex = -1;

  $: filteredSuggestions = (() => {
    const q = (newWifiSsid || '').trim().toLowerCase();
    const list = candidateSsidSuggestions.filter(s =>
      !q || s.toLowerCase().includes(q)
    );
    return list.slice(0, 10);
  })();

  function pickSuggestion(ssid) {
    addSsid(ssid);
    newWifiSsid = '';
    suggestionsOpen = false;
    suggestionFocusIndex = -1;
    // Don't refocus — leave focus on whatever the user clicked. The
    // dropdown will reopen on the next explicit click in the input.
  }

  function onSuggestionInputKeydown(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (suggestionFocusIndex >= 0 && filteredSuggestions[suggestionFocusIndex]) {
        pickSuggestion(filteredSuggestions[suggestionFocusIndex]);
      } else {
        addManualSsid();
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

  // candidateSsidSuggestions feeds the <datalist> autocomplete:
  // current SSID first, then OS-saved networks. Already-added SSIDs
  // are filtered out so the dropdown only offers actionable options.
  $: candidateSsidSuggestions = (() => {
    const seen = new Set(wifiSsids || []);
    const list = [];
    if (currentSSID && !seen.has(currentSSID)) {
      list.push(currentSSID);
      seen.add(currentSSID);
    }
    for (const s of (knownSSIDs || [])) {
      if (!seen.has(s)) {
        list.push(s);
        seen.add(s);
      }
    }
    return list;
  })();

  // Track the last name we issued loadDetail/loadWifiRules for. The
  // selectedTunnel store emits a fresh object reference on every
  // status change (refreshTunnels and the per-tick is_connected
  // diff both call .set/.update), which without this gate would
  // trigger two RPCs every second. We only re-fetch when the
  // *name* actually changes.
  let lastLoadedName = '';
  $: if ($selectedTunnel && $selectedTunnel.name !== lastLoadedName) {
    lastLoadedName = $selectedTunnel.name;
    loadDetail($selectedTunnel.name);
    loadWifiRules($selectedTunnel.name);
  }

  async function loadWifiRules(name) {
    try {
      const s = await TunnelService.GetSettings();
      const perTunnel = s?.wifi_rules?.per_tunnel || {};
      wifiSsids = perTunnel[name]?.auto_connect_ssids || [];
    } catch (e) {
      wifiSsids = [];
      console.error('loadWifiRules:', e);
    }
  }

  async function saveWifiSsidsForTunnel(name, ssids) {
    try {
      const s = await TunnelService.GetSettings();
      const rules = s?.wifi_rules || { trusted_ssids: [], per_tunnel: {} };
      rules.per_tunnel = rules.per_tunnel || {};
      if (ssids.length === 0) {
        delete rules.per_tunnel[name];
      } else {
        rules.per_tunnel[name] = { auto_connect_ssids: ssids };
      }
      await TunnelService.SaveSettings({ ...s, wifi_rules: rules });
    } catch (e) {
      // Surface to the user — silently failing here meant the
      // checkbox state in the modal got out of sync with what's on
      // disk and the rule didn't fire on next SSID change.
      error = `Wi-Fi rule save failed: ${errText(e)}`;
      console.error('save wifi rule:', e);
    }
  }

  function addSsid(ssid) {
    const v = (ssid || '').trim();
    if (!v || !$selectedTunnel) return;
    if (wifiSsids.includes(v)) return;
    wifiSsids = [...wifiSsids, v];
    saveWifiSsidsForTunnel($selectedTunnel.name, wifiSsids);
  }

  function addManualSsid() {
    if (!newWifiSsid.trim()) return;
    addSsid(newWifiSsid);
    newWifiSsid = '';
    // Refocus so the user can chain-add multiple networks without
    // moving the mouse back to the input.
    wifiAddInput?.focus();
  }

  function removeWifiSsid(ssid) {
    if (!$selectedTunnel) return;
    wifiSsids = wifiSsids.filter(s => s !== ssid);
    saveWifiSsidsForTunnel($selectedTunnel.name, wifiSsids);
  }

  async function openWifiModal() {
    showWifiModal = true;
    try {
      const r = await TunnelService.GetKnownSSIDs();
      knownSSIDs = r?.known || [];
      currentSSID = r?.current || '';
    } catch (e) {
      knownSSIDs = [];
      currentSSID = '';
    }
    // Intentionally do NOT auto-focus the input. Auto-focus would
    // synthesize a focus event that pops the dropdown open before
    // the user has interacted, which feels noisy. The dropdown
    // appears only after a click/keyboard focus.
  }

  function closeWifiModal() {
    showWifiModal = false;
  }

  // Single source of truth for "is this tunnel currently active?" —
  // combine the selected-tunnel flag with the live connection status so the
  // UI can't show a stale "connected" chip briefly after disconnect.
  $: isConnected = $selectedTunnel?.is_connected
    && ($connectionStatus?.active_tunnels || []).includes($selectedTunnel?.name);
  $: isConnecting = !isConnected
    && $connectionStatus?.state === 'connecting'
    && $connectionStatus?.tunnel_name === $selectedTunnel?.name;
  $: noHandshake = isConnected && !status?.last_handshake;
  // Use the primary status if it matches the selected tunnel (has full stats).
  // Otherwise fall back to the lightweight per-tunnel info from the tunnels array
  // (name + state + handshake only, no rx/tx/duration).
  $: status = (() => {
    if ($connectionStatus?.tunnel_name === $selectedTunnel?.name) {
      return $connectionStatus;
    }
    const tunnels = $connectionStatus?.tunnels || [];
    const match = tunnels.find(t => t.tunnel_name === $selectedTunnel?.name);
    return match || $connectionStatus;
  })();

  async function loadDetail(name) {
    try {
      detail = await TunnelService.GetTunnelDetail(name);
      error = '';
    } catch (e) {
      detail = null;
      // Surface the failure rather than silently leaving the panel
      // blank — most failures here are "tunnel was deleted" or
      // "config is corrupt" which the user can act on.
      error = errText(e);
    }
  }

  function connect() {
    dispatch('connect', {
      name: $selectedTunnel.name
    });
  }

  // Track consecutive "client closed" failures so we can swap the
  // raw error for a recovering-helper hint on the second attempt.
  let consecutiveClientClosed = 0;

  async function disconnect() {
    error = '';
    loading = true;
    try {
      await TunnelService.DisconnectTunnel($selectedTunnel.name);
      consecutiveClientClosed = 0;
      // Don't wait for event stream — refresh immediately.
      await refreshTunnels(TunnelService);
      await refreshStatus(TunnelService);
    } catch (e) {
      const raw = errText(e);
      if (/client closed|connection closed|broken pipe|EOF/i.test(raw)) {
        consecutiveClientClosed += 1;
        if (consecutiveClientClosed >= 2) {
          error = $t('tunnel.helper_recovering') || 'Helper recovering, please retry in a moment.';
        } else {
          error = raw;
        }
      } else {
        consecutiveClientClosed = 0;
        error = raw;
      }
    }
    loading = false;
  }

  let showDeleteConfirm = false;
  let deleteConfirmBtn = null;

  async function askDelete() {
    if (isConnected) {
      error = $t('confirm.disconnect_first');
      return;
    }
    showDeleteConfirm = true;
    // Auto-focus the confirm button so Enter confirms, Escape cancels,
    // and a stray Space press doesn't accidentally trigger the No button.
    await tick();
    deleteConfirmBtn?.focus();
  }

  async function confirmDelete() {
    showDeleteConfirm = false;
    try {
      await TunnelService.DeleteTunnel($selectedTunnel.name);
      selectedTunnel.set(null);
      dispatch('refresh');
    } catch (e) {
      error = errText(e);
    }
  }

  function cancelDelete() {
    showDeleteConfirm = false;
  }

  // Global ESC handler — closes whichever modal is open.
  function handleKeydown(e) {
    if (e.key !== 'Escape') return;
    if (showWifiModal) closeWifiModal();
    else if (showDeleteConfirm) cancelDelete();
    else if (renaming) cancelRename();
  }
  if (typeof window !== 'undefined') {
    window.addEventListener('keydown', handleKeydown);
    onDestroy(() => window.removeEventListener('keydown', handleKeydown));
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  let renaming = false;
  let renameValue = '';

  function startRename() {
    if (isConnected) {
      error = $t('confirm.disconnect_first');
      return;
    }
    renameValue = $selectedTunnel.name;
    renaming = true;
  }

  async function commitRename() {
    const oldName = $selectedTunnel.name;
    const newName = renameValue.trim();
    renaming = false;
    if (!newName || newName === oldName) return;
    try {
      await TunnelService.RenameTunnel(oldName, newName);
      selectedTunnel.set({ ...$selectedTunnel, name: newName });
      dispatch('refresh');
    } catch (e) {
      error = errText(e);
    }
  }

  function cancelRename() {
    renaming = false;
  }
</script>

<div class="detail-panel">
  {#if !$selectedTunnel}
    <div class="no-selection">
      <p>{$t('tunnel.no_tunnels')}</p>
    </div>
  {:else}
    <div class="detail-header" class:connected={isConnected}>
      {#if renaming}
        <input
          class="rename-input"
          type="text"
          bind:value={renameValue}
          on:blur={commitRename}
          on:keydown={(e) => {
            if (e.key === 'Enter') commitRename();
            if (e.key === 'Escape') cancelRename();
          }}
          autofocus
        />
      {:else}
        <h2 on:dblclick={startRename} title={$t('tunnel.rename_hint')}>{$selectedTunnel.name}</h2>
        <button class="btn-rename" on:click={startRename} title="Rename">✎</button>
      {/if}
      <span class="state-badge" class:on={isConnected && !noHandshake} class:warning={noHandshake} class:connecting={isConnecting}>
        {#if isConnected && noHandshake}
          {$t('app.no_handshake')}
        {:else if isConnected}
          {$t('app.connected')}
        {:else if isConnecting}
          {$t('app.connecting')}
        {:else}
          {$t('app.disconnected')}
        {/if}
      </span>
    </div>

    {#if isConnected && status.state === 'connected'}
      <div class="stats-grid">
        <div class="stat">
          <span class="stat-label">{$t('tunnel.rx')}</span>
          <span class="stat-value down">{formatBytes(status.rx_bytes || 0)}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.tx')}</span>
          <span class="stat-value up">{formatBytes(status.tx_bytes || 0)}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.handshake')}</span>
          <span class="stat-value">{status.last_handshake || '-'}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.duration')}</span>
          <span class="stat-value">{status.duration || '-'}</span>
        </div>
        <div class="stat">
          <span class="stat-label">{$t('tunnel.latency')}</span>
          <span class="stat-value">{status.latency_ms ? `${Math.round(status.latency_ms)} ms` : '—'}</span>
        </div>
      </div>
    {/if}

    <div class="detail-info">
      {#if $selectedTunnel.endpoint}
        <div class="info-row">
          <span class="label">{$t('tunnel.endpoint')}</span>
          <span class="value">{$selectedTunnel.endpoint}</span>
        </div>
      {/if}
      {#if detail}
        {#each detail.Peers || [] as peer}
          <div class="info-row">
            <span class="label">{$t('tunnel.allowed_ips')}</span>
            <span class="value">{(peer.AllowedIPs || []).join(', ')}</span>
          </div>
          <div class="info-row">
            <span class="label">{$t('tunnel.public_key')}</span>
            <span class="value mono">{peer.PublicKey?.substring(0, 20)}...</span>
          </div>
        {/each}
        {#if detail.Interface?.DNS?.length}
          <div class="info-row">
            <span class="label">DNS</span>
            <span class="value">{detail.Interface.DNS.join(', ')}</span>
          </div>
        {/if}
      {/if}
    </div>

    {#if error}
      <div class="error-msg">{error}</div>
    {/if}

    <div class="actions">
      {#if isConnected}
        <button class="btn btn-disconnect" on:click={disconnect} disabled={loading}>
          {$t('tunnel.disconnect')}
        </button>
      {:else}
        <button class="btn btn-connect" on:click={connect} disabled={loading}>
          {loading ? $t('app.connecting') : $t('tunnel.connect')}
        </button>
      {/if}
      <button class="btn btn-secondary" on:click={() => dispatch('edit', $selectedTunnel.name)}>
        {$t('tunnel.edit')}
      </button>
      <button class="btn btn-secondary" on:click={() => dispatch('export', $selectedTunnel.name)}>
        {$t('tunnel.export')}
      </button>
      <button class="btn btn-secondary wifi-btn" on:click={openWifiModal}>
        {$t('tunnel.wifi_auto_connect')}
        {#if wifiSsids.length > 0}
          <span class="wifi-count">{wifiSsids.length}</span>
        {/if}
      </button>
      <button class="btn btn-danger" on:click={askDelete}>
        {$t('tunnel.delete')}
      </button>
    </div>
  {/if}
</div>

{#if showWifiModal && $selectedTunnel}
  <div class="confirm-backdrop" on:click={closeWifiModal}>
    <div class="confirm-dialog wifi-dialog" on:click|stopPropagation role="dialog" aria-modal="true" aria-label={$t('tunnel.wifi_auto_connect')}>
      <h3>{$t('tunnel.wifi_auto_connect')} — {$selectedTunnel.name}</h3>
      <p>{$t('tunnel.wifi_auto_connect_hint')}</p>

      <div class="wifi-add-row">
        <div class="wifi-combo">
          <input
            bind:this={wifiAddInput}
            type="text"
            role="combobox"
            aria-expanded={suggestionsOpen}
            aria-autocomplete="list"
            autocomplete="off"
            placeholder={$t('tunnel.wifi_combo_placeholder')}
            bind:value={newWifiSsid}
            on:click={() => { suggestionsOpen = true; }}
            on:focus={() => { suggestionsOpen = true; }}
            on:blur={() => { setTimeout(() => { suggestionsOpen = false; suggestionFocusIndex = -1; }, 120); }}
            on:input={() => { suggestionsOpen = true; suggestionFocusIndex = -1; }}
            on:keydown={onSuggestionInputKeydown} />
          {#if suggestionsOpen && filteredSuggestions.length > 0}
            <ul class="wifi-combo-dropdown" role="listbox">
              {#each filteredSuggestions as ssid, i}
                <li
                  class="wifi-combo-option"
                  class:focused={i === suggestionFocusIndex}
                  role="option"
                  aria-selected={i === suggestionFocusIndex}
                  on:mousedown|preventDefault={() => pickSuggestion(ssid)}>
                  <span class="wifi-combo-name">{ssid}</span>
                  {#if ssid === currentSSID}
                    <span class="wifi-current-badge">{$t('tunnel.wifi_current')}</span>
                  {/if}
                </li>
              {/each}
            </ul>
          {/if}
        </div>
        <button class="btn btn-connect" on:click={addManualSsid} disabled={!newWifiSsid.trim()}>{$t('wifi_rules.add')}</button>
      </div>

      <div class="wifi-list-block">
        {#if wifiSsids.length === 0}
          <div class="wifi-empty-row">{$t('tunnel.wifi_empty')}</div>
        {:else}
          <ul class="wifi-list-rows">
            {#each wifiSsids as ssid}
              <li class="wifi-row">
                <span class="wifi-row-name">{ssid}</span>
                {#if ssid === currentSSID}
                  <span class="wifi-current-badge">{$t('tunnel.wifi_current')}</span>
                {/if}
                <button class="wifi-row-remove" on:click={() => removeWifiSsid(ssid)} aria-label="remove {ssid}" title={$t('confirm.no') || 'Remove'}>✕</button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>

      <div class="confirm-footer">
        <button class="btn btn-secondary" on:click={closeWifiModal}>{$t('confirm.close')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showDeleteConfirm}
  <div class="confirm-backdrop" on:click={cancelDelete}>
    <div class="confirm-dialog" on:click|stopPropagation>
      <h3>{$t('confirm.delete_title')}</h3>
      <p>{$t('confirm.delete_message', { name: $selectedTunnel.name })}</p>
      <div class="confirm-footer">
        <button class="btn btn-disconnect" bind:this={deleteConfirmBtn} on:click={confirmDelete}>{$t('confirm.yes')}</button>
        <button class="btn btn-secondary" on:click={cancelDelete}>{$t('confirm.no')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  /* ---------- Wi-Fi auto-connect button + modal ---------- */
  .wifi-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }
  .wifi-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 6px;
    border-radius: 9px;
    background: var(--accent-blue, #007AFF);
    color: #fff;
    font-size: 11px;
    font-weight: 600;
    line-height: 1;
  }
  .wifi-dialog {
    width: 460px;
    max-width: 90vw;
    /* Let internal scroll regions handle overflow; the modal itself
       must stay overflow:visible so the combobox dropdown can extend
       past the dialog edge instead of being clipped. */
    overflow: visible;
  }
  .wifi-warn {
    font: var(--text-footnote);
    color: var(--text-primary);
    background: color-mix(in srgb, var(--accent-yellow, #FF9500) 12%, transparent);
    border: 0.5px solid var(--accent-yellow, #FF9500);
    border-radius: var(--radius-sm, 6px);
    padding: var(--space-2) var(--space-3);
    margin: 0 0 var(--space-4);
  }
  .wifi-section-title {
    font: var(--text-footnote);
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: var(--space-4) 0 var(--space-2);
  }
  .wifi-list-block {
    border: 0.5px solid var(--border);
    border-radius: var(--radius-sm, 6px);
    background: var(--bg-card);
    margin-top: var(--space-3);
    margin-bottom: var(--space-3);
    /* Fixed-height scroll region: the modal stays the same size no
       matter how many networks the user adds. */
    height: 200px;
    /* Always-show the scrollbar track so row width never jumps when
       the list grows past the visible area. (`scrollbar-gutter:
       stable` is the modern equivalent but isn't reliably honored by
       all WebKit builds Wails ships against — `scroll` works
       everywhere.) */
    overflow-y: scroll;
  }
  /* Thin overlay-style scrollbar that matches native macOS list
     scrollbars instead of the chunky default WebKit one. */
  .wifi-list-block::-webkit-scrollbar {
    width: 8px;
  }
  .wifi-list-block::-webkit-scrollbar-track {
    background: transparent;
  }
  .wifi-list-block::-webkit-scrollbar-thumb {
    background-color: color-mix(in srgb, var(--text-muted) 50%, transparent);
    border-radius: 4px;
    border: 2px solid transparent;
    background-clip: content-box;
  }
  .wifi-list-block::-webkit-scrollbar-thumb:hover {
    background-color: var(--text-muted);
  }
  .wifi-empty-row {
    /* Center vertically in the fixed-height block when there are no
       networks yet, so the empty state doesn't look unbalanced. */
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
  }
  .wifi-list-rows {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .wifi-row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-bottom: 0.5px solid var(--border);
    font: var(--text-body);
    color: var(--text-primary);
    min-height: 32px;
  }
  .wifi-row:last-child { border-bottom: none; }
  .wifi-row-name { flex: 1; }
  .wifi-row-remove {
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
  .wifi-row-remove:hover {
    background: color-mix(in srgb, var(--accent-red, #FF3B30) 14%, transparent);
    color: var(--accent-red, #FF3B30);
  }
  .wifi-current-badge {
    font: var(--text-caption);
    font-weight: 600;
    color: var(--accent-green, #34C759);
    padding: 1px 8px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--accent-green, #34C759) 14%, transparent);
  }
  .wifi-add-row {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    margin-bottom: var(--space-3);
  }
  .wifi-combo {
    flex: 1;
    position: relative;
  }
  .wifi-combo input {
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
  .wifi-combo input:focus-visible {
    outline: 2px solid var(--accent-blue, #007AFF);
    outline-offset: 0;
    border-color: var(--accent-blue, #007AFF);
  }
  .wifi-combo-dropdown {
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
  .wifi-combo-option {
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
  .wifi-combo-option:hover,
  .wifi-combo-option.focused {
    background: color-mix(in srgb, var(--accent-blue, #007AFF) 12%, transparent);
  }
  .wifi-combo-name { flex: 1; }

  /* ---------- Layout ---------- */
  .detail-panel {
    flex: 1;
    padding: var(--space-6) var(--space-6);
    padding-top: 52px; /* clears the macOS traffic-light inset */
    overflow-y: auto;
  }
  .no-selection {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-muted);
    font: var(--text-body);
  }

  /* ---------- Header: title + rename + state badge ---------- */
  .detail-header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-5);
    padding-bottom: var(--space-4);
    border-bottom: 0.5px solid var(--border);
  }
  .detail-header h2 {
    margin: 0;
    font: var(--text-title-1);
    color: var(--text-primary);
    cursor: text;
  }
  .btn-rename {
    background: transparent;
    border: 0;
    color: var(--text-secondary);
    cursor: pointer;
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-xs);
    font: var(--text-body);
    opacity: 0.65;
  }
  .btn-rename:hover {
    background: var(--bg-hover);
    opacity: 1;
  }
  .rename-input {
    font: var(--text-title-1);
    padding: 2px var(--space-2);
    background: var(--bg-input);
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    outline: none;
    flex: 1;
    max-width: 320px;
    box-shadow: 0 0 0 3px var(--blue-tint);
  }

  /* ---------- State badge (connected / connecting / disconnected) ---------- */
  .state-badge {
    padding: 2px var(--space-2);
    border-radius: var(--radius-xs);
    font: var(--text-footnote);
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    background: var(--bg-card);
    color: var(--text-muted);
  }
  @media (prefers-reduced-motion: no-preference) {
    .state-badge {
      transition: background-color var(--dur-base) var(--ease-out),
                  color var(--dur-base) var(--ease-out);
    }
  }
  .state-badge.on {
    background: var(--green-tint);
    color: var(--green);
  }
  .state-badge.connecting {
    background: var(--yellow-tint);
    color: var(--yellow);
  }
  .state-badge.warning {
    background: var(--orange-tint, rgba(255, 149, 0, 0.12));
    color: var(--orange, #FF9500);
  }
  @media (prefers-reduced-motion: no-preference) {
    .state-badge.connecting {
      animation: pulse 1.6s ease-in-out infinite;
    }
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%      { opacity: 0.55; }
  }

  /* ---------- Stats grid ---------- */
  .stats-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-2);
    margin-bottom: var(--space-5);
  }
  .stat {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-md);
    padding: var(--space-3);
  }
  .stat-label {
    display: block;
    font: var(--text-footnote);
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: var(--space-1);
  }
  .stat-value {
    font: 600 17px/22px var(--font-sans);
    font-feature-settings: "tnum";   /* tabular numerals for stable alignment */
    color: var(--text-primary);
  }
  .stat-value.down { color: var(--stats-rx); }
  .stat-value.up   { color: var(--stats-tx); }

  /* ---------- Info rows ---------- */
  .detail-info {
    margin-bottom: var(--space-5);
  }
  .info-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: var(--space-4);
    padding: var(--space-2) 0;
    border-bottom: 0.5px solid var(--border);
    font: var(--text-body);
  }
  .info-row:last-child { border-bottom: 0; }
  .label { color: var(--text-secondary); flex-shrink: 0; }
  .value {
    color: var(--text-primary);
    text-align: right;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .value.mono {
    font-family: var(--font-mono);
    font-size: 11px;
  }

  /* ---------- Error message ---------- */
  .error-msg {
    padding: var(--space-2) var(--space-3);
    margin-bottom: var(--space-3);
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: var(--radius-sm);
    color: var(--error-text);
    font: var(--text-body);
  }

  /* ---------- Actions (button row) ---------- */
  .actions {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }
  .btn {
    height: 28px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: var(--radius-sm);
    font: var(--text-headline);
    cursor: pointer;
    color: var(--text-primary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn {
      transition: background-color var(--dur-fast) var(--ease-out),
                  filter var(--dur-fast) var(--ease-out),
                  border-color var(--dur-fast) var(--ease-out);
    }
  }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-connect {
    background: var(--accent);
    color: var(--text-inverse);
  }
  .btn-connect:hover:not(:disabled) { filter: brightness(1.08); }
  .btn-connect:active:not(:disabled) { filter: brightness(0.94); }
  .btn-disconnect {
    background: var(--red);
    color: var(--text-inverse);
  }
  .btn-disconnect:hover:not(:disabled) { filter: brightness(1.08); }
  .btn-disconnect:active:not(:disabled) { filter: brightness(0.94); }
  .btn-secondary {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
  }
  .btn-secondary:hover { background: var(--bg-hover); }
  .btn-secondary:active { background: var(--bg-active); }
  .btn-danger {
    background: transparent;
    color: var(--red);
    border: 0.5px solid var(--red);
  }
  .btn-danger:hover { background: var(--error-bg); }

  /* ---------- Delete confirmation dialog ---------- */
  .confirm-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 400;
  }
  .confirm-dialog {
    background: var(--bg-primary);
    border: 0.5px solid var(--border);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    width: 380px;
    box-shadow: var(--shadow-md);
  }
  .confirm-dialog h3 {
    margin: 0 0 var(--space-2);
    color: var(--text-primary);
    font: var(--text-title-3);
  }
  .confirm-dialog p {
    margin: 0 0 var(--space-4);
    color: var(--text-secondary);
    font: var(--text-body);
  }
  .confirm-footer {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
  }
</style>

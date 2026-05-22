<script>
  import { tunnels, selectedTunnel, connectionStatus, refreshTunnels, refreshStatus } from '../stores/tunnels.js';
  import Icon from './Icon.svelte';
  import { t } from '../i18n/index.js';
  import { errText } from './errors.js';
  import { createEventDispatcher, tick, onDestroy } from 'svelte';
  import SSIDPermissionBanner from './SSIDPermissionBanner.svelte';

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
    // Flush any pending edit for the previous tunnel BEFORE we reset the
    // textarea state. Without this, a quick switch within the 800ms
    // debounce window would clobber notesValue with the new tunnel's
    // notes, and the deferred saveNotes would early-return on the
    // notesValue === notesSaved check, silently dropping the edit.
    if (lastLoadedName && notesValue !== notesSaved) {
      flushNotes(lastLoadedName, notesValue);
    }
    if (notesSaveTimer) {
      clearTimeout(notesSaveTimer);
      notesSaveTimer = null;
    }
    lastLoadedName = $selectedTunnel.name;
    notesValue = $selectedTunnel.notes || '';
    notesSaved = notesValue;
    notesError = '';
    loadDetail($selectedTunnel.name);
    loadWifiRules($selectedTunnel.name);
  }

  // Per-tunnel notes. Populated from TunnelInfo.notes in the store, edited
  // locally, persisted via SetTunnelNotes on blur or 800ms idle.
  // notesSaved is the last value we committed to disk — used to skip
  // no-op saves and to detect dirty state on tunnel switch.
  let notesValue = '';
  let notesSaved = '';
  let notesSaveTimer = null;
  let notesError = '';

  // flushNotes is the single write path used by both the debounce/blur
  // saver and the cross-tunnel-switch flush. It patches BOTH stores —
  // selectedTunnel for the immediate UI, tunnels for the list — so
  // re-selecting the same tunnel before the next ListTunnels refresh
  // doesn't show stale (pre-edit) notes.
  async function flushNotes(name, value) {
    if (!name) return false;
    try {
      await TunnelService.SetTunnelNotes(name, value);
      tunnels.update(list => list.map(t => t.name === name ? { ...t, notes: value } : t));
      selectedTunnel.update(sel => sel && sel.name === name ? { ...sel, notes: value } : sel);
      // Only update local UI state if the user is still on this tunnel —
      // otherwise we'd overwrite the new tunnel's notesSaved with the
      // wrong value (this flush could be the cross-switch fire-and-forget).
      if ($selectedTunnel && $selectedTunnel.name === name) {
        notesSaved = value;
        notesError = '';
      }
      return true;
    } catch (e) {
      if ($selectedTunnel && $selectedTunnel.name === name) {
        notesError = errText(e);
      } else {
        console.error('flushNotes for', name, e);
      }
      return false;
    }
  }

  async function saveNotes() {
    if (!$selectedTunnel) return;
    if (notesValue === notesSaved) return;
    await flushNotes($selectedTunnel.name, notesValue);
  }

  function onNotesInput() {
    // Debounced auto-save. Blur still calls saveNotes immediately, so this
    // covers the case where the user stays in the textarea but stops typing.
    if (notesSaveTimer) clearTimeout(notesSaveTimer);
    notesSaveTimer = setTimeout(saveNotes, 800);
  }

  onDestroy(() => {
    if (notesSaveTimer) clearTimeout(notesSaveTimer);
    // Best-effort flush on unmount (e.g. user deselected the tunnel
    // while a debounce was still pending).
    if (lastLoadedName && notesValue !== notesSaved) {
      flushNotes(lastLoadedName, notesValue);
    }
  });

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
    <!-- HERO STATUS CARD: big visual, gradient bg by state, large icon -->
    <div class="hero-card"
      class:hero-connected={isConnected && !noHandshake}
      class:hero-connecting={isConnecting}
      class:hero-warning={noHandshake}
      class:hero-idle={!isConnected && !isConnecting && !noHandshake}>
      <div class="hero-glow"></div>

      <div class="hero-icon">
        {#if isConnected && !noHandshake}
          <Icon name="shield" size={28} strokeWidth={2} />
        {:else if isConnecting}
          <Icon name="zap" size={28} strokeWidth={2} />
        {:else if noHandshake}
          <Icon name="triangle-alert" size={28} strokeWidth={2} />
        {:else}
          <Icon name="shield-off" size={28} strokeWidth={1.75} />
        {/if}
      </div>

      <div class="hero-body">
        <div class="hero-name-row">
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
            <h2 class="hero-name" on:dblclick={startRename} title={$t('tunnel.rename_hint')}>{$selectedTunnel.name}</h2>
            <button class="btn-rename" on:click={startRename} title="Rename">
              <Icon name="pencil" size={12} strokeWidth={1.75} />
            </button>
          {/if}
        </div>
        <div class="hero-status-line">
          <span class="hero-dot"
            class:on={isConnected && !noHandshake}
            class:warning={noHandshake}
            class:connecting={isConnecting}></span>
          <span class="hero-state-text">
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
          {#if $selectedTunnel.endpoint}
            <span class="hero-sep">·</span>
            <span class="hero-endpoint">{$selectedTunnel.endpoint}</span>
          {/if}
        </div>
      </div>
    </div>

    <!-- PRIMARY ACTION: big full-width button -->
    <div class="primary-action">
      {#if isConnected}
        <button class="btn-primary-large btn-disconnect-lg" on:click={disconnect} disabled={loading}>
          <Icon name="lock" size={16} strokeWidth={2.25} />
          <span>{$t('tunnel.disconnect')}</span>
        </button>
      {:else}
        <button class="btn-primary-large btn-connect-lg" on:click={connect} disabled={loading}>
          {#if loading || isConnecting}
            <span class="spinner"></span>
            <span>{$t('app.connecting')}</span>
          {:else}
            <Icon name="zap" size={16} strokeWidth={2.25} />
            <span>{$t('tunnel.connect')}</span>
          {/if}
        </button>
      {/if}
    </div>

    <!-- STATS HERO: big numbers, colored icons, 3-up grid -->
    {#if isConnected && status.state === 'connected'}
      <div class="stats-hero">
        <div class="stat-card stat-rx">
          <div class="stat-card-top">
            <div class="stat-icon"><Icon name="arrow-down" size={13} strokeWidth={2.5} /></div>
            <span class="stat-label">{$t('tunnel.rx')}</span>
          </div>
          <div class="stat-value">{formatBytes(status.rx_bytes || 0)}</div>
        </div>
        <div class="stat-card stat-tx">
          <div class="stat-card-top">
            <div class="stat-icon"><Icon name="arrow-up" size={13} strokeWidth={2.5} /></div>
            <span class="stat-label">{$t('tunnel.tx')}</span>
          </div>
          <div class="stat-value">{formatBytes(status.tx_bytes || 0)}</div>
        </div>
        <div class="stat-card stat-latency">
          <div class="stat-card-top">
            <div class="stat-icon"><Icon name="activity" size={13} strokeWidth={2.5} /></div>
            <span class="stat-label">{$t('tunnel.latency')}</span>
          </div>
          <div class="stat-value">
            {status.latency_ms ? `${Math.round(status.latency_ms)}` : '—'}
            {#if status.latency_ms}<span class="stat-unit">ms</span>{/if}
          </div>
        </div>
      </div>

      <div class="stats-meta">
        <span class="meta-item">
          <Icon name="clock" size={11} strokeWidth={2} />
          {$t('tunnel.handshake')}: {status.last_handshake || '—'}
        </span>
        <span class="meta-sep">·</span>
        <span class="meta-item">{$t('tunnel.duration')}: {status.duration || '—'}</span>
      </div>
    {/if}

    <!-- INFO SECTION: card with rows + dividers -->
    {#if $selectedTunnel.endpoint || detail}
      <div class="info-section">
        <h3 class="section-label">{$t('tunnel.endpoint')}</h3>
        <div class="info-card">
          {#if $selectedTunnel.endpoint}
            <div class="info-row">
              <span class="info-label">{$t('tunnel.endpoint')}</span>
              <span class="info-value mono">{$selectedTunnel.endpoint}</span>
            </div>
          {/if}
          {#if detail}
            {#each detail.Peers || [] as peer}
              {#if $selectedTunnel.endpoint || (peer.AllowedIPs || []).length}
                <div class="row-divider"></div>
              {/if}
              <div class="info-row">
                <span class="info-label">{$t('tunnel.allowed_ips')}</span>
                <span class="info-value">{(peer.AllowedIPs || []).join(', ') || '—'}</span>
              </div>
              <div class="row-divider"></div>
              <div class="info-row">
                <span class="info-label">{$t('tunnel.public_key')}</span>
                <span class="info-value mono">{peer.PublicKey?.substring(0, 20)}…</span>
              </div>
            {/each}
            {#if detail.Interface?.DNS?.length}
              <div class="row-divider"></div>
              <div class="info-row">
                <span class="info-label">DNS</span>
                <span class="info-value">{detail.Interface.DNS.join(', ')}</span>
              </div>
            {/if}
          {/if}
        </div>
      </div>
    {/if}

    <!-- NOTES -->
    <div class="info-section">
      <h3 class="section-label">{$t('tunnel.notes')}</h3>
      <textarea
        id="tunnel-notes"
        class="notes-textarea"
        placeholder={$t('tunnel.notes_placeholder')}
        bind:value={notesValue}
        on:input={onNotesInput}
        on:blur={saveNotes}
        rows="2"></textarea>
      {#if notesError}
        <div class="notes-error">{notesError}</div>
      {/if}
    </div>

    {#if error}
      <div class="error-msg">{error}</div>
    {/if}

    <!-- SECONDARY ACTIONS: 4-up icon button grid -->
    <div class="secondary-actions">
      <button class="btn-icon-action" on:click={() => dispatch('edit', $selectedTunnel.name)}>
        <Icon name="file-pen" size={15} strokeWidth={1.75} />
        <span>{$t('tunnel.edit')}</span>
      </button>
      <button class="btn-icon-action" on:click={() => dispatch('export', $selectedTunnel.name)}>
        <Icon name="share" size={15} strokeWidth={1.75} />
        <span>{$t('tunnel.export')}</span>
      </button>
      <button class="btn-icon-action wifi-btn" on:click={openWifiModal}>
        <Icon name="wifi" size={15} strokeWidth={1.75} />
        <span>{$t('tunnel.wifi_auto_connect')}</span>
        {#if wifiSsids.length > 0}
          <span class="wifi-count">{wifiSsids.length}</span>
        {/if}
      </button>
      <button class="btn-icon-action btn-icon-danger" on:click={askDelete}>
        <Icon name="trash-2" size={15} strokeWidth={1.75} />
        <span>{$t('tunnel.delete')}</span>
      </button>
    </div>
  {/if}
</div>

{#if showWifiModal && $selectedTunnel}
  <div class="confirm-backdrop" on:click={closeWifiModal}>
    <div class="confirm-dialog wifi-dialog" on:click|stopPropagation role="dialog" aria-modal="true" aria-label={$t('tunnel.wifi_auto_connect')}>
      <div class="dialog-header">
        <div class="dialog-icon-tile">
          <Icon name="wifi" size={18} strokeWidth={2} />
        </div>
        <div class="dialog-header-text">
          <h3>{$t('tunnel.wifi_auto_connect')}</h3>
          <p class="dialog-sub">{$selectedTunnel.name}</p>
        </div>
      </div>
      <p class="dialog-hint">{$t('tunnel.wifi_auto_connect_hint')}</p>

      <SSIDPermissionBanner {TunnelService} />

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
        <button class="dialog-btn dialog-btn-primary" on:click={addManualSsid} disabled={!newWifiSsid.trim()}>{$t('wifi_rules.add')}</button>
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
                <button class="wifi-row-remove" on:click={() => removeWifiSsid(ssid)} aria-label="remove {ssid}" title={$t('confirm.no') || 'Remove'}>
                  <Icon name="x" size={12} strokeWidth={2} />
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>

      <div class="confirm-footer">
        <button class="dialog-btn dialog-btn-ghost" on:click={closeWifiModal}>{$t('confirm.close')}</button>
      </div>
    </div>
  </div>
{/if}

{#if showDeleteConfirm}
  <div class="confirm-backdrop" on:click={cancelDelete}>
    <div class="confirm-dialog" on:click|stopPropagation>
      <div class="dialog-header">
        <div class="dialog-icon-tile danger">
          <Icon name="triangle-alert" size={18} strokeWidth={2} />
        </div>
        <div class="dialog-header-text">
          <h3>{$t('confirm.delete_title')}</h3>
        </div>
      </div>
      <p class="dialog-message">{$t('confirm.delete_message', { name: $selectedTunnel.name })}</p>
      <div class="confirm-footer">
        <button class="dialog-btn dialog-btn-ghost" on:click={cancelDelete}>{$t('confirm.no')}</button>
        <button class="dialog-btn dialog-btn-danger" bind:this={deleteConfirmBtn} on:click={confirmDelete}>{$t('confirm.yes')}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  /* ---------- Wi-Fi auto-connect badge + modal ---------- */
  .wifi-count {
    position: absolute;
    top: 6px;
    right: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 16px;
    height: 16px;
    padding: 0 5px;
    border-radius: 8px;
    background: var(--accent);
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    line-height: 1;
  }
  .wifi-dialog {
    width: 640px;
    max-width: 90vw;
    /* Let combobox dropdown extend past dialog edge */
    overflow: visible;
  }
  .wifi-list-block {
    border: 0.5px solid var(--border);
    border-radius: 10px;
    background: var(--bg-card);
    margin-bottom: 12px;
    height: 160px;
    overflow-y: scroll;
  }
  .wifi-list-block::-webkit-scrollbar { width: 8px; }
  .wifi-list-block::-webkit-scrollbar-track { background: transparent; }
  .wifi-list-block::-webkit-scrollbar-thumb {
    background-color: color-mix(in srgb, var(--text-muted) 40%, transparent);
    border-radius: 4px;
    border: 2px solid transparent;
    background-clip: content-box;
  }
  .wifi-list-block::-webkit-scrollbar-thumb:hover { background-color: var(--text-muted); }
  .wifi-empty-row {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    font: 11px/15px var(--font-sans);
    color: var(--text-muted);
    font-style: italic;
  }
  .wifi-list-rows {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .wifi-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 9px 14px;
    border-bottom: 0.5px solid var(--border);
    font: 13px/18px var(--font-sans);
    color: var(--text-primary);
    min-height: 36px;
  }
  .wifi-row:last-child { border-bottom: none; }
  .wifi-row-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .wifi-row-remove {
    background: transparent;
    border: 0;
    color: var(--text-muted);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 6px;
    min-width: 24px;
    min-height: 24px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .wifi-row-remove:hover {
    background: color-mix(in srgb, var(--red) 14%, transparent);
    color: var(--red);
  }
  .wifi-current-badge {
    font: 700 10px/1 var(--font-sans);
    color: var(--green);
    padding: 3px 8px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--green) 16%, transparent);
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }
  .wifi-add-row {
    display: flex;
    gap: 8px;
    align-items: stretch;
    margin-bottom: 12px;
  }
  .wifi-combo {
    flex: 1;
    position: relative;
  }
  .wifi-combo input {
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
    .wifi-combo input { transition: border-color 140ms ease, box-shadow 140ms ease, background 140ms ease; }
  }
  .wifi-combo input:focus-visible {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
    background: var(--bg-primary);
  }
  .wifi-combo-dropdown {
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
  .wifi-combo-option {
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
  .wifi-combo-option:hover,
  .wifi-combo-option.focused {
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent);
  }
  .wifi-combo-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* ---------- Layout ---------- */
  .detail-panel {
    flex: 1;
    padding: 52px var(--space-7, 28px) var(--space-7, 28px);
    overflow-y: auto;
    max-width: 760px;
    margin: 0 auto;
    width: 100%;
    box-sizing: border-box;
  }
  .no-selection {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-muted);
    font: var(--text-body);
  }

  /* ========== HERO STATUS CARD ==========
     Big visual element. Gradient background tinted by state.
     Large icon tile + tunnel name + state line. */
  .hero-card {
    position: relative;
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 20px;
    border-radius: 16px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    margin-bottom: 14px;
    overflow: hidden;
    box-shadow: 0 1px 2px rgba(0,0,0,0.06);
  }
  @media (prefers-reduced-motion: no-preference) {
    .hero-card {
      transition: background 280ms ease, border-color 280ms ease, box-shadow 280ms ease;
    }
  }
  .hero-card.hero-connected {
    background:
      radial-gradient(120% 140% at 0% 0%, color-mix(in srgb, var(--green) 22%, var(--bg-card)) 0%, var(--bg-card) 70%);
    border-color: color-mix(in srgb, var(--green) 30%, var(--border));
    box-shadow: 0 4px 16px color-mix(in srgb, var(--green) 14%, transparent);
  }
  .hero-card.hero-connecting {
    background:
      radial-gradient(120% 140% at 0% 0%, color-mix(in srgb, var(--yellow) 22%, var(--bg-card)) 0%, var(--bg-card) 70%);
    border-color: color-mix(in srgb, var(--yellow) 30%, var(--border));
  }
  .hero-card.hero-warning {
    background:
      radial-gradient(120% 140% at 0% 0%, color-mix(in srgb, var(--orange, #FF9500) 22%, var(--bg-card)) 0%, var(--bg-card) 70%);
    border-color: color-mix(in srgb, var(--orange, #FF9500) 30%, var(--border));
  }

  /* Decorative glow blob in the top-right of connected state */
  .hero-glow {
    position: absolute;
    top: -40px;
    right: -40px;
    width: 140px;
    height: 140px;
    border-radius: 50%;
    pointer-events: none;
    filter: blur(40px);
    opacity: 0;
  }
  .hero-card.hero-connected .hero-glow {
    background: var(--green);
    opacity: 0.18;
  }
  .hero-card.hero-connecting .hero-glow {
    background: var(--yellow);
    opacity: 0.18;
  }
  .hero-card.hero-warning .hero-glow {
    background: var(--orange, #FF9500);
    opacity: 0.18;
  }

  /* Hero icon tile — 56x56 rounded square with state-colored bg/fg */
  .hero-icon {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 56px;
    height: 56px;
    border-radius: 14px;
    background: color-mix(in srgb, var(--text-muted) 14%, var(--bg-card));
    color: var(--text-muted);
    flex-shrink: 0;
    z-index: 1;
  }
  .hero-card.hero-connected .hero-icon {
    background: color-mix(in srgb, var(--green) 22%, transparent);
    color: var(--green);
  }
  .hero-card.hero-connecting .hero-icon {
    background: color-mix(in srgb, var(--yellow) 22%, transparent);
    color: var(--yellow);
  }
  .hero-card.hero-warning .hero-icon {
    background: color-mix(in srgb, var(--orange, #FF9500) 22%, transparent);
    color: var(--orange, #FF9500);
  }
  @keyframes hero-icon-pulse {
    0%, 100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--green) 55%, transparent); }
    55% { box-shadow: 0 0 0 10px color-mix(in srgb, var(--green) 0%, transparent); }
  }
  @media (prefers-reduced-motion: no-preference) {
    .hero-card.hero-connected .hero-icon {
      animation: hero-icon-pulse 2.6s ease-out infinite;
    }
  }

  .hero-body {
    flex: 1;
    min-width: 0;
    z-index: 1;
  }
  .hero-name-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .hero-name {
    margin: 0;
    font: 700 22px/28px var(--font-sans);
    color: var(--text-primary);
    letter-spacing: -0.02em;
    cursor: text;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .btn-rename {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    border: 0;
    color: var(--text-muted);
    cursor: pointer;
    padding: 4px;
    border-radius: 6px;
    opacity: 0.65;
  }
  .btn-rename:hover {
    background: rgba(255,255,255,0.06);
    opacity: 1;
  }
  .rename-input {
    font: 700 22px/28px var(--font-sans);
    letter-spacing: -0.02em;
    padding: 2px 8px;
    background: var(--bg-input);
    border: 1px solid var(--accent);
    border-radius: 6px;
    color: var(--text-primary);
    outline: none;
    flex: 1;
    max-width: 320px;
    box-shadow: 0 0 0 3px var(--blue-tint);
  }

  .hero-status-line {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-top: 6px;
    font: 500 12px/16px var(--font-sans);
    color: var(--text-secondary);
    min-width: 0;
  }
  .hero-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: color-mix(in srgb, var(--text-muted) 55%, transparent);
    flex-shrink: 0;
  }
  .hero-dot.on {
    background: var(--green);
    box-shadow: 0 0 8px color-mix(in srgb, var(--green) 90%, transparent);
  }
  .hero-dot.warning { background: var(--orange, #FF9500); }
  @keyframes dot-blink {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.85); }
  }
  @media (prefers-reduced-motion: no-preference) {
    .hero-dot.connecting {
      background: var(--yellow);
      animation: dot-blink 1.2s ease-in-out infinite;
    }
  }
  .hero-state-text {
    color: var(--text-primary);
    font-weight: 600;
    letter-spacing: -0.01em;
  }
  .hero-card.hero-connected .hero-state-text { color: var(--green); }
  .hero-card.hero-connecting .hero-state-text { color: var(--yellow); }
  .hero-card.hero-warning .hero-state-text { color: var(--orange, #FF9500); }
  .hero-sep { color: var(--text-muted); opacity: 0.6; }
  .hero-endpoint {
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  /* ========== PRIMARY ACTION ==========
     Big full-width gradient button below the hero card. */
  .primary-action {
    margin-bottom: 18px;
  }
  .btn-primary-large {
    width: 100%;
    height: 48px;
    padding: 0 20px;
    border: 0;
    border-radius: 12px;
    font: 600 14px/20px var(--font-sans);
    letter-spacing: -0.01em;
    cursor: pointer;
    color: #fff;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    position: relative;
    overflow: hidden;
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn-primary-large {
      transition: filter 180ms ease, transform 180ms ease, box-shadow 180ms ease;
    }
  }
  .btn-primary-large:disabled { opacity: 0.55; cursor: not-allowed; }
  .btn-connect-lg {
    background: var(--green);
    box-shadow: 0 2px 6px color-mix(in srgb, var(--green) 28%, transparent),
                0 1px 2px rgba(0,0,0,0.08);
  }
  .btn-connect-lg:hover:not(:disabled) {
    background: color-mix(in srgb, #fff 8%, var(--green));
    transform: translateY(-1px);
    box-shadow: 0 6px 16px color-mix(in srgb, var(--green) 36%, transparent),
                0 1px 2px rgba(0,0,0,0.10);
  }
  .btn-connect-lg:active:not(:disabled) {
    background: color-mix(in srgb, #000 8%, var(--green));
    transform: translateY(0);
  }

  .btn-disconnect-lg {
    background: var(--red);
    box-shadow: 0 2px 6px color-mix(in srgb, var(--red) 28%, transparent),
                0 1px 2px rgba(0,0,0,0.08);
  }
  .btn-disconnect-lg:hover:not(:disabled) {
    background: color-mix(in srgb, #fff 8%, var(--red));
    transform: translateY(-1px);
    box-shadow: 0 6px 16px color-mix(in srgb, var(--red) 34%, transparent),
                0 1px 2px rgba(0,0,0,0.10);
  }
  .btn-disconnect-lg:active:not(:disabled) {
    background: color-mix(in srgb, #000 8%, var(--red));
    transform: translateY(0);
  }

  /* Spinner inside connect button when connecting */
  .spinner {
    width: 14px;
    height: 14px;
    border: 2px solid rgba(255,255,255,0.35);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ========== STATS HERO ==========
     3-column grid of stat cards with big numbers and color-coded icons. */
  .stats-hero {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 10px;
    margin-bottom: 8px;
  }
  .stat-card {
    padding: 14px 14px 12px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .stat-card-top {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .stat-icon {
    width: 22px;
    height: 22px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    background: color-mix(in srgb, var(--text-muted) 14%, transparent);
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .stat-card.stat-rx .stat-icon {
    background: color-mix(in srgb, var(--green) 22%, transparent);
    color: var(--green);
  }
  .stat-card.stat-tx .stat-icon {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
    color: var(--accent);
  }
  .stat-card.stat-latency .stat-icon {
    background: color-mix(in srgb, var(--yellow) 22%, transparent);
    color: var(--yellow);
  }
  .stat-label {
    font: 500 10px/13px var(--font-sans);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .stat-value {
    font: 700 22px/26px var(--font-sans);
    color: var(--text-primary);
    font-feature-settings: "tnum";
    letter-spacing: -0.02em;
  }
  .stat-unit {
    font: 500 12px/16px var(--font-sans);
    color: var(--text-muted);
    letter-spacing: 0;
    margin-left: 2px;
  }

  .stats-meta {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    margin: 0 0 18px 2px;
    font: 11px/15px var(--font-sans);
    color: var(--text-muted);
  }
  .meta-item {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .meta-sep { opacity: 0.5; }

  /* ========== INFO SECTION ==========
     Card with rows + hairline dividers (iOS Settings style). */
  .info-section {
    margin-bottom: 16px;
  }
  .section-label {
    margin: 0 0 8px 4px;
    font: 500 10px/13px var(--font-sans);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .info-card {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }
  .info-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 16px;
    padding: 11px 14px;
    font: 13px/18px var(--font-sans);
  }
  .row-divider {
    height: 0.5px;
    background: var(--border);
    margin: 0 14px;
  }
  .info-label { color: var(--text-secondary); flex-shrink: 0; }
  .info-value {
    color: var(--text-primary);
    text-align: right;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .info-value.mono {
    font-family: var(--font-mono);
    font-size: 11px;
  }

  /* ========== NOTES ========== */
  .notes-textarea {
    width: 100%;
    box-sizing: border-box;
    padding: 10px 14px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 12px;
    color: var(--text-primary);
    font: 13px/18px var(--font-sans);
    line-height: 1.5;
    resize: vertical;
    min-height: 56px;
    max-height: 200px;
    outline: none;
  }
  @media (prefers-reduced-motion: no-preference) {
    .notes-textarea {
      transition: border-color 140ms ease, box-shadow 140ms ease;
    }
  }
  .notes-textarea:focus-visible {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--blue-tint);
  }
  .notes-textarea::placeholder { color: var(--text-muted); }
  .notes-error {
    margin: 6px 0 0 4px;
    font: 11px/15px var(--font-sans);
    color: var(--red);
  }

  /* ========== ERROR ========== */
  .error-msg {
    padding: 10px 14px;
    margin-bottom: 14px;
    background: var(--error-bg);
    border: 0.5px solid var(--red);
    border-radius: 10px;
    color: var(--error-text);
    font: 13px/18px var(--font-sans);
  }

  /* ========== SECONDARY ACTIONS ==========
     4-column icon-button grid at the bottom. */
  .secondary-actions {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
    margin-top: 4px;
  }
  .btn-icon-action {
    display: inline-flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 4px;
    height: 64px;
    padding: 0 8px;
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 12px;
    color: var(--text-primary);
    font: 500 11px/14px var(--font-sans);
    cursor: pointer;
    position: relative;
  }
  @media (prefers-reduced-motion: no-preference) {
    .btn-icon-action {
      transition: background 140ms ease, border-color 140ms ease, transform 140ms ease;
    }
  }
  .btn-icon-action:hover {
    background: var(--bg-hover);
    border-color: color-mix(in srgb, var(--accent) 35%, var(--border));
    transform: translateY(-1px);
  }
  .btn-icon-action:active { transform: translateY(0); background: var(--bg-active); }
  .btn-icon-action.btn-icon-danger { color: var(--red); }
  .btn-icon-action.btn-icon-danger:hover {
    background: color-mix(in srgb, var(--red) 8%, var(--bg-card));
    border-color: color-mix(in srgb, var(--red) 40%, var(--border));
    color: var(--red);
  }

  /* ========== Modal dialog (Wi-Fi auto-connect + Delete confirm) ========== */
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
    border-radius: 14px;
    padding: 22px 26px 18px;
    width: 480px;
    box-shadow: var(--shadow-lg);
  }

  /* Shared dialog header: icon tile + title + optional subtitle */
  .dialog-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
  }
  .dialog-icon-tile {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: color-mix(in srgb, var(--accent) 16%, transparent);
    color: var(--accent);
    flex-shrink: 0;
  }
  .dialog-icon-tile.danger {
    background: color-mix(in srgb, var(--red) 16%, transparent);
    color: var(--red);
  }
  .dialog-header-text {
    flex: 1;
    min-width: 0;
  }
  .confirm-dialog h3 {
    margin: 0;
    color: var(--text-primary);
    font: 700 15px/20px var(--font-sans);
    letter-spacing: -0.01em;
  }
  .dialog-sub {
    margin: 1px 0 0;
    font: 500 12px/16px var(--font-sans);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dialog-hint {
    margin: 0 0 14px;
    font: 12px/17px var(--font-sans);
    color: var(--text-muted);
  }
  .dialog-message {
    margin: 0 0 18px;
    font: 13px/19px var(--font-sans);
    color: var(--text-secondary);
  }
  .confirm-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-top: 14px;
  }

  /* Dialog buttons — 32px height, gradient primary / red danger / ghost cancel */
  .dialog-btn {
    height: 32px;
    min-width: 76px;
    padding: 0 16px;
    border: 0;
    border-radius: 9px;
    font: 600 13px/18px var(--font-sans);
    letter-spacing: -0.005em;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    color: var(--text-primary);
  }
  @media (prefers-reduced-motion: no-preference) {
    .dialog-btn {
      transition: filter 140ms ease, background-color 140ms ease,
                  border-color 140ms ease, transform 140ms ease,
                  box-shadow 140ms ease;
    }
  }
  .dialog-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .dialog-btn-primary {
    background: var(--accent);
    color: #fff;
    box-shadow:
      0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
      0 1px 2px rgba(0,0,0,0.08);
  }
  .dialog-btn-primary:hover:not(:disabled) {
    background: color-mix(in srgb, #fff 8%, var(--accent));
    transform: translateY(-1px);
    box-shadow:
      0 4px 10px color-mix(in srgb, var(--accent) 30%, transparent),
      0 1px 2px rgba(0,0,0,0.10);
  }
  .dialog-btn-primary:active:not(:disabled) {
    background: color-mix(in srgb, #000 8%, var(--accent));
    transform: translateY(0);
  }

  .dialog-btn-danger {
    background: var(--red);
    color: #fff;
    box-shadow:
      0 1px 3px color-mix(in srgb, var(--red) 26%, transparent),
      0 1px 2px rgba(0,0,0,0.08);
  }
  .dialog-btn-danger:hover:not(:disabled) {
    background: color-mix(in srgb, #fff 8%, var(--red));
    transform: translateY(-1px);
    box-shadow:
      0 4px 10px color-mix(in srgb, var(--red) 30%, transparent),
      0 1px 2px rgba(0,0,0,0.10);
  }
  .dialog-btn-danger:active:not(:disabled) {
    background: color-mix(in srgb, #000 8%, var(--red));
    transform: translateY(0);
  }

  .dialog-btn-ghost {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    color: var(--text-primary);
  }
  .dialog-btn-ghost:hover { background: var(--bg-hover); }
  .dialog-btn-ghost:active { background: var(--bg-active); }
</style>

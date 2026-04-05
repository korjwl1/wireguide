<script>
  import { createEventDispatcher } from 'svelte';
  import SplitTunnelUI from './SplitTunnelUI.svelte';
  import ConfigEditor from './ConfigEditor.svelte';
  import { errText } from './errors.js';
  import { t } from '../i18n/index.js';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  let mode = 'form'; // 'form' or 'text'

  // Form fields
  let name = '';
  let privateKey = '';
  let address = '10.0.0.2/24';
  let dns = '1.1.1.1';
  let mtu = '';
  let peerPublicKey = '';
  let peerEndpoint = '';
  let peerPSK = '';
  let allowedIPs = ['0.0.0.0/0', '::/0'];
  let keepalive = '';

  // Text mode: raw .conf
  let textContent = '';

  let errors = [];
  let generating = false;

  function generateKey() {
    generating = true;
    errors = [];
    try {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      // Curve25519 clamping
      bytes[0] &= 248;
      bytes[31] &= 127;
      bytes[31] |= 64;
      privateKey = btoa(String.fromCharCode(...bytes));
    } catch (e) {
      errors = ['Key generation failed: ' + errText(e)];
    }
    generating = false;
  }

  function buildConfFromForm() {
    let conf = '[Interface]\n';
    conf += `PrivateKey = ${privateKey}\n`;
    conf += `Address = ${address}\n`;
    if (dns) conf += `DNS = ${dns}\n`;
    if (mtu) conf += `MTU = ${mtu}\n`;
    conf += '\n[Peer]\n';
    conf += `PublicKey = ${peerPublicKey}\n`;
    if (peerPSK) conf += `PresharedKey = ${peerPSK}\n`;
    if (peerEndpoint) conf += `Endpoint = ${peerEndpoint}\n`;
    conf += `AllowedIPs = ${allowedIPs.join(', ')}\n`;
    if (keepalive) conf += `PersistentKeepalive = ${keepalive}\n`;
    return conf;
  }

  // When switching from form → text, populate text with current form values
  function switchToText() {
    if (privateKey || peerPublicKey) {
      textContent = buildConfFromForm();
    } else if (!textContent) {
      textContent = `[Interface]
PrivateKey =
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey =
Endpoint =
AllowedIPs = 0.0.0.0/0, ::/0
`;
    }
    mode = 'text';
  }

  async function save() {
    errors = [];
    if (!name.trim()) {
      errors = ['Tunnel name is required'];
      return;
    }

    const content = mode === 'form' ? buildConfFromForm() : textContent;

    try {
      const validationErrors = await TunnelService.ValidateConfig(content);
      if (validationErrors && validationErrors.length > 0) {
        errors = validationErrors;
        return;
      }
      await TunnelService.ImportConfig(name, content);
      dispatch('save', { name, content });
    } catch (e) {
      errors = [errText(e)];
    }
  }

  function updateAllowedIPs(e) {
    allowedIPs = e.detail;
  }
</script>

<div class="modal-backdrop" on:click={() => dispatch('close')}>
  <div class="modal" on:click|stopPropagation>
    <div class="modal-header">
      <h3>{$t('new_tunnel.title')}</h3>
      <div class="mode-tabs">
        <button class:active={mode === 'form'} on:click={() => mode = 'form'}>{$t('new_tunnel.mode_form')}</button>
        <button class:active={mode === 'text'} on:click={switchToText}>{$t('new_tunnel.mode_text')}</button>
      </div>
    </div>

    <section>
      <label>{$t('new_tunnel.name_label')} *</label>
      <input type="text" bind:value={name} placeholder={$t('new_tunnel.name_placeholder')} />
    </section>

    {#if mode === 'form'}
      <section>
        <h4>{$t('new_tunnel.section_interface')}</h4>

        <label>{$t('new_tunnel.private_key_label')} *</label>
        <div class="key-row">
          <input type="text" bind:value={privateKey} placeholder="base64" />
          <button class="btn-gen" on:click={generateKey} disabled={generating}>{$t('new_tunnel.generate')}</button>
        </div>

        <label>{$t('new_tunnel.address_label')} *</label>
        <input type="text" bind:value={address} placeholder="10.0.0.2/24" />

        <div class="row-2">
          <div>
            <label>{$t('new_tunnel.dns_label')}</label>
            <input type="text" bind:value={dns} placeholder="1.1.1.1" />
          </div>
          <div>
            <label>{$t('new_tunnel.mtu_label')}</label>
            <input type="text" bind:value={mtu} placeholder="1420" />
          </div>
        </div>
      </section>

      <section>
        <h4>{$t('new_tunnel.section_peer')}</h4>

        <label>{$t('new_tunnel.peer_public_key_label')} *</label>
        <input type="text" bind:value={peerPublicKey} placeholder="base64" />

        <label>{$t('new_tunnel.peer_endpoint_label')}</label>
        <input type="text" bind:value={peerEndpoint} placeholder="vpn.example.com:51820" />

        <label>{$t('new_tunnel.peer_psk_label')}</label>
        <input type="text" bind:value={peerPSK} placeholder="base64" />

        <label>{$t('new_tunnel.peer_allowed_ips_label')}</label>
        <SplitTunnelUI {allowedIPs} on:change={updateAllowedIPs} />

        <label>{$t('new_tunnel.peer_keepalive_label')}</label>
        <input type="text" bind:value={keepalive} placeholder="25" />
      </section>
    {:else}
      <section class="text-mode">
        <div class="text-editor-wrapper">
          <ConfigEditor bind:content={textContent} errors={[]} on:save={() => save()} on:cancel={() => dispatch('close')} />
        </div>
      </section>
    {/if}

    {#if errors.length > 0}
      <div class="errors">
        {#each errors as err}<p>{err}</p>{/each}
      </div>
    {/if}

    <div class="modal-footer">
      <button class="btn btn-save" on:click={save}>{$t('new_tunnel.create')}</button>
      <button class="btn btn-cancel" on:click={() => dispatch('close')}>{$t('new_tunnel.cancel')}</button>
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
    padding: 24px;
    width: 560px;
    max-height: 85vh;
    overflow-y: auto;
  }
  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }
  h3 { margin: 0; color: var(--text-primary); }
  .mode-tabs {
    display: flex;
    gap: 4px;
    background: var(--bg-card);
    border-radius: 6px;
    padding: 2px;
  }
  .mode-tabs button {
    padding: 4px 12px;
    background: transparent;
    border: none;
    border-radius: 4px;
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
  }
  .mode-tabs button.active {
    background: var(--accent);
    color: var(--text-primary);
  }
  h4 {
    margin: 16px 0 8px;
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--border);
  }
  section { margin-bottom: 12px; }
  .text-mode {
    margin-top: 12px;
  }
  .text-editor-wrapper {
    height: 400px;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }
  label {
    display: block;
    margin: 10px 0 4px;
    font-size: 11px;
    color: var(--text-secondary);
  }
  input[type="text"] {
    width: 100%;
    padding: 6px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-primary);
    font-size: 13px;
    font-family: monospace;
    box-sizing: border-box;
  }
  input[type="text"]:focus {
    outline: none;
    border-color: var(--accent);
  }
  .key-row {
    display: flex;
    gap: 4px;
  }
  .key-row input { flex: 1; }
  .btn-gen {
    padding: 6px 12px;
    background: var(--accent);
    border: none;
    border-radius: 4px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 12px;
    white-space: nowrap;
  }
  .row-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }
  .errors {
    margin-top: 12px;
    padding: 8px 12px;
    background: var(--error-bg);
    border: 1px solid var(--red);
    border-radius: 6px;
  }
  .errors p { margin: 2px 0; color: var(--red); font-size: 12px; }
  .modal-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-top: 16px;
  }
  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
  }
  .btn-save { background: var(--green); color: var(--text-inverse); }
  .btn-cancel { background: var(--bg-card); color: var(--text-primary); border: 1px solid var(--border); }
</style>

<script>
  import { createEventDispatcher } from 'svelte';
  import SplitTunnelUI from './SplitTunnelUI.svelte';

  export let TunnelService;
  const dispatch = createEventDispatcher();

  let name = '';
  let privateKey = '';
  let publicKeyHint = '';
  let address = '10.0.0.2/24';
  let dns = '1.1.1.1';
  let mtu = '';
  let peerPublicKey = '';
  let peerEndpoint = '';
  let peerPSK = '';
  let allowedIPs = ['0.0.0.0/0', '::/0'];
  let keepalive = '';
  let errors = [];
  let generating = false;

  async function generateKey() {
    generating = true;
    errors = [];
    try {
      // Use Web Crypto to generate a random 32-byte key (placeholder)
      // Proper Curve25519 is done server-side, but we need the private key here
      // For now, we'll build the .conf with a placeholder and let validation guide
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      // WireGuard key clamping
      bytes[0] &= 248;
      bytes[31] &= 127;
      bytes[31] |= 64;
      privateKey = btoa(String.fromCharCode(...bytes));
      publicKeyHint = '(computed on save)';
    } catch (e) {
      errors = ['Key generation failed: ' + e.toString()];
    }
    generating = false;
  }

  function buildConfText() {
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

  async function save() {
    errors = [];
    if (!name.trim()) {
      errors = ['Tunnel name is required'];
      return;
    }
    if (!privateKey) {
      errors = ['Private key is required (generate one or paste)'];
      return;
    }
    if (!peerPublicKey) {
      errors = ['Peer public key is required'];
      return;
    }

    const content = buildConfText();
    try {
      const validationErrors = await TunnelService.ValidateConfig(content);
      if (validationErrors && validationErrors.length > 0) {
        errors = validationErrors;
        return;
      }
      await TunnelService.ImportConfig(name, content);
      dispatch('save', { name, content });
    } catch (e) {
      errors = [e.toString()];
    }
  }

  function updateAllowedIPs(e) {
    allowedIPs = e.detail;
  }
</script>

<div class="modal-backdrop" on:click={() => dispatch('close')}>
  <div class="modal" on:click|stopPropagation>
    <h3>New Tunnel</h3>

    <section>
      <label>Tunnel Name *</label>
      <input type="text" bind:value={name} placeholder="my-vpn" />
    </section>

    <section>
      <h4>Interface</h4>

      <label>Private Key *</label>
      <div class="key-row">
        <input type="text" bind:value={privateKey} placeholder="Generate or paste base64 key" />
        <button class="btn-gen" on:click={generateKey} disabled={generating}>Generate</button>
      </div>

      <label>Address *</label>
      <input type="text" bind:value={address} placeholder="10.0.0.2/24" />

      <div class="row-2">
        <div>
          <label>DNS</label>
          <input type="text" bind:value={dns} placeholder="1.1.1.1" />
        </div>
        <div>
          <label>MTU</label>
          <input type="text" bind:value={mtu} placeholder="1420" />
        </div>
      </div>
    </section>

    <section>
      <h4>Peer</h4>

      <label>Public Key *</label>
      <input type="text" bind:value={peerPublicKey} placeholder="base64 peer public key" />

      <label>Endpoint</label>
      <input type="text" bind:value={peerEndpoint} placeholder="vpn.example.com:51820" />

      <label>Preshared Key (optional)</label>
      <input type="text" bind:value={peerPSK} placeholder="base64 preshared key" />

      <label>AllowedIPs</label>
      <SplitTunnelUI {allowedIPs} on:change={updateAllowedIPs} />

      <label>Persistent Keepalive (seconds, optional)</label>
      <input type="text" bind:value={keepalive} placeholder="25" />
    </section>

    {#if errors.length > 0}
      <div class="errors">
        {#each errors as err}<p>{err}</p>{/each}
      </div>
    {/if}

    <div class="modal-footer">
      <button class="btn btn-save" on:click={save}>Create</button>
      <button class="btn btn-cancel" on:click={() => dispatch('close')}>Cancel</button>
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
    width: 520px;
    max-height: 85vh;
    overflow-y: auto;
  }
  h3 { margin: 0 0 16px; }
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
  .key-row input {
    flex: 1;
  }
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
  .errors p { margin: 2px 0; color: #ff7675; font-size: 12px; }
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
  .btn-save { background: var(--green); color: #fff; }
  .btn-save:hover { background: #00a884; }
  .btn-cancel { background: var(--bg-card); color: var(--text-primary); }
</style>

<script>
  import { t } from '../i18n/index.js';

  let privateKey = '';
  let publicKey = '';
  let generated = false;
  let copied = false;

  // Generate keys via Go backend — for now use JS placeholder
  // In production, this calls TunnelService.GenerateKeyPair()
  async function generate() {
    // Placeholder: real implementation would call Go backend
    // For now, generate random base64 strings for UI demo
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    privateKey = btoa(String.fromCharCode(...bytes));

    // Derive "public key" — proper Curve25519 done in Go backend
    crypto.getRandomValues(bytes);
    publicKey = btoa(String.fromCharCode(...bytes));

    generated = true;
    copied = false;
  }

  async function copyPublicKey() {
    try {
      await navigator.clipboard.writeText(publicKey);
      copied = true;
      setTimeout(() => copied = false, 2000);
    } catch (e) {
      console.error('clipboard copy failed:', e);
    }
  }
</script>

<div class="keygen">
  <button class="btn-generate" on:click={generate}>
    Generate Key Pair
  </button>

  {#if generated}
    <div class="key-display">
      <div class="key-row">
        <label>Private Key</label>
        <code class="key-value private">{privateKey.substring(0, 20)}...</code>
      </div>
      <div class="key-row">
        <label>Public Key</label>
        <code class="key-value" on:click={copyPublicKey}>
          {publicKey}
        </code>
        <span class="copy-hint">{copied ? 'Copied!' : 'Click to copy'}</span>
      </div>
    </div>
  {/if}
</div>

<style>
  .keygen { margin: 12px 0; }
  .btn-generate {
    padding: 8px 16px;
    background: var(--accent);
    border: none;
    border-radius: 6px;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 13px;
  }
  .btn-generate:hover { opacity: 0.9; }
  .key-display { margin-top: 12px; }
  .key-row {
    margin-bottom: 8px;
  }
  .key-row label {
    display: block;
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    margin-bottom: 2px;
  }
  .key-value {
    display: block;
    padding: 8px;
    background: var(--bg-card);
    border-radius: 4px;
    font-size: 12px;
    color: var(--text-primary);
    word-break: break-all;
    cursor: pointer;
  }
  .key-value.private {
    color: var(--text-muted);
    cursor: default;
  }
  .copy-hint {
    font-size: 11px;
    color: var(--green);
    margin-top: 2px;
    display: block;
  }
</style>

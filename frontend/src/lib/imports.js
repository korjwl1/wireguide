import { diagText } from './wireguard-lint.js';

export const MAX_CONFIG_BYTES = 1 << 20;
export const MAX_ZIP_BYTES = 32 << 20;
export const MAX_QR_BYTES = 8 << 20;

export function sanitizeImportName(raw) {
  let name = (raw || '').replace(/[^A-Za-z0-9_ -]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[-\s]+|[-\s]+$/g, '')
    .slice(0, 64).replace(/[-\s]+$/g, '') || 'tunnel';
  if (/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i.test(name)) name = `tunnel-${name}`;
  return name;
}

export async function uniqueImportName(raw, exists) {
  const base = sanitizeImportName(raw);
  if (!(await exists(base))) return base;
  for (let i = 1; i < 1000; i++) {
    const suffix = `-${i}`;
    const candidate = base.slice(0, 64 - suffix.length) + suffix;
    if (!(await exists(candidate))) return candidate;
  }
  throw new Error('Too many tunnels with this name; choose another name');
}

export function checkImportSize(file, limit) {
  if (file.size > limit) throw new Error(`File too large (max ${limit} bytes)`);
}

// Wails represents []byte as base64. Chunk conversion to avoid argument-stack
// overflow, and reject oversized Files before allocating their ArrayBuffer.
export async function fileBase64(file, limit) {
  checkImportSize(file, limit);
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > limit) throw new Error(`File too large (max ${limit} bytes)`);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
}

/**
 * Joined, translated text of the cross-tunnel duplicate-Address warnings in a
 * list of Go Diagnostics (TunnelInfo.Warnings / ZipImportResult.Warnings).
 * Other diagnostics are only shown inside the editor. Returns '' when none.
 */
export function warningText(diagnostics, tr) {
  return (diagnostics || [])
    .filter((d) => d && d.code === 'address_shared')
    .map((d) => diagText(d, tr))
    .join('; ');
}

/** Toast text after a successful import, with any warning appended. */
export function importedMessage(name, diagnostics, tr) {
  const warning = warningText(diagnostics, tr);
  return warning
    ? tr('app.imported_with_warning', { name, warning })
    : tr('app.imported', { name });
}

/**
 * True when a DisconnectTunnel error only means "already disconnected".
 *
 * The IPC layer has no dedicated error code for this case, so this matches the
 * helper's message text, "tunnel %q is not connected" (internal/tunnel
 * manager.go, ErrNotConnected). TestDisconnectNotConnectedMessage pins that
 * text; change both together.
 */
export function isNotConnectedError(message) {
  return /is not connected/i.test(message || '');
}

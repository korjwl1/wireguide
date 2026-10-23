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

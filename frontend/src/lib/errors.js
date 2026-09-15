// errText normalises error values coming out of Wails RPC.
// Wails errors can be Error objects, plain strings, or structured
// `{code, message}` payloads depending on which layer failed. A naive
// `e.toString()` returns "[object Object]" on the last case — use this
// helper everywhere instead.
export function errText(e) {
  // Some native Wails transport failures wrap the structured error in a
  // string (occasionally inside Error.message). Unwrap only error-shaped
  // payloads, leaving ordinary text/JSON untouched. Bound nested wrappers.
  for (let depth = 0; depth < 4 && e; depth++) {
    if (typeof e === 'string') {
      try {
        const parsed = JSON.parse(e);
        if (parsed && typeof parsed === 'object' && (parsed.message || parsed.error)) {
          e = parsed;
          continue;
        }
      } catch { /* Plain error text. */ }
      return e;
    }
    if (e.message || e.error) {
      e = e.message || e.error;
      continue;
    }
    break;
  }
  if (!e) return 'unknown error';
  if (typeof e === 'string') return e;
  if (e.message) return e.message;
  if (e.error) return e.error;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

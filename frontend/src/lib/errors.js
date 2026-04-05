// errText normalises error values coming out of Wails RPC.
// Wails errors can be Error objects, plain strings, or structured
// `{code, message}` payloads depending on which layer failed. A naive
// `e.toString()` returns "[object Object]" on the last case — use this
// helper everywhere instead.
export function errText(e) {
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

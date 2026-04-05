import { writable, get } from 'svelte/store';

// User-selected theme preference. One of: 'dark' | 'light' | 'system'.
// `system` follows the OS via prefers-color-scheme.
export const theme = writable('system');

// Actually rendered theme (concrete: 'dark' or 'light'). Components that
// need to react to theme at runtime (e.g. CodeMirror) subscribe to this,
// not to `theme`, so that they don't have to repeat the system→concrete
// resolution themselves.
export const resolvedTheme = writable('dark');

function resolve(name) {
  if (name === 'dark' || name === 'light') return name;
  // system
  if (typeof window === 'undefined' || !window.matchMedia) return 'dark';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

// applyTheme is the single entry point for theme changes. Called once at
// startup with the persisted setting, and again whenever the user picks a
// new value in Settings. Writes both the store and the `data-theme`
// attribute (which the CSS variable selectors key off of).
export function applyTheme(name) {
  theme.set(name);
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', name);
  }
  resolvedTheme.set(resolve(name));
}

// initThemeWatcher hooks into the OS media query so a user sitting on
// `system` gets instant updates when they toggle macOS dark mode etc.
// Safe to call multiple times — the listener is attached once.
let watcherInstalled = false;
export function initThemeWatcher() {
  if (watcherInstalled || typeof window === 'undefined' || !window.matchMedia) return;
  watcherInstalled = true;
  const mql = window.matchMedia('(prefers-color-scheme: dark)');
  const update = () => {
    if (get(theme) === 'system') {
      resolvedTheme.set(mql.matches ? 'dark' : 'light');
    }
  };
  // Some very old WebKits only support addListener; fall back if needed.
  if (mql.addEventListener) mql.addEventListener('change', update);
  else mql.addListener(update);
}

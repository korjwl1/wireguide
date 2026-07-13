import { writable } from 'svelte/store';

// compactList mirrors the persisted Settings.compact_list flag. It's a
// shared store so the Settings toggle updates the tunnel list live
// (App.onMount seeds it from GetSettings; Settings writes it on change;
// TunnelList subscribes for the `compact` class).
export const compactList = writable(false);

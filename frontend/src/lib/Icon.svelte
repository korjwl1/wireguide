<script>
  // Lucide-compatible SVG icon component.
  // All paths are from Lucide Icons (MIT license) — inlined to avoid
  // an npm dependency and extra bundle weight in the Wails WebKit shell.
  export let name;
  export let size = 16;
  export let strokeWidth = 1.75;
  export let className = '';

  // Map of icon name → raw SVG inner HTML (paths/shapes only, no <svg> wrapper).
  // viewBox is always "0 0 24 24", stroke="currentColor", fill="none".
  const icons = {
    'shield':
      `<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>`,

    'shield-off':
      `<path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18"/>` +
      `<path d="M4.73 4.73 4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38"/>` +
      `<line x1="2" x2="22" y1="2" y2="22"/>`,

    'clock':
      `<circle cx="12" cy="12" r="10"/>` +
      `<polyline points="12 6 12 12 16 14"/>`,

    'wrench':
      `<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>`,

    'terminal':
      `<polyline points="4 17 10 11 4 5"/>` +
      `<line x1="12" x2="20" y1="19" y2="19"/>`,

    'settings':
      `<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>` +
      `<circle cx="12" cy="12" r="3"/>`,

    'wifi':
      `<path d="M5 12.55a11 11 0 0 1 14.08 0"/>` +
      `<path d="M1.42 9a16 16 0 0 1 21.16 0"/>` +
      `<path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>` +
      `<line x1="12" x2="12.01" y1="20" y2="20"/>`,

    'pencil':
      `<path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/>` +
      `<path d="m15 5 4 4"/>`,

    'plus':
      `<path d="M5 12h14"/>` +
      `<path d="M12 5v14"/>`,

    'download':
      `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>` +
      `<polyline points="7 10 12 15 17 10"/>` +
      `<line x1="12" x2="12" y1="15" y2="3"/>`,

    'upload':
      `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>` +
      `<polyline points="17 8 12 3 7 8"/>` +
      `<line x1="12" x2="12" y1="3" y2="15"/>`,

    'check':
      `<path d="M20 6 9 17l-5-5"/>`,

    'x':
      `<path d="M18 6 6 18"/>` +
      `<path d="m6 6 12 12"/>`,

    'triangle-alert':
      `<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>` +
      `<path d="M12 9v4"/>` +
      `<path d="M12 17h.01"/>`,

    'arrow-down':
      `<path d="M12 5v14"/>` +
      `<path d="m19 12-7 7-7-7"/>`,

    'arrow-up':
      `<path d="M12 19V5"/>` +
      `<path d="m5 12 7-7 7 7"/>`,

    'trash-2':
      `<path d="M3 6h18"/>` +
      `<path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>` +
      `<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>` +
      `<line x1="10" x2="10" y1="11" y2="17"/>` +
      `<line x1="14" x2="14" y1="11" y2="17"/>`,

    'file-pen':
      `<path d="M12 22h6a2 2 0 0 0 2-2V7l-5-5H6a2 2 0 0 0-2 2v10"/>` +
      `<path d="M14 2v4a2 2 0 0 0 2 2h4"/>` +
      `<path d="M10.4 19.4 8 22l-4-1 .9-2.4"/>` +
      `<path d="m15.5 15.5-4.2 4.2"/>`,

    'share':
      `<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/>` +
      `<polyline points="16 6 12 2 8 6"/>` +
      `<line x1="12" x2="12" y1="2" y2="15"/>`,

    'activity':
      `<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>`,

    'network':
      `<rect x="16" y="16" width="6" height="6" rx="1"/>` +
      `<rect x="2" y="16" width="6" height="6" rx="1"/>` +
      `<rect x="9" y="2" width="6" height="6" rx="1"/>` +
      `<path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/>` +
      `<path d="M12 12V8"/>`,

    'chevron-right':
      `<path d="m9 18 6-6-6-6"/>`,

    'chevron-down':
      `<path d="m6 9 6 6 6-6"/>`,

    'search':
      `<circle cx="11" cy="11" r="8"/>` +
      `<path d="m21 21-4.3-4.3"/>`,

    'info':
      `<circle cx="12" cy="12" r="10"/>` +
      `<path d="M12 16v-4"/>` +
      `<path d="M12 8h.01"/>`,

    'zap':
      `<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>`,

    'globe':
      `<circle cx="12" cy="12" r="10"/>` +
      `<path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/>` +
      `<path d="M2 12h20"/>`,

    'lock':
      `<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>` +
      `<path d="M7 11V7a5 5 0 0 1 10 0v4"/>`,

    'unlock':
      `<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>` +
      `<path d="M7 11V7a5 5 0 0 1 9.9-1"/>`,

    'eye':
      `<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>` +
      `<circle cx="12" cy="12" r="3"/>`,

    'copy':
      `<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>` +
      `<path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>`,

    'rotate-ccw':
      `<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>` +
      `<path d="M3 3v5h5"/>`,

    'log-out':
      `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>` +
      `<polyline points="16 17 21 12 16 7"/>` +
      `<line x1="21" x2="9" y1="12" y2="12"/>`,
  };

  $: svgContent = icons[name] || '';
</script>

<!--
  Inline SVG icon. The `{@html ...}` injection is safe here because
  svgContent is always pulled from the hardcoded icons map above —
  it is never built from user input.
-->
<svg
  class="icon {className}"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width={strokeWidth}
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  focusable="false"
>{@html svgContent}</svg>

<style>
  .icon {
    display: inline-block;
    vertical-align: middle;
    flex-shrink: 0;
  }
</style>

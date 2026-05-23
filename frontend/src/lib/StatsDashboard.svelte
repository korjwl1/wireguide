<script>
  import { onMount, onDestroy } from 'svelte';
  import { connectionStatus } from '../stores/tunnels.js';
  import { resolvedTheme } from '../stores/theme.js';
  import { t } from '../i18n/index.js';

  let canvas;
  let ctx;
  // Ring buffer of throughput samples. Same pattern as stores/logs.js:
  // pre-allocate the array, write at `head`, wrap on cap. The previous
  // `samples = [...samples, x].slice(-60)` rebuilt the entire 60-element
  // array on every 1Hz status tick, churning the GC. With the ring we
  // only mutate one slot per tick.
  const maxSamples = 60;
  const samplesBuf = new Array(maxSamples);
  let samplesHead = 0;
  let samplesCount = 0;
  let samplesVersion = 0; // bump on every push so reactivity fires
  // Cache the resolved palette so we don't getComputedStyle on every draw.
  // Refreshed on theme change via the resolvedTheme subscription below.
  let palette = null;

  function refreshPalette() {
    if (typeof document === 'undefined') return;
    const css = getComputedStyle(document.documentElement);
    palette = {
      rxStroke: css.getPropertyValue('--stats-rx').trim() || '#00b894',
      txStroke: css.getPropertyValue('--stats-tx').trim() || '#74b9ff',
      rxFill:   css.getPropertyValue('--stats-rx-fill').trim() || 'rgba(0, 184, 148, 0.2)',
      txFill:   css.getPropertyValue('--stats-tx-fill').trim() || 'rgba(116, 185, 255, 0.2)',
      textMuted:     css.getPropertyValue('--text-muted').trim() || '#555',
      textSecondary: css.getPropertyValue('--text-secondary').trim() || '#666',
    };
  }

  // Resize observer so the canvas redraws when the panel is resized
  // without piggy-backing on rAF.
  let resizeObs;

  onMount(() => {
    ctx = canvas.getContext('2d');
    refreshPalette();
    draw();
    if (typeof ResizeObserver !== 'undefined') {
      resizeObs = new ResizeObserver(() => draw());
      resizeObs.observe(canvas);
    }
  });

  // Refresh palette + repaint when the theme flips.
  const unsubTheme = resolvedTheme.subscribe(() => {
    refreshPalette();
    if (ctx) draw();
  });

  onDestroy(() => {
    unsubTheme();
    if (resizeObs) resizeObs.disconnect();
  });

  // Collect samples from status polling. Drawing is driven by data arrival
  // (1 Hz from the helper broadcast) — NOT by rAF — so the renderer can
  // actually idle between samples. Previously self-scheduling rAF burned
  // 3-6% CPU painting the same pixels 60×/sec.
  //
  // Ring-buffer push: O(1), zero allocations on the steady-state path
  // (the buffer is pre-allocated). samplesVersion increments so Svelte's
  // reference-equality check on the reactive statement fires — without
  // that the same store value would suppress the re-render.
  $: if ($connectionStatus?.state === 'connected') {
    samplesBuf[samplesHead] = {
      rx: $connectionStatus.rx_bytes || 0,
      tx: $connectionStatus.tx_bytes || 0,
      time: Date.now(),
    };
    samplesHead = (samplesHead + 1) % maxSamples;
    if (samplesCount < maxSamples) samplesCount++;
    samplesVersion++;
    if (ctx) draw();
  }

  // orderedSamples returns the samples in chronological order (oldest
  // first). Called only by draw(); allocates a single Array(samplesCount)
  // per draw, much less than the per-push slice(-60) we used to do.
  function orderedSamples() {
    if (samplesCount === 0) return [];
    if (samplesCount < maxSamples) {
      // Buffer hasn't wrapped yet — entries 0..samplesCount-1 are in
      // insertion order.
      return samplesBuf.slice(0, samplesCount);
    }
    // Wrapped: oldest is at samplesHead, newest at samplesHead-1.
    return samplesBuf.slice(samplesHead).concat(samplesBuf.slice(0, samplesHead));
  }

  function draw() {
    if (!ctx) return;
    if (!palette) refreshPalette();
    const w = canvas.width = canvas.offsetWidth * 2;
    const h = canvas.height = canvas.offsetHeight * 2;
    ctx.scale(2, 2);
    const cw = w / 2;
    const ch = h / 2;

    ctx.clearRect(0, 0, cw, ch);

    const { rxStroke, txStroke, rxFill, txFill, textMuted, textSecondary } = palette;
    const samples = orderedSamples();

    if (samples.length < 2) {
      ctx.fillStyle = textMuted;
      ctx.font = '13px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText($t('stats.waiting'), cw / 2, ch / 2);
      return;
    }

    // Calculate speeds
    let speeds = [];
    for (let i = 1; i < samples.length; i++) {
      const dt = (samples[i].time - samples[i-1].time) / 1000;
      if (dt <= 0) continue;
      speeds.push({
        rx: Math.max(0, (samples[i].rx - samples[i-1].rx) / dt),
        tx: Math.max(0, (samples[i].tx - samples[i-1].tx) / dt),
      });
    }

    if (speeds.length === 0) return;

    const maxSpeed = Math.max(
      ...speeds.map(s => Math.max(s.rx, s.tx)),
      1024 // minimum 1 KB/s scale
    );

    const padding = { top: 10, right: 10, bottom: 20, left: 10 };
    const gw = cw - padding.left - padding.right;
    const gh = ch - padding.top - padding.bottom;
    const step = gw / (maxSamples - 1);

    // X coordinate of the i-th sample. Samples are right-aligned: if we
    // only have 5 samples in a 60-slot window, they pack against the right
    // edge of the graph so the chart "fills up from the right" as data
    // accumulates — matches Activity Monitor / iStat's convention.
    const sx = (i) => padding.left + (i + maxSamples - speeds.length) * step;
    const ry = (v) => padding.top + gh - (v / maxSpeed) * gh;

    // Draws one data series: a filled area under the line, then the line
    // itself on top. IMPORTANT: the filled area is a polygon whose two
    // baseline endpoints sit DIRECTLY under the first and last sample, not
    // at the chart corners. Anchoring to (0,0) and (gw, 0) produced the
    // ugly triangular sweep from the bottom-left corner to the first
    // sample that showed up at startup.
    const drawSeries = (field, fillStyle, strokeStyle) => {
      if (speeds.length < 1) return;

      const firstX = sx(0);
      const lastX = sx(speeds.length - 1);
      const baseY = ch - padding.bottom;

      // Filled area
      ctx.beginPath();
      ctx.moveTo(firstX, baseY);
      for (let i = 0; i < speeds.length; i++) {
        ctx.lineTo(sx(i), ry(speeds[i][field]));
      }
      ctx.lineTo(lastX, baseY);
      ctx.closePath();
      ctx.fillStyle = fillStyle;
      ctx.fill();

      // Line on top (separate path so the closing segment along the
      // baseline isn't stroked — otherwise we'd see a hard horizontal line
      // under the chart).
      ctx.beginPath();
      ctx.moveTo(sx(0), ry(speeds[0][field]));
      for (let i = 1; i < speeds.length; i++) {
        ctx.lineTo(sx(i), ry(speeds[i][field]));
      }
      ctx.strokeStyle = strokeStyle;
      ctx.lineWidth = 1.5;
      ctx.lineJoin = 'round';
      ctx.stroke();
    };

    drawSeries('rx', rxFill, rxStroke);
    drawSeries('tx', txFill, txStroke);

    // Scale label
    ctx.fillStyle = textSecondary;
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(formatSpeed(maxSpeed), cw - padding.right, padding.top + 12);

    // Legend
    ctx.textAlign = 'left';
    ctx.fillStyle = rxStroke;
    ctx.fillText('↓ RX', padding.left, ch - 4);
    ctx.fillStyle = txStroke;
    ctx.fillText('↑ TX', padding.left + 50, ch - 4);
  }

  function formatSpeed(bytesPerSec) {
    if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
    if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
    return (bytesPerSec / 1024 / 1024).toFixed(1) + ' MB/s';
  }
</script>

<div class="stats-dashboard">
  <h4>{$t('stats.speed_graph')}</h4>
  <div class="graph-container">
    <canvas bind:this={canvas}></canvas>
  </div>
</div>

<style>
  .stats-dashboard { padding: 8px 0; }
  h4 {
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }
  .graph-container {
    background: var(--graph-bg);
    border-radius: 8px;
    height: 150px;
    overflow: hidden;
  }
  canvas {
    width: 100%;
    height: 100%;
  }
</style>

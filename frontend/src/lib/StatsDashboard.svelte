<script>
  import { onMount, onDestroy } from 'svelte';
  import { connectionStatus } from '../stores/tunnels.js';
  import { t } from '../i18n/index.js';

  let canvas;
  let ctx;
  let samples = [];
  const maxSamples = 60;
  let animFrame;

  onMount(() => {
    ctx = canvas.getContext('2d');
    draw();
  });

  onDestroy(() => {
    if (animFrame) cancelAnimationFrame(animFrame);
  });

  // Collect samples from status polling
  $: if ($connectionStatus?.state === 'connected') {
    samples = [...samples, {
      rx: $connectionStatus.rx_bytes || 0,
      tx: $connectionStatus.tx_bytes || 0,
      time: Date.now()
    }].slice(-maxSamples);
  }

  function draw() {
    if (!ctx) return;
    const w = canvas.width = canvas.offsetWidth * 2;
    const h = canvas.height = canvas.offsetHeight * 2;
    ctx.scale(2, 2);
    const cw = w / 2;
    const ch = h / 2;

    ctx.clearRect(0, 0, cw, ch);

    // Pull palette from CSS variables so the canvas respects the current
    // theme. getComputedStyle is cheap at 1 Hz and means we don't have to
    // re-subscribe to the theme store inside the draw loop.
    const css = getComputedStyle(document.documentElement);
    const rxStroke = css.getPropertyValue('--stats-rx').trim() || '#00b894';
    const txStroke = css.getPropertyValue('--stats-tx').trim() || '#74b9ff';
    const rxFill = css.getPropertyValue('--stats-rx-fill').trim() || 'rgba(0, 184, 148, 0.2)';
    const txFill = css.getPropertyValue('--stats-tx-fill').trim() || 'rgba(116, 185, 255, 0.2)';
    const textMuted = css.getPropertyValue('--text-muted').trim() || '#555';
    const textSecondary = css.getPropertyValue('--text-secondary').trim() || '#666';

    if (samples.length < 2) {
      ctx.fillStyle = textMuted;
      ctx.font = '13px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Waiting for data...', cw / 2, ch / 2);
      animFrame = requestAnimationFrame(draw);
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

    if (speeds.length === 0) {
      animFrame = requestAnimationFrame(draw);
      return;
    }

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

    animFrame = requestAnimationFrame(draw);
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

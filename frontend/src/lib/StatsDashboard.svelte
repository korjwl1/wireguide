<script>
  import { onMount, onDestroy } from 'svelte';
  import { connectionStatus } from '../stores/tunnels.js';

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

    if (samples.length < 2) {
      ctx.fillStyle = '#555';
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

    // Draw RX (green, filled)
    ctx.beginPath();
    ctx.moveTo(padding.left, ch - padding.bottom);
    speeds.forEach((s, i) => {
      const x = padding.left + (i + maxSamples - speeds.length) * step;
      const y = padding.top + gh - (s.rx / maxSpeed) * gh;
      ctx.lineTo(x, y);
    });
    ctx.lineTo(padding.left + gw, ch - padding.bottom);
    ctx.closePath();
    ctx.fillStyle = 'rgba(0, 184, 148, 0.2)';
    ctx.fill();
    ctx.strokeStyle = '#00b894';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Draw TX (blue, filled)
    ctx.beginPath();
    ctx.moveTo(padding.left, ch - padding.bottom);
    speeds.forEach((s, i) => {
      const x = padding.left + (i + maxSamples - speeds.length) * step;
      const y = padding.top + gh - (s.tx / maxSpeed) * gh;
      ctx.lineTo(x, y);
    });
    ctx.lineTo(padding.left + gw, ch - padding.bottom);
    ctx.closePath();
    ctx.fillStyle = 'rgba(116, 185, 255, 0.2)';
    ctx.fill();
    ctx.strokeStyle = '#74b9ff';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Scale label
    ctx.fillStyle = '#666';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(formatSpeed(maxSpeed), cw - padding.right, padding.top + 12);

    // Legend
    ctx.textAlign = 'left';
    ctx.fillStyle = '#00b894';
    ctx.fillText('↓ RX', padding.left, ch - 4);
    ctx.fillStyle = '#74b9ff';
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
  <h4>Speed Graph</h4>
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
    background: #0a0a18;
    border-radius: 8px;
    height: 150px;
    overflow: hidden;
  }
  canvas {
    width: 100%;
    height: 100%;
  }
</style>

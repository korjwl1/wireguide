import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tunnelStatus, tunnelState, connectedTunnelNames } from './tunnel-state.js';

test('connected indicators exclude pending and teardown intent', () => {
  const status = {
    state: 'connecting', tunnel_name: 'pending',
    active_tunnels: ['pending', 'up', 'leaving'],
    tunnels: [
      { tunnel_name: 'pending', state: 'connecting' },
      { tunnel_name: 'up', state: 'connected', rx_bytes: 42 },
      { tunnel_name: 'leaving', state: 'disconnecting' },
    ],
  };
  assert.deepEqual(connectedTunnelNames(status), ['up']);
  assert.equal(tunnelState(status, 'pending'), 'connecting');
  assert.equal(tunnelState(status, 'leaving'), 'disconnecting');
  assert.equal(tunnelStatus(status, 'up').rx_bytes, 42);
  assert.equal(tunnelStatus(status, 'missing'), null);
});

test('single-tunnel compatibility requires matching name and connected state', () => {
  assert.deepEqual(connectedTunnelNames({ state: 'connected', tunnel_name: 'solo' }), ['solo']);
  assert.deepEqual(connectedTunnelNames({ state: 'connecting', tunnel_name: 'solo' }), []);
  assert.equal(tunnelState({ state: 'connected', tunnel_name: 'solo' }, 'other'), 'disconnected');
  assert.deepEqual(connectedTunnelNames(null), []);
});

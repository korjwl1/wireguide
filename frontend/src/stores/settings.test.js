import { test } from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'svelte/store';
import { loadSettings, patchSettings, settingsErrors } from './settings.js';

test('settings writes serialize and preserve errors belonging to other fields', async () => {
  settingsErrors.set({});
  let active = 0;
  let maximum = 0;
  const calls = [];
  const service = {
    async UpdateSettings(patch) {
      active++;
      maximum = Math.max(maximum, active);
      calls.push(patch);
      await new Promise(resolve => setImmediate(resolve));
      active--;
      if (patch.kill_switch) throw new Error('live apply failed');
    },
  };
  const security = patchSettings(service, { kill_switch: true });
  const theme = patchSettings(service, { theme: 'dark' });
  await assert.rejects(security, /live apply failed/);
  await theme;
  assert.equal(maximum, 1);
  assert.deepEqual(calls, [{ kill_switch: true }, { theme: 'dark' }]);
  assert.match(get(settingsErrors).kill_switch, /live apply failed/);
  await patchSettings(service, { kill_switch: false });
  assert.deepEqual(get(settingsErrors), {});
});

test('unavailable settings never become an editable default snapshot', async () => {
  await assert.rejects(loadSettings({ GetSettings: async () => null }), /unavailable/);
  await assert.rejects(loadSettings({ GetSettings: async () => { throw new Error('permission denied'); } }), /permission denied/);
});

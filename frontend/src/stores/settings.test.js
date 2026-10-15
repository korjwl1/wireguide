import { test } from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'svelte/store';
import { loadSettings, patchSettings, settingsErrors, settingRetryValue } from './settings.js';

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


test('retry preserves the requested value from another view after persistence fails', async () => {
  settingsErrors.set({});
  const calls = [];
  let fails = true;
  const service = { async UpdateSettings(patch) {
    calls.push({...patch});
    if (fails) throw new Error('disk write failed');
  }};
  const preference = {list_pane_width:333};
  await assert.rejects(patchSettings(service,preference), /disk write failed/);
  preference.list_pane_width = 444;
  assert.equal(settingRetryValue('list_pane_width'),333);
  fails = false;
  await patchSettings(service,{list_pane_width:settingRetryValue('list_pane_width')});
  assert.deepEqual(calls,[{list_pane_width:333},{list_pane_width:333}]);
  assert.deepEqual(get(settingsErrors),{});
  await assert.rejects(patchSettings(service,{list_pane_width:undefined}), /missing value/);
  assert.equal(calls.length,2);
});

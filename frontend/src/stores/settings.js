import { writable } from 'svelte/store';
import { errText } from '../lib/errors.js';

export const settingsErrors = writable({});
let writes = Promise.resolve();
// Keep the last requested scalar per field, including edits from other views.
const requestedValues = new Map();
export function settingRetryValue(key) { return requestedValues.get(key); }

export async function loadSettings(service) {
  const value = await service.GetSettings();
  if (!value) throw new Error('Settings are unavailable');
  return value;
}

// Every view submits its own changed fields. Serialize live apply requests,
// retaining failures by field so an unrelated success cannot hide them.
export function patchSettings(service, patch) {
  const snapshot = { ...patch };
  if (Object.values(snapshot).some(value => value === undefined)) {
    return Promise.reject(new Error('A settings patch contains a missing value'));
  }
  for (const [key, value] of Object.entries(snapshot)) requestedValues.set(key, value);
  const next = writes.then(async () => {
    try {
      await service.UpdateSettings(snapshot);
      settingsErrors.update(errors => {
        const result = { ...errors };
        for (const key of Object.keys(snapshot)) delete result[key];
        return result;
      });
    } catch (error) {
      settingsErrors.update(errors => {
        const result = { ...errors };
        for (const key of Object.keys(snapshot)) result[key] = errText(error);
        return result;
      });
      throw error;
    }
  });
  writes = next.catch(() => {});
  return next;
}

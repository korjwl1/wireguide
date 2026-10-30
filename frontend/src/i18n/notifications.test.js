import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const langs = ['en', 'ko', 'ja', 'zh'];
const load = (lang) => JSON.parse(readFileSync(new URL(`./${lang}.json`, import.meta.url), 'utf8'));

test('notification strings exist in every language', () => {
  for (const lang of langs) {
    const messages = load(lang);
    for (const key of ['section_notifications', 'notify_auto_changes', 'notify_auto_changes_hint']) {
      assert.ok(messages.settings[key], `${lang}: settings.${key}`);
    }
    assert.match(messages.app.automation_connected, /\{name\}/, `${lang}: app.automation_connected`);
  }
  // Localized, not an English copy.
  for (const lang of langs.slice(1)) {
    assert.notEqual(load(lang).settings.notify_auto_changes, load('en').settings.notify_auto_changes);
  }
});

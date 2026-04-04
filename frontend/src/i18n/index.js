import en from './en.json';
import ko from './ko.json';
import ja from './ja.json';

const translations = { en, ko, ja };
let currentLang = 'en';

export function detectLanguage() {
  const nav = navigator.language || 'en';
  const short = nav.split('-')[0];
  if (translations[short]) return short;
  return 'en';
}

export function setLanguage(lang) {
  if (translations[lang]) {
    currentLang = lang;
  }
}

export function getLanguage() {
  return currentLang;
}

export function t(key, params = {}) {
  const keys = key.split('.');
  let value = translations[currentLang];
  for (const k of keys) {
    if (value && typeof value === 'object') {
      value = value[k];
    } else {
      return key;
    }
  }
  if (typeof value !== 'string') return key;
  // Replace {param} placeholders
  return value.replace(/\{(\w+)\}/g, (_, name) => params[name] ?? `{${name}}`);
}

// Initialize with detected language
currentLang = detectLanguage();

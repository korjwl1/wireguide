<script>
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import { EditorView, keymap, lineNumbers, highlightActiveLine } from '@codemirror/view';
  import { EditorState, Compartment } from '@codemirror/state';
  import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
  import { oneDark } from '@codemirror/theme-one-dark';
  import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
  import { tags as tg } from '@lezer/highlight';
  import { autocompletion } from '@codemirror/autocomplete';
  import { wireguardLanguage, wireguardCompletion } from './wireguard-lang.js';
  import { resolvedTheme } from '../stores/theme.js';
  import { t } from '../i18n/index.js';

  // Unified config editor: handles both "new" and "edit" modes.
  // - isNew=true: shows name input, generates template with random private key
  // - isNew=false: shows name as editable field, content pre-filled
  export let content = '';
  export let errors = [];
  export let name = '';
  export let isNew = false;
  export let nameEditable = true;

  const dispatch = createEventDispatcher();

  // Generate a random WireGuard private key (Curve25519 clamped)
  function generatePrivateKey() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return btoa(String.fromCharCode(...bytes));
  }

  // Build default template for new configs with auto-generated private key
  function buildNewTemplate() {
    const key = generatePrivateKey();
    return `[Interface]
PrivateKey = ${key}
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey =
Endpoint =
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
  }

  if (isNew && !content) {
    content = buildNewTemplate();
  }
  let editorContainer;
  let view;

  // The theme extension lives in a Compartment so we can reconfigure it at
  // runtime when the user toggles light/dark. Without the compartment we'd
  // have to destroy and recreate the entire EditorView on every theme flip,
  // losing undo history and selection.
  const themeCompartment = new Compartment();

  // Lightweight inline light theme — we avoid pulling in another npm dep
  // just for a light CodeMirror palette. These values read directly from
  // the same CSS variables that the rest of the UI uses, so "light" in
  // the editor actually matches "light" in the surrounding chrome.
  //
  // IMPORTANT: oneDark bundles syntax highlighting with its appearance, so
  // simply replacing it in the Compartment drops ALL syntax colours in light
  // mode. We therefore pair our light appearance with an explicit
  // HighlightStyle that maps the Lezer tags our wireguard grammar produces
  // (and common fallbacks) onto GitHub-ish light colours.
  const lightHighlight = HighlightStyle.define([
    { tag: tg.keyword,      color: '#cf222e', fontWeight: '600' }, // [Interface] / [Peer]
    { tag: tg.propertyName, color: '#953800' },                    // PrivateKey / PublicKey / ...
    { tag: tg.string,       color: '#0a3069' },
    { tag: tg.number,       color: '#0550ae' },
    { tag: tg.comment,      color: '#6e7781', fontStyle: 'italic' },
    { tag: tg.operator,     color: '#0550ae' },
    { tag: tg.variableName, color: '#0a3069' },
    { tag: tg.atom,         color: '#0550ae' },
  ]);
  const lightAppearance = EditorView.theme(
    {
      '&': {
        backgroundColor: 'var(--editor-bg)',
        color: 'var(--text-primary)',
      },
      '.cm-content': { caretColor: 'var(--accent)' },
      '.cm-activeLine': { backgroundColor: 'var(--bg-hover)' },
      '.cm-activeLineGutter': { backgroundColor: 'var(--bg-hover)' },
      '.cm-selectionBackground, &.cm-focused .cm-selectionBackground, .cm-content ::selection': {
        backgroundColor: 'var(--blue-tint)',
      },
    },
    { dark: false }
  );
  // lightTheme is an array of extensions — Compartment.of() accepts any
  // Extension, and an array is itself an Extension in CodeMirror.
  const lightTheme = [lightAppearance, syntaxHighlighting(lightHighlight)];

  function themeExt(resolved) {
    return resolved === 'light' ? lightTheme : oneDark;
  }

  // Re-dispatch CodeMirror theme whenever resolvedTheme changes.
  const unsubTheme = resolvedTheme.subscribe((resolved) => {
    if (view) {
      view.dispatch({ effects: themeCompartment.reconfigure(themeExt(resolved)) });
    }
  });

  onMount(() => {
    const initial = typeof document !== 'undefined'
      ? document.documentElement.getAttribute('data-theme')
      : 'dark';
    // We don't know the resolved value at mount time without subscribing
    // to the store synchronously; use a safe default and let the
    // subscription above reconfigure on first tick if it differs.
    const initialThemeExt = themeExt(initial === 'light' ? 'light' : 'dark');

    const state = EditorState.create({
      doc: content,
      extensions: [
        lineNumbers(),
        highlightActiveLine(),
        history(),
        keymap.of([indentWithTab, ...defaultKeymap, ...historyKeymap]),
        wireguardLanguage,
        autocompletion({ override: [wireguardCompletion] }),
        themeCompartment.of(initialThemeExt),
        EditorView.theme({
          '&': { height: '100%', fontSize: '13px' },
          '.cm-content': { fontFamily: 'monospace' },
          '.cm-gutters': {
            background: 'var(--editor-gutter-bg)',
            borderRight: '1px solid var(--editor-border)',
          },
        }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            content = update.state.doc.toString();
          }
        }),
      ],
    });

    view = new EditorView({
      state,
      parent: editorContainer,
    });
  });

  onDestroy(() => {
    unsubTheme();
    if (view) view.destroy();
  });

  // Update editor content when prop changes externally
  $: if (view && content !== view.state.doc.toString()) {
    view.dispatch({
      changes: { from: 0, to: view.state.doc.length, insert: content }
    });
  }

  function save() {
    dispatch('save', { name: name.trim(), content });
  }

  function cancel() {
    dispatch('cancel');
  }
</script>

<div class="editor-wrapper">
  <div class="editor-toolbar">
    {#if nameEditable}
      <input
        class="name-input"
        type="text"
        bind:value={name}
        placeholder={$t('editor.name_placeholder')}
      />
    {:else}
      <span class="editor-title">{name || $t('editor.title', { name: '' })}</span>
    {/if}
    <div class="editor-actions">
      <button class="editor-btn editor-btn-ghost" on:click={cancel}>{$t('editor.cancel')}</button>
      <button class="editor-btn editor-btn-primary" on:click={save}>{$t('editor.save')}</button>
    </div>
  </div>

  <div class="editor-container" bind:this={editorContainer}></div>

  {#if errors.length > 0}
    <div class="editor-errors">
      {#each errors as err}
        <p>{err}</p>
      {/each}
    </div>
  {/if}
</div>

<style>
  .editor-wrapper {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: var(--bg-primary);
  }
  .editor-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-bottom: 0.5px solid var(--border);
    background: var(--bg-secondary);
    flex-shrink: 0;
  }
  .editor-title {
    flex: 1;
    font: 600 14px/18px var(--font-sans);
    color: var(--text-primary);
    letter-spacing: -0.005em;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .name-input {
    flex: 1;
    height: 32px;
    padding: 0 12px;
    font: 600 14px/18px var(--font-sans);
    letter-spacing: -0.005em;
    color: var(--text-primary);
    background: var(--bg-card);
    border: 0.5px solid var(--border);
    border-radius: 8px;
    min-width: 0;
    outline: none;
    box-sizing: border-box;
  }
  @media (prefers-reduced-motion: no-preference) {
    .name-input {
      transition: border-color 140ms ease, box-shadow 140ms ease, background 140ms ease;
    }
  }
  .name-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
    background: var(--bg-primary);
  }
  .editor-actions {
    display: flex;
    gap: 8px;
    flex-shrink: 0;
  }
  .editor-container {
    flex: 1;
    overflow: auto;
    min-height: 0;
  }
  .editor-container :global(.cm-editor) {
    height: 100%;
  }
  .editor-errors {
    padding: 10px 16px;
    background: var(--error-bg);
    border-top: 0.5px solid var(--red);
    flex-shrink: 0;
    max-height: 100px;
    overflow-y: auto;
  }
  .editor-errors p {
    margin: 3px 0;
    color: var(--error-text);
    font: 12px/16px var(--font-sans);
  }

  /* Toolbar buttons — gradient primary + ghost cancel */
  .editor-btn {
    height: 32px;
    min-width: 72px;
    padding: 0 14px;
    border: 0;
    border-radius: 9px;
    font: 600 13px/18px var(--font-sans);
    letter-spacing: -0.005em;
    cursor: pointer;
    color: var(--text-primary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  @media (prefers-reduced-motion: no-preference) {
    .editor-btn {
      transition: filter 140ms ease, background-color 140ms ease,
                  border-color 140ms ease, transform 140ms ease, box-shadow 140ms ease;
    }
  }
  .editor-btn-primary {
    background: var(--accent);
    color: #fff;
    box-shadow:
      0 1px 3px color-mix(in srgb, var(--accent) 26%, transparent),
      0 1px 2px rgba(0,0,0,0.08);
  }
  .editor-btn-primary:hover {
    background: color-mix(in srgb, #fff 8%, var(--accent));
    transform: translateY(-1px);
    box-shadow:
      0 4px 10px color-mix(in srgb, var(--accent) 30%, transparent),
      0 1px 2px rgba(0,0,0,0.10);
  }
  .editor-btn-primary:active {
    background: color-mix(in srgb, #000 8%, var(--accent));
    transform: translateY(0);
  }

  .editor-btn-ghost {
    background: var(--bg-card);
    border: 0.5px solid var(--border);
  }
  .editor-btn-ghost:hover {
    background: var(--bg-hover);
    border-color: color-mix(in srgb, var(--accent) 30%, var(--border));
  }
  .editor-btn-ghost:active { background: var(--bg-active); }
</style>

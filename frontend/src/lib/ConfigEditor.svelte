<script>
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import { EditorView, keymap, lineNumbers, highlightActiveLine } from '@codemirror/view';
  import { EditorState, Compartment } from '@codemirror/state';
  import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
  import { oneDark } from '@codemirror/theme-one-dark';
  import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
  import { tags as tg } from '@lezer/highlight';
  import { autocompletion } from '@codemirror/autocomplete';
  import { wireguardLanguage, wireguardCompletion } from './wireguard-lang.js';
  import { resolvedTheme } from '../stores/theme.js';
  import { t } from '../i18n/index.js';

  export let content = '';
  export let errors = [];

  const dispatch = createEventDispatcher();
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
        keymap.of([...defaultKeymap, ...historyKeymap]),
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
    dispatch('save', content);
  }

  function cancel() {
    dispatch('cancel');
  }
</script>

<div class="editor-wrapper">
  <div class="editor-toolbar">
    <span class="editor-title">{$t('editor.title', { name: '' })}</span>
    <div class="editor-actions">
      <button class="btn btn-save" on:click={save}>{$t('editor.save')}</button>
      <button class="btn btn-cancel" on:click={cancel}>{$t('editor.cancel')}</button>
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
  }
  .editor-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
  }
  .editor-title {
    font-size: 14px;
    color: var(--text-secondary);
  }
  .editor-actions {
    display: flex;
    gap: 8px;
  }
  .editor-container {
    flex: 1;
    overflow: auto;
  }
  .editor-container :global(.cm-editor) {
    height: 100%;
  }
  .editor-errors {
    padding: 8px 12px;
    background: var(--error-bg);
    border-top: 1px solid var(--red);
  }
  .editor-errors p {
    margin: 4px 0;
    color: var(--error-text);
    font-size: 13px;
  }
  .btn {
    padding: 6px 14px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
    color: var(--text-primary);
  }
  .btn-save { background: var(--green); color: var(--text-inverse); }
  .btn-save:hover { opacity: 0.9; }
  .btn-cancel { background: var(--bg-card); border: 1px solid var(--border); }
  .btn-cancel:hover { background: var(--bg-hover); }
</style>

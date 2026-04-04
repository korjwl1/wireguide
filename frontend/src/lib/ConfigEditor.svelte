<script>
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import { EditorView, keymap, lineNumbers, highlightActiveLine } from '@codemirror/view';
  import { EditorState } from '@codemirror/state';
  import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
  import { oneDark } from '@codemirror/theme-one-dark';
  import { autocompletion } from '@codemirror/autocomplete';
  import { wireguardLanguage, wireguardCompletion } from './wireguard-lang.js';
  import { t } from '../i18n/index.js';

  export let content = '';
  export let errors = [];

  const dispatch = createEventDispatcher();
  let editorContainer;
  let view;

  onMount(() => {
    const state = EditorState.create({
      doc: content,
      extensions: [
        lineNumbers(),
        highlightActiveLine(),
        history(),
        keymap.of([...defaultKeymap, ...historyKeymap]),
        wireguardLanguage,
        autocompletion({ override: [wireguardCompletion] }),
        oneDark,
        EditorView.theme({
          '&': { height: '100%', fontSize: '13px' },
          '.cm-content': { fontFamily: 'monospace' },
          '.cm-gutters': { background: '#0d0d1a', borderRight: '1px solid #2a2a4a' },
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
    <span class="editor-title">{t('editor.title', { name: '' })}</span>
    <div class="editor-actions">
      <button class="btn btn-save" on:click={save}>{t('editor.save')}</button>
      <button class="btn btn-cancel" on:click={cancel}>{t('editor.cancel')}</button>
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
    border-bottom: 1px solid #2a2a4a;
  }
  .editor-title {
    font-size: 14px;
    color: #8888aa;
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
    background: #d6303122;
    border-top: 1px solid #d63031;
  }
  .editor-errors p {
    margin: 4px 0;
    color: #ff7675;
    font-size: 13px;
  }
  .btn {
    padding: 6px 14px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
    color: #e0e0e0;
  }
  .btn-save { background: #00b894; color: #fff; }
  .btn-save:hover { background: #00a884; }
  .btn-cancel { background: #2a2a4a; }
  .btn-cancel:hover { background: #3a3a5a; }
</style>

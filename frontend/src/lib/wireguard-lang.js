import { StreamLanguage } from '@codemirror/language';
import { snippet } from '@codemirror/autocomplete';
import { linter } from '@codemirror/lint';
import { hoverTooltip } from '@codemirror/view';
import {
  mapDiagnostics, fixChanges, fixLabel,
  dnsValueContext, dnsCompletionOptions, dnsHoverAt, dnsHoverText,
} from './wireguard-lint.js';

// WireGuard .conf syntax highlighting
const wireguardMode = {
  startState() {
    return { section: null };
  },
  token(stream, state) {
    // Skip whitespace
    if (stream.eatSpace()) return null;

    // Comments
    if (stream.match(/^[#;].*/)) return 'comment';

    // Section headers
    if (stream.match(/^\[Interface\]/i)) {
      state.section = 'interface';
      return 'heading';
    }
    if (stream.match(/^\[Peer\]/i)) {
      state.section = 'peer';
      return 'heading';
    }

    // Key = Value pairs
    if (stream.match(/^(PrivateKey|PublicKey|PresharedKey)\s*=/)) {
      return 'keyword';
    }
    if (stream.match(/^(Address|DNS|MTU|ListenPort|Table|FwMark)\s*=/)) {
      return 'keyword';
    }
    if (stream.match(/^(Endpoint|AllowedIPs|PersistentKeepalive)\s*=/)) {
      return 'keyword';
    }
    if (stream.match(/^(PreUp|PostUp|PreDown|PostDown)\s*=/)) {
      return 'atom'; // Highlight scripts differently (warning color)
    }

    // Values after = sign
    if (stream.match(/^=\s*/)) return 'operator';

    // Split-DNS routing domains in DNS= lists: ~corp.example
    if (stream.match(/^~[A-Za-z0-9][A-Za-z0-9.-]*/)) return 'string';

    // IP addresses / CIDR
    if (stream.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?/)) return 'number';

    // Port numbers
    if (stream.match(/^:\d+/)) return 'number';

    // Base64 keys (44 chars)
    if (stream.match(/^[A-Za-z0-9+/]{43}=/)) return 'string';

    // List separators (DNS = 1.1.1.1, ~corp.lan): keep tokenizing the line
    if (stream.match(/^,\s*/)) return null;

    // Consume rest of line
    stream.skipToEnd();
    return null;
  }
};

export const wireguardLanguage = StreamLanguage.define(wireguardMode);

// Autocompletion
const interfaceKeys = [
  'PrivateKey', 'Address', 'DNS', 'MTU', 'ListenPort',
  'Table', 'FwMark', 'PreUp', 'PostUp', 'PreDown', 'PostDown'
];

const peerKeys = [
  'PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'
];

const sections = ['[Interface]', '[Peer]'];

// Identity translator: used when no i18n function is supplied (labels then
// show their keys, which is only ever visible in tests).
const identityTr = (key) => key;

/**
 * Completion for `DNS = ` values: the `~` split-DNS snippet, gateway
 * candidates, derived reverse zones and a whole-line template.
 */
function dnsValueCompletion(context, line, lineBefore, tr) {
  const ctx = dnsValueContext(lineBefore);
  if (!ctx) return null;
  const doc = context.state.doc.toString();
  const options = dnsCompletionOptions(doc, tr, { valueEmpty: ctx.valueEmpty, token: ctx.token }).map((o) => {
    const opt = {
      label: o.label,
      type: o.kind === 'tilde' ? 'keyword' : o.kind === 'line' ? 'text' : 'constant',
      detail: o.detail,
    };
    if (o.info) opt.info = o.info;
    if (o.kind === 'tilde') {
      opt.apply = snippet(o.insert);
    } else if (o.kind === 'line') {
      // Replace the whole (empty) value, not just the current token.
      opt.apply = (view, _completion, _from, to) => {
        view.dispatch({
          changes: { from: line.from + ctx.valueStart, to, insert: o.insert },
          selection: { anchor: line.from + ctx.valueStart + o.insert.length },
        });
      };
    } else {
      opt.apply = o.insert;
    }
    return opt;
  });
  return {
    from: line.from + ctx.tokenStart,
    options,
    // Options are prefix-filtered in dnsCompletionOptions; re-run the source
    // on every keystroke instead of letting CodeMirror fuzzy-filter.
    filter: false,
  };
}

/** Build the CodeMirror completion source. `tr(key, params)` translates. */
export function createWireguardCompletion(tr = identityTr) {
  return function wireguardCompletionSource(context) {
    const line = context.state.doc.lineAt(context.pos);
    const lineBefore = line.text.substring(0, context.pos - line.from);

    // Value completion after `DNS =` must work even with nothing typed yet.
    const dnsResult = dnsValueCompletion(context, line, lineBefore, tr);
    if (dnsResult) return dnsResult;

    const before = context.matchBefore(/\w*/);
    if (!before || (before.from === before.to && !context.explicit)) return null;

    // If line is empty or starts with [, suggest sections
    if (lineBefore.trim() === '' || lineBefore.startsWith('[')) {
      return {
        from: before.from,
        options: sections.map(s => ({ label: s, type: 'keyword' }))
      };
    }

    // Check which section we're in
    let inPeer = false;
    for (let i = line.number - 1; i >= 1; i--) {
      const prevLine = context.state.doc.line(i).text.trim().toLowerCase();
      if (prevLine === '[peer]') { inPeer = true; break; }
      if (prevLine === '[interface]') { inPeer = false; break; }
    }

    const keys = inPeer ? peerKeys : interfaceKeys;
    return {
      from: before.from,
      options: keys.map(k => ({ label: k + ' = ', type: 'property', apply: k + ' = ' }))
    };
  };
}

export const wireguardCompletion = createWireguardCompletion();

/**
 * Lint extension. `lintFn(text)` resolves to the Go diagnostics
 * (TunnelService.LintConfig); failures yield no diagnostics.
 */
export function wireguardLinter(lintFn, tr = identityTr) {
  return linter(async (view) => {
    const text = view.state.doc.toString();
    let diagnostics;
    try {
      diagnostics = await lintFn(text);
    } catch (e) {
      return [];
    }
    // The document moved on while the call was in flight; the next lint
    // pass will report against the current text.
    if (view.state.doc.toString() !== text) return [];
    return mapDiagnostics(text, diagnostics, tr).map((d) => ({
      from: d.from,
      to: d.to,
      severity: d.severity,
      message: d.message,
      actions: d.fix ? [{
        name: fixLabel(d.fix, tr),
        apply(v) {
          const changes = fixChanges(v.state.doc.toString(), d.fix);
          if (changes) v.dispatch({ changes });
        },
      }] : undefined,
    }));
  }, { delay: 600 });
}

/** Hover tooltips on the `DNS` key and on `~domain` tokens. */
export function wireguardHover(tr = identityTr) {
  return hoverTooltip((view, pos) => {
    const line = view.state.doc.lineAt(pos);
    const hit = dnsHoverAt(line.text, pos - line.from);
    if (!hit) return null;
    return {
      pos: line.from + hit.from,
      end: line.from + hit.to,
      above: true,
      create() {
        const dom = document.createElement('div');
        dom.className = 'cm-wg-hover';
        for (const p of dnsHoverText(hit, tr)) {
          const para = document.createElement('p');
          if (p.strong) {
            const b = document.createElement('strong');
            b.textContent = p.strong + ' ';
            para.appendChild(b);
          }
          para.appendChild(document.createTextNode(p.text));
          dom.appendChild(para);
        }
        return { dom };
      },
    };
  });
}

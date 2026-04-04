import { StreamLanguage } from '@codemirror/language';

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

    // IP addresses / CIDR
    if (stream.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?/)) return 'number';

    // Port numbers
    if (stream.match(/^:\d+/)) return 'number';

    // Base64 keys (44 chars)
    if (stream.match(/^[A-Za-z0-9+/]{43}=/)) return 'string';

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

export function wireguardCompletion(context) {
  const before = context.matchBefore(/\w*/);
  if (!before || (before.from === before.to && !context.explicit)) return null;

  const line = context.state.doc.lineAt(context.pos);
  const lineText = line.text.substring(0, context.pos - line.from);

  // If line is empty or starts with [, suggest sections
  if (lineText.trim() === '' || lineText.startsWith('[')) {
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
}

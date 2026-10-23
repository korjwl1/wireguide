// Shared dialog behavior keeps keyboard focus inside the topmost modal.
const dialogs = [];
export function modal(node, close) {
  const previous = document.activeElement;
  dialogs.push(node);
  node.tabIndex = -1;
  const focusable = () => [...node.querySelectorAll('button, [href], input, select, textarea, [tabindex]')]
    .filter(el => !el.matches(':disabled') && el.tabIndex >= 0 && el.getClientRects().length > 0);
  queueMicrotask(() => { if (node.isConnected) (focusable()[0] || node).focus(); });
  function keydown(event) {
    if (dialogs.at(-1) !== node) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopImmediatePropagation();
      close?.();
    } else if (event.key === 'Tab') {
      const items = focusable();
      const index = items.indexOf(document.activeElement);
      if (!items.length || (event.shiftKey ? index <= 0 : index === items.length - 1 || index < 0)) {
        event.preventDefault();
        (event.shiftKey ? items.at(-1) || node : items[0] || node).focus();
      }
    }
  }
  node.addEventListener('keydown', keydown, true);
  return { update(value) { close = value; }, destroy() {
    node.removeEventListener('keydown', keydown, true);
    const index = dialogs.indexOf(node);
    if (index >= 0) dialogs.splice(index, 1);
    if (previous?.isConnected) previous.focus();
  }};
}

// The backdrop closes only when directly clicked, preserving child controls.
export function backdrop(node, close) {
  const click = event => { if (event.target === node) close?.(); };
  node.addEventListener('click', click);
  return { update(value) { close = value; }, destroy() { node.removeEventListener('click', click); } };
}

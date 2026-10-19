// Own a component's event subscriptions, including registrations attempted
// after asynchronous startup has outlived the component.
export function createEventScope(subscribe, onError = console.error) {
  let disposed = false;
  const cleanups = [];
  return {
    get disposed() { return disposed; },
    on(name, handler) {
      if (disposed) return;
      const off = subscribe(name, (...args) => {
        if (disposed) return;
        try {
          const result = handler(...args);
          if (result?.catch) result.catch(onError);
        } catch (error) {
          onError(error);
        }
      });
      cleanups.push(off);
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      for (const off of cleanups.splice(0)) {
        try { off(); } catch (error) { onError(error); }
      }
    },
  };
}

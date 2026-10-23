// Serialize each profile's field writes and coalesce duplicate pending saves.
// A failed write does not prevent a later retry or another profile's save.
export function createFieldWriter(write, saved, failed) {
  const pending = new Map();
  return (name, value) => {
    if (!name) return Promise.resolve(false);
    const previous = pending.get(name);
    if (previous?.value === value) return previous.promise;
    const entry = { value };
    entry.promise = (previous?.promise || Promise.resolve()).then(async () => {
      try {
        await write(name, value);
        saved(name, value);
        return true;
      } catch (error) {
        failed(name, error);
        return false;
      } finally {
        if (pending.get(name) === entry) pending.delete(name);
      }
    });
    pending.set(name, entry);
    return entry.promise;
  };
}

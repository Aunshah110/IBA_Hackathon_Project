/* =========================================================
   GSDS Offline Queue
   Stores pending inspection events in IndexedDB.
   Flushes to /api/sync on reconnect. Idempotent via client_uuid.
   ========================================================= */
(function () {
  const DB_NAME = 'gsds';
  const DB_VERSION = 1;
  const STORE = 'pending_events';

  let _db = null;

  function open() {
    return new Promise((resolve, reject) => {
      if (_db) return resolve(_db);
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE, { keyPath: 'client_uuid' });
        }
      };
      req.onsuccess = () => { _db = req.result; resolve(_db); };
      req.onerror = () => reject(req.error);
    });
  }

  async function put(event) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(event);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
    });
  }

  async function all() {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }

  async function remove(uuid) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).delete(uuid);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
    });
  }

  async function count() {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  async function flush() {
    if (!navigator.onLine) return { flushed: 0, remaining: await count() };
    const events = await all();
    if (!events.length) return { flushed: 0, remaining: 0 };

    try {
      const res = await fetch('/api/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ events }),
      });
      if (!res.ok) throw new Error('sync http ' + res.status);
      const data = await res.json();

      for (const r of (data.results || [])) {
        if (r.status === 'accepted' || r.status === 'duplicate') {
          await remove(r.uuid);
        }
        // 'rejected' stays queued — user must review. Could also add a
        // permanent-fail store; for now, leave in queue and surface count.
      }
      const remaining = await count();
      window.GSDS = window.GSDS || {};
      window.GSDS.toast && window.GSDS.toast(
        'Synced', `${data.results.length - remaining} of ${data.results.length} events`,
        'ok'
      );
      return { flushed: data.results.length, remaining };
    } catch (e) {
      return { flushed: 0, remaining: await count(), error: String(e) };
    }
  }

  // Auto-flush on reconnect and on load
  window.addEventListener('online', () => flush());
  document.addEventListener('DOMContentLoaded', () => {
    if (navigator.onLine) flush();
    // Show pending count in topbar if the slot exists
    updatePendingBadge();
    setInterval(updatePendingBadge, 5000);
  });

  async function updatePendingBadge() {
    const el = document.getElementById('pendingCount');
    if (!el) return;
    const n = await count();
    el.textContent = n ? `${n} pending` : '';
    el.style.display = n ? 'inline-flex' : 'none';
  }

  window.GSDSQueue = { put, all, remove, count, flush, uuid };
})();
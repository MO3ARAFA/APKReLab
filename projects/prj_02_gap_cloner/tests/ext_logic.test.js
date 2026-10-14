// Node test for db.js using a tiny in-memory IndexedDB fake.
// Usage: node tests/ext_logic.test.js <path-to-db.js>
const assert = require('assert');

const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));

function makeFakeIDB() {
  const dbs = {};
  class Tx {
    constructor(db) { this.db = db; this.pending = 0; this.finished = false; this.oncomplete = null; setTimeout(() => this._check(), 0); }
    _check() { if (this.pending <= 0 && !this.finished) { this.finished = true; this.oncomplete && this.oncomplete(); } }
    _req(fn) {
      this.pending++;
      const req = { onsuccess: null, onerror: null };
      setTimeout(() => {
        try { req.result = fn(); } catch (e) { req.error = e; req.onerror && req.onerror(); }
        if (!req.error) req.onsuccess && req.onsuccess();
        this.pending--;
        setTimeout(() => this._check(), 0); // handlers may have queued more requests
      }, 0);
      return req;
    }
    objectStore(name) {
      const st = this.db.stores[name];
      return {
        put: (v) => this._req(() => { st.data.set(v[st.keyPath], clone(v)); return v[st.keyPath]; }),
        get: (k) => this._req(() => clone(st.data.get(k))),
        getAll: () => this._req(() => [...st.data.values()].map(clone)),
        delete: (k) => this._req(() => { st.data.delete(k); }),
        count: () => this._req(() => st.data.size),
      };
    }
  }
  return {
    open(name) {
      const req = { onupgradeneeded: null, onsuccess: null, onerror: null, onblocked: null };
      setTimeout(() => {
        let db = dbs[name]; const fresh = !db;
        if (fresh) db = dbs[name] = { stores: {}, close() {} };
        db.createObjectStore = (n, o) => { db.stores[n] = { keyPath: o.keyPath, data: new Map() }; return { createIndex() {} }; };
        db.transaction = () => new Tx(db);
        req.result = db;
        if (fresh) req.onupgradeneeded && req.onupgradeneeded();
        req.onsuccess && req.onsuccess();
      }, 0);
      return req;
    },
  };
}

globalThis.indexedDB = makeFakeIDB();
const CRMDB = require(require('path').resolve(process.argv[2]));
const H = CRMDB.helpers;

async function main() {
  // --- pure helpers
  assert.strictEqual(H.nextBackoff(1), 30000);
  assert.strictEqual(H.nextBackoff(3), 120000);
  assert.strictEqual(H.nextBackoff(50), 6 * 3600 * 1000, 'backoff is capped');
  assert.strictEqual(H.extractEmail('contact: jane.doe+crm@acme.io today'), 'jane.doe+crm@acme.io');
  assert.deepStrictEqual(H.parseTags(' Hot, hot ,Q4,, '), ['hot', 'q4']);
  assert.strictEqual(H.csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"', 'CSV formula injection neutralised');
  const n = H.normalizeClip({ name: ' Ann ', stage: 'bogus', tags: 'a,b', selection: 'mail me at x@y.com' });
  assert.strictEqual(n.stage, 'lead'); assert.strictEqual(n.email, 'x@y.com'); assert.strictEqual(n.synced, 0);
  const p = H.buildWebhookPayload(n);
  assert.strictEqual(p.event, 'clip.created'); assert.strictEqual(p.clip.id, n.id);

  // --- IndexedDB flows
  assert.strictEqual(await CRMDB.getSetting('webhookUrl', 'dflt'), 'dflt', 'missing setting returns fallback');
  await CRMDB.setSetting('webhookUrl', 'https://hook.test/x');
  assert.strictEqual(await CRMDB.getSetting('webhookUrl', ''), 'https://hook.test/x');

  const a = await CRMDB.addClip({ name: 'Ann', company: 'Acme', notes: 'first' });
  const b = await CRMDB.addClip({ name: 'Bob', company: 'Globex', notes: 'second' });
  assert.strictEqual(await CRMDB.pendingCount(), 2);
  assert.strictEqual((await CRMDB.listClips({})).length, 2);
  assert.strictEqual((await CRMDB.listClips({ query: 'globex' })).length, 1);
  assert.strictEqual((await CRMDB.dueOutbox(Date.now())).length, 2);

  await CRMDB.markSynced(a.id);
  assert.strictEqual(await CRMDB.pendingCount(), 1);
  assert.strictEqual((await CRMDB.getClip(a.id)).synced, 1);

  await CRMDB.markFailed(b.id, 'HTTP 500');
  assert.strictEqual((await CRMDB.dueOutbox(Date.now())).length, 0, 'failed item is backed off');
  assert.strictEqual((await CRMDB.dueOutbox(Date.now() + 31000)).length, 1, 'retried after backoff');

  await CRMDB.deleteClip(b.id);
  assert.strictEqual(await CRMDB.pendingCount(), 0);
  assert.strictEqual((await CRMDB.listClips({})).length, 1);
  console.log('ext_logic: all assertions passed');
}
main().catch((e) => { console.error(e); process.exit(1); });

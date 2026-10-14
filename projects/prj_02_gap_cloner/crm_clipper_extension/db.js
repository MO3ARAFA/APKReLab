/* Offline CRM Clipper - IndexedDB layer + pure helpers.
 * Loaded by the service worker via importScripts('db.js') and by popup.html via <script>.
 * Exposes `CRMDB` on the global scope (and module.exports for Node-based tests). */
(function (root) {
  'use strict';

  var DB_NAME = 'crm_clipper';
  var DB_VERSION = 1;
  var MAX_BACKOFF_MS = 6 * 60 * 60 * 1000; // 6h
  var BASE_BACKOFF_MS = 30 * 1000;
  var dbPromise = null;

  // ---------- pure helpers (unit-tested in Node, no IndexedDB needed) ----------
  function uuid() {
    if (root.crypto && root.crypto.randomUUID) return root.crypto.randomUUID();
    return 'id-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  }

  function nextBackoff(attempts) {
    var exp = Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * Math.pow(2, Math.max(0, attempts - 1)));
    return exp;
  }

  function csvCell(v) {
    var s = v === null || v === undefined ? '' : String(v);
    // Neutralise spreadsheet formula injection, then quote.
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  var CSV_FIELDS = ['id', 'name', 'company', 'email', 'stage', 'tags', 'notes', 'title', 'url', 'selection', 'createdAt', 'synced'];

  function toCSV(clips) {
    var rows = [CSV_FIELDS.join(',')];
    clips.forEach(function (c) {
      rows.push(CSV_FIELDS.map(function (f) {
        var v = c[f];
        if (Array.isArray(v)) v = v.join('; ');
        return csvCell(v);
      }).join(','));
    });
    return rows.join('\r\n');
  }

  function extractEmail(text) {
    var m = /[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i.exec(text || '');
    return m ? m[0] : '';
  }

  function parseTags(s) {
    return String(s || '').split(',').map(function (t) { return t.trim().toLowerCase(); })
      .filter(function (t, i, a) { return t && a.indexOf(t) === i; }).slice(0, 20);
  }

  function normalizeClip(input) {
    var now = Date.now();
    var stages = ['lead', 'contacted', 'qualified', 'won', 'lost'];
    var stage = stages.indexOf(input.stage) >= 0 ? input.stage : 'lead';
    return {
      id: input.id || uuid(),
      name: String(input.name || '').trim().slice(0, 200),
      company: String(input.company || '').trim().slice(0, 200),
      email: String(input.email || extractEmail(input.selection) || '').trim().slice(0, 254),
      stage: stage,
      tags: Array.isArray(input.tags) ? input.tags : parseTags(input.tags),
      notes: String(input.notes || '').slice(0, 5000),
      title: String(input.title || '').slice(0, 500),
      url: String(input.url || '').slice(0, 2000),
      selection: String(input.selection || '').slice(0, 5000),
      createdAt: input.createdAt || now,
      updatedAt: now,
      synced: 0 // 0 = pending, 1 = delivered (numeric so it can be indexed)
    };
  }

  function buildWebhookPayload(clip) {
    return {
      event: 'clip.created',
      version: 1,
      sentAt: new Date().toISOString(),
      clip: {
        id: clip.id, name: clip.name, company: clip.company, email: clip.email, stage: clip.stage,
        tags: clip.tags, notes: clip.notes, title: clip.title, url: clip.url, selection: clip.selection,
        createdAt: new Date(clip.createdAt).toISOString()
      }
    };
  }

  // ---------- IndexedDB ----------
  function openDB() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise(function (resolve, reject) {
      var req = root.indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function () {
        var db = req.result;
        var clips = db.createObjectStore('clips', { keyPath: 'id' });
        clips.createIndex('createdAt', 'createdAt');
        clips.createIndex('url', 'url');
        clips.createIndex('synced', 'synced');
        var outbox = db.createObjectStore('outbox', { keyPath: 'clipId' });
        outbox.createIndex('nextAttemptAt', 'nextAttemptAt');
        db.createObjectStore('meta', { keyPath: 'key' });
      };
      req.onsuccess = function () {
        var db = req.result;
        db.onversionchange = function () { db.close(); dbPromise = null; };
        resolve(db);
      };
      req.onerror = function () { dbPromise = null; reject(req.error); };
      req.onblocked = function () { reject(new Error('IndexedDB upgrade blocked by another tab')); };
    });
    return dbPromise;
  }

  function tx(stores, mode, fn) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var t = db.transaction(stores, mode);
        var result;
        try { result = fn(t); } catch (e) { reject(e); return; }
        t.oncomplete = function () { resolve(result && Object.prototype.hasOwnProperty.call(result, '__value') ? result.__value : result); };
        t.onerror = function () { reject(t.error); };
        t.onabort = function () { reject(t.error || new Error('transaction aborted')); };
      });
    });
  }

  function reqValue(req) {
    var box = { __value: undefined };
    req.onsuccess = function () { box.__value = req.result; };
    return box;
  }

  function addClip(input) {
    var clip = normalizeClip(input);
    return tx(['clips', 'outbox'], 'readwrite', function (t) {
      t.objectStore('clips').put(clip);
      t.objectStore('outbox').put({ clipId: clip.id, attempts: 0, nextAttemptAt: 0, lastError: '' });
    }).then(function () { return clip; });
  }

  function getClip(id) {
    return tx(['clips'], 'readonly', function (t) { return reqValue(t.objectStore('clips').get(id)); });
  }

  function listClips(opts) {
    opts = opts || {};
    var q = (opts.query || '').toLowerCase();
    var limit = opts.limit || 50;
    return tx(['clips'], 'readonly', function (t) {
      return reqValue(t.objectStore('clips').getAll());
    }).then(function (all) {
      return all.filter(function (c) {
        if (!q) return true;
        return [c.name, c.company, c.email, c.title, c.notes, (c.tags || []).join(' ')].join(' ').toLowerCase().indexOf(q) >= 0;
      }).sort(function (a, b) { return b.createdAt - a.createdAt; }).slice(0, limit);
    });
  }

  function deleteClip(id) {
    return tx(['clips', 'outbox'], 'readwrite', function (t) {
      t.objectStore('clips').delete(id);
      t.objectStore('outbox').delete(id);
    });
  }

  function dueOutbox(now) {
    now = now || Date.now();
    return tx(['outbox'], 'readonly', function (t) {
      return reqValue(t.objectStore('outbox').getAll());
    }).then(function (items) {
      return items.filter(function (i) { return i.nextAttemptAt <= now; });
    });
  }

  function pendingCount() {
    return tx(['outbox'], 'readonly', function (t) { return reqValue(t.objectStore('outbox').count()); });
  }

  function markSynced(clipId) {
    return tx(['clips', 'outbox'], 'readwrite', function (t) {
      var store = t.objectStore('clips');
      var g = store.get(clipId);
      g.onsuccess = function () {
        if (g.result) { g.result.synced = 1; g.result.updatedAt = Date.now(); store.put(g.result); }
      };
      t.objectStore('outbox').delete(clipId);
    });
  }

  function markFailed(clipId, errorMessage) {
    return tx(['outbox'], 'readwrite', function (t) {
      var store = t.objectStore('outbox');
      var g = store.get(clipId);
      g.onsuccess = function () {
        var item = g.result || { clipId: clipId, attempts: 0 };
        item.attempts += 1;
        item.lastError = String(errorMessage || 'error').slice(0, 300);
        item.nextAttemptAt = Date.now() + nextBackoff(item.attempts);
        store.put(item);
      };
    });
  }

  function getSetting(key, fallback) {
    return tx(['meta'], 'readonly', function (t) { return reqValue(t.objectStore('meta').get(key)); })
      .then(function (row) { return row ? row.value : fallback; });
  }

  function setSetting(key, value) {
    return tx(['meta'], 'readwrite', function (t) { t.objectStore('meta').put({ key: key, value: value }); });
  }

  var api = {
    openDB: openDB, addClip: addClip, getClip: getClip, listClips: listClips, deleteClip: deleteClip,
    dueOutbox: dueOutbox, pendingCount: pendingCount, markSynced: markSynced, markFailed: markFailed,
    getSetting: getSetting, setSetting: setSetting,
    helpers: { nextBackoff: nextBackoff, toCSV: toCSV, csvCell: csvCell, extractEmail: extractEmail,
               parseTags: parseTags, normalizeClip: normalizeClip, buildWebhookPayload: buildWebhookPayload }
  };
  root.CRMDB = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);

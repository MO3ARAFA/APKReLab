/* Offline CRM Clipper - MV3 service worker: context menu, outbox sync with backoff, badge. */
importScripts('db.js');

var MENU_ID = 'clip-to-crm';
var SYNC_ALARM = 'crm-sync';
var syncing = false;

function hex(buf) {
  return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
}

async function sign(secret, body) {
  var key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)));
}

async function updateBadge() {
  try {
    var n = await CRMDB.pendingCount();
    await chrome.action.setBadgeText({ text: n > 0 ? String(n) : '' });
    await chrome.action.setBadgeBackgroundColor({ color: '#d97706' });
  } catch (e) { /* badge is cosmetic */ }
}

async function syncNow() {
  if (syncing) return { skipped: 'already syncing' };
  syncing = true;
  var result = { sent: 0, failed: 0, skipped: null };
  try {
    var url = await CRMDB.getSetting('webhookUrl', '');
    if (!url) { result.skipped = 'no webhook configured'; return result; }
    var secret = await CRMDB.getSetting('webhookSecret', '');
    var due = await CRMDB.dueOutbox(Date.now());
    for (var i = 0; i < due.length; i++) {
      var clip = await CRMDB.getClip(due[i].clipId);
      if (!clip) { await CRMDB.markSynced(due[i].clipId); continue; }
      var body = JSON.stringify(CRMDB.helpers.buildWebhookPayload(clip));
      var headers = { 'Content-Type': 'application/json', 'Idempotency-Key': clip.id };
      if (secret) headers['X-Signature'] = 'sha256=' + await sign(secret, body);
      var ctrl = new AbortController();
      var timer = setTimeout(function () { ctrl.abort(); }, 15000);
      try {
        var resp = await fetch(url, { method: 'POST', headers: headers, body: body, signal: ctrl.signal });
        if (resp.ok) { await CRMDB.markSynced(clip.id); result.sent++; }
        else { await CRMDB.markFailed(clip.id, 'HTTP ' + resp.status); result.failed++; }
      } catch (err) {
        await CRMDB.markFailed(clip.id, err && err.message); result.failed++;
        if (!navigator.onLine) break; // offline: stop hammering, retry on next alarm
      } finally { clearTimeout(timer); }
    }
    return result;
  } finally {
    syncing = false;
    await updateBadge();
  }
}

chrome.runtime.onInstalled.addListener(function () {
  chrome.contextMenus.create({
    id: MENU_ID, title: 'Clip to CRM', contexts: ['selection', 'page', 'link']
  });
  chrome.alarms.create(SYNC_ALARM, { periodInMinutes: 5 });
  updateBadge();
});

chrome.runtime.onStartup.addListener(function () {
  chrome.alarms.create(SYNC_ALARM, { periodInMinutes: 5 });
  updateBadge();
});

chrome.alarms.onAlarm.addListener(function (alarm) {
  if (alarm.name === SYNC_ALARM) syncNow();
});

chrome.contextMenus.onClicked.addListener(async function (info, tab) {
  if (info.menuItemId !== MENU_ID) return;
  await CRMDB.addClip({
    title: (tab && tab.title) || '',
    url: info.linkUrl || info.pageUrl || (tab && tab.url) || '',
    selection: info.selectionText || ''
  });
  await updateBadge();
  syncNow();
});

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || sender.id !== chrome.runtime.id) return false;
  if (msg.type === 'sync') {
    syncNow().then(sendResponse, function (e) { sendResponse({ error: String(e) }); });
    return true; // async response
  }
  if (msg.type === 'refresh-badge') { updateBadge().then(function () { sendResponse({}); }); return true; }
  return false;
});

self.addEventListener('online', function () { syncNow(); });

/* Offline CRM Clipper - popup logic. All DOM writes use textContent (no innerHTML). */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var pageCtx = { title: '', url: '', selection: '' };

  function setStatus(msg) { $('status').textContent = msg; }

  async function refreshStatus() {
    var n = await CRMDB.pendingCount();
    var url = await CRMDB.getSetting('webhookUrl', '');
    setStatus(n + ' pending sync' + (url ? '' : ' (no webhook configured - data stays local)'));
  }

  async function renderList() {
    var clips = await CRMDB.listClips({ query: $('search').value, limit: 30 });
    var ul = $('list');
    ul.textContent = '';
    clips.forEach(function (c) {
      var li = document.createElement('li');
      var left = document.createElement('div');
      var title = document.createElement('strong');
      title.textContent = c.name || c.company || c.title || c.url || '(untitled)';
      var sub = document.createElement('small');
      sub.textContent = [c.stage, c.email, c.synced ? 'synced' : 'pending'].filter(Boolean).join(' · ');
      left.appendChild(title); left.appendChild(sub);
      var del = document.createElement('button');
      del.textContent = '✕';
      del.title = 'Delete';
      del.setAttribute('aria-label', 'Delete clip');
      del.addEventListener('click', async function () {
        await CRMDB.deleteClip(c.id); await renderList(); await refreshStatus();
        chrome.runtime.sendMessage({ type: 'refresh-badge' });
      });
      li.appendChild(left); li.appendChild(del);
      ul.appendChild(li);
    });
  }

  async function loadPageContext() {
    try {
      var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      var tab = tabs[0];
      if (!tab) return;
      pageCtx.title = tab.title || ''; pageCtx.url = tab.url || '';
      if (tab.id && /^https?:/.test(tab.url || '')) {
        var res = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: function () { return String(window.getSelection()); } });
        pageCtx.selection = (res && res[0] && res[0].result) || '';
      }
      if (!$('email').value) $('email').value = CRMDB.helpers.extractEmail(pageCtx.selection);
      if (!$('notes').value && pageCtx.selection) $('notes').value = pageCtx.selection.slice(0, 500);
    } catch (e) { /* restricted pages (chrome://, web store) cannot be scripted */ }
  }

  async function saveClip(ev) {
    ev.preventDefault();
    await CRMDB.addClip({
      name: $('name').value, company: $('company').value, email: $('email').value, stage: $('stage').value,
      tags: $('tags').value, notes: $('notes').value, title: pageCtx.title, url: pageCtx.url, selection: pageCtx.selection
    });
    $('clip-form').reset();
    await renderList();
    setStatus('Saved locally.');
    chrome.runtime.sendMessage({ type: 'sync' }, function () { refreshStatus(); });
  }

  async function saveSettings() {
    var raw = $('webhook').value.trim();
    if (raw) {
      var u;
      try { u = new URL(raw); } catch (e) { setStatus('Invalid URL.'); return; }
      if (u.protocol !== 'https:') { setStatus('Webhook must use https.'); return; }
      var granted = await chrome.permissions.request({ origins: [u.origin + '/*'] });
      if (!granted) { setStatus('Host permission denied - cannot sync.'); return; }
    }
    await CRMDB.setSetting('webhookUrl', raw);
    await CRMDB.setSetting('webhookSecret', $('secret').value);
    setStatus('Settings saved.');
  }

  function download(name, text, type) {
    var url = URL.createObjectURL(new Blob([text], { type: type }));
    var a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  async function init() {
    $('clip-form').addEventListener('submit', saveClip);
    $('save-settings').addEventListener('click', saveSettings);
    $('search').addEventListener('input', renderList);
    $('sync').addEventListener('click', function () {
      setStatus('Syncing...');
      chrome.runtime.sendMessage({ type: 'sync' }, function (r) {
        setStatus(r && r.skipped ? 'Skipped: ' + r.skipped : r && !r.error ? 'Sent ' + r.sent + ', failed ' + r.failed : 'Sync error');
        renderList();
      });
    });
    $('export').addEventListener('click', async function () {
      var all = await CRMDB.listClips({ limit: 100000 });
      download('crm-clips.csv', CRMDB.helpers.toCSV(all), 'text/csv');
    });
    $('webhook').value = await CRMDB.getSetting('webhookUrl', '');
    $('secret').value = await CRMDB.getSetting('webhookSecret', '');
    await Promise.all([loadPageContext(), renderList()]);
    await refreshStatus();
  }

  init().catch(function (e) { setStatus('Error: ' + e.message); });
})();

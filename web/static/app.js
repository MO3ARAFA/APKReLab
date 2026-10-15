/* Agency Command Center - vanilla JS. Dynamic values go through textContent; the only innerHTML is server-rendered,
   escape-first markdown. State-changing calls carry the per-process CSRF token from the page's <meta>. */
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const CSRF = $('meta[name=csrf-token]').content;
  const UNIT_LABEL = {audits_ready: 'audits ready', legacy_repos_audited: 'repo audited', extensions_packaged: 'extension packaged',
                      patches_ready: 'patches ready', datasets_generated: 'dataset generated'};
  let S = null;            // last /api/state
  let activeTab = 'sheet';
  let pollJob = null;
  const loaded = {};       // tab -> loaded once

  const usd = (x, d = 4) => '$' + Number(x || 0).toFixed(d);
  const el = (tag, props = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
    }
    kids.flat().forEach(c => n.append(c));
    return n;
  };

  async function api(path, {method = 'GET', json} = {}) {
    const opts = {method, headers: {}};
    if (method !== 'GET') {
      opts.headers['X-CSRF-Token'] = CSRF;
      if (json !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(json); }
    }
    const r = await fetch(path, opts);
    let data = {};
    try { data = await r.json(); } catch (_) { /* non-JSON error */ }
    if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : (data.detail ? JSON.stringify(data.detail) : r.statusText));
    return data;
  }

  function toast(msg, kind = '') {
    const t = el('div', {class: 'toast ' + kind, text: msg});
    $('#toasts').append(t);
    setTimeout(() => t.remove(), kind === 'err' ? 8000 : 4000);
  }

  async function copyText(text, btn) {
    try { await navigator.clipboard.writeText(text); }
    catch (_) {
      const ta = el('textarea', {style: 'position:fixed;opacity:0'}); ta.value = text; document.body.append(ta); ta.select();
      try { document.execCommand('copy'); } finally { ta.remove(); }
    }
    if (btn) { const old = btn.textContent; btn.textContent = 'Copied ✓'; btn.classList.add('copied');
      setTimeout(() => { btn.textContent = old; btn.classList.remove('copied'); }, 1400); }
  }

  /* ---------- markdown panes: wire up copy buttons (server renders code blocks with a button) ---------- */
  function enhance(container) {
    $$('.copy-btn[data-copy=code]', container).forEach(b => b.addEventListener('click', () => copyText($('code', b.parentElement).textContent, b)));
    $$('h2, h3', container).forEach(h => {
      const level = Number(h.tagName[1]);
      const parts = [];
      for (let n = h.nextElementSibling; n && !(/^H[1-6]$/.test(n.tagName) && Number(n.tagName[1]) <= level); n = n.nextElementSibling) {
        const c = n.cloneNode(true); $$('.copy-btn', c).forEach(x => x.remove()); parts.push(c.innerText || c.textContent);
      }
      if (!parts.join('').trim()) return;
      const label = h.textContent;
      const b = el('button', {type: 'button', class: 'copy-btn', text: 'Copy section', 'aria-label': 'Copy section: ' + label});
      b.addEventListener('click', () => copyText(parts.join('\n\n').trim(), b));
      h.append(b);
    });
  }
  function setMarkdown(target, html) { target.innerHTML = html; enhance(target); }   // html is escape-first server output

  /* ---------- CFO cards ---------- */
  function renderCards(s) {
    $('#c-remaining').textContent = `${usd(s.remaining_seed_usd)} / ${usd(s.seed_usd, 2)}`;
    $('#c-remaining-bar').style.width = Math.max(0, Math.min(100, s.seed_remaining_pct)) + '%';
    $('#c-remaining-sub').textContent = `${s.seed_remaining_pct.toFixed(2)}% of seed capital left`;
    $('#c-burn').textContent = usd(s.burn_usd);
    $('#c-burn-sub').textContent = `${s.live_calls} live calls · ${s.cached_calls} cached` + (s.blocked_calls ? ` · ${s.blocked_calls} blocked` : '') + (s.llm_errors ? ` · ${s.llm_errors} errors` : '');
    $('#c-cache').textContent = usd(s.cache_savings_usd);
    $('#c-cache-sub').textContent = `${s.cache_hits} hits · ${s.cache_entries} cached responses`;
    $('#c-vault').textContent = usd(s.vault_amount, 2) + ' ' + (s.vault_locked ? 'LOCKED' : 'UNLOCKED');
    $('#c-vault-sub').textContent = s.vault_locked ? 'Unlocks on first verified Group A revenue' : `Released to ${s.vault_released_to}`;
    $('#c-pipeline').textContent = '$' + Number(s.pipeline_usd).toLocaleString(undefined, {maximumFractionDigits: 2});
    const b = $('#c-breaker');
    b.textContent = s.breaker_tripped ? 'TRIPPED' : 'ACTIVE';
    b.className = 'badge ' + (s.breaker_tripped ? 'bad' : 'ok');
    $('#c-breaker-sub').textContent = s.breaker_tripped ? 'Hard cap reached - live calls blocked' : `$${s.global_remaining_usd.toFixed(2)} remaining under the $${s.seed_usd.toFixed(2)} cap`;
  }

  /* ---------- project matrix ---------- */
  function renderProjects(state) {
    const body = $('#projects-body'); body.textContent = '';
    for (const p of state.projects) {
      const units = Object.entries(p.units || {}).map(([k, v]) => `${v} ${UNIT_LABEL[k] || k}`).join(', ') || '–';
      const score = p.ceo_score == null ? '–' : p.ceo_score.toFixed(1) + '%';
      const sub = p.status === 'BREAKER' ? p.blocked_calls + ' call(s) blocked' : (p.blockers.length ? p.blockers[0] : p.mode);
      const off = el('button', {type: 'button', class: 'btn', text: '▶ Run Offline (Free)', 'aria-label': `Run ${p.id} offline for free`});
      off.addEventListener('click', () => runProject(p, 'offline'));
      const live = el('button', {type: 'button', class: 'btn warn', text: '⚡ Run Live (Paid)', 'aria-label': `Run ${p.id} live, paid`});
      live.addEventListener('click', () => runProject(p, 'live'));
      if (state.busy) { off.disabled = true; live.disabled = true; }
      if (!state.live_available) { live.disabled = true; live.title = 'No API key configured in .env'; }
      body.append(el('tr', {},
        el('td', {}, el('b', {text: p.id}), el('small', {text: p.name})),
        el('td', {text: p.group_label}), el('td', {text: p.pm}),
        el('td', {}, el('span', {text: `${usd(p.spent_usd, 4)} / ${usd(p.quota_usd, 2)}`}), el('div', {class: 'mini'}, el('span', {style: `width:${Math.min(100, p.spent_pct)}%`}))),
        el('td', {text: score}),
        el('td', {}, el('span', {class: 'st ' + p.status.replace(' ', '-'), text: p.status}), el('small', {text: sub})),
        el('td', {text: units}),
        el('td', {}, el('div', {class: 'actions'}, off, live))));
    }
    const sel = $('#rev-project');
    if (!sel.options.length) state.projects.forEach(p => sel.append(el('option', {value: p.id, text: `${p.id} · ${p.name}`})));
  }

  function renderWarnings(list) {
    const w = $('#warnings'); w.textContent = '';
    w.classList.toggle('hidden', !list.length);
    list.forEach(t => w.append(el('div', {text: '⚠ ' + t})));
  }

  function renderTop(state) {
    renderWarnings(state.warnings || []);
    const pm = $('#pill-mode');
    pm.textContent = state.live_available ? 'Live API available (paid, capped)' : 'Offline only (no API key)';
    pm.className = 'pill ' + (state.live_available ? 'live' : 'off');
    $('#pill-sync').textContent = 'updated ' + new Date(state.generated_at * 1000).toLocaleTimeString();
    $('#btn-all-live').disabled = !state.live_available || state.busy;
    $('#btn-auto-live').disabled = !state.live_available || state.busy; $('#btn-auto-off').disabled = state.busy; $('#t-rotate').disabled = state.busy;
    $('#btn-auto-live').textContent = `🤖 AI CEO: Run Full Auto-Pilot (Live - Capped at ${usd(state.limits.all_default, 2)})`;
    $('#btn-all-offline').disabled = state.busy; $('#btn-rebuild').disabled = state.busy; $('#t-audit').disabled = !state.live_available || state.busy;
    $('#btn-all-live').textContent = `Run All (Live Sprint - Capped at ${usd(state.limits.all_default, 2)})`;
    renderBanner(state.job);
  }

  function renderBanner(job) {
    const b = $('#banner');
    if (!job) { b.classList.add('hidden'); return; }
    b.classList.remove('hidden', 'run', 'done', 'fail');
    b.textContent = '';
    const stepList = () => el('ul', {class: 'steps'}, (job.progress || []).map(s => el('li', {},
      el('span', {class: s.status === 'done' ? 'ok' : s.status === 'failed' ? 'bad' : 'run', text: s.status === 'done' ? '✓' : s.status === 'failed' ? '✗' : '…'}),
      el('span', {}, el('b', {text: s.label + ' '}), el('small', {text: s.detail})))));
    if (job.status === 'running') {
      b.classList.add('run');
      b.append(el('span', {class: 'spin'}), el('b', {text: 'Running '}), document.createTextNode(`${job.label} · ${job.elapsed.toFixed(0)}s` + (job.max_spend ? ` · cap ${usd(job.max_spend, 2)}` : '')));
      if (job.progress && job.progress.length) b.append(stepList());
    } else if (job.status === 'failed') {
      b.classList.add('fail'); b.append(el('b', {text: 'Failed '}), document.createTextNode(`${job.label}: ${job.error}`));
      if (job.progress && job.progress.length) b.append(stepList());
    } else {
      b.classList.add('done');
      const r = job.result || {}, l = r.llm || {};
      if (job.kind === 'autopilot') {
        const failed = (r.failed_steps || []).length;
        b.classList.toggle('fail', failed > 0);
        b.append(el('b', {text: failed ? 'Auto-pilot finished with issues ' : 'Auto-pilot complete '}),
          document.createTextNode(`in ${job.elapsed.toFixed(1)}s. LLM: ${l.live_calls || 0} live (${usd(l.spent_usd || 0)}), ${l.cache_hits || 0} cached, ${l.blocked || 0} blocked, ${l.errors || 0} errors.`), stepList());
        return;
      }
      const ps = Object.entries(r.projects || {}).map(([id, v]) => `${id} ${v.ceo_status}${v.ceo_score != null ? ' ' + v.ceo_score.toFixed(0) + '%' : ''}`).join(' · ');
      b.append(el('b', {text: 'Done '}), document.createTextNode(`${job.label} in ${job.elapsed.toFixed(1)}s - ${ps}. LLM: ${l.live_calls || 0} live (${usd(l.spent_usd || 0)}), ${l.cache_hits || 0} cached, ${l.blocked || 0} blocked, ${l.errors || 0} errors.` + (r.sell_sheet ? ` Sell sheet ${r.sell_sheet}.` : '')));
    }
  }

  /* ---------- actions ---------- */
  function capValue(inputId) {
    const v = parseFloat($(inputId).value);
    if (!(v > 0 && v <= S.limits.click_ceiling)) { toast(`Max spend must be between $0.01 and $${S.limits.click_ceiling.toFixed(2)}`, 'err'); return null; }
    return Math.round(v * 100) / 100;
  }
  async function start(path, body) {
    try {
      const {job} = await api(path, {method: 'POST', json: body});
      watchJob(job.id); refresh();
    } catch (e) { toast(e.message, 'err'); }
  }
  function runProject(p, mode) {
    if (mode === 'offline') return start(`/api/run/${p.id}`, {mode});
    const cap = capValue('#cap-single'); if (cap == null) return;
    if (!confirm(`Run ${p.id} LIVE?\n\nThis makes paid API calls and may spend up to ${usd(cap, 2)} of your seed capital (hard-capped). Continue?`)) return;
    start(`/api/run/${p.id}`, {mode, max_spend: cap, confirm: true});
  }
  function watchJob(id) {
    clearInterval(pollJob);
    pollJob = setInterval(async () => {
      try {
        const {job} = await api('/api/jobs/' + id);
        renderBanner(job);
        if (job.status !== 'running') {
          clearInterval(pollJob); pollJob = null; await refresh(); Object.keys(loaded).forEach(k => delete loaded[k]);
          if (job.kind === 'autopilot' && job.status === 'done') { history.replaceState(null, '', '#sheet'); activate('sheet'); } else { loadTab(activeTab, true); }
          toast(job.status === 'done' ? 'Run finished' : 'Run failed', job.status === 'done' ? 'ok' : 'err');
        }
      } catch (e) { clearInterval(pollJob); pollJob = null; toast(e.message, 'err'); }
    }, 1000);
  }

  $('#btn-auto-off').addEventListener('click', () => start('/api/autopilot', {mode: 'offline'}));
  $('#btn-auto-live').addEventListener('click', () => {
    const cap = S.limits.all_default;
    if (!confirm(`Run the full AI CEO AUTO-PILOT LIVE?\n\nIt will fetch real websites, make paid API calls (hard-capped at ${usd(cap, 2)} for the whole chain) and rebuild the sell sheet. Continue?`)) return;
    start('/api/autopilot', {mode: 'live', max_spend: cap, confirm: true});
  });
  $('#btn-all-offline').addEventListener('click', () => start('/api/run-all', {mode: 'offline'}));
  $('#btn-all-live').addEventListener('click', () => {
    const cap = S.limits.all_default;
    if (!confirm(`Run ALL projects LIVE?\n\nPaid API calls, capped at ${usd(cap, 2)} for the whole sprint. Continue?`)) return;
    start('/api/run-all', {mode: 'live', max_spend: cap, confirm: true});
  });
  $('#btn-rebuild').addEventListener('click', async () => {
    try { const r = await api('/api/rebuild-sell-sheet', {method: 'POST', json: {}}); toast(`Sell sheet rebuilt (${r.outreach_ready} outreach messages)`, 'ok'); loaded.sheet = false; loadTab('sheet', true); refresh(); }
    catch (e) { toast(e.message, 'err'); }
  });
  const modal = $('#revenue-modal');
  $('#btn-revenue').addEventListener('click', () => { $('#rev-confirm').checked = false; modal.classList.remove('hidden'); $('#rev-amount').focus(); });
  $('#rev-cancel').addEventListener('click', () => modal.classList.add('hidden'));
  modal.addEventListener('click', e => { if (e.target === modal) modal.classList.add('hidden'); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') modal.classList.add('hidden'); });
  $('#rev-save').addEventListener('click', async () => {
    const amount = parseFloat($('#rev-amount').value);
    if (!(amount > 0)) return toast('Enter a positive amount', 'err');
    if (!$('#rev-confirm').checked) return toast('Tick the confirmation: only log verified revenue', 'err');
    try {
      await api('/api/revenue', {method: 'POST', json: {project_id: $('#rev-project').value, amount, note: $('#rev-note').value, confirm: true}});
      modal.classList.add('hidden'); toast(`Logged ${usd(amount, 2)} for ${$('#rev-project').value}`, 'ok'); refresh();
    } catch (e) { toast(e.message, 'err'); }
  });

  /* ---------- tabs ---------- */
  function activate(tab) {
    if (!$('#tab-' + tab)) return;
    activeTab = tab;
    $$('.tab').forEach(x => { const on = x.dataset.tab === tab; x.classList.toggle('active', on); x.setAttribute('aria-selected', on); });
    $$('.tabpane').forEach(p => p.classList.toggle('hidden', p.id !== 'tab-' + tab));
    loadTab(tab);
  }
  $$('.tab').forEach(t => t.addEventListener('click', () => { history.replaceState(null, '', '#' + t.dataset.tab); activate(t.dataset.tab); }));
  window.addEventListener('hashchange', () => activate(location.hash.slice(1)));

  async function loadTab(tab, force) {
    if (loaded[tab] && !force && tab !== 'audit') return;
    loaded[tab] = true;
    try {
      if (tab === 'sheet') {
        const d = await api('/api/sell-sheet'); setMarkdown($('#sheet-body'), d.html);
        $('#sheet-meta').textContent = d.exists ? 'updated ' + new Date(d.updated * 1000).toLocaleString() : '';
        $('#sheet-body').dataset.md = d.markdown;
      } else if (tab === 'targets') {
        await loadTargets();
      } else if (tab === 'ext') {
        const d = await api('/api/launch-copy'); setMarkdown($('#ext-body'), d.html);
        $('#ext-meta').textContent = d.zip.exists ? `${(d.zip.size / 1024).toFixed(1)} KB` : 'not built yet - run PRJ-02';
        $('#dl-ext').classList.toggle('hidden', !d.zip.exists);
      } else if (tab === 'audit') {
        const [led, rep] = await Promise.all([api('/api/ledger?limit=200'), api('/api/audit-report')]);
        renderLedger(led); if (!loaded.auditReport || force) { setMarkdown($('#audit-body'), rep.html); loaded.auditReport = true; }
      }
    } catch (e) { toast(e.message, 'err'); }
  }
  $('#copy-sheet').addEventListener('click', e => copyText($('#sheet-body').dataset.md || '', e.currentTarget));

  function renderLedger(d) {
    $('#ledger-meta').textContent = `(latest ${d.entries.length} of ${d.total})`;
    const body = $('#ledger-body'); body.textContent = '';
    if (!d.entries.length) body.append(el('tr', {}, el('td', {colspan: 7, class: 'muted', text: 'No ledger entries yet.'})));
    for (const e of d.entries) {
      const model = e.model ? `${e.model}${e.tier ? ' · tier ' + e.tier : ''}` : '–';
      const kind = {api: e.provider === 'offline' ? 'offline' : 'live call', cache_hit: 'cache hit', blocked: 'blocked', vault_release: 'vault release', reinvest: 'reinvest'}[e.kind] || e.kind;
      const cost = e.kind === 'cache_hit' ? `saved ${usd(e.saved_usd, 6)}` : usd(e.usd, 6);
      body.append(el('tr', {}, el('td', {text: new Date(e.t * 1000).toLocaleString()}), el('td', {text: e.project}), el('td', {text: kind}), el('td', {text: model}),
        el('td', {class: 'num', text: `${e.tokens_in} / ${e.tokens_out}`}), el('td', {class: 'num', text: cost}), el('td', {class: 'muted', text: e.note})));
    }
  }

  /* ---------- targets ---------- */
  async function loadTargets() {
    const d = await api('/api/targets'); const body = $('#targets-body'); body.textContent = '';
    $('#t-pool').textContent = `Prospect pool: ${d.pool.remaining} of ${d.pool.pool} not yet audited`;
    if (!d.targets.length) body.append(el('tr', {}, el('td', {colspan: 4, class: 'muted', text: 'No targets yet - add one below.'})));
    d.targets.forEach(t => {
      const rm = el('button', {type: 'button', class: 'btn small ghost', text: 'Remove', 'aria-label': 'Remove ' + t.url});
      rm.addEventListener('click', async () => { try { await api('/api/targets?url=' + encodeURIComponent(t.url), {method: 'DELETE'}); loadTargets(); } catch (e) { toast(e.message, 'err'); } });
      body.append(el('tr', {}, el('td', {text: t.url}), el('td', {text: t.ceo}), el('td', {text: t.company}), el('td', {}, rm)));
    });
  }
  $('#t-add').addEventListener('click', async () => {
    try {
      await api('/api/targets', {method: 'POST', json: {url: $('#t-url').value, ceo: $('#t-ceo').value, company: $('#t-company').value}});
      ['#t-url', '#t-ceo', '#t-company'].forEach(i => $(i).value = ''); loadTargets();
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#t-rotate').addEventListener('click', async () => {
    const discover = $('#t-discover').checked;
    if (discover && !confirm('Ask the AI CEO to suggest new prospects?\n\nThis makes one small paid call (capped at $0.02). Suggestions are unverified leads and greet with "there". Continue?')) return;
    try {
      const body = discover ? {count: 5, discover: true, confirm: true, max_spend: 0.02} : {count: 5};
      const r = await api('/api/targets/rotate', {method: 'POST', json: body});
      toast(r.note, 'ok'); loadTargets();
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#t-audit').addEventListener('click', () => {
    const cap = capValue('#cap-targets'); if (cap == null) return;
    if (!confirm(`Audit all targets LIVE?\n\nReal HTTP requests to the listed sites plus paid LLM drafts, capped at ${usd(cap, 2)}. Continue?`)) return;
    $('#t-msg').textContent = 'started - watch the banner above';
    start('/api/targets/audit', {max_spend: cap, confirm: true, rebuild: true});
  });

  /* ---------- polling ---------- */
  async function refresh() {
    try { S = await api('/api/state'); renderCards(S.summary); renderProjects(S); renderTop(S);
      if (S.busy && !pollJob) watchJob(S.job.id);
    } catch (e) { $('#pill-sync').textContent = 'offline: ' + e.message; }
  }
  setInterval(() => { if (!document.hidden) { refresh(); if (activeTab === 'audit') loadTab('audit', false); } }, 3000);
  refresh().then(() => activate($('#tab-' + location.hash.slice(1)) ? location.hash.slice(1) : 'sheet'));
})();

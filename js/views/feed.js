/* Live intelligence feed.
   Server aggregates vendor/CERT RSS and scores Bangladesh relevance; the
   curated BGD e-GOV CIRT advisory record is always merged in and is used as
   the offline fallback when the aggregator is unreachable. */
import { esc, safeUrl, host } from '../lib/security.js';
import { BD_ADVISORIES } from '../../data/advisories.js';

const state = { filter: 'bd', sev: null, q: '', items: null, sources: null, loading: false };

function timeAgo(d) {
  const t = new Date(d).getTime();
  if (!t) return '';
  const m = Math.floor((Date.now() - t) / 60000);
  if (m < 60) return m + 'm ago';
  const h = Math.floor(m / 60);
  if (h < 24) return h + 'h ago';
  const dd = Math.floor(h / 24);
  return dd < 30 ? dd + 'd ago' : new Date(d).toISOString().slice(0, 10);
}

export async function renderFeed() {
  const body = document.getElementById('feed-body');
  if (!state.items) {
    body.innerHTML = shell('<div class="panel"><div class="skel" style="margin-bottom:8px"></div><div class="skel" style="width:70%"></div></div>');
    await load();
  }
  paint();
}

async function load() {
  state.loading = true;
  try {
    const [items, sources] = await Promise.all([
      fetch('/api/feed/items?limit=120').then(r => r.json()).catch(() => null),
      fetch('/api/feed/sources').then(r => r.json()).catch(() => null)
    ]);
    state.items = (items?.items || []).concat(curated());
    state.sources = sources?.sources || null;
    state.live = !!items?.items?.length;
  } catch {
    state.items = curated();
    state.live = false;
  }
  state.loading = false;
}

function curated() {
  return BD_ADVISORIES.map(a => ({
    id: 'adv-' + a.date + a.title.slice(0, 12),
    title: a.title, summary: a.summary, url: a.url,
    source_name: a.source, source_cat: a.cat, severity: a.severity,
    published_at: a.date.length === 7 ? a.date + '-01' : a.date,
    bd: true, bd_reason: 'Curated national advisory record', actors: a.actors || [], tags: a.tags || []
  }));
}

function shell(inner) {
  return `<div class="v-head">
      <div class="v-title">Live intelligence feed</div>
      <div class="v-sub">Vendor research, CERT advisories and security reporting, scored for Bangladesh relevance. The BGD e-GOV CIRT advisory record is always included.</div>
    </div>${inner}`;
}

function paint() {
  const body = document.getElementById('feed-body');
  let items = state.items.slice();

  if (state.filter === 'bd') items = items.filter(i => i.bd);
  if (state.filter === 'cert') items = items.filter(i => i.source_cat === 'cert');
  if (state.sev) items = items.filter(i => i.severity === state.sev);
  if (state.q) {
    const q = state.q.toLowerCase();
    items = items.filter(i => (i.title + ' ' + (i.summary || '') + ' ' + (i.actors || []).join(' ')).toLowerCase().includes(q));
  }
  items.sort((a, b) => String(b.published_at).localeCompare(String(a.published_at)));

  const bdCount = state.items.filter(i => i.bd).length;
  const critCount = state.items.filter(i => i.severity === 'critical').length;

  body.innerHTML = shell(`
    <div class="grid3" style="margin-bottom:14px">
      <div class="stat-card"><div class="lab">Items in window</div><div class="val">${state.items.length}</div><div class="sub">${state.live ? '<span style="color:var(--green)">live aggregator online</span>' : 'curated record only — aggregator offline'}</div></div>
      <div class="stat-card"><div class="lab">BD-relevant</div><div class="val" style="color:var(--bd-green)">${bdCount}</div><div class="sub">matched on BD keywords or tracked actors</div></div>
      <div class="stat-card"><div class="lab">Critical</div><div class="val" style="color:var(--red)">${critCount}</div><div class="sub">severity-ranked</div></div>
    </div>

    <div class="feed-bar">
      <div class="seg" id="feed-seg">
        <button class="${state.filter === 'bd' ? 'on' : ''}" data-f="bd">🇧🇩 Bangladesh</button>
        <button class="${state.filter === 'cert' ? 'on' : ''}" data-f="cert">National CERT</button>
        <button class="${state.filter === 'all' ? 'on' : ''}" data-f="all">Global</button>
      </div>
      <div class="seg" id="sev-seg">
        ${['critical', 'high', 'medium'].map(s => `<button class="${state.sev === s ? 'on' : ''}" data-s="${s}">${s}</button>`).join('')}
      </div>
      <input id="feed-q" placeholder="Filter…" value="${esc(state.q)}"
        style="flex:1;min-width:160px;padding:7px 11px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;font-family:var(--mono);font-size:11.5px;outline:none">
      <button class="btn-ghost" style="padding:7px 13px;font-size:11.5px" id="feed-refresh">↻ Refresh</button>
    </div>

    <div class="grid2" style="grid-template-columns: 1fr 250px; align-items:start">
      <div>
        ${items.length ? items.map(card).join('') : '<div class="pr-empty">Nothing matches those filters.</div>'}
      </div>
      <div class="panel">
        <div class="panel-t">Source health</div>
        <div class="src-health">
          ${(state.sources || []).map(s => `
            <div class="sh-row" title="${esc(s.error || 'ok')}">
              <span class="dot" style="background:${s.ok ? 'var(--green)' : 'var(--red)'}"></span>
              ${esc(s.name)}<span class="n">${s.count ?? 0}</span>
            </div>`).join('') || '<div class="mono muted" style="font-size:10.5px">Aggregator offline — showing curated advisory record.</div>'}
        </div>
        <div class="panel-t" style="margin-top:14px">BD keyword model</div>
        <div class="mono" style="font-size:10px;color:var(--text4);line-height:1.7">
          bangladesh · dhaka · chattogram · bgd e-gov cirt · gov.bd · taka · bdt · + every tracked actor alias in the corpus
        </div>
      </div>
    </div>`);

  body.querySelectorAll('#feed-seg button').forEach(b => b.addEventListener('click', () => { state.filter = b.dataset.f; paint(); }));
  body.querySelectorAll('#sev-seg button').forEach(b => b.addEventListener('click', () => { state.sev = state.sev === b.dataset.s ? null : b.dataset.s; paint(); }));
  const q = body.querySelector('#feed-q');
  q.addEventListener('input', () => { state.q = q.value; const p = q.selectionStart; paint(); const nq = document.getElementById('feed-q'); nq.focus(); nq.setSelectionRange(p, p); });
  body.querySelector('#feed-refresh').addEventListener('click', async () => { state.items = null; await renderFeed(); });
}

function card(i) {
  const sev = i.severity || 'info';
  return `<div class="feed-item ${i.bd ? 'bd' : ''} sev-${esc(sev)}">
    <div class="fi-top">
      <span class="fi-src">${esc((i.source_cat || 'news').toUpperCase())}</span>
      <span class="mono muted" style="font-size:10px">${esc(i.source_name || host(i.url))}</span>
      ${i.bd ? '<span class="pill live">BD RELEVANT</span>' : ''}
      <span class="pill ${sev === 'critical' ? 'crit' : sev === 'high' ? 'warn' : ''}">${esc(sev)}</span>
      <span class="fi-time">${esc(timeAgo(i.published_at))}</span>
    </div>
    <div class="fi-title"><a href="${esc(safeUrl(i.url))}" target="_blank" rel="noopener">${esc(i.title)}</a></div>
    ${i.summary ? `<div class="fi-sum">${esc(String(i.summary).slice(0, 320))}</div>` : ''}
    <div class="fi-tags">
      ${(i.actors || []).map(a => `<span class="tag accent">${esc(a)}</span>`).join('')}
      ${(i.tags || []).slice(0, 4).map(t => `<span class="tag">#${esc(t)}</span>`).join('')}
      ${i.bd_reason ? `<span class="tag" style="color:var(--text4)">${esc(i.bd_reason)}</span>` : ''}
    </div>
  </div>`;
}

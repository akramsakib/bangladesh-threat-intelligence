/* ============================================================================
   ThreatNexus BD — application shell
   Persistent filter state across six views; hand-rolled router; spotlight;
   theme; keyboard shortcuts.
   ========================================================================== */
import { GROUPS } from '../data/actors.js';
import { NATION_COLORS, MOTIVATION, STATUS, FRESHNESS, computeEdges, freshness, nationColor } from './config.js';
import { initGlobe, updateGlobe, toggleArcs, focusActor } from './globe.js';
import { openDetail, closeDetail, toast } from './detail.js';
import { renderCluster } from './views/cluster.js';
import { renderDiamond } from './views/diamond.js';
import { renderLandscape } from './views/landscape.js';
import { renderFeed } from './views/feed.js';
import { renderHunt } from './views/hunt.js';
import { renderPrism, lookup as prismLookup } from './views/prism.js';
import { viewForPath, pathForView, BASE } from './lib/router.js';
import { esc } from './lib/security.js';

const ALL = GROUPS.slice();
const EDGES = computeEdges(ALL);

let currentView = 'globe';
let fCountry = null, fMot = null, fStatus = null, q = '';
let visible = ALL.slice();
let arcsOn = true;

const $ = id => document.getElementById(id);

/* ------------------------------------------------------------------- theme */
function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem('tnbd_theme'); } catch {}
  document.body.classList.toggle('light-mode', saved === 'light');
}
function toggleTheme() {
  const light = !document.body.classList.contains('light-mode');
  document.body.classList.toggle('light-mode', light);
  try { localStorage.setItem('tnbd_theme', light ? 'light' : 'dark'); } catch {}
  document.dispatchEvent(new CustomEvent('theme-change'));
}

/* ----------------------------------------------------------------- filters */
function buildFilters() {
  $('status-chips').innerHTML = Object.entries(STATUS).map(([k, v]) =>
    `<span class="chip" data-status="${k}" title="${esc(v.desc)}"><span class="dot" style="background:${v.hex}"></span>${esc(v.label)}
      <span style="margin-left:auto;color:var(--text4)">${ALL.filter(g => g.bd_status === k).length}</span></span>`).join('');

  $('mot-chips').innerHTML = Object.entries(MOTIVATION).map(([k, v]) =>
    `<span class="chip" data-mot="${k}"><span class="dot" style="background:${v.hex}"></span>${esc(v.label)}
      <span style="margin-left:auto;color:var(--text4)">${ALL.filter(g => g.motivation === k).length}</span></span>`).join('');

  const counts = {};
  ALL.forEach(g => { counts[g.country] = (counts[g.country] || 0) + 1; });
  $('c-list').innerHTML = Object.keys(NATION_COLORS).filter(c => counts[c]).map(c =>
    `<div class="c-row" data-country="${esc(c)}"><span class="dot" style="background:${NATION_COLORS[c]}"></span>${esc(c)}<span class="n">${counts[c]}</span></div>`).join('');

  $('freshness-key').innerHTML = FRESHNESS.map(f =>
    `<div class="ek-row"><span class="ek-dot" style="background:${f.hex}"></span>${esc(f.label)}</div>`).join('');

  document.querySelectorAll('[data-status]').forEach(el => el.addEventListener('click', () => {
    fStatus = fStatus === el.dataset.status ? null : el.dataset.status; syncChips(); refresh();
  }));
  document.querySelectorAll('[data-mot]').forEach(el => el.addEventListener('click', () => {
    fMot = fMot === el.dataset.mot ? null : el.dataset.mot; syncChips(); refresh();
  }));
  document.querySelectorAll('[data-country]').forEach(el => el.addEventListener('click', () => {
    fCountry = fCountry === el.dataset.country ? null : el.dataset.country; syncChips(); refresh();
  }));
}

function syncChips() {
  document.querySelectorAll('[data-status]').forEach(e => e.classList.toggle('on', e.dataset.status === fStatus));
  document.querySelectorAll('[data-mot]').forEach(e => e.classList.toggle('on', e.dataset.mot === fMot));
  document.querySelectorAll('[data-country]').forEach(e => e.classList.toggle('on', e.dataset.country === fCountry));
}

function applyFilters() {
  const needle = q.trim().toLowerCase();
  visible = ALL.filter(g => {
    if (fCountry && g.country !== fCountry) return false;
    if (fMot && g.motivation !== fMot) return false;
    if (fStatus && g.bd_status !== fStatus) return false;
    if (needle) {
      const hay = [g.name, g.apt, g.aka, g.country, g.description,
        ...(g.malware || []).map(m => m[0]), ...(g.cves || []),
        ...(g.ttps || []).map(t => t[0] + ' ' + t[1]),
        ...(g.bd_targets || []), ...(g.sectors || [])].join(' ').toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
  const active = fCountry || fMot || fStatus || needle;
  $('filter-count').textContent = active ? `${visible.length}/${ALL.length}` : '';
}

function refresh() {
  applyFilters();
  updateGlobe(visible);
  renderCurrentView();
}

/* ------------------------------------------------------------------- views */
function renderCurrentView() {
  const sel = g => { if (g) { openDetail(g); if (currentView === 'globe') focusActor(g); } };
  $('cluster-legend').style.display = currentView === 'cluster' ? '' : 'none';
  $('arc-sec').style.display = currentView === 'globe' ? '' : 'none';

  if (currentView === 'cluster') renderCluster(visible, EDGES, sel);
  if (currentView === 'diamond') renderDiamond(visible, sel);
  if (currentView === 'landscape') renderLandscape(visible, sel);
  if (currentView === 'feed') renderFeed();
  if (currentView === 'hunt') renderHunt(visible, sel);
  if (currentView === 'prism') renderPrism();
}

function showView(view, { push = true } = {}) {
  currentView = view;
  document.querySelectorAll('.view-panel').forEach(p => p.classList.toggle('on', p.dataset.view === view));
  document.querySelectorAll('.tab').forEach(t => {
    const on = t.dataset.view === view;
    t.classList.toggle('on', on);
    t.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  document.querySelectorAll('.mob-tab').forEach(t => t.classList.toggle('on', t.dataset.view === view));
  if (push) { try { history.pushState({ v: view }, '', pathForView(view)); } catch {} }
  renderCurrentView();
}

function bindTabs() {
  // rebase static hrefs so middle-click / "open in new tab" work under a path prefix
  document.querySelectorAll('.tab, .mob-tab').forEach(t => {
    if (t.dataset.view) t.setAttribute('href', pathForView(t.dataset.view));
  });
  document.querySelectorAll('.tab, .mob-tab').forEach(t => t.addEventListener('click', e => {
    e.preventDefault();
    showView(t.dataset.view);
    $('sidebar').classList.remove('on');
    $('sb-overlay').classList.remove('on');
  }));
  $('tb-brand').addEventListener('click', () => showView('globe'));
  window.addEventListener('popstate', () => showView(viewForPath(location.pathname) || 'globe', { push: false }));
}

/* --------------------------------------------------------------- spotlight */
function bindSpotlight() {
  const overlay = $('spotlight-overlay'), input = $('spotlight-input'), results = $('spotlight-results');
  let sel = 0, items = [];

  const open = () => { overlay.classList.add('on'); input.value = ''; input.focus(); render(''); };
  const close = () => overlay.classList.remove('on');

  function render(needle) {
    const n = needle.toLowerCase().trim();
    items = !n ? ALL.slice(0, 8) : ALL.filter(g =>
      (g.name + g.apt + g.aka + (g.malware || []).map(m => m[0]).join(' ') + (g.cves || []).join(' ') +
       (g.ttps || []).map(t => t[0]).join(' ')).toLowerCase().includes(n)).slice(0, 12);
    sel = 0;
    results.innerHTML = items.length ? items.map((g, i) =>
      `<div class="sr-item ${i === 0 ? 'sel' : ''}" data-i="${i}">
         <span class="dot" style="background:${nationColor(g.country)}"></span>
         <span class="sr-name">${esc(g.name)}</span>
         <span class="mono muted" style="font-size:10px">${esc(g.apt)}</span>
         <span class="sr-meta">BD ${g.bd_relevance}</span>
       </div>`).join('') : '<div class="spotlight-empty">No match in the Bangladesh corpus.</div>';
    results.querySelectorAll('.sr-item').forEach(el =>
      el.addEventListener('click', () => { openDetail(items[Number(el.dataset.i)]); close(); }));
  }

  input.addEventListener('input', () => render(input.value));
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  $('spotlight-hint').addEventListener('click', open);

  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); open(); return; }
    if (!overlay.classList.contains('on')) return;
    if (e.key === 'Escape') close();
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      sel = Math.max(0, Math.min(items.length - 1, sel + (e.key === 'ArrowDown' ? 1 : -1)));
      results.querySelectorAll('.sr-item').forEach((el, i) => el.classList.toggle('sel', i === sel));
    }
    if (e.key === 'Enter' && items[sel]) { openDetail(items[sel]); close(); }
  });
}

function bindKeys() {
  document.addEventListener('keydown', e => {
    if (e.target.matches('input, textarea')) return;
    const k = e.key.toLowerCase();
    if (k === 't') toggleTheme();
    if (k === 'escape') closeDetail();
    const order = ['globe', 'cluster', 'diamond', 'landscape', 'feed', 'hunt', 'prism'];
    if (/^[1-7]$/.test(k)) showView(order[Number(k) - 1]);
  });
}

/* -------------------------------------------------------------------- boot */
function boot() {
  try {
    initTheme();
    buildFilters();
    bindTabs();
    bindSpotlight();
    bindKeys();

    $('theme-toggle').addEventListener('click', toggleTheme);
    $('dp-close').addEventListener('click', closeDetail);
    $('mob-menu-btn').addEventListener('click', () => {
      $('sidebar').classList.toggle('on'); $('sb-overlay').classList.toggle('on');
    });
    $('sb-overlay').addEventListener('click', () => {
      $('sidebar').classList.remove('on'); $('sb-overlay').classList.remove('on');
    });
    $('arc-toggle').addEventListener('click', () => {
      arcsOn = toggleArcs();
      $('arc-toggle').textContent = arcsOn ? 'Hide attack arcs' : 'Show attack arcs';
    });

    const search = $('g-search');
    let t;
    search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { q = search.value; refresh(); }, 160); });

    document.addEventListener('prism-lookup', ev => {
      showView('prism');
      setTimeout(() => prismLookup(ev.detail.ioc), 60);
    });

    applyFilters();
    initGlobe(visible, g => { openDetail(g); focusActor(g); });
    $('globe-loading').style.display = 'none';

    const initial = viewForPath(location.pathname) || 'globe';
    showView(initial, { push: false });

    const m = /^#actor=(.+)$/.exec(location.hash || '');
    if (m) {
      const g = ALL.find(x => x.id === decodeURIComponent(m[1]));
      if (g) openDetail(g);
    }
  } catch (err) {
    console.error('[ThreatNexus BD]', err);
    const el = $('globe-loading');
    if (el) el.innerHTML = `<div style="text-align:center;padding:40px;max-width:460px;font-family:ui-monospace,monospace">
      <div style="font-size:14px;color:#f0544f;margin-bottom:12px;font-weight:700">Init failed</div>
      <div style="font-size:11px;color:#5a6d88;line-height:1.9;background:#131a27;padding:14px;border-radius:6px;text-align:left">${esc(err.message || String(err))}</div></div>`;
  }
}

window.addEventListener('error', e => console.error('[TNBD]', e.message));
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();

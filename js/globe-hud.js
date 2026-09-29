/* ============================================================================
   Globe HUD — hero stat bar + campaign timeline

   Vendor threat maps (Check Point, Radware, SonicWall) lead with a very large
   number and a trend strip along the bottom. Both are effective. Both, on those
   sites, are driven by sensor telemetry that is mostly automated scanning noise.

   The same two components are built here from the curated corpus instead:
   every figure in the hero bar is counted at render time, and every bar in the
   timeline is a dated campaign with a cited source. Nothing is estimated and
   nothing is animated to imply activity that did not happen.
   ========================================================================== */

/** Year of a campaign, from an ISO-ish "YYYY" / "YYYY-MM" date string. */
function campaignYear(c) {
  const m = /^(\d{4})/.exec(String(c && c.date || ''));
  return m ? Number(m[1]) : null;
}

/** All dated campaigns across the corpus, flattened with their actor. */
export function allCampaigns(groups) {
  const out = [];
  groups.forEach(g => (g.campaigns || []).forEach(c => {
    const y = campaignYear(c);
    if (y) out.push({ year: y, actor: g, campaign: c });
  }));
  return out;
}

/** Does this actor have campaign activity in `year`? */
export function activeInYear(g, year) {
  return (g.campaigns || []).some(c => campaignYear(c) === year);
}

/* ------------------------------------------------------------------ hero bar */

export function renderHero(visible, all, year = null) {
  const el = document.getElementById('globe-hero');
  if (!el) return;

  // When a year is selected the hero must describe that year, otherwise it
  // reports an actor's whole history and contradicts the bar the user clicked.
  const camps = allCampaigns(visible).filter(c => year === null || c.year === year);
  const confirmed = visible.filter(g => g.bd_status === 'confirmed').length;
  const origins = new Set(visible.map(g => g.country).filter(Boolean)).size;
  const years = camps.map(c => c.year).sort((a, b) => a - b);
  const span = years.length ? `${years[0]}\u2013${years[years.length - 1]}` : '\u2014';

  const stats = [
    { n: visible.length, l: 'actors tracked', c: 'var(--text)' },
    { n: confirmed, l: 'confirmed vs BD', c: 'var(--red, #f0544f)' },
    { n: camps.length, l: 'documented campaigns', c: 'var(--accent)' },
    { n: origins, l: 'origin countries', c: 'var(--text)' },
    { n: year === null ? span : year, l: year === null ? 'record spans' : 'year selected', c: 'var(--text3)' }
  ];

  el.innerHTML = stats.map((s, i) =>
    (i ? '<div class="gh-sep"></div>' : '') +
    `<div class="gh-stat"><div class="gh-num" style="color:${s.c}">${s.n}</div>` +
    `<div class="gh-lab">${s.l}</div></div>`
  ).join('');
}

/* ----------------------------------------------------------------- timeline */

let playTimer = null;
let years = [];
let onYearCb = null;
let current = null;

function paint() {
  document.querySelectorAll('.gt-bar').forEach(b => {
    const y = Number(b.dataset.year);
    b.classList.toggle('on', current === y);
    b.classList.toggle('dim', current !== null && current !== y);
  });
  const lab = document.getElementById('gt-year');
  if (lab) lab.textContent = current === null ? 'ALL YEARS' : String(current);
}

function select(year) {
  current = year;
  paint();
  if (onYearCb) onYearCb(year);
}

export function stopPlay() {
  if (playTimer) { clearInterval(playTimer); playTimer = null; }
  const b = document.getElementById('gt-play');
  if (b) b.textContent = '\u25b6';
}

function togglePlay() {
  const btn = document.getElementById('gt-play');
  if (playTimer) { stopPlay(); return; }
  if (!years.length) return;
  let i = current === null ? -1 : years.indexOf(current);
  if (btn) btn.textContent = '\u2758\u2758';
  playTimer = setInterval(() => {
    i += 1;
    if (i >= years.length) { stopPlay(); select(null); return; }
    select(years[i]);
  }, 900);
}

export function initTimeline(all, onYear) {
  const wrap = document.getElementById('gt-bars');
  if (!wrap) return;
  onYearCb = onYear;

  const camps = allCampaigns(all);
  const counts = {};
  camps.forEach(c => { counts[c.year] = (counts[c.year] || 0) + 1; });
  years = Object.keys(counts).map(Number).sort((a, b) => a - b);
  if (!years.length) return;

  // Fill gap years so the axis is chronologically honest rather than compressed.
  const full = [];
  for (let y = years[0]; y <= years[years.length - 1]; y++) full.push(y);
  const max = Math.max(...Object.values(counts));

  wrap.innerHTML = full.map(y => {
    const n = counts[y] || 0;
    // sqrt scale: 2026 carries 19 campaigns and most years carry 1, so a
    // linear axis flattens the whole record into a single visible bar.
    const h = n ? Math.max(14, Math.round(Math.sqrt(n / max) * 100)) : 3;
    const label = n === 1 ? '1 campaign' : `${n} campaigns`;
    return `<div class="gt-bar" data-year="${y}" title="${y} — ${label}">
      <div class="gt-fill" style="height:${h}%"></div>
      <div class="gt-yr">${String(y).slice(2)}</div>
    </div>`;
  }).join('');

  wrap.querySelectorAll('.gt-bar').forEach(b => {
    b.addEventListener('click', () => {
      stopPlay();
      const y = Number(b.dataset.year);
      select(current === y ? null : y);
    });
  });

  const play = document.getElementById('gt-play');
  if (play) play.addEventListener('click', togglePlay);
  const reset = document.getElementById('gt-reset');
  if (reset) reset.addEventListener('click', () => { stopPlay(); select(null); });

  paint();
}

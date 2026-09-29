/* National threat landscape — board-ready brief for Bangladesh. */
import { esc, safeUrl } from '../lib/security.js';
import { nationColor, MOTIVATION, STATUS } from '../config.js';
import { INCIDENTS, SECTORS } from '../../data/actors.js';

let yearFilter = 'all';

export function renderLandscape(groups, onSelect) {
  const body = document.getElementById('landscape-body');
  const active = groups.filter(g => g.last_seen >= 2025 && g.bd_status !== 'outbound');
  const confirmed = groups.filter(g => g.bd_status === 'confirmed');

  const byCountry = {};
  groups.forEach(g => { byCountry[g.country] = (byCountry[g.country] || 0) + 1; });
  const originRows = Object.entries(byCountry).sort((a, b) => b[1] - a[1]);
  const total = groups.length || 1;

  const cves = new Set(); groups.forEach(g => (g.cves || []).forEach(c => cves.add(c)));
  const campaigns = groups.reduce((n, g) => n + (g.campaigns || []).length, 0);

  const top = [...groups].sort((a, b) => b.bd_relevance - a.bd_relevance).slice(0, 10);

  const years = [...new Set(INCIDENTS.map(i => i.date.slice(0, 4)))].sort().reverse();
  const incidents = INCIDENTS.filter(i => yearFilter === 'all' || i.date.startsWith(yearFilter))
    .slice().sort((a, b) => b.date.localeCompare(a.date));

  body.innerHTML = `
    <div class="cond-banner">
      <span class="blip"></span>
      <b>CONDITION RED</b>
      <span>Three India-nexus espionage actors and one named RaaS operation are running live campaigns against Bangladeshi government, defence and financial targets — treat credential-phishing alerts on gov.bd mail as live until triaged.</span>
    </div>

    <div class="v-head">
      <div class="v-title">Bangladesh Threat Intelligence Brief</div>
      <div class="v-sub">National picture · ${esc(new Date().toLocaleString('en-GB', { month: 'long', year: 'numeric' }))} · compiled from BGD e-GOV CIRT advisories, vendor research and public incident reporting. TLP:CLEAR.</div>
    </div>

    <div class="grid3" style="margin-bottom:14px">
      <div class="stat-card"><div class="lab">Tracked actors</div><div class="val">${groups.length}</div><div class="sub">${confirmed.length} confirmed against BD targets</div></div>
      <div class="stat-card"><div class="lab">Active 2025-26</div><div class="val" style="color:var(--red)">${active.length}</div><div class="sub">seen in the last 24 months</div></div>
      <div class="stat-card"><div class="lab">Tracked campaigns</div><div class="val">${campaigns}</div><div class="sub">${cves.size} exploited CVEs in corpus</div></div>
      <div class="stat-card"><div class="lab">National incidents</div><div class="val">${INCIDENTS.length}</div><div class="sub">2013 → present, sourced</div></div>
    </div>

    <div class="grid2" style="margin-bottom:14px">
      <div class="panel">
        <div class="panel-t">Threat origin <span class="mut">actors by attributed origin</span></div>
        <div class="donut-wrap">
          ${donut(originRows, total)}
          <div class="donut-legend">
            ${originRows.map(([c, n]) => `
              <div class="dl-row"><span class="dot" style="background:${nationColor(c)}"></span>${esc(c)}<span class="n">${n}</span></div>`).join('')}
          </div>
        </div>

        <div class="panel-t" style="margin-top:20px">Motivation <span class="mut">why they are here</span></div>
        ${Object.entries(MOTIVATION).map(([k, v]) => {
          const n = groups.filter(g => g.motivation === k).length;
          return `<div style="margin-bottom:9px">
            <div class="row" style="font-size:12px;margin-bottom:3px">
              <span class="dot" style="background:${v.hex}"></span><span>${esc(v.label)}</span>
              <span class="mono muted" style="margin-left:auto">${n}</span>
            </div>
            <div class="bar-track"><div class="bar-fill" style="width:${total ? (n / total) * 100 : 0}%;background:${v.hex}"></div></div>
          </div>`;
        }).join('')}

        <div class="panel-t" style="margin-top:20px">Attribution confidence <span class="mut">how firmly each dossier is held</span></div>
        ${['high', 'moderate', 'low'].map(c => {
          const n = groups.filter(g => (g.confidence || '').toLowerCase() === c).length;
          const col = c === 'high' ? 'var(--green)' : c === 'moderate' ? 'var(--orange)' : 'var(--text4)';
          return `<div style="margin-bottom:9px">
            <div class="row" style="font-size:12px;margin-bottom:3px">
              <span style="text-transform:capitalize">${esc(c)}</span>
              <span class="mono muted" style="margin-left:auto">${n}</span>
            </div>
            <div class="bar-track"><div class="bar-fill" style="width:${total ? (n / total) * 100 : 0}%;background:${col}"></div></div>
          </div>`;
        }).join('')}

        <div class="mono" style="font-size:10px;color:var(--text4);line-height:1.8;margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
          Precision over recall: an actor is only attributed to a state when named by government or first-party vendor reporting. Everything else stays UNATTRIBUTED.
        </div>
      </div>

      <div class="panel">
        <div class="panel-t">Sector exposure <span class="mut">analyst-assigned, 0-100</span></div>
        ${SECTORS.map(s => `
          <div style="margin-bottom:9px">
            <div class="row" style="font-size:12px;margin-bottom:3px">
              <span>${esc(s.name)}</span>
              <span class="mono muted" style="margin-left:auto">${s.exposure}</span>
            </div>
            <div class="bar-track"><div class="bar-fill" style="width:${s.exposure}%;background:${s.exposure >= 90 ? 'var(--red)' : s.exposure >= 75 ? 'var(--orange)' : 'var(--blue)'}"></div></div>
            <div class="mono" style="font-size:9.5px;color:var(--text4);margin-top:3px">${esc(s.note)}</div>
          </div>`).join('')}
      </div>
    </div>

    <div class="grid2">
      <div class="panel">
        <div class="panel-t">Top threats to Bangladesh <span class="mut">by exposure score</span></div>
        ${top.map((g, i) => `
          <div class="rank-row">
            <span class="rank-n">${i + 1}</span>
            <span class="dot" style="width:8px;height:8px;border-radius:50%;background:${nationColor(g.country)}"></span>
            <div>
              <div class="rank-name" data-open="${esc(g.id)}">${esc(g.name)}</div>
              <div class="rank-sub">${esc(g.country)} · ${esc(STATUS[g.bd_status]?.label || '')}</div>
            </div>
            <span class="rank-score" style="color:${g.bd_relevance >= 90 ? 'var(--red)' : g.bd_relevance >= 75 ? 'var(--orange)' : 'var(--text2)'}">${g.bd_relevance}</span>
          </div>`).join('')}
      </div>

      <div class="panel">
        <div class="panel-t">
          National incident record
          <span style="margin-left:auto" class="seg" id="year-seg">
            <button class="${yearFilter === 'all' ? 'on' : ''}" data-y="all">All</button>
            ${years.slice(0, 4).map(y => `<button class="${yearFilter === y ? 'on' : ''}" data-y="${y}">${y}</button>`).join('')}
          </span>
        </div>
        <div style="max-height:520px;overflow-y:auto">
          ${incidents.map(i => `
            <div class="tl-item">
              <div class="tl-date">${esc(i.date)}</div>
              <div>
                <div class="tl-title">${esc(i.title)}</div>
                <div class="tl-meta">${esc(i.org)} · ${esc(i.sector)} · <span style="color:${sevCol(i.severity)}">${esc(i.severity.toUpperCase())}</span> · ${esc(i.actor)}</div>
                <div class="tl-sum">${esc(i.summary)}</div>
                <div class="tl-meta"><a href="${esc(safeUrl(i.url))}" target="_blank" rel="noopener">${esc(i.source)} ↗</a></div>
              </div>
            </div>`).join('')}
        </div>
      </div>
    </div>

    <div class="notice" style="margin-top:16px">
      <b>Analytic caveat.</b> Attribution is hard. Exposure scores are analyst judgements, not measurements; "assessed" actors have no publicly confirmed Bangladeshi victim and are listed because their documented targeting profile matches Bangladeshi infrastructure. Corroborate against primary sources before acting.
    </div>`;

  body.querySelectorAll('[data-open]').forEach(el =>
    el.addEventListener('click', () => onSelect(groups.find(g => g.id === el.dataset.open))));
  body.querySelectorAll('#year-seg button').forEach(b =>
    b.addEventListener('click', () => { yearFilter = b.dataset.y; renderLandscape(groups, onSelect); }));
}

function sevCol(s) {
  return { critical: 'var(--sev-crit)', high: 'var(--sev-high)', medium: 'var(--sev-med)', low: 'var(--sev-low)' }[s] || 'var(--text3)';
}

function donut(rows, total) {
  const R = 46, C = 2 * Math.PI * R;
  let off = 0;
  const segs = rows.map(([c, n]) => {
    const len = (n / total) * C;
    const s = `<circle cx="60" cy="60" r="${R}" fill="none" stroke="${nationColor(c)}" stroke-width="13"
       stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 60 60)"/>`;
    off += len;
    return s;
  }).join('');
  return `<svg width="120" height="120" viewBox="0 0 120 120" style="flex:none">
    ${segs}
    <text x="60" y="58" text-anchor="middle" fill="currentColor" font-size="22" font-weight="700" font-family="ui-monospace,monospace">${total}</text>
    <text x="60" y="73" text-anchor="middle" fill="#7c8aa0" font-size="8.5" font-family="ui-monospace,monospace">ACTORS</text>
  </svg>`;
}

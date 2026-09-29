/* Hunt — turn the corpus into something a Bangladeshi SOC can run today:
   detection leads, a TTP × actor matrix, a sector pivot and the national
   hardening checklist. */
import { esc, escAttr } from '../lib/security.js';
import { TACTIC, nationColor } from '../config.js';
import { SECTORS } from '../../data/actors.js';
import { toast } from '../detail.js';

let tab = 'detections';

export function renderHunt(groups, onSelect) {
  const body = document.getElementById('hunt-body');
  const tabs = [['detections', 'Detection leads'], ['matrix', 'TTP × Actor matrix'], ['sector', 'Sector pivot'], ['hardening', 'National hardening']];

  body.innerHTML = `
    <div class="v-head">
      <div class="v-title">Threat hunting — Bangladesh</div>
      <div class="v-sub">Every technique in the corpus carried through to something you can run in Defender XDR / Sentinel (KQL), Splunk (SPL) or a Sigma pipeline. Filters from the sidebar apply here.</div>
    </div>
    <div class="seg" style="margin-bottom:16px" id="hunt-tabs">
      ${tabs.map(([k, l]) => `<button class="${tab === k ? 'on' : ''}" data-t="${k}">${l}</button>`).join('')}
    </div>
    <div id="hunt-pane"></div>`;

  body.querySelectorAll('#hunt-tabs button').forEach(b =>
    b.addEventListener('click', () => { tab = b.dataset.t; renderHunt(groups, onSelect); }));

  const pane = document.getElementById('hunt-pane');
  if (tab === 'detections') detections(pane, groups);
  if (tab === 'matrix') matrix(pane, groups, onSelect);
  if (tab === 'sector') sector(pane, groups, onSelect);
  if (tab === 'hardening') hardening(pane);
}

/* ------------------------------------------------------------- detections */
function detections(pane, groups) {
  const rows = [];
  groups.forEach(g => (g.hunt || []).forEach(h => rows.push({ ...h, actor: g.name, id: g.id, country: g.country })));

  pane.innerHTML = `
    <div class="row" style="margin-bottom:12px;gap:10px">
      <input id="det-q" placeholder="Filter detections by name, actor or query text…"
        style="flex:1;padding:9px 13px;background:var(--bg2);border:1px solid var(--border);border-radius:9px;font-family:var(--mono);font-size:11.5px;outline:none">
      <span class="mono muted" style="font-size:11px">${rows.length} leads</span>
    </div>
    <div id="det-list">${rows.map(detCard).join('')}</div>`;

  const wire = () => {
    pane.querySelectorAll('.det-head').forEach(h => h.addEventListener('click', () => h.parentElement.classList.toggle('open')));
    pane.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', e => {
      e.stopPropagation(); navigator.clipboard?.writeText(b.dataset.copy); toast('Query copied');
    }));
  };
  wire();

  pane.querySelector('#det-q').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    const filtered = rows.filter(r => (r.title + r.actor + r.query + r.platform).toLowerCase().includes(q));
    pane.querySelector('#det-list').innerHTML = filtered.map(detCard).join('') || '<div class="pr-empty">No detections match.</div>';
    wire();
  });
}

function detCard(r) {
  return `<div class="det-item">
    <div class="det-head">
      <span class="det-plat">${esc(r.platform)}</span>
      <span class="det-title">${esc(r.title)}</span>
      <span class="det-actor" style="color:${nationColor(r.country)}">${esc(r.actor)}</span>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text3)"><path d="m6 9 6 6 6-6"/></svg>
    </div>
    <div class="det-body">
      <div class="code-block">${esc(r.query)}<button class="copy-btn" data-copy="${escAttr(r.query)}">copy</button></div>
    </div>
  </div>`;
}

/* ----------------------------------------------------------------- matrix */
function matrix(pane, groups, onSelect) {
  const techMap = new Map();
  groups.forEach(g => (g.ttps || []).forEach(([id, name, tac]) => {
    if (!techMap.has(id)) techMap.set(id, { id, name, tac, actors: new Set() });
    techMap.get(id).actors.add(g.id);
  }));
  const techs = [...techMap.values()].sort((a, b) => b.actors.size - a.actors.size || a.id.localeCompare(b.id));
  const cols = groups.slice().sort((a, b) => b.bd_relevance - a.bd_relevance);

  pane.innerHTML = `
    <div class="notice" style="margin-bottom:12px">
      <b>Coverage logic.</b> Techniques are ranked by how many tracked actors use them against Bangladesh — the top rows buy the broadest detection coverage per unit of engineering effort. Cell colour = the actor's ATT&CK tactic for that technique.
    </div>
    <div class="matrix-wrap" style="max-height:66vh">
      <table class="matrix">
        <thead><tr><th class="corner">technique</th>
          ${cols.map(g => `<th><div class="rot">${esc(g.name)}</div></th>`).join('')}
        </tr></thead>
        <tbody>
          ${techs.map(t => `<tr>
            <th title="${escAttr(t.name)}">${esc(t.id)} · ${esc(t.name.slice(0, 34))} <span style="color:var(--text4)">(${t.actors.size})</span></th>
            ${cols.map(g => {
              const on = t.actors.has(g.id);
              const col = TACTIC[t.tac]?.col || '#888';
              return `<td class="cell" ${on ? `data-open="${esc(g.id)}" style="background:${col}cc"` : ''} title="${escAttr(g.name + ' — ' + t.id)}"></td>`;
            }).join('')}
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;

  pane.querySelectorAll('[data-open]').forEach(c =>
    c.addEventListener('click', () => onSelect(groups.find(g => g.id === c.dataset.open))));
}

/* ----------------------------------------------------------- sector pivot */
function sector(pane, groups, onSelect) {
  const rows = SECTORS.map(s => {
    const hits = groups.filter(g =>
      (g.sectors || []).some(x => x.toLowerCase().includes(s.name.split(' ')[0].toLowerCase())) ||
      (g.bd_targets || []).some(x => x.toLowerCase().includes(s.name.split(' ')[0].toLowerCase()))
    );
    return { ...s, hits };
  }).sort((a, b) => b.hits.length - a.hits.length || b.exposure - a.exposure);

  pane.innerHTML = `
    <div class="notice" style="margin-bottom:12px"><b>Who is hunting my industry?</b> Sector exposure is the analyst score; the chips are every tracked actor whose documented targeting touches that sector in Bangladesh.</div>
    ${rows.map(r => `
      <div class="pivot-row">
        <div>
          <div class="pivot-name">${esc(r.name)}</div>
          <div class="mono" style="font-size:9.5px;color:var(--text4)">${esc(r.note)}</div>
        </div>
        <div class="pivot-actors">${r.hits.map(g => `<span class="pv-chip" data-open="${esc(g.id)}" style="border-left:3px solid ${nationColor(g.country)}">${esc(g.name)}</span>`).join('') || '<span class="muted mono" style="font-size:10px">no direct corpus match</span>'}</div>
        <span class="rank-score">${r.exposure}</span>
      </div>`).join('')}`;

  pane.querySelectorAll('[data-open]').forEach(c =>
    c.addEventListener('click', () => onSelect(groups.find(g => g.id === c.dataset.open))));
}

/* -------------------------------------------------------------- hardening */
function hardening(pane) {
  const items = [
    ['Enforce MFA on all critical systems', 'Directly counters the SideWinder credential-harvesting model against gov.bd webmail — stolen passwords alone stop being enough.'],
    ['Review and restrict remote access, VPNs and privileged accounts', 'INC Ransom affiliate tooling recovered by the CERT included OpenVPN configs and session tokens for long-term access.'],
    ['Patch internet-facing services, servers and firewalls urgently', '452 Bangladeshi IPs were found running end-of-life IIS; n8n (CVE-2026-21858) and MongoDB (CVE-2025-14847) exposures were identified nationally.'],
    ['Block Office child processes and template injection egress', 'Bitter, SideWinder and DoNot all chain document → EQNEDT32/mshta/rundll32 → implant.'],
    ['Disable unused ports and services; enforce least privilege', 'Reduces the opportunistic mass-exploitation surface that produces most Bangladeshi incidents.'],
    ['Monitor scheduled tasks masquerading as vendor telemetry', 'DoNot persists as a OneDrive-themed scheduled task running rundll32 against a DLL in %TEMP%.'],
    ['Segment and monitor payment/SWIFT environments; alert on off-hours activity', 'The 2016 heist ran across a weekend closure — Eid and Puja closures are the modern equivalent windows.'],
    ['Harden e-KYC: liveness + device binding + velocity checks', 'GoldPickaxe steals facial biometrics and identity documents to defeat onboarding checks.'],
    ['Keep offline, encrypted, tested backups', 'Krishi Bank and Biman show recovery — not prevention — decided the outcome.'],
    ['Inventory and monitor edge routers (incl. MikroTik) and CPE', 'Salt Typhoon-class actors live in provider and customer edge routers; MikroTik botnets are named in national alerts.'],
    ['Report IOCs and incidents to BGD e-GOV CIRT', 'cti@cirt.gov.bd / info@cirt.gov.bd · NCSA: notify@ncsa.gov.bd']
  ];
  pane.innerHTML = `
    <div class="notice" style="margin-bottom:12px">Derived from BGD e-GOV CIRT's national alerts, mapped to the actors in this corpus so each control has a named reason.</div>
    ${items.map(([t, why], i) => `
      <div class="pivot-row" style="align-items:flex-start">
        <span class="rank-n" style="padding-top:2px">${String(i + 1).padStart(2, '0')}</span>
        <div>
          <div class="pivot-name" style="min-width:auto">${esc(t)}</div>
          <div style="font-size:11.5px;color:var(--text3);line-height:1.6;margin-top:3px">${esc(why)}</div>
        </div>
      </div>`).join('')}`;
}

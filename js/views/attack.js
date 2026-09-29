/* ============================================================================
   ATT&CK coverage matrix

   The corpus carries 159 technique mappings across the tracked actors. This
   view aggregates them into an enterprise-ATT&CK style matrix, heat-weighted
   by how many Bangladesh-relevant actors are reported using each technique,
   and exports a MITRE ATT&CK Navigator layer so the same picture can be opened
   in the analyst's own tooling.

   The heat is a count of actors in *this corpus*, not a global prevalence
   score. A technique used by four BD-relevant actors is not necessarily more
   common worldwide - it is more common in the reporting that concerns
   Bangladesh, which is the question this console exists to answer.
   ========================================================================== */
import { esc } from '../lib/security.js';

/* Enterprise tactics in kill-chain order. Slugs match the phase names carried
   in the corpus and the shortnames ATT&CK itself uses. */
const TACTICS = [
  ['reconnaissance', 'Reconnaissance'],
  ['resource-development', 'Resource Development'],
  ['initial-access', 'Initial Access'],
  ['execution', 'Execution'],
  ['persistence', 'Persistence'],
  ['privilege-escalation', 'Privilege Escalation'],
  ['defense-evasion', 'Defense Evasion'],
  ['credential-access', 'Credential Access'],
  ['discovery', 'Discovery'],
  ['lateral-movement', 'Lateral Movement'],
  ['collection', 'Collection'],
  ['command-and-control', 'Command and Control'],
  ['exfiltration', 'Exfiltration'],
  ['impact', 'Impact']
];

/** id -> { id, name, tactic, actors:[group] } */
export function buildMatrix(groups) {
  const map = new Map();
  groups.forEach(g => (g.ttps || []).forEach(([id, name, tactic]) => {
    if (!id) return;
    let e = map.get(id);
    if (!e) { e = { id, name, tactic, actors: [] }; map.set(id, e); }
    if (!e.actors.includes(g)) e.actors.push(g);
  }));
  return map;
}

function heat(n, max) {
  if (!n) return { bg: 'transparent', fg: 'var(--text4)', bd: 'var(--border)' };
  const t = max <= 1 ? 1 : (n - 1) / (max - 1);          // 0..1
  const a = 0.13 + t * 0.55;
  return {
    bg: `rgba(240,84,79,${a.toFixed(3)})`,
    fg: t > 0.5 ? '#fff' : 'var(--text2)',
    bd: `rgba(240,84,79,${(0.28 + t * 0.5).toFixed(3)})`
  };
}

/* ------------------------------------------------------- Navigator layer */

/** A MITRE ATT&CK Navigator v4.5 layer for the current selection. */
export function navigatorLayer(groups) {
  const matrix = buildMatrix(groups);
  const max = Math.max(1, ...[...matrix.values()].map(e => e.actors.length));
  return {
    name: 'ThreatNexus BD — Bangladesh-relevant ATT&CK coverage',
    versions: { attack: '15', navigator: '4.9.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description:
      `Techniques reported against Bangladeshi targets across ${groups.length} tracked actors. ` +
      'Score = number of actors in this corpus reported using the technique, not global prevalence. ' +
      'Source: https://akramsakib.github.io/bangladesh-threat-intelligence/',
    filters: { platforms: ['Windows', 'Linux', 'macOS', 'Network'] },
    sorting: 3,
    layout: { layout: 'side', showID: true, showName: true },
    hideDisabled: false,
    techniques: [...matrix.values()].map(e => ({
      techniqueID: e.id,
      score: e.actors.length,
      comment: e.actors.map(a => a.name).join(', '),
      enabled: true
    })),
    gradient: {
      colors: ['#2a1416', '#f0544f'],
      minValue: 0,
      maxValue: max
    },
    legendItems: [
      { label: `1 actor`, color: '#4a1f21' },
      { label: `${max} actors (max)`, color: '#f0544f' }
    ],
    showTacticRowBackground: true,
    tacticRowBackground: '#12151c',
    selectTechniquesAcrossTactics: true
  };
}

function download(name, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* --------------------------------------------------------------- render */

export function renderAttack(groups, onSelect) {
  const body = document.getElementById('attack-body');
  if (!body) return;

  const matrix = buildMatrix(groups);
  const entries = [...matrix.values()];
  const max = Math.max(1, ...entries.map(e => e.actors.length));
  const used = new Set(entries.map(e => e.tactic));
  const cols = TACTICS.filter(([slug]) => used.has(slug));
  const totalMaps = groups.reduce((n, g) => n + (g.ttps || []).length, 0);

  body.innerHTML = `
    <div class="view-head">
      <div>
        <h2>ATT&amp;CK coverage</h2>
        <p class="sub">${entries.length} distinct techniques from ${totalMaps} mappings across
        ${groups.length} actors. Cell heat = how many tracked actors are reported using that
        technique against Bangladeshi targets.</p>
      </div>
      <button class="btn-ghost" style="padding:7px 13px;font-size:11.5px;white-space:nowrap" id="nav-export">&darr; ATT&amp;CK Navigator layer</button>
    </div>

    <div class="atk-note">
      Scores count actors <b>in this corpus</b>, not global prevalence. A technique weighted
      heavily here is prominent in reporting that concerns Bangladesh &mdash; which is a different
      claim from being common worldwide.
    </div>

    <div class="atk-grid">
      ${cols.map(([slug, label]) => {
        const cells = entries.filter(e => e.tactic === slug)
          .sort((a, b) => b.actors.length - a.actors.length || a.id.localeCompare(b.id));
        return `<div class="atk-col">
          <div class="atk-col-h">${esc(label)}<span class="atk-col-n">${cells.length}</span></div>
          ${cells.map(e => {
            const h = heat(e.actors.length, max);
            return `<div class="atk-cell" data-tid="${esc(e.id)}"
              style="background:${h.bg};border-color:${h.bd};color:${h.fg}"
              title="${esc(e.id)} — ${esc(e.name)}\n${e.actors.length} actor(s): ${esc(e.actors.map(a => a.name).join(', '))}">
              <span class="atk-tid">${esc(e.id)}</span>
              <span class="atk-tn">${esc(e.name)}</span>
              <span class="atk-cnt">${e.actors.length}</span>
            </div>`;
          }).join('')}
        </div>`;
      }).join('')}
    </div>`;

  const btn = document.getElementById('nav-export');
  if (btn) btn.addEventListener('click', () => download('threatnexus-bd-attack-layer.json', navigatorLayer(groups)));

  body.querySelectorAll('.atk-cell').forEach(c => {
    c.addEventListener('click', () => {
      const e = matrix.get(c.dataset.tid);
      if (e && e.actors.length === 1 && onSelect) onSelect(e.actors[0]);
      else if (e) {
        const q = document.getElementById('spotlight-input') || document.getElementById('search-input');
        if (q) { q.value = e.id; q.dispatchEvent(new Event('input', { bubbles: true })); }
      }
    });
  });
}

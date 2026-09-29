/* Diamond Model cards — adversary / capability / infrastructure / victim,
   with the victim axis expressed in Bangladeshi terms. */
import { esc } from '../lib/security.js';
import { nationColor, MOTIVATION, STATUS } from '../config.js';

export function renderDiamond(groups, onSelect) {
  const body = document.getElementById('diamond-body');
  if (!groups.length) { body.innerHTML = '<div class="pr-empty">No actors match the current filters.</div>'; return; }

  body.innerHTML = `
    <div class="v-head">
      <div class="v-title">Diamond Model — Bangladesh view</div>
      <div class="v-sub">One card per actor. The victim axis is scoped to Bangladeshi organisations and asset classes, so each diamond reads as a local targeting hypothesis rather than a global summary.</div>
    </div>
    ${groups.map(g => card(g)).join('')}`;

  body.querySelectorAll('[data-open]').forEach(el =>
    el.addEventListener('click', () => onSelect(groups.find(x => x.id === el.dataset.open))));
}

function card(g) {
  const mot = MOTIVATION[g.motivation] || { hex: '#888', label: g.motivation };
  const list = (arr, n = 6) => (arr || []).slice(0, n).map(x => `<span class="tag">${esc(Array.isArray(x) ? x[0] : x)}</span>`).join('') || '<span class="muted">—</span>';
  return `
  <div class="dia-card">
    <div class="dia-head" data-open="${esc(g.id)}" style="cursor:pointer">
      <span class="dot" style="background:${nationColor(g.country)}"></span>
      <span class="dia-name">${esc(g.name)}</span>
      <span class="tag" style="color:${mot.hex};border-color:${mot.hex}55">${esc(mot.label)}</span>
      <span class="tag" style="color:${STATUS[g.bd_status]?.hex}">${esc(STATUS[g.bd_status]?.label || '')}</span>
      <span style="margin-left:auto" class="mono muted">BD ${esc(g.bd_relevance)}/100</span>
    </div>
    <div class="dia-grid">
      <div class="dia-q adversary">
        <div class="dia-q-t">Adversary</div>
        <div class="dia-q-body"><b>${esc(g.country)}</b> · ${esc(g.agency)}<br>${esc(g.aka)}</div>
      </div>
      <div class="dia-q capability">
        <div class="dia-q-t">Capability</div>
        <div class="dia-q-body">${list((g.malware || []).map(m => m[0]))}<br><span class="mono muted" style="font-size:10px">${(g.ttps || []).length} ATT&CK techniques · ${(g.cves || []).length} CVEs</span></div>
      </div>
      <div class="dia-q infrastructure">
        <div class="dia-q-t">Infrastructure</div>
        <div class="dia-q-body">${(g.infra || []).slice(0, 3).map(i => `• ${esc(i)}`).join('<br>') || '<span class="muted">—</span>'}</div>
      </div>
      <div class="dia-q victim">
        <div class="dia-q-t">Victim — Bangladesh</div>
        <div class="dia-q-body">${list(g.bd_targets, 5)}</div>
      </div>
    </div>
  </div>`;
}

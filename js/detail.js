/* Actor dossier drawer. */
import { esc, escAttr, safeUrl, host } from './lib/security.js';
import { TACTIC, MOTIVATION, STATUS, nationColor, freshness } from './config.js';

const $ = id => document.getElementById(id);

export function openDetail(g) {
  if (!g) return;
  const panel = $('detail');
  $('dp-name').textContent = g.name;
  $('dp-sub').innerHTML =
    `${esc(g.apt)} · ${esc(g.country)} · <span style="color:${nationColor(g.country)}">${esc(STATUS[g.bd_status]?.label || g.bd_status)}</span>`;

  const fr = freshness(g.last_seen);
  const mot = MOTIVATION[g.motivation] || { hex: '#888', label: g.motivation };

  const sec = (title, body, extra = '') => body
    ? `<div class="dp-sec"><div class="dp-sec-t">${esc(title)}${extra}</div>${body}</div>` : '';

  const tags = (arr, cls = '') => (arr || []).map(x => `<span class="tag ${cls}">${esc(x)}</span>`).join('');

  const ttps = (g.ttps || []).map(([id, name, tac]) => {
    const t = TACTIC[tac] || { label: tac, col: '#888' };
    return `<div class="ttp-row">
      <span class="ttp-id">${esc(id)}</span>
      <span class="ttp-name">${esc(name)}</span>
      <span class="ttp-tac" style="color:${t.col};background:${t.col}1f">${esc(t.label)}</span>
    </div>`;
  }).join('');

  const malware = (g.malware || []).map(([n, note]) =>
    `<div class="kv-item"><div class="kv-k">${esc(n)}</div><div class="kv-v">${esc(note)}</div></div>`).join('');

  const camps = (g.campaigns || []).map(c =>
    `<div class="kv-item">
       <div class="kv-date">${esc(c.date)}</div>
       <div class="kv-k">${esc(c.name)}</div>
       <div class="kv-v">${esc(c.summary)}</div>
       <div class="kv-v" style="color:var(--text4)">Source: ${esc(c.source)}</div>
     </div>`).join('');

  const iocs = (g.iocs || []).map(([type, value, note]) =>
    `<div class="kv-item">
       <div class="row"><span class="tag">${esc(type)}</span><span class="kv-k" style="word-break:break-all">${esc(value)}</span></div>
       <div class="kv-v">${esc(note)}</div>
       <button class="copy-btn" style="position:static;margin-top:6px" data-copy="${escAttr(value)}">copy</button>
       <button class="copy-btn" style="position:static;margin-top:6px" data-prism="${escAttr(value)}">→ Prism</button>
     </div>`).join('');

  const hunts = (g.hunt || []).map((h, i) =>
    `<div class="kv-item">
       <div class="row" style="margin-bottom:6px"><span class="tag">${esc(h.platform)}</span><span class="kv-k">${esc(h.title)}</span></div>
       <div class="code-block">${esc(h.query)}<button class="copy-btn" data-copy="${escAttr(h.query)}">copy</button></div>
     </div>`).join('');

  const sources = (g.sources || []).map(s =>
    `<a class="src-link" href="${escAttr(safeUrl(s.url))}" target="_blank" rel="noopener">${esc(s.name)}
       <span class="src-host">${esc(host(s.url))}</span></a>`).join('');

  $('dp-body').innerHTML = `
    ${g.archived ? `<div class="notice" style="margin-bottom:14px"><b>Archived.</b> ${esc(g.archive_reason || '')}</div>` : ''}

    <div class="dp-sec">
      <div class="row" style="gap:8px;flex-wrap:wrap;margin-bottom:10px">
        <span class="tag" style="color:${mot.hex};border-color:${mot.hex}66;background:${mot.hex}14">${esc(mot.label)}</span>
        <span class="tag" style="color:${fr.hex};border-color:${fr.hex}66">last seen ${esc(g.last_seen)}</span>
        <span class="tag">confidence: ${esc(g.confidence)}</span>
        <span class="tag accent">BD exposure ${esc(g.bd_relevance)}/100</span>
      </div>
      <div class="bar-track"><div class="bar-fill" style="width:${Number(g.bd_relevance) || 0}%;background:linear-gradient(90deg,var(--bd-green),var(--bd-red))"></div></div>
    </div>

    ${sec('Identity', `<dl class="dp-grid">
      <dt>Aliases</dt><dd>${esc(g.aka)}</dd>
      <dt>Sponsor</dt><dd>${esc(g.agency)}</dd>
      <dt>Active</dt><dd>${esc(g.active_since)} → ${esc(g.last_seen)}</dd>
      ${g.mitre_group ? `<dt>MITRE</dt><dd><a href="https://attack.mitre.org/groups/${escAttr(g.mitre_group)}/" target="_blank" rel="noopener">${esc(g.mitre_group)}</a></dd>` : ''}
      <dt>BD status</dt><dd>${esc(STATUS[g.bd_status]?.desc || '')}</dd>
    </dl>`)}

    ${sec('Assessment', `<p class="dp-p">${esc(g.description)}</p>`)}
    ${sec('Bangladeshi targets', tags(g.bd_targets, 'accent'))}
    ${sec('Sectors', tags(g.sectors))}
    ${sec('Target geography', tags(g.targets))}
    ${sec('ATT&CK techniques', ttps, ` <span style="color:var(--text4)">${(g.ttps || []).length}</span>`)}
    ${sec('Malware & tooling', malware)}
    ${sec('Exploited CVEs', tags(g.cves, 'sev-high'))}
    ${sec('Infrastructure patterns', tags(g.infra))}
    ${sec('Campaigns', camps)}
    ${sec('Public indicators', iocs)}
    ${sec('Hunt leads', hunts)}
    ${sec('Sources', sources)}
  `;

  panel.classList.add('on');
  panel.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => {
    navigator.clipboard?.writeText(b.dataset.copy);
    toast('Copied to clipboard');
  }));
  panel.querySelectorAll('[data-prism]').forEach(b => b.addEventListener('click', () => {
    document.dispatchEvent(new CustomEvent('prism-lookup', { detail: { ioc: b.dataset.prism } }));
  }));
  try { history.replaceState(history.state, '', location.pathname + '#actor=' + encodeURIComponent(g.id)); } catch {}
}

export function closeDetail() {
  $('detail').classList.remove('on');
  try { history.replaceState(history.state, '', location.pathname); } catch {}
}

export function toast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.add('on');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('on'), 1800);
}

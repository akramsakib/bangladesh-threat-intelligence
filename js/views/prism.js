/* PRISM BD — indicator enrichment.
   Keyless public sources only (RDAP, DNS, crt.sh, Shodan InternetDB, RIPEstat,
   ipwho.is) plus a lookup against the ThreatNexus BD corpus. Every finding is
   labelled with the provider that supplied it. Infrastructure facts never move
   the verdict on their own, and "benign" is never asserted — absence of
   evidence returns UNKNOWN. */
import { esc, escAttr } from '../lib/security.js';
import { toast } from '../detail.js';

let last = null;

export function renderPrism() {
  const body = document.getElementById('prism-body');
  body.innerHTML = `
    <div class="v-head">
      <div class="v-title">Prism — indicator enrichment</div>
      <div class="v-sub">Refract one indicator into its full public picture: registration, hosting, DNS, certificates, exposed services and any sighting inside the Bangladesh corpus. Every datum carries its provider. No API keys, no account, nothing logged.</div>
    </div>
    <div class="row" style="gap:6px;flex-wrap:wrap">
      <span class="mono muted" style="font-size:10.5px">Live sources</span>
      ${['RDAP', 'Cloudflare DoH', 'crt.sh', 'Shodan InternetDB', 'RIPEstat', 'ipwho.is', 'ThreatNexus BD corpus'].map(s => `<span class="tag">${esc(s)}</span>`).join('')}
    </div>
    <div class="prism-input-row">
      <input id="prism-input" placeholder="8.8.8.8  ·  mailbox3-inbox1-bd.com  ·  cirt.gov.bd  ·  AS17494" autocomplete="off">
      <button class="btn-primary" id="prism-go">Enrich →</button>
    </div>
    <div class="row" style="gap:6px;flex-wrap:wrap;margin-bottom:16px">
      <span class="mono muted" style="font-size:10.5px">Try:</span>
      ${['mailbox3-inbox1-bd.com', '146.70.118.226', 'cirt.gov.bd', 'drive-dgdp-gov-bd-files.netlify.app'].map(s =>
        `<span class="pv-chip" data-try="${escAttr(s)}">${esc(s)}</span>`).join('')}
    </div>
    <div id="prism-out">${last ? '' : '<div class="pr-empty">Submit a domain, IP, URL or ASN to begin.</div>'}</div>`;

  document.getElementById('prism-go').addEventListener('click', run);
  document.getElementById('prism-input').addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
  body.querySelectorAll('[data-try]').forEach(c => c.addEventListener('click', () => {
    document.getElementById('prism-input').value = c.dataset.try; run();
  }));

  if (last) paint(last);
}

export function lookup(ioc) {
  const input = document.getElementById('prism-input');
  if (input) { input.value = ioc; run(); }
}

async function run() {
  const v = document.getElementById('prism-input').value.trim();
  if (!v) return;
  const out = document.getElementById('prism-out');
  out.innerHTML = `<div class="panel"><div class="panel-t">Querying public sources…</div>
    ${'<div class="skel" style="margin-bottom:8px"></div>'.repeat(4)}</div>`;
  try {
    const res = await fetch('/api/enrich?ioc=' + encodeURIComponent(v));
    const data = await res.json();
    last = data;
    paint(data);
  } catch (e) {
    out.innerHTML = `<div class="pr-empty">Enrichment service unavailable (${esc(e.message)}).</div>`;
  }
}

function paint(d) {
  const out = document.getElementById('prism-out');
  const cls = d.verdict === 'MALICIOUS' ? 'malicious' : d.verdict === 'SUSPICIOUS' ? 'suspicious' : 'unknown';

  out.innerHTML = `
    <div class="pr-verdict ${cls}">
      <div>
        <div class="mono muted" style="font-size:9.5px;letter-spacing:.1em">VERDICT</div>
        <div class="vd">${esc(d.verdict || 'UNKNOWN')}</div>
      </div>
      <div style="flex:1">
        <div class="mono" style="font-size:12px;word-break:break-all">${esc(d.indicator)} <span class="tag">${esc(d.type)}</span></div>
        <div style="font-size:12px;color:var(--text2);margin-top:4px">${esc(d.narrative || '')}</div>
      </div>
      <button class="btn-ghost" id="pr-copy">Copy report</button>
    </div>

    ${(d.signals || []).length ? `<div class="panel" style="margin-bottom:12px">
      <div class="panel-t">Signals <span class="mut">what moved the verdict</span></div>
      ${d.signals.map(s => `<div class="row" style="padding:4px 0;font-size:12px">
        <span class="pill ${s.weight === 'high' ? 'crit' : s.weight === 'medium' ? 'warn' : ''}">${esc(s.weight)}</span>
        <span>${esc(s.text)}</span>
        <span class="mono muted" style="margin-left:auto;font-size:10px">${esc(s.source)}</span>
      </div>`).join('')}
    </div>` : ''}

    ${(d.sources || []).map(s => `
      <div class="pr-src">
        <div class="pr-src-h">
          <span class="dot" style="width:7px;height:7px;border-radius:50%;background:${s.ok ? 'var(--green)' : 'var(--text4)'}"></span>
          <span class="pr-src-name">${esc(s.name)}</span>
          <span class="mono muted" style="font-size:9.5px;margin-left:auto">${esc(s.observed || '')}</span>
        </div>
        ${s.error ? `<div class="mono muted" style="font-size:10.5px">${esc(s.error)}</div>` :
          `<dl class="pr-kv">${Object.entries(s.data || {}).map(([k, v]) => {
            const empty = v == null || (Array.isArray(v) && !v.length) || String(v).trim() === '';
            const txt = empty ? 'none observed' : (Array.isArray(v) ? v.slice(0, 12).join(', ') : String(v));
            return `<dt>${esc(k.replace(/_/g, ' '))}</dt><dd${empty ? ' class="mut"' : ''}>${esc(txt).slice(0, 700)}</dd>`;
          }).join('')}</dl>`}
      </div>`).join('')}

    <div class="notice" style="margin-top:14px">
      Infrastructure facts (hosting, registrar, ASN) never move the malice verdict on their own. <b>Benign is never asserted</b> — absence of evidence returns UNKNOWN, not clean.
    </div>`;

  document.getElementById('pr-copy')?.addEventListener('click', () => {
    navigator.clipboard?.writeText(JSON.stringify(d, null, 2));
    toast('Report JSON copied');
  });
}

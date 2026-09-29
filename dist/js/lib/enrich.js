/* ============================================================================
   Isomorphic IOC enrichment engine.

   Runs unchanged in two places:
     · inside server.mjs, when the Node edge service is available
     · directly in the browser, when the app is served as static files
       (every provider below sends Access-Control-Allow-Origin: *)

   Rules carried over from the corpus doctrine:
     · infrastructure facts never move the malice verdict on their own
     · "benign" is never asserted — absence of evidence returns UNKNOWN
   ========================================================================== */
import { GROUPS } from '../../data/actors.js';

const RE = {
  ipv4: /^(\d{1,3}\.){3}\d{1,3}$/,
  domain: /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i,
  sha256: /^[a-f0-9]{64}$/i, md5: /^[a-f0-9]{32}$/i,
  asn: /^as\d+$/i, url: /^https?:\/\//i
};

export function classify(v) {
  const s = String(v || '').trim().replace(/\[\.\]/g, '.').replace(/^hxxp/i, 'http');
  if (RE.url.test(s)) return { type: 'url', value: s };
  if (RE.ipv4.test(s)) return { type: 'ipv4', value: s };
  if (RE.asn.test(s)) return { type: 'asn', value: s.toUpperCase() };
  if (RE.sha256.test(s)) return { type: 'sha256', value: s.toLowerCase() };
  if (RE.md5.test(s)) return { type: 'md5', value: s.toLowerCase() };
  if (RE.domain.test(s)) return { type: 'domain', value: s.toLowerCase() };
  return { type: 'unknown', value: s };
}

async function j(url, opts = {}, ms = 12000) {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(ms),
    headers: { accept: 'application/json' },
    ...opts
  });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

function corpusSighting(value) {
  const v = String(value).toLowerCase();
  const hits = [];
  for (const g of GROUPS) {
    for (const [type, val, note] of (g.iocs || [])) {
      const clean = String(val).toLowerCase().replace(/\[\.\]/g, '.');
      if (clean === v || (v.length > 6 && clean.includes(v))) hits.push({ actor: g.name, type, note });
    }
    for (const inf of (g.infra || [])) {
      if (v.length > 6 && String(inf).toLowerCase().includes(v)) {
        hits.push({ actor: g.name, type: 'infrastructure-pattern', note: inf });
      }
    }
  }
  return hits;
}

export async function enrich(raw) {
  const { type, value } = classify(raw);
  const out = { indicator: value, type, generated_at: new Date().toISOString(), sources: [], signals: [] };
  const stamp = () => new Date().toISOString().replace('T', ' ').slice(0, 16) + 'Z';
  const push = (name, ok, data, error) => out.sources.push({ name, ok, data, error, observed: stamp() });

  /* 0 — local corpus, always first and always authoritative for the verdict */
  const sight = corpusSighting(value);
  push('ThreatNexus BD corpus', true,
    sight.length
      ? { sightings: sight.map(s => `${s.actor} — ${s.type}: ${s.note}`) }
      : { sightings: 'no prior sighting in the BD corpus' });
  if (sight.length) {
    out.signals.push({ weight: 'high', text: `Matches a published indicator for ${sight[0].actor}`, source: 'ThreatNexus BD corpus' });
  }

  const tasks = [];

  if (type === 'domain' || type === 'url') {
    let host = value;
    try { if (type === 'url') host = new URL(value).hostname; } catch { /* keep raw */ }

    // RDAP only answers for a registrable domain — walk up the labels
    const parts = host.split('.');
    const candidates = [];
    for (let i = 0; i <= parts.length - 2; i++) candidates.push(parts.slice(i).join('.'));

    tasks.push((async () => {
      let r = null, used = host, err = '';
      for (const cand of candidates.slice(0, 3)) {
        try { r = await j(`https://rdap.org/domain/${encodeURIComponent(cand)}`); used = cand; break; }
        catch (e) { err = String(e.message); }
      }
      if (!r) { push('RDAP (registration)', false, null, `no RDAP record for ${host} (${err})`); return; }
      const events = Object.fromEntries((r.events || []).map(e => [e.eventAction, (e.eventDate || '').slice(0, 10)]));
      const reg = (r.entities || []).find(e => (e.roles || []).includes('registrar'));
      const created = events.registration;
      if (created) {
        const ageDays = Math.floor((Date.now() - new Date(created).getTime()) / 86400000);
        if (ageDays >= 0 && ageDays < 90) {
          out.signals.push({ weight: 'medium', text: `Domain registered ${ageDays} days ago — young infrastructure`, source: 'RDAP' });
        }
      }
      push('RDAP (registration)', true, {
        queried: used + (used === host ? '' : `  (registrable parent of ${host})`),
        registrar: reg?.vcardArray?.[1]?.find(x => x[0] === 'fn')?.[3] || 'n/a',
        registered: created || 'n/a',
        expires: events.expiration || 'n/a',
        status: (r.status || []).join(', ') || 'n/a',
        nameservers: (r.nameservers || []).map(n => n.ldhName)
      });
    })().catch(e => push('RDAP (registration)', false, null, String(e.message))));

    tasks.push((async () => {
      const r = await j(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
        { headers: { accept: 'application/dns-json' } });
      push('Cloudflare DoH (A records)', true, {
        answers: (r.Answer || []).map(a => `${a.name} → ${a.data} (ttl ${a.TTL})`)
      });
    })().catch(e => push('Cloudflare DoH (A records)', false, null, String(e.message))));

    tasks.push((async () => {
      const r = await j(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json&limit=20`, {}, 18000);
      const arr = Array.isArray(r) ? r.slice(0, 15) : [];
      push('crt.sh (certificate transparency)', true, {
        certificates_seen: arr.length,
        issuers: [...new Set(arr.map(c => c.issuer_name?.split('O=')[1]?.split(',')[0] || 'n/a'))].slice(0, 5),
        names: [...new Set(arr.flatMap(c => String(c.name_value || '').split('\n')))].slice(0, 12),
        first_seen: arr.length ? arr[arr.length - 1].not_before?.slice(0, 10) : 'n/a'
      });
    })().catch(() => push('crt.sh (certificate transparency)', false, null,
      'crt.sh did not respond in time — it is frequently rate-limited, retry shortly')));

    /* Bangladesh-specific tradecraft heuristics */
    if (/\.(netlify\.app|pages\.dev|workers\.dev|b4a\.run|vercel\.app|glitch\.me)$/i.test(host)) {
      out.signals.push({
        weight: 'medium',
        text: 'Hosted on a free app platform — matches SideWinder credential-portal tradecraft against gov.bd targets',
        source: 'ThreatNexus BD heuristic'
      });
    }
    if (/gov[-.]?bd|dgdp|dgfi|bangladesh|sonali|krishi|bkash|nagad/i.test(host) && !/\.(gov|mil)\.bd$/i.test(host)) {
      out.signals.push({
        weight: 'high',
        text: 'Contains Bangladeshi government, defence or financial keywords but is not on an official .bd domain — likely lookalike',
        source: 'ThreatNexus BD heuristic'
      });
    }
  }

  if (type === 'ipv4') {
    tasks.push((async () => {
      const r = await j(`https://internetdb.shodan.io/${value}`);
      push('Shodan InternetDB', true, {
        open_ports: r.ports || [], hostnames: r.hostnames || [],
        tags: r.tags || [], vulns: r.vulns || [], cpes: (r.cpes || []).slice(0, 8)
      });
      if ((r.vulns || []).length) {
        out.signals.push({ weight: 'medium', text: `${r.vulns.length} known CVEs exposed on this host`, source: 'Shodan InternetDB' });
      }
    })().catch(e => push('Shodan InternetDB', false, null, 'no record / ' + String(e.message))));

    tasks.push((async () => {
      const r = await j(`https://ipwho.is/${value}`);
      push('ipwho.is (geo/ASN)', true, {
        country: `${r.country || '?'} (${r.country_code || '?'})`,
        city: r.city || 'n/a',
        asn: r.connection?.asn ? 'AS' + r.connection.asn : 'n/a',
        org: r.connection?.org || r.connection?.isp || 'n/a',
        type: r.type || 'n/a'
      });
      if (r.country_code === 'BD') {
        out.signals.push({ weight: 'low', text: 'Address geolocates inside Bangladesh', source: 'ipwho.is' });
      }
    })().catch(e => push('ipwho.is (geo/ASN)', false, null, String(e.message))));

    tasks.push((async () => {
      const r = await j(`https://stat.ripe.net/data/network-info/data.json?resource=${value}`);
      push('RIPEstat (network info)', true, { prefix: r.data?.prefix || 'n/a', asns: r.data?.asns || [] });
    })().catch(e => push('RIPEstat (network info)', false, null, String(e.message))));
  }

  if (type === 'asn') {
    tasks.push((async () => {
      const r = await j(`https://stat.ripe.net/data/as-overview/data.json?resource=${value}`);
      push('RIPEstat (AS overview)', true, {
        holder: r.data?.holder || 'n/a',
        announced: String(r.data?.announced),
        block: r.data?.block?.desc || 'n/a'
      });
    })().catch(e => push('RIPEstat (AS overview)', false, null, String(e.message))));
  }

  if (type === 'sha256' || type === 'md5') {
    push('Hash pivots (no-key)', true, {
      note: 'No keyless public hash-reputation source is bundled. Pivot manually:',
      malwarebazaar: `https://bazaar.abuse.ch/browse.php?search=${value}`,
      virustotal: `https://www.virustotal.com/gui/file/${value}`,
      triage: `https://tria.ge/s?q=${value}`
    });
  }

  await Promise.all(tasks);

  const high = out.signals.filter(s => s.weight === 'high').length;
  const med = out.signals.filter(s => s.weight === 'medium').length;
  out.verdict = high ? 'MALICIOUS' : med >= 2 ? 'SUSPICIOUS' : med === 1 ? 'INCONCLUSIVE' : 'UNKNOWN';
  out.narrative = high
    ? 'Positive evidence of malicious use found in tracked reporting. Treat as hostile and hunt retrospectively across the estate.'
    : med
      ? 'Contextual signals warrant caution, but no positive evidence of malicious use was found in the keyless sources queried.'
      : 'No positive evidence of malicious use was found in the public sources queried. This is not an assertion that the indicator is benign.';

  // stable ordering: corpus first, then successful sources, then failures
  out.sources.sort((a, b) => (a.name.startsWith('ThreatNexus') ? -1 : b.name.startsWith('ThreatNexus') ? 1 : 0) || (b.ok - a.ok));
  return out;
}

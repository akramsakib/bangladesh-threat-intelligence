/* ============================================================================
   ThreatNexus BD — edge service (zero dependencies)
   · static asset serving with SPA fallback
   · /api/feed/*   RSS aggregation + Bangladesh relevance scoring (15m cache)
   · /api/enrich   keyless IOC enrichment (RDAP, DoH, crt.sh, InternetDB,
                   RIPEstat, ipwho.is) + corpus sighting
   · /api/taxii2/* STIX 2.1 objects over a read-only TAXII 2.1 surface
   ========================================================================== */
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { GROUPS } from './data/actors.js';
import { BD_ADVISORIES } from './data/advisories.js';

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const PORT = process.env.PORT || 3000;
const ROUTES = ['/', '/globe', '/cluster', '/diamond', '/threat-landscape', '/brief', '/feed', '/hunt', '/prism', '/enrich'];

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml; charset=utf-8'
};

/* --------------------------------------------------------------- BD model */
const BD_KEYWORDS = [
  'bangladesh', 'bangladeshi', 'dhaka', 'chattogram', 'chittagong', 'sylhet', 'khulna',
  'bgd e-gov', 'cirt.gov.bd', 'gov.bd', 'bangladesh bank', 'bkash', 'nagad', 'biman',
  'krishi bank', 'sonali bank', 'dgfi', 'dgdp', 'rapid action battalion',
  'south asia', 'south asian', 'bay of bengal'
];
const ACTOR_TERMS = [];
for (const g of GROUPS) {
  ACTOR_TERMS.push(g.name.toLowerCase());
  String(g.aka || '').split('·').forEach(a => { const s = a.trim().toLowerCase(); if (s.length > 3) ACTOR_TERMS.push(s); });
  if (g.apt && g.apt.length > 3) ACTOR_TERMS.push(g.apt.toLowerCase());
}

const SOURCES = [
  { id: 'thn',       name: 'The Hacker News',   cat: 'news',   url: 'https://feeds.feedburner.com/TheHackersNews' },
  { id: 'bleeping',  name: 'BleepingComputer',  cat: 'news',   url: 'https://www.bleepingcomputer.com/feed/' },
  { id: 'record',    name: 'The Record',        cat: 'news',   url: 'https://therecord.media/feed' },
  { id: 'darkread',  name: 'Dark Reading',      cat: 'news',   url: 'https://www.darkreading.com/rss.xml' },
  { id: 'talos',     name: 'Cisco Talos',       cat: 'vendor', url: 'https://blog.talosintelligence.com/rss/' },
  { id: 'unit42',    name: 'Unit 42',           cat: 'vendor', url: 'https://unit42.paloaltonetworks.com/feed/' },
  { id: 'securelist',name: 'Kaspersky Securelist', cat: 'vendor', url: 'https://securelist.com/feed/' },
  { id: 'welivesec', name: 'ESET WeLiveSecurity', cat: 'vendor', url: 'https://www.welivesecurity.com/en/rss/feed/' },
  { id: 'cisa',      name: 'CISA Advisories',   cat: 'gov',    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml' },
  { id: 'sans',      name: 'SANS ISC Diary',    cat: 'gov',    url: 'https://isc.sans.edu/rssfeed_full.xml' }
];

const cache = { items: [], sources: [], at: 0 };
const TTL = 15 * 60 * 1000;

const decode = t => String(t || '')
  .replace(/&nbsp;/gi, ' ').replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
  .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
  .replace(/&quot;/gi, '"').replace(/&apos;|&#39;|&rsquo;|&#8217;/gi, "'")
  .replace(/&lsquo;|&#8216;/gi, "'").replace(/&ldquo;|&rdquo;/gi, '"')
  .replace(/&mdash;/gi, '\u2014').replace(/&ndash;/gi, '\u2013').replace(/&hellip;/gi, '\u2026')
  .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&amp;/gi, '&');

const strip = raw => {
  let t = String(raw || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  // feeds double-escape: decode, strip, decode, strip again
  for (let i = 0; i < 3; i++) {
    const before = t;
    t = decode(t).replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]*>/g, ' ');
    if (t === before) break;
  }
  return t.replace(/\s+/g, ' ').trim();
};

const tagVal = (block, tag) => {
  const m = block.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
  return m ? strip(m[1]) : '';
};

function severityOf(text) {
  const t = text.toLowerCase();
  if (/zero-day|zero day|actively exploited|exploited in the wild|critical rce|unauthenticated rce|emergency/.test(t)) return 'critical';
  if (/ransomware|breach|data leak|apt|espionage|backdoor|critical|cve-/.test(t)) return 'high';
  if (/phishing|malware|vulnerability|stealer|botnet|scam/.test(t)) return 'medium';
  return 'info';
}

function bdScore(text) {
  const t = text.toLowerCase();
  const hits = [];
  for (const k of BD_KEYWORDS) {
    const re = new RegExp('(^|[^a-z0-9])' + k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^a-z0-9]|$)', 'i');
    if (re.test(t)) hits.push(k);
  }
  const actors = [];
  for (const g of GROUPS) {
    const terms = [g.name.toLowerCase(), ...(String(g.aka || '').split('·').map(s => s.trim().toLowerCase()).filter(s => s.length > 4))];
    if (terms.some(term => t.includes(term))) actors.push(g.name);
  }
  const reason = actors.length ? 'tracked actor: ' + actors[0] : hits.length ? 'keyword: ' + hits[0] : '';
  return { bd: hits.length > 0 || actors.length > 0, reason, actors };
}

async function fetchSource(s) {
  const ctl = AbortSignal.timeout(9000);
  try {
    const res = await fetch(s.url, { signal: ctl, headers: { 'user-agent': 'ThreatNexusBD/1.0 (+https://threatnexus.bd)' } });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const xml = await res.text();
    const blocks = xml.split(/<item[\s>]|<entry[\s>]/i).slice(1);
    const items = blocks.slice(0, 25).map(b => {
      const title = tagVal(b, 'title');
      let url = tagVal(b, 'link');
      if (!url) { const m = b.match(/<link[^>]*href="([^"]+)"/i); url = m ? m[1] : ''; }
      const summary = tagVal(b, 'description') || tagVal(b, 'summary') || tagVal(b, 'content:encoded');
      const date = tagVal(b, 'pubDate') || tagVal(b, 'published') || tagVal(b, 'updated');
      const blob = title + ' ' + summary;
      const score = bdScore(blob);
      return {
        id: createHash('sha1').update(url || title).digest('hex').slice(0, 16),
        title, url, summary: summary.slice(0, 400),
        published_at: date ? new Date(date).toISOString() : new Date().toISOString(),
        source_id: s.id, source_name: s.name, source_cat: s.cat,
        severity: severityOf(blob),
        bd: score.bd, bd_reason: score.reason, actors: score.actors,
        tags: [...new Set((blob.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(c => c.toUpperCase()))].slice(0, 4)
      };
    }).filter(i => i.title && i.url);
    return { ok: true, items, meta: { id: s.id, name: s.name, ok: true, count: items.length, cat: s.cat } };
  } catch (e) {
    return { ok: false, items: [], meta: { id: s.id, name: s.name, ok: false, count: 0, cat: s.cat, error: String(e.message || e) } };
  }
}

async function getFeed() {
  if (Date.now() - cache.at < TTL && cache.items.length) return cache;
  const results = await Promise.all(SOURCES.map(fetchSource));
  cache.items = results.flatMap(r => r.items)
    .sort((a, b) => String(b.published_at).localeCompare(String(a.published_at)));
  cache.sources = results.map(r => r.meta);
  cache.at = Date.now();
  return cache;
}

/* ------------------------------------------------------------- enrichment */
const RE = {
  ipv4: /^(\d{1,3}\.){3}\d{1,3}$/,
  domain: /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i,
  sha256: /^[a-f0-9]{64}$/i, md5: /^[a-f0-9]{32}$/i,
  asn: /^as\d+$/i, url: /^https?:\/\//i
};

function classify(v) {
  const s = v.trim().replace(/\[\.\]/g, '.').replace(/^hxxp/i, 'http');
  if (RE.url.test(s)) return { type: 'url', value: s };
  if (RE.ipv4.test(s)) return { type: 'ipv4', value: s };
  if (RE.asn.test(s)) return { type: 'asn', value: s.toUpperCase() };
  if (RE.sha256.test(s)) return { type: 'sha256', value: s.toLowerCase() };
  if (RE.md5.test(s)) return { type: 'md5', value: s.toLowerCase() };
  if (RE.domain.test(s)) return { type: 'domain', value: s.toLowerCase() };
  return { type: 'unknown', value: s };
}

async function j(url, opts = {}, ms = 9000) {
  const res = await fetch(url, { signal: AbortSignal.timeout(ms), headers: { accept: 'application/json', 'user-agent': 'ThreatNexusBD/1.0' }, ...opts });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

function corpusSighting(value) {
  const v = value.toLowerCase();
  const hits = [];
  for (const g of GROUPS) {
    for (const [type, val, note] of (g.iocs || [])) {
      const clean = String(val).toLowerCase().replace(/\[\.\]/g, '.');
      if (clean === v || (v.length > 6 && clean.includes(v))) hits.push({ actor: g.name, type, note });
    }
    for (const inf of (g.infra || [])) {
      if (v.length > 6 && inf.toLowerCase().includes(v)) hits.push({ actor: g.name, type: 'infrastructure-pattern', note: inf });
    }
  }
  return hits;
}

async function enrich(raw) {
  const { type, value } = classify(raw);
  const out = { indicator: value, type, generated_at: new Date().toISOString(), sources: [], signals: [] };
  const now = () => new Date().toISOString().replace('T', ' ').slice(0, 16) + 'Z';
  const push = (name, ok, data, error) => out.sources.push({ name, ok, data, error, observed: now() });

  // 0 — corpus
  const sight = corpusSighting(value);
  push('ThreatNexus BD corpus', true,
    sight.length ? { sightings: sight.map(s => `${s.actor} — ${s.type}: ${s.note}`) } : { sightings: 'no prior sighting in the BD corpus' });
  if (sight.length) out.signals.push({ weight: 'high', text: `Matches a published indicator for ${sight[0].actor}`, source: 'ThreatNexus BD corpus' });

  const tasks = [];

  if (type === 'domain' || type === 'url') {
    const host = type === 'url' ? new URL(value).hostname : value;

    // RDAP only answers for a registrable domain — walk up the labels
    const rdapCandidates = (() => {
      const parts = host.split('.');
      const out = [];
      for (let i = 0; i <= parts.length - 2; i++) out.push(parts.slice(i).join('.'));
      return out.slice(0, 3);
    })();

    tasks.push((async () => {
      let r = null, used = host, err = '';
      for (const cand of rdapCandidates) {
        try { r = await j(`https://rdap.org/domain/${encodeURIComponent(cand)}`); used = cand; break; }
        catch (e) { err = String(e.message); }
      }
      if (!r) { push('RDAP (registration)', false, null, `no RDAP record for ${host} (${err})`); return; }
      try {
        const events = Object.fromEntries((r.events || []).map(e => [e.eventAction, (e.eventDate || '').slice(0, 10)]));
        const reg = (r.entities || []).find(e => (e.roles || []).includes('registrar'));
        const created = events.registration;
        if (created) {
          const ageDays = Math.floor((Date.now() - new Date(created).getTime()) / 86400000);
          if (ageDays < 90) out.signals.push({ weight: 'medium', text: `Domain registered ${ageDays} days ago — young infrastructure`, source: 'RDAP' });
        }
        push('RDAP (registration)', true, {
          queried: used + (used === host ? '' : `  (registrable parent of ${host})`),
          registrar: reg?.vcardArray?.[1]?.find(x => x[0] === 'fn')?.[3] || 'n/a',
          registered: created || 'n/a', expires: events.expiration || 'n/a',
          status: (r.status || []).join(', ') || 'n/a', nameservers: (r.nameservers || []).map(n => n.ldhName)
        });
      } catch (e) { push('RDAP (registration)', false, null, String(e.message)); }
    })());

    tasks.push((async () => {
      try {
        const r = await j(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { accept: 'application/dns-json' } });
        push('Cloudflare DoH (A records)', true, { answers: (r.Answer || []).map(a => `${a.name} → ${a.data} (ttl ${a.TTL})`) || 'none' });
      } catch (e) { push('Cloudflare DoH (A records)', false, null, String(e.message)); }
    })());

    tasks.push((async () => {
      try {
        const r = await j(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json&limit=20`, {}, 16000);
        const arr = Array.isArray(r) ? r.slice(0, 15) : [];
        push('crt.sh (certificate transparency)', true, {
          certificates_seen: arr.length,
          issuers: [...new Set(arr.map(c => c.issuer_name?.split('O=')[1]?.split(',')[0] || 'n/a'))].slice(0, 5),
          names: [...new Set(arr.flatMap(c => String(c.name_value || '').split('\n')))].slice(0, 12),
          first_seen: arr.length ? arr[arr.length - 1].not_before?.slice(0, 10) : 'n/a'
        });
      } catch (e) { push('crt.sh (certificate transparency)', false, null, 'crt.sh did not respond in time — retry, it is frequently rate-limited'); }
    })());

    // free-hosting heuristic — the SideWinder pattern seen against BD gov portals
    if (/\.(netlify\.app|pages\.dev|workers\.dev|b4a\.run|vercel\.app|glitch\.me)$/i.test(host)) {
      out.signals.push({ weight: 'medium', text: 'Hosted on a free app platform — matches SideWinder credential-portal tradecraft against gov.bd targets', source: 'ThreatNexus BD heuristic' });
    }
    if (/gov[-.]?bd|dgdp|baf|dgfi|bank/i.test(host) && !/\.gov\.bd$/i.test(host)) {
      out.signals.push({ weight: 'high', text: 'Contains Bangladeshi government/defence keywords but is not on .gov.bd — likely lookalike', source: 'ThreatNexus BD heuristic' });
    }
  }

  if (type === 'ipv4') {
    tasks.push((async () => {
      try {
        const r = await j(`https://internetdb.shodan.io/${value}`);
        push('Shodan InternetDB', true, {
          open_ports: r.ports || [], hostnames: r.hostnames || [], tags: r.tags || [], vulns: r.vulns || [], cpes: (r.cpes || []).slice(0, 8)
        });
        if ((r.vulns || []).length) out.signals.push({ weight: 'medium', text: `${r.vulns.length} known CVEs exposed on this host`, source: 'Shodan InternetDB' });
      } catch (e) { push('Shodan InternetDB', false, null, 'no record / ' + String(e.message)); }
    })());

    tasks.push((async () => {
      try {
        const r = await j(`https://ipwho.is/${value}`);
        push('ipwho.is (geo/ASN)', true, {
          country: `${r.country || '?'} (${r.country_code || '?'})`, city: r.city || 'n/a',
          asn: r.connection?.asn ? 'AS' + r.connection.asn : 'n/a', org: r.connection?.org || r.connection?.isp || 'n/a',
          type: r.type || 'n/a'
        });
        if (r.country_code === 'BD') out.signals.push({ weight: 'low', text: 'Address geolocates inside Bangladesh', source: 'ipwho.is' });
      } catch (e) { push('ipwho.is (geo/ASN)', false, null, String(e.message)); }
    })());

    tasks.push((async () => {
      try {
        const r = await j(`https://stat.ripe.net/data/network-info/data.json?resource=${value}`);
        push('RIPEstat (network info)', true, { prefix: r.data?.prefix || 'n/a', asns: r.data?.asns || [] });
      } catch (e) { push('RIPEstat (network info)', false, null, String(e.message)); }
    })());
  }

  if (type === 'asn') {
    tasks.push((async () => {
      try {
        const r = await j(`https://stat.ripe.net/data/as-overview/data.json?resource=${value}`);
        push('RIPEstat (AS overview)', true, { holder: r.data?.holder || 'n/a', announced: String(r.data?.announced), block: r.data?.block?.desc || 'n/a' });
      } catch (e) { push('RIPEstat (AS overview)', false, null, String(e.message)); }
    })());
  }

  if (type === 'sha256' || type === 'md5') {
    push('Hash pivots (no-key)', true, {
      note: 'No keyless public hash reputation source is bundled. Pivot manually:',
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
  return out;
}

/* ------------------------------------------------------------ STIX / TAXII */
const NS = 'threatnexus-bd';
const uuid5 = s => {
  const h = createHash('sha1').update(NS + s).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

function stixBundle() {
  const objects = [];
  const now = new Date().toISOString();
  const idOf = (t, k) => `${t}--${uuid5(t + ':' + k)}`;

  objects.push({
    type: 'identity', spec_version: '2.1', id: idOf('identity', 'threatnexus-bd'),
    created: now, modified: now, name: 'ThreatNexus BD', identity_class: 'organization',
    description: 'Bangladesh-focused threat intelligence compilation. TLP:CLEAR, CC BY 4.0.'
  });
  objects.push({
    type: 'location', spec_version: '2.1', id: idOf('location', 'BD'),
    created: now, modified: now, name: 'Bangladesh', country: 'BD', region: 'southern-asia'
  });

  for (const g of GROUPS) {
    const isId = idOf('intrusion-set', g.id);
    objects.push({
      type: 'intrusion-set', spec_version: '2.1', id: isId, created: now, modified: now,
      name: g.name,
      aliases: String(g.aka || '').split('·').map(s => s.trim()).filter(Boolean),
      description: g.description,
      primary_motivation: g.motivation === 'financial' ? 'personal-gain' : g.motivation === 'hacktivism' ? 'ideology' : 'organizational-gain',
      first_seen: `${g.active_since}-01-01T00:00:00.000Z`,
      last_seen: `${g.last_seen}-12-31T23:59:59.000Z`,
      confidence: g.confidence === 'high' ? 85 : g.confidence === 'moderate' ? 60 : 40,
      labels: [`bd-status:${g.bd_status}`, `bd-relevance:${g.bd_relevance}`, `origin:${g.country}`],
      external_references: (g.sources || []).map(s => ({ source_name: s.name, url: s.url }))
        .concat(g.mitre_group ? [{ source_name: 'mitre-attack', external_id: g.mitre_group, url: `https://attack.mitre.org/groups/${g.mitre_group}/` }] : [])
    });

    objects.push({
      type: 'relationship', spec_version: '2.1', id: idOf('relationship', g.id + '-targets-bd'),
      created: now, modified: now, relationship_type: 'targets',
      source_ref: isId, target_ref: idOf('location', 'BD'),
      description: `Bangladesh exposure ${g.bd_relevance}/100 — ${g.bd_status}`
    });

    for (const [name, note] of (g.malware || [])) {
      const mid = idOf('malware', name);
      if (!objects.some(o => o.id === mid)) {
        objects.push({ type: 'malware', spec_version: '2.1', id: mid, created: now, modified: now, name, description: note, is_family: true });
      }
      objects.push({
        type: 'relationship', spec_version: '2.1', id: idOf('relationship', g.id + '-uses-' + name),
        created: now, modified: now, relationship_type: 'uses', source_ref: isId, target_ref: mid
      });
    }

    for (const [tid, tname] of (g.ttps || [])) {
      const aid = idOf('attack-pattern', tid);
      if (!objects.some(o => o.id === aid)) {
        objects.push({
          type: 'attack-pattern', spec_version: '2.1', id: aid, created: now, modified: now, name: tname,
          external_references: [{ source_name: 'mitre-attack', external_id: tid, url: `https://attack.mitre.org/techniques/${tid.replace('.', '/')}/` }]
        });
      }
      objects.push({
        type: 'relationship', spec_version: '2.1', id: idOf('relationship', g.id + '-uses-' + tid),
        created: now, modified: now, relationship_type: 'uses', source_ref: isId, target_ref: aid
      });
    }

    for (const cve of (g.cves || [])) {
      const vid = idOf('vulnerability', cve);
      if (!objects.some(o => o.id === vid)) {
        objects.push({
          type: 'vulnerability', spec_version: '2.1', id: vid, created: now, modified: now, name: cve,
          external_references: [{ source_name: 'cve', external_id: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}` }]
        });
      }
      objects.push({
        type: 'relationship', spec_version: '2.1', id: idOf('relationship', g.id + '-exploits-' + cve),
        created: now, modified: now, relationship_type: 'exploits', source_ref: isId, target_ref: vid
      });
    }

    for (const [t, val, note] of (g.iocs || [])) {
      const pattern = t === 'domain' ? `[domain-name:value = '${String(val).replace(/\[\.\]/g, '.')}']`
        : t === 'ipv4' ? `[ipv4-addr:value = '${val}']`
        : t === 'email' ? `[email-addr:value = '${String(val).replace(/\[\.\]/g, '.')}']`
        : null;
      if (!pattern) continue;
      const iid = idOf('indicator', val);
      objects.push({
        type: 'indicator', spec_version: '2.1', id: iid, created: now, modified: now,
        name: `${g.name} — ${t}`, description: note, pattern, pattern_type: 'stix',
        valid_from: now, labels: ['malicious-activity']
      });
      objects.push({
        type: 'relationship', spec_version: '2.1', id: idOf('relationship', g.id + '-indicates-' + val),
        created: now, modified: now, relationship_type: 'indicates', source_ref: iid, target_ref: isId
      });
    }
  }
  return { type: 'bundle', id: 'bundle--' + uuid5('bd-bundle-' + objects.length), objects };
}

/* ------------------------------------------------------------------ server */
const json = (res, obj, code = 200, extra = {}) => {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'public, max-age=60',
    'access-control-allow-origin': '*',
    ...extra
  });
  res.end(body);
};

async function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  if (ROUTES.includes(pathname)) rel = '/index.html';
  const file = path.join(ROOT, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
  if (!file.startsWith(ROOT)) { res.writeHead(403).end('forbidden'); return; }
  try {
    const data = await fs.readFile(file);
    const ext = path.extname(file).toLowerCase();
    const immutable = /^\/(vendor|assets)\//.test(rel);
    res.writeHead(200, {
      'content-type': MIME[ext] || 'application/octet-stream',
      'cache-control': immutable ? 'public, max-age=31536000, immutable' : 'no-cache',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin'
    });
    res.end(data);
  } catch {
    const idx = await fs.readFile(path.join(ROOT, 'index.html')).catch(() => null);
    if (idx) { res.writeHead(200, { 'content-type': MIME['.html'] }); res.end(idx); }
    else { res.writeHead(404).end('not found'); }
  }
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname.replace(/\/+$/, '') || '/';

  try {
    if (p === '/api/health') {
      const f = cache.items.length ? cache : { items: [], sources: [] };
      return json(res, {
        ok: true, service: 'threatnexus-bd', timestamp: new Date().toISOString(),
        corpus: { actors: GROUPS.length, advisories: BD_ADVISORIES.length,
                  confirmed_vs_bd: GROUPS.filter(g => g.bd_status === 'confirmed').length },
        feed: { cached_items: f.items.length, sources: SOURCES.length, age_s: cache.at ? Math.round((Date.now() - cache.at) / 1000) : null },
        capabilities: { feed: true, enrich: true, taxii: true, ai: false }
      });
    }

    if (p === '/api/feed/items') {
      const { items } = await getFeed();
      const limit = Math.min(Number(u.searchParams.get('limit')) || 80, 300);
      const only = u.searchParams.get('bd') === '1';
      return json(res, { items: (only ? items.filter(i => i.bd) : items).slice(0, limit), total: items.length, generated_at: new Date().toISOString() });
    }

    if (p === '/api/feed/sources') {
      const { sources } = await getFeed();
      return json(res, { sources, generated_at: new Date().toISOString() });
    }

    if (p === '/api/enrich') {
      const ioc = u.searchParams.get('ioc');
      if (!ioc) return json(res, { error: 'ioc parameter required' }, 400);
      return json(res, await enrich(ioc), 200, { 'cache-control': 'no-store' });
    }

    if (p === '/api/actors') {
      return json(res, { actors: GROUPS.map(({ description, ...rest }) => rest), count: GROUPS.length });
    }

    if (p === '/api/taxii2' || p === '/taxii2') {
      return json(res, {
        title: 'ThreatNexus BD TAXII Server',
        description: 'Read-only TAXII 2.1 feed of Bangladesh-relevant threat intelligence — intrusion sets, malware, ATT&CK techniques, exploited CVEs, indicators and their relationships. Public, no authentication. Curated corpus: poll every 6 hours.',
        default: '/api/taxii2/root/', api_roots: ['/api/taxii2/root/'],
        x_license: 'CC-BY-4.0', x_tlp: 'TLP:CLEAR',
        x_attribution: 'ThreatNexus BD — compiled from BGD e-GOV CIRT, government and vendor reporting'
      }, 200, { 'content-type': 'application/taxii+json;version=2.1' });
    }

    if (p === '/api/taxii2/root') {
      return json(res, { title: 'ThreatNexus BD API root', versions: ['application/taxii+json;version=2.1'], max_content_length: 10485760 },
        200, { 'content-type': 'application/taxii+json;version=2.1' });
    }

    if (p === '/api/taxii2/root/collections') {
      return json(res, {
        collections: [{
          id: 'bd', title: 'Bangladesh nation-state, hacktivist and criminal threat corpus',
          description: 'Actors with confirmed or assessed relevance to Bangladesh, mapped to MITRE ATT&CK.',
          can_read: true, can_write: false, media_types: ['application/stix+json;version=2.1']
        }]
      }, 200, { 'content-type': 'application/taxii+json;version=2.1' });
    }

    if (p === '/api/taxii2/root/collections/bd/objects' || p === '/api/stix') {
      const bundle = stixBundle();
      const etag = '"' + createHash('sha1').update(JSON.stringify(bundle.objects.length + bundle.id)).digest('hex').slice(0, 16) + '"';
      if (req.headers['if-none-match'] === etag) { res.writeHead(304).end(); return; }
      return json(res, bundle, 200, { 'content-type': 'application/stix+json;version=2.1', etag });
    }

    if (p.startsWith('/api/')) return json(res, { error: 'Not found', hint: 'Try /api/health, /api/feed/items, /api/enrich?ioc=, /api/taxii2/' }, 404);

    await serveStatic(req, res, u.pathname);
  } catch (err) {
    json(res, { error: String(err.message || err) }, 500);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`ThreatNexus BD listening on 0.0.0.0:${PORT}`);
  console.log(`  corpus: ${GROUPS.length} actors · ${BD_ADVISORIES.length} curated advisories`);
  getFeed().then(c => console.log(`  feed warm: ${c.items.length} items from ${c.sources.filter(s => s.ok).length}/${SOURCES.length} sources`));
});

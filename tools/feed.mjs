/* ============================================================================
   Feed aggregation — RSS/Atom collection with Bangladesh relevance scoring.
   Used by server.mjs at request time and by tools/build.mjs to bake a snapshot
   for static hosting (refreshed by a scheduled GitHub Action).
   ========================================================================== */
import { createHash } from 'node:crypto';
import { GROUPS } from '../data/actors.js';

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

export const SOURCES = [
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

export const cache = { items: [], sources: [], at: 0 };
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

export async function getFeed() {
  if (Date.now() - cache.at < TTL && cache.items.length) return cache;
  const results = await Promise.all(SOURCES.map(fetchSource));
  cache.items = results.flatMap(r => r.items)
    .sort((a, b) => String(b.published_at).localeCompare(String(a.published_at)));
  cache.sources = results.map(r => r.meta);
  cache.at = Date.now();
  return cache;
}


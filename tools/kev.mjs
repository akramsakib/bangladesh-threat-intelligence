/* ============================================================================
   Active Exploitation Watch — CISA Known Exploited Vulnerabilities, cross-
   referenced against the actor corpus and the curated BD advisory record.

   Source: CISA KEV catalog (public, no key, updated as CISA confirms active
   exploitation — not a scanner, not a prediction, just "this is confirmed
   being exploited in the wild right now").

   Two outputs:
     matched — KEV entries whose CVE appears in a tracked actor's cves[].
               This is the honest version of "is Bangladesh at risk from this":
               a named actor that has targeted Bangladesh is known to use it.
     recent  — the newest KEV additions generally (not actor-matched), each
               checked against the curated advisory record for a vendor/product
               mention so any "relevant here" note traces to a cited advisory,
               never a guess.
   ========================================================================== */
import { GROUPS } from '../data/actors.js';
import { BD_ADVISORIES } from '../data/advisories.js';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const TTL = 6 * 60 * 60 * 1000; // 6h — KEV is updated a few times a week, not per minute
const RECENT_DAYS = 45;
const RECENT_CAP = 20;

export const cache = { data: null, at: 0, error: null };

function cveActorMap() {
  const map = new Map();
  for (const g of GROUPS) {
    for (const cve of (g.cves || [])) {
      const key = cve.toUpperCase();
      if (!map.has(key)) map.set(key, []);
      map.get(key).push({ id: g.id, name: g.name, country: g.country, bd_status: g.bd_status, bd_relevance: g.bd_relevance });
    }
  }
  return map;
}

// Advisory-grounded vendor/product match. A naive "does this word appear in
// any advisory" check is unsafe here — generic words like "Secure", "Media"
// or "Support" collide with unrelated advisories and would print a false
// relevance claim. Instead this is a small, hand-verified map of distinctive
// technology names that are actually named in a specific curated advisory's
// text, each pointing at that one advisory. Nothing here is inferred — every
// row below was read directly out of data/advisories.js.
const CURATED_TECH_HINTS = [
  { term: 'MikroTik', advisoryTitle: 'Cyber security alert during the Eid holiday period' },
  { term: 'Microsoft IIS', advisoryTitle: '452 Bangladeshi IPs exposed running end-of-life Microsoft IIS' },
  { term: 'IIS', advisoryTitle: '452 Bangladeshi IPs exposed running end-of-life Microsoft IIS' },
  { term: 'Magento', advisoryTitle: 'Web defacement artefacts on Bangladesh government infrastructure linked to global Magento exploitation' },
  { term: 'Adobe Commerce', advisoryTitle: 'Web defacement artefacts on Bangladesh government infrastructure linked to global Magento exploitation' },
  { term: 'GeoServer', advisoryTitle: 'SideWinder-associated campaign targeting South Asian government and financial infrastructure' },
  { term: 'GeoTools', advisoryTitle: 'SideWinder-associated campaign targeting South Asian government and financial infrastructure' },
  { term: 'Laravel', advisoryTitle: 'SideWinder-associated campaign targeting South Asian government and financial infrastructure' },
  { term: 'Tomcat', advisoryTitle: 'SideWinder-associated campaign targeting South Asian government and financial infrastructure' },
  { term: 'Redis', advisoryTitle: 'SideWinder-associated campaign targeting South Asian government and financial infrastructure' },
  { term: 'ESXi', advisoryTitle: 'INC ransomware expands cross-platform capabilities across Asia-Pacific' },
  { term: 'Axios', advisoryTitle: 'Axios npm package compromise deploying RAT in Node.js environments' }
];

function advisoryHint(vendorProject, product) {
  const blob = `${vendorProject || ''} ${product || ''}`.toLowerCase();
  for (const { term, advisoryTitle } of CURATED_TECH_HINTS) {
    if (!blob.includes(term.toLowerCase())) continue;
    const a = BD_ADVISORIES.find(x => x.title === advisoryTitle);
    if (a) return { term, title: a.title, url: a.url, date: a.date, source: a.source };
  }
  return null;
}

async function fetchKev() {
  const ctl = AbortSignal.timeout(12000);
  const res = await fetch(KEV_URL, {
    signal: ctl,
    headers: { 'user-agent': 'ThreatNexusBD/1.0 (+https://threatnexus.bd)', accept: 'application/json' }
  });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const body = await res.json();
  return Array.isArray(body?.vulnerabilities) ? body.vulnerabilities : [];
}

export async function getKev() {
  if (Date.now() - cache.at < TTL && cache.data) return cache.data;

  let vulns;
  try {
    vulns = await fetchKev();
  } catch (e) {
    cache.error = String(e.message || e);
    if (cache.data) return cache.data; // serve stale rather than nothing
    return { ok: false, error: cache.error, total_kev: 0, matched: [], recent: [], generated_at: new Date().toISOString() };
  }

  const byCve = cveActorMap();
  const matched = [];
  const seenCorpusCves = new Set();
  for (const v of vulns) {
    const actors = byCve.get(String(v.cveID).toUpperCase());
    if (!actors) continue;
    seenCorpusCves.add(String(v.cveID).toUpperCase());
    matched.push({
      cve: v.cveID,
      vendorProject: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
      actors
    });
  }
  matched.sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)));

  // Corpus CVEs that CISA has not (yet) confirmed as actively exploited.
  // Real, cited vulnerabilities — just not in KEV. Shown, not hidden, so
  // "not matched" never silently reads as "not a risk".
  const unconfirmed = [];
  for (const [cve, actors] of byCve.entries()) {
    if (seenCorpusCves.has(cve)) continue;
    unconfirmed.push({ cve, actors });
  }
  unconfirmed.sort((a, b) => a.cve.localeCompare(b.cve));

  const cutoff = new Date(Date.now() - RECENT_DAYS * 86400000).toISOString().slice(0, 10);
  const recent = vulns
    .filter(v => v.dateAdded >= cutoff)
    .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)))
    .slice(0, RECENT_CAP)
    .map(v => ({
      cve: v.cveID,
      vendorProject: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
      advisory: advisoryHint(v.vendorProject, v.product)
    }));

  const data = {
    ok: true,
    total_kev: vulns.length,
    matched_count: matched.length,
    matched,
    unconfirmed,
    recent,
    generated_at: new Date().toISOString()
  };
  cache.data = data;
  cache.at = Date.now();
  cache.error = null;
  return data;
}

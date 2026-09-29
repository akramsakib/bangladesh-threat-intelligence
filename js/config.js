/* ThreatNexus BD — shared configuration, palettes, geography, derived edges */

export const HOME = { name: 'Bangladesh', lat: 23.6850, lng: 90.3563, city: 'Dhaka' };

export const NATION_COLORS = {
  'North Korea': '#d44545',
  'India':       '#f48a4a',
  'Pakistan':    '#4ab4e6',
  'China':       '#ee864a',
  'Bangladesh':  '#1db584',
  'Russia':      '#e05a5a',
  'Unknown':     '#7c8aa0'
};

export const MOTIVATION = {
  espionage:  { hex: '#4a9eff', label: 'Espionage' },
  financial:  { hex: '#3ecf8e', label: 'Financial' },
  hacktivism: { hex: '#f5a623', label: 'Hacktivism' },
  mixed:      { hex: '#a87dff', label: 'Mixed' }
};

export const STATUS = {
  confirmed: { label: 'Confirmed vs BD', hex: '#f0544f', desc: 'Public reporting places this actor on Bangladeshi targets' },
  assessed:  { label: 'Assessed exposure', hex: '#f5a623', desc: 'Profile matches BD attack surface; no public BD victim confirmed' },
  regional:  { label: 'Regional spillover', hex: '#4a9eff', desc: 'Active in the neighbourhood; BD inside collection aperture' },
  outbound:  { label: 'BD-origin / outbound', hex: '#a87dff', desc: 'Operates from Bangladesh against external targets' }
};

export const TACTIC = {
  'reconnaissance':       { label: 'Reconnaissance',    col: '#94a3b8' },
  'resource-development': { label: 'Resource Dev',      col: '#78716c' },
  'initial-access':       { label: 'Initial Access',    col: '#3b82f6' },
  'execution':            { label: 'Execution',         col: '#f97316' },
  'persistence':          { label: 'Persistence',       col: '#eab308' },
  'privilege-escalation': { label: 'Priv. Escalation',  col: '#ef4444' },
  'defense-evasion':      { label: 'Defense Evasion',   col: '#a855f7' },
  'credential-access':    { label: 'Credential Access', col: '#ec4899' },
  'discovery':            { label: 'Discovery',         col: '#06b6d4' },
  'lateral-movement':     { label: 'Lateral Movement',  col: '#10b981' },
  'collection':           { label: 'Collection',        col: '#14b8a6' },
  'exfiltration':         { label: 'Exfiltration',      col: '#f43f5e' },
  'command-and-control':  { label: 'C2',                col: '#6366f1' },
  'impact':               { label: 'Impact',            col: '#dc2626' }
};

export const COUNTRY_COORDS = {
  'North Korea': { lat: 40.3,  lng: 127.5 },
  'India':       { lat: 22.6,  lng:  78.9 },
  'Pakistan':    { lat: 30.4,  lng:  69.3 },
  'China':       { lat: 35.8,  lng: 104.2 },
  'Bangladesh':  { lat: 23.68, lng:  90.35 },
  'Russia':      { lat: 61.5,  lng: 105.3 },
  'Unknown':     { lat:  2.0,  lng:  78.0 }   // rendered as "UNATTRIBUTED" over the Indian Ocean
};

/* Bangladeshi target nodes used for the globe arcs (where the attacks land). */
export const BD_NODES = [
  { key: 'dhaka-gov',   label: 'Dhaka — Government',      lat: 23.777, lng: 90.399 },
  { key: 'dhaka-bank',  label: 'Motijheel — Banking',     lat: 23.727, lng: 90.418 },
  { key: 'dhaka-mil',   label: 'Dhaka Cantonment — Defence', lat: 23.826, lng: 90.395 },
  { key: 'ctg-port',    label: 'Chattogram — Port & Energy', lat: 22.335, lng: 91.834 },
  { key: 'moheshkhali', label: 'Moheshkhali — LNG / OT',  lat: 21.550, lng: 91.930 },
  { key: 'sylhet',      label: 'Sylhet — Telecom / Gas',  lat: 24.895, lng: 91.868 }
];

export const FRESHNESS = [
  { label: '2026 — Live',        min: 2026, hex: '#3ecf8e' },
  { label: '2025 — Recent',      min: 2025, hex: '#f5a623' },
  { label: '2024 — Ageing',      min: 2024, hex: '#f0544f' },
  { label: '< 2024 — Historical', min: 0,   hex: '#6b7280' }
];

export function freshness(year) {
  for (const f of FRESHNESS) if (year >= f.min) return f;
  return FRESHNESS[FRESHNESS.length - 1];
}

export function nationColor(c) { return NATION_COLORS[c] || NATION_COLORS.Unknown; }

/* ---------------------------------------------------------------------------
   Derived relationship edges — computed at runtime so the graph can never
   drift from the dossiers. Shared malware / shared CVE / shared TTP.
--------------------------------------------------------------------------- */
const norm = s => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '');

export function computeEdges(groups) {
  const edges = [];
  for (let i = 0; i < groups.length; i++) {
    for (let j = i + 1; j < groups.length; j++) {
      const a = groups[i], b = groups[j];

      const am = new Set((a.malware || []).map(m => norm(m[0])));
      const bm = new Set((b.malware || []).map(m => norm(m[0])));
      const sharedMal = [...am].filter(x => bm.has(x));

      const ac = new Set(a.cves || []), bc = new Set(b.cves || []);
      const sharedCve = [...ac].filter(x => bc.has(x));

      const at = new Set((a.ttps || []).map(t => t[0]));
      const bt = new Set((b.ttps || []).map(t => t[0]));
      const sharedTtp = [...at].filter(x => bt.has(x));

      if (sharedMal.length) edges.push({ s: a.id, t: b.id, type: 'malware', n: sharedMal.length, items: sharedMal });
      if (sharedCve.length) edges.push({ s: a.id, t: b.id, type: 'cve', n: sharedCve.length, items: sharedCve });
      if (sharedTtp.length >= 3) edges.push({ s: a.id, t: b.id, type: 'ttp', n: sharedTtp.length, items: sharedTtp });
      if (a.country !== 'Unknown' && a.country === b.country) {
        edges.push({ s: a.id, t: b.id, type: 'origin', n: 1, items: [a.country] });
      }
    }
  }
  return edges;
}

export const EDGE_COLORS = {
  malware: '#a87dff',
  cve:     '#f0544f',
  ttp:     '#4a9eff',
  origin:  '#e8b84b'
};

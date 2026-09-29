/* ============================================================================
   STIX 2.1 bundle generation from the Bangladesh corpus.
   Deterministic UUIDv5-style ids, so the bundle is stable across restarts and
   safe for consumers to poll and diff.
   ========================================================================== */
import { createHash } from 'node:crypto';
import { GROUPS } from '../data/actors.js';

const NS = 'threatnexus-bd';
const uuid5 = s => {
  const h = createHash('sha1').update(NS + s).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

export function stixBundle() {
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


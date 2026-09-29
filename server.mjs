/* ============================================================================
   ThreatNexus BD — edge service (zero dependencies)
   · static asset serving with SPA fallback
   · /api/feed/*   RSS aggregation + Bangladesh relevance scoring (15m cache)
   · /api/enrich   keyless IOC enrichment (RDAP, DoH, crt.sh, InternetDB,
                   RIPEstat, ipwho.is) + corpus sighting
   · /api/taxii2/* STIX 2.1 objects over a read-only TAXII 2.1 surface

   The feed, STIX and enrichment engines live in shared modules so the static
   GitHub Pages build produces byte-identical intelligence.
   ========================================================================== */
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { GROUPS } from './data/actors.js';
import { BD_ADVISORIES } from './data/advisories.js';
import { SOURCES, getFeed, cache } from './tools/feed.mjs';
import { stixBundle } from './tools/stix.mjs';
import { enrich } from './js/lib/enrich.js';

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const PORT = process.env.PORT || 3000;
const ROUTES = ['/', '/globe', '/cluster', '/diamond', '/threat-landscape', '/brief', '/feed', '/hunt', '/prism', '/enrich'];

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8'
};

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

/* ============================================================================
   Static build for GitHub Pages.

   Produces dist/ — the same application, with the API surface baked into JSON
   artifacts instead of served by Node:

     api/stix.json          481-object STIX 2.1 bundle
     api/actors.json        actor index
     api/feed.json          aggregated feed snapshot   (refreshed by cron Action)
     api/feed-sources.json  per-source health snapshot
     api/health.json        build metadata

   The browser bundle detects the absence of a live backend and switches to
   these artifacts plus in-browser IOC enrichment, so the deployed site keeps
   every feature except on-demand RSS re-aggregation.

   Usage:  node tools/build.mjs
   Env:    BASE_PATH   path prefix, e.g. /bangladesh-threat-intelligence  (default '')
           SITE_URL    absolute origin for sitemap/OG tags
           SKIP_FEED   '1' to skip network aggregation (fast local builds)
   ========================================================================== */
import fs from 'node:fs/promises';
import path from 'node:path';
import { GROUPS, INCIDENTS, SECTORS } from '../data/actors.js';
import { BD_ADVISORIES } from '../data/advisories.js';
import { stixBundle } from './stix.mjs';
import { getFeed, SOURCES } from './feed.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const DIST = path.join(ROOT, 'dist');

let BASE = (process.env.BASE_PATH || '').replace(/\/+$/, '');
if (BASE && !BASE.startsWith('/')) BASE = '/' + BASE;
const SITE = (process.env.SITE_URL || '').replace(/\/+$/, '');
const HREF = (BASE || '') + '/';

const COPY = ['css', 'js', 'data', 'vendor', 'assets'];
const FILES = ['robots.txt', 'README.md', 'LICENSE'];

const log = (...a) => console.log('  ', ...a);

async function main() {
  console.log('\nThreatNexus BD — static build');
  console.log(`   base path : ${BASE || '(domain root)'}`);
  console.log(`   site url  : ${SITE || '(relative)'}\n`);

  await fs.rm(DIST, { recursive: true, force: true });
  await fs.mkdir(path.join(DIST, 'api'), { recursive: true });

  /* ---------------------------------------------------------- static files */
  for (const dir of COPY) {
    await fs.cp(path.join(ROOT, dir), path.join(DIST, dir), { recursive: true });
    log(`copied  ${dir}/`);
  }
  for (const f of FILES) {
    await fs.copyFile(path.join(ROOT, f), path.join(DIST, f)).catch(() => {});
  }
  await fs.writeFile(path.join(DIST, '.nojekyll'), '');   // keep _-prefixed paths, skip Jekyll

  /* ------------------------------------------------------------- index.html */
  let html = await fs.readFile(path.join(ROOT, 'index.html'), 'utf8');

  html = html.replace('<head>', `<head>\n<base href="${HREF}">`);

  if (SITE) {
    html = html.replace('<meta property="og:type" content="website">',
      `<meta property="og:type" content="website">\n<link rel="canonical" href="${SITE}${HREF}">\n<meta property="og:url" content="${SITE}${HREF}">`);
  }

  // build stamp, visible in the DOM for support questions
  html = html.replace('</head>',
    `<meta name="generator" content="threatnexus-bd static build ${new Date().toISOString()}">\n</head>`);

  await fs.writeFile(path.join(DIST, 'index.html'), html);
  await fs.writeFile(path.join(DIST, '404.html'), html);   // SPA deep-link fallback
  log('wrote   index.html + 404.html');

  /* -------------------------------------------------------------- STIX 2.1 */
  const bundle = stixBundle();
  await fs.writeFile(path.join(DIST, 'api', 'stix.json'), JSON.stringify(bundle));
  const counts = {};
  bundle.objects.forEach(o => { counts[o.type] = (counts[o.type] || 0) + 1; });
  log(`wrote   api/stix.json — ${bundle.objects.length} objects`, JSON.stringify(counts));

  // TAXII-shaped aliases so existing consumers keep working on static hosting
  const taxiiDir = path.join(DIST, 'api', 'taxii2', 'root', 'collections', 'bd', 'objects');
  await fs.mkdir(taxiiDir, { recursive: true });
  await fs.writeFile(path.join(taxiiDir, 'index.json'), JSON.stringify(bundle));
  await fs.mkdir(path.join(DIST, 'api', 'taxii2'), { recursive: true });
  await fs.writeFile(path.join(DIST, 'api', 'taxii2', 'index.json'), JSON.stringify({
    title: 'ThreatNexus BD TAXII Server (static mirror)',
    description: 'Read-only STIX 2.1 objects for Bangladesh-relevant threat intelligence.',
    default: `${BASE}/api/taxii2/root/collections/bd/objects/`,
    x_license: 'CC-BY-4.0', x_tlp: 'TLP:CLEAR'
  }));

  /* ----------------------------------------------------------- actor index */
  await fs.writeFile(path.join(DIST, 'api', 'actors.json'), JSON.stringify({
    actors: GROUPS.map(({ description, ...rest }) => rest),
    count: GROUPS.length,
    generated_at: new Date().toISOString()
  }));
  log(`wrote   api/actors.json — ${GROUPS.length} actors`);

  /* ------------------------------------------------------------------ feed */
  let feedCount = 0, healthy = 0;
  if (process.env.SKIP_FEED === '1') {
    log('skipped api/feed.json (SKIP_FEED=1)');
    await fs.writeFile(path.join(DIST, 'api', 'feed.json'),
      JSON.stringify({ items: [], total: 0, generated_at: new Date().toISOString(), skipped: true }));
    await fs.writeFile(path.join(DIST, 'api', 'feed-sources.json'),
      JSON.stringify({ sources: [], generated_at: new Date().toISOString() }));
  } else {
    const feed = await getFeed();
    feedCount = feed.items.length;
    healthy = feed.sources.filter(s => s.ok).length;
    await fs.writeFile(path.join(DIST, 'api', 'feed.json'), JSON.stringify({
      items: feed.items.slice(0, 200), total: feed.items.length,
      generated_at: new Date().toISOString()
    }));
    await fs.writeFile(path.join(DIST, 'api', 'feed-sources.json'), JSON.stringify({
      sources: feed.sources, generated_at: new Date().toISOString()
    }));
    log(`wrote   api/feed.json — ${feedCount} items from ${healthy}/${SOURCES.length} sources`);
  }

  /* ---------------------------------------------------------------- health */
  await fs.writeFile(path.join(DIST, 'api', 'health.json'), JSON.stringify({
    ok: true, service: 'threatnexus-bd', mode: 'static',
    built_at: new Date().toISOString(),
    corpus: {
      actors: GROUPS.length, incidents: INCIDENTS.length, sectors: SECTORS.length,
      advisories: BD_ADVISORIES.length,
      confirmed_vs_bd: GROUPS.filter(g => g.bd_status === 'confirmed').length,
      stix_objects: bundle.objects.length
    },
    feed: { snapshot_items: feedCount, sources: SOURCES.length, healthy },
    capabilities: { feed: 'snapshot', enrich: 'client-side', taxii: 'static', ai: false }
  }, null, 2));

  /* --------------------------------------------------------------- sitemap */
  const routes = ['', 'globe', 'cluster', 'diamond', 'threat-landscape', 'feed', 'hunt', 'prism'];
  const today = new Date().toISOString().slice(0, 10);
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${routes.map(r => `  <url><loc>${SITE}${HREF}${r}</loc><lastmod>${today}</lastmod><priority>${r ? '0.8' : '1.0'}</priority></url>`).join('\n')}
</urlset>
`;
  await fs.writeFile(path.join(DIST, 'sitemap.xml'), sitemap);
  await fs.writeFile(path.join(DIST, 'robots.txt'),
    `User-agent: *\nAllow: /\n${SITE ? `Sitemap: ${SITE}${HREF}sitemap.xml\n` : ''}`);
  log('wrote   sitemap.xml + robots.txt');

  /* ------------------------------------------------------------------ size */
  const size = async d => {
    let t = 0;
    for (const e of await fs.readdir(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      t += e.isDirectory() ? await size(p) : (await fs.stat(p)).size;
    }
    return t;
  };
  console.log(`\n   dist/ ready — ${(await size(DIST) / 1048576).toFixed(1)} MB\n`);
}

main().catch(e => { console.error('\nBuild failed:', e); process.exit(1); });

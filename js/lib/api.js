/* ============================================================================
   Data layer with two runtimes.

   live   — the Node edge service (server.mjs) is answering /api/*. Feed is
            aggregated on demand, enrichment runs server-side, TAXII is dynamic.
   static — the app is a pile of files on a CDN (GitHub Pages). The feed is read
            from a snapshot refreshed by a scheduled GitHub Action, enrichment
            runs directly in the browser against CORS-enabled providers, and the
            STIX bundle is a pre-generated artifact.

   Views call these functions and never care which runtime they got. Every path
   is resolved against document.baseURI so the app works at a domain root or
   under a /repository-name/ project-pages prefix.
   ========================================================================== */

export const resolve = p => new URL(String(p).replace(/^\//, ''), document.baseURI).href;

let modePromise = null;

/** Probe once for a live backend; cache the answer for the session. */
export function detectMode() {
  if (modePromise) return modePromise;
  modePromise = (async () => {
    try {
      const res = await fetch(resolve('api/health'), {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(4000)
      });
      if (!res.ok) return 'static';
      const ct = res.headers.get('content-type') || '';
      if (!ct.includes('json')) return 'static';          // Pages 404.html fallback
      const body = await res.json();
      return body?.service === 'threatnexus-bd' ? 'live' : 'static';
    } catch {
      return 'static';
    }
  })();
  return modePromise;
}

const getJSON = async (path, timeout = 15000) => {
  const res = await fetch(resolve(path), {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(timeout)
  });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('json')) throw new Error('not json');
  return res.json();
};

/* -------------------------------------------------------------------- feed */
export async function getFeed(limit = 120) {
  const mode = await detectMode();
  if (mode === 'live') {
    const [items, sources] = await Promise.all([
      getJSON(`api/feed/items?limit=${limit}`).catch(() => null),
      getJSON('api/feed/sources').catch(() => null)
    ]);
    return {
      mode,
      items: items?.items || [],
      sources: sources?.sources || [],
      generated_at: items?.generated_at || null
    };
  }
  const [items, sources] = await Promise.all([
    getJSON('api/feed.json').catch(() => null),
    getJSON('api/feed-sources.json').catch(() => null)
  ]);
  return {
    mode,
    items: items?.items || [],
    sources: sources?.sources || [],
    generated_at: items?.generated_at || null
  };
}

/* ---------------------------------------------------------------- enrichment */
export async function getEnrichment(ioc) {
  const mode = await detectMode();
  if (mode === 'live') {
    try {
      return await getJSON('api/enrich?ioc=' + encodeURIComponent(ioc), 30000);
    } catch {
      /* fall through to in-browser enrichment */
    }
  }
  const { enrich } = await import('./enrich.js');
  return enrich(ioc);
}

/* --------------------------------------------------------------- STIX/TAXII */
export async function stixUrl() {
  const mode = await detectMode();
  return resolve(mode === 'live' ? 'api/taxii2/root/collections/bd/objects/' : 'api/stix.json');
}

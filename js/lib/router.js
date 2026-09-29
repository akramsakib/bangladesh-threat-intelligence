/* Tiny table-driven router over the History API. */

const ROUTES = [
  { path: '/globe',            view: 'globe',     aliases: ['/'] },
  { path: '/cluster',          view: 'cluster' },
  { path: '/diamond',          view: 'diamond' },
  { path: '/threat-landscape', view: 'landscape', aliases: ['/brief', '/landscape'] },
  { path: '/feed',             view: 'feed' },
  { path: '/hunt',             view: 'hunt' },
  { path: '/prism',            view: 'prism',     aliases: ['/enrich'] }
];

const byPath = new Map(), byView = new Map();
for (const r of ROUTES) {
  byPath.set(r.path, r.view);
  (r.aliases || []).forEach(a => byPath.set(a, r.view));
  byView.set(r.view, r.path);
}

const normalise = p => {
  let s = String(p || '/').toLowerCase();
  if (s.length > 1 && s.endsWith('/')) s = s.replace(/\/+$/, '');
  return s || '/';
};

export const viewForPath = p => byPath.get(normalise(p)) || null;
export const pathForView = v => byView.get(v) || '/globe';
export const routeViews = () => ROUTES.map(r => r.view);

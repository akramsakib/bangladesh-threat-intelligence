/* Local simulation of GitHub Pages: serves dist/ under a path prefix, returns
   404.html (with HTTP 404) for unknown paths, and has no /api/* backend.
   Used to verify the static build before deploying.  node tools/pages-sim.mjs */
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', 'dist');
const PREFIX = (process.env.BASE_PATH || '/bangladesh-threat-intelligence').replace(/\/+$/, '');
const PORT = process.env.PORT || 4000;

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.jpg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.xml': 'application/xml; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8'
};

http.createServer(async (req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);

  if (PREFIX && !p.startsWith(PREFIX)) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    return res.end('outside project prefix — Pages would 404 here');
  }
  p = p.slice(PREFIX.length) || '/';

  const candidates = [p, p.replace(/\/$/, '') + '/index.json', path.join(p, 'index.html')];
  for (const c of candidates) {
    if (c === '/' || c.endsWith('/')) continue;
    try {
      const file = path.join(ROOT, path.normalize(c));
      if (!file.startsWith(ROOT)) break;
      const data = await fs.readFile(file);
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      return res.end(data);
    } catch { /* next candidate */ }
  }
  if (p === '/') {
    const data = await fs.readFile(path.join(ROOT, 'index.html'));
    res.writeHead(200, { 'content-type': MIME['.html'] });
    return res.end(data);
  }
  // GitHub Pages behaviour: 404 status, 404.html body
  const data = await fs.readFile(path.join(ROOT, '404.html'));
  res.writeHead(404, { 'content-type': MIME['.html'] });
  res.end(data);
}).listen(PORT, '0.0.0.0', () =>
  console.log(`Pages simulation on 0.0.0.0:${PORT}${PREFIX}/`));

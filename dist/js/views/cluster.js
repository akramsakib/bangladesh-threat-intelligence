/* Relationship graph — D3 force layout over runtime-derived edges.
   D3 is loaded lazily the first time this view is opened. */
import { nationColor, EDGE_COLORS, MOTIVATION } from '../config.js';
import { esc } from '../lib/security.js';

let d3Loading = null;
const state = { types: { malware: true, cve: true, ttp: true, origin: true }, sim: null, built: false };

function loadD3() {
  if (globalThis.d3) return Promise.resolve();
  if (d3Loading) return d3Loading;
  d3Loading = new Promise((res, rej) => {
    const s = document.createElement('script');
    s.src = new URL('../../vendor/d3.min.js', import.meta.url).href;
    s.onload = res;
    s.onerror = () => { d3Loading = null; rej(new Error('d3 failed to load')); };
    document.head.appendChild(s);
  });
  return d3Loading;
}

export async function renderCluster(groups, edges, onSelect) {
  const root = document.getElementById('cluster-view');
  const counts = edges.reduce((a, e) => (a[e.type] = (a[e.type] || 0) + 1, a), {});

  root.innerHTML = `
    <div class="cl-top">
      <span class="mono" style="font-size:10px;color:var(--text3);letter-spacing:.1em">EDGES</span>
      ${['malware', 'cve', 'ttp', 'origin'].map(t => `
        <button class="cl-edge-toggle ${state.types[t] ? 'on' : ''}" data-type="${t}">
          <span class="ek-line" style="background:${EDGE_COLORS[t]}"></span>
          ${t === 'cve' ? 'CVE' : t === 'ttp' ? 'TTP' : t[0].toUpperCase() + t.slice(1)}
          <span class="n">${counts[t] || 0}</span>
        </button>`).join('')}
      <div style="flex:1"></div>
      <button class="btn-ghost" style="padding:6px 12px;font-size:11px" id="cl-stix">↓ STIX 2.1</button>
      <button class="btn-ghost" style="padding:6px 12px;font-size:11px" id="cl-reset">Reset</button>
    </div>
    <div class="cl-canvas"><svg id="cluster-svg"></svg></div>`;

  root.querySelectorAll('[data-type]').forEach(b => b.addEventListener('click', () => {
    state.types[b.dataset.type] = !state.types[b.dataset.type];
    b.classList.toggle('on', state.types[b.dataset.type]);
    draw(groups, edges, onSelect);
  }));
  document.getElementById('cl-stix').addEventListener('click', async () => window.open(await stixUrl(), '_blank'));
  document.getElementById('cl-reset').addEventListener('click', () => draw(groups, edges, onSelect));

  try { await loadD3(); } catch {
    root.querySelector('.cl-canvas').innerHTML = '<div class="pr-empty">Graph library unavailable.</div>';
    return;
  }
  requestAnimationFrame(() => draw(groups, edges, onSelect));
}

function draw(groups, edges, onSelect) {
  const svgEl = document.getElementById('cluster-svg');
  if (!svgEl || !globalThis.d3) return;
  const box = svgEl.getBoundingClientRect();
  const W = box.width || 900, H = box.height || 600;

  const nodes = groups.map(g => ({ ...g }));
  const ids = new Set(nodes.map(n => n.id));
  const links = edges
    .filter(e => state.types[e.type] && ids.has(e.s) && ids.has(e.t))
    .map(e => ({ source: e.s, target: e.t, type: e.type, n: e.n, items: e.items }));

  const svg = d3.select(svgEl);
  svg.selectAll('*').remove();
  svg.attr('viewBox', `0 0 ${W} ${H}`);
  const g = svg.append('g');

  const zoom = d3.zoom().scaleExtent([.25, 4]).on('zoom', ev => g.attr('transform', ev.transform));
  svg.call(zoom);
  state.zoom = zoom; state.svg = svg; state.g = g; state.W = W; state.H = H;

  const link = g.append('g').selectAll('line').data(links).join('line')
    .attr('stroke', d => EDGE_COLORS[d.type])
    .attr('stroke-opacity', d => d.type === 'ttp' ? .18 : .45)
    .attr('stroke-width', d => d.type === 'ttp' ? 1 : Math.min(3.5, 1 + d.n * .5))
    .attr('stroke-dasharray', d => d.type === 'cve' ? '4 3' : d.type === 'ttp' ? '2 3' : null);

  const node = g.append('g').selectAll('g').data(nodes).join('g')
    .style('cursor', 'pointer')
    .on('click', (_, d) => onSelect(d))
    .call(d3.drag()
      .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(.25).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
      .on('end', (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

  node.append('circle')
    .attr('class', 'node-circle')
    .attr('r', d => 8 + (d.bd_relevance / 100) * 12)
    .attr('fill', d => nationColor(d.country))
    .attr('fill-opacity', .88)
    .attr('stroke', d => MOTIVATION[d.motivation]?.hex || '#888')
    .attr('stroke-width', 2);

  node.append('title').text(d => `${d.name} — ${d.country} · BD exposure ${d.bd_relevance}`);

  node.append('text')
    .attr('class', 'node-label')
    .attr('text-anchor', 'middle')
    .attr('dy', d => 8 + (d.bd_relevance / 100) * 12 + 13)
    .text(d => d.name);

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(d => d.type === 'ttp' ? 165 : 115).strength(d => d.type === 'ttp' ? .06 : .3))
    .force('charge', d3.forceManyBody().strength(-430).distanceMax(520))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('x', d3.forceX(W / 2).strength(.055))
    .force('y', d3.forceY(H / 2).strength(.085))
    .force('collide', d3.forceCollide().radius(d => 40 + (d.bd_relevance / 100) * 14))
    .on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    })
    .on('end', fit);

  // frame the whole graph once the layout settles
  function fit() {
    if (!nodes.length) return;
    const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y);
    const pad = 70;
    const x0 = Math.min(...xs) - pad, x1 = Math.max(...xs) + pad;
    const y0 = Math.min(...ys) - pad, y1 = Math.max(...ys) + pad;
    const k = Math.min(2, Math.max(.25, Math.min(W / (x1 - x0), H / (y1 - y0))));
    const tx = W / 2 - k * (x0 + x1) / 2, ty = H / 2 - k * (y0 + y1) / 2;
    svg.transition().duration(650)
       .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(k));
  }
  state.fit = fit;
  setTimeout(fit, 2200);

  state.sim = sim;
}

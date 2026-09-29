/* ============================================================================
   ThreatNexus BD — WebGL globe
   Earth + atmosphere + starfield, origin markers per actor, and attack arcs
   converging on Bangladeshi target nodes (Dhaka, Motijheel, Chattogram…).
   ========================================================================== */

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { COUNTRY_COORDS, BD_NODES, OUTBOUND_TARGETS, nationColor, MOTIVATION, HOME } from './config.js';

const R = 100;
const ARC_PTS = 64;

let scene, camera, renderer, controls, raycaster, mouse, container, canvas;
let globeGroup, markerGroup, arcGroup, starField;
let markers = [], arcs = [];
let onSelect = null, hoverEl = null;
let showArcs = true, animId = null;
let arcDirection = 'both';           // 'in' | 'out' | 'both'
const OUT_COLOR = 0xa87dff;          // BD-origin / outbound
let allGroups = [];

const deg = d => d * Math.PI / 180;

function toVec(lat, lng, radius = R) {
  const phi = deg(90 - lat), theta = deg(lng + 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
     radius * Math.cos(phi),
     radius * Math.sin(phi) * Math.sin(theta)
  );
}

/* ----------------------------------------------------------- scene assets */
function makeAtmosphere() {
  return new THREE.ShaderMaterial({
    uniforms: { glowColor: { value: new THREE.Color(0x35c79a) } },
    vertexShader: `
      varying vec3 vNormal; varying vec3 vPos;
      void main(){ vNormal = normalize(normalMatrix * normal); vPos = normalize(position);
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }`,
    fragmentShader: `
      uniform vec3 glowColor; varying vec3 vNormal;
      void main(){
        float i = pow(0.62 - dot(vNormal, vec3(0.0,0.0,1.0)), 3.0);
        gl_FragColor = vec4(glowColor, 1.0) * i * 1.15; }`,
    side: THREE.BackSide, blending: THREE.AdditiveBlending, transparent: true, depthWrite: false
  });
}

function makeStars() {
  const n = 2600, pos = [], sizes = [];
  for (let i = 0; i < n; i++) {
    const r = 600 + Math.random() * 900;
    const t = Math.random() * Math.PI * 2, p = Math.acos(2 * Math.random() - 1);
    pos.push(r * Math.sin(p) * Math.cos(t), r * Math.sin(p) * Math.sin(t), r * Math.cos(p));
    sizes.push(Math.random() * 2.4 + 0.5);
  }
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
  g.setAttribute('aSize', new THREE.Float32BufferAttribute(sizes, 1));
  const mat = new THREE.ShaderMaterial({
    uniforms: { uColor: { value: new THREE.Color(0xbcd4ff) } },
    vertexShader: `attribute float aSize; varying float vS;
      void main(){ vS = aSize; vec4 mv = modelViewMatrix * vec4(position,1.0);
        gl_PointSize = aSize * (300.0 / -mv.z); gl_Position = projectionMatrix * mv; }`,
    fragmentShader: `uniform vec3 uColor; varying float vS;
      void main(){ float d = length(gl_PointCoord - vec2(0.5));
        if(d > 0.5) discard; gl_FragColor = vec4(uColor, (1.0 - d*2.0) * 0.75); }`,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending
  });
  return new THREE.Points(g, mat);
}


/* ------------------------------------------------------------------ label */
function makeLabel(text, lat, lng, color, size = 9) {
  const pad = 8, dpr = 2;
  const c = document.createElement('canvas');
  const ctx = c.getContext('2d');
  const font = `700 ${size * dpr}px ui-monospace, SFMono-Regular, Menlo, monospace`;
  ctx.font = font;
  const w = Math.ceil(ctx.measureText(text).width) + pad * 2 * dpr;
  const h = Math.ceil(size * dpr * 1.9);
  c.width = w; c.height = h;
  ctx.font = font;
  ctx.textBaseline = 'middle';
  ctx.fillStyle = color;
  ctx.shadowColor = 'rgba(0,0,0,.9)'; ctx.shadowBlur = 6 * dpr;
  ctx.fillText(text, pad * dpr, h / 2);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false, depthWrite: false }));
  const k = 0.105;
  spr.scale.set(w * k, h * k, 1);
  spr.position.copy(toVec(lat, lng, R + 2.2));
  spr.userData.isLabel = true;
  return spr;
}

/* ------------------------------------------------------------------ marker */
function makeMarker(group, idx, total) {
  const base = COUNTRY_COORDS[group.country] || COUNTRY_COORDS.Unknown;
  // fan actors out around their origin so overlapping dossiers stay clickable
  const ring = Math.floor(idx / 6), slot = idx % 6;
  const ang = (slot / 6) * Math.PI * 2 + ring * 0.5;
  const spread = idx === 0 ? 0 : 2.6 + ring * 2.8;
  const lat = base.lat + Math.sin(ang) * spread;
  const lng = base.lng + Math.cos(ang) * spread * 1.25;

  const col = new THREE.Color(nationColor(group.country));
  const pos = toVec(lat, lng, R + 1.2);
  const g = new THREE.Group();
  g.position.copy(pos);
  g.lookAt(0, 0, 0);

  const size = 0.75 + (group.bd_relevance / 100) * 1.15;
  const core = new THREE.Mesh(
    new THREE.CircleGeometry(size, 24),
    new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: .95, side: THREE.DoubleSide })
  );
  const halo = new THREE.Mesh(
    new THREE.RingGeometry(size * 1.5, size * 2.1, 32),
    new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: .40, side: THREE.DoubleSide, depthWrite: false })
  );
  g.add(core); g.add(halo);
  g.userData = { group, halo, baseSize: size, lat, lng, phase: Math.random() * Math.PI * 2 };
  return g;
}

function makeHomeMarker() {
  const g = new THREE.Group();
  const pos = toVec(HOME.lat, HOME.lng, R + 1.4);
  g.position.copy(pos); g.lookAt(0, 0, 0);
  const green = new THREE.Color(0x1db584), red = new THREE.Color(0xf42a41);
  g.add(new THREE.Mesh(new THREE.CircleGeometry(1.9, 32),
    new THREE.MeshBasicMaterial({ color: green, transparent: true, opacity: .9, side: THREE.DoubleSide })));
  g.add(new THREE.Mesh(new THREE.CircleGeometry(0.85, 24),
    new THREE.MeshBasicMaterial({ color: red, side: THREE.DoubleSide })));
  const pulse = new THREE.Mesh(new THREE.RingGeometry(2.3, 2.9, 48),
    new THREE.MeshBasicMaterial({ color: green, transparent: true, opacity: .5, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
  g.add(pulse);
  g.userData = { home: true, pulse };
  return g;
}

/* --------------------------------------------------------------------- arc */
function makeArc(fromLat, fromLng, toLat, toLng, color, speed) {
  const v1 = toVec(fromLat, fromLng, R + 0.5);
  const v2 = toVec(toLat, toLng, R + 0.5);
  const dist = v1.distanceTo(v2);
  const mid = v1.clone().add(v2).multiplyScalar(.5).normalize().multiplyScalar(R + dist * 0.42 + 6);
  const curve = new THREE.QuadraticBezierCurve3(v1, mid, v2);
  const pts = curve.getPoints(ARC_PTS - 1);

  const line = new THREE.Line(
    new THREE.BufferGeometry().setFromPoints(pts),
    new THREE.LineBasicMaterial({ color, transparent: true, opacity: .30, blending: THREE.AdditiveBlending, depthWrite: false })
  );
  const head = new THREE.Mesh(
    new THREE.SphereGeometry(0.55, 10, 10),
    new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .95, blending: THREE.AdditiveBlending, depthWrite: false })
  );
  const ring = new THREE.Mesh(
    new THREE.RingGeometry(0.7, 1.15, 28),
    new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false })
  );
  ring.position.copy(v2); ring.lookAt(0, 0, 0);

  const grp = new THREE.Group();
  grp.add(line); grp.add(head); grp.add(ring);
  grp.userData = { curve, head, ring, t: Math.random(), speed };
  return grp;
}

/* -------------------------------------------------------------------- init */
export function initGlobe(groups, selectHandler) {
  onSelect = selectHandler;
  canvas = document.getElementById('globe-canvas');
  container = canvas.parentElement;
  hoverEl = document.getElementById('g-tooltip');

  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x03060c);
  scene.fog = new THREE.FogExp2(0x03060c, 0.0016);

  camera = new THREE.PerspectiveCamera(38, container.clientWidth / container.clientHeight, 0.1, 4000);
  // open looking at South Asia
  camera.position.copy(toVec(18, 86, 330));

  renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(container.clientWidth, container.clientHeight);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.06;

  controls = new OrbitControls(camera, canvas);
  controls.enableDamping = true;
  controls.dampingFactor = .06;
  controls.rotateSpeed = .42;
  controls.minDistance = 150;
  controls.maxDistance = 520;
  controls.enablePan = false;
  controls.autoRotate = false;

  globeGroup = new THREE.Group();
  scene.add(globeGroup);

  const earthMat = new THREE.MeshPhongMaterial({ color: 0x0d1c2c, shininess: 6, specular: 0x14324a });
  new THREE.TextureLoader().load(new URL('../assets/earth-blue-marble.jpg', import.meta.url).href, tex => {
    tex.colorSpace = THREE.SRGBColorSpace;
    earthMat.map = tex; earthMat.color.set(0xffffff); earthMat.needsUpdate = true;
  });
  globeGroup.add(new THREE.Mesh(new THREE.SphereGeometry(R, 96, 96), earthMat));
  globeGroup.add(new THREE.Mesh(new THREE.SphereGeometry(R + 3.2, 64, 64), makeAtmosphere()));

  const sun = new THREE.DirectionalLight(0xfff3e2, 1.25);
  sun.position.copy(new THREE.Vector3(0.6, 0.35, 0.8).normalize().multiplyScalar(500));
  scene.add(sun);
  scene.add(new THREE.AmbientLight(0x50708f, .85));
  scene.add(new THREE.HemisphereLight(0x9fc0ff, 0x0c1626, .5));

  starField = makeStars();
  scene.add(starField);

  markerGroup = new THREE.Group(); globeGroup.add(markerGroup);
  arcGroup = new THREE.Group(); globeGroup.add(arcGroup);
  globeGroup.add(makeHomeMarker());

  raycaster = new THREE.Raycaster();
  mouse = new THREE.Vector2(-9999, -9999);

  canvas.addEventListener('pointermove', onPointerMove);
  canvas.addEventListener('click', onClick);
  window.addEventListener('resize', onResize);
  document.addEventListener('theme-change', applyTheme);
  applyTheme();

  allGroups = groups;
  updateGlobe(groups);
  animate();
}

function applyTheme() {
  const light = document.body.classList.contains('light-mode');
  const bg = light ? 0xdfe8f4 : 0x03060c;
  scene.background = new THREE.Color(bg);
  scene.fog = new THREE.FogExp2(bg, light ? 0.0009 : 0.0016);
  if (starField) starField.visible = !light;
}

/* ------------------------------------------------------------------ update */
export function updateGlobe(groups) {
  allGroups = groups;
  markerGroup.clear(); arcGroup.clear();
  markers = []; arcs = [];

  const perCountry = {};
  groups.forEach(g => {
    const c = g.country || 'Unknown';
    perCountry[c] = perCountry[c] || [];
    perCountry[c].push(g);
  });

  Object.entries(perCountry).forEach(([country, list]) => {
    list.forEach((g, i) => {
      const m = makeMarker(g, i, list.length);
      markerGroup.add(m); markers.push(m);
    });
    const base = COUNTRY_COORDS[country] || COUNTRY_COORDS.Unknown;
    const rows = Math.ceil(list.length / 6);
    const text = country === 'Unknown' ? `UNATTRIBUTED (${list.length})` : `${country.toUpperCase()} (${list.length})`;
    markerGroup.add(makeLabel(text, base.lat - (6.0 + rows * 1.6), base.lng, nationColor(country), 9));
  });

  markerGroup.add(makeLabel('DHAKA \u2014 HOME', HOME.lat + 6.5, HOME.lng - 9, '#4ade9f', 9.5));

  /* --- inbound: origin country -> a Bangladeshi asset class --- */
  groups.forEach((g, gi) => {
    if (g.bd_status === 'outbound') return;            // purely outbound actors never strike BD
    const origin = COUNTRY_COORDS[g.country] || COUNTRY_COORDS.Unknown;
    const node = BD_NODES[gi % BD_NODES.length];
    const col = new THREE.Color(MOTIVATION[g.motivation]?.hex || '#4a9eff');
    const speed = 0.0026 + (g.bd_relevance / 100) * 0.004;
    const a = makeArc(origin.lat + (gi % 3) * 1.4, origin.lng + (gi % 4) * 1.6, node.lat, node.lng, col, speed);
    a.userData.dir = 'in';
    a.visible = showArcs && arcDirection !== 'out';
    arcGroup.add(a); arcs.push(a);
  });

  /* --- outbound: Dhaka -> countries struck from Bangladesh --- */
  const outActors = groups.filter(g => Array.isArray(g.outbound_targets) && g.outbound_targets.length);
  const outTally = new Map();
  outActors.forEach(g => g.outbound_targets.forEach(([name, share, note]) => {
    const prev = outTally.get(name) || { share: 0, actors: [], contributions: [], note };
    prev.share = share;                       // last writer; only shown when a single actor
    prev.actors.push(g.name);
    prev.contributions.push(`${g.name}: ${share}%`);
    outTally.set(name, prev);
  }));

  outTally.forEach((info, name) => {
    const dest = OUTBOUND_TARGETS.find(t => t.label === name)
              || (COUNTRY_COORDS[name] ? { ...COUNTRY_COORDS[name], label: name } : null);
    if (!dest) return;
    const col = new THREE.Color(OUT_COLOR);
    const speed = 0.0030 + (info.share / 100) * 0.004;
    const a = makeArc(HOME.lat, HOME.lng, dest.lat, dest.lng, col, speed);
    a.userData.dir = 'out';
    a.userData.outbound = { name, ...info };
    a.visible = showArcs && arcDirection !== 'in';
    arcGroup.add(a); arcs.push(a);

    const tag = info.actors.length > 1
      ? `${info.actors.length} actors`
      : `${info.share}%`;
    markerGroup.add(makeLabel(`\u2192 ${name.toUpperCase()} ${tag}`,
      dest.lat - 5.5, dest.lng, '#c4a6ff', 8));
  });

  renderLegend(groups);
}

function renderLegend(groups) {
  const el = document.getElementById('globe-legend');
  if (!el) return;
  const byStatus = {};
  groups.forEach(g => { byStatus[g.bd_status] = (byStatus[g.bd_status] || 0) + 1; });
  const labels = { confirmed: 'Confirmed vs BD', assessed: 'Assessed exposure', regional: 'Regional spillover', outbound: 'BD-origin (outbound)' };
  const cols = { confirmed: '#f0544f', assessed: '#f5a623', regional: '#4a9eff', outbound: '#a87dff' };
  const outCount = groups.filter(g => Array.isArray(g.outbound_targets) && g.outbound_targets.length).length;
  el.innerHTML =
    '<div class="gl-title">Targeting Bangladesh</div>' +
    Object.keys(labels).filter(k => byStatus[k]).map(k =>
      `<div class="ek-row"><span class="ek-dot" style="background:${cols[k]}"></span>${labels[k]}<span style="margin-left:auto;color:var(--text4)">${byStatus[k]}</span></div>`
    ).join('') +
    (outCount ? `<div class="ek-row" style="margin-top:6px;padding-top:6px;border-top:1px solid var(--border)">
        <span class="ek-dot" style="background:#a87dff"></span>Outbound from Bangladesh<span style="margin-left:auto;color:var(--text4)">${outCount}</span></div>` : '') +
    `<div class="gl-note">Inbound arcs run from actor origin to the Bangladeshi asset class most associated with their reporting. <b style="color:#c4a6ff">Violet arcs leave Dhaka</b> for targets struck from Bangladesh. Marker size = BD exposure score.</div>`;
}

export function setArcDirection(dir) {
  arcDirection = dir;
  arcs.forEach(a => {
    a.visible = showArcs && (dir === 'both' || a.userData.dir === dir);
  });
  return arcDirection;
}

export function arcCounts() {
  return {
    in: arcs.filter(a => a.userData.dir === 'in').length,
    out: arcs.filter(a => a.userData.dir === 'out').length
  };
}

export function toggleArcs(force) {
  showArcs = typeof force === 'boolean' ? force : !showArcs;
  arcs.forEach(a => {
    a.visible = showArcs && (arcDirection === 'both' || a.userData.dir === arcDirection);
  });
  return showArcs;
}

export function focusActor(group) {
  const m = markers.find(x => x.userData.group?.id === group.id);
  if (!m) return;
  const { lat, lng } = m.userData;
  const target = toVec(lat, lng, 250);
  const start = camera.position.clone();
  const t0 = performance.now();
  (function fly() {
    const k = Math.min(1, (performance.now() - t0) / 900);
    const e = 1 - Math.pow(1 - k, 3);
    camera.position.lerpVectors(start, target, e);
    if (k < 1) requestAnimationFrame(fly);
  })();
}

/* -------------------------------------------------------------- interaction */
function onPointerMove(ev) {
  const r = canvas.getBoundingClientRect();
  mouse.x = ((ev.clientX - r.left) / r.width) * 2 - 1;
  mouse.y = -((ev.clientY - r.top) / r.height) * 2 + 1;
  hoverEl.dataset.x = ev.clientX - r.left;
  hoverEl.dataset.y = ev.clientY - r.top;
}

function pick() {
  raycaster.setFromCamera(mouse, camera);
  const hits = raycaster.intersectObjects(markerGroup.children, true);
  if (!hits.length) return null;
  let o = hits[0].object;
  while (o && !o.userData?.group) o = o.parent;
  return o || null;
}

function onClick() {
  const hit = pick();
  if (hit && onSelect) onSelect(hit.userData.group);
}

function onResize() {
  if (!container.clientWidth) return;
  camera.aspect = container.clientWidth / container.clientHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(container.clientWidth, container.clientHeight);
}

/* ------------------------------------------------------------------- frame */
function animate() {
  animId = requestAnimationFrame(animate);
  const t = performance.now() * 0.001;

  const camDir = camera.position.clone().normalize();
  markerGroup.children.forEach(o => {
    if (!o.userData?.isLabel) return;
    const n = o.position.clone().applyMatrix4(globeGroup.matrixWorld).normalize();
    o.visible = n.dot(camDir) > 0.22;
  });

  markers.forEach(m => {
    const u = m.userData;
    const s = 1 + Math.sin(t * 1.6 + u.phase) * .18;
    u.halo.scale.setScalar(s);
    u.halo.material.opacity = .45 - Math.sin(t * 1.6 + u.phase) * .15;
  });

  globeGroup.children.forEach(c => {
    if (c.userData?.home) {
      const k = (t * 0.5) % 1;
      c.userData.pulse.scale.setScalar(1 + k * 1.9);
      c.userData.pulse.material.opacity = .55 * (1 - k);
    }
  });

  if (showArcs) {
    arcs.forEach(a => {
      const u = a.userData;
      u.t += u.speed;
      if (u.t > 1) { u.t = 0; u.ring.userData = { flash: performance.now() }; }
      u.head.position.copy(u.curve.getPoint(u.t));
      u.head.material.opacity = .35 + Math.sin(u.t * Math.PI) * .65;
      const f = u.ring.userData?.flash;
      if (f) {
        const k = Math.min(1, (performance.now() - f) / 900);
        u.ring.scale.setScalar(1 + k * 4);
        u.ring.material.opacity = .8 * (1 - k);
        if (k >= 1) u.ring.userData = {};
      }
    });
  }

  // hover tooltip
  const hit = pick();
  if (hit) {
    const g = hit.userData.group;
    canvas.style.cursor = 'pointer';
    hoverEl.style.opacity = '1';
    hoverEl.style.left = (Number(hoverEl.dataset.x) + 14) + 'px';
    hoverEl.style.top = (Number(hoverEl.dataset.y) + 14) + 'px';
    hoverEl.innerHTML =
      `<div class="tt-name">${g.name}</div>
       <div class="tt-sub">${g.country} · ${g.motivation} · BD exposure ${g.bd_relevance}</div>`;
  } else {
    canvas.style.cursor = 'grab';
    hoverEl.style.opacity = '0';
  }

  controls.update();
  renderer.render(scene, camera);
}

export function disposeGlobe() { if (animId) cancelAnimationFrame(animId); }

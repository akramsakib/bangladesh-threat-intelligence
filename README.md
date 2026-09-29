# ThreatNexus BD

A Bangladesh-focused cyber threat intelligence console, built in the same architectural idiom as
[threatnexus.online](https://threatnexus.online) — frameworkless ES modules, a three.js globe, a D3 force graph,
and a zero-dependency Node edge service — but with the corpus, geography, executive brief and hunt content
centred entirely on threats to Bangladesh.

```bash
npm start                # full app on http://localhost:3000  (Node >= 20, zero dependencies)
npm run build            # static build into dist/
npm run preview          # build + serve dist/ exactly as GitHub Pages would
```

**Live site:** deployed to GitHub Pages by `.github/workflows/deploy.yml` on every push,
and rebuilt on a 6-hourly cron so the intelligence feed stays current.

---

## The intelligence

**19 actor dossiers** with confirmed or assessed relevance to Bangladesh, in four exposure bands:

| Band | Meaning | Count |
|---|---|---|
| `confirmed` | Public reporting names Bangladeshi victims or Bangladesh-specific lures | 10 |
| `assessed` | Documented capability and regional targeting; BD exposure inferred | 4 |
| `regional` | Active in South Asia, spillover risk to BD | 4 |
| `outbound` | Operating *from* Bangladesh | 1 |

Origins: India (4), China (3), North Korea (2), Pakistan (2), Bangladesh (1), unattributed clusters (7).

Everything is sourced. Each dossier carries a `sources` array of the advisories and vendor reports it was
built from — BGD e-GOV CIRT, Cyderes, Hunt.io, Trellix, Kaspersky, Group-IB, CISA, Talos and mainstream
Bangladeshi press. Three data-integrity rules are enforced throughout:

1. **Precision over recall on attribution.** An actor is attributed to a state only where government or
   first-party vendor reporting names it. Everything else stays `Unknown` / *unattributed* — which is why
   seven of nineteen entries are clusters rather than named groups.
2. **Infrastructure facts never move a malice verdict.** Hosting, registrar and ASN are context, not evidence.
3. **"Benign" is never asserted.** Absence of evidence returns `UNKNOWN`, not clean.

Alongside the actors: a **national incident record** of 19 sourced events from the 2013 Sonali Bank breach
through the 2016 Bangladesh Bank SWIFT heist to 2026 CIRT advisories, and a **10-sector exposure model**
(Banking 96, Military & Defence 94, Government 91, Telecom 82, Energy/OT 78 …).

## The views

| Route | View | What it answers |
|---|---|---|
| `/globe` | 3D globe | Where do attacks on Bangladesh originate? Every arc terminates on a Bangladeshi asset class; Dhaka is the home marker. |
| `/cluster` | D3 force graph | Which actors overlap? Edges are derived at runtime from shared malware, shared CVEs, ≥3 shared ATT&CK techniques and common origin. |
| `/diamond` | Diamond Model cards | Adversary / Capability / Infrastructure / **Victim scoped to Bangladesh** — each card reads as a local targeting hypothesis. |
| `/threat-landscape` | National brief | CONDITION banner, headline counts, origin donut, motivation and confidence mix, sector bars, top-10 ranking, filterable incident timeline. |
| `/feed` | Live feed | Ten RSS sources scored for Bangladesh relevance, always merged with a curated BGD e-GOV CIRT advisory record. Source-health panel included. |
| `/hunt` | Hunt packs | 31 detection leads (KQL / SPL / Sigma), a TTP × actor coverage matrix, a sector pivot, and the national hardening checklist mapped to named actors. |
| `/prism` | IOC enrichment | RDAP, Cloudflare DoH, crt.sh, Shodan InternetDB, RIPEstat, ipwho.is + corpus sighting. No API keys, no account. |

Filters (exposure band, motivation, origin, free text) live in the shell and persist across every view —
each view is a lens over one filtered set. `⌘K` opens spotlight; `1`–`7` switch views; `T` toggles theme;
`Esc` closes the dossier. Dossiers deep-link as `#actor=<id>`.

## The API

| Endpoint | Returns |
|---|---|
| `GET /api/health` | Corpus counts, feed cache age, capabilities |
| `GET /api/actors` | Actor index as JSON |
| `GET /api/feed/items?limit=&bd=1` | Aggregated, deduplicated, severity- and BD-scored feed items |
| `GET /api/feed/sources` | Per-source health: reachable, item count, category |
| `GET /api/enrich?ioc=` | Multi-source enrichment with signals, verdict and per-datum provenance |
| `GET /api/taxii2/` → `/root/` → `/root/collections/` | TAXII 2.1 discovery |
| `GET /api/taxii2/root/collections/bd/objects/` | **481-object STIX 2.1 bundle** — 19 intrusion-sets, 65 malware, 92 attack-patterns, 20 vulnerabilities, indicators and 278 relationships, ETag-cached |

The STIX bundle is generated from the same corpus the UI reads, with deterministic UUIDv5-style ids, so it is
stable across restarts and safe to poll.

## Two runtimes, one codebase

The app detects at boot whether a Node backend is answering and adapts. Nothing is stubbed out
and no feature is faked — the static deployment keeps every capability except on-demand
re-aggregation, which becomes a scheduled rebuild instead.

| Capability | `npm start` (Node) | GitHub Pages (static) |
|---|---|---|
| Globe, cluster, diamond, brief, hunt | Full | Full — pure client-side already |
| Intelligence feed | Aggregated on request, 15-min cache | Snapshot in `api/feed.json`, rebuilt every 6 h by Action |
| IOC enrichment (Prism) | Server-side via `/api/enrich` | **Runs in the browser** — all six providers send `Access-Control-Allow-Origin: *` |
| STIX 2.1 / TAXII | Generated per request, ETag-cached | Pre-generated `api/stix.json` + TAXII-shaped path aliases |
| Deep links, back button | History API | Same, via `404.html` fallback and a base-aware router |

`js/lib/api.js` is the single switch: it probes `api/health`, caches the verdict for the session,
and every view calls it rather than `fetch` directly. `js/lib/enrich.js` is genuinely isomorphic —
`server.mjs` imports the same module the browser does, so both runtimes produce identical verdicts
from identical logic.

Because the build is base-aware (paths resolve against `document.baseURI`, the router strips the
deployment prefix), the identical `dist/` works at `user.github.io/repo/` or at a domain root with
no reconfiguration.

## Publishing

First time only — creates the repo, pushes, enables Pages and waits for the deploy:

```bash
./tools/publish.sh          # prompts for a token; nothing is written to disk
```

The token needs the **`repo`** and **`workflow`** scopes (GitHub refuses any push
containing `.github/workflows/` without the latter). It is held in a shell variable
for the duration of the run, passed to git via an in-memory header, and never
persisted to `.git/config`.

## Deploying

After that, pushing to `main` is all that is required — the workflow calls `actions/configure-pages`, which
supplies the repository path prefix and origin to the build, then uploads `dist/`.

To host the **full** backend as well (live on-demand aggregation rather than a 6-hourly snapshot),
`server.mjs` runs as-is on any Node host — `npm start`, port from `$PORT`, no dependencies, no build
step. Point it at the same repo and the frontend will detect the live API and switch itself over.

## Design notes

Same token system and shell geometry as the original — 56px topbar, 222px filter rail, 480px detail drawer,
mono type for all data, nation-coloured dots, freshness ramp — with the palette shifted towards Bangladeshi
green and red and four South Asian origin colours added.

Four flaws found in the original teardown are fixed here:

- **Fonts.** The original names font families it never loads. This build uses system stacks only, so the
  rendered type matches the specified type.
- **Caching.** `/vendor/*` and `/assets/*` ship `max-age=31536000, immutable`; HTML and modules ship `no-cache`.
- **Semantics.** A real `<h1>`, `role="tablist"`/`tab`/`tabpanel` with live `aria-selected`, JSON-LD
  (`WebSite` + `Dataset`), Open Graph tags, `robots.txt` and `sitemap.xml`.
- **No-JS fallback.** A `<noscript>` block links to the STIX bundle, the JSON actor index and the national CERT.

## Layout

```
index.html            app shell — topbar, filter rail, 7 panels, detail drawer, spotlight
server.mjs            static serving + API surface (imports the shared engines)
tools/feed.mjs        RSS aggregation + Bangladesh relevance scoring
tools/stix.mjs        STIX 2.1 bundle generation
tools/build.mjs       static build for GitHub Pages
tools/pages-sim.mjs   local GitHub Pages simulator (prefix + 404 behaviour)
.github/workflows/    build, verify and deploy; 6-hourly feed refresh
css/style.css         tokens, shell, drawer, spotlight
css/views.css         per-view components
data/actors.js        GROUPS (19 dossiers) · INCIDENTS (19) · SECTORS (10)
data/advisories.js    BD_ADVISORIES — curated CIRT + vendor record, always merged into the feed
js/app.js             boot, filters, router, theme, spotlight, keyboard
js/config.js          palettes, geography, BD asset nodes, freshness, computeEdges()
js/globe.js           three.js scene
js/detail.js          dossier drawer
js/lib/               security.js (escaping) · router.js (base-aware) ·
                      api.js (runtime switch) · enrich.js (isomorphic engine)
js/views/             cluster · diamond · landscape · feed · hunt · prism
vendor/               three 0.160.0, OrbitControls, d3 7.9.0 — pinned, self-hosted
```

## Licence & provenance

Intelligence content is compiled from public reporting under **CC BY 4.0**, **TLP:CLEAR**. Not affiliated
with BGD e-GOV CIRT, NCSA or any source organisation. Attribution is hard — corroborate against the cited
primary sources before acting on anything here.

Report indicators and incidents to BGD e-GOV CIRT: `cti@cirt.gov.bd` · NCSA: `notify@ncsa.gov.bd`

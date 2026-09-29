# LinkedIn post drafts — ThreatNexus BD

Pick one, edit the voice to sound like you, and post the link as a **comment**
rather than in the post body (LinkedIn suppresses reach on posts with outbound
links in the body).

Live: https://akramsakib.github.io/bangladesh-threat-intelligence/
Repo: https://github.com/akramsakib/bangladesh-threat-intelligence

**Images to attach** (captured from production, not mockups):
- `docs/screenshots/linkedin-card.png` — 1200x627, the standard LinkedIn card
- `docs/screenshots/linkedin-card-square.png` — 1200x1200, takes more vertical
  space in the mobile feed; use this one if you want maximum thumb-stopping size
- `docs/screenshots/landscape-outbound-panel.png` — the Threat Landscape brief,
  good as a second image if you post a carousel

---

## Option A — the community / practitioner angle (recommended)

> Most threat intelligence written about South Asia treats Bangladesh as a
> footnote. I wanted to see what the picture looked like if you put it in the
> centre instead.
>
> So I built ThreatNexus BD — a free, open threat intelligence console focused
> entirely on threats to Bangladeshi organisations.
>
> What's in it:
>
> • 19 actor dossiers — SideWinder, DoNot (APT-C-35), Bitter, Lazarus and others
>   with documented activity against Bangladeshi government, military, banking,
>   telecom and energy targets
> • A live advisory feed aggregated from BGD e-GOV CIRT, government sources and
>   vendor reporting
> • Sector exposure scoring, ATT&CK mapping, and hunt queries
> • STIX 2.1 export, so anything here drops straight into your own tooling
> • An attack map that runs both directions — inbound campaigns against
>   Bangladesh, and hacktivist activity originating from it
>
> Every claim is sourced. Where the reporting doesn't break something out, the
> interface says so rather than filling the gap with a guess — there's a
> literal "unspecified" bucket on the map for exactly that reason.
>
> No login, no paywall, no email capture. If it's useful to your SOC, take it.
>
> Design language adapted with thanks from Awais Munir's ThreatNexus
> (threatnexus.online).
>
> Feedback from anyone working Bangladeshi infrastructure defence is very
> welcome — particularly corrections. Getting attribution wrong in public is
> worse than saying nothing.
>
> #ThreatIntelligence #CyberSecurity #Bangladesh #CTI #InfoSec

---

## Option A (short) — FINAL

> Most threat intelligence on South Asia treats Bangladesh as a footnote.
> I wanted to see the picture with it in the centre.
>
> So I built ThreatNexus BD — a free threat intelligence console focused
> entirely on threats to Bangladeshi organisations.
>
> • 19 actor dossiers — SideWinder, DoNot, Bitter, Lazarus and others with
>   documented activity against BD government, banking, telecom and energy
> • Live advisory feed from BGD e-GOV CIRT and vendor reporting
> • ATT&CK mapping, hunt queries, STIX 2.1 export for your own tooling
> • An attack map that runs both ways — inbound campaigns, and hacktivist
>   activity originating from Bangladesh
>
> Every claim is sourced. Where reporting leaves a gap, the interface says so
> instead of guessing.
>
> No login, no paywall. If it's useful to your SOC, take it.
>
> Design adapted with thanks from Awais Munir's ThreatNexus.
>
> Corrections welcome — especially on attribution.
>
> Link in comments.
>
> #ThreatIntelligence #CyberSecurity #Bangladesh #CTI

**Word count:** ~120. Roughly 3 lines above LinkedIn's "see more" fold.

### Follow-up comment to post underneath

> Live: https://akramsakib.github.io/bangladesh-threat-intelligence/
> Source: https://github.com/akramsakib/bangladesh-threat-intelligence
>
> Static site — no backend. A GitHub Action aggregates the advisory feeds and
> publishes to Pages; the client re-fetches on a timer so the feed stays
> current without a reload. Free to fork.

---

## Option B — the build / engineering angle

> I spent this week building a threat intelligence platform with no backend.
>
> ThreatNexus BD is a Bangladesh-focused CTI console: 19 actor dossiers, a live
> advisory feed, ATT&CK mapping, hunt queries and STIX 2.1 export. It's a
> static site. No server, no database, no running costs.
>
> How it works: a GitHub Action aggregates advisory feeds, builds a static
> bundle and publishes it to Pages. The client re-fetches the feed JSON on a
> timer, so the UI stays current without a reload. A WebGL globe renders
> campaign arcs in both directions — inbound against Bangladesh, and outbound
> from it.
>
> The interesting constraint was honesty under uncertainty. When Group-IB
> reported one group's targeting as 34% India and 18% Israel, the remaining 48%
> was never broken out. The easy thing is to quietly drop it. Instead it renders
> as an explicit "unspecified" bucket — because a visualisation that looks
> complete when the underlying data isn't is worse than one that admits the gap.
>
> Live and open source, links in the comments.
>
> Design language adapted with thanks from Awais Munir's ThreatNexus.
>
> #CyberSecurity #ThreatIntelligence #OpenSource #WebGL #StaticSite

---

## Option C — short, for higher engagement

> Bangladesh gets treated as a footnote in most South Asia threat reporting.
>
> So I built a threat intelligence console that puts it in the centre — 19
> actor dossiers, a live advisory feed from BGD e-GOV CIRT and vendor sources,
> ATT&CK mapping, and STIX export for your own tooling.
>
> Free. No login. Every claim sourced.
>
> Corrections welcome — especially on attribution.
>
> Link in comments 👇
>
> #ThreatIntelligence #CyberSecurity #Bangladesh #CTI

---

## Notes before you post

**Credit the original.** The visual design and app structure are closely modelled
on threatnexus.online by Awais Munir. His content is CC BY 4.0, but the platform
itself is proprietary. A one-line credit costs you nothing and protects you from
the much worse outcome of someone else pointing it out in your comments.

**Don't claim a refresh cadence.** GitHub's scheduler has not fired a single
scheduled build on the repo yet, so avoid "updates every 15 minutes" or similar.
"Live feed" and "auto-refreshing" are accurate; a specific interval is not.

**Say 19 actors, not "comprehensive."** The dataset is deliberately narrow and
sourced. Precision is the selling point — overclaiming invites exactly the kind
of scrutiny that finds the weakest entry.

**Expect attribution pushback.** Naming state-linked groups in a public post
about a neighbouring country's activity can attract argument. The "corrections
welcome" line is doing real work — keep it.

**First two lines matter most.** LinkedIn truncates around 140 characters. Every
draft above front-loads the hook before the fold.

---

## FINAL — short, with tags (use this one)

**Attach:** `docs/screenshots/linkedin-card.png`

> Most threat intelligence on South Asia treats Bangladesh as a footnote.
> I wanted to see the picture with it in the centre.
>
> So I built ThreatNexus BD — a free threat intelligence console focused
> entirely on threats to Bangladeshi organisations.
>
> - 19 actor dossiers: SideWinder, DoNot, Bitter, Lazarus and others with
>   documented activity against BD government, banking, telecom and energy
> - A live advisory feed built on @BGD e-GOV CIRT bulletins and vendor reporting
> - ATT&CK mapping, hunt queries, STIX 2.1 export for your own tooling
> - An attack map that runs both ways: inbound campaigns, and hacktivist
>   activity originating from Bangladesh
>
> Every claim is sourced. Where the reporting leaves a gap, the interface says
> so instead of guessing.
>
> No login, no paywall. If it is useful to your SOC, take it.
>
> Design adapted with thanks from Awais Munir's ThreatNexus.
>
> Corrections welcome, especially on attribution.
>
> Link in comments.
>
> #ThreatIntelligence #CyberSecurity #Bangladesh #CTI

### Tags to insert
Type `@` in the LinkedIn composer and pick from the dropdown. Pasting the text
`@BGD e-GOV CIRT` does nothing - it stays plain text and nobody is notified.

| Org | Page to select | Where |
|---|---|---|
| BGD e-GOV CIRT | company/bgdegovcirt (~1,900 followers, NOT the 22-follower showcase) | in the feed bullet |
| Bangladesh Computer Council | company/bangladesh-computer-council | optional, in the comment |
| BASIS | company/basis-bd | optional, in the comment |

### First comment

> Live: https://akramsakib.github.io/bangladesh-threat-intelligence/
> Source: https://github.com/akramsakib/bangladesh-threat-intelligence
>
> Static site, no backend. A GitHub Action aggregates the advisory feeds and
> publishes to Pages. Free to fork.
>
> Built on public advisories from @BGD e-GOV CIRT and @Bangladesh Computer Council.

### Do not tag
- **Bangladesh Bank** - the dossier set includes the 2016 SWIFT heist. Tagging
  the victim of the incident you are showcasing reads as tone-deaf.
- **Any Indian agency or company** - the map shows outbound hacktivist activity
  from Bangladesh against Indian targets. Tagging them invites a fight.
- More than 3 orgs total. Over-tagging is a spam signal and suppresses reach.

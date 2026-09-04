#!/usr/bin/env python3
"""Render the slides the course video is cut from: one 1920x1080 PNG per narrated paragraph.

    python3 scripts/render-slides.py [--only SLUG]

Reads audio/course.json (from `scripts/course-audio.py --json`: every paragraph as HTML plus the
lesson's figures, terminal blocks and tables) and audio/timeline.json (from render-course.py:
which paragraphs were narrated, in what order) and writes, per episode,

    video/slides/<slug>/title.png     the title card — scripts/render-video.sh also uses it as the poster
    video/slides/<slug>/pNNNN.png     one per timeline entry, NNNN = the entry's index

A paragraph slide shows the spoken paragraph and the lesson visual that belongs to that point of the
episode (visuals are spread evenly over the paragraphs) — or, when the lesson has none, a quiet
episode numeral. Two layouts: the paragraph in a left column with the visual beside it, or, when that
would show the visual clearly smaller, the paragraph as a band on top with the visual full-width
below. The layout, the band's height and the visual's scale are decided once per visual, for the
whole run of paragraphs that share it, so a diagram holds its size and its place across the cuts
inside that run instead of growing, shrinking and jumping with every paragraph. The look is
docs/course.html's dark theme: the same tokens, the same four fonts, the same terminal/figure/table
rules, so a frame of the video and the lesson page read as one thing. Text is fitted, never clipped:
the paragraph shrinks from 34px to a 20px floor until it fits, and the script fails loudly if it still
does not; a figure is zoomed to its box, a terminal or code block scaled to it (up to a quarter
larger than on the lesson page, never more), a table only ever shrunk.

Deterministic: the same inputs give byte-identical PNGs, and a slide whose bytes did not change is
left alone (mtime included), so render-video.sh's "mp4 newer than its slides" check keeps working
after a run that changed nothing. An episode is skipped outright when nothing its slides depend on
has changed — its text and visuals in course.json, its paragraph order in timeline.json, this script
— judged by a content hash kept in video/slides/<slug>/manifest.json rather than by mtime: the
narration render rewrites timeline.json every time an episode finishes, and that must not send the
other thirteen episodes back through the renderer.

Needs playwright with its chromium (`pip install playwright && playwright install chromium`),
nothing else beyond the stdlib. The fonts come from Google Fonts, so a run that has anything to render
needs the network: without the fonts the script stops rather than write system-font slides, which the
next run would take for finished ones.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

from playwright.sync_api import sync_playwright

REPO = pathlib.Path(__file__).resolve().parent.parent
COURSE_NAME = "Who is calling this server?"
WIDTH, HEIGHT = 1920, 1080

# The page every slide is drawn on. Tokens, fonts and the figure/terminal/table rules are
# docs/course.html's dark theme, sized for a 1920px canvas instead of a 16px page. The SVG
# figures reference the arrowhead markers only the first figure of course.html defines, so the
# template defines them once, up front.
TEMPLATE = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Serif:ital,wght@0,400;0,500;1,400&display=swap">
<style>
:root{{
  --ground:#0E1116; --surface:#161A21; --sunk:#1D222A;
  --ink:#E3E8EE; --ink-2:#B4BDC9; --muted:#87919E;
  --rule:#272E38; --rule-2:#3A434F;
  --brass:#D9AC53; --brass-2:#C0913A; --ox:#E28277;
  --term-bg:#12161C; --term-fg:#CFD7E1; --term-dim:#7E8B9B; --term-rule:#242C36;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  --serif:"IBM Plex Serif",Georgia,"Times New Roman",serif;
  --display:Archivo,"IBM Plex Sans",-apple-system,"Segoe UI",sans-serif;
}}
*{{box-sizing:border-box}}
[hidden]{{display:none!important}}
html,body{{margin:0;width:{WIDTH}px;height:{HEIGHT}px;overflow:hidden;background:var(--ground)}}
body{{
  color:var(--ink);font-family:"IBM Plex Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  font-size:24px;line-height:1.62;-webkit-font-smoothing:antialiased;
}}
h1,p,figure,pre{{margin:0}}
a{{color:var(--ink);text-decoration-color:var(--brass);text-underline-offset:3px;text-decoration-thickness:1.5px}}
code{{font-family:var(--mono);font-size:.86em}}
:not(pre) > code{{background:var(--sunk);padding:.1em .34em;border-radius:3px;color:var(--ink-2)}}
/* A header name in running text stays on one line rather than splitting at its hyphen into two
   chips; a table cell keeps wrapping, or its column would be as wide as its longest chip. */
.prose code,figcaption code{{white-space:nowrap}}
strong{{font-weight:600}}

.slide{{position:absolute;inset:0;display:flex;flex-direction:column}}
.strip{{
  flex:none;height:112px;padding:0 208px 0 96px;display:flex;align-items:center;justify-content:space-between;
  gap:48px;border-bottom:1px solid var(--rule);background:var(--surface);
}}
.eyebrow{{
  font-family:var(--mono);font-size:22px;font-weight:500;text-transform:uppercase;letter-spacing:.15em;
  color:var(--muted);white-space:nowrap;
}}
.eyebrow b{{color:var(--brass);font-weight:500}}

/* ── title card ─────────────────────────────────────────────────────────── */
.hero{{flex:1;min-height:0;display:flex;flex-direction:column;justify-content:center;gap:44px;padding:48px 400px 120px 96px;overflow:hidden}}
.ep-n{{
  font-family:var(--display);font-weight:800;font-size:176px;line-height:.85;letter-spacing:-.04em;
  color:var(--brass);font-variant-numeric:tabular-nums;
}}
h1{{
  font-family:var(--display);font-weight:800;font-size:104px;line-height:1.06;letter-spacing:-.032em;
  max-width:16ch;text-wrap:balance;
}}
.kick{{font-family:var(--serif);font-size:38px;line-height:1.5;color:var(--ink-2);max-width:48ch;text-wrap:pretty}}

/* ── paragraph slide ────────────────────────────────────────────────────── */
.body{{flex:1;min-height:0;display:grid;grid-template-columns:44fr 56fr;gap:96px;padding:64px 96px}}
/* Wide visuals: the text becomes a band on top (its height set per run by the script) and the
   visual takes the full width below. The band's measure is capped in ch so that a paragraph that
   had to shrink still wraps at a readable length rather than spanning the whole frame. */
.body.stacked{{grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr);gap:40px}}
.body.stacked .prose{{max-width:min(90ch,1240px)}}
.body.stacked figcaption{{max-width:84ch}}
.col{{min-height:0;min-width:0;position:relative;overflow:hidden}}
.beat{{
  font-family:var(--mono);font-size:22px;font-weight:500;text-transform:uppercase;letter-spacing:.11em;
  color:var(--brass);margin-bottom:30px;
}}
.prose{{font-family:var(--serif);font-size:34px;line-height:1.5;color:var(--ink);text-wrap:pretty;overflow-wrap:break-word}}
.prose em{{color:var(--brass-2);font-style:italic}}
.numeral{{
  position:absolute;right:0;bottom:-.06em;font-family:var(--display);font-weight:800;font-size:560px;line-height:.85;
  letter-spacing:-.04em;color:var(--brass);opacity:.13;font-variant-numeric:tabular-nums;
}}
.visual{{position:absolute;top:0;left:0;width:100%;transform-origin:top left}}
.progress{{flex:none;height:6px;background:var(--rule)}}
.bar{{width:0;height:100%;background:var(--brass)}}

/* ── the lesson visuals: course.html's rules, at slide scale ────────────── */
figure{{display:flex;flex-direction:column;gap:22px}}
.figbox{{background:var(--surface);border:1px solid var(--rule);border-radius:3px;padding:36px 36px 28px;overflow:hidden}}
/* A label drawn to the edge of its viewBox may run a few units past it with true advances (see
   `svg text` below), so the SVG may spill into the box's padding; the box, not the viewBox, clips. */
figure svg{{display:block;width:100%;height:auto;color:var(--ink-2);overflow:visible}}
figcaption{{font-size:24px;line-height:1.5;color:var(--muted);max-width:62ch}}
figcaption b{{color:var(--ink-2);font-weight:500}}
svg .bx{{fill:none;stroke:currentColor;stroke-width:1.25}}
svg .bx-fill{{fill:var(--sunk);stroke:var(--rule-2);stroke-width:1.25}}
svg .bx-acc{{fill:none;stroke:var(--brass);stroke-width:1.6;stroke-dasharray:5 3}}
svg .ln{{stroke:currentColor;stroke-width:1.25;fill:none}}
svg .ln-acc{{stroke:var(--brass);stroke-width:1.6;fill:none}}
svg .ln-bad{{stroke:var(--ox);stroke-width:1.5;fill:none;stroke-dasharray:5 3}}
svg .ln-dim{{stroke:var(--rule-2);stroke-width:1.1;fill:none;stroke-dasharray:3 4}}
svg .t{{fill:currentColor;font-family:var(--mono);font-size:12px}}
svg .t-lbl{{fill:var(--muted);font-family:var(--mono);font-size:11px}}
svg .t-acc{{fill:var(--brass);font-family:var(--mono);font-size:11.5px}}
svg .t-bad{{fill:var(--ox);font-family:var(--mono);font-size:11.5px}}
svg .t-hd{{fill:currentColor;font-family:var(--display);font-size:12.5px;font-weight:700;letter-spacing:.06em}}
/* Lay SVG text out with the font's true advances. At this scale Chromium otherwise snaps every glyph
   of an 11.5px mono label to whole device pixels — up to 9% wide — and a label that fits on the lesson
   page runs past its viewBox and is clipped. */
svg text{{text-rendering:geometricPrecision}}
svg .fill-acc{{fill:var(--brass)}}
svg .fill-bad{{fill:var(--ox)}}
svg .fill-cur{{fill:currentColor}}
svg .fill-soft{{fill:var(--sunk)}}

.term,.code{{
  display:inline-block;vertical-align:top;min-width:100%;white-space:pre;
  background:var(--term-bg);color:var(--term-fg);border:1px solid var(--term-rule);
  border-radius:3px;padding:28px 32px;font-family:var(--mono);font-size:27px;line-height:1.72;
}}
.code{{font-size:26px;line-height:1.68}}
.term .c{{color:var(--term-dim)}}
.term .p{{color:#B99A56}}
.term .o{{color:#7FA8B8}}
.term .bad{{color:#D98077}}
.code .k{{color:#C58FB0}}
.code .s{{color:#8FB88F}}
.code .c{{color:var(--term-dim);font-style:italic}}
.code .f{{color:#7FA8B8}}

.tablewrap{{border:1px solid var(--rule);border-radius:3px;background:var(--surface)}}
table{{border-collapse:collapse;width:100%;font-size:26px;line-height:1.5}}
th,td{{text-align:left;padding:16px 22px;border-bottom:1px solid var(--rule);vertical-align:top}}
/* Header cells may wrap: a nowrap "TYPESCRIPT SDK" over a column of three-digit codes would take the
   width the prose column needs. */
thead th{{
  font-family:var(--mono);font-size:21px;text-transform:uppercase;letter-spacing:.09em;
  color:var(--muted);font-weight:500;background:var(--sunk);
}}
tbody tr:last-child td{{border-bottom:0}}
td.n{{font-family:var(--mono);color:var(--brass);font-variant-numeric:tabular-nums}}
td.m{{font-family:var(--mono);font-size:24px;color:var(--ink-2);white-space:nowrap}}
td a{{font-weight:500}}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <defs>
    <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" class="fill-cur"/>
    </marker>
    <marker id="ah-a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" class="fill-acc"/>
    </marker>
  </defs>
</svg>

<div class="slide" id="title">
  <header class="strip"><span class="eyebrow" id="t-eyebrow"></span><span class="eyebrow">{COURSE_NAME}</span></header>
  <div class="hero" id="hero">
    <div class="ep-n" id="t-n"></div>
    <h1 id="t-title"></h1>
    <p class="kick" id="t-kicker"></p>
  </div>
</div>

<div class="slide" id="para" hidden>
  <header class="strip"><span class="eyebrow" id="p-eyebrow"></span><span class="eyebrow">{COURSE_NAME}</span></header>
  <div class="body" id="p-body">
    <div class="col" id="text-col"><div class="beat" id="p-beat"></div><p class="prose" id="p-text"></p></div>
    <div class="col" id="visual-col"><div class="numeral" id="p-numeral"></div><div class="visual" id="p-visual"></div></div>
  </div>
  <div class="progress"><div class="bar" id="p-bar"></div></div>
</div>

<script>
(function () {{
  'use strict';
  var $ = function (id) {{ return document.getElementById(id); }};

  /* One representative face per family and style the slides use. document.fonts.load() both
     starts the download and tells us whether a face exists at all — check() alone would say
     "yes" for a family that never loaded, because it has nothing to wait for. */
  var FACES = [
    '800 100px Archivo', '400 34px "IBM Plex Serif"', 'italic 400 34px "IBM Plex Serif"',
    '400 24px "IBM Plex Mono"', '500 22px "IBM Plex Mono"', '400 24px "IBM Plex Sans"'
  ];

  var TEXT_MAX = 34, TEXT_FLOOR = 20;   /* the paragraph's size range, px */
  var PRE_CAP = 1.25;                   /* a terminal or code block may grow this much: 27px mono → the 34px of the prose */
  var FIGURE_CAP = 2.4;
  var CLEARLY = 1.2;                    /* the stacked layout must show the visual this much larger to win */
  var BANDS = [480, 420, 360, 300, 240];        /* candidate heights of the stacked layout's text band, px */
  var BAND_FLOORS = [26, 24, 22, TEXT_FLOOR];   /* how small the band may make the text, tried in this order */

  /* Shrink el's font-size, 1px at a time, until its column no longer overflows. Returns the size
     that fits, or 0 when even the floor does not. */
  function fit(el, col, max, min) {{
    for (var size = max; size >= min; size--) {{
      el.style.fontSize = size + 'px';
      if (col.scrollHeight <= col.clientHeight && col.scrollWidth <= col.clientWidth) return size;
    }}
    return 0;
  }}

  function eyebrow(el, lead, rest) {{
    el.textContent = '';
    var b = document.createElement('b');
    b.textContent = lead;
    el.appendChild(b);
    el.appendChild(document.createTextNode(' · ' + rest));
  }}

  function setText(e) {{
    $('p-beat').textContent = e.beat || '';
    $('p-beat').hidden = !e.beat;
    $('p-text').innerHTML = e.html;
  }}

  /* 'side': the paragraph left, the visual right. 'stacked': the paragraph in a band of `band` px
     on top, the visual full-width below it. */
  function layout(name, band) {{
    $('p-body').classList.toggle('stacked', name === 'stacked');
    $('text-col').style.height = name === 'stacked' ? band + 'px' : '';
  }}

  /* Fit the visual to its column and say how large it got, relative to the lesson page. A figure is
     vector: it is laid out at its viewBox width and the diagram box zoomed — zoom, not transform, so
     the caption below keeps its own size and its place. A terminal or code block is scaled to the
     column's width and height, up to PRE_CAP: 27px mono at 1 is fine on the lesson page but small on
     a 1920px frame, and the code on a slide should read like its prose. A table lays out to the width
     it gets, so it is only ever shrunk to the column's height. */
  function fitVisual() {{
    var visual = $('p-visual'), box = $('visual-col');
    var figbox = visual.querySelector('.figbox'), svg = figbox && figbox.querySelector('svg');
    visual.style.transform = '';
    visual.style.width = '';
    var k;
    if (svg) {{
      var vb = svg.viewBox.baseVal;
      /* Under CSS zoom a block still fills its parent — in its own, zoomed units — so a
         width:auto box would only shrink its contents. Size the diagram in viewBox units,
         let the box wrap it exactly, and give it the whole column to grow into. */
      visual.style.width = box.clientWidth + 'px';
      svg.style.width = vb.width + 'px';
      figbox.style.width = 'max-content';
      figbox.style.zoom = 1;
      var caption = visual.querySelector('figcaption');
      var room = box.clientHeight - (caption ? caption.offsetHeight + 22 : 0);
      k = Math.min(FIGURE_CAP, box.clientWidth / figbox.offsetWidth, room / figbox.offsetHeight);
      figbox.style.zoom = k;
    }} else if (visual.querySelector('pre')) {{
      visual.style.width = 'max-content';   /* the block's own width: its longest line */
      k = Math.min(PRE_CAP, box.clientWidth / visual.scrollWidth, box.clientHeight / visual.scrollHeight);
      visual.style.width = (box.clientWidth / k) + 'px';   /* scaled, it spans the column exactly */
      visual.style.transform = 'scale(' + k + ')';
    }} else {{
      k = Math.min(1, box.clientWidth / visual.scrollWidth, box.clientHeight / visual.scrollHeight);
      visual.style.transform = 'scale(' + k + ')';
    }}
    return k;
  }}

  window.slides = {{
    ready: function () {{
      return Promise.all(FACES.map(function (f) {{
        return document.fonts.load(f).then(function (faces) {{ return faces.length ? null : f; }}, function () {{ return f; }});
      }})).then(function (missing) {{
        return document.fonts.ready.then(function () {{ return missing.filter(Boolean); }});
      }});
    }},

    title: function (ep) {{
      $('para').hidden = true;
      $('title').hidden = false;
      eyebrow($('t-eyebrow'), 'Track ' + ep.track, ep.eyebrow);
      $('t-n').textContent = ep.label;
      $('t-title').textContent = ep.title;
      $('t-kicker').textContent = ep.kicker;
      return fit($('t-title'), $('hero'), 104, 56);
    }},

    /* Decide the layout for a run of slides that share one visual — {{ visual: html|null, entries:
       [{{ beat, html }}, …] }} — and put the visual on the page. Returns {{ layout, band, scale }}: what
       entry() needs, the same for every slide of the run, so the visual holds its size and its place
       across the cuts inside the run.

       The side layout is the default. The stacked one wins when it shows the visual clearly larger
       with every paragraph of the run in the band on top: the band is the smallest of BANDS that
       holds each paragraph at a comfortable size, and the text is let down towards the floor only
       when the visual cannot be won any other way. A short paragraph is not shrunk by that — it is
       fitted on its own slide, in the same band — and the visual's scale is measured with the band
       at its final height, which is what makes it constant over the run. */
    plan: function (run) {{
      $('title').hidden = true;
      $('para').hidden = false;
      var visual = $('p-visual');
      visual.innerHTML = run.visual || '';
      visual.hidden = !run.visual;
      $('p-numeral').hidden = !!run.visual;
      layout('side');
      var side = {{ layout: 'side', band: 0, scale: run.visual ? fitVisual() : 1 }};
      if (!run.visual) return side;

      /* What the band must hold, per paragraph and size. */
      layout('stacked', 0);
      $('text-col').style.height = 'auto';
      var text = $('p-text'), col = $('text-col');
      var needs = run.entries.map(function (e) {{
        setText(e);
        var need = {{}};
        for (var s = TEXT_MAX; s >= TEXT_FLOOR; s--) {{
          text.style.fontSize = s + 'px';
          need[s] = col.scrollWidth <= col.clientWidth ? col.scrollHeight : Infinity;
        }}
        return need;
      }});
      var scales = {{}};
      function stacked(band) {{
        if (!(band in scales)) {{
          layout('stacked', band);
          scales[band] = fitVisual();
        }}
        return scales[band];
      }}
      for (var f = 0; f < BAND_FLOORS.length; f++) {{
        var best = null;
        for (var b = 0; b < BANDS.length; b++) {{
          var band = 0;
          for (var i = 0; i < needs.length && band >= 0; i++) {{
            var s = TEXT_MAX;
            while (s >= BAND_FLOORS[f] && needs[i][s] > BANDS[b]) s--;
            band = s < BAND_FLOORS[f] ? -1 : Math.max(band, needs[i][s]);
          }}
          if (band < 0) continue;
          var k = stacked(band);
          if (!best || k > best.scale) best = {{ layout: 'stacked', band: band, scale: k }};
        }}
        if (best && best.scale >= side.scale * CLEARLY) {{
          layout(best.layout, best.band);
          return best;
        }}
      }}
      layout('side');
      side.scale = fitVisual();
      return side;
    }},

    /* One slide of a planned run: e carries the header, the paragraph, the progress and the run's
       plan. Returns the paragraph's size (0: does not fit) and the visual's scale, which entry()
       measures again — the caller checks it is the run's. */
    entry: function (e) {{
      eyebrow($('p-eyebrow'), e.eyebrow, e.title);
      setText(e);
      $('p-bar').style.width = (e.progress * 100) + '%';
      $('p-numeral').textContent = e.numeral;
      layout(e.plan.layout, e.plan.band);
      var size = fit($('p-text'), $('text-col'), TEXT_MAX, TEXT_FLOOR);
      var scale = $('p-visual').hidden ? 1 : fitVisual();
      return {{ size: size, scale: scale }};
    }}
  }};
}})();
</script>
</body>
</html>
"""


def display_title(title: str) -> str:
    """'04 — Keycloak issues, …' → 'Keycloak issues, …': the numeral shows the label already."""
    prefix, sep, rest = title.partition(" — ")
    return rest if sep and prefix.isdigit() else title


def episode_eyebrow(ep: dict) -> str:
    """'EPISODE 04' for the numbered episodes; the prelude and finale go by name, as on the page."""
    if ep["label"].isdigit():
        return f"Episode {ep['label']}"
    return ep.get("section") or f"Track {ep['track']}"


def slide_files(out: pathlib.Path, timeline: dict) -> list[pathlib.Path]:
    folder = out / timeline["slug"]
    return [folder / "title.png"] + [folder / f"p{e['index']:04d}.png" for e in timeline["entries"]]


def slides_hash(ep: dict, timeline: dict, script: str) -> str:
    """Everything an episode's slides are a function of: its course.json entry, which paragraphs the
    narration cut it into (not their timing — a re-take with the same text needs no new slides), and
    this script, template included."""
    cues = [[e["index"], e["segment"], e["paragraph"], e["beat"]] for e in timeline["entries"]]
    return hashlib.sha256(json.dumps([ep, cues, script], sort_keys=True).encode()).hexdigest()[:16]


def is_png(path: pathlib.Path) -> bool:
    """A whole PNG — signature in front, IEND chunk at the back — so an empty or truncated slide
    (a full disk, a botched copy) does not pass as rendered."""
    try:
        with path.open("rb") as f:
            head = f.read(8)
            f.seek(-8, 2)
            return head == b"\x89PNG\r\n\x1a\n" and f.read() == b"IEND\xaeB`\x82"
    except (OSError, ValueError):
        return False


def up_to_date(manifest: pathlib.Path, digest: str, files: list[pathlib.Path]) -> bool:
    if not manifest.exists():
        return False
    try:
        previous = json.loads(manifest.read_text())
    except json.JSONDecodeError:
        return False
    return previous.get("hash") == digest and all(is_png(f) for f in files)


def write_if_changed(path: pathlib.Path, data: bytes) -> bool:
    """Leave an unchanged file (and its mtime) alone, so downstream mtime checks stay meaningful."""
    if path.exists() and path.read_bytes() == data:
        return False
    tmp = path.with_name(path.name + ".part")
    tmp.write_bytes(data)
    tmp.replace(path)
    return True


def render_episode(page, ep: dict, timeline: dict, files: list[pathlib.Path]) -> int:
    """All slides of one episode on one page load. Returns how many files actually changed."""
    slug = ep["slug"]
    paragraphs = [(seg["beat"], p) for seg in ep["segments"] for p in seg["paragraphs"]]
    entries = timeline["entries"]
    if len(entries) != len(paragraphs):
        raise SystemExit(f"{slug}: timeline has {len(entries)} entries but course.json has {len(paragraphs)} paragraphs — rerun render-course.py --only {slug}")

    page.set_content(TEMPLATE)
    missing = page.evaluate("() => slides.ready()")
    if missing:
        raise SystemExit(f"{slug}: fonts unavailable ({', '.join(missing)}) — not rendering with the fallback stacks; check the network and rerun")

    files[0].parent.mkdir(parents=True, exist_ok=True)
    changed = 0
    eyebrow = episode_eyebrow(ep)
    title = display_title(ep["title"])
    size = page.evaluate("ep => slides.title(ep)", {"track": ep["track"], "label": ep["label"], "eyebrow": eyebrow, "title": title, "kicker": ep["kicker"]})
    if not size:
        raise SystemExit(f"{slug}: the title does not fit the title card even at 56px")
    changed += write_if_changed(files[0], page.screenshot(type="png"))

    visuals = ep["visuals"]
    numeral = ep["label"] if ep["label"].isdigit() else ep["track"]
    # The paragraphs that share a visual are consecutive: entry k (0-based) shows visuals[k * len / n].
    runs: list[list[tuple[dict, pathlib.Path]]] = []
    for entry, path in zip(entries, files[1:]):
        which = (entry["index"] - 1) * len(visuals) // len(entries) if visuals else 0
        if not runs or which != runs[-1][0]:
            runs.append((which, []))
        runs[-1][1].append((entry, path))
    for which, run in runs:
        plan = page.evaluate("r => slides.plan(r)", {
            "visual": visuals[which]["html"] if visuals else None,
            "entries": [{"beat": paragraphs[e["index"] - 1][0], "html": paragraphs[e["index"] - 1][1]["display_html"]} for e, _ in run],
        })
        for entry, path in run:
            beat, paragraph = paragraphs[entry["index"] - 1]
            result = page.evaluate("e => slides.entry(e)", {
                "eyebrow": eyebrow,
                "title": title,
                "beat": beat,
                "html": paragraph["display_html"],
                "numeral": numeral,
                "progress": entry["index"] / len(entries),
                "plan": plan,
            })
            if not result["size"]:
                raise SystemExit(f"{slug} p{entry['index']:04d}: the paragraph does not fit even at 20px")
            if abs(result["scale"] - plan["scale"]) > 1e-6:  # the plan's promise: one scale per run
                raise SystemExit(f"{slug} p{entry['index']:04d}: visual scale {result['scale']:.3f} differs from the run's {plan['scale']:.3f}")
            changed += write_if_changed(path, page.screenshot(type="png"))
    for stale in files[0].parent.glob("p[0-9]*.png"):  # a paragraph the episode no longer has
        if stale not in files:
            stale.unlink()
            changed += 1
    return changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--course", default=str(REPO / "audio" / "course.json"))
    ap.add_argument("--timeline", default=str(REPO / "audio" / "timeline.json"))
    ap.add_argument("--out", default=str(REPO / "video" / "slides"))
    ap.add_argument("--only", metavar="SLUG", help="render one episode")
    args = ap.parse_args()

    course_path, timeline_path, out = pathlib.Path(args.course), pathlib.Path(args.timeline), pathlib.Path(args.out)
    for path, producer in ((course_path, "course-audio.py --json"), (timeline_path, "render-course.py")):
        if not path.is_file():
            print(f"{path} does not exist — run {producer} first", file=sys.stderr)
            return 1
    course = {ep["slug"]: ep for ep in json.loads(course_path.read_text())}
    timelines = [t for t in json.loads(timeline_path.read_text()) if not args.only or t["slug"] == args.only]
    if not timelines:
        what = f"{args.only} is not in {timeline_path}" if args.only else f"{timeline_path} lists no episode"
        print(f"nothing to render: {what} — run render-course.py first", file=sys.stderr)
        return 1
    script = pathlib.Path(__file__).read_text()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=1)
        for timeline in timelines:
            slug = timeline["slug"]
            if slug not in course:
                raise SystemExit(f"{slug} is in the timeline but not in {course_path} — rerun course-audio.py --json")
            files = slide_files(out, timeline)
            manifest = out / slug / "manifest.json"
            digest = slides_hash(course[slug], timeline, script)
            if up_to_date(manifest, digest, files):
                print(f"    {slug:<52} {len(files):3d} slides — up to date")
                continue
            changed = render_episode(page, course[slug], timeline, files)
            write_if_changed(manifest, (json.dumps({"hash": digest, "slides": [f.name for f in files]}, indent=1) + "\n").encode())
            print(f"    {slug:<52} {len(files):3d} slides" + ("" if changed else " — unchanged"))
        browser.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:  # the interrupted episode has no manifest yet, so the next run redoes it
        raise SystemExit(130) from None

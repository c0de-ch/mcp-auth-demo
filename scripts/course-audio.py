#!/usr/bin/env python3
"""Extract the read-aloud scripts from docs/course.md as plain text for a TTS engine.

Stdlib only, so it runs anywhere Python does — `scripts/render-audio.sh` calls it before
handing the text to piper, but it is useful on its own:

    python3 scripts/course-audio.py --out audio/text     # 14 .txt files + manifest.json

What it does to the Markdown, in order:

  * takes the body of each <details> block, dropping the <summary> line
  * drops the "**Beat — …**" stage directions; they are structure for a reader, not speech
  * unwraps *emphasis*, **strong** and `code`
  * rewrites identifiers a speech engine mangles (see SPOKEN below) — this table is meant to
    be edited: listen once, add what grates
  * rejoins the hard-wrapped lines into paragraphs, so the engine breaks on sentences rather
    than on the 100-column margin
"""

from __future__ import annotations

import argparse
import html as htmllib
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
COURSE = REPO / "docs" / "course.md"
COURSE_HTML = REPO / "docs" / "course.html"

# Longest first: 'mcp:tools' must win before 'MCP'. Keys are matched whole-word where the
# key is word-shaped, so 'aud' never fires inside 'audience'.
SPOKEN: list[tuple[str, str]] = [
    ("mcp:tools", "M C P tools"),
    ("mcp:admin", "M C P admin"),
    ("mcp-admin", "M C P admin"),
    ("mcp-user", "M C P user"),
    ("mcp-server", "M C P server"),
    ("mcp-service", "M C P service"),
    ("mcp-internal", "M C P internal"),
    ("downstream-api", "downstream A P I"),
    ("WWW-Authenticate", "W W W Authenticate"),
    ("X-Forwarded-User", "X forwarded user"),
    ("X-Forwarded", "X forwarded"),
    ("resource_metadata", "resource metadata"),
    ("private_key_jwt", "private key J W T"),
    ("client_secret_basic", "client secret basic"),
    ("unauthorized_client", "unauthorized client"),
    ("invalid_client", "invalid client"),
    ("invalid_grant", "invalid grant"),
    ("admin_only", "admin only"),
    ("service_only", "service only"),
    ("auth_request", "auth request"),
    ("ext_authz", "ext auth Z"),
    ("forwardAuth", "forward auth"),
    ("PUBLIC_HOST", "PUBLIC HOST"),
    ("RS256", "R S 256"),
    ("HS256", "H S 256"),
    ("JWKS", "J W K S"),
    ("JWT", "J W T"),
    ("PKCE", "P K C E"),
    ("MCP", "M C P"),
    ("azp", "A Z P"),
    ("iss", "I S S"),
    ("aud", "A U D"),
    ("sub", "sub"),
]

BEAT = re.compile(r"^\*\*Beat\s+.*\*\*$")
SUMMARY = re.compile(r"^<summary>.*</summary>$", re.S)


def slugify(title: str) -> str:
    t = title.lower()
    t = re.sub(r"^\d+\s*—\s*", "", t)          # drop the episode number, the track has one
    t = t.replace("*", "").replace("`", "")
    t = re.sub(r"[^\w\s-]", "", t)
    return re.sub(r"[\s_]+", "-", t.strip())[:60].strip("-")


def spoken(text: str) -> str:
    for src, dst in SPOKEN:
        flags = 0 if src.lower() != src else re.IGNORECASE
        pattern = re.escape(src)
        if re.match(r"^\w", src) and re.search(r"\w$", src):
            pattern = rf"\b{pattern}\b"
        text = re.sub(pattern, dst, text, flags=flags)
    return text


def to_speech(md: str) -> str:
    """One <details> body → paragraphs of plain prose."""
    paragraphs: list[str] = []
    for chunk in re.split(r"\n\s*\n", md.strip()):
        chunk = chunk.strip()
        if not chunk or SUMMARY.match(chunk) or BEAT.match(chunk):
            continue
        chunk = " ".join(line.strip() for line in chunk.splitlines())
        chunk = re.sub(r"\*\*(.+?)\*\*", r"\1", chunk)
        chunk = re.sub(r"\*(.+?)\*", r"\1", chunk)
        chunk = re.sub(r"`(.+?)`", r"\1", chunk)
        chunk = spoken(chunk)
        chunk = chunk.replace(" — ", ", ").replace("—", ", ")
        chunk = re.sub(r"\s+", " ", chunk).strip()
        if chunk:
            paragraphs.append(chunk)
    return "\n\n".join(paragraphs) + "\n"


def inline_html(md: str) -> str:
    """Markdown inline marks → HTML, for showing a paragraph on screen."""
    text = htmllib.escape(md, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def segments_of(md: str) -> list[dict]:
    """One <details> body → [{beat, paragraphs:[{display_html, spoken}]}], beats as boundaries."""
    out: list[dict] = [{"beat": None, "paragraphs": []}]
    for chunk in re.split(r"\n\s*\n", md.strip()):
        chunk = chunk.strip()
        if not chunk or SUMMARY.match(chunk):
            continue
        if BEAT.match(chunk):
            beat = re.sub(r"^\*\*Beat\s*[—-]\s*|\*\*$", "", chunk).strip()
            if out[-1]["paragraphs"]:
                out.append({"beat": beat, "paragraphs": []})
            else:
                out[-1]["beat"] = beat
            continue
        joined = " ".join(line.strip() for line in chunk.splitlines())
        out[-1]["paragraphs"].append({"display_html": inline_html(joined), "spoken": to_speech(chunk).strip()})
    return [seg for seg in out if seg["paragraphs"]]


VISUAL = re.compile(
    r"<figure>.*?</figure>|<pre class=\"(?:term|code)\">.*?</pre>|<div class=\"tablewrap\">.*?</table>\s*</div>",
    re.S,
)


def visuals_of_html(course_html: str) -> list[dict]:
    """Per script-bearing <section> of course.html (in order): label, kicker and the lesson's figures/code."""
    out: list[dict] = []
    for sec in re.finditer(r'<section id="([\w-]+)"[^>]*>(.*?)</section>', course_html, re.S):
        body = sec.group(2)
        if 'class="script"' not in body:
            continue
        lesson = body.split('<div class="script">', 1)[0]
        label = re.search(r'<div class="ep-n">(.*?)</div>', lesson, re.S)
        kicker = re.search(r'<p class="ep-sub">(.*?)</p>', lesson, re.S)
        visuals = []
        for m in VISUAL.finditer(lesson):
            block = m.group(0)
            kind = "figure" if block.startswith("<figure") else "table" if block.startswith("<div") else ("term" if 'class="term"' in block[:20] else "code")
            visuals.append({"kind": kind, "html": block})
        out.append({
            "id": sec.group(1),
            "label": htmllib.unescape(re.sub(r"<[^>]+>", "", label.group(1))).strip() if label else "",
            "kicker": " ".join(htmllib.unescape(re.sub(r"<[^>]+>", "", kicker.group(1))).split()) if kicker else "",
            "visuals": visuals,
        })
    return out


def structured(course: str, course_html: str) -> list[dict]:
    """course.md's scripts zipped with course.html's visuals, by course order."""
    flat = episodes(course)
    bodies = re.findall(r"<details>(.*?)</details>", course, re.S)
    pages = visuals_of_html(course_html)
    if not (len(flat) == len(bodies) == len(pages)):
        raise SystemExit(f"course.md has {len(flat)} scripts but course.html has {len(pages)} script-bearing sections")
    out = []
    for ep, body, page in zip(flat, bodies, pages):
        out.append({
            "track": ep["track"],
            "slug": ep["slug"],
            "title": ep["title"],
            "label": page["label"],
            "kicker": page["kicker"],
            "section": page["id"],
            "visuals": page["visuals"],
            "segments": segments_of(body),
        })
    return out


def episodes(course: str) -> list[dict]:
    """Pair every <details> script with the '## ' heading above it, in document order."""
    out: list[dict] = []
    heading = None
    for match in re.finditer(r"^## ([^\n]+)$|<details>(.*?)</details>", course, re.S | re.M):
        if match.group(1) is not None:
            heading = match.group(1).strip()
            continue
        if heading is None:
            continue
        body = to_speech(match.group(2))
        out.append(
            {
                "track": f"{len(out):02d}",
                "title": heading.replace("*", ""),
                "slug": f"{len(out):02d}-{slugify(heading)}",
                "words": len(body.split()),
                "text": body,
            }
        )
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="audio/text", help="directory for the .txt files (default: audio/text)")
    ap.add_argument("--course", default=str(COURSE), help="path to course.md")
    ap.add_argument("--json", action="store_true", help="also write <out>/../course.json: segments, paragraphs and the lesson's visuals, for the video pipeline")
    args = ap.parse_args()

    course = pathlib.Path(args.course).read_text()
    found = episodes(course)
    if not found:
        print("no <details> script blocks found — has course.md changed shape?", file=sys.stderr)
        return 1

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for ep in found:
        path = out / f"{ep['slug']}.txt"
        # Leave the mtime alone when nothing changed: render-audio.sh skips a track whose
        # WAV is newer than its text, and an unconditional write would defeat that.
        if not path.exists() or path.read_text() != ep["text"]:
            path.write_text(ep["text"])

    manifest = [{k: v for k, v in ep.items() if k != "text"} for ep in found]
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    if args.json:
        data = structured(course, COURSE_HTML.read_text())
        target = out.parent / "course.json"
        text = json.dumps(data, indent=1) + "\n"
        if not target.exists() or target.read_text() != text:  # mtime again: render-slides.py keys off it
            target.write_text(text)
        paragraphs = sum(len(seg["paragraphs"]) for ep in data for seg in ep["segments"])
        visuals = sum(len(ep["visuals"]) for ep in data)
        print(f"{len(data)} episodes → {target}  ({paragraphs} paragraphs, {visuals} visuals)")

    total = sum(ep["words"] for ep in found)
    print(f"{len(found)} scripts → {out}  ({total:,} words, ~{round(total / 150)} min at 150 wpm)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

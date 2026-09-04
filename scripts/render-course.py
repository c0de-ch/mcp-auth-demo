#!/usr/bin/env python3
"""Render the course narration paragraph by paragraph, and write the timeline the video is cut to.

Runs inside the piper venv that scripts/render-audio.sh creates:

    .audio/venv/bin/python scripts/render-course.py [--only SLUG]

Reads audio/course.json (from `scripts/course-audio.py --json`). For every episode it synthesises
each paragraph separately — the voice model is loaded once, not once per file — and writes

    audio/parts/<slug>/pNNNN.wav     one file per paragraph, no trailing gap
    audio/<slug>.wav                 the episode: paragraphs joined with a short gap
    audio/timeline.json              where every paragraph starts and how long it lasts

Because the episode file is assembled from the parts, the timeline is exact by construction: the
slide for paragraph k can be shown for exactly the samples paragraph k occupies. Episodes whose
spoken text has not changed since the last run are skipped (content hash, not mtime).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import wave

from piper import PiperVoice, SynthesisConfig

REPO = pathlib.Path(__file__).resolve().parent.parent
AUDIO = REPO / "audio"

VOICE = os.environ.get("VOICE", "en_US-ryan-high")
CACHE = pathlib.Path(os.environ.get("CACHE", REPO / ".audio"))
LENGTH_SCALE = float(os.environ.get("LENGTH_SCALE", "1.15"))
SENTENCE_SILENCE = float(os.environ.get("SENTENCE_SILENCE", "0.45"))
PARAGRAPH_GAP = float(os.environ.get("PARAGRAPH_GAP", "0.8"))
LEAD_IN = float(os.environ.get("LEAD_IN", "2.5"))  # the video's title card; the audio has none


def text_hash(episode: dict) -> str:
    spoken = "\n".join(p["spoken"] for seg in episode["segments"] for p in seg["paragraphs"])
    return hashlib.sha256(f"{VOICE}|{LENGTH_SCALE}|{SENTENCE_SILENCE}|{PARAGRAPH_GAP}|{spoken}".encode()).hexdigest()[:16]


def silence(seconds: float, rate: int) -> bytes:
    return b"\x00\x00" * int(rate * seconds)


def synth_paragraph(voice: PiperVoice, cfg: SynthesisConfig, text: str, path: pathlib.Path) -> tuple[float, int]:
    """One paragraph → one WAV. Sentences are joined with SENTENCE_SILENCE, like the piper CLI does."""
    chunks = list(voice.synthesize(text, cfg))
    rate = chunks[0].sample_rate
    pcm = bytearray()
    for i, chunk in enumerate(chunks):
        pcm += chunk.audio_int16_bytes
        if i < len(chunks) - 1:
            pcm += silence(SENTENCE_SILENCE, rate)
    path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(pcm))
    return len(pcm) / 2 / rate, rate


def render_episode(voice: PiperVoice, cfg: SynthesisConfig, ep: dict) -> dict:
    slug = ep["slug"]
    parts_dir = AUDIO / "parts" / slug
    entries = []
    pcm = bytearray()
    rate = None
    index = 0
    cursor = 0.0
    paragraphs = [(si, pi, seg["beat"], p) for si, seg in enumerate(ep["segments"]) for pi, p in enumerate(seg["paragraphs"])]
    for n, (si, pi, beat, p) in enumerate(paragraphs):
        index += 1
        part = parts_dir / f"p{index:04d}.wav"
        seconds, rate = synth_paragraph(voice, cfg, p["spoken"], part)
        gap = PARAGRAPH_GAP if n < len(paragraphs) - 1 else 0.0
        with wave.open(str(part), "rb") as w:
            pcm += w.readframes(w.getnframes())
        pcm += silence(gap, rate)
        entries.append({
            "index": index,
            "segment": si,
            "paragraph": pi,
            "beat": beat,
            "start": round(cursor, 3),
            "duration": round(seconds + gap, 3),
            "wav": str(part.relative_to(REPO)),
        })
        cursor += seconds + gap
        print(f"    {slug} p{index:04d} {seconds:6.1f}s", file=sys.stderr)

    episode_wav = AUDIO / f"{slug}.wav"
    tmp = episode_wav.with_suffix(".wav.part")
    with wave.open(str(tmp), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(pcm))
    tmp.replace(episode_wav)
    total = len(pcm) / 2 / rate
    return {
        "slug": slug,
        "track": ep["track"],
        "title": ep["title"],
        "label": ep["label"],
        "wav": str(episode_wav.relative_to(REPO)),
        "seconds": round(total, 3),
        "lead_in": LEAD_IN,
        "text_hash": text_hash(ep),
        "entries": entries,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--course", default=str(AUDIO / "course.json"))
    ap.add_argument("--only", metavar="SLUG", help="render one episode")
    args = ap.parse_args()

    course = json.loads(pathlib.Path(args.course).read_text())
    timeline_path = AUDIO / "timeline.json"
    previous = {}
    if timeline_path.exists():
        previous = {e["slug"]: e for e in json.loads(timeline_path.read_text())}

    model = CACHE / "voices" / f"{VOICE}.onnx"
    if not model.exists():
        print(f"voice model missing: {model} — run scripts/render-audio.sh once, it downloads it", file=sys.stderr)
        return 1
    voice = PiperVoice.load(model)
    cfg = SynthesisConfig(length_scale=LENGTH_SCALE)

    def save(entry: dict) -> list[dict]:
        """Merge one episode into timeline.json as it is on disk right now, atomically."""
        current = {}
        if timeline_path.exists():
            try:
                current = {e["slug"]: e for e in json.loads(timeline_path.read_text())}
            except json.JSONDecodeError:
                current = {}
        current[entry["slug"]] = entry
        merged = sorted(current.values(), key=lambda e: e["track"])
        tmp = timeline_path.with_suffix(".json.part")
        tmp.write_text(json.dumps(merged, indent=1) + "\n")
        tmp.replace(timeline_path)
        return merged

    timeline = list(previous.values())
    for ep in course:
        slug = ep["slug"]
        if args.only and slug != args.only:
            continue
        prev = previous.get(slug)
        wav = AUDIO / f"{slug}.wav"
        parts_ok = bool(prev) and all((REPO / e["wav"]).exists() for e in prev["entries"])
        if prev and prev.get("text_hash") == text_hash(ep) and wav.exists() and parts_ok:
            print(f"==> {slug} — up to date", file=sys.stderr)
            continue
        print(f"==> {slug}", file=sys.stderr)
        timeline = save(render_episode(voice, cfg, ep))

    total = sum(e["seconds"] for e in timeline)
    print(f"{len(timeline)} episodes in {timeline_path}  ({int(total // 60)}:{int(total % 60):02d} of narration)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

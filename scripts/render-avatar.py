#!/usr/bin/env python3
"""The presenter: a small animated face that speaks along with the narration.

Not a talking head — a mark in the course's own style: a brass circle on the dark ground, two eyes
that blink now and then, a mouth that opens with the loudness of the voice, and a ring that pulses
around it the way an active-speaker indicator does. It is driven by the audio itself, frame by
frame, so it never drifts from the words.

    python3 scripts/render-avatar.py audio/<slug>.wav --lead-in 2.5 --size 88 | ffmpeg … -f rawvideo -pix_fmt rgba -s 88x88 -r 24 -i pipe:0 …
    python3 scripts/render-avatar.py --still video/avatar.png --size 240        # the resting face, for the title card and the poster

Stdlib plus Pillow. Loudness is the RMS of each frame's samples, normalised so that the loud part
of this episode's speech opens the mouth fully; a fast attack and a slower decay keep it from
flickering. Blinks fall on a fixed pseudo-random schedule seeded from the file, so a re-render is
identical. Frames are drawn at 4x and downsampled, and every distinct pose is drawn once and cached,
so an hour of video costs a few seconds.
"""

from __future__ import annotations

import argparse
import array
import math
import random
import sys
import wave

from PIL import Image, ImageDraw

BRASS = (217, 172, 83)
SURFACE = (22, 26, 33)
GROUND = (14, 17, 22)

LEVELS = 8          # mouth and ring openness steps
SUPER = 4           # supersampling factor for antialiased circles


def draw_pose(size: int, mouth: int, ring: int, blink: bool) -> Image.Image:
    """One frame of the face. mouth/ring in 0..LEVELS-1."""
    S = size * SUPER
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    c = S / 2
    r = S * 0.34                       # face radius; the ring needs room outside it
    m = mouth / (LEVELS - 1)
    g = ring / (LEVELS - 1)

    # the speaking ring: swells outward and brightens with the voice
    rr = r + S * (0.05 + 0.09 * g)
    d.ellipse([c - rr, c - rr, c + rr, c + rr], outline=BRASS + (int(70 + 150 * g),), width=max(2, int(S * 0.012)))

    # the face
    d.ellipse([c - r, c - r, c + r, c + r], fill=SURFACE + (255,), outline=BRASS + (255,), width=max(2, int(S * 0.018)))

    # eyes
    ey = c - r * 0.22
    for ex in (c - r * 0.36, c + r * 0.36):
        if blink:
            d.line([ex - r * 0.13, ey, ex + r * 0.13, ey], fill=BRASS + (255,), width=max(2, int(S * 0.016)))
        else:
            er = r * 0.09
            d.ellipse([ex - er, ey - er, ex + er, ey + er], fill=BRASS + (255,))

    # the mouth: a line at rest, an opening that grows with the voice
    my = c + r * 0.36
    mw = r * (0.42 + 0.14 * m)
    mh = r * (0.04 + 0.42 * m)
    if m < 0.08:
        d.line([c - mw, my, c + mw, my], fill=BRASS + (255,), width=max(2, int(S * 0.018)))
    else:
        d.ellipse([c - mw, my - mh, c + mw, my + mh], fill=GROUND + (255,), outline=BRASS + (255,), width=max(2, int(S * 0.016)))

    return img.resize((size, size), Image.LANCZOS)


def loudness(path: str, fps: int) -> tuple[list[float], int]:
    """RMS of each video frame's samples, normalised to 0..1 against this file's loud speech."""
    with wave.open(path, "rb") as w:
        assert w.getnchannels() == 1 and w.getsampwidth() == 2, "expected 16-bit mono"
        rate = w.getframerate()
        pcm = array.array("h")
        pcm.frombytes(w.readframes(w.getnframes()))
    n = len(pcm)
    frames = math.ceil(n * fps / rate)
    rms = []
    for k in range(frames):
        a, b = int(k * rate / fps), min(n, int((k + 1) * rate / fps))
        chunk = pcm[a:b]
        rms.append(math.sqrt(sum(x * x for x in chunk) / max(1, len(chunk))))
    voiced = sorted(v for v in rms if v > 300) or [1.0]
    ref = voiced[int(len(voiced) * 0.9)]          # the 90th percentile of speech opens the mouth fully
    out, level = [], 0.0
    for v in rms:
        target = min(1.0, v / ref)
        level += (target - level) * (0.6 if target > level else 0.3)   # quick to open, slower to close
        out.append(level)
    return out, frames


def blink_schedule(frames: int, fps: int, seed: str) -> set[int]:
    rng = random.Random(seed)
    closed, t = set(), rng.uniform(1.0, 2.5)
    while t < frames / fps:
        start = int(t * fps)
        closed.update(range(start, start + 3))
        t += rng.uniform(2.6, 4.8)
    return closed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("wav", nargs="?", help="the episode narration (16-bit mono WAV)")
    ap.add_argument("--lead-in", type=float, default=0.0, help="seconds of silence to prepend (the title card)")
    ap.add_argument("--size", type=int, default=88, help="frame size in pixels (square)")
    ap.add_argument("--fps", type=int, default=24)
    ap.add_argument("--still", metavar="PNG", help="write the resting face as a PNG and exit")
    args = ap.parse_args()

    if args.still:
        draw_pose(args.size, 0, 0, False).save(args.still)
        return 0
    if not args.wav:
        ap.error("a WAV is required unless --still is given")

    levels, frames = loudness(args.wav, args.fps)
    blinks = blink_schedule(frames, args.fps, f"{args.wav}:{frames}")
    cache: dict[tuple[int, int, bool], bytes] = {}

    def frame(mouth: int, ring: int, blink: bool) -> bytes:
        key = (mouth, ring, blink)
        if key not in cache:
            cache[key] = draw_pose(args.size, mouth, ring, blink).tobytes()
        return cache[key]

    out = sys.stdout.buffer
    try:
        rest = frame(0, 0, False)
        for _ in range(int(round(args.lead_in * args.fps))):
            out.write(rest)
        for k, level in enumerate(levels):
            q = int(round(level * (LEVELS - 1)))
            out.write(frame(q, q, k in blinks))
        out.flush()
    except BrokenPipeError:
        return 0      # ffmpeg stopped reading (it hit -t); nothing to report
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

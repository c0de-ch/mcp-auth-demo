#!/usr/bin/env bash
# Cut the course into videos: one slide per narrated paragraph, over the rendered speech.
#
#   npm run video                          → video/<slug>.mp4 + video/<slug>.jpg (the poster), one per episode
#   npm run video -- --only 01-no-authentication
#   SLIDES=/elsewhere/slides OUT=/elsewhere npm run video   # cut from, and into, other directories
#
# Three steps, each incremental — what is already up to date is not redone:
#   1. scripts/render-audio.sh      the narration, audio/<slug>.wav, and audio/timeline.json: where every
#                                   paragraph starts and how long it lasts (see scripts/render-course.py)
#   2. scripts/render-slides.py     the title card and one 1920×1080 PNG per paragraph → video/slides/<slug>/
#   3. scripts/render-avatar.py     the presenter — a face that speaks with the narration — as raw frames;
#                                   or, when video/presenter/<slug>.mp4 exists, that clip in a panel instead
#                                   (a real presenter, see docs/course-audio.md — the slides keep its column clear)
#   4. ffmpeg, below                the title card for lead_in seconds of silence, then each slide for
#                                   exactly the seconds its paragraph occupies, the presenter overlaid,
#                                   muxed with the narration
#
# The cut is exact by construction: the timeline is written from the very samples the episode WAV is
# assembled from, so slide k appears on the 24 fps frame nearest to where paragraph k starts. Slides
# are stills, so the video costs few bytes (x264 -tune stillimage): a few MB per episode.
# Everything under video/ is git-ignored, like the audio: publish it, do not commit it.
#
# Requires: what render-audio.sh needs (uv), python3 with playwright (slides) and Pillow (presenter), ffmpeg with libx264.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT="${OUT:-$ROOT/video}"               # the mp4s and their posters
SLIDES="${SLIDES:-$ROOT/video/slides}"  # the PNGs render-slides.py produces
PRESENTER="${PRESENTER:-$ROOT/video/presenter}"   # optional: <slug>.mp4 per episode, a real presenter (docs/course-audio.md)
SLIDES_P="${SLIDES_P:-$ROOT/video/slides-presenter}"  # the same slides with a column kept clear for the panel
TIMELINE="$ROOT/audio/timeline.json"    # written by render-course.py, next to the WAVs it describes

only=()
while [ $# -gt 0 ]; do
  case "$1" in
    --only) [ $# -ge 2 ] || { echo "--only needs an episode slug (they are listed in audio/course.json)" >&2; exit 2; }
            only=(--only "$2"); shift ;;
    --help|-h) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

for tool in ffmpeg ffprobe; do
  command -v "$tool" >/dev/null || { echo "$tool is required (ffmpeg built with libx264 and aac)" >&2; exit 1; }
done
python3 -c 'import playwright.sync_api' 2>/dev/null || { echo "python3 needs playwright for the slides: pip install playwright && playwright install chromium" >&2; exit 1; }
# A wrong --only slug should fail here, not after the audio step has spent its time.
if [ ${#only[@]} -gt 0 ] && [ -f "$ROOT/audio/course.json" ]; then
  python3 -c '
import json, sys
slugs = [e["slug"] for e in json.load(open(sys.argv[1]))]
if sys.argv[2] not in slugs:
    sys.exit(f"--only {sys.argv[2]}: no such episode. The slugs are:\n  " + "\n  ".join(slugs))
' "$ROOT/audio/course.json" "${only[1]}" || exit 2
fi

bash "$ROOT/scripts/render-audio.sh" "${only[@]}"

AVATAR=88;  AVATAR_X=$((1920 - 96 - AVATAR)); AVATAR_Y=$(((112 - AVATAR) / 2))
STILL=240;  STILL_X=$((1920 - 96 - STILL));   STILL_Y=$((1080 - 96 - STILL))
# A real presenter gets a 3:4 panel in the bottom-right, and the slides keep that column clear.
PANEL_W=360; PANEL_H=480; PANEL_X=$((1920 - 96 - PANEL_W)); PANEL_Y=$((1080 - 64 - PANEL_H)); GUTTER=$((PANEL_W + 40))
BIG_W=480; BIG_H=640; BIG_X=$((1920 - 96 - BIG_W)); BIG_Y=$((1080 - 64 - BIG_H))   # on the title card

echo "==> rendering the slides"
python3 "$ROOT/scripts/render-slides.py" --out "$SLIDES" "${only[@]}"
if ls "$PRESENTER"/*.mp4 >/dev/null 2>&1; then
  echo "==> rendering the slides with a presenter column ($PRESENTER has clips)"
  python3 "$ROOT/scripts/render-slides.py" --out "$SLIDES_P" --gutter "$GUTTER" "${only[@]}"
fi

echo "==> cutting the video"
mkdir -p "$OUT"
LISTS="$(mktemp -d)"
trap 'rm -rf "$LISTS"' EXIT

# The presenter's geometry: an 88 px face centred in the 112 px header strip, inset 96 px like the
# text; the 240 px resting face on the title card sits in the hero's bottom-right gutter.

python3 "$ROOT/scripts/render-avatar.py" --still "$LISTS/avatar-still.png" --size "$STILL"

# The plan: one line per episode — slug, cut|skip, lead-in in ms, total seconds, wav, title card —
# plus, for each episode to cut, the concat list ffmpeg assembles it from. Python's json rather than
# jq, so that the only tool this script adds to the audio pipeline is ffmpeg.
python3 - "$ROOT" "$TIMELINE" "$SLIDES" "$OUT" "$LISTS" "${only[1]:-}" "$PRESENTER" "$SLIDES_P" >"$LISTS/plan.tsv" <<'PY'
import json, os, sys

root, timeline, slides, out, lists, only, presenter, slides_p = sys.argv[1:]
if not os.path.exists(timeline):
    sys.exit(f"{timeline} is missing — render-audio.sh should have written it")
episodes = json.load(open(timeline))
if only:
    episodes = [e for e in episodes if e["slug"] == only]
if not episodes:
    sys.exit(f"nothing to cut: {only or 'no episode'} in {timeline} — the slugs are listed in audio/course.json")

def quoted(path):  # the concat demuxer's own quoting: single quotes, with ' as '\''
    return "'" + path.replace("'", "'\\''") + "'"

for e in episodes:
    slug = e["slug"]
    clip = os.path.join(presenter, slug + ".mp4")
    if not os.path.exists(clip):
        clip = ""
    folder = slides_p if clip else slides   # a real presenter gets the slides with the panel column
    title = os.path.join(folder, slug, "title.png")
    # Each slide holds until the NEXT paragraph's cumulative start, not for its own rounded
    # duration: summing 28 three-decimal durations drifts by up to a frame; differences of
    # starts cannot drift, and the last one runs to the episode's total.
    starts = [x["start"] for x in e["entries"]] + [e["seconds"]]
    shots = [(title, e["lead_in"])] + [
        (os.path.join(folder, slug, f"p{x['index']:04d}.png"), round(starts[i + 1] - starts[i], 3))
        for i, x in enumerate(e["entries"])
    ]
    missing = [path for path, _ in shots if not os.path.exists(path)]
    if missing:
        sys.exit(f"{slug}: {len(missing)} slide(s) missing, first {missing[0]} — did render-slides.py fail?")
    wav = os.path.join(root, e["wav"])
    mp4 = os.path.join(out, slug + ".mp4")
    poster = os.path.join(out, slug + ".jpg")
    part = mp4 + ".part"
    if os.path.exists(part):
        os.remove(part)  # a previous run died mid-encode; nothing trusts it
    avatar = os.path.join(root, "scripts", "render-avatar.py")
    newest = max(os.path.getmtime(path) for path in [wav, avatar] + ([clip] if clip else []) + [path for path, _ in shots])
    fresh = os.path.exists(mp4) and os.path.getmtime(mp4) > newest
    action = "skip" if fresh and os.path.exists(poster) else "poster" if fresh else "cut"
    if action == "cut":
        with open(os.path.join(lists, slug + ".txt"), "w") as f:
            for path, seconds in shots:
                # framerate 1000: a still's timebase is 1/25 s otherwise, and the demuxer would round
                # every duration to it — 4.722 s becomes 4.72 — and the rounding compounds per slide.
                f.write(f"file {quoted(path)}\noption framerate 1000\nduration {seconds}\n")
    print(slug, action, round(e["lead_in"] * 1000), round(e["lead_in"] + e["seconds"], 3), wav, title, clip or "-", sep="\t")
PY

while IFS=$'\t' read -r slug action lead_in_ms total wav title clip; do
  if [ "$action" = skip ]; then
    echo "    $slug.mp4 — up to date"
    continue
  fi
  if [ "$clip" != "-" ]; then
    # The presenter's first frame, cropped 3:4 to the head and shoulders, is the title card's portrait.
    ffmpeg -nostdin -loglevel error -y -i "$clip" -frames:v 1 -vf "crop=ih*3/4:ih,scale=$BIG_W:$BIG_H" "$LISTS/$slug-portrait.png"
  fi
  if [ "$action" = poster ]; then
    if [ "$clip" != "-" ]; then
      ffmpeg -nostdin -loglevel error -y -i "$title" -i "$LISTS/$slug-portrait.png" -filter_complex "overlay=x=$BIG_X:y=$BIG_Y" -q:v 3 "$OUT/$slug.jpg"
    else
      ffmpeg -nostdin -loglevel error -y -i "$title" -i "$LISTS/avatar-still.png" -filter_complex "overlay=x=$STILL_X:y=$STILL_Y" -q:v 3 "$OUT/$slug.jpg"
    fi
    echo "    $slug.jpg — poster regenerated"
    continue
  fi
  lead_in_s=$(awk -v ms="$lead_in_ms" 'BEGIN{printf "%.3f", ms/1000}')
  if [ "$clip" != "-" ]; then
    # A real presenter: the clip runs from the end of the title card, cropped 3:4 into a panel in the
    # bottom-right with a hairline brass frame; the title card carries the larger portrait.
    ffmpeg -nostdin -loglevel error -y \
        -f concat -safe 0 -i "$LISTS/$slug.txt" -i "$wav" -i "$clip" -loop 1 -i "$LISTS/$slug-portrait.png" \
        -filter_complex "[0:v]fps=24,tpad=stop=-1:stop_mode=clone[base];[2:v]crop=ih*3/4:ih,scale=$PANEL_W:$PANEL_H,setpts=PTS+$lead_in_s/TB[p];[base][3:v]overlay=x=$BIG_X:y=$BIG_Y:enable='lt(t,$lead_in_s)'[t];[t][p]overlay=x=$PANEL_X:y=$PANEL_Y:enable='gte(t,$lead_in_s)':eof_action=repeat,drawbox=x=$((PANEL_X-2)):y=$((PANEL_Y-2)):w=$((PANEL_W+4)):h=$((PANEL_H+4)):color=0xD9AC53@0.9:t=2:enable='gte(t,$lead_in_s)'[v];[1:a]adelay=${lead_in_ms}:all=1[a]" \
        -map "[v]" -map "[a]" \
        -c:v libx264 -preset medium -crf 23 -pix_fmt yuv420p \
        -c:a aac -b:a 96k -movflags +faststart -t "$total" \
        -f mp4 "$OUT/$slug.mp4.part"
    mv "$OUT/$slug.mp4.part" "$OUT/$slug.mp4"
    ffmpeg -nostdin -loglevel error -y -i "$title" -i "$LISTS/$slug-portrait.png" -filter_complex "overlay=x=$BIG_X:y=$BIG_Y" -q:v 3 "$OUT/$slug.jpg"
    echo "    $slug.mp4 — with presenter"
    continue
  fi
  # Encode to a temporary file and move it into place, so an interrupted run leaves no truncated
  # mp4 that the mtime check above would mistake for a finished episode. (-f: ffmpeg cannot guess
  # the container from ".part".) The audio is delayed by the lead-in so it starts with slide 1.
  # The end is cut by -t, not -shortest: how long the concat demuxer holds its last still is not
  # defined (measured 2.5–4.7 s, varying run to run), so tpad holds it for ever and -t ends both
  # streams at lead-in + narration — the exact instant, not "when the shorter stream happens to end".
  # The presenter (scripts/render-avatar.py) is piped in as raw RGBA frames and overlaid at the
  # right end of the header strip; during the title card the large resting face sits bottom-right
  # instead. The audio delay and both overlays live in one filter graph.
  python3 "$ROOT/scripts/render-avatar.py" "$wav" --lead-in "$lead_in_s" --size "$AVATAR" --fps 24 \
  | ffmpeg -nostdin -loglevel error -y \
      -f concat -safe 0 -i "$LISTS/$slug.txt" -i "$wav" \
      -f rawvideo -pix_fmt rgba -s "${AVATAR}x${AVATAR}" -r 24 -i pipe:0 \
      -loop 1 -i "$LISTS/avatar-still.png" \
      -filter_complex "[0:v]fps=24,tpad=stop=-1:stop_mode=clone[base];[base][3:v]overlay=x=$STILL_X:y=$STILL_Y:enable='lt(t,$lead_in_s)'[t];[t][2:v]overlay=x=$AVATAR_X:y=$AVATAR_Y:enable='gte(t,$lead_in_s)'[v];[1:a]adelay=${lead_in_ms}:all=1[a]" \
      -map "[v]" -map "[a]" \
      -c:v libx264 -preset medium -crf 23 -tune stillimage -pix_fmt yuv420p \
      -c:a aac -b:a 96k -movflags +faststart -t "$total" \
      -f mp4 "$OUT/$slug.mp4.part"
  mv "$OUT/$slug.mp4.part" "$OUT/$slug.mp4"
  ffmpeg -nostdin -loglevel error -y -i "$title" -i "$LISTS/avatar-still.png" -filter_complex "overlay=x=$STILL_X:y=$STILL_Y" -q:v 3 "$OUT/$slug.jpg"
  echo "    $slug.mp4"
done <"$LISTS/plan.tsv"

echo
echo "video:"
printf '%-52s %8s %10s\n' TRACK DURATION SIZE
total=0
for f in "$OUT"/*.mp4; do
  d=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$f")
  total=$(awk -v a="$total" -v b="$d" 'BEGIN{print a+b}')
  printf '%-52s %8s %10s\n' "$(basename "$f")" "$(awk -v d="$d" 'BEGIN{printf "%d:%02d", d/60, d%60}')" "$(du -h "$f" | cut -f1)"
done
printf '%-52s %8s %10s\n' TOTAL "$(awk -v d="$total" 'BEGIN{printf "%d:%02d", d/60, d%60}')" "$(du -ch "$OUT"/*.mp4 | tail -1 | cut -f1)"

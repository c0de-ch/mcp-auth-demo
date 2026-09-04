#!/usr/bin/env bash
# Render the read-aloud scripts of docs/course.md to speech with piper (local, offline TTS).
#
#   npm run audio                       → audio/*.wav + audio/timeline.json   (14 tracks, 58:06, 147 MB)
#   npm run audio -- --only 01-no-authentication
#   npm run audio -- --opus             → also audio/opus/*.opus (≈20 MB, what you would publish)
#   VOICE=en_GB-alba-medium npm run audio
#
# This script owns the environment — the piper venv and the voice model — and the summary table.
# The speech itself comes from scripts/render-course.py: it reads each episode paragraph by paragraph
# (audio/parts/<slug>/) and joins the parts into the episode file, so audio/timeline.json knows to the
# sample where every paragraph starts. scripts/render-video.sh cuts the slides to that timeline.
#
# Everything it produces is git-ignored: the venv, the ~120 MB voice model and the audio itself.
# Committing 147 MB of WAV to git history is not something you can undo — publish the compressed
# copies as release assets instead. See docs/course-audio.md.
#
# Requires: uv (for the venv), and ffmpeg only for --opus.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VOICE="${VOICE:-en_US-ryan-high}"       # piper voice name; see https://rhasspy.github.io/piper-samples/
PIPER_VERSION="${PIPER_VERSION:-1.7.0}" # pinned: a voice model is tied to the runtime that reads it
CACHE="${CACHE:-$ROOT/.audio}"          # venv + voice model, git-ignored
LENGTH_SCALE="${LENGTH_SCALE:-1.15}"    # >1 slower. Measured with en_US-ryan-high:
                                        #   1.00 ≈ 183 wpm · 1.05 ≈ 174 · 1.15 ≈ 159 · 1.20 ≈ 152
SENTENCE_SILENCE="${SENTENCE_SILENCE:-0.45}"
export VOICE CACHE LENGTH_SCALE SENTENCE_SILENCE   # render-course.py reads the same knobs
OUT="$ROOT/audio"                       # render-course.py writes here and serve-course.ts reads here

want_opus=0
only=()
while [ $# -gt 0 ]; do
  case "$1" in
    --opus) want_opus=1 ;;
    --only) [ $# -ge 2 ] || { echo "--only needs an episode slug (they are listed in audio/course.json)" >&2; exit 2; }
            only=(--only "$2"); shift ;;
    --help|-h) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

command -v uv >/dev/null || { echo "uv is required: https://docs.astral.sh/uv/" >&2; exit 1; }
if [ "$want_opus" = 1 ]; then
  command -v ffmpeg >/dev/null || { echo "--opus needs ffmpeg on PATH" >&2; exit 1; }
fi

PY="$CACHE/venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "==> creating the piper venv in $CACHE/venv"
  uv venv --python 3.12 "$CACHE/venv" >/dev/null
  uv pip install --quiet --python "$PY" "piper-tts==$PIPER_VERSION"
fi

if [ ! -f "$CACHE/voices/$VOICE.onnx" ]; then
  echo "==> downloading voice $VOICE (~120 MB, once)"
  mkdir -p "$CACHE/voices"
  "$PY" -m piper.download_voices "$VOICE" --data-dir "$CACHE/voices"
fi

echo "==> extracting the scripts from docs/course.md"
python3 "$ROOT/scripts/course-audio.py" --json --out "$OUT/text"

echo "==> rendering with $VOICE"
"$PY" "$ROOT/scripts/render-course.py" "${only[@]}"

if [ "$want_opus" = 1 ]; then
  echo "==> encoding opus (48 kbps mono — speech)"
  mkdir -p "$OUT/opus"
  for wav in "$OUT"/*.wav; do
    name="$(basename "$wav" .wav)"
    ffmpeg -nostdin -loglevel error -y -i "$wav" -c:a libopus -b:a 48k -ac 1 \
        -metadata title="$name" -metadata album="Who is calling this server?" \
        "$OUT/opus/$name.opus"
  done
fi

echo
printf '%-52s %8s %10s\n' TRACK DURATION SIZE
total=0
for f in "$OUT"/*.wav; do
  d=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$f" 2>/dev/null || echo 0)
  total=$(awk -v a="$total" -v b="$d" 'BEGIN{print a+b}')
  printf '%-52s %8s %10s\n' "$(basename "$f")" "$(awk -v d="$d" 'BEGIN{printf "%d:%02d", d/60, d%60}')" "$(du -h "$f" | cut -f1)"
done
printf '%-52s %8s %10s\n' TOTAL "$(awk -v d="$total" 'BEGIN{printf "%d:%02d", d/60, d%60}')" "$(du -ch "$OUT"/*.wav | tail -1 | cut -f1)"
if [ "$want_opus" = 1 ]; then
  printf '%-52s %8s %10s\n' "  opus (publish these)" "" "$(du -ch "$OUT"/opus/*.opus | tail -1 | cut -f1)"
fi

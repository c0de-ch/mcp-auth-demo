# Rendering the course as audio

[`course.md`](course.md) carries fourteen read-aloud scripts — 9,081 words, which render to **58 minutes
and 6 seconds** of speech at 156 words per minute. `scripts/render-audio.sh` turns them into one audio file per episode using
[piper](https://github.com/OHF-Voice/piper1-gpl), which runs locally on CPU: no account, no API key,
nothing leaves the machine.

```bash
npm run audio                                  # audio/*.wav
npm run audio -- --only 01-no-authentication   # one episode
npm run audio -- --opus                        # …and audio/opus/*.opus, which is what you would publish
```

First run creates a virtual environment under `.audio/` and downloads a ~120 MB voice model. Both are
git-ignored and cached, so subsequent runs start immediately. Rendering is incremental: a track whose
text has not changed is skipped.

## Requirements

| | |
|---|---|
| [`uv`](https://docs.astral.sh/uv/) | creates the Python 3.12 environment piper runs in |
| `ffmpeg` | only for `--opus`, and for `npm run video` |
| Playwright for Python, with its Chromium | only for `npm run video` — the slides are screenshots |
| Pillow (`PIL`) | only for `npm run video` — the presenter is drawn with it |

## Knobs

| Variable | Default | |
|---|---|---|
| `VOICE` | `en_US-ryan-high` | any piper voice — browse the [samples](https://rhasspy.github.io/piper-samples/) and use the name, e.g. `en_GB-alba-medium` |
| `LENGTH_SCALE` | `1.15` | above 1 is slower. Measured with `en_US-ryan-high`: `1.00` ≈ 183 wpm, `1.05` ≈ 174, `1.15` ≈ 159, `1.20` ≈ 152 |
| `SENTENCE_SILENCE` | `0.45` | seconds of pause between sentences |
| `PARAGRAPH_GAP` | `0.8` | seconds of pause between paragraphs — where the video cuts to the next slide |
| `LEAD_IN` | `2.5` | seconds the video holds its title card before the narration; the audio has none. Recorded in `audio/timeline.json` when an episode is rendered, so a new value only takes effect on episodes that render again |
| `PIPER_VERSION` | `1.7.0` | pinned — a voice model is tied to the runtime that reads it |

## How the text is prepared

`scripts/course-audio.py` does the Markdown-to-speech step, and runs on its own if you want the plain
text for some other engine:

```bash
python3 scripts/course-audio.py --out audio/text            # 14 .txt files + manifest.json
python3 scripts/course-audio.py --out audio/text --json     # …and audio/course.json, what the video is cut from
```

It takes the body of each `<details>` block and, in order: drops the `**Beat — …**` stage directions
(they are structure for a reader, not speech), unwraps `*emphasis*` and `` `code` ``, rewrites the
identifiers a speech engine mangles, turns em dashes into commas so the phrasing breathes, and rejoins
the hard-wrapped lines into paragraphs — otherwise the engine breaks on the 100-column margin instead
of on sentences.

**The pronunciation table is meant to be edited.** It is the `SPOKEN` list at the top of
`course-audio.py`, longest key first:

```python
("mcp:tools",        "M C P tools"),
("WWW-Authenticate", "W W W Authenticate"),
("private_key_jwt",  "private key J W T"),
```

Listen to one episode, add whatever grates, re-run. Word-shaped keys are matched on word boundaries,
so `aud` never fires inside "audience".

## Video

`npm run video` renders the same fourteen episodes as video: the narration over slides that show the
paragraph being read, with the lesson's diagrams, terminals and tables beside it.

```bash
npm run video                                  # video/<track>.mp4 + video/<track>.jpg
npm run video -- --only 01-no-authentication   # one episode
```

It is the audio pipeline with two more stages, and every stage is incremental — an episode whose
text, audio and slides have not changed is skipped:

1. `scripts/course-audio.py --json` writes `audio/course.json`: every paragraph of every script with
   its on-screen HTML and its spoken text, plus the lesson's figures in document order.
2. `scripts/render-course.py` synthesises each paragraph on its own (`audio/parts/<track>/pNNNN.wav`),
   joins them into `audio/<track>.wav`, and records in `audio/timeline.json` where each paragraph
   starts and how long it lasts. The episode is assembled from the parts, so the timeline is exact
   by construction rather than estimated afterwards.
3. `scripts/render-slides.py` renders one 1920×1080 slide per paragraph, and a title card, by
   screenshotting a page in the lesson's own dark theme with headless Chromium: the paragraph with
   the current figure beside it, or as a band above it when the figure is wide, and a progress bar
   along the bottom. The layout and the figure's size are chosen once for every run of paragraphs
   that share a figure, so the figure holds still across those cuts.
4. `scripts/render-avatar.py` draws the presenter: a face in the course's own style that speaks
   along with the narration — the mouth opens with the loudness of the voice, a ring pulses around it
   like an active-speaker indicator, and it blinks now and then. It is driven by the audio frame by
   frame, so it cannot drift from the words. It sits at the right end of every slide's header; the
   title card and the poster carry a larger resting face.
5. `scripts/render-video.sh` shows each slide for exactly the seconds its paragraph occupies, after a
   short lead-in on the title card, puts the narration underneath and encodes H.264 with AAC audio
   (`libx264`, CRF 23, 24 fps, `faststart` so playback starts before the download ends). The title
   card is also written as `video/<track>.jpg`, the poster.

Measured for the full course: **58:41 across fourteen MP4s, 111 MB** — between 5 and 14 MB each, so
smaller than the WAVs and in the same range as the Opus files, because a slide that does not move
costs almost nothing to encode. `video/` is git-ignored like `audio/`; distribute the MP4s as release
assets the same way.

The cut is exact by construction: the timeline is written from the very samples the episode WAV is
assembled from, and each slide holds until the next paragraph's cumulative start. When the pipeline
was built this was verified by extracting a frame just after each cut and comparing it with that
paragraph's slide; `npm run video` itself does not repeat that check.

## Listening on the LAN

`npm run course:serve` (or `course:server` — both work) publishes the lot on this machine — the lesson page, the Markdown, the audio,
the video where it has been rendered, and a podcast feed for each:

```
[course] listening on 0.0.0.0:4120
[course] lesson    http://192.168.78.87:4120/
[course] markdown  http://192.168.78.87:4120/course.md
[course] podcast   http://192.168.78.87:4120/feed.xml    14 tracks, 0:58:06
[course] video     http://192.168.78.87:4120/video.xml   14 tracks
```

| Route | |
|---|---|
| `/` | `docs/course.html`, with a player per episode and a **Watch** button on the episodes that have a video |
| `/course.md` | the Markdown edition |
| `/audio/<track>.opus` | the encoded audio, falling back to `.wav` when you have not run `--opus` |
| `/video/<track>.mp4` | the rendered episode — answers `Range` requests, so seeking works |
| `/video/<track>.jpg` | its poster, the title card |
| `/feed.xml` | RSS 2.0 with iTunes tags — paste it into any podcast app on the network |
| `/video.xml` | the same feed with the MP4s as enclosures, for the episodes that have one |

Like every server here it binds `0.0.0.0` and builds its URLs from `PUBLIC_HOST`, which matters most
for the feed: enclosure URLs pointing at loopback are useless on the phone you want to listen on. The
feed is marked `itunes:type: serial` with ascending dates, so podcast apps play episode 00 first
instead of newest-first. Durations come from the WAV headers, so the feed is accurate without ffprobe.

The video is optional at every level: `tracks.json`, which the page reads, carries `video` and
`poster` only for the episodes whose MP4 exists, `/video.xml` lists only those, and a course that is
rendered half-way serves fine.

Set `PORT_COURSE` to move it off 4120.

## Why the audio is not in the repository

The full course as 22.05 kHz mono WAV is **147 MB** (measured, 14 files). Git stores every version of it forever, and the
only way to take that back is rewriting history — so `audio/` is git-ignored, and the pipeline that
reproduces it is what lives here instead.

To distribute the audio, attach the Opus files to a GitHub release — **19 MB** for the whole course at
48 kbps mono:

```bash
npm run audio -- --opus
gh release upload <tag> audio/opus/*.opus
```

That keeps the clone small, gives every file a stable URL, and — because this repository already signs
its releases — puts the audio under the same [cosign attestation](release-signing.md) as everything
else it publishes.

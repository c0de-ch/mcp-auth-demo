# Rendering the course as audio

[`course.md`](course.md) carries fourteen read-aloud scripts — 9,081 words, which render to **55 minutes
and 39 seconds** of speech at 163 words per minute. `scripts/render-audio.sh` turns them into one audio file per episode using
[piper](https://github.com/OHF-Voice/piper1-gpl), which runs locally on CPU: no account, no API key,
nothing leaves the machine.

```bash
npm run audio                 # audio/*.wav
npm run audio -- --opus       # …and audio/opus/*.opus, which is what you would publish
```

First run creates a virtual environment under `.audio/` and downloads a ~120 MB voice model. Both are
git-ignored and cached, so subsequent runs start immediately. Rendering is incremental: a track whose
text has not changed is skipped.

## Requirements

| | |
|---|---|
| [`uv`](https://docs.astral.sh/uv/) | creates the Python 3.12 environment piper runs in |
| `ffmpeg` | only for `--opus` |

## Knobs

| Variable | Default | |
|---|---|---|
| `VOICE` | `en_US-ryan-high` | any piper voice — browse the [samples](https://rhasspy.github.io/piper-samples/) and use the name, e.g. `en_GB-alba-medium` |
| `LENGTH_SCALE` | `1.15` | above 1 is slower. Measured with `en_US-ryan-high`: `1.00` ≈ 183 wpm, `1.05` ≈ 174, `1.15` ≈ 159, `1.20` ≈ 152 |
| `SENTENCE_SILENCE` | `0.45` | seconds of pause between sentences |
| `OUT` | `audio/` | output directory |
| `PIPER_VERSION` | `1.7.0` | pinned — a voice model is tied to the runtime that reads it |

## How the text is prepared

`scripts/course-audio.py` does the Markdown-to-speech step, and runs on its own if you want the plain
text for some other engine:

```bash
python3 scripts/course-audio.py --out audio/text     # 14 .txt files + manifest.json
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

## Listening on the LAN

`npm run course:serve` (or `course:server` — both work) publishes the lot on this machine — the lesson page, the Markdown, the audio,
and a podcast feed:

```
[course] listening on 0.0.0.0:4120
[course] lesson    http://192.168.78.87:4120/
[course] markdown  http://192.168.78.87:4120/course.md
[course] podcast   http://192.168.78.87:4120/feed.xml    14 tracks, 0:55:39
```

| Route | |
|---|---|
| `/` | `docs/course.html` |
| `/course.md` | the Markdown edition |
| `/audio/<track>.opus` | the encoded audio, falling back to `.wav` when you have not run `--opus` |
| `/feed.xml` | RSS 2.0 with iTunes tags — paste it into any podcast app on the network |

Like every server here it binds `0.0.0.0` and builds its URLs from `PUBLIC_HOST`, which matters most
for the feed: enclosure URLs pointing at loopback are useless on the phone you want to listen on. The
feed is marked `itunes:type: serial` with ascending dates, so podcast apps play episode 00 first
instead of newest-first. Durations come from the WAV headers, so the feed is accurate without ffprobe.

Set `PORT_COURSE` to move it off 4120.

## Why the audio is not in the repository

The full course as 22.05 kHz mono WAV is **141 MB** (measured, 14 files). Git stores every version of it forever, and the
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

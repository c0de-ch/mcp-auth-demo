/**
 * serve-course.ts — publish the course on the LAN: the lesson page, the Markdown, the rendered
 * audio (and video, once rendered), and podcast feeds you can subscribe to from a phone on the
 * same network.
 *
 *   npm run audio            # render the audio first (scripts/render-audio.sh)
 *   npm run video            # optional: the episodes as video (scripts/render-video.sh)
 *   npm run course:serve     # → http://<PUBLIC_HOST>:4120/
 *
 *   /            docs/course.html          the lesson page
 *   /course.md   docs/course.md            the Markdown edition
 *   /audio/…     audio/opus/*.opus         (falls back to the WAVs when not encoded)
 *   /video/…     video/*.mp4, *.jpg        the rendered episodes and their posters
 *   /feed.xml    an RSS 2.0 podcast feed — paste that URL into any podcast app
 *   /video.xml   the same feed with the videos as enclosures, for the episodes that have one
 *
 * Like every server in this repository it binds 0.0.0.0 and builds every advertised URL from
 * PUBLIC_HOST, because a feed full of loopback URLs is useless on the device you want to listen on.
 */
import { port, publicUrl, REPO_ROOT } from '../src/shared/env.ts';
import { closeSync, existsSync, openSync, readFileSync, readSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import express from 'express';

export const PORT = port('PORT_COURSE', 4120);

const AUDIO_DIR = join(REPO_ROOT, 'audio');
const OPUS_DIR = join(AUDIO_DIR, 'opus');
const VIDEO_DIR = join(REPO_ROOT, 'video');
const DOCS = join(REPO_ROOT, 'docs');

interface Video {
  file: string;
  bytes: number;
  /** video/<slug>.jpg, the title card — only once render-video.sh has written it. */
  poster?: string;
}

interface Track {
  file: string;
  slug: string;
  title: string;
  bytes: number;
  seconds: number;
  type: string;
  /** Only when video/<slug>.mp4 exists. The audio is what makes a track; the video is optional. */
  video?: Video;
}

/** Duration from the WAV header — no ffprobe, no dependency: walk the RIFF chunks. Reads the
 *  first 4 KiB only; readFileSync would pull the whole 10 MB file for every listing. */
function wavSeconds(path: string): number {
  const head = Buffer.alloc(4096);
  const fd = openSync(path, 'r');
  try {
    readSync(fd, head, 0, head.length, 0);
  } finally {
    closeSync(fd);
  }
  if (head.subarray(0, 4).toString('ascii') !== 'RIFF') return 0;
  let offset = 12;
  let byteRate = 0;
  while (offset + 8 <= head.length) {
    const id = head.subarray(offset, offset + 4).toString('ascii');
    const size = head.readUInt32LE(offset + 4);
    if (id === 'fmt ') byteRate = head.readUInt32LE(offset + 16);
    if (id === 'data') return byteRate ? size / byteRate : 0;
    offset += 8 + size + (size % 2);
  }
  return 0;
}

const hms = (total: number): string => {
  const s = Math.round(total);
  return [Math.floor(s / 3600), Math.floor((s % 3600) / 60), s % 60]
    .map((n, i) => (i === 0 ? String(n) : String(n).padStart(2, '0')))
    .join(':');
};

const titleOf = (slug: string): string => {
  const words = slug.replace(/^\d+-/, '').replace(/-/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
};

/** The rendered episode, when `npm run video` has produced it. */
function videoOf(slug: string): Video | undefined {
  const file = join(VIDEO_DIR, `${slug}.mp4`);
  if (!existsSync(file)) return undefined;
  const poster = join(VIDEO_DIR, `${slug}.jpg`);
  return { file, bytes: statSync(file).size, poster: existsSync(poster) ? poster : undefined };
}

/** The video's title card precedes the narration by this much; from the timeline, else none. */
function leadInSeconds(): number {
  try {
    const timeline = JSON.parse(readFileSync(join(AUDIO_DIR, 'timeline.json'), 'utf8')) as { lead_in?: number }[];
    return timeline[0]?.lead_in ?? 0;
  } catch {
    return 0;
  }
}

let cached: { key: string; list: Track[] } | undefined;
const dirKey = (dir: string): string => (existsSync(dir) ? String(statSync(dir).mtimeMs) : '-');

/** Opus when it has been encoded, WAV otherwise. Durations always come from the WAV.
 *  Cached on the audio/ and video/ directory mtimes — every render lands by rename, which bumps
 *  them — so a Range request on a video does not re-read fourteen WAV headers. */
export function tracks(): Track[] {
  const key = [dirKey(AUDIO_DIR), dirKey(OPUS_DIR), dirKey(VIDEO_DIR)].join('|');
  if (cached && cached.key === key) return cached.list;
  cached = { key, list: listTracks() };
  return cached.list;
}

function listTracks(): Track[] {
  if (!existsSync(AUDIO_DIR)) return [];
  const wavs = readdirSync(AUDIO_DIR).filter((f) => f.endsWith('.wav')).sort();
  return wavs.map((wav) => {
    const slug = wav.replace(/\.wav$/, '');
    const opus = join(OPUS_DIR, `${slug}.opus`);
    const useOpus = existsSync(opus);
    const file = useOpus ? opus : join(AUDIO_DIR, wav);
    return {
      file,
      slug,
      title: titleOf(slug),
      bytes: statSync(file).size,
      seconds: wavSeconds(join(AUDIO_DIR, wav)),
      type: useOpus ? 'audio/ogg' : 'audio/wav',
      video: videoOf(slug),
    };
  });
}

/** The URL paths /audio/:name and /video/:name answer to — the only names they accept. */
const audioPath = (t: Track): string =>
  `/audio/${encodeURIComponent(t.slug)}${t.type === 'audio/ogg' ? '.opus' : '.wav'}`;
const videoPath = (t: Track, ext: 'mp4' | 'jpg'): string => `/video/${encodeURIComponent(t.slug)}.${ext}`;

const xml = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** RFC 822 dates, one hour apart, oldest first — so a podcast app plays the course in order. */
const pubDate = (index: number): string =>
  new Date(Date.UTC(2026, 0, 1, index)).toUTCString();

type Media = 'audio' | 'video';

/** What a podcast app downloads for an item. Every track has audio; only rendered ones have video. */
function enclosure(t: Track, media: Media): { path: string; length: number; type: string } | undefined {
  if (media === 'audio') return { path: audioPath(t), length: t.bytes, type: t.type };
  return t.video && { path: videoPath(t, 'mp4'), length: t.video.bytes, type: 'video/mp4' };
}

/**
 * /feed.xml lists every track; /video.xml the same items with the video as enclosure, for the
 * tracks that have one. Distinct guids, so an app subscribed to both keeps them apart.
 */
export function feed(list: Track[], media: Media = 'audio'): string {
  const base = publicUrl(PORT, '');
  const leadIn = media === 'video' ? leadInSeconds() : 0;
  const items = list
    .flatMap((t, i) => {
      const file = enclosure(t, media);
      if (!file) return [];
      return `    <item>
      <title>${xml(t.title)}</title>
      <description>${xml(`Episode ${i} of "Who is calling this server?" — ${t.title}.`)}</description>
      <guid isPermaLink="false">mcp-auth-course-${xml(t.slug)}${media === 'video' ? '-video' : ''}</guid>
      <pubDate>${pubDate(i)}</pubDate>
      <enclosure url="${xml(base + file.path)}" length="${file.length}" type="${file.type}"/>
      <itunes:duration>${hms(t.seconds + (media === 'video' ? leadIn : 0))}</itunes:duration>
      <itunes:episode>${i + 1}</itunes:episode>
      <itunes:episodeType>full</itunes:episodeType>
    </item>`;
    })
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
  <channel>
    <title>Who is calling this server?${media === 'video' ? ' (video)' : ''}</title>
    <link>${xml(base)}/</link>
    <description>A fourteen-episode course on MCP authentication, built on the twelve runnable examples of mcp-auth-demo.</description>
    <language>en</language>
    <itunes:author>mcp-auth-demo</itunes:author>
    <itunes:type>serial</itunes:type>
    <itunes:category text="Technology"/>
    <itunes:explicit>false</itunes:explicit>
${items}
  </channel>
</rss>
`;
}

export function buildApp(): express.Express {
  const app = express();

  app.get('/', (_req, res) => res.sendFile(join(DOCS, 'course.html')));
  app.get('/course.md', (_req, res) => res.type('text/markdown; charset=utf-8').sendFile(join(DOCS, 'course.md')));
  app.get('/feed.xml', (_req, res) => res.type('application/rss+xml; charset=utf-8').send(feed(tracks())));
  app.get('/video.xml', (_req, res) => res.type('application/rss+xml; charset=utf-8').send(feed(tracks(), 'video')));

  // The lesson page fetches this and attaches a player per episode. It 404s everywhere the
  // audio is not being served (the published artifact, a file:// open), and the page then
  // simply renders without players. The video fields exist only for rendered episodes; the
  // page shows its Watch button on exactly those.
  app.get('/tracks.json', (_req, res) =>
    res.json(
      tracks().map((t, i) => ({
        episode: i,
        slug: t.slug,
        title: t.title,
        duration: hms(t.seconds),
        seconds: Math.round(t.seconds),
        bytes: t.bytes,
        type: t.type,
        url: audioPath(t),
        ...(t.video
          ? {
              video: videoPath(t, 'mp4'),
              videoBytes: t.video.bytes,
              ...(t.video.poster ? { poster: videoPath(t, 'jpg') } : {}),
            }
          : {}),
      })),
    ),
  );

  app.get('/audio/:name', (req, res) => {
    // Whitelist by generated name: never join user input onto a path.
    const wanted = req.params.name;
    const track = tracks().find(
      (t) => `${t.slug}.opus` === wanted || `${t.slug}.wav` === wanted,
    );
    if (!track) return res.status(404).json({ error: 'no such track' });
    return res.type(track.type).sendFile(track.file);
  });

  app.get('/video/:name', (req, res) => {
    // Same whitelist. sendFile answers Range requests, which is what lets a browser seek.
    const wanted = req.params.name;
    for (const t of tracks()) {
      if (!t.video) continue;
      if (`${t.slug}.mp4` === wanted) return res.type('video/mp4').sendFile(t.video.file);
      if (t.video.poster && `${t.slug}.jpg` === wanted) return res.type('image/jpeg').sendFile(t.video.poster);
    }
    return res.status(404).json({ error: 'no such video' });
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true, tracks: tracks().length }));
  app.use((_req, res) => res.status(404).json({ error: 'not found' }));
  return app;
}

const list = tracks();
if (list.length === 0) {
  console.error('No audio in audio/ — run `npm run audio` first. Serving the pages anyway.');
}
buildApp().listen(PORT, '0.0.0.0', () => {
  const base = publicUrl(PORT, '');
  const total = list.reduce((sum, t) => sum + t.seconds, 0);
  const videos = list.filter((t) => t.video).length;
  console.error(`[course] listening on 0.0.0.0:${PORT}`);
  console.error(`[course] lesson    ${base}/`);
  console.error(`[course] markdown  ${base}/course.md`);
  console.error(`[course] podcast   ${base}/feed.xml    ${list.length} tracks, ${hms(total)}`);
  console.error(`[course] video     ${base}/video.xml   ${videos} tracks`);
});

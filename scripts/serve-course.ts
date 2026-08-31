/**
 * serve-course.ts — publish the course on the LAN: the lesson page, the Markdown, the rendered
 * audio, and a podcast feed you can subscribe to from a phone on the same network.
 *
 *   npm run audio            # render the audio first (scripts/render-audio.sh)
 *   npm run course:serve     # → http://<PUBLIC_HOST>:4120/
 *
 *   /            docs/course.html          the lesson page
 *   /course.md   docs/course.md            the Markdown edition
 *   /audio/…     audio/opus/*.opus         (falls back to the WAVs when not encoded)
 *   /feed.xml    an RSS 2.0 podcast feed — paste that URL into any podcast app
 *
 * Like every server in this repository it binds 0.0.0.0 and builds every advertised URL from
 * PUBLIC_HOST, because a feed full of loopback URLs is useless on the device you want to listen on.
 */
import { port, publicUrl, REPO_ROOT } from '../src/shared/env.ts';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import express from 'express';

export const PORT = port('PORT_COURSE', 4120);

const AUDIO_DIR = join(REPO_ROOT, 'audio');
const OPUS_DIR = join(AUDIO_DIR, 'opus');
const DOCS = join(REPO_ROOT, 'docs');

interface Track {
  file: string;
  slug: string;
  title: string;
  bytes: number;
  seconds: number;
  type: string;
}

/** Duration from the WAV header — no ffprobe, no dependency: walk the RIFF chunks. */
function wavSeconds(path: string): number {
  const head = readFileSync(path).subarray(0, 4096);
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

/** Opus when it has been encoded, WAV otherwise. Durations always come from the WAV. */
export function tracks(): Track[] {
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
    };
  });
}

const xml = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** RFC 822 dates, one hour apart, oldest first — so a podcast app plays the course in order. */
const pubDate = (index: number): string =>
  new Date(Date.UTC(2026, 0, 1, index)).toUTCString();

export function feed(list: Track[]): string {
  const base = publicUrl(PORT, '');
  const items = list
    .map((t, i) => {
      const url = `${base}/audio/${encodeURIComponent(t.slug)}${t.type === 'audio/ogg' ? '.opus' : '.wav'}`;
      return `    <item>
      <title>${xml(t.title)}</title>
      <description>${xml(`Episode ${i} of "Who is calling this server?" — ${t.title}.`)}</description>
      <guid isPermaLink="false">mcp-auth-course-${xml(t.slug)}</guid>
      <pubDate>${pubDate(i)}</pubDate>
      <enclosure url="${xml(url)}" length="${t.bytes}" type="${t.type}"/>
      <itunes:duration>${hms(t.seconds)}</itunes:duration>
      <itunes:episode>${i + 1}</itunes:episode>
      <itunes:episodeType>full</itunes:episodeType>
    </item>`;
    })
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
  <channel>
    <title>Who is calling this server?</title>
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

  // The lesson page fetches this and attaches a player per episode. It 404s everywhere the
  // audio is not being served (the published artifact, a file:// open), and the page then
  // simply renders without players.
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
        url: `/audio/${encodeURIComponent(t.slug)}${t.type === 'audio/ogg' ? '.opus' : '.wav'}`,
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
  console.error(`[course] listening on 0.0.0.0:${PORT}`);
  console.error(`[course] lesson    ${base}/`);
  console.error(`[course] markdown  ${base}/course.md`);
  console.error(`[course] podcast   ${base}/feed.xml    ${list.length} tracks, ${hms(total)}`);
});

/**
 * Tests for the SSE client. Run with `npm test` (Node's built-in runner).
 */
import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';

import { AnalysisError, analyzeFile, MAX_UPLOAD_BYTES, parseSseBuffer } from '../src/lib/analyzeStream.ts';

const REPORT = {
  schema_version: '1.0',
  mode: 'heuristic',
  features: { metadata: { filename: 'a.py' }, note: 'line one\nline two' },
  intelligence: { threat_level: 'High' },
  detections: { yara_rule: 'rule X { condition: true }', sigma_rule: 'title: X' },
  warnings: [],
  capabilities: {},
};

const sse = (payload: unknown): string => `data: ${JSON.stringify(payload)}\n\n`;

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Stub fetch with a response whose body arrives in the given chunks. */
function stubFetch(chunks: string[], init: ResponseInit = {}): void {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
  globalThis.fetch = (async () => new Response(body, init)) as typeof fetch;
}

const sample = (): File => new File(['print(1)\n'], 'a.py');

// ── parseSseBuffer ───────────────────────────────────────────

test('an event split across chunks is held until it is complete', () => {
  const full = sse({ type: 'complete', data: REPORT });
  const cut = Math.floor(full.length / 2);

  const first = parseSseBuffer(full.slice(0, cut));
  assert.deepEqual(first.events, []);
  assert.equal(first.rest, full.slice(0, cut));

  const second = parseSseBuffer(first.rest + full.slice(cut));
  assert.equal(second.events.length, 1);
  assert.equal(second.events[0].type, 'complete');
  assert.equal(second.rest, '');
});

test('several events in one chunk are all returned in order', () => {
  const text = sse({ type: 'status', agent: 'Extractor', message: 'a' })
    + sse({ type: 'status', agent: 'Analyst', message: 'b' });
  const { events } = parseSseBuffer(text);
  assert.deepEqual(events.map((e) => (e.type === 'status' ? e.agent : e.type)), ['Extractor', 'Analyst']);
});

test('malformed and unknown events are skipped', () => {
  const text = 'data: {not json}\n\n' + sse({ type: 'telemetry' }) + sse({ type: 'error', message: 'boom' });
  const { events } = parseSseBuffer(text);
  assert.deepEqual(events, [{ type: 'error', message: 'boom' }]);
});

test('CRLF line endings are accepted', () => {
  const { events } = parseSseBuffer('data: {"type":"error","message":"x"}\r\n\r\n');
  assert.equal(events.length, 1);
});

// ── analyzeFile ──────────────────────────────────────────────

test('resolves with the report when the complete event spans many chunks', async () => {
  const stream = sse({ type: 'status', agent: 'Extractor', message: 'working' })
    + sse({ type: 'complete', data: REPORT });
  const chunks = stream.match(/[\s\S]{1,7}/g) ?? [];
  stubFetch(chunks);

  const statuses: string[] = [];
  const report = await analyzeFile(sample(), { onStatus: (agent, message) => statuses.push(`${agent}:${message}`) });

  assert.deepEqual(report, REPORT);
  assert.deepEqual(statuses, ['Extractor:working']);
});

test('a final event without a trailing blank line is still delivered', async () => {
  stubFetch([`data: ${JSON.stringify({ type: 'complete', data: REPORT })}`]);
  assert.deepEqual(await analyzeFile(sample()), REPORT);
});

test('an error event rejects with the server message', async () => {
  stubFetch([sse({ type: 'error', message: 'Extraction timed out after 120s.' })]);
  await assert.rejects(analyzeFile(sample()), (error: unknown) => {
    assert.ok(error instanceof AnalysisError);
    assert.equal(error.message, 'Extraction timed out after 120s.');
    return true;
  });
});

test('a stream that ends without a result rejects instead of hanging', async () => {
  stubFetch([sse({ type: 'status', agent: 'Extractor', message: 'working' })]);
  await assert.rejects(analyzeFile(sample()), /closed before the analysis finished/);
});

test('HTTP errors surface the API detail message', async () => {
  globalThis.fetch = (async () => new Response(
    JSON.stringify({ detail: 'File exceeds the 32 MB upload limit.' }),
    { status: 413, headers: { 'Content-Type': 'application/json' } },
  )) as typeof fetch;
  await assert.rejects(analyzeFile(sample()), /File exceeds the 32 MB upload limit\./);
});

test('an unreachable API is reported clearly', async () => {
  globalThis.fetch = (async () => {
    throw new TypeError('fetch failed');
  }) as typeof fetch;
  await assert.rejects(analyzeFile(sample()), /Cannot reach the analysis API/);
});

test('empty and oversized files are rejected before any request', async () => {
  let called = false;
  globalThis.fetch = (async () => {
    called = true;
    return new Response('');
  }) as typeof fetch;

  await assert.rejects(analyzeFile(new File([], 'empty.bin')), /empty/);
  const huge = { size: MAX_UPLOAD_BYTES + 1, name: 'huge.bin' } as File;
  await assert.rejects(analyzeFile(huge), /upload limit/);
  assert.equal(called, false);
});

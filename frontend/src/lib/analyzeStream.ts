/**
 * Client for POST /api/v1/analyze.
 *
 * The backend streams Server-Sent Events. A single event (the final report
 * can be hundreds of kilobytes) routinely spans several network chunks, so
 * chunks are buffered and only complete events are parsed.
 */
import type { FinalReport, StreamEvent } from '../types/report';
import { formatBytes } from './format.ts';

/** Matches the backend default (MAX_UPLOAD_MB); Cloud Run caps bodies at 32 MiB. */
export const MAX_UPLOAD_BYTES = 32 * 1024 * 1024;

const DEFAULT_API_BASE = 'http://localhost:8080';

export class AnalysisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AnalysisError';
  }
}

export interface AnalyzeOptions {
  onStatus?: (agent: string, message: string) => void;
  signal?: AbortSignal;
}

export function apiBaseUrl(): string {
  // `env` is undefined outside Vite (for example under `node --test`).
  const configured = import.meta.env?.VITE_API_URL as string | undefined;
  return (configured || DEFAULT_API_BASE).replace(/\/+$/, '');
}

function isStreamEvent(value: unknown): value is StreamEvent {
  if (typeof value !== 'object' || value === null) return false;
  const type = (value as { type?: unknown }).type;
  return type === 'status' || type === 'complete' || type === 'error';
}

/**
 * Split buffered SSE text into complete events plus the unfinished remainder.
 * Events are separated by a blank line; malformed or unknown events are skipped.
 */
export function parseSseBuffer(buffer: string): { events: StreamEvent[]; rest: string } {
  const blocks = buffer.replace(/\r\n/g, '\n').split('\n\n');
  const rest = blocks.pop() ?? '';
  const events: StreamEvent[] = [];

  for (const block of blocks) {
    const data = block
      .split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trimStart())
      .join('\n');
    if (!data) continue;
    try {
      const parsed: unknown = JSON.parse(data);
      if (isStreamEvent(parsed)) events.push(parsed);
    } catch {
      // A malformed event is dropped; a missing result is reported by the caller.
    }
  }
  return { events, rest };
}

async function describeHttpError(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    const detail = (body as { detail?: unknown } | null)?.detail;
    if (typeof detail === 'string' && detail) return detail;
  } catch {
    // Non-JSON error body: fall through to the status line.
  }
  return `The analysis API returned HTTP ${response.status}.`;
}

function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

/**
 * Upload a file for analysis and resolve with the final report.
 * Rejects with `AnalysisError` carrying a message fit to show the user.
 */
export async function analyzeFile(file: File, options: AnalyzeOptions = {}): Promise<FinalReport> {
  if (file.size === 0) throw new AnalysisError('The selected file is empty.');
  if (file.size > MAX_UPLOAD_BYTES) {
    throw new AnalysisError(
      `File is ${formatBytes(file.size)}; the upload limit is ${formatBytes(MAX_UPLOAD_BYTES)}.`,
    );
  }

  const formData = new FormData();
  formData.append('file', file);

  let response: Response;
  try {
    // No Content-Type header: the browser sets the multipart boundary itself.
    response = await fetch(`${apiBaseUrl()}/api/v1/analyze`, {
      method: 'POST',
      body: formData,
      signal: options.signal,
    });
  } catch (error) {
    if (isAbort(error)) throw error;
    throw new AnalysisError(`Cannot reach the analysis API at ${apiBaseUrl()}. Is the backend running?`);
  }

  if (!response.ok) throw new AnalysisError(await describeHttpError(response));
  if (!response.body) throw new AnalysisError('Streaming responses are not supported by this browser.');

  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  try {
    for (;;) {
      const { done, value } = await reader.read();
      // On close, append a terminator so a final unterminated event is parsed.
      buffer += done ? `${decoder.decode()}\n\n` : decoder.decode(value, { stream: true });

      const { events, rest } = parseSseBuffer(buffer);
      buffer = rest;

      for (const event of events) {
        if (event.type === 'status') {
          options.onStatus?.(event.agent, event.message);
        } else if (event.type === 'error') {
          throw new AnalysisError(event.message || 'Analysis failed.');
        } else {
          return event.data;
        }
      }
      if (done) break;
    }
  } finally {
    reader.cancel().catch(() => undefined);
  }

  throw new AnalysisError('The connection closed before the analysis finished.');
}

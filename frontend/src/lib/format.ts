/** Formatting helpers with no runtime dependencies. */

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || Number.isNaN(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** Shorten a long value (hash, URL) by eliding the middle. */
export function truncateMiddle(value: string, head = 12, tail = 6): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function truncateEnd(value: string, max = 30): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

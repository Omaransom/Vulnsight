import type { Alert } from '../types';

/**
 * Merge the live (WebSocket) and historical (fetched) alert lists, removing
 * duplicates.
 *
 * The same alert arrives over the live feed AND in the next history fetch, so a
 * naive `[...live, ...historical]` double-counts it — inflating every derived
 * stat (malicious count, top targets, attack-type breakdown). We de-duplicate
 * on the stable payload fields, keeping the live copy first (it arrives sooner).
 */
export function mergeAlerts(live: Alert[], historical: Alert[], limit = 500): Alert[] {
  const seen = new Set<string>();
  const out: Alert[] = [];
  for (const a of [...live, ...historical]) {
    const key = `${a.timestamp}|${a.source_ip}|${a.destination_ip}|${a.label}|${a.confidence}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
    if (out.length >= limit) break;
  }
  return out;
}

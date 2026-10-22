/**
 * Encode a flat object as a query string, dropping null/undefined entries so an
 * absent optional parameter does not arrive as the literal "null".
 */
export function objectToParams(object: Record<string, string | number | boolean | null | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(object)) {
    if (value === null || value === undefined) { continue; }
    params.set(key, String(value));
  }
  return params.toString();
}

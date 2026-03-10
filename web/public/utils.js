// Pure utility functions shared by app.js and tests.

/**
 * Format an ISO 8601 date string for display.
 * Returns "—" for falsy input.
 */
export function formatDate(isoString) {
  if (!isoString) return "\u2014";
  const d = new Date(isoString);
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/**
 * Escape a string for safe insertion into HTML.
 * Uses DOM textContent/innerHTML round-trip to handle all entities.
 * Returns "" for null, undefined, or empty string.
 */
export function escapeHTML(str) {
  if (str == null || str === "") return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Decode a base64 string into a Uint8Array.
 */
export function decodeBase64ToUint8Array(base64) {
  if (!base64) return new Uint8Array();
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

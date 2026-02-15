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
 * Returns "" for falsy input.
 */
export function escapeHTML(str) {
  if (!str) return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

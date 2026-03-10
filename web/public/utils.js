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
 * Normalize a raw export password from the prompt dialog.
 *
 * Returns an object with:
 * - password: the trimmed password string, or undefined if blank/null
 * - isExplicit: true when the user provided a non-empty password
 * - statusNote: suffix for the status bar message
 * - promptWasCancelled: true when the user cancelled the dialog (null input)
 */
export function normalizeExportPassword(rawPassword) {
  if (rawPassword === null) {
    return {
      password: undefined,
      isExplicit: false,
      statusNote: "",
      promptWasCancelled: true,
    };
  }
  const trimmed = rawPassword.trim();
  if (trimmed === "") {
    return {
      password: undefined,
      isExplicit: false,
      statusNote: "",
      promptWasCancelled: false,
    };
  }
  return {
    password: trimmed,
    isExplicit: true,
    statusNote: " (encrypting keys\u2026)",
    promptWasCancelled: false,
  };
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

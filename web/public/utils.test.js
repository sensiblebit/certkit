// @vitest-environment jsdom
import { describe, it, expect } from "vitest";
import { formatDate, escapeHTML } from "./utils.js";

// ---------------------------------------------------------------------------
// formatDate
// ---------------------------------------------------------------------------

describe("formatDate", () => {
  it("formats an ISO 8601 date string", () => {
    // Use midday UTC to avoid timezone-shift changing the date.
    const result = formatDate("2026-03-15T12:00:00Z");
    expect(result).toContain("2026");
    expect(result).toContain("15");
  });

  it.each([null, undefined, ""])("returns em-dash for %s", (input) => {
    expect(formatDate(input)).toBe("\u2014");
  });

  it("returns Invalid Date string for garbage input", () => {
    const result = formatDate("not-a-date");
    expect(result).toContain("Invalid");
  });

  it("handles date-only ISO string", () => {
    // Date-only strings are parsed as UTC midnight; timezone offset may
    // shift the display date, so just verify it returns a non-empty string.
    const result = formatDate("2025-06-15");
    expect(result).toContain("2025");
  });
});

// ---------------------------------------------------------------------------
// escapeHTML
// ---------------------------------------------------------------------------

describe("escapeHTML", () => {
  it("escapes angle brackets", () => {
    expect(escapeHTML("<script>alert(1)</script>")).toBe(
      "&lt;script&gt;alert(1)&lt;/script&gt;",
    );
  });

  it("escapes ampersands", () => {
    expect(escapeHTML("a & b")).toBe("a &amp; b");
  });

  it("does not escape double quotes (only needed in attributes)", () => {
    // The DOM textContent/innerHTML round-trip correctly leaves double
    // quotes unescaped — they only need escaping inside attribute values.
    expect(escapeHTML('"hello"')).toBe('"hello"');
  });

  it("passes through safe strings unchanged", () => {
    expect(escapeHTML("hello world")).toBe("hello world");
  });

  it.each([null, undefined, ""])("returns empty string for %s", (input) => {
    expect(escapeHTML(input)).toBe("");
  });

  it("handles numeric zero without treating as falsy", () => {
    expect(escapeHTML(0)).toBe("0");
  });

  it("handles mixed special characters", () => {
    const input = '<img src="x" onerror="alert(1)">';
    const result = escapeHTML(input);
    expect(result).not.toContain("<");
    expect(result).not.toContain(">");
    expect(result).toContain("&lt;");
    expect(result).toContain("&gt;");
  });
});

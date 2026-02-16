---
paths:
  - "web/**"
---

# JS/TS Testing Rules (`web/`)

Tests use [vitest](https://vitest.dev/) with jsdom for DOM-dependent tests.

```sh
cd web && npm test           # Run all JS/TS tests (vitest run)
cd web && npm run test:watch # Watch mode
```

- **Test locations**: `web/functions/api/fetch.test.ts` (proxy, 65 tests), `web/public/utils.test.js` (utilities, 13 tests).
- **Environment**: Default is `node` (`web/vitest.config.ts`). Files needing DOM APIs use `// @vitest-environment jsdom` per-file directive.
- **Fetch mocking**: Use `vi.stubGlobal("fetch", vi.fn())` for the proxy tests. Use `mockImplementation(() => Promise.resolve(new Response(...)))` — not `mockResolvedValue` — because `Response` body can only be consumed once.
- **Date testing**: `formatDate()` uses `toLocaleDateString()` which applies timezone offset. Use midday UTC times (e.g., `2026-06-15T12:00:00Z`) in test fixtures to avoid day-boundary shifts.
- **No test framework deps in Go**: JS/TS tests are separate from Go tests. vitest is a dev dependency only in `web/package.json`.

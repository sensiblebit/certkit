import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { onRequestGet, onRequestOptions, isAllowedDomain } from "./fetch";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_ORIGIN = "https://certkit.pages.dev";

/** Build a Request as the proxy would receive it. */
function makeRequest(
  targetURL: string | null,
  opts: { origin?: string | null; referer?: string | null } = {},
): Request {
  const base = new URL("https://certkit.pages.dev/api/fetch");
  if (targetURL !== null) base.searchParams.set("url", targetURL);

  const headers = new Headers();
  if (opts.origin !== null) {
    headers.set("Origin", opts.origin ?? VALID_ORIGIN);
  }
  if (opts.referer) headers.set("Referer", opts.referer);

  return new Request(base.toString(), { headers });
}

/** Invoke the GET handler with a target URL and valid origin. */
async function callGet(
  targetURL: string | null,
  opts: { origin?: string | null; referer?: string | null } = {},
): Promise<Response> {
  const request = makeRequest(targetURL, opts);
  // PagesFunction expects EventContext; we only need the request field.
  return onRequestGet({ request } as any);
}

/** Extract the JSON error message from an error response. */
async function errorMsg(resp: Response): Promise<string> {
  const body = await resp.json();
  return (body as any).error;
}

// ---------------------------------------------------------------------------
// isAllowedDomain — unit tests
// ---------------------------------------------------------------------------

describe("isAllowedDomain", () => {
  it("matches exact domain", () => {
    expect(isAllowedDomain("cacerts.digicert.com")).toBe(true);
  });

  it("matches subdomain via suffix", () => {
    expect(isAllowedDomain("crl.disa.mil")).toBe(true);
    expect(isAllowedDomain("crl.nit.disa.mil")).toBe(true);
    expect(isAllowedDomain("crl.gds.nit.disa.mil")).toBe(true);
  });

  it("is case-insensitive", () => {
    expect(isAllowedDomain("CACERTS.DIGICERT.COM")).toBe(true);
    expect(isAllowedDomain("CRL.DISA.MIL")).toBe(true);
  });

  it("rejects non-matching domain", () => {
    expect(isAllowedDomain("evil.com")).toBe(false);
    expect(isAllowedDomain("example.com")).toBe(false);
  });

  it("rejects partial suffix that is not a subdomain boundary", () => {
    // "notdisa.mil" ends with "disa.mil" as a string but is not a subdomain.
    expect(isAllowedDomain("notdisa.mil")).toBe(false);
    expect(isAllowedDomain("fakedigicert.com")).toBe(false);
  });

  it("matches suffix entries like managed.entrust.com", () => {
    expect(isAllowedDomain("sspweb.managed.entrust.com")).toBe(true);
    expect(isAllowedDomain("rootweb.managed.entrust.com")).toBe(true);
    expect(isAllowedDomain("managed.entrust.com")).toBe(true);
  });

  it("matches fpki.gov subdomains (repo, http, cite)", () => {
    expect(isAllowedDomain("repo.fpki.gov")).toBe(true);
    expect(isAllowedDomain("http.fpki.gov")).toBe(true);
    expect(isAllowedDomain("cite.fpki.gov")).toBe(true);
    expect(isAllowedDomain("fpki.gov")).toBe(true);
  });

  it("matches amazontrust.com suffix (consolidates rootca1-4, rootg2, sca, eu)", () => {
    expect(isAllowedDomain("crt.rootca1.amazontrust.com")).toBe(true);
    expect(isAllowedDomain("crt.rootca4.amazontrust.com")).toBe(true);
    expect(isAllowedDomain("crl.rootg2.amazontrust.com")).toBe(true);
    expect(isAllowedDomain("eue2m1.crt.root.eu.amazontrust.com")).toBe(true);
  });

  it("matches amznts.eu suffix (Amazon EU short domain)", () => {
    expect(isAllowedDomain("eue2m1.crt.root.amznts.eu")).toBe(true);
    expect(isAllowedDomain("eur2m1.crt.root.amznts.eu")).toBe(true);
  });

  it("matches microsoft.com suffix (www, caissuers, pkiops)", () => {
    expect(isAllowedDomain("www.microsoft.com")).toBe(true);
    expect(isAllowedDomain("caissuers.microsoft.com")).toBe(true);
    expect(isAllowedDomain("pkiops.microsoft.com")).toBe(true);
  });

  it("matches e-szigno.hu suffix (Hungarian CA, many subdomains)", () => {
    expect(isAllowedDomain("www.e-szigno.hu")).toBe(true);
    expect(isAllowedDomain("rootca2017-ca1.e-szigno.hu")).toBe(true);
    expect(isAllowedDomain("tlsrootca2023-ca.e-szigno.hu")).toBe(true);
    expect(isAllowedDomain("esmimerootca2024-ca.e-szigno.hu")).toBe(true);
  });

  it("matches telesec.de suffix (T-Systems, many subdomains)", () => {
    expect(isAllowedDomain("grcl2.crt.telesec.de")).toBe(true);
    expect(isAllowedDomain("pki0336.telesec.de")).toBe(true);
    expect(isAllowedDomain("grcl3g2.pki.telesec.de")).toBe(true);
    expect(isAllowedDomain("telesec.de")).toBe(true);
  });

  it("matches certum.pl suffix (Asseco, Poland)", () => {
    expect(isAllowedDomain("repository.certum.pl")).toBe(true);
    expect(isAllowedDomain("subca.repository.certum.pl")).toBe(true);
    expect(isAllowedDomain("sslcom.repository.certum.pl")).toBe(true);
  });

  it("matches netlock.hu suffix (Hungary)", () => {
    expect(isAllowedDomain("aia1.netlock.hu")).toBe(true);
    expect(isAllowedDomain("aia2.netlock.hu")).toBe(true);
    expect(isAllowedDomain("aia3.netlock.hu")).toBe(true);
  });

  it("matches harica.gr suffix (Greece)", () => {
    expect(isAllowedDomain("repo.harica.gr")).toBe(true);
    expect(isAllowedDomain("crt.harica.gr")).toBe(true);
    expect(isAllowedDomain("www.harica.gr")).toBe(true);
  });

  it("matches secomtrust.net suffix (Japan)", () => {
    expect(isAllowedDomain("repository.secomtrust.net")).toBe(true);
    expect(isAllowedDomain("repo2.secomtrust.net")).toBe(true);
  });

  it("matches sheca.com suffix (Shanghai CA, China)", () => {
    expect(isAllowedDomain("certs.global.sheca.com")).toBe(true);
    expect(isAllowedDomain("certs.sheca.com")).toBe(true);
    expect(isAllowedDomain("ldap2.sheca.com")).toBe(true);
  });

  it("matches new exact domain entries", () => {
    // SSL.com
    expect(isAllowedDomain("cert.ssl.com")).toBe(true);
    expect(isAllowedDomain("www.ssl.com")).toBe(true);
    // Telia
    expect(isAllowedDomain("cps.trust.telia.com")).toBe(true);
    // emSign
    expect(isAllowedDomain("repository.emsign.com")).toBe(true);
    // Actalis
    expect(isAllowedDomain("cacert.actalis.it")).toBe(true);
    // D-TRUST
    expect(isAllowedDomain("www.d-trust.net")).toBe(true);
    // PKIoverheid
    expect(isAllowedDomain("cert.pkioverheid.nl")).toBe(true);
    // WiseKey
    expect(isAllowedDomain("public.wisekey.com")).toBe(true);
    // Naver
    expect(isAllowedDomain("rca.navercloudtrust.com")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// CORS — OPTIONS handler
// ---------------------------------------------------------------------------

describe("onRequestOptions", () => {
  it("returns 204 with CORS headers", async () => {
    const request = new Request("https://certkit.pages.dev/api/fetch", {
      method: "OPTIONS",
      headers: { Origin: VALID_ORIGIN },
    });
    const resp = await onRequestOptions({ request } as any);

    expect(resp.status).toBe(204);
    expect(resp.headers.get("Access-Control-Allow-Methods")).toBe(
      "GET, OPTIONS",
    );
  });

  it("reflects allowed origin", async () => {
    const request = new Request("https://certkit.pages.dev/api/fetch", {
      method: "OPTIONS",
      headers: { Origin: VALID_ORIGIN },
    });
    const resp = await onRequestOptions({ request } as any);
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(VALID_ORIGIN);
  });

  it("falls back to default origin for unknown origin", async () => {
    const request = new Request("https://certkit.pages.dev/api/fetch", {
      method: "OPTIONS",
      headers: { Origin: "https://evil.com" },
    });
    const resp = await onRequestOptions({ request } as any);
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(VALID_ORIGIN);
  });
});

// ---------------------------------------------------------------------------
// Origin / Referer validation
// ---------------------------------------------------------------------------

describe("origin validation", () => {
  // These tests don't need fetch mocked because they fail before fetching.

  it("rejects request with no Origin and no Referer", async () => {
    const resp = await callGet("https://cacerts.digicert.com/cert.crt", {
      origin: null,
    });
    expect(resp.status).toBe(403);
    expect(await errorMsg(resp)).toMatch(/Missing Origin or Referer/);
  });

  it("rejects request with disallowed Origin", async () => {
    const resp = await callGet("https://cacerts.digicert.com/cert.crt", {
      origin: "https://evil.com",
    });
    expect(resp.status).toBe(403);
    expect(await errorMsg(resp)).toMatch(/Origin not allowed/);
  });

  it("accepts request with valid Origin", async () => {
    // Will fail at fetch (not mocked), but should pass origin check.
    // Use a disallowed domain so it fails at domain check (deterministic).
    const resp = await callGet("https://evil.com/cert.crt", {
      origin: VALID_ORIGIN,
    });
    expect(resp.status).toBe(403);
    expect(await errorMsg(resp)).toMatch(/not in the allow list/);
  });

  it("accepts request with valid Referer when Origin is absent", async () => {
    const resp = await callGet("https://evil.com/cert.crt", {
      origin: null,
      referer: "https://certkit.pages.dev/index.html",
    });
    expect(resp.status).toBe(403);
    // Passes origin check, fails at domain check.
    expect(await errorMsg(resp)).toMatch(/not in the allow list/);
  });

  it("rejects request with invalid Referer when Origin is absent", async () => {
    const resp = await callGet("https://cacerts.digicert.com/cert.crt", {
      origin: null,
      referer: "https://evil.com/page",
    });
    expect(resp.status).toBe(403);
    expect(await errorMsg(resp)).toMatch(/Origin not allowed/);
  });
});

// ---------------------------------------------------------------------------
// URL parameter validation
// ---------------------------------------------------------------------------

describe("URL parameter validation", () => {
  it("rejects missing url parameter", async () => {
    const resp = await callGet(null);
    expect(resp.status).toBe(400);
    expect(await errorMsg(resp)).toMatch(/Missing 'url'/);
  });

  it("rejects invalid URL", async () => {
    const resp = await callGet("not-a-url");
    expect(resp.status).toBe(400);
    expect(await errorMsg(resp)).toMatch(/Invalid URL/);
  });
});

// ---------------------------------------------------------------------------
// URL sanitization
// ---------------------------------------------------------------------------

describe("URL sanitization", () => {
  it("rejects URLs with username credentials", async () => {
    const resp = await callGet("https://admin@cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(400);
    expect(await errorMsg(resp)).toMatch(/credentials/);
  });

  it("rejects URLs with username:password credentials", async () => {
    const resp = await callGet(
      "https://admin:pass@cacerts.digicert.com/cert.crt",
    );
    expect(resp.status).toBe(400);
    expect(await errorMsg(resp)).toMatch(/credentials/);
  });

  it("rejects URLs with non-standard port", async () => {
    const resp = await callGet("https://cacerts.digicert.com:9090/cert.crt");
    expect(resp.status).toBe(400);
    expect(await errorMsg(resp)).toMatch(/Non-standard ports/);
  });

  it("rejects non-HTTP protocols", async () => {
    const resp = await callGet("ftp://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(400);
    expect(await errorMsg(resp)).toMatch(/Only HTTP\/HTTPS/);
  });

  it("rejects URLs with query strings", async () => {
    const resp = await callGet("https://cacerts.digicert.com/cert.crt?foo=bar");
    expect(resp.status).toBe(400);
    expect(await errorMsg(resp)).toMatch(/Query strings/);
  });

  it("rejects URLs with fragments", async () => {
    const resp = await callGet("https://cacerts.digicert.com/cert.crt#section");
    expect(resp.status).toBe(400);
    expect(await errorMsg(resp)).toMatch(/fragments/);
  });
});

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

describe("domain validation", () => {
  it("rejects disallowed domain", async () => {
    const resp = await callGet("https://evil.com/cert.crt");
    expect(resp.status).toBe(403);
    expect(await errorMsg(resp)).toMatch(/not in the allow list/);
  });

  it("includes domain name in error message", async () => {
    const resp = await callGet("https://evil.com/cert.crt");
    expect(await errorMsg(resp)).toContain("evil.com");
  });
});

// ---------------------------------------------------------------------------
// Path / extension validation
// ---------------------------------------------------------------------------

describe("path validation", () => {
  const allowed = [".crt", ".cer", ".der", ".pem", ".p7b", ".p7c", ".crl"];

  for (const ext of allowed) {
    it(`allows ${ext} extension`, async () => {
      // Stub fetch so it doesn't actually go out.
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            new Response(new Uint8Array([1, 2, 3]), { status: 200 }),
          ),
      );

      const resp = await callGet(`https://cacerts.digicert.com/cert${ext}`);
      expect(resp.status).toBe(200);

      vi.restoreAllMocks();
    });
  }

  it("allows trailing slash", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(new Uint8Array([1, 2, 3]), { status: 200 }),
        ),
    );

    const resp = await callGet("https://cacerts.digicert.com/certs/");
    expect(resp.status).toBe(200);

    vi.restoreAllMocks();
  });

  it("rejects .exe extension", async () => {
    const resp = await callGet("https://cacerts.digicert.com/file.exe");
    expect(resp.status).toBe(403);
    expect(await errorMsg(resp)).toMatch(/does not look like a certificate/);
  });

  it("rejects .js extension", async () => {
    const resp = await callGet("https://cacerts.digicert.com/script.js");
    expect(resp.status).toBe(403);
  });

  it("rejects .html extension", async () => {
    const resp = await callGet("https://cacerts.digicert.com/page.html");
    expect(resp.status).toBe(403);
  });

  it("rejects extensionless path", async () => {
    const resp = await callGet("https://cacerts.digicert.com/noext");
    expect(resp.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// Fetch behavior (mocked)
// ---------------------------------------------------------------------------

describe("fetch behavior", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns upstream body on success", async () => {
    const certBytes = new Uint8Array([0x30, 0x82, 0x01, 0x22]);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(certBytes, { status: 200 })),
    );

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(200);
    expect(resp.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(resp.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(resp.headers.get("Cache-Control")).toContain("immutable");

    const body = new Uint8Array(await resp.arrayBuffer());
    expect(body).toEqual(certBytes);
  });

  it("proxies upstream error status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 404 })),
    );

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(404);
    expect(await errorMsg(resp)).toMatch(/Upstream returned 404/);
  });

  it("returns 502 for empty upstream response", async () => {
    // Use mockImplementation to create a fresh Response per call (Response
    // body can only be consumed once, so reusing the same instance fails).
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockImplementation(() =>
          Promise.resolve(new Response(new Uint8Array(0), { status: 200 })),
        ),
    );

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(502);
    expect(await errorMsg(resp)).toMatch(/empty response/);
  });

  it("returns 413 when Content-Length exceeds limit", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(new Uint8Array([1]), {
          status: 200,
          headers: { "Content-Length": "999999999" },
        }),
      ),
    );

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(413);
    expect(await errorMsg(resp)).toMatch(/too large/);
  });

  it("returns 502 when fetch throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("network error")),
    );

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(502);
    expect(await errorMsg(resp)).toMatch(/Fetch failed/);
  });

  it("falls back from HTTPS to HTTP when HTTPS fails", async () => {
    const mockFetch = vi
      .fn()
      // First call (HTTPS) fails
      .mockRejectedValueOnce(new Error("SSL error"))
      // Second call (HTTP) succeeds
      .mockResolvedValueOnce(
        new Response(new Uint8Array([1, 2, 3]), { status: 200 }),
      );
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(200);

    // Verify the second call used http://
    expect(mockFetch).toHaveBeenCalledTimes(2);
    const secondCallURL = mockFetch.mock.calls[1][0];
    expect(secondCallURL).toMatch(/^http:\/\//);
  });

  it("does not attempt HTTP fallback for http:// URLs", async () => {
    const mockFetch = vi
      .fn()
      .mockRejectedValue(new Error("connection refused"));
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("http://crl.disa.mil/cert.p7c");
    expect(resp.status).toBe(502);

    // Only one attempt — no fallback for plain HTTP.
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// URL reconstruction — query strings must not reach upstream
// ---------------------------------------------------------------------------

describe("URL reconstruction", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches reconstructed URL without query params from raw input", async () => {
    // The handler blocks query strings, but let's verify that even the
    // reconstructed URL used for fetching contains only protocol+host+path.
    const mockFetch = vi
      .fn()
      .mockResolvedValue(
        new Response(new Uint8Array([1, 2, 3]), { status: 200 }),
      );
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(200);

    const fetchedURL = mockFetch.mock.calls[0][0];
    expect(fetchedURL).toBe("https://cacerts.digicert.com/cert.crt");
    expect(fetchedURL).not.toContain("?");
    expect(fetchedURL).not.toContain("#");
  });
});

// ---------------------------------------------------------------------------
// Redirect handling
// ---------------------------------------------------------------------------

describe("redirect handling", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("follows redirect to allowed domain", async () => {
    const mockFetch = vi
      .fn()
      // First call: redirect
      .mockResolvedValueOnce(
        new Response(null, {
          status: 301,
          headers: { Location: "https://crt.r.digicert.com/cert.crt" },
        }),
      )
      // Second call: success at redirect target
      .mockResolvedValueOnce(
        new Response(new Uint8Array([1, 2, 3]), { status: 200 }),
      );
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("blocks redirect to disallowed domain", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { Location: "https://evil.com/malware.exe" },
      }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(502);
    expect(await errorMsg(resp)).toMatch(/Fetch failed/);
  });

  it("handles redirect without Location header", async () => {
    // Use http:// to avoid HTTPS→HTTP fallback (single attempt).
    const mockFetch = vi.fn().mockResolvedValueOnce(
      // 301 with no Location — safeFetch returns the response as-is,
      // which is not ok (301), so the handler treats it as an upstream error.
      new Response(null, { status: 301 }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("http://crl.disa.mil/cert.p7c");
    expect(resp.status).toBe(301);
    expect(await errorMsg(resp)).toMatch(/Upstream returned 301/);
  });

  it("fails after too many redirects", async () => {
    // 7 consecutive redirects (MAX_REDIRECTS is 5, loop runs 6 times)
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(null, {
        status: 302,
        headers: { Location: "https://cacerts.digicert.com/cert.crt" },
      }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(502);
    expect(await errorMsg(resp)).toMatch(/Fetch failed/);
  });

  it("blocks redirect to non-HTTP protocol", async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { Location: "ftp://cacerts.digicert.com/cert.crt" },
      }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(502);
  });

  it("sanitizes redirect target URL (strips query strings)", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 301,
          headers: {
            Location: "https://crt.r.digicert.com/cert.crt?tracking=123",
          },
        }),
      )
      .mockResolvedValueOnce(
        new Response(new Uint8Array([1, 2, 3]), { status: 200 }),
      );
    vi.stubGlobal("fetch", mockFetch);

    const resp = await callGet("https://cacerts.digicert.com/cert.crt");
    expect(resp.status).toBe(200);

    // The second fetch should be the sanitized redirect URL without query.
    const redirectFetchURL = mockFetch.mock.calls[1][0];
    expect(redirectFetchURL).toBe("https://crt.r.digicert.com/cert.crt");
    expect(redirectFetchURL).not.toContain("?");
  });
});

// ---------------------------------------------------------------------------
// CORS headers on error responses
// ---------------------------------------------------------------------------

describe("CORS headers on errors", () => {
  it("includes CORS headers on 400 errors", async () => {
    const resp = await callGet("not-a-url");
    expect(resp.status).toBe(400);
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(VALID_ORIGIN);
  });

  it("includes CORS headers on 403 errors", async () => {
    const resp = await callGet("https://evil.com/cert.crt");
    expect(resp.status).toBe(403);
    expect(resp.headers.get("Access-Control-Allow-Origin")).toBe(VALID_ORIGIN);
  });

  it("error responses have JSON content type", async () => {
    const resp = await callGet("not-a-url");
    expect(resp.headers.get("Content-Type")).toBe("application/json");
  });
});

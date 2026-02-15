// CORS proxy for AIA certificate fetching.
//
// This is NOT a general-purpose proxy. It only allows fetching from known
// Certificate Authority AIA/CRL domains and enforces strict response limits.
//
// Usage: GET /api/fetch?url=https://cacerts.digicert.com/...

const MAX_RESPONSE_SIZE = 256 * 1024; // 256KB — certs are small

// Allowed origins for CORS. The proxy only serves requests from these origins.
const ALLOWED_ORIGINS: string[] = [
  "https://certkit.pages.dev",
  "http://localhost:8080",  // local dev (make wasm-serve)
  "http://localhost:8788",  // wrangler pages dev
];

function corsHeaders(origin: string | null): Record<string, string> {
  const allowed = origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

// Allowed hostname suffixes for CA AIA/CRL endpoints.
// Only requests to these domains are proxied. Add entries as needed.
const ALLOWED_DOMAINS: string[] = [
  // DigiCert
  "cacerts.digicert.com",
  "crt.r.digicert.com",
  // Let's Encrypt / ISRG
  "letsencrypt.org",
  "i.lencr.org",
  "r.lencr.org",
  "x.lencr.org",
  // Sectigo / Comodo
  "crt.sectigo.com",
  "crt.comodoca.com",
  "crt.usertrust.com",
  // GlobalSign
  "secure.globalsign.com",
  // GoDaddy / Starfield
  "certificates.godaddy.com",
  "certificates.starfieldtech.com",
  // Entrust
  "aia.entrust.net",
  // Amazon Trust Services
  "crt.rootca1.amazontrust.com",
  "crt.rootg2.amazontrust.com",
  "crt.sca1b.amazontrust.com",
  "crt.sca0a.amazontrust.com",
  // Google Trust Services
  "pki.goog",
  "i.pki.goog",
  // Microsoft / Azure
  "www.microsoft.com",
  "pkiops.microsoft.com",
  // Cloudflare
  "cacerts.cloudflare.com",
  // Apple
  "certs.apple.com",
  // Buypass
  "crt.buypass.no",
  // SwissSign
  "aia.swisssign.net",
  // QuoVadis
  "trust.quovadisglobal.com",
  // VeriSign / Symantec (legacy, now DigiCert)
  "svrintl-g3-aia.verisign.com",
  // GeoTrust / RapidSSL (legacy, now DigiCert)
  "rapidssl-aia.geotrust.com",
  // E-Tugra (Turkish CA)
  "www.e-tugra.com",
  // US Federal PKI
  "repo.fpki.gov",
  // Swiss Federal PKI
  "www.pki.admin.ch",
  // TBS Internet
  "crt.tbs-internet.com",
  "crt.tbs-x509.com",
];

function isAllowedDomain(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return ALLOWED_DOMAINS.some(
    (domain) => lower === domain || lower.endsWith("." + domain)
  );
}

export const onRequestOptions: PagesFunction = async ({ request }) => {
  const origin = request.headers.get("Origin");
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
};

export const onRequestGet: PagesFunction = async ({ request }) => {
  const origin = request.headers.get("Origin");
  const referer = request.headers.get("Referer");

  // Reject requests not originating from an allowed origin.
  // Check both Origin (set by fetch/XHR) and Referer (fallback).
  const refererOrigin = referer ? new URL(referer).origin : null;
  if (!origin && !refererOrigin) {
    return errorResponse(403, "Missing Origin or Referer header", null);
  }
  if (
    (origin && !ALLOWED_ORIGINS.includes(origin)) ||
    (!origin && refererOrigin && !ALLOWED_ORIGINS.includes(refererOrigin))
  ) {
    return errorResponse(403, "Origin not allowed", origin);
  }

  const reqURL = new URL(request.url);
  const targetURL = reqURL.searchParams.get("url");

  if (!targetURL) {
    return errorResponse(400, "Missing 'url' query parameter", origin);
  }

  let parsed: URL;
  try {
    parsed = new URL(targetURL);
  } catch {
    return errorResponse(400, "Invalid URL", origin);
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return errorResponse(400, "Only HTTP/HTTPS URLs are allowed", origin);
  }

  if (!isAllowedDomain(parsed.hostname)) {
    return errorResponse(
      403,
      `Domain '${parsed.hostname}' is not in the allow list. ` +
        "This proxy only fetches from known CA AIA endpoints.",
      origin
    );
  }

  // Only allow paths that look like certificate files
  const path = parsed.pathname.toLowerCase();
  if (
    !path.endsWith(".crt") &&
    !path.endsWith(".cer") &&
    !path.endsWith(".der") &&
    !path.endsWith(".pem") &&
    !path.endsWith(".p7b") &&
    !path.endsWith(".p7c") &&
    !path.endsWith("/") &&
    !path.endsWith(".crl")
  ) {
    return errorResponse(403, "URL path does not look like a certificate file", origin);
  }

  // Try the URL as given. If HTTPS fails with an SSL error, fall back to HTTP
  // (many CA AIA endpoints only serve plain HTTP).
  const urlsToTry = [targetURL];
  if (parsed.protocol === "https:") {
    urlsToTry.push(targetURL.replace(/^https:/, "http:"));
  }

  let lastStatus = 502;
  let lastMessage = "All fetch attempts failed";

  for (const tryURL of urlsToTry) {
    try {
      const upstream = await fetch(tryURL, {
        headers: { "User-Agent": "certkit AIA proxy/1.0" },
        redirect: "follow",
      });

      if (!upstream.ok) {
        lastStatus = upstream.status;
        lastMessage = `Upstream returned ${upstream.status}`;
        continue; // try next URL (HTTP fallback)
      }

      const contentLength = upstream.headers.get("content-length");
      if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_SIZE) {
        return errorResponse(413, "Response too large", origin);
      }

      const body = await upstream.arrayBuffer();
      if (body.byteLength > MAX_RESPONSE_SIZE) {
        return errorResponse(413, "Response too large", origin);
      }

      if (body.byteLength === 0) {
        lastStatus = 502;
        lastMessage = "Upstream returned empty response";
        continue;
      }

      const responseHeaders = new Headers(corsHeaders(origin));
      responseHeaders.set("Content-Type", "application/octet-stream");
      responseHeaders.set("Content-Length", body.byteLength.toString());
      responseHeaders.set("X-Content-Type-Options", "nosniff");
      // Cache certificate responses for 1 hour — they rarely change
      responseHeaders.set("Cache-Control", "public, max-age=3600");

      return new Response(body, { status: 200, headers: responseHeaders });
    } catch {
      lastStatus = 502;
      lastMessage = `Fetch failed for ${tryURL}`;
    }
  }

  return errorResponse(lastStatus, lastMessage, origin);
};

function errorResponse(status: number, message: string, origin: string | null): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
  });
}

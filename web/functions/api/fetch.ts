// CORS proxy for AIA certificate fetching.
//
// This is NOT a general-purpose proxy. It only allows fetching from known
// Certificate Authority AIA/CRL domains and enforces strict response limits.
//
// Usage: GET /api/fetch?url=https://cacerts.digicert.com/...

const MAX_RESPONSE_SIZE = 256 * 1024; // 256KB — certs are small
const UPSTREAM_TIMEOUT_MS = 8_000;

// Allowed origins for CORS. The proxy only serves requests from these origins.
const ALLOWED_ORIGINS: string[] = [
  "https://certkit.pages.dev",
  "http://localhost:8080", // local dev (make wasm-serve)
  "http://localhost:8788", // wrangler pages dev
];

function corsHeaders(origin: string | null): Record<string, string> {
  const allowed =
    origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    Vary: "Origin",
  };
}

// Allowed hostname suffixes for CA AIA/CRL endpoints.
// Only requests to these domains are proxied. Add entries as needed.
//
// Source: CA Issuers AIA URLs from all time-valid Mozilla-trusted intermediate
// certificates, queried via crt.sh/CCADB (trust_context_id=5). Suffix entries
// (e.g., "amazontrust.com") match any subdomain.
const ALLOWED_DOMAINS: string[] = [
  // ── Major Commercial CAs ──
  // Suffix entries match the domain itself and all subdomains.
  // The file extension check (.crt, .cer, .der, .pem, .p7b, .p7c, .crl)
  // provides a strong secondary filter against non-certificate requests.

  // DigiCert (includes Thawte, GeoTrust, RapidSSL, VeriSign, Symantec)
  "digicert.com",
  "digicert.cn",
  "verisign.com",
  "geotrust.com",
  "thawte.com",
  "symauth.com",

  // Sectigo / Comodo / USERTrust
  "sectigo.com",
  "comodoca.com",
  "comodo.net",
  "usertrust.com",
  "trust-provider.com",

  // Let's Encrypt / ISRG
  "letsencrypt.org",
  "lencr.org",

  // GlobalSign
  "globalsign.com",

  // GoDaddy / Starfield
  "godaddy.com",
  "starfieldtech.com",

  // Entrust
  "entrust.net",
  "entrust.com",

  // Amazon Trust Services
  "amazontrust.com",
  "amznts.eu",

  // Google Trust Services
  "pki.goog",

  // Microsoft
  "microsoft.com",

  // Cloudflare
  "cloudflare.com",

  // Apple
  "apple.com",

  // SSL.com
  "ssl.com",
  "sslcom.cn",
  "ss2.us",

  // Certum (Asseco / Unizeto, Poland)
  "certum.pl",
  "elektronicznypodpis.pl",

  // HARICA (Hellenic Academic and Research Institutions CA, Greece)
  "harica.gr",

  // IdenTrust
  "identrust.com",

  // Buypass (Norway)
  "buypass.no",

  // SwissSign
  "swisssign.net",
  "swisssign.ch",

  // QuoVadis (DigiCert subsidiary)
  "quovadisglobal.com",

  // Telia / TeliaSonera (Finland/Nordics)
  "telia.com",
  "teliasonera.com",

  // Trustwave / SecureTrust
  "trustwave.com",
  "securetrust.com",
  "sslsecuretrust.com",

  // D-TRUST (Bundesdruckerei, Germany)
  "d-trust.net",

  // T-Systems / Deutsche Telekom
  "telesec.de",
  "telekom.de",

  // DFN-Verein (German Research Network)
  "dfn.de",

  // Atos (France)
  "atos.net",

  // emSign (eMudhra, India)
  "emsign.com",

  // Actalis (Italy)
  "actalis.it",

  // SECOM Trust Systems (Japan)
  "secomtrust.net",

  // Cybertrust Japan
  "cybertrust.ne.jp",

  // TWCA (Taiwan)
  "twca.com.tw",
  "epki.com.tw",

  // Chunghwa Telecom (Taiwan)
  "hinet.net",

  // WiseKey / OISTE (Switzerland)
  "wisekey.com",

  // AffirmTrust (now Entrust)
  "affirmtrust.com",

  // NetLock (Hungary)
  "netlock.hu",

  // Microsec / e-Szigno (Hungary)
  "e-szigno.hu",

  // Certigna / Dhimyotis (France)
  "certigna.fr",
  "certigna.com",
  "dhimyotis.com",

  // Firmaprofesional (Spain)
  "firmaprofesional.com",

  // FNMT (Fabrica Nacional de Moneda y Timbre, Spain)
  "fnmt.es",

  // ACCV (Spain)
  "accv.es",

  // ANF AC (Spain)
  "anf.es",

  // CertSign (Romania)
  "certsign.ro",

  // Disig (Slovakia)
  "disig.sk",

  // DigitalSign (Portugal)
  "digitalsign.pt",

  // Certainly (Denmark)
  "certainly.com",

  // GlobalTrust (Austria)
  "globaltrust.eu",

  // PKIoverheid (Netherlands)
  "pkioverheid.nl",

  // Naver Cloud Trust (South Korea)
  "navercloudtrust.com",
  "navercorp.com",

  // GDCA (Guangdong CA, China)
  "gdca.com.cn",

  // CFCA (China Financial CA)
  "cfca.com.cn",

  // BJCA (Beijing CA, China)
  "bjca.cn",

  // Shanghai Electronic CA (SHECA, China)
  "sheca.com",

  // iTrusChina
  "itrus.com.cn",

  // TrustAsia (WoTrus subsidiary, China)
  "trustasia.com",
  "trustca.net",

  // LiteSSL (Asseco/Certum white-label)
  "litessl.com",

  // E-Tugra (Turkey)
  "e-tugra.com",

  // KAMUSM (Turkey)
  "kamusm.gov.tr",

  // TunTrust (Tunisia)
  "tuntrust.tn",

  // Hong Kong Post
  "hongkongpost.gov.hk",

  // Hongkong eCert (HKSAR Government)
  "ecert.gov.hk",

  // LawTrust (South Africa)
  "lawtrust.co.za",

  // Hungarian Government PKI
  "kgyhsz.gov.hu",

  // Siemens (corporate PKI)
  "siemens.com",

  // E.ON / Uniper (corporate PKI)
  "eon.com",
  "uniper.energy",
  "uniperapps.com",

  // ── US Federal PKI (.gov / .mil) ──

  "fpki.gov",
  "disa.mil",
  "treas.gov",
  "treasury.gov",
  "state.gov",
  "uspto.gov",
  "va.gov",

  // ── FPKI Shared Service Providers ──

  // WidePoint / ORC PKI
  "orc.com",
  "xpki.com",

  // ── FPKI Bridge Participants ──

  "certipath.com",
  "boeing.com",
  "lmco.com",
  "northropgrumman.com",
  "rtx.com",
  "evincible.com",
  "carillon.ca",
  "carillonfedserv.com",
  "strac.org",
  "fti.org",
  "makeidentitysafe.com",
  "ssp-strong-id.net",
  "docusign.net",

  // ── Non-US Government PKI ──

  // Swiss Federal PKI
  "admin.ch",
  // Bavarian State PKI
  "bayern.de",
  // TBS Internet
  "tbs-internet.com",
  "tbs-x509.com",
];

export function isAllowedDomain(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return ALLOWED_DOMAINS.some(
    (domain) => lower === domain || lower.endsWith("." + domain),
  );
}

// Follows redirects manually, re-validating each target against the domain
// allow list. Prevents open redirects on allowed domains from bouncing to
// arbitrary URLs.
const MAX_REDIRECTS = 5;

type SafeFetchResult = {
  response: Response;
  release: () => void;
};

async function safeFetch(url: string): Promise<SafeFetchResult> {
  let currentURL = url;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
    const release = (): void => {
      clearTimeout(timer);
      controller.abort();
    };

    let resp: Response;
    try {
      resp = await fetch(currentURL, {
        headers: { "User-Agent": "certkit AIA proxy/1.0" },
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      release();
      throw err;
    }

    // Not a redirect — return as-is.
    if (resp.status < 300 || resp.status >= 400) {
      return { response: resp, release };
    }

    const location = resp.headers.get("Location");
    if (!location) {
      return { response: resp, release };
    }

    const target = new URL(location, currentURL);
    if (target.protocol !== "https:" && target.protocol !== "http:") {
      release();
      throw new Error("Redirect to non-HTTP protocol");
    }
    if (!isAllowedDomain(target.hostname)) {
      release();
      throw new Error(`Redirect to disallowed domain '${target.hostname}'`);
    }

    // Sanitize redirect URL — only keep protocol, host, and path.
    currentURL = `${target.protocol}//${target.hostname}${target.pathname}`;
    release();
  }

  throw new Error("Too many redirects");
}

function isAbortError(err: unknown): boolean {
  const anyErr = err as { name?: unknown } | null | undefined;
  return anyErr?.name === "AbortError";
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

  // Block credentials in URL
  if (parsed.username || parsed.password) {
    return errorResponse(400, "URLs with credentials are not allowed", origin);
  }

  // Block non-standard ports — CA AIA endpoints use default ports only
  if (parsed.port) {
    return errorResponse(400, "Non-standard ports are not allowed", origin);
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return errorResponse(400, "Only HTTP/HTTPS URLs are allowed", origin);
  }

  // Block query strings and fragments — AIA URLs are static file paths
  if (parsed.search || parsed.hash) {
    return errorResponse(
      400,
      "Query strings and fragments are not allowed",
      origin,
    );
  }

  if (!isAllowedDomain(parsed.hostname)) {
    return errorResponse(
      403,
      `Domain '${parsed.hostname}' is not in the allow list. ` +
        "This proxy only fetches from known CA AIA endpoints.",
      origin,
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
    return errorResponse(
      403,
      "URL path does not look like a certificate file",
      origin,
    );
  }

  // Reconstruct from validated components — never forward the raw input URL.
  const sanitizedURL = `${parsed.protocol}//${parsed.hostname}${parsed.pathname}`;

  // Try the URL as given. If HTTPS fails with an SSL error, fall back to HTTP
  // (many CA AIA endpoints only serve plain HTTP).
  const urlsToTry = [sanitizedURL];
  if (parsed.protocol === "https:") {
    urlsToTry.push(`http://${parsed.hostname}${parsed.pathname}`);
  }

  let lastStatus = 502;
  let lastMessage = "All fetch attempts failed";

  for (const tryURL of urlsToTry) {
    try {
      const { response: upstream, release } = await safeFetch(tryURL);

      try {
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
        // Cache forever — AIA certificates are immutable (same URL = same cert)
        responseHeaders.set(
          "Cache-Control",
          "public, max-age=31536000, immutable",
        );

        return new Response(body, { status: 200, headers: responseHeaders });
      } finally {
        release();
      }
    } catch (err) {
      if (isAbortError(err)) {
        lastStatus = 504;
        lastMessage = `Upstream fetch timed out after ${UPSTREAM_TIMEOUT_MS}ms for ${tryURL}`;
        continue;
      }
      lastStatus = 502;
      lastMessage = `Fetch failed for ${tryURL}`;
    }
  }

  return errorResponse(lastStatus, lastMessage, origin);
};

function errorResponse(
  status: number,
  message: string,
  origin: string | null,
): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
  });
}

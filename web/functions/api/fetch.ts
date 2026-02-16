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

  // DigiCert (includes Thawte, GeoTrust, RapidSSL, VeriSign, Symantec)
  "cacerts.digicert.com",
  "cacerts.digicert.cn", // DigiCert China
  "crt.r.digicert.com",
  "ssp-aia.digicert.com",
  "ssp-crl.digicert.com",
  "ssp-sia.digicert.com",
  "onsite-crl.pki.digicert.com",
  "svrintl-g3-aia.verisign.com",
  "rapidssl-aia.geotrust.com",
  "symauth.com", // suffix: pki-crl, tscp-crl, tscp-aia, tscp-sia subdomains

  // Sectigo / Comodo / USERTrust
  "crt.sectigo.com",
  "crt.comodoca.com",
  "crt.comodo.net",
  "crt.usertrust.com",
  "crt.trust-provider.com",

  // Let's Encrypt / ISRG
  "letsencrypt.org",
  "i.lencr.org",
  "r.lencr.org",
  "x.lencr.org",

  // GlobalSign
  "secure.globalsign.com",

  // GoDaddy / Starfield
  "certificates.godaddy.com",
  "certs.godaddy.com",
  "certificates.starfieldtech.com",
  "certs.starfieldtech.com",

  // Entrust
  "aia.entrust.net",
  "managed.entrust.com", // suffix: Entrust Federal SSP subdomains

  // Amazon Trust Services — suffix covers crt.rootca1-4, crt.rootg2,
  // crt.sca0a, crt.sca1b, crl.rootca1, crl.rootg2, and EU subdomains.
  "amazontrust.com",
  "amznts.eu", // suffix: eue2m1/eue3m1/eur2m1.crt.root.amznts.eu

  // Google Trust Services
  "pki.goog",
  "i.pki.goog",

  // Microsoft — suffix covers www, caissuers, pkiops subdomains.
  "microsoft.com",

  // Cloudflare
  "cacerts.cloudflare.com",

  // Apple
  "certs.apple.com",

  // SSL.com
  "cert.ssl.com",
  "www.ssl.com",
  "crt.sslcom.cn", // SSL.com China
  "x.ss2.us",

  // Certum (Asseco / Unizeto, Poland)
  // suffix: repository, subca.repository, sslcom.repository,
  // trustasia.repository, cdp.elektronicznypodpis subdomains.
  "certum.pl",
  "elektronicznypodpis.pl",

  // HARICA (Hellenic Academic and Research Institutions CA, Greece)
  "harica.gr", // suffix: repo, crt, www subdomains

  // IdenTrust
  "apps.identrust.com",
  "validation.identrust.com",

  // Buypass (Norway)
  "crt.buypass.no",

  // SwissSign — suffix covers aia.swisssign.net and bare domain.
  "swisssign.net",
  "swisssign.ch", // aia.swisssign.ch

  // QuoVadis (DigiCert subsidiary)
  "trust.quovadisglobal.com",

  // Telia / TeliaSonera (Finland/Nordics)
  "cps.trust.telia.com",
  "repository.trust.teliasonera.com",
  "ca.trust.teliasonera.com",

  // Trustwave / SecureTrust
  "ssl.trustwave.com",
  "certs.securetrust.com",
  "certs.sslsecuretrust.com",

  // D-TRUST (Bundesdruckerei, Germany)
  "www.d-trust.net",

  // T-Systems / Deutsche Telekom — suffix covers grcl2.crt, grcl3.crt,
  // tssmer21.crt, tssmrr23.crt, tstlser20.crt, tstlsrr23.crt, pki,
  // pki0336, grcl2g2.pki, grcl3g2.pki, grcl2 subdomains.
  "telesec.de",
  "telekom.de", // suffix: crt-cpki, corporate-pki subdomains

  // DFN-Verein (German Research Network)
  "cdp1.pca.dfn.de",
  "cdp2.pca.dfn.de",

  // Atos (France)
  "pki.atos.net",

  // emSign (eMudhra, India)
  "repository.emsign.com",

  // Actalis (Italy)
  "cacert.actalis.it",

  // SECOM Trust Systems (Japan)
  "secomtrust.net", // suffix: repository, repo2 subdomains

  // Cybertrust Japan
  "rtcrl.cybertrust.ne.jp",

  // TWCA (Taiwan)
  "sslserver.twca.com.tw",
  "epki.com.tw",

  // Chunghwa Telecom (Taiwan)
  "eca.hinet.net",

  // WiseKey / OISTE (Switzerland)
  "public.wisekey.com",

  // AffirmTrust (now Entrust)
  "ocsp.affirmtrust.com",

  // NetLock (Hungary) — suffix covers aia1, aia2, aia3 subdomains.
  "netlock.hu",

  // Microsec / e-Szigno (Hungary) — suffix covers rootca2009-ca1-3,
  // rootca2017-ca1-3, tlsrootca2023-ca, tlsrootca2025-ca,
  // etlsrootca2024-ca, esmimerootca2024-ca, www subdomains.
  "e-szigno.hu",

  // Certigna / Dhimyotis (France)
  "autorite.certigna.fr",
  "cert.certigna.com",
  "autorite.dhimyotis.com",

  // Firmaprofesional (Spain)
  "crl.firmaprofesional.com",

  // FNMT (Fabrica Nacional de Moneda y Timbre, Spain)
  "www.cert.fnmt.es",

  // ACCV (Agencia de Tecnologia y Certificacion Electronica, Spain)
  "www.accv.es",

  // ANF AC (Spain)
  "www.anf.es",

  // CertSign (Romania)
  "certsign.ro", // suffix: www, pkipro subdomains

  // Disig (Slovakia)
  "disig.sk", // suffix: www, cdp subdomains

  // DigitalSign (Portugal)
  "digitalsign.pt", // suffix: root-ecdsa, root-rsa subdomains

  // Certainly (Formerly SSC, Denmark)
  "certainly.com", // suffix: root-e1, root-r1 subdomains

  // GlobalTrust (Austria)
  "service.globaltrust.eu",

  // PKIoverheid (Netherlands)
  "cert.pkioverheid.nl",

  // Naver Cloud Trust (South Korea)
  "rca.navercloudtrust.com",
  "rca.navercorp.com",

  // GDCA (Guangdong CA, China)
  "www.gdca.com.cn",

  // CFCA (China Financial CA)
  "gtc.cfca.com.cn",

  // BJCA (Beijing CA, China)
  "repo.bjca.cn",

  // Shanghai Electronic CA (SHECA, China)
  "sheca.com", // suffix: certs.global, certs, ldap2 subdomains

  // iTrusChina
  "wtca-cafiles.itrus.com.cn",

  // TrustAsia (WoTrus subsidiary, China)
  "ica.wt.trustasia.com",
  "ica.oem.trustca.net",

  // LiteSSL (Asseco/Certum white-label)
  "ica.litessl.com",
  "ica-pro.litessl.com",

  // E-Tugra (Turkey)
  "www.e-tugra.com",

  // KAMUSM (Turkey)
  "depo.kamusm.gov.tr",

  // TunTrust (Tunisia)
  "www.tuntrust.tn",

  // Hong Kong Post
  "www1.hongkongpost.gov.hk",

  // Hongkong eCert (HKSAR Government)
  "www1.ecert.gov.hk",

  // LawTrust (South Africa)
  "www.lawtrust.co.za",

  // Hungarian Government PKI
  "aia.kgyhsz.gov.hu",

  // Siemens (corporate PKI)
  "ah.siemens.com",

  // E.ON / Uniper (corporate PKI)
  "pki.intranet.eon.com",
  "pki.intranet.uniper.energy",
  "pkicdp.uniperapps.com",

  // ── US Federal PKI (.gov / .mil) ──

  // FPKI repository and test infra (GSA) — suffix covers repo.fpki.gov,
  // http.fpki.gov, cite.fpki.gov (conformance test environment).
  "fpki.gov",
  // US DoD PKI (DISA) — suffix covers crl.disa.mil, crl.nit.disa.mil,
  // crl.gds.disa.mil, crl.gds.nit.disa.mil, and future subdomains.
  "disa.mil",
  // US Treasury PKI SSP (serves DHS, VA, NASA, SSA, Treasury OCIO)
  "pki.treas.gov",
  "pki.treasury.gov",
  // US Department of State
  "crls.pki.state.gov",
  // US Patent and Trademark Office
  "ipki.uspto.gov",
  // US Department of Veterans Affairs
  "crl.pki.va.gov",

  // ── FPKI Shared Service Providers ──

  // WidePoint / ORC PKI
  "crl-server.orc.com",
  "eva.orc.com",
  "eca.orc.com",
  "crl.xca.xpki.com",

  // ── FPKI Bridge Participants ──

  // CertiPath Bridge — suffix covers crl. and aia. subdomains.
  "certipath.com",
  // Defense contractors
  "crl.boeing.com",
  "crl.external.lmco.com",
  "certdata.northropgrumman.com",
  "pki.rtx.com",
  // Exostar
  "www.fis.evincible.com",
  // Carillon (Canadian FPKI bridge partner)
  "pub.carillon.ca",
  "pub.carillonfedserv.com",
  // STRAC / Foundation for Trusted Identity
  "pki.strac.org",
  "pki.fti.org",
  // DirectTrust SAFE Identity Bridge — suffix covers crl. and aia.
  "makeidentitysafe.com",
  // Verizon SSP
  "sia1.ssp-strong-id.net",
  // DocuSign Federal
  "crl.dsf.docusign.net",

  // ── Non-US Government PKI ──

  // Swiss Federal PKI
  "www.pki.admin.ch",
  // Bavarian State PKI
  "www.pki.bayern.de",
  // TBS Internet
  "crt.tbs-internet.com",
  "crt.tbs-x509.com",
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

async function safeFetch(url: string): Promise<Response> {
  let currentURL = url;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const resp = await fetch(currentURL, {
      headers: { "User-Agent": "certkit AIA proxy/1.0" },
      redirect: "manual",
    });

    // Not a redirect — return as-is.
    if (resp.status < 300 || resp.status >= 400) {
      return resp;
    }

    const location = resp.headers.get("Location");
    if (!location) {
      return resp;
    }

    const target = new URL(location, currentURL);
    if (target.protocol !== "https:" && target.protocol !== "http:") {
      throw new Error("Redirect to non-HTTP protocol");
    }
    if (!isAllowedDomain(target.hostname)) {
      throw new Error(`Redirect to disallowed domain '${target.hostname}'`);
    }

    // Sanitize redirect URL — only keep protocol, host, and path.
    currentURL = `${target.protocol}//${target.hostname}${target.pathname}`;
  }

  throw new Error("Too many redirects");
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
      const upstream = await safeFetch(tryURL);

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
    } catch {
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

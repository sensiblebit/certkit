import { formatDate, escapeHTML, normalizeExportPassword } from "./utils.js";
import {
  readResponseBytesWithLimit,
  validateUploadSizes,
} from "./browser_io.js";

// DOM references — Scan page
const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const passwordsInput = document.getElementById("passwords");
const statusBar = document.getElementById("status-bar");
const statusText = document.getElementById("status-text");
const progressContainer = document.getElementById("progress-container");
const progressFill = document.getElementById("progress-fill");
const progressLabel = document.getElementById("progress-label");
const resultsSection = document.getElementById("results-section");
const summaryDiv = document.getElementById("summary");
const certTableContainer = document.getElementById("cert-table-container");
const resultsBody = document.getElementById("results-body");
const keysSection = document.getElementById("keys-section");
const keysBody = document.getElementById("keys-body");
const warningsSection = document.getElementById("warnings-section");
const warningsList = document.getElementById("warnings-list");
const exportBtn = document.getElementById("export-btn");
const resetBtn = document.getElementById("reset-btn");
const filtersDiv = document.getElementById("filters");
const filterExpired = document.getElementById("filter-expired");
const filterUnmatched = document.getElementById("filter-unmatched");
const filterUntrusted = document.getElementById("filter-untrusted");
const selectAll = document.getElementById("select-all");
const scanAllowPrivateNetwork = document.getElementById(
  "scan-allow-private-network",
);

// DOM references — Inspect page
const inspectDropZone = document.getElementById("inspect-drop-zone");
const inspectFileInput = document.getElementById("inspect-file-input");
const inspectPasswordsInput = document.getElementById("inspect-passwords");
const inspectAllowPrivateNetwork = document.getElementById(
  "inspect-allow-private-network",
);
const inspectStatusBar = document.getElementById("inspect-status");
const inspectStatusText = document.getElementById("inspect-status-text");
const inspectResultsSection = document.getElementById("inspect-results");
const inspectCards = document.getElementById("inspect-cards");
const inspectResetBtn = document.getElementById("inspect-reset-btn");

// DOM references — Page tabs
const pageScan = document.getElementById("page-scan");
const pageInspect = document.getElementById("page-inspect");

// State
let wasmReady = false;
let aiaComplete = false;
let processing = false;
let activePage = "scan";
const selectedSKIs = new Set();
const certSort = { column: "expiry", direction: "desc" };
const keySort = { column: "match", direction: "desc" };
let activeCategory = "leaf";
let selectedDetailSKI = null;
let selectedKeyDetailSKI = null;

// Status icons for validation checks
const STATUS_ICONS = {
  pass: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  fail: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
  warn: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
};

// certkitFetchURL is called from Go (WASM) to fetch AIA certificates.
// Tries direct fetch first, then falls back to our own /api/fetch proxy
// (same-origin, no CORS issues).
window.certkitFetchURL = async function (url, timeoutMs = 10000) {
  const fetchResponseWithTimeout = async (targetURL) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(targetURL, { signal: controller.signal });
      return {
        resp,
        controller,
        done() {
          clearTimeout(timer);
        },
      };
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  };

  // 1. Try direct fetch (works if CA serves CORS headers)
  try {
    const direct = await fetchResponseWithTimeout(url);
    try {
      if (direct.resp.ok) {
        const data = await readResponseBytesWithLimit(direct.resp, {
          controller: direct.controller,
        });
        console.log("certkit: AIA direct fetch succeeded:", url);
        return data;
      }
    } finally {
      direct.done();
    }
  } catch (e) {
    console.log("certkit: AIA direct fetch failed:", url, e.message);
  }

  // 2. Proxy through our own /api/fetch endpoint
  const proxiedURL = "/api/fetch?url=" + encodeURIComponent(url);
  console.log("certkit: AIA proxy fetch:", proxiedURL);
  const proxied = await fetchResponseWithTimeout(proxiedURL);
  try {
    const data = await readResponseBytesWithLimit(proxied.resp, {
      controller: proxied.controller,
    });
    if (!proxied.resp.ok) {
      const body = new TextDecoder().decode(data);
      throw new Error(`Proxy returned ${proxied.resp.status}: ${body}`);
    }
    console.log("certkit: AIA proxy fetch succeeded for", url);
    return data;
  } finally {
    proxied.done();
  }
};

// --- WASM Loading ---

async function loadWasm() {
  showStatus("Loading WASM module...");

  const go = new Go();
  let result;
  if (typeof WebAssembly.instantiateStreaming === "function") {
    result = await WebAssembly.instantiateStreaming(
      fetch("certkit.wasm"),
      go.importObject,
    );
  } else {
    const resp = await fetch("certkit.wasm");
    const bytes = await resp.arrayBuffer();
    result = await WebAssembly.instantiate(bytes, go.importObject);
  }

  go.run(result.instance);
  wasmReady = true;
  hideStatus();

  // Show version and build year from WASM build.
  const v = window.certkitVersion;
  if (v && v !== "dev") {
    document.getElementById("version").textContent = v;
  }
  const y = window.certkitBuildYear;
  if (y) {
    document.getElementById("build-year").textContent = y;
  }
}

loadWasm().catch((err) => {
  showStatus(`Failed to load WASM: ${err.message}`, true);
});

// --- Page-level Tabs (Scan / Inspect) ---

function switchPage(page) {
  activePage = page;
  for (const btn of document.querySelectorAll(".page-tab")) {
    const isActive = btn.dataset.page === page;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-selected", String(isActive));
  }
  pageScan.hidden = page !== "scan";
  pageInspect.hidden = page !== "inspect";
}

for (const btn of document.querySelectorAll(".page-tab")) {
  btn.addEventListener("click", () => switchPage(btn.dataset.page));
}

// --- Drop Zone (Scan) ---

dropZone.addEventListener("click", () => fileInput.click());

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragging");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("dragging");
});

dropZone.addEventListener("drop", async (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragging");
  if (!wasmReady || processing) return;

  const items = e.dataTransfer.items;
  if (items) {
    const files = await collectFiles(items);
    if (files.length > 0) {
      await processFiles(files);
    }
  }
});

fileInput.addEventListener("change", async () => {
  if (!wasmReady || processing) return;
  const files = Array.from(fileInput.files);
  if (files.length > 0) {
    await processFiles(files);
  }
  fileInput.value = "";
});

dropZone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
});

// --- Paste Support ---

const MAX_PASTE_BYTES = 1024 * 1024; // 1 MB

document.addEventListener("paste", async (e) => {
  // Don't intercept paste into input fields.
  const tag = e.target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || e.target.isContentEditable) {
    return;
  }
  e.preventDefault();
  if (!wasmReady) {
    showStatus("Please wait, WASM module is still loading...");
    return;
  }
  if (processing) return;
  const text = e.clipboardData.getData("text/plain");
  if (!text.trim()) return;
  if (text.length > MAX_PASTE_BYTES) {
    if (activePage === "inspect") {
      showInspectStatus("Pasted data is too large (max 1 MB)", true);
    } else {
      showStatus("Pasted data is too large (max 1 MB)", true);
    }
    return;
  }
  const data = new TextEncoder().encode(text);
  if (activePage === "inspect") {
    await inspectFileObjects([{ name: "pasted.pem", data }]);
  } else {
    await addFileObjects(
      [{ name: "pasted.pem", data }],
      "Processing pasted data...",
    );
  }
});

// --- File Collection (supports recursive folder reading) ---

async function collectFiles(items) {
  const files = [];
  const entries = [];

  for (let i = 0; i < items.length; i++) {
    const entry = items[i].webkitGetAsEntry
      ? items[i].webkitGetAsEntry()
      : null;
    if (entry) {
      entries.push(entry);
    } else if (items[i].kind === "file") {
      files.push(items[i].getAsFile());
    }
  }

  if (entries.length > 0) {
    const entryFiles = await readEntries(entries);
    files.push(...entryFiles);
  }

  return files;
}

async function readEntries(entries) {
  const files = [];
  for (const entry of entries) {
    if (entry.isFile) {
      const file = await new Promise((resolve) => entry.file(resolve));
      files.push(file);
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const subEntries = await new Promise((resolve) =>
        reader.readEntries(resolve),
      );
      const subFiles = await readEntries(subEntries);
      files.push(...subFiles);
    }
  }
  return files;
}

// --- File Processing ---

async function processFiles(files) {
  if (processing) return;
  const sizeErr = validateUploadSizes(files);
  if (sizeErr) {
    showStatus(sizeErr, true);
    return;
  }
  let fileObjects;
  try {
    fileObjects = await Promise.all(
      files.map(async (f) => {
        const buf = await f.arrayBuffer();
        return { name: f.name, data: new Uint8Array(buf) };
      }),
    );
  } catch (err) {
    showStatus(`Error reading files: ${err.message}`, true);
    return;
  }
  await addFileObjects(fileObjects, `Processing ${files.length} file(s)...`);
}

// Shared helper for both file drops and paste. Sends file objects to WASM,
// handles errors, and kicks off AIA resolution.
async function addFileObjects(fileObjects, statusMessage) {
  processing = true;
  showStatus(statusMessage, false, true);

  try {
    const resultJSON = await certkitAddFiles(
      fileObjects,
      passwordsInput.value.trim(),
      scanAllowPrivateNetwork.checked,
    );
    const results = JSON.parse(resultJSON);

    const errors = results.filter((r) => r.status === "error");
    if (errors.length > 0) {
      const msgs = errors.map((e) => `${e.name}: ${e.error}`);
      console.warn("Processing errors:", msgs);
    }

    // If every input failed, show a user-visible error and bail.
    if (errors.length === results.length) {
      showStatus(`Could not parse input: ${errors[0].error}`, true);
      return;
    }

    refreshUI();
    aiaComplete = false;
    showStatus("Resolving certificate chains via AIA...", false, true);
  } catch (err) {
    showStatus(`Error: ${err.message}`, true);
  } finally {
    processing = false;
  }
}

// Called from Go after background AIA resolution completes.
// Refreshes the UI with any newly fetched intermediates and shows warnings.
window.certkitOnAIAComplete = function (warningsJSON) {
  aiaComplete = true;
  const warnings = JSON.parse(warningsJSON || "[]") || [];
  refreshUI();

  if (warnings.length > 0) {
    warningsSection.hidden = false;
    warningsList.innerHTML = "";
    for (const w of warnings) {
      const li = document.createElement("li");
      li.textContent = w;
      warningsList.appendChild(li);
    }
    showStatus(
      `Chain resolution done (${warnings.length} warning(s))`,
      false,
      false,
    );
  } else {
    warningsSection.hidden = true;
    hideStatus();
  }
};

// Called from Go via setTimeout during AIA resolution with per-cert progress.
// Ignores late callbacks that arrive after certkitOnAIAComplete has fired.
window.certkitOnAIAProgress = function (completed, total) {
  if (aiaComplete) return;
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
  statusText.textContent = `Resolving certificate chains via AIA... (${completed} of ${total})`;
  progressContainer.hidden = false;
  progressFill.classList.remove("indeterminate");
  progressFill.style.width = `${pct}%`;
  progressFill.setAttribute("aria-valuenow", String(pct));
  progressLabel.textContent = `${pct}%`;
};

// --- Drop Zone (Inspect) ---

inspectDropZone.addEventListener("click", () => inspectFileInput.click());

inspectDropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  inspectDropZone.classList.add("dragging");
});

inspectDropZone.addEventListener("dragleave", () => {
  inspectDropZone.classList.remove("dragging");
});

inspectDropZone.addEventListener("drop", async (e) => {
  e.preventDefault();
  inspectDropZone.classList.remove("dragging");
  if (!wasmReady || processing) return;

  const items = e.dataTransfer.items;
  if (items) {
    const files = await collectFiles(items);
    if (files.length > 0) {
      await processInspectFiles(files);
    }
  }
});

inspectFileInput.addEventListener("change", async () => {
  if (!wasmReady || processing) return;
  const files = Array.from(inspectFileInput.files);
  if (files.length > 0) {
    await processInspectFiles(files);
  }
  inspectFileInput.value = "";
});

inspectDropZone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    inspectFileInput.click();
  }
});

// --- Inspect File Processing ---

async function processInspectFiles(files) {
  if (processing) return;
  const sizeErr = validateUploadSizes(files);
  if (sizeErr) {
    showInspectStatus(sizeErr, true);
    return;
  }
  let fileObjects;
  try {
    fileObjects = await Promise.all(
      files.map(async (f) => {
        const buf = await f.arrayBuffer();
        return { name: f.name, data: new Uint8Array(buf) };
      }),
    );
  } catch (err) {
    showInspectStatus(`Error reading files: ${err.message}`, true);
    return;
  }
  await inspectFileObjects(fileObjects);
}

async function inspectFileObjects(fileObjects) {
  processing = true;
  showInspectStatus("Inspecting...", false, true);

  try {
    const resultJSON = await certkitInspect(
      fileObjects,
      inspectPasswordsInput.value.trim(),
      inspectAllowPrivateNetwork.checked,
    );
    const payload = JSON.parse(resultJSON);
    const results = Array.isArray(payload) ? payload : payload.results || [];
    const warning = Array.isArray(payload) ? "" : payload.warning || "";

    if (!results || results.length === 0) {
      showInspectStatus("No certificates, keys, or CSRs found in input.", true);
      return;
    }

    renderInspectResults(results);
    if (warning) {
      showInspectStatus(warning, false, false);
      return;
    }
    hideInspectStatus();
  } catch (err) {
    showInspectStatus(`Error: ${err.message}`, true);
  } finally {
    processing = false;
  }
}

// --- Inspect Results Rendering ---

function renderInspectResults(results) {
  inspectResultsSection.hidden = false;
  inspectCards.innerHTML = "";

  for (const r of results) {
    switch (r.type) {
      case "certificate":
        inspectCards.appendChild(buildCertCard(r));
        break;
      case "csr":
        inspectCards.appendChild(buildCSRCard(r));
        break;
      case "private_key":
        inspectCards.appendChild(buildKeyCard(r));
        break;
    }
  }
}

function buildCertCard(r) {
  const card = document.createElement("div");
  card.className = "inspect-card";

  const typeBadge = `<span class="badge badge-${escapeHTML(r.cert_type || "leaf")}">${escapeHTML(r.cert_type || "unknown")}</span>`;
  const badges = [typeBadge];
  if (r.aia_fetched) {
    badges.push(
      `<span class="badge badge-aia" title="This certificate was automatically fetched via Authority Information Access (AIA), not from your input file">via aia</span>`,
    );
  }
  if (r.expired === true) {
    badges.push(`<span class="badge badge-expired">expired</span>`);
  }
  if (r.trusted === true) {
    badges.push(`<span class="badge badge-match">trusted</span>`);
  } else if (r.trusted === false) {
    badges.push(`<span class="badge badge-expired">untrusted</span>`);
  }

  card.innerHTML = `
    <div class="inspect-card-header">Certificate ${badges.join(" ")}</div>
    <div class="inspect-card-body">
      <div class="metadata-grid">
        ${metaRow("Subject", r.subject)}
        ${metaRow("Issuer", r.issuer)}
        ${r.sans && r.sans.length > 0 ? metaRow("SANs", r.sans.join(", ")) : ""}
        ${metaRow("Serial", r.serial, true)}
        ${metaRow("Type", r.cert_type)}
        ${r.is_ca != null ? metaRow("CA", r.is_ca ? "Yes" : "No") : ""}
        ${metaRow("Not Before", formatDate(r.not_before))}
        ${metaRow("Not After", formatDate(r.not_after))}
        ${metaRow("Key", `${r.key_algorithm || ""} ${r.key_size || ""}`.trim())}
        ${metaRow("Signature", r.signature_algorithm)}
        ${r.key_usages && r.key_usages.length > 0 ? metaRow("Key Usage", r.key_usages.join(", ")) : ""}
        ${r.ekus && r.ekus.length > 0 ? metaRow("EKU", r.ekus.join(", ")) : ""}
        ${metaRow("SHA-256", r.sha256_fingerprint, true)}
        ${metaRow("SHA-1", r.sha1_fingerprint, true)}
        ${r.subject_key_id ? metaRow("SKI", r.subject_key_id, true) : ""}
        ${r.authority_key_id ? metaRow("AKI", r.authority_key_id, true) : ""}
      </div>
    </div>`;
  return card;
}

function buildCSRCard(r) {
  const card = document.createElement("div");
  card.className = "inspect-card";

  card.innerHTML = `
    <div class="inspect-card-header">Certificate Signing Request</div>
    <div class="inspect-card-body">
      <div class="metadata-grid">
        ${metaRow("Subject", r.csr_subject)}
        ${r.sans && r.sans.length > 0 ? metaRow("SANs", r.sans.join(", ")) : ""}
        ${r.is_ca != null ? metaRow("CA", r.is_ca ? "Yes" : "No") : ""}
        ${metaRow("Key", `${r.key_algorithm || ""} ${r.key_size || ""}`.trim())}
        ${metaRow("Signature", r.signature_algorithm)}
        ${r.key_usages && r.key_usages.length > 0 ? metaRow("Key Usage", r.key_usages.join(", ")) : ""}
        ${r.ekus && r.ekus.length > 0 ? metaRow("EKU", r.ekus.join(", ")) : ""}
        ${r.subject_key_id ? metaRow("SKI", r.subject_key_id, true) : ""}
      </div>
    </div>`;
  return card;
}

function buildKeyCard(r) {
  const card = document.createElement("div");
  card.className = "inspect-card";

  card.innerHTML = `
    <div class="inspect-card-header">Private Key</div>
    <div class="inspect-card-body">
      <div class="metadata-grid">
        ${metaRow("Type", r.key_type)}
        ${metaRow("Size", r.key_size)}
        ${r.subject_key_id ? metaRow("SKI (SHA-256)", r.subject_key_id, true) : ""}
        ${r.subject_key_id_sha1 ? metaRow("SKI (SHA-1)", r.subject_key_id_sha1, true) : ""}
      </div>
    </div>`;
  return card;
}

function metaRow(label, value, mono = false) {
  if (!value && value !== 0) return "";
  const cls = mono ? " mono" : "";
  return `<div class="metadata-label">${escapeHTML(label)}</div><div class="metadata-value${cls}">${escapeHTML(String(value))}</div>`;
}

// --- Inspect Status Helpers ---

function showInspectStatus(message, isError = false, isProcessing = false) {
  inspectStatusBar.hidden = false;
  inspectStatusText.textContent = message;
  inspectStatusBar.className = "status-bar";
  if (isError) inspectStatusBar.style.color = "var(--danger)";
  else if (isProcessing) {
    inspectStatusBar.classList.add("processing");
    inspectStatusBar.style.color = "";
  } else {
    inspectStatusBar.style.color = "";
  }
}

function hideInspectStatus() {
  inspectStatusBar.hidden = true;
}

// --- Inspect Reset ---

inspectResetBtn.addEventListener("click", () => {
  inspectResultsSection.hidden = true;
  inspectCards.innerHTML = "";
  hideInspectStatus();
});

// --- Category Tabs ---

function switchCategory(cat) {
  activeCategory = cat;
  for (const btn of document.querySelectorAll(".cat-tab")) {
    const isActive = btn.dataset.cat === cat;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-selected", String(isActive));
  }

  if (cat === "keys") {
    certTableContainer.hidden = true;
    keysSection.hidden = false;
    renderKeys();
  } else {
    certTableContainer.hidden = false;
    keysSection.hidden = true;
    renderCerts();
  }
}

for (const btn of document.querySelectorAll(".cat-tab")) {
  btn.addEventListener("click", () => switchCategory(btn.dataset.cat));
}

// --- Filters ---

function onFilterChange() {
  renderCerts();
  renderKeys();
}

filterExpired.addEventListener("change", onFilterChange);
filterUnmatched.addEventListener("change", onFilterChange);
filterUntrusted.addEventListener("change", onFilterChange);

// --- Sorting ---

const SORT_DEFAULT_DESC = new Set(["expiry", "match", "trusted"]);

function toggleSort(state, column) {
  if (state.column === column) {
    state.direction = state.direction === "asc" ? "desc" : "asc";
  } else {
    state.column = column;
    state.direction = SORT_DEFAULT_DESC.has(column) ? "desc" : "asc";
  }
}

function certCompare(a, b, column) {
  switch (column) {
    case "cn":
      return (a.cn || "").localeCompare(b.cn || "");
    case "serial":
      return (a.serial || "").localeCompare(b.serial || "");
    case "key_type":
      return (a.key_type || "").localeCompare(b.key_type || "");
    case "expiry":
      return (a.not_after || "").localeCompare(b.not_after || "");
    case "trusted":
      return (a.trusted ? 1 : 0) - (b.trusted ? 1 : 0);
    case "match":
      return (a.has_key ? 1 : 0) - (b.has_key ? 1 : 0);
    default:
      return 0;
  }
}

function keyCompare(a, b, column) {
  switch (column) {
    case "type":
      return (a.key_type || "").localeCompare(b.key_type || "");
    case "bits":
      return (a.bit_length || 0) - (b.bit_length || 0);
    case "ski":
      return (a.ski || "").localeCompare(b.ski || "");
    case "match":
      return (a.has_cert ? 1 : 0) - (b.has_cert ? 1 : 0);
    default:
      return 0;
  }
}

function updateSortIndicators(table, sort) {
  for (const th of table.querySelectorAll("th[data-sort]")) {
    th.classList.remove("sort-asc", "sort-desc");
    if (th.dataset.sort === sort.column) {
      th.classList.add(sort.direction === "asc" ? "sort-asc" : "sort-desc");
    }
  }
}

document
  .getElementById("results-table")
  .querySelector("thead")
  .addEventListener("click", (e) => {
    const th = e.target.closest("th[data-sort]");
    if (!th) return;
    toggleSort(certSort, th.dataset.sort);
    renderCerts();
  });

document
  .getElementById("keys-table")
  .querySelector("thead")
  .addEventListener("click", (e) => {
    const th = e.target.closest("th[data-sort]");
    if (!th) return;
    toggleSort(keySort, th.dataset.sort);
    renderKeys();
  });

// --- Selection ---

// Handle individual cert checkbox changes via event delegation.
resultsBody.addEventListener("change", (e) => {
  if (!e.target.classList.contains("cert-select")) return;
  e.stopPropagation(); // Prevent row click handler from toggling detail
  const ski = e.target.dataset.ski;
  if (e.target.checked) {
    selectedSKIs.add(ski);
  } else {
    selectedSKIs.delete(ski);
  }
  updateSelectAll();
  updateExportBtn();
});

// Select-all toggles all visible exportable cert checkboxes.
selectAll.addEventListener("change", () => {
  const checkboxes = resultsBody.querySelectorAll(
    ".cert-select:not(:disabled)",
  );
  for (const cb of checkboxes) {
    cb.checked = selectAll.checked;
    if (selectAll.checked) {
      selectedSKIs.add(cb.dataset.ski);
    } else {
      selectedSKIs.delete(cb.dataset.ski);
    }
  }
  updateExportBtn();
});

// Last fetched state — kept so filters can re-render without re-calling WASM.
let lastState = null;

// --- UI Refresh ---

function refreshUI() {
  const stateJSON = certkitGetState();
  lastState = JSON.parse(stateJSON);

  resultsSection.hidden = false;
  filtersDiv.hidden = false;

  renderCerts();
  if (activeCategory === "keys") {
    renderKeys();
  }
}

function renderSummary() {
  if (!lastState) return;
  const allCerts = lastState.certs || [];
  const allKeys = lastState.keys || [];

  const leafCount = allCerts.filter((c) => c.cert_type === "leaf").length;
  const intermediateCount = allCerts.filter(
    (c) => c.cert_type === "intermediate",
  ).length;
  const rootCount = allCerts.filter((c) => c.cert_type === "root").length;
  const keyCount = allKeys.length;
  const matchedCount = lastState.matched_pairs;

  summaryDiv.innerHTML = `
    <div class="summary-item"><span class="summary-count">${leafCount}</span> leaf</div>
    <div class="summary-item"><span class="summary-count">${intermediateCount}</span> intermediate</div>
    <div class="summary-item"><span class="summary-count">${rootCount}</span> root</div>
    <div class="summary-item"><span class="summary-count">${keyCount}</span> keys</div>
    <div class="summary-item"><span class="summary-count">${matchedCount}</span> matched</div>
  `;
}

function renderCerts() {
  if (!lastState) return;

  const allCerts = lastState.certs || [];

  // Filter by active category tab.
  const visible = allCerts.filter((c) => {
    if (c.cert_type !== activeCategory) return false;
    if (filterExpired.checked && c.expired) return false;
    if (filterUnmatched.checked && !c.has_key) return false;
    if (filterUntrusted.checked && !c.trusted) return false;
    return true;
  });

  renderSummary();

  // Preserve selected detail row.
  const hadDetail = selectedDetailSKI;

  // Sort — tiebreak by CN ascending when primary values are equal.
  const dir = certSort.direction === "asc" ? 1 : -1;
  visible.sort((a, b) => {
    const primary = certCompare(a, b, certSort.column) * dir;
    if (primary !== 0) return primary;
    return certCompare(a, b, "cn");
  });

  resultsBody.innerHTML = "";
  for (const cert of visible) {
    const tr = document.createElement("tr");
    tr.dataset.ski = cert.ski;
    if (cert.ski === selectedDetailSKI) {
      tr.classList.add("selected");
    }

    const matchBadge = cert.has_key
      ? `<span class="badge badge-match">matched</span>`
      : `<span class="badge badge-no-match">no key</span>`;
    const expiryClass = cert.expired ? "badge-expired" : "";
    const expiryBadge = cert.expired
      ? ` <span class="badge badge-expired">expired</span>`
      : "";
    const trustedBadge = cert.trusted
      ? `<span class="badge badge-match">trusted</span>`
      : `<span class="badge badge-expired">untrusted</span>`;

    const canExport = cert.has_key;
    const checked = canExport && selectedSKIs.has(cert.ski) ? "checked" : "";
    const disabled = canExport ? "" : "disabled";

    tr.innerHTML = `
            <td class="col-select"><input type="checkbox" class="cert-select" data-ski="${escapeHTML(
              cert.ski,
            )}" ${checked} ${disabled}></td>
            <td title="${escapeHTML(cert.issuer)}">${escapeHTML(cert.cn)}</td>
            <td class="serial" title="${escapeHTML(cert.serial)}">${escapeHTML(
              cert.serial,
            )}</td>
            <td>${escapeHTML(cert.key_type)}</td>
            <td><span class="${expiryClass}">${formatDate(
              cert.not_after,
            )}</span>${expiryBadge}</td>
            <td>${trustedBadge}</td>
            <td>${matchBadge}</td>
        `;
    resultsBody.appendChild(tr);
  }

  // Restore open detail row after re-render.
  if (hadDetail) {
    const openRow = resultsBody.querySelector(
      `tr[data-ski="${CSS.escape(hadDetail)}"]`,
    );
    if (openRow) {
      const existing = resultsBody.querySelector(".cert-detail-row");
      if (!existing) {
        certRowClick(openRow);
      }
    }
  }

  updateSortIndicators(document.getElementById("results-table"), certSort);
  updateSelectAll();
  updateExportBtn();
}

function renderKeys() {
  if (!lastState) return;
  const allKeys = lastState.keys || [];

  if (allKeys.length === 0 && activeCategory === "keys") {
    keysBody.innerHTML = "";
    return;
  }

  const visible = allKeys.filter((k) => {
    if (filterUnmatched.checked && !k.has_cert) return false;
    return true;
  });

  // Sort — tiebreak by type ascending when primary values are equal.
  const dir = keySort.direction === "asc" ? 1 : -1;
  visible.sort((a, b) => {
    const primary = keyCompare(a, b, keySort.column) * dir;
    if (primary !== 0) return primary;
    return keyCompare(a, b, "type");
  });

  // Preserve selected detail row.
  const hadKeyDetail = selectedKeyDetailSKI;

  keysBody.innerHTML = "";
  for (const key of visible) {
    const tr = document.createElement("tr");
    tr.dataset.ski = key.ski;
    if (key.ski === selectedKeyDetailSKI) {
      tr.classList.add("selected");
    }
    const matchBadge = key.has_cert
      ? `<span class="badge badge-match">matched</span>`
      : `<span class="badge badge-no-match">no cert</span>`;
    tr.innerHTML = `
      <td>${escapeHTML(key.key_type)}</td>
      <td>${key.bit_length}</td>
      <td class="ski" title="${escapeHTML(key.ski)}">${escapeHTML(key.ski)}</td>
      <td>${matchBadge}</td>
    `;
    keysBody.appendChild(tr);
  }

  // Restore open detail row after re-render.
  if (hadKeyDetail) {
    const openRow = keysBody.querySelector(
      `tr[data-ski="${CSS.escape(hadKeyDetail)}"]`,
    );
    if (openRow && !keysBody.querySelector(".key-detail-row")) {
      keyRowClick(openRow);
    }
  }

  updateSortIndicators(document.getElementById("keys-table"), keySort);
}

function updateSelectAll() {
  const checkboxes = resultsBody.querySelectorAll(
    ".cert-select:not(:disabled)",
  );
  if (checkboxes.length === 0) {
    selectAll.checked = false;
    selectAll.indeterminate = false;
    return;
  }
  const checkedCount = Array.from(checkboxes).filter((cb) => cb.checked).length;
  selectAll.checked = checkedCount === checkboxes.length;
  selectAll.indeterminate =
    checkedCount > 0 && checkedCount < checkboxes.length;
}

// Returns SKIs that are both selected and currently visible in the table.
function getExportableSKIs() {
  const checkboxes = resultsBody.querySelectorAll(".cert-select:checked");
  const skis = [];
  for (const cb of checkboxes) {
    skis.push(cb.dataset.ski);
  }
  return skis;
}

function updateExportBtn() {
  const count = getExportableSKIs().length;
  exportBtn.disabled = count === 0;
  exportBtn.textContent =
    count > 0
      ? `Export ${count} Bundle${count !== 1 ? "s" : ""} (ZIP)`
      : "Export Bundles (ZIP)";
}

// --- Click-to-expand detail rows ---

function removeDetail() {
  const existing = resultsBody.querySelector(".cert-detail-row");
  if (existing) existing.remove();
}

function insertDetail(afterRow, html) {
  removeDetail();
  const detailTr = document.createElement("tr");
  detailTr.className = "cert-detail-row";
  detailTr.innerHTML = `<td colspan="7"><div class="cert-detail-inner">${html}</div></td>`;
  afterRow.after(detailTr);
}

async function certRowClick(tr) {
  const ski = tr.dataset.ski;
  if (!ski || !wasmReady) return;

  // Toggle: clicking the same row closes it.
  if (
    selectedDetailSKI === ski &&
    resultsBody.querySelector(".cert-detail-row")
  ) {
    selectedDetailSKI = null;
    removeDetail();
    tr.classList.remove("selected");
    return;
  }

  selectedDetailSKI = ski;
  for (const row of resultsBody.querySelectorAll("tr:not(.cert-detail-row)")) {
    row.classList.toggle("selected", row.dataset.ski === ski);
  }

  // Show loading state inline.
  insertDetail(tr, `<span class="hint">Verifying...</span>`);

  try {
    const resultJSON = await certkitValidateCert(ski);
    if (selectedDetailSKI !== ski || !tr.isConnected) return;
    const result = JSON.parse(resultJSON);

    // Find the cert data for metadata.
    const cert = (lastState.certs || []).find((c) => c.ski === ski);
    const html = buildChecksHTML(result) + buildMetadataHTML(cert);
    insertDetail(tr, html);
  } catch (err) {
    if (selectedDetailSKI !== ski || !tr.isConnected) return;
    insertDetail(
      tr,
      `<div class="verify-banner-inline invalid"><span class="check-status check-fail">${
        STATUS_ICONS.fail
      }</span> ${escapeHTML(err.message)}</div>`,
    );
  }
}

resultsBody.addEventListener("click", (e) => {
  // Don't trigger on checkbox clicks.
  if (e.target.closest(".col-select") || e.target.closest("input")) return;
  const tr = e.target.closest("tr:not(.cert-detail-row)");
  if (tr) certRowClick(tr);
});

function buildChecksHTML(result) {
  const bannerIcon = result.valid ? STATUS_ICONS.pass : STATUS_ICONS.fail;
  const bannerClass = result.valid ? "valid" : "invalid";
  const statusClass = result.valid ? "check-pass" : "check-fail";
  const bannerText = result.valid ? "Valid" : "Invalid";

  let html = `<div class="verify-banner-inline ${bannerClass}"><span class="check-status ${statusClass}">${bannerIcon}</span> ${escapeHTML(
    bannerText,
  )}</div>`;

  for (const check of result.checks) {
    const icon = STATUS_ICONS[check.status] || STATUS_ICONS.warn;
    const cls =
      check.status === "pass"
        ? "check-pass"
        : check.status === "fail"
          ? "check-fail"
          : "check-warn";
    html += `
      <div class="check-row">
        <div>
          <span class="check-label">${escapeHTML(check.name)}</span>
          <span class="check-detail">${escapeHTML(check.detail)}</span>
        </div>
        <span class="check-status ${cls}">${icon}</span>
      </div>`;
  }
  return html;
}

function buildMetadataHTML(cert) {
  if (!cert) return "";

  const sans =
    cert.sans && cert.sans.length > 0 ? cert.sans.join(", ") : "None";
  const ekus = cert.ekus && cert.ekus.length > 0 ? cert.ekus.join(", ") : "";

  const rows = [
    ["Subject", cert.subject],
    ["Issuer", cert.issuer],
    ["SANs", sans],
    ["SKI", cert.ski],
    ["Not Before", formatDate(cert.not_before)],
  ];
  if (ekus) rows.splice(3, 0, ["EKU", ekus]);

  let html = `<div class="metadata-grid">`;
  for (const [label, value] of rows) {
    const cls = label === "SKI" ? " mono" : "";
    html += `<div class="metadata-label">${escapeHTML(
      label,
    )}</div><div class="metadata-value${cls}">${escapeHTML(value || "")}</div>`;
  }
  html += `</div>`;
  return html;
}

// --- Click-to-expand key detail rows ---

function removeKeyDetail() {
  const existing = keysBody.querySelector(".key-detail-row");
  if (existing) existing.remove();
}

function insertKeyDetail(afterRow, html) {
  removeKeyDetail();
  const detailTr = document.createElement("tr");
  detailTr.className = "key-detail-row";
  detailTr.innerHTML = `<td colspan="4"><div class="key-detail-inner">${html}</div></td>`;
  afterRow.after(detailTr);
}

function keyRowClick(tr) {
  const ski = tr.dataset.ski;
  if (!ski) return;

  // Toggle: clicking the same row closes it.
  if (
    selectedKeyDetailSKI === ski &&
    keysBody.querySelector(".key-detail-row")
  ) {
    selectedKeyDetailSKI = null;
    removeKeyDetail();
    tr.classList.remove("selected");
    return;
  }

  selectedKeyDetailSKI = ski;
  for (const row of keysBody.querySelectorAll("tr:not(.key-detail-row)")) {
    row.classList.toggle("selected", row.dataset.ski === ski);
  }

  // Find matching certs by SKI.
  const matchingCerts = (lastState.certs || []).filter((c) => c.ski === ski);
  if (matchingCerts.length === 0) {
    insertKeyDetail(
      tr,
      `<span class="hint">No matching certificates found.</span>`,
    );
    return;
  }

  let html = `<div class="key-match-header">Matching Certificates</div>`;
  for (const cert of matchingCerts) {
    const typeBadge = `<span class="badge badge-${escapeHTML(
      cert.cert_type,
    )}">${escapeHTML(cert.cert_type)}</span>`;
    const trustedBadge = cert.trusted
      ? `<span class="badge badge-match">trusted</span>`
      : `<span class="badge badge-expired">untrusted</span>`;
    const expiryBadge = cert.expired
      ? `<span class="badge badge-expired">expired</span>`
      : "";

    html += `
      <div class="key-match-cert">
        <div class="key-match-info">
          <span class="key-match-cn">${escapeHTML(cert.cn)}</span>
          ${typeBadge} ${trustedBadge} ${expiryBadge}
        </div>
        <div class="key-match-meta">${escapeHTML(cert.issuer)} — ${formatDate(
          cert.not_after,
        )}</div>
        <button class="btn-go-to-cert" data-cat="${escapeHTML(
          cert.cert_type,
        )}" data-ski="${escapeHTML(cert.ski)}">View certificate</button>
      </div>`;
  }
  insertKeyDetail(tr, html);
}

keysBody.addEventListener("click", (e) => {
  // Handle "View certificate" button clicks.
  const goBtn = e.target.closest(".btn-go-to-cert");
  if (goBtn) {
    const cat = goBtn.dataset.cat;
    const ski = goBtn.dataset.ski;

    // Uncheck filters that would hide the target cert.
    const cert = (lastState.certs || []).find((c) => c.ski === ski);
    if (cert) {
      if (cert.expired && filterExpired.checked) filterExpired.checked = false;
      if (!cert.trusted && filterUntrusted.checked)
        filterUntrusted.checked = false;
      if (!cert.has_key && filterUnmatched.checked)
        filterUnmatched.checked = false;
    }

    switchCategory(cat);
    // Highlight and expand the target cert row after tab switch.
    requestAnimationFrame(() => {
      const targetRow = resultsBody.querySelector(
        `tr[data-ski="${CSS.escape(ski)}"]`,
      );
      if (targetRow) {
        targetRow.scrollIntoView({ behavior: "smooth", block: "center" });
        certRowClick(targetRow);
      }
    });
    return;
  }

  const tr = e.target.closest("tr:not(.key-detail-row)");
  if (tr) keyRowClick(tr);
});

// --- Export ---

exportBtn.addEventListener("click", async () => {
  if (!wasmReady) return;
  const skis = getExportableSKIs();
  if (skis.length === 0) return;

  const rawPassword = window.prompt(
    "Export password?\n\n" +
      "\u2022 With password: encrypts .key and .yaml key material; .p12 uses that password\n" +
      "\u2022 Blank: .key and .yaml key material unencrypted; .p12 uses default password\n" +
      "\u2022 Note: Kubernetes tls.key is always unencrypted",
    "",
  );
  const ep = normalizeExportPassword(rawPassword);
  if (ep.promptWasCancelled) return;
  const password = ep.password;

  exportBtn.disabled = true;
  exportBtn.textContent = "Exporting...";
  const encryptingNote = ep.statusNote;
  showStatus(
    `Building ${skis.length} bundle(s) and ZIP${encryptingNote}`,
    false,
    true,
  );

  // Yield to the browser so the status bar paints before WASM blocks.
  await new Promise((r) =>
    requestAnimationFrame(() => requestAnimationFrame(r)),
  );

  try {
    const payload = await certkitExportBundles(skis, password);
    downloadBlob(payload.data, "certkit-bundles.zip", "application/zip");
    if (payload.warning) {
      showStatus(payload.warning, false, false);
    } else {
      hideStatus();
    }
  } catch (err) {
    if (
      err?.code === "VERIFY_FAILED" &&
      window.confirm(
        "Verified export failed. Retry without certificate chain verification?",
      )
    ) {
      try {
        showStatus(
          `Retrying ${skis.length} bundle(s) without verification${encryptingNote}`,
          false,
          true,
        );
        await new Promise((r) =>
          requestAnimationFrame(() => requestAnimationFrame(r)),
        );
        const payload = await certkitExportBundles(skis, password, true);
        downloadBlob(payload.data, "certkit-bundles.zip", "application/zip");
        const messages = [];
        if (payload.warning) messages.push(payload.warning);
        messages.push(
          "Export completed without chain verification. Verify trust before use.",
        );
        showStatus(messages.join(" "), false);
      } catch (retryErr) {
        showStatus(`Export error: ${retryErr.message}`, true);
      }
    } else {
      showStatus(`Export error: ${err.message}`, true);
    }
  } finally {
    exportBtn.disabled = false;
    updateExportBtn();
  }
});

// --- Reset ---

resetBtn.addEventListener("click", () => {
  if (!wasmReady) return;
  certkitReset();
  processing = false;
  lastState = null;
  aiaComplete = false;
  selectedSKIs.clear();
  certSort.column = "expiry";
  certSort.direction = "desc";
  keySort.column = "match";
  keySort.direction = "desc";
  activeCategory = "leaf";
  selectedDetailSKI = null;
  selectedKeyDetailSKI = null;
  resultsSection.hidden = true;
  filtersDiv.hidden = true;
  resultsBody.innerHTML = "";
  keysBody.innerHTML = "";
  keysSection.hidden = true;
  certTableContainer.hidden = false;
  warningsSection.hidden = true;
  summaryDiv.innerHTML = "";
  exportBtn.textContent = "Export Bundles (ZIP)";
  exportBtn.disabled = true;
  hideStatus();
  // Reset tab selection
  for (const btn of document.querySelectorAll(".cat-tab")) {
    const isLeaf = btn.dataset.cat === "leaf";
    btn.classList.toggle("active", isLeaf);
    btn.setAttribute("aria-selected", String(isLeaf));
  }
});

// --- Helpers ---

function showStatus(message, isError = false, isProcessing = false) {
  statusBar.hidden = false;
  statusText.textContent = message;
  statusBar.className = "status-bar";
  progressFill.classList.remove("indeterminate");
  progressFill.style.width = "0%";
  progressFill.setAttribute("aria-valuenow", "0");
  statusBar.style.color = "";
  if (isError) {
    statusBar.style.color = "var(--danger)";
    progressContainer.hidden = true;
  } else if (isProcessing) {
    statusBar.classList.add("processing");
    progressContainer.hidden = false;
    progressLabel.textContent = "";
    progressFill.classList.add("indeterminate");
  } else {
    progressContainer.hidden = true;
  }
}

function hideStatus() {
  statusBar.hidden = true;
  progressContainer.hidden = true;
  progressFill.classList.remove("indeterminate");
  progressFill.style.width = "0%";
  progressFill.setAttribute("aria-valuenow", "0");
}

function downloadBlob(data, filename, mimeType) {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

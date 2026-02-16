import { formatDate, escapeHTML } from "./utils.js";

// DOM references
const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const passwordsInput = document.getElementById("passwords");
const statusBar = document.getElementById("status-bar");
const statusText = document.getElementById("status-text");
const resultsSection = document.getElementById("results-section");
const summaryDiv = document.getElementById("summary");
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
const filterNonleaf = document.getElementById("filter-nonleaf");
const filterUntrusted = document.getElementById("filter-untrusted");
const selectAll = document.getElementById("select-all");
const keysShowAll = document.getElementById("keys-show-all");

// State
let wasmReady = false;
const selectedSKIs = new Set();
let visibleCertSKIs = new Set();
const certSort = { column: "expiry", direction: "desc" };
const keySort = { column: "match", direction: "desc" };

// certkitFetchURL is called from Go (WASM) to fetch AIA certificates.
// Tries direct fetch first, then falls back to our own /api/fetch proxy
// (same-origin, no CORS issues).
window.certkitFetchURL = async function (url) {
  // 1. Try direct fetch (works if CA serves CORS headers)
  try {
    const resp = await fetch(url);
    if (resp.ok) {
      console.log("certkit: AIA direct fetch succeeded:", url);
      return new Uint8Array(await resp.arrayBuffer());
    }
  } catch (e) {
    console.log("certkit: AIA direct fetch failed:", url, e.message);
  }

  // 2. Proxy through our own /api/fetch endpoint
  const proxiedURL = "/api/fetch?url=" + encodeURIComponent(url);
  console.log("certkit: AIA proxy fetch:", proxiedURL);
  const resp = await fetch(proxiedURL);
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Proxy returned ${resp.status}: ${body}`);
  }
  console.log("certkit: AIA proxy fetch succeeded for", url);
  return new Uint8Array(await resp.arrayBuffer());
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

// --- Drop Zone ---

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
  if (!wasmReady) return;

  const items = e.dataTransfer.items;
  if (items) {
    const files = await collectFiles(items);
    if (files.length > 0) {
      await processFiles(files);
    }
  }
});

fileInput.addEventListener("change", async () => {
  if (!wasmReady) return;
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
  showStatus(`Processing ${files.length} file(s)...`, false, true);

  const passwords = passwordsInput.value.trim();

  const fileObjects = await Promise.all(
    files.map(async (f) => {
      const buf = await f.arrayBuffer();
      return { name: f.name, data: new Uint8Array(buf) };
    }),
  );

  try {
    const resultJSON = await certkitAddFiles(fileObjects, passwords);
    const results = JSON.parse(resultJSON);

    const errors = results.filter((r) => r.status === "error");
    if (errors.length > 0) {
      const msgs = errors.map((e) => `${e.name}: ${e.error}`);
      console.warn("Processing errors:", msgs);
    }

    refreshUI();
    showStatus("Resolving certificate chains via AIA...", false, true);
  } catch (err) {
    showStatus(`Error: ${err.message}`, true);
  }
}

// Called from Go after background AIA resolution completes.
// Refreshes the UI with any newly fetched intermediates and shows warnings.
window.certkitOnAIAComplete = function (warningsJSON) {
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

// --- Filters ---

// Re-render both tables when any filter changes — cert filters cascade to keys
// because keys only show when their corresponding cert is visible.
function onFilterChange() {
  renderCerts();
  renderKeys();
}

filterExpired.addEventListener("change", onFilterChange);
filterUnmatched.addEventListener("change", onFilterChange);
filterNonleaf.addEventListener("change", onFilterChange);
filterUntrusted.addEventListener("change", onFilterChange);
keysShowAll.addEventListener("change", renderKeys);

// --- Sorting ---

const CERT_TYPE_ORDER = { leaf: 0, intermediate: 1, root: 2 };
const SORT_DEFAULT_DESC = new Set(["expiry", "match"]);

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
    case "type":
      return (
        (CERT_TYPE_ORDER[a.cert_type] ?? 3) -
        (CERT_TYPE_ORDER[b.cert_type] ?? 3)
      );
    case "key_type":
      return (a.key_type || "").localeCompare(b.key_type || "");
    case "expiry":
      return (a.not_after || "").localeCompare(b.not_after || "");
    case "ski":
      return (a.ski || "").localeCompare(b.ski || "");
    case "match":
      return (a.has_key ? 1 : 0) - (b.has_key ? 1 : 0);
    case "source":
      return (a.source || "").localeCompare(b.source || "");
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
    case "source":
      return (a.source || "").localeCompare(b.source || "");
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

  // Auto-select newly discovered matched certs (from file add or AIA resolution).
  for (const c of lastState.certs || []) {
    if (c.has_key) selectedSKIs.add(c.ski);
  }

  resultsSection.hidden = false;
  filtersDiv.hidden = false;

  renderCerts();
  renderKeys();
}

function renderSummary() {
  if (!lastState) return;
  const allCerts = lastState.certs || [];
  const allKeys = lastState.keys || [];

  // Cert count uses visibleCertSKIs (computed by renderCerts).
  const visibleCertCount = visibleCertSKIs.size;
  // Keys follow cert visibility unless "Show all" is checked or no certs exist.
  const showAll = keysShowAll.checked || allCerts.length === 0;
  const visibleKeyCount = showAll
    ? allKeys.length
    : allKeys.filter((k) => visibleCertSKIs.has(k.ski)).length;

  const hiddenCerts = allCerts.length - visibleCertCount;
  const hiddenKeys = allKeys.length - visibleKeyCount;

  summaryDiv.innerHTML = `
    <div class="summary-item"><span class="summary-count">${visibleCertCount}</span> certificates${hiddenCerts > 0 ? ` <span class="summary-hidden">(${hiddenCerts} hidden)</span>` : ""}</div>
    <div class="summary-item"><span class="summary-count">${visibleKeyCount}</span> keys${hiddenKeys > 0 ? ` <span class="summary-hidden">(${hiddenKeys} hidden)</span>` : ""}</div>
    <div class="summary-item"><span class="summary-count">${lastState.matched_pairs}</span> matched pairs</div>
  `;
}

function renderCerts() {
  if (!lastState) return;

  const allCerts = lastState.certs || [];
  const visible = allCerts.filter((c) => {
    if (filterExpired.checked && c.expired) return false;
    if (filterUnmatched.checked && !c.has_key) return false;
    if (filterNonleaf.checked && c.cert_type !== "leaf") return false;
    if (filterUntrusted.checked && !c.trusted) return false;
    return true;
  });

  // Store visible cert SKIs so renderKeys can filter keys to match.
  visibleCertSKIs = new Set(visible.map((c) => c.ski));

  renderSummary();

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

    const typeBadge = `<span class="badge badge-${cert.cert_type}">${cert.cert_type}</span>`;
    const matchBadge = cert.has_key
      ? `<span class="badge badge-match">matched</span>`
      : `<span class="badge badge-no-match">no key</span>`;
    const expiryClass = cert.expired ? "badge-expired" : "";
    const expiryBadge = cert.expired
      ? ` <span class="badge badge-expired">expired</span>`
      : "";

    const canExport = cert.has_key;
    const checked = canExport && selectedSKIs.has(cert.ski) ? "checked" : "";
    const disabled = canExport ? "" : "disabled";

    tr.innerHTML = `
            <td class="col-select"><input type="checkbox" class="cert-select" data-ski="${escapeHTML(cert.ski)}" ${checked} ${disabled}></td>
            <td title="${escapeHTML(cert.issuer)}">${escapeHTML(cert.cn)}</td>
            <td>${typeBadge}</td>
            <td>${escapeHTML(cert.key_type)}</td>
            <td><span class="${expiryClass}">${formatDate(cert.not_after)}</span>${expiryBadge}</td>
            <td class="ski" title="${escapeHTML(cert.ski)}">${escapeHTML(cert.ski)}</td>
            <td>${matchBadge}</td>
            <td>${escapeHTML(cert.source)}</td>
        `;
    resultsBody.appendChild(tr);
  }

  updateSortIndicators(document.getElementById("results-table"), certSort);
  updateSelectAll();
  updateExportBtn();
}

function renderKeys() {
  if (!lastState) return;
  const allKeys = lastState.keys || [];

  if (allKeys.length === 0) {
    keysSection.hidden = true;
    return;
  }
  keysSection.hidden = false;

  // Show all keys when the checkbox is checked or no certs have been loaded.
  const allCerts = lastState.certs || [];
  const showAll = keysShowAll.checked || allCerts.length === 0;
  const visible = showAll
    ? allKeys.slice()
    : allKeys.filter((k) => visibleCertSKIs.has(k.ski));

  renderSummary();

  // Sort — tiebreak by type ascending when primary values are equal.
  const dir = keySort.direction === "asc" ? 1 : -1;
  visible.sort((a, b) => {
    const primary = keyCompare(a, b, keySort.column) * dir;
    if (primary !== 0) return primary;
    return keyCompare(a, b, "type");
  });

  keysBody.innerHTML = "";
  for (const key of visible) {
    const tr = document.createElement("tr");
    const matchBadge = key.has_cert
      ? `<span class="badge badge-match">matched</span>`
      : `<span class="badge badge-no-match">no cert</span>`;
    tr.innerHTML = `
      <td>${escapeHTML(key.key_type)}</td>
      <td>${key.bit_length}</td>
      <td class="ski" title="${escapeHTML(key.ski)}">${escapeHTML(key.ski)}</td>
      <td>${matchBadge}</td>
      <td>${escapeHTML(key.source)}</td>
    `;
    keysBody.appendChild(tr);
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

// --- Export ---

exportBtn.addEventListener("click", async () => {
  if (!wasmReady) return;
  const skis = getExportableSKIs();
  if (skis.length === 0) return;

  exportBtn.disabled = true;
  exportBtn.textContent = "Exporting...";
  showStatus(`Building ${skis.length} bundle(s) and ZIP...`, false, true);

  try {
    const zipData = await certkitExportBundles(skis);
    downloadBlob(zipData, "certkit-bundles.zip", "application/zip");
    hideStatus();
  } catch (err) {
    showStatus(`Export error: ${err.message}`, true);
  } finally {
    exportBtn.disabled = false;
    updateExportBtn();
  }
});

// --- Reset ---

resetBtn.addEventListener("click", () => {
  if (!wasmReady) return;
  certkitReset();
  lastState = null;
  selectedSKIs.clear();
  visibleCertSKIs = new Set();
  keysShowAll.checked = false;
  certSort.column = "expiry";
  certSort.direction = "desc";
  keySort.column = "match";
  keySort.direction = "desc";
  resultsSection.hidden = true;
  filtersDiv.hidden = true;
  resultsBody.innerHTML = "";
  keysBody.innerHTML = "";
  keysSection.hidden = true;
  warningsSection.hidden = true;
  summaryDiv.innerHTML = "";
  exportBtn.textContent = "Export Bundles (ZIP)";
  exportBtn.disabled = true;
  hideStatus();
});

// --- Helpers ---

function showStatus(message, isError = false, isProcessing = false) {
  statusBar.hidden = false;
  statusText.textContent = message;
  statusBar.className = "status-bar";
  if (isError) statusBar.style.color = "var(--danger)";
  else if (isProcessing) statusBar.classList.add("processing");
  else statusBar.style.color = "";
}

function hideStatus() {
  statusBar.hidden = true;
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

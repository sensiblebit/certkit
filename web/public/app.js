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

// State
let wasmReady = false;
const selectedSKIs = new Set();

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

// Re-render the cert table when any filter changes.
filterExpired.addEventListener("change", renderCerts);
filterUnmatched.addEventListener("change", renderCerts);
filterNonleaf.addEventListener("change", renderCerts);
filterUntrusted.addEventListener("change", renderCerts);

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

  // Keys table
  const keys = lastState.keys || [];
  if (keys.length > 0) {
    keysSection.hidden = false;
    keysBody.innerHTML = "";
    for (const key of keys) {
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
  } else {
    keysSection.hidden = true;
  }
}

function renderCerts() {
  if (!lastState) return;

  const allCerts = lastState.certs || [];
  const hideExpired = filterExpired.checked;
  const hideUnmatched = filterUnmatched.checked;
  const hideNonleaf = filterNonleaf.checked;
  const hideUntrusted = filterUntrusted.checked;

  const visible = allCerts.filter((c) => {
    if (hideExpired && c.expired) return false;
    if (hideUnmatched && !c.has_key) return false;
    if (hideNonleaf && c.cert_type !== "leaf") return false;
    if (hideUntrusted && !c.trusted) return false;
    return true;
  });

  const hidden = allCerts.length - visible.length;

  // Summary
  summaryDiv.innerHTML = `
        <div class="summary-item"><span class="summary-count">${visible.length}</span> certificates${hidden > 0 ? ` <span class="summary-hidden">(${hidden} hidden)</span>` : ""}</div>
        <div class="summary-item"><span class="summary-count">${lastState.keys ? lastState.keys.length : 0}</span> keys</div>
        <div class="summary-item"><span class="summary-count">${lastState.matched_pairs}</span> matched pairs</div>
    `;

  // Certificates table
  resultsBody.innerHTML = "";
  visible.sort((a, b) => {
    const typeOrder = { leaf: 0, intermediate: 1, root: 2 };
    return (typeOrder[a.cert_type] || 3) - (typeOrder[b.cert_type] || 3);
  });

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

  // Sync select-all checkbox state
  updateSelectAll();
  updateExportBtn();
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

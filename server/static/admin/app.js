const state = {
  adminToken: "",
  currentLicenseKey: "",
  currentLicense: null,
};

const el = {
  tabs: [...document.querySelectorAll(".tab-btn")],
  panels: {
    generate: document.getElementById("tab-generate"),
    manage: document.getElementById("tab-manage"),
    activations: document.getElementById("tab-activations"),
    "license-list": document.getElementById("tab-license-list"),
    downloads: document.getElementById("tab-downloads"),
  },
  message: document.getElementById("message"),

  adminTokenInput: document.getElementById("adminTokenInput"),
  btnSetToken: document.getElementById("btnSetToken"),

  durationSelect: document.getElementById("durationSelect"),
  customDaysWrap: document.getElementById("customDaysWrap"),
  customDaysInput: document.getElementById("customDaysInput"),
  maxDevicesSelect: document.getElementById("maxDevicesSelect"),
  productInput: document.getElementById("productInput"),
  btnGenerate: document.getElementById("btnGenerate"),
  licenseOutput: document.getElementById("licenseOutput"),
  btnCopyKey: document.getElementById("btnCopyKey"),

  lookupKeyInput: document.getElementById("lookupKeyInput"),
  btnLookup: document.getElementById("btnLookup"),
  detailStatus: document.getElementById("detailStatus"),
  detailExpiration: document.getElementById("detailExpiration"),
  detailMaxDevices: document.getElementById("detailMaxDevices"),
  detailActivationCount: document.getElementById("detailActivationCount"),
  btnRevoke: document.getElementById("btnRevoke"),
  deviceSelect: document.getElementById("deviceSelect"),
  btnDeactivateSelected: document.getElementById("btnDeactivateSelected"),

  activationsKeyInput: document.getElementById("activationsKeyInput"),
  btnLoadActivations: document.getElementById("btnLoadActivations"),
  activationsTableBody: document.getElementById("activationsTableBody"),

  licenseListStatus: document.getElementById("licenseListStatus"),
  includeExpiredToggle: document.getElementById("includeExpiredToggle"),
  btnLoadLicenseList: document.getElementById("btnLoadLicenseList"),
  licenseListMeta: document.getElementById("licenseListMeta"),
  licenseListTableBody: document.getElementById("licenseListTableBody"),

  downloadVersion: document.getElementById("downloadVersion"),
  downloadDirectUrl: document.getElementById("downloadDirectUrl"),
  downloadCommand: document.getElementById("downloadCommand"),
  btnCopyDirectUrl: document.getElementById("btnCopyDirectUrl"),
  btnCopyDownloadCommand: document.getElementById("btnCopyDownloadCommand"),
  btnRefreshDownloads: document.getElementById("btnRefreshDownloads"),
};

function showMessage(type, text) {
  el.message.className = `message ${type}`;
  el.message.textContent = text;
}

function clearMessage() {
  el.message.className = "message hidden";
  el.message.textContent = "";
}

function setActiveTab(tabName) {
  el.tabs.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });

  Object.entries(el.panels).forEach(([name, panel]) => {
    panel.classList.toggle("active", name === tabName);
  });

  if (tabName === "license-list" && state.adminToken) {
    void loadLicenseList({ silent: true });
  }

  if (tabName === "downloads") {
    void refreshDownloadInfo({ silent: true });
  }
}

function normalizeKey(raw) {
  return (raw || "").trim().toUpperCase();
}

function requireAdminToken() {
  if (!state.adminToken) {
    showMessage("error", "Enter your admin token and click Unlock first.");
    return false;
  }
  return true;
}

function getExpirationDateIso() {
  const selected = el.durationSelect.value;
  let days = 0;

  if (selected === "custom") {
    days = Number(el.customDaysInput.value || 0);
  } else {
    days = Number(selected);
  }

  if (!Number.isFinite(days) || days < 1) {
    throw new Error("Duration must be at least 1 day.");
  }

  const now = new Date();
  now.setDate(now.getDate() + days);
  return now.toISOString().slice(0, 10);
}

function formatDate(value, includeTime = false) {
  if (!value) {
    return "-";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return String(value);
  }

  return includeTime ? parsed.toLocaleString() : parsed.toLocaleDateString();
}

async function parseError(response) {
  try {
    const payload = await response.json();
    if (payload && typeof payload.detail === "string") {
      return payload.detail;
    }
    return JSON.stringify(payload);
  } catch {
    return `Request failed (${response.status})`;
  }
}

async function apiFetch(path, options = {}) {
  if (!requireAdminToken()) {
    throw new Error("Admin token missing");
  }

  const headers = {
    "Content-Type": "application/json",
    "X-Admin-Token": state.adminToken,
    ...(options.headers || {}),
  };

  const response = await fetch(path, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const reason = await parseError(response);
    throw new Error(reason);
  }

  if (response.status === 204) {
    return {};
  }

  return response.json();
}

async function publicFetch(path) {
  const response = await fetch(path, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    const reason = await parseError(response);
    throw new Error(reason);
  }

  return response.json();
}

async function unlockDashboard() {
  const token = el.adminTokenInput.value.trim();
  if (!token) {
    showMessage("error", "Admin token is required.");
    return;
  }

  const previousToken = state.adminToken;
  state.adminToken = token;

  try {
    await apiFetch("/licenses?status=active&include_expired=true", { method: "GET" });
    showMessage("success", "Dashboard unlocked. Admin header will be included automatically.");
    void loadLicenseList({ silent: true });
  } catch (err) {
    const msg = String(err && err.message ? err.message : err);
    state.adminToken = previousToken;
    showMessage("error", `Token check failed: ${msg}`);
  }
}

function setGenerateBusy(isBusy) {
  el.btnGenerate.disabled = isBusy;
  el.btnGenerate.textContent = isBusy ? "Generating..." : "Generate License";
}

async function generateLicense() {
  clearMessage();

  if (!requireAdminToken()) {
    return;
  }

  const product = el.productInput.value.trim();
  const maxDevices = Number(el.maxDevicesSelect.value);

  if (!product) {
    showMessage("error", "Product name is required.");
    return;
  }

  let expirationDate;
  try {
    expirationDate = getExpirationDateIso();
  } catch (err) {
    showMessage("error", String(err && err.message ? err.message : err));
    return;
  }

  setGenerateBusy(true);
  try {
    const result = await apiFetch("/generate", {
      method: "POST",
      body: JSON.stringify({
        product,
        max_devices: maxDevices,
        expiration_date: expirationDate,
      }),
    });

    el.licenseOutput.textContent = result.license_key;
    el.btnCopyKey.disabled = false;
    el.lookupKeyInput.value = result.license_key;
    el.activationsKeyInput.value = result.license_key;

    showMessage("success", "License generated successfully.");
    void loadLicenseList({ silent: true });
  } catch (err) {
    showMessage("error", `Generate failed: ${err.message || err}`);
  } finally {
    setGenerateBusy(false);
  }
}

function renderLicenseDetails(licenseKey, details) {
  state.currentLicenseKey = licenseKey;
  state.currentLicense = details;

  el.detailStatus.textContent = details.status || "-";
  el.detailExpiration.textContent = details.expiration_date || "No expiration";
  el.detailMaxDevices.textContent = String(details.max_devices ?? "-");
  el.detailActivationCount.textContent = String(details.activation_count ?? 0);

  el.btnRevoke.disabled = false;

  const activations = Array.isArray(details.activations) ? details.activations : [];
  el.deviceSelect.innerHTML = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = activations.length ? "Select device" : "No devices";
  el.deviceSelect.appendChild(placeholder);

  activations.forEach((a) => {
    const opt = document.createElement("option");
    opt.value = a.device_id;
    opt.textContent = `${a.device_name} (${a.device_id.slice(0, 12)}...)`;
    el.deviceSelect.appendChild(opt);
  });

  el.deviceSelect.disabled = activations.length === 0;
  el.btnDeactivateSelected.disabled = activations.length === 0;

  renderActivationsTable(activations, licenseKey);
}

function renderActivationsTable(activations, licenseKey) {
  if (!activations.length) {
    el.activationsTableBody.innerHTML = '<tr><td colspan="5" class="empty">No activated devices.</td></tr>';
    return;
  }

  el.activationsTableBody.innerHTML = "";
  activations.forEach((a) => {
    const row = document.createElement("tr");
    const date = formatDate(a.activated_at, true);

    row.innerHTML = `
      <td>${escapeHtml(a.device_name || "-")}</td>
      <td><code>${escapeHtml(a.device_id || "-")}</code></td>
      <td>${escapeHtml(date)}</td>
      <td>${escapeHtml(a.ip_address || "-")}</td>
      <td><button class="row-action" data-device-id="${escapeHtml(a.device_id)}" data-license-key="${escapeHtml(licenseKey)}">Deactivate</button></td>
    `;

    el.activationsTableBody.appendChild(row);
  });
}

function statusBadge(statusText, isExpired) {
  const status = String(statusText || "unknown").toLowerCase();
  if (status === "active" && isExpired) {
    return '<span class="status-pill expired">Expired</span>';
  }

  if (status === "active") {
    return '<span class="status-pill active">Active</span>';
  }

  if (status === "revoked") {
    return '<span class="status-pill revoked">Revoked</span>';
  }

  if (status === "suspended") {
    return '<span class="status-pill suspended">Suspended</span>';
  }

  return `<span class="status-pill suspended">${escapeHtml(status)}</span>`;
}

function renderLicenseList(items, total) {
  const safeItems = Array.isArray(items) ? items : [];
  const count = Number.isFinite(Number(total)) ? Number(total) : safeItems.length;

  el.licenseListMeta.textContent = `${count} license${count === 1 ? "" : "s"} loaded.`;

  if (!safeItems.length) {
    el.licenseListTableBody.innerHTML = '<tr><td colspan="7" class="empty">No licenses matched your filter.</td></tr>';
    return;
  }

  el.licenseListTableBody.innerHTML = "";

  safeItems.forEach((item) => {
    const row = document.createElement("tr");
    const deviceUsage = `${Number(item.activation_count || 0)} / ${Number(item.max_devices || 0)}`;
    const keyText = String(item.license_key || "UNAVAILABLE");
    const keyCellClass = item.full_key_available ? "mono-key" : "mono-key legacy-key";
    const isRevoked = String(item.status || "").toLowerCase() === "revoked";
    const actionHtml = isRevoked
      ? '<span class="muted-dash">-</span>'
      : `<button class="row-action row-revoke" data-license-id="${escapeHtml(String(item.id || ""))}" data-license-key="${escapeHtml(keyText)}">Revoke</button>`;

    row.innerHTML = `
      <td class="${escapeHtml(keyCellClass)}">${escapeHtml(keyText)}</td>
      <td>${escapeHtml(item.product || "-")}</td>
      <td>${statusBadge(item.status, Boolean(item.is_expired))}</td>
      <td>${escapeHtml(deviceUsage)}</td>
      <td>${escapeHtml(item.expiration_date || "No expiration")}</td>
      <td>${escapeHtml(formatDate(item.created_at, true))}</td>
      <td>${actionHtml}</td>
    `;

    el.licenseListTableBody.appendChild(row);
  });
}

async function loadLicenseList({ silent = false } = {}) {
  if (!silent) {
    clearMessage();
  }

  if (!requireAdminToken()) {
    return;
  }

  const params = new URLSearchParams({
    status: el.licenseListStatus.value || "active",
    include_expired: el.includeExpiredToggle.checked ? "true" : "false",
  });

  try {
    const result = await apiFetch(`/licenses?${params.toString()}`, { method: "GET" });
    renderLicenseList(result.items || [], result.total);

    if (!silent) {
      showMessage("success", "License list loaded.");
    }
  } catch (err) {
    if (!silent) {
      showMessage("error", `Load list failed: ${err.message || err}`);
    }
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function lookupLicense(rawKey) {
  clearMessage();

  if (!requireAdminToken()) {
    return;
  }

  const key = normalizeKey(rawKey || el.lookupKeyInput.value);
  if (!key) {
    showMessage("error", "License key is required.");
    return;
  }

  try {
    const details = await apiFetch(`/license/${encodeURIComponent(key)}`, { method: "GET" });
    el.lookupKeyInput.value = key;
    el.activationsKeyInput.value = key;
    renderLicenseDetails(key, details);
    showMessage("success", "License loaded.");
  } catch (err) {
    showMessage("error", `Lookup failed: ${err.message || err}`);
  }
}

async function revokeLicenseById(licenseId, label) {
  const idNum = Number(licenseId || 0);
  if (!Number.isFinite(idNum) || idNum < 1) {
    showMessage("error", "Invalid license ID.");
    return;
  }

  const shown = String(label || `ID ${idNum}`);
  const confirmed = window.confirm(`Revoke ${shown}? This cannot be undone.`);
  if (!confirmed) {
    return;
  }

  try {
    await apiFetch("/revoke-by-id", {
      method: "POST",
      body: JSON.stringify({ license_id: idNum }),
    });

    showMessage("success", `License revoked (${shown}).`);
    await loadLicenseList({ silent: true });
  } catch (err) {
    showMessage("error", `Revoke failed: ${err.message || err}`);
  }
}

async function revokeCurrentLicense() {
  const key = normalizeKey(state.currentLicenseKey || el.lookupKeyInput.value);
  if (!key) {
    showMessage("error", "Lookup a license before revoking.");
    return;
  }

  const confirmed = window.confirm(`Revoke license ${key}? This cannot be undone.`);
  if (!confirmed) {
    return;
  }

  try {
    await apiFetch("/revoke", {
      method: "POST",
      body: JSON.stringify({ license_key: key }),
    });

    showMessage("success", `License ${key} revoked.`);
    await lookupLicense(key);
    void loadLicenseList({ silent: true });
  } catch (err) {
    showMessage("error", `Revoke failed: ${err.message || err}`);
  }
}

async function deactivateDevice(licenseKey, deviceId) {
  const key = normalizeKey(licenseKey);
  const device = String(deviceId || "").trim();

  if (!key || !device) {
    showMessage("error", "License key and device are required for deactivation.");
    return;
  }

  const confirmed = window.confirm(`Deactivate device ${device} from ${key}?`);
  if (!confirmed) {
    return;
  }

  try {
    await apiFetch("/deactivate", {
      method: "POST",
      body: JSON.stringify({
        license_key: key,
        device_id: device,
      }),
    });

    showMessage("success", `Device ${device} deactivated.`);
    await lookupLicense(key);
    void loadLicenseList({ silent: true });
  } catch (err) {
    showMessage("error", `Deactivate failed: ${err.message || err}`);
  }
}

async function copyToClipboard(value, successMessage) {
  const text = String(value || "").trim();
  if (!text || text === "Not published" || text === "----") {
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    showMessage("success", successMessage);
  } catch {
    showMessage("error", "Clipboard access failed.");
  }
}

async function copyCurrentKey() {
  await copyToClipboard(el.licenseOutput.textContent, "License key copied to clipboard.");
}

function setDownloadUnavailable(reason = "Not published") {
  el.downloadVersion.value = reason;
  el.downloadDirectUrl.value = reason;
  el.downloadCommand.value = reason;
  el.btnCopyDirectUrl.disabled = true;
  el.btnCopyDownloadCommand.disabled = true;
}

function buildInstallCommand(scriptUrl) {
  return `powershell -NoProfile -ExecutionPolicy Bypass -Command "irm '${scriptUrl}' | iex"`;
}

function renderDownloadInfo(metadata) {
  const version = String(metadata.version || "latest");
  const fileName = String(metadata.file_name || metadata.latest_file_name || "MacroSuiteSetup.exe");
  const directUrl = String(metadata.download_url || new URL("/download/latest", window.location.origin).toString());
  const scriptUrl = String(metadata.install_script_url || new URL("/download/install.ps1", window.location.origin).toString());
  const command = buildInstallCommand(scriptUrl);

  el.downloadVersion.value = `${version} (${fileName})`;
  el.downloadDirectUrl.value = directUrl;
  el.downloadCommand.value = command;
  el.btnCopyDirectUrl.disabled = false;
  el.btnCopyDownloadCommand.disabled = false;
}

async function refreshDownloadInfo({ silent = false } = {}) {
  try {
    const metadata = await publicFetch("/download/latest.json");
    renderDownloadInfo(metadata);
    if (!silent) {
      showMessage("success", "Download information refreshed.");
    }
  } catch (err) {
    setDownloadUnavailable("Not published");
    if (!silent) {
      showMessage("error", `Download info unavailable: ${err.message || err}`);
    }
  }
}

function wireEvents() {
  el.tabs.forEach((btn) => {
    btn.addEventListener("click", () => setActiveTab(btn.dataset.tab));
  });

  el.durationSelect.addEventListener("change", () => {
    const isCustom = el.durationSelect.value === "custom";
    el.customDaysWrap.classList.toggle("hidden", !isCustom);
  });

  el.btnSetToken.addEventListener("click", unlockDashboard);

  el.btnGenerate.addEventListener("click", generateLicense);
  el.btnCopyKey.addEventListener("click", copyCurrentKey);

  el.btnLookup.addEventListener("click", () => lookupLicense(el.lookupKeyInput.value));
  el.btnRevoke.addEventListener("click", revokeCurrentLicense);

  el.btnDeactivateSelected.addEventListener("click", () => {
    deactivateDevice(el.lookupKeyInput.value, el.deviceSelect.value);
  });

  el.btnLoadActivations.addEventListener("click", () => {
    void lookupLicense(el.activationsKeyInput.value);
    setActiveTab("activations");
  });

  el.activationsTableBody.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    if (!target.classList.contains("row-action")) {
      return;
    }

    const licenseKey = target.getAttribute("data-license-key") || el.activationsKeyInput.value;
    const deviceId = target.getAttribute("data-device-id") || "";
    void deactivateDevice(licenseKey, deviceId);
  });

  el.btnLoadLicenseList.addEventListener("click", () => {
    void loadLicenseList({ silent: false });
  });

  el.licenseListStatus.addEventListener("change", () => {
    if (el.panels["license-list"].classList.contains("active") && state.adminToken) {
      void loadLicenseList({ silent: true });
    }
  });

  el.includeExpiredToggle.addEventListener("change", () => {
    if (el.panels["license-list"].classList.contains("active") && state.adminToken) {
      void loadLicenseList({ silent: true });
    }
  });

  el.licenseListTableBody.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    if (!target.classList.contains("row-revoke")) {
      return;
    }

    const licenseId = target.getAttribute("data-license-id") || "";
    const licenseLabel = target.getAttribute("data-license-key") || licenseId;
    void revokeLicenseById(licenseId, licenseLabel);
  });

  el.btnRefreshDownloads.addEventListener("click", () => {
    void refreshDownloadInfo({ silent: false });
  });

  el.btnCopyDirectUrl.addEventListener("click", () => {
    void copyToClipboard(el.downloadDirectUrl.value, "Direct download URL copied.");
  });

  el.btnCopyDownloadCommand.addEventListener("click", () => {
    void copyToClipboard(el.downloadCommand.value, "Install command copied.");
  });
}

setDownloadUnavailable("Not published");
wireEvents();

(() => {
  "use strict";

  const PATHS = {
    status: "/v0/management/plugins/key-model-access/status",
    policies: "/v0/management/plugins/key-model-access/policies",
    reload: "/v0/management/plugins/key-model-access/reload",
    initializeStorage: "/v0/management/plugins/key-model-access/initialize-storage",
    pluginList: "/v0/management/plugins",
    pluginConfig: "/v0/management/plugins/key-model-access/config",
    apiKeys: "/v0/management/api-keys",
    models: "/v1/models"
  };

  const CPAMC_AUTH_KEY = "cli-proxy-auth";
  const CPAMC_THEME_KEY = "cli-proxy-theme";
  const OBFUSCATION_PREFIX = "enc::v1::";
  const OBFUSCATION_SALT = "cli-proxy-api-webui::secure-storage";

  const icons = {
    search: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>',
    overview: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg>',
    key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M15 12v2"/></svg>',
    refresh: '<svg viewBox="0 0 24 24"><path d="M20 6v5h-5M4 18v-5h5"/><path d="M6.1 8.2A7 7 0 0 1 18.8 9M17.9 15.8A7 7 0 0 1 5.2 15"/></svg>',
    file: '<svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></svg>',
    save: '<svg viewBox="0 0 24 24"><path d="M5 4h12l2 2v14H5z"/><path d="M8 4v6h8V4M8 20v-6h8v6"/></svg>',
    close: '<svg viewBox="0 0 24 24"><path d="m7 7 10 10M17 7 7 17"/></svg>',
    warning: '<svg viewBox="0 0 24 24"><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4M12 16.5h.01"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>',
    spinner: '<svg class="spinner" viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-9 9"/><path d="M3 12a9 9 0 0 1 9-9" opacity=".35"/></svg>'
  };

  const state = {
    token: "",
    status: null,
    keys: [],
    models: [],
    modelsError: "",
    persistenceSetupError: "",
    stalePolicies: [],
    revision: 0,
    selectedIndex: -1,
    dirty: false,
    busy: false,
    modelBusy: false,
    sessionBusy: false,
    sessionEnded: false,
    pendingDraft: null,
    pendingScope: "",
    search: "",
    openPicker: "",
    pickerQuery: "",
    pickerScroll: 0
  };

  const $ = (selector) => document.querySelector(selector);
  const authGate = $("#authGate");
  const app = $("#app");
  const editor = $("#editor");
  const nav = $("#policyNav");
  const saveButton = $("#saveButton");
  const reloadButton = $("#reloadButton");
  const refreshDataButton = $("#refreshDataButton");
  const healthBadge = $("#healthBadge");
  let navFrame = 0;

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
    })[character]);
  }

  // Mirrors CPAMC secureStorage v1. This is reversible obfuscation for session
  // compatibility, not cryptography and not a new security boundary.
  function decodeStoredValue(raw) {
    if (!raw || !raw.startsWith(OBFUSCATION_PREFIX)) return raw;
    const encoded = atob(raw.slice(OBFUSCATION_PREFIX.length));
    const encrypted = Uint8Array.from(encoded, (character) => character.charCodeAt(0));
    const key = new TextEncoder().encode(`${OBFUSCATION_SALT}|${window.location.host}|${navigator.userAgent}`);
    const decoded = new Uint8Array(encrypted.length);
    for (let index = 0; index < encrypted.length; index += 1) decoded[index] = encrypted[index] ^ key[index % key.length];
    return new TextDecoder().decode(decoded);
  }

  function readStoredValue(name) {
    try {
      const raw = localStorage.getItem(name);
      if (raw === null) return null;
      const decoded = decodeStoredValue(raw);
      try { return JSON.parse(decoded); } catch (_) { return decoded; }
    } catch (_) {
      return null;
    }
  }

  function readCPAMCManagementKey() {
    try {
      if (localStorage.getItem("isLoggedIn") !== "true") return "";
      const persisted = readStoredValue(CPAMC_AUTH_KEY);
      const current = persisted && typeof persisted === "object" ? persisted.state?.managementKey : "";
      if (typeof current === "string" && current.trim()) return current.trim();
      const legacy = readStoredValue("managementKey");
      return typeof legacy === "string" ? legacy.trim() : "";
    } catch (_) {
      return "";
    }
  }

  function normalizeModels(value) {
    if (!Array.isArray(value)) return [];
    return [...new Set(value.map((model) => String(model).trim()).filter(Boolean))];
  }

  function modelPatternMatches(pattern, model) {
    const source = String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
    try { return new RegExp(`^${source}$`).test(model); } catch (_) { return false; }
  }

  function normalizePolicyDocument(raw) {
    if (!raw || typeof raw !== "object" || raw.version !== 2 || !Array.isArray(raw.policies)) {
      throw new Error("The plugin returned an invalid v2 policy document.");
    }
    const seen = new Set();
    const policies = raw.policies.map((item, index) => {
      if (!item || typeof item !== "object") throw new Error(`Policy ${index + 1} is malformed.`);
      const scope = typeof item.caller_scope === "string" ? item.caller_scope.trim().toLowerCase() : "";
      if (!/^[0-9a-f]{64}$/.test(scope)) throw new Error(`Policy ${index + 1} has an invalid caller scope.`);
      if (seen.has(scope)) throw new Error(`Policy ${index + 1} has a duplicate caller scope.`);
      seen.add(scope);
      for (const field of ["allow_models", "deny_models"]) {
        if (!Array.isArray(item[field]) || item[field].some((model) => typeof model !== "string" || !model.trim())) {
          throw new Error(`Policy ${index + 1} has an invalid ${field}.`);
        }
      }
      return {
        caller_scope: scope,
        allow_models: normalizeModels(item.allow_models),
        deny_models: normalizeModels(item.deny_models)
      };
    });
    return { version: 2, policies };
  }

  function shortFingerprint(scope) {
    return `${scope.slice(0, 10)}…${scope.slice(-6)}`;
  }

  function keyLabel(index) {
    return `CPA API Key ${String(index + 1).padStart(2, "0")}`;
  }

  async function api(path, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const timeout = options.timeout || (method === "GET" ? 12000 : 20000);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, {
        ...options,
        method,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${state.token}`,
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...(options.headers || {})
        },
        cache: "no-store"
      });
      let payload = null;
      try { payload = await response.json(); } catch (_) { payload = null; }
      if (!response.ok) {
        const detail = payload && (payload.error?.message || payload.error);
        const error = new Error(detail ? String(detail) : `Request failed (HTTP ${response.status})`);
        error.status = response.status;
        throw error;
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") {
        const timeoutError = new Error(method === "GET" ? "CPA timed out. Check that the service is up." : "The operation timed out; whether it was applied is not yet confirmed.");
        timeoutError.code = "timeout";
        throw timeoutError;
      }
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function sha256Hex(value) {
    const bytes = new TextEncoder().encode(value);
    if (window.crypto?.subtle) {
      const digest = await window.crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    // SubtleCrypto is unavailable on plain HTTP origins other than localhost.
    // Keep remote CPA panels functional without sending raw API keys elsewhere.
    return sha256FallbackHex(bytes);
  }

  function sha256FallbackHex(bytes) {
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const stateWords = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLength);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const bitLength = bytes.length * 8;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(paddedLength - 4, bitLength >>> 0, false);
    const words = new Uint32Array(64);
    const rotateRight = (word, count) => (word >>> count) | (word << (32 - count));

    for (let offset = 0; offset < paddedLength; offset += 64) {
      for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(offset + index * 4, false);
      for (let index = 16; index < 64; index += 1) {
        const left = words[index - 15];
        const right = words[index - 2];
        const sigma0 = rotateRight(left, 7) ^ rotateRight(left, 18) ^ (left >>> 3);
        const sigma1 = rotateRight(right, 17) ^ rotateRight(right, 19) ^ (right >>> 10);
        words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = stateWords;
      for (let index = 0; index < 64; index += 1) {
        const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
        const choose = (e & f) ^ (~e & g);
        const temp1 = (h + sum1 + choose + constants[index] + words[index]) >>> 0;
        const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (sum0 + majority) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      stateWords[0] = (stateWords[0] + a) >>> 0;
      stateWords[1] = (stateWords[1] + b) >>> 0;
      stateWords[2] = (stateWords[2] + c) >>> 0;
      stateWords[3] = (stateWords[3] + d) >>> 0;
      stateWords[4] = (stateWords[4] + e) >>> 0;
      stateWords[5] = (stateWords[5] + f) >>> 0;
      stateWords[6] = (stateWords[6] + g) >>> 0;
      stateWords[7] = (stateWords[7] + h) >>> 0;
    }
    return stateWords.map((word) => word.toString(16).padStart(8, "0")).join("");
  }

  async function fetchModelCatalog(apiKey) {
    if (!apiKey) return { models: [], error: "CPA has no API key that can be used to read the model catalogue." };
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(PATHS.models, {
        method: "GET",
        headers: { Accept: "application/json", Authorization: `Bearer ${apiKey}` },
        signal: controller.signal,
        cache: "no-store"
      });
      let payload = null;
      try { payload = await response.json(); } catch (_) { payload = null; }
      if (!response.ok) throw new Error(`Model catalogue request failed (HTTP ${response.status})`);
      const source = Array.isArray(payload) ? payload : Array.isArray(payload?.data) ? payload.data : Array.isArray(payload?.models) ? payload.models : [];
      const seen = new Set();
      const models = source.map((item) => {
        if (typeof item === "string") return { id: item, displayName: "" };
        if (!item || typeof item !== "object") return null;
        const id = String(item.id ?? item.name ?? item.model ?? item.value ?? "").trim();
        const displayName = String(item.display_name ?? item.displayName ?? item.alias ?? "").trim();
        return id ? { id, displayName: displayName === id ? "" : displayName } : null;
      }).filter((item) => {
        if (!item) return false;
        const key = item.id.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      }).sort((left, right) => left.id.localeCompare(right.id));
      return { models, error: models.length ? "" : "CPA's /v1/models returned no models yet." };
    } catch (error) {
      const message = error.name === "AbortError" ? "Loading the model catalogue timed out." : error.message;
      return { models: [], error: message || "Failed to load the model catalogue." };
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function fetchCurrentKeys(options = {}) {
    const payload = await api(PATHS.apiKeys, { method: "GET" });
    const values = Array.isArray(payload?.["api-keys"]) ? payload["api-keys"] : null;
    if (!values) throw new Error("CPA returned an API key list in an unrecognised format.");

    const temporaryValues = values.slice();
    const normalizedValues = temporaryValues.map((value) => String(value).trim()).filter(Boolean);
    try {
      const [scopes, catalog] = await Promise.all([
        Promise.all(normalizedValues.map((value) => sha256Hex(`cli-proxy-api:caller-scope:v1\0${value}`))),
        options.includeCatalog ? fetchModelCatalog(normalizedValues[0] || "") : Promise.resolve(null)
      ]);
      const seen = new Set();
      const keys = scopes.filter((scope) => {
        if (seen.has(scope)) return false;
        seen.add(scope);
        return true;
      }).map((scope) => ({
        scope,
        fingerprint: shortFingerprint(scope),
        mask: "••••••••••••",
        allow_models: [],
        deny_models: []
      }));
      return options.includeCatalog ? { keys, catalog } : keys;
    } finally {
      normalizedValues.fill("");
      temporaryValues.fill("");
      values.fill("");
    }
  }

  async function waitForPersistentStatus(expectedPath) {
    let lastError = null;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (attempt > 0) await new Promise((resolve) => window.setTimeout(resolve, 250));
      try {
        const status = await api(PATHS.status, { method: "GET", timeout: 1500 });
        if (status?.persistent_updates && status.policy_file === expectedPath) return status;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error("CPA saved the plugin config, but timed out waiting for the policy file to take effect.");
  }

  async function initializeDefaultPersistence() {
    const pluginList = await api(PATHS.pluginList, { method: "GET" });
    const pluginsDir = typeof pluginList?.plugins_dir === "string" ? pluginList.plugins_dir.trim() : "";
    if (!pluginsDir) throw new Error("CPA did not return a valid plugins_dir.");
    const initialized = await api(PATHS.initializeStorage, {
      method: "POST",
      body: JSON.stringify({ plugins_dir: pluginsDir })
    });
    const policyFile = typeof initialized?.policy_file === "string" ? initialized.policy_file.trim() : "";
    if (!policyFile) throw new Error("The plugin did not return a default policy file path.");
    await api(PATHS.pluginConfig, {
      method: "PATCH",
      body: JSON.stringify({ policy_file: policyFile })
    });
    return waitForPersistentStatus(policyFile);
  }

  async function fetchRemoteData() {
    // Verify Management authentication once before issuing the remaining reads.
    let status = await api(PATHS.status, { method: "GET" });
    let persistenceSetupError = "";
    if (!status?.persistent_updates) {
      try {
        status = await initializeDefaultPersistence();
      } catch (error) {
        persistenceSetupError = error.message || "Failed to create the plugin policy file automatically.";
      }
    }
    const [policies, keyData] = await Promise.all([
      api(PATHS.policies, { method: "GET" }),
      fetchCurrentKeys({ includeCatalog: true })
    ]);
    return { status, policies, keys: keyData.keys, catalog: keyData.catalog, persistenceSetupError };
  }

  function applyPolicyDocument(rawDocument) {
    const documentValue = normalizePolicyDocument(rawDocument);
    const byScope = new Map(documentValue.policies.map((policy) => [policy.caller_scope, policy]));
    const currentScopes = new Set(state.keys.map((key) => key.scope));

    state.keys = state.keys.map((key) => {
      const policy = byScope.get(key.scope);
      return {
        ...key,
        allow_models: policy ? [...policy.allow_models] : [],
        deny_models: policy ? [...policy.deny_models] : []
      };
    });
    state.stalePolicies = documentValue.policies
      .filter((policy) => !currentScopes.has(policy.caller_scope))
      .map((policy) => ({ ...policy, allow_models: [...policy.allow_models], deny_models: [...policy.deny_models] }));
  }

  function installRemoteData(remote, preferredScope = "") {
    state.status = remote.status;
    state.keys = remote.keys;
    state.models = remote.catalog?.models || [];
    state.modelsError = remote.catalog?.error || "";
    state.persistenceSetupError = remote.persistenceSetupError || "";
    applyPolicyDocument(remote.policies?.policy);
    state.revision = Number(remote.policies?.revision ?? remote.status?.revision ?? 0);
    state.dirty = false;
    state.openPicker = "";
    state.pickerQuery = "";
    state.pickerScroll = 0;
    state.selectedIndex = preferredScope ? state.keys.findIndex((key) => key.scope === preferredScope) : -1;
  }

  function setSessionState(kind, title, message) {
    $("#authTitle").textContent = title;
    $("#authMessage").textContent = message;
    $("#sessionIcon").classList.toggle("error", kind === "error");
    $("#sessionIcon").innerHTML = kind === "loading" ? icons.spinner : kind === "error" ? icons.warning : icons.check;
    $("#retrySessionButton").hidden = kind !== "error";
  }

  async function connectFromCPAMC() {
    if (state.sessionBusy) return;
    const token = readCPAMCManagementKey();
    if (!token) {
      state.token = "";
      setSessionState("error", "No reusable CPAMC session found", "Automatic connection needs CPAMC on the same origin as CPA, logged in with \"Remember password\" on. Check that and come back to retry; the plugin never asks for the Management Key itself.");
      return;
    }
    state.token = token;
    state.sessionBusy = true;
    setSessionState("loading", "Connecting to management session", "Verifying the saved CPAMC connection and loading model policies…");
    try {
      const remote = await fetchRemoteData();
      const pendingDraft = state.pendingDraft;
      const pendingScope = state.pendingScope;
      installRemoteData(remote, pendingScope);
      if (pendingDraft) {
        applyPolicyDocument(pendingDraft);
        state.dirty = true;
        state.pendingDraft = null;
        state.pendingScope = "";
      }
      state.sessionEnded = false;
      authGate.hidden = true;
      app.hidden = false;
      renderAll();
    } catch (error) {
      state.token = "";
      const message = error.status === 401
        ? "The Management Key saved by CPAMC is no longer valid. Log in to CPAMC again with \"Remember password\" on."
        : `Cannot reach CPA: ${error.message}`;
      setSessionState("error", "Management session unavailable", message);
    } finally {
      state.sessionBusy = false;
    }
  }

  function finalizeEndedSession() {
    if (!state.sessionEnded || state.busy || state.modelBusy) return;
    const hadDraft = state.dirty;
    if (hadDraft) {
      state.pendingDraft = serializablePolicy();
      state.pendingScope = selectedKey()?.scope || "";
    }
    state.token = "";
    state.status = null;
    state.keys = [];
    state.models = [];
    state.stalePolicies = [];
    state.dirty = false;
    state.sessionEnded = false;
    app.hidden = true;
    authGate.hidden = false;
    setSessionState("error", "CPAMC session ended", hadDraft
      ? "Your unsaved policy draft is kept in this page's memory. Log in again and it will be restored once the session is back."
      : "Log in to CPAMC again with \"Remember password\" on; this page will reconnect automatically.");
  }

  function setBusy(busy, action = "") {
    state.busy = busy;
    $("#workspace").inert = busy;
    refreshDataButton.disabled = busy || state.modelBusy;
    saveButton.disabled = busy || state.modelBusy || !state.dirty;
    reloadButton.disabled = busy || state.modelBusy || !state.status?.persistent_updates;
    saveButton.innerHTML = action === "save" && busy
      ? `${icons.spinner}<span class="label-long">Saving</span>`
      : `${icons.save}<span class="label-long">${state.dirty ? "Save changes" : "Saved"}</span>`;
    reloadButton.innerHTML = action === "reload" && busy
      ? `${icons.spinner}<span class="label-long">Reloading</span>`
      : `${icons.file}<span class="label-long">Reload from file</span>`;
    refreshDataButton.innerHTML = action === "refresh" && busy
      ? icons.spinner
      : icons.refresh;
    if (!busy) finalizeEndedSession();
  }

  function markDirty() {
    state.dirty = true;
    syncHeader();
  }

  function renderAll() {
    renderNav();
    renderEditor();
    syncHeader();
    syncPersistence();
  }

  function syncHeader() {
    const healthy = state.status && !state.status.last_error;
    const warning = state.status?.last_error;
    healthBadge.innerHTML = `<span class="status-dot ${warning ? "warning" : healthy ? "" : "error"}"></span><span>${escapeHTML(warning ? "Policy warning" : healthy ? `Schema v${state.status.schema_version || 2}` : "Disconnected")}</span>`;
    healthBadge.title = warning ? state.status.last_error : "Plugin is healthy";
    saveButton.disabled = state.busy || state.modelBusy || !state.dirty;
    reloadButton.disabled = state.busy || state.modelBusy || !state.status?.persistent_updates;
    reloadButton.title = state.status?.persistent_updates ? "Reload from policy file" : "No policy_file configured; cannot reload from file";
    saveButton.innerHTML = `${icons.save}<span class="label-long">${state.dirty ? "Save changes" : "Saved"}</span>`;
    $("#policyCount").textContent = `${state.keys.length} current keys`;
  }

  function syncPersistence() {
    const notice = $("#persistenceNotice");
    if (!state.status) return;
    if (state.status.persistent_updates) {
      notice.className = "persistence-notice";
      notice.textContent = `Policies are saved automatically to ${state.status.policy_file}`;
    } else {
      notice.className = "persistence-notice warning";
      notice.textContent = state.persistenceSetupError
        ? `Automatic persistence failed: ${state.persistenceSetupError} Changes are kept in memory only.`
        : "In-memory mode; the plugin policy file is created automatically when this page opens.";
    }
  }

  function scheduleNavRender() {
    if (navFrame) return;
    navFrame = requestAnimationFrame(() => {
      navFrame = 0;
      renderNav();
    });
  }

  function renderNav() {
    const query = state.search.trim().toLowerCase();
    const visible = state.keys.map((key, index) => ({ key, index })).filter(({ key, index }) =>
      !query || key.fingerprint.toLowerCase().includes(query) || keyLabel(index).toLowerCase().includes(query)
    );
    nav.innerHTML = `
      <button class="nav-item" type="button" data-select="overview" aria-current="${state.selectedIndex < 0 ? "page" : "false"}">
        <span class="nav-icon">${icons.overview}</span>
        <span class="nav-copy"><strong>Overview</strong><span>Authentication is handled by CPA</span></span>
      </button>
      <p class="nav-group-label">Current CPA API keys</p>
      ${visible.length ? visible.map(({ key, index }) => `
        <button class="nav-item" type="button" data-select="key" data-index="${index}" aria-current="${state.selectedIndex === index ? "page" : "false"}" aria-label="${escapeHTML(keyLabel(index))}, SHA-256 fingerprint ${escapeHTML(key.fingerprint)}">
          <span class="nav-icon key">${icons.key}</span>
          <span class="nav-copy"><strong>${escapeHTML(keyLabel(index))}</strong><span>SHA-256 ${escapeHTML(key.fingerprint)}</span></span>
        </button>`).join("") : `<p class="empty-nav">${query ? "No matching keys" : "CPA has no API keys"}</p>`}
    `;
  }

  function renderEditor() {
    if (state.selectedIndex >= 0 && state.keys[state.selectedIndex]) {
      renderKeyEditor(state.keys[state.selectedIndex], state.selectedIndex);
      return;
    }
    state.selectedIndex = -1;
    renderOverview();
  }

  function hasRules(key) {
    return key.allow_models.length > 0 || key.deny_models.length > 0;
  }

  function renderOverview() {
    const configured = state.keys.filter(hasRules).length;
    const defaults = state.keys.length - configured;
    const staleCount = state.stalePolicies.length;
    const statusWarning = state.status?.last_error
      ? `<div class="notice">${icons.warning}<span><strong>The last configuration had a problem:</strong> ${escapeHTML(state.status.last_error)}. The last valid policy is still in effect.</span></div>`
      : "";
    const staleWarning = staleCount
      ? `<div class="notice">${icons.warning}<span><strong>${staleCount} stale policies:</strong> these caller scopes match no current CPA key. Saving keeps them as they are rather than silently deleting them; once you are sure the old key is gone for good, remove them in the policy file.</span></div>`
      : "";

    editor.innerHTML = `
      <header class="editor-head">
        <div class="editor-title-wrap">
          <p class="editor-kicker">Access overview</p>
          <h1>Model access overview</h1>
          <p class="editor-subtitle">CPA alone creates, deletes and manages API keys; this page only sets model rules for keys that already exist.</p>
        </div>
      </header>
      ${statusWarning}
      ${staleWarning}
      <section class="overview-grid" aria-label="Access statistics">
        ${statCard("Current CPA keys", state.keys.length, "read-only sync")}
        ${statCard("Configured", configured, "has allow or deny")}
        ${statCard("Allowed by default", defaults, "no model rules")}
        ${statCard("Stale policies", staleCount, "kept on save", staleCount > 0)}
      </section>
      <section class="card">
        <div class="card-head"><h2>Authentication boundary</h2><p>Key identity and model authorisation are separate.</p></div>
        <div class="info-callout">
          <span class="callout-icon">${icons.key}</span>
          <div><strong>Authentication is done by CPA's built-in API keys</strong><p>The plugin only receives the caller scope CPA provides and enforces allow_models and deny_models against it. With no policy, or empty rules, every model is allowed.</p></div>
        </div>
      </section>
      <section class="card">
        <div class="card-head"><h2>Runtime status</h2><p>From the running CPA plugin instance.</p></div>
        ${statusRow("Auth mode", displayAuthMode(state.status?.auth_mode))}
        ${statusRow("Identity source", state.status?.identity_source || "—")}
        ${statusRow("Keys without a policy", state.status?.unconfigured_key_action === "allow" ? "All models allowed" : state.status?.unconfigured_key_action || "—")}
        ${statusRow("Policies loaded", state.status?.policy_count ?? "—")}
        ${statusRow("Policy revision", `rev-${state.revision}`)}
        ${statusRow("Policy source", state.status?.source || "—")}
        ${statusRow("Last updated", formatDate(state.status?.updated_at))}
      </section>`;
  }

  function statCard(label, value, note, warning = false) {
    return `<article class="stat-card ${warning ? "warning" : ""}"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong><small>${escapeHTML(note)}</small></article>`;
  }

  function displayAuthMode(value) {
    return value === "cpa_builtin_api_keys" ? "CPA built-in API keys" : value || "—";
  }

  function statusRow(label, value) {
    return `<div class="setting-row"><div class="setting-copy"><strong>${escapeHTML(label)}</strong></div><div class="setting-control mono">${escapeHTML(value)}</div></div>`;
  }

  function renderKeyEditor(key, index) {
    const empty = !hasRules(key);
    editor.innerHTML = `
      <header class="editor-head">
        <div class="editor-title-wrap">
          <p class="editor-kicker">Existing CPA key</p>
          <h1>${escapeHTML(keyLabel(index))}</h1>
          <p class="editor-subtitle key-summary"><span>${key.mask}</span><span class="mono">SHA-256 ${escapeHTML(key.fingerprint)}</span></p>
        </div>
      </header>
      ${empty ? `<div class="default-notice">${icons.check}<span><strong>All models are currently allowed.</strong> A policy is written for this key only once you pick allowed or denied models from the catalogue.</span></div>` : ""}
      <section class="card rules-card">
        <div class="card-head"><h2>Model rules</h2><p>Pick straight from CPA's model catalogue; deny rules always win over allow rules.</p></div>
        ${modelPicker("allow_models", "Allowed models", "When set, only these models are allowed", key.allow_models, false)}
        ${modelPicker("deny_models", "Denied models", "Always refused when matched", key.deny_models, true)}
      </section>
      <div class="privacy-note">The Management Key comes from CPAMC's saved same-origin session; CPA API keys are used only to compute caller scopes and read the model catalogue, and are never written to the DOM, browser storage or URLs.</div>`;
    editor.dataset.keyIndex = String(index);
  }

  function modelPicker(kind, title, description, selectedModels, deny) {
    const selected = new Set(selectedModels);
    const wildcardRules = selectedModels.filter((model) => model.includes("*") || model.includes("?"));
    const wildcardSelected = selected.has("*");
    const matchedRuleFor = (model) => wildcardRules.find((rule) => modelPatternMatches(rule, model)) || "";
    const effectiveCatalogCount = state.models.filter((model) => selected.has(model.id) || matchedRuleFor(model.id)).length;
    const isOpen = state.openPicker === kind;
    const summary = wildcardSelected
      ? "All models (*, including future ones)"
      : state.models.length
        ? effectiveCatalogCount ? `${effectiveCatalogCount} / ${state.models.length} models matched` : `Choose from ${state.models.length} models`
        : selectedModels.length ? `${selectedModels.length} existing rules kept` : "Model catalogue unavailable";
    const chips = selectedModels.length
      ? selectedModels.map((model) => {
          const wildcard = model.includes("*") || model.includes("?");
          const outsideCatalog = !wildcard && !state.models.some((candidate) => candidate.id === model);
          return `<span class="chip ${deny ? "deny" : ""}"><span>${escapeHTML(model)}</span>${wildcard ? '<small>wildcard</small>' : outsideCatalog ? '<small>not in catalogue</small>' : ""}<button class="chip-remove" type="button" data-action="remove-model" data-kind="${kind}" data-model="${escapeHTML(model)}" aria-label="Remove this model rule">${icons.close}</button></span>`;
        }).join("")
      : '<span class="empty-chips">No models selected</span>';
    const wildcardRow = `<button class="model-option wildcard-option ${wildcardSelected ? "selected" : ""}" type="button" role="option" aria-selected="${wildcardSelected}" data-action="toggle-model" data-kind="${kind}" data-model="*" data-search="all models wildcard *">
      <span class="model-checkbox" aria-hidden="true">${wildcardSelected ? icons.check : ""}</span>
      <span class="model-option-copy"><strong>All models</strong><small>${deny ? "* · this key will be refused every model" : "* · includes future models automatically"}</small></span>
      <span class="model-badge">wildcard</span>
    </button>`;
    const commonWildcards = ["gpt-*", "claude-*", "gemini-*", "qwen-*", "deepseek-*", "grok-*", "kimi-*", "glm-*", "minimax-*"];
    const presetRows = commonWildcards.filter((rule) => selected.has(rule) || state.models.some((model) => modelPatternMatches(rule, model.id))).map((rule) => {
      const explicit = selected.has(rule);
      const derived = wildcardSelected && !explicit;
      const checked = explicit || derived;
      const matchCount = state.models.filter((model) => modelPatternMatches(rule, model.id)).length;
      return `<button class="model-option preset-option ${checked ? "selected" : ""} ${derived ? "derived" : ""}" type="button" role="option" aria-selected="${checked}" aria-disabled="${derived}" data-action="toggle-model" data-kind="${kind}" data-model="${rule}" data-locked="${derived}" data-search="${rule} wildcard">
        <span class="model-checkbox" aria-hidden="true">${checked ? icons.check : ""}</span>
        <span class="model-option-copy"><strong>${rule}</strong><small>matches ${matchCount} models now, plus future ones with this prefix</small></span>
        <span class="model-badge">wildcard</span>
      </button>`;
    }).join("");
    const rows = state.models.map((model) => {
      const explicit = selected.has(model.id);
      const matchedRule = explicit ? "" : matchedRuleFor(model.id);
      const derived = Boolean(matchedRule);
      const checked = explicit || derived;
      return `<button class="model-option ${checked ? "selected" : ""} ${derived ? "derived" : ""}" type="button" role="option" aria-selected="${checked}" aria-disabled="${derived}" data-action="toggle-model" data-kind="${kind}" data-model="${escapeHTML(model.id)}" data-locked="${derived}" data-search="${escapeHTML(`${model.id} ${model.displayName}`.toLowerCase())}">
        <span class="model-checkbox" aria-hidden="true">${checked ? icons.check : ""}</span>
        <span class="model-option-copy"><strong>${escapeHTML(model.id)}</strong>${model.displayName ? `<small>${escapeHTML(model.displayName)}</small>` : ""}${derived ? `<small>matched by wildcard ${escapeHTML(matchedRule)}</small>` : ""}</span>
        ${derived ? '<span class="model-badge">wildcard</span>' : ""}
      </button>`;
    }).join("");

    return `<div class="model-editor ${deny ? "deny" : ""}">
      <div class="tag-head"><div><strong>${escapeHTML(title)}</strong><span>${escapeHTML(description)}</span></div><span class="selection-count">${selectedModels.length} rules</span></div>
      <button class="model-trigger ${isOpen ? "open" : ""}" type="button" data-action="toggle-picker" data-kind="${kind}" aria-expanded="${isOpen}">
        <span>${escapeHTML(summary)}</span><span class="picker-chevron" aria-hidden="true">⌄</span>
        ${state.models.length ? `<progress class="selection-meter" max="${state.models.length}" value="${effectiveCatalogCount}" aria-label="${effectiveCatalogCount} / ${state.models.length} models matched"></progress>` : ""}
      </button>
      ${isOpen ? `<div class="model-panel">
        ${state.models.length ? `<div class="model-search"><span>${icons.search}</span><input type="search" data-model-search="${kind}" value="${escapeHTML(state.pickerQuery)}" autocomplete="off" placeholder="Search models…" aria-label="Search ${escapeHTML(title)}"></div>
        <div class="model-list" role="listbox" aria-multiselectable="true">${wildcardRow}${presetRows}${rows}<p class="model-empty" hidden>No matching models</p></div>
        <div class="model-panel-footer"><span>${effectiveCatalogCount} / ${state.models.length} matched</span><div><button type="button" data-action="select-all-models" data-kind="${kind}">Select whole catalogue</button><button type="button" data-action="clear-models" data-kind="${kind}">Clear</button></div></div>`
        : `<div class="model-list compact" role="listbox" aria-multiselectable="true">${wildcardRow}</div><div class="catalog-notice"><span>${escapeHTML(state.modelsError || "No model catalogue available.")}</span><button type="button" data-action="refresh-models">Reload</button></div>`}
      </div>` : ""}
      <div class="chips">${chips}</div>
    </div>`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function selectedKey() {
    return state.selectedIndex >= 0 ? state.keys[state.selectedIndex] : null;
  }

  function validModelKind(kind) {
    return kind === "allow_models" || kind === "deny_models";
  }

  function restorePickerView(kind, focusSearch = false) {
    requestAnimationFrame(() => {
      const input = editor.querySelector(`[data-model-search="${kind}"]`);
      const list = input?.closest(".model-panel")?.querySelector(".model-list");
      if (input) filterModelPicker(input);
      if (list) list.scrollTop = state.pickerScroll;
      if (focusSearch) input?.focus({ preventScroll: true });
    });
  }

  function updateModels(kind, updater) {
    if (state.busy || !validModelKind(kind)) return;
    const key = selectedKey();
    if (!key) return;
    const currentList = editor.querySelector(`[data-model-search="${kind}"]`)?.closest(".model-panel")?.querySelector(".model-list");
    state.pickerScroll = currentList?.scrollTop || 0;
    const nextModels = normalizeModels(updater([...key[kind]]));
    if (nextModels.length === key[kind].length && nextModels.every((model, index) => model === key[kind][index])) return;
    key[kind] = nextModels;
    markDirty();
    renderEditor();
    if (state.openPicker === kind) restorePickerView(kind, true);
  }

  function filterModelPicker(input) {
    const query = input.value.trim().toLowerCase();
    state.pickerQuery = input.value;
    const panel = input.closest(".model-panel");
    if (!panel) return;
    let visible = 0;
    panel.querySelectorAll(".model-option").forEach((option) => {
      const matches = !query || option.dataset.search.includes(query);
      option.hidden = !matches;
      if (matches) visible += 1;
    });
    const empty = panel.querySelector(".model-empty");
    if (empty) empty.hidden = visible > 0;
  }

  function setModelBusy(busy) {
    state.modelBusy = busy;
    refreshDataButton.disabled = busy || state.busy;
    saveButton.disabled = busy || state.busy || !state.dirty;
    reloadButton.disabled = busy || state.busy || !state.status?.persistent_updates;
    if (!busy) finalizeEndedSession();
  }

  async function refreshModelCatalog() {
    if (state.busy || state.modelBusy) return;
    setModelBusy(true);
    const retryButton = editor.querySelector('[data-action="refresh-models"]');
    if (retryButton) { retryButton.disabled = true; retryButton.innerHTML = `${icons.spinner}<span>Loading</span>`; }
    try {
      const result = await fetchCurrentKeys({ includeCatalog: true });
      state.models = result.catalog?.models || [];
      state.modelsError = result.catalog?.error || "";
      renderEditor();
      showToast(state.models.length ? `Loaded ${state.models.length} models` : state.modelsError, state.models.length ? "success" : "error");
    } finally {
      setModelBusy(false);
      syncHeader();
    }
  }

  function serializablePolicy() {
    const active = state.keys.filter(hasRules).map((key) => ({
      caller_scope: key.scope,
      allow_models: [...key.allow_models],
      deny_models: [...key.deny_models]
    }));
    const stale = state.stalePolicies.map((policy) => ({
      caller_scope: policy.caller_scope,
      allow_models: [...policy.allow_models],
      deny_models: [...policy.deny_models]
    }));
    return { version: 2, policies: [...active, ...stale] };
  }

  function scopeSet(keys) {
    return new Set(keys.map((key) => key.scope));
  }

  function setsEqual(left, right) {
    if (left.size !== right.size) return false;
    for (const value of left) if (!right.has(value)) return false;
    return true;
  }

  async function save() {
    if (!state.dirty || state.busy) return;
    const expectedRevision = state.revision;
    const submittedPolicy = serializablePolicy();
    setBusy(true, "save");
    try {
      const latestKeys = await fetchCurrentKeys();
      if (!setsEqual(scopeSet(state.keys), scopeSet(latestKeys))) {
        const changed = new Error("The CPA API key list changed, so saving was aborted to avoid attaching rules to the wrong key. Refresh and check the rules again.");
        changed.code = "key_set_changed";
        throw changed;
      }

      const response = await api(PATHS.policies, {
        method: "PUT",
        headers: { "If-Match": `"rev-${expectedRevision}"` },
        body: JSON.stringify(submittedPolicy)
      });
      let keySetChangedAfterSave = false;
      let postSaveCheckError = null;
      try {
        const keysAfterSave = await fetchCurrentKeys();
        keySetChangedAfterSave = !setsEqual(scopeSet(state.keys), scopeSet(keysAfterSave));
        if (keySetChangedAfterSave) state.keys = keysAfterSave;
      } catch (verificationError) {
        postSaveCheckError = verificationError;
      }
      applyPolicyDocument(response?.policy || submittedPolicy);
      state.revision = Number(response?.revision ?? expectedRevision + 1);
      state.dirty = false;
      renderAll();
      if (keySetChangedAfterSave) {
        showToast("Policies saved, but the CPA key list changed while saving; any new key is allowed every model until you add rules. Check now.", "error");
      } else if (postSaveCheckError) {
        showToast(`Policies saved, but the CPA key list could not be re-checked: ${postSaveCheckError.message}`, "error");
      } else {
        showToast(response?.persistent ? "Policies saved and persisted" : "Policies saved in memory only", "success");
      }
      try {
        state.status = await api(PATHS.status, { method: "GET" });
        syncHeader();
        syncPersistence();
      } catch (refreshError) {
        showToast(`Policies saved, but refreshing the status failed: ${refreshError.message}`, "error");
      }
    } catch (error) {
      if (error.code === "timeout") {
        const confirmed = await confirmTimedOutSave(submittedPolicy, expectedRevision);
        showToast(confirmed ? "Saving timed out, but a re-read confirmed it was applied" : "Could not confirm the save; your local changes are kept. Refresh and check.", confirmed ? "success" : "error");
      } else if (error.code === "key_set_changed") {
        showToast(error.message, "error", "Refresh", refreshData);
      } else if (error.status === 412) {
        showToast("Policies were changed by another admin or a config reload. Refresh before saving.", "error", "Refresh", refreshData);
      } else {
        showToast(error.message, "error");
      }
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function confirmTimedOutSave(submittedPolicy, expectedRevision) {
    try {
      const policies = await api(PATHS.policies, { method: "GET" });
      const remoteRevision = Number(policies?.revision ?? 0);
      if (remoteRevision <= expectedRevision || !policiesEquivalent(submittedPolicy, policies?.policy)) return false;
      applyPolicyDocument(policies.policy);
      state.revision = remoteRevision;
      state.dirty = false;
      try { state.status = await api(PATHS.status, { method: "GET" }); } catch (_) { /* policy confirmation is sufficient */ }
      renderAll();
      return true;
    } catch (_) {
      return false;
    }
  }

  function policiesEquivalent(leftRaw, rightRaw) {
    const canonical = (raw) => normalizePolicyDocument(raw).policies.map((policy) => ({
      caller_scope: policy.caller_scope,
      allow_models: [...policy.allow_models].sort(),
      deny_models: [...policy.deny_models].sort()
    })).sort((left, right) => left.caller_scope.localeCompare(right.caller_scope));
    return JSON.stringify(canonical(leftRaw)) === JSON.stringify(canonical(rightRaw));
  }

  async function refreshData() {
    if (state.busy) return;
    if (state.dirty && !window.confirm("Refreshing discards unsaved model rules. Continue?")) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "refresh");
    try {
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast("CPA keys and policies refreshed", "success");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function reload() {
    if (state.busy || !state.status?.persistent_updates) return;
    if (state.dirty && !window.confirm("Reloading from the policy file discards unsaved model rules. Continue?")) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "reload");
    let reloaded = false;
    try {
      await api(PATHS.reload, { method: "POST" });
      reloaded = true;
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast("Reloaded from policy file", "success");
    } catch (error) {
      showToast(reloaded ? `Policies reloaded, but refreshing the page failed: ${error.message}` : error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  function showToast(message, type = "success", actionLabel = "", action = null) {
    const toast = document.createElement("div");
    toast.className = `toast ${type} enter`;
    toast.innerHTML = `${type === "error" ? icons.warning : icons.check}<span>${escapeHTML(message)}</span>${actionLabel ? `<button type="button">${escapeHTML(actionLabel)}</button>` : ""}`;
    $("#toastRegion").appendChild(toast);
    const button = toast.querySelector("button");
    let timer = window.setTimeout(remove, actionLabel ? 7000 : 3600);
    if (button) button.addEventListener("click", () => { window.clearTimeout(timer); action?.(); remove(); });
    requestAnimationFrame(() => toast.classList.remove("enter"));
    function remove() {
      if (!toast.isConnected) return;
      toast.classList.add("exit");
      window.setTimeout(() => toast.remove(), 190);
    }
  }

  function resolveCPAMCTheme() {
    try {
      if (window.self !== window.top) {
        const parentTheme = window.parent.document.documentElement.getAttribute("data-theme");
        return parentTheme === "dark" || parentTheme === "white" ? parentTheme : "light";
      }
    } catch (_) { /* same-origin storage remains the fallback */ }
    try {
      const persisted = JSON.parse(localStorage.getItem(CPAMC_THEME_KEY) || "null");
      const theme = persisted?.state?.theme;
      if (theme === "dark" || theme === "white" || theme === "light") return theme;
      if (theme === "auto") return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white";
    } catch (_) { /* use system preference */ }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white";
  }

  function syncTheme() {
    const theme = resolveCPAMCTheme();
    if (theme === "light") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = theme;
  }

  function initializeChrome() {
    document.documentElement.classList.toggle("is-embedded", window.self !== window.top);
    $("#searchIcon").innerHTML = icons.search;
    refreshDataButton.innerHTML = icons.refresh;
    reloadButton.innerHTML = `${icons.file}<span class="label-long">Reload from file</span>`;
    saveButton.innerHTML = `${icons.save}<span class="label-long">Saved</span>`;
    syncTheme();
    try {
      if (window.self !== window.top) {
        new MutationObserver(syncTheme).observe(window.parent.document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
      }
    } catch (_) { /* cross-origin embedding is unsupported for session reuse */ }
  }

  $("#retrySessionButton").addEventListener("click", connectFromCPAMC);
  window.addEventListener("storage", (event) => {
    if (event.key === CPAMC_THEME_KEY) syncTheme();
    if (event.key !== CPAMC_AUTH_KEY && event.key !== "isLoggedIn") return;
    if (app.hidden) {
      connectFromCPAMC();
      return;
    }
    if (!readCPAMCManagementKey()) {
      state.sessionEnded = true;
      finalizeEndedSession();
    }
  });

  refreshDataButton.addEventListener("click", refreshData);
  saveButton.addEventListener("click", save);
  reloadButton.addEventListener("click", reload);
  $("#searchInput").addEventListener("input", (event) => { state.search = event.target.value; scheduleNavRender(); });

  nav.addEventListener("click", (event) => {
    if (state.busy) return;
    const item = event.target.closest("[data-select]");
    if (!item) return;
    state.selectedIndex = item.dataset.select === "overview" ? -1 : Number(item.dataset.index);
    state.openPicker = "";
    state.pickerQuery = "";
    state.pickerScroll = 0;
    renderNav();
    renderEditor();
  });

  editor.addEventListener("click", (event) => {
    if (state.busy) return;
    const target = event.target.closest("button");
    if (!target) return;
    const action = target.dataset.action;
    const kind = target.dataset.kind;
    if (action === "toggle-picker" && validModelKind(kind)) {
      const opening = state.openPicker !== kind;
      state.openPicker = opening ? kind : "";
      if (opening) { state.pickerQuery = ""; state.pickerScroll = 0; }
      renderEditor();
      if (opening) restorePickerView(kind, true);
    } else if (action === "toggle-model") {
      if (target.dataset.locked === "true") return;
      updateModels(kind, (models) => models.includes(target.dataset.model) ? models.filter((model) => model !== target.dataset.model) : [...models, target.dataset.model]);
    } else if (action === "remove-model") {
      updateModels(kind, (models) => models.filter((model) => model !== target.dataset.model));
    } else if (action === "select-all-models") {
      updateModels(kind, (models) => [...new Set([...models, ...state.models.map((model) => model.id)])]);
    } else if (action === "clear-models") {
      updateModels(kind, () => []);
    } else if (action === "refresh-models") {
      refreshModelCatalog().catch((error) => showToast(error.message, "error"));
    }
  });

  editor.addEventListener("input", (event) => {
    if (event.target.matches("[data-model-search]")) filterModelPicker(event.target);
  });

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s" && !app.hidden) {
      event.preventDefault();
      save();
    }
  });

  window.addEventListener("beforeunload", (event) => {
    if (!state.dirty) return;
    event.preventDefault();
    event.returnValue = "";
  });

  initializeChrome();
  connectFromCPAMC();
})();

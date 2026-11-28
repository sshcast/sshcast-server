// Sshcast Browser Workstation (WASM + WebSocket Client)

(() => {
  "use strict";

  const STORAGE_BUNDLE_KEY = "sshcast_wasm_bundle_v1";
  const STORAGE_WS_URL_KEY = "sshcast_wasm_ws_url_v1";
  const DEFAULT_SWARM_DOMAIN = "sshcast.net";

  let wasmEngine = null;
  let ws = null;
  let wsConnected = false;
  let wsAuthenticated = false;
  let manualDisconnect = false;
  let reconnectTimer = null;
  let reconnectAttempt = 0;
  let heartbeatTimer = null;
  let policyCleanupTimer = null;
  let lastInputEpochMs = Date.now();

  let currentBundleInfo = null;
  let discoveredDefaultDomain = "";
  let discoveredOperatorUrl = "";
  let discoveredServers = [];
  let certRenewInFlight = false;

  let heldKeys = [];
  let pendingQueue = [];
  let activePromptReq = null;
  let approvalPolicies = [];
  let zellijHosts = [];
  const originalTitle = document.title;

  let enrollSeq = 0;
  let activeEnroll = null; // { token, operatorUrl, state, pollToken, authUrl, popup, pollTimer, pairingInfo, inFlight }

  let pairingListenerKey = "";
  let pairingPollAbort = null;
  let activeApproverPairing = null;
  const handledPairings = new Map(); // pairing_id -> handledAtMs

  let lastMintedBundle = "";
  let lastMintedCommand = "";

  const $ = (id) => document.getElementById(id);

  function logEvent(level, msg) {
    const container = $("event-log");
    if (!container) return;
    const now = new Date().toLocaleTimeString();
    const row = document.createElement("div");
    row.className = `log-row log-${level}`;
    row.textContent = `[${now}] ${msg}`;
    container.prepend(row);
    while (container.children.length > 200) {
      container.removeChild(container.lastChild);
    }
  }

  function b64ToUint8Array(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }

  function uint8ArrayToB64(bytes) {
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  function randomBytesB64(len) {
    const buf = new Uint8Array(len);
    crypto.getRandomValues(buf);
    return uint8ArrayToB64(buf);
  }

  function sleepMs(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function normalizeHttpUrl(raw) {
    const trimmed = String(raw || "").trim().replace(/\/+$/, "");
    if (!trimmed) return "";
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    return `https://${trimmed}`;
  }

  function deriveWsFromCoordinatorUrl(raw) {
    const trimmed = String(raw || "").trim().replace(/\/+$/, "");
    if (!trimmed) return "";
    if (/^wss?:\/\//i.test(trimmed)) {
      return trimmed.endsWith("/ws/workstation") ? trimmed : `${trimmed}/ws/workstation`;
    }
    if (/^https:\/\//i.test(trimmed)) {
      return `${trimmed.replace(/^https:\/\//i, "wss://")}/ws/workstation`;
    }
    if (/^http:\/\//i.test(trimmed)) {
      return `${trimmed.replace(/^http:\/\//i, "ws://")}/ws/workstation`;
    }
    return `wss://${trimmed}/ws/workstation`;
  }

  function flashCopyButton(btn, label) {
    if (!btn) return;
    const prev = btn.textContent;
    btn.textContent = label || "Copied!";
    setTimeout(() => {
      btn.textContent = prev;
    }, 1400);
  }

  async function copyToClipboard(text, btn) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      flashCopyButton(btn, "Copied!");
    } catch (err) {
      logEvent("warn", `Clipboard copy failed: ${err.message || err}`);
    }
  }

  async function loadRustClientWasm() {
    const resp = await fetch("./sshcast_wasm.wasm", { cache: "no-cache" });
    if (!resp.ok) {
      throw new Error(`Failed to fetch sshcast_wasm.wasm: HTTP ${resp.status}`);
    }
    const buf = await resp.arrayBuffer();
    const magic = new Uint8Array(buf, 0, 4);
    if (
      magic.length < 4 ||
      magic[0] !== 0x00 ||
      magic[1] !== 0x61 ||
      magic[2] !== 0x73 ||
      magic[3] !== 0x6d
    ) {
      throw new Error("Invalid WebAssembly magic header in sshcast_wasm.wasm");
    }
    const { instance } = await WebAssembly.instantiate(buf, {});
    const ex = instance.exports;
    if (
      typeof ex.sshcast_wasm_alloc !== "function" ||
      typeof ex.sshcast_wasm_call !== "function"
    ) {
      throw new Error("sshcast_wasm.wasm is missing sshcast-client FFI exports");
    }
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    return {
      type: "rust-wasm (sshcast-client)",
      call(reqObj) {
        const reqBytes = encoder.encode(JSON.stringify(reqObj));
        const ptr = ex.sshcast_wasm_alloc(reqBytes.length);
        new Uint8Array(ex.memory.buffer, ptr, reqBytes.length).set(reqBytes);
        const resLen = ex.sshcast_wasm_call(ptr, reqBytes.length);
        ex.sshcast_wasm_free(ptr, reqBytes.length);
        const resPtr = ex.sshcast_wasm_result_ptr();
        const resBytes = new Uint8Array(ex.memory.buffer, resPtr, resLen);
        return JSON.parse(decoder.decode(resBytes));
      },
    };
  }

  async function deriveScryptKeyAsync(passphrase, saltB64, logN, r, p) {
    if (typeof Worker === "undefined") {
      return wasmEngine.call({
        op: "derive_scrypt_key",
        passphrase,
        salt_b64: saltB64,
        log_n: logN,
        r,
        p,
      });
    }
    const worker = new Worker("./scrypt_worker.js");
    try {
      return await new Promise((resolve, reject) => {
        worker.onmessage = (ev) => {
          resolve(ev.data || { ok: false, error: "Empty scrypt worker response" });
        };
        worker.onerror = (ev) => {
          reject(new Error(ev.message || "scrypt Web Worker failed"));
        };
        worker.postMessage({
          wasmUrl: new URL("./sshcast_wasm.wasm", window.location.href).href,
          passphrase,
          salt_b64: saltB64,
          log_n: logN,
          r,
          p,
        });
      });
    } finally {
      worker.terminate();
    }
  }

  async function initWasm() {
    const badge = $("wasm-engine-badge");
    try {
      badge.textContent = "Loading WASM Engine...";
      const eng = await loadRustClientWasm();
      wasmEngine = eng;
      badge.textContent = `Engine: ${eng.type}`;
      badge.className = "badge badge-ok";
      logEvent("info", `Initialized WebAssembly engine: ${eng.type}`);
      restoreSavedState();
      await bootstrapDiscovery();
    } catch (err) {
      badge.textContent = "WASM Load Failed";
      badge.className = "badge badge-err";
      logEvent("error", `Failed to load WASM engine: ${err.message || err}`);
    }
  }

  function defaultWsUrlFromLocation() {
    if (window.location.protocol === "https:") {
      return `wss://${window.location.host}/ws/workstation`;
    }
    if (window.location.protocol === "http:") {
      return `ws://${window.location.host}/ws/workstation`;
    }
    return "";
  }

  async function fetchCoordinators(domain) {
    const url = domain
      ? `./coordinators?domain=${encodeURIComponent(domain)}`
      : "./coordinators";
    const resp = await fetch(url, { cache: "no-cache" });
    if (!resp.ok) {
      throw new Error(`Discovery failed (HTTP ${resp.status})`);
    }
    return resp.json();
  }

  async function bootstrapDiscovery() {
    try {
      let data = await fetchCoordinators("");
      if (data && data.default_domain) {
        discoveredDefaultDomain = data.default_domain;
      }
      if (
        (!data || (!data.operator_url && (!Array.isArray(data.servers) || data.servers.length === 0))) &&
        !$("enroll-domain-input").value.trim()
      ) {
        data = await fetchCoordinators(DEFAULT_SWARM_DOMAIN);
      }
      if (data) {
        if (data.operator_url && !discoveredOperatorUrl) {
          discoveredOperatorUrl = normalizeHttpUrl(data.operator_url);
        }
        if (Array.isArray(data.servers) && data.servers.length > 0 && discoveredServers.length === 0) {
          discoveredServers = data.servers;
        }
      }
      if (!$("enroll-domain-input").value.trim()) {
        $("enroll-domain-input").value =
          discoveredDefaultDomain || (data && data.domain) || DEFAULT_SWARM_DOMAIN;
      }
      if (discoveredOperatorUrl) {
        $("enroll-operator-input").placeholder = discoveredOperatorUrl;
      }
      if (!$("ws-url-input").value.trim()) {
        const locWs = defaultWsUrlFromLocation();
        const discWs =
          discoveredServers.length > 0 ? deriveWsFromCoordinatorUrl(discoveredServers[0]) : "";
        if (locWs || discWs) {
          $("ws-url-input").value = locWs || discWs;
        }
      }
      updateIdentityUI();
    } catch (_) {
      if (!$("enroll-domain-input").value.trim()) {
        $("enroll-domain-input").value = DEFAULT_SWARM_DOMAIN;
      }
    }
  }

  function currentOperatorUrl() {
    const explicit = normalizeHttpUrl($("enroll-operator-input").value);
    return explicit || discoveredOperatorUrl || "";
  }

  async function resolveOperatorAndServersForEnroll() {
    const explicitOp = normalizeHttpUrl($("enroll-operator-input").value);
    const domain = $("enroll-domain-input").value.trim() || discoveredDefaultDomain || DEFAULT_SWARM_DOMAIN;
    let opUrl = explicitOp || discoveredOperatorUrl;
    let servers = domain ? [domain] : discoveredServers.slice();

    if (!opUrl && domain) {
      const data = await fetchCoordinators(domain);
      if (data && data.operator_url) {
        opUrl = normalizeHttpUrl(data.operator_url);
        discoveredOperatorUrl = opUrl;
      }
      if (data && Array.isArray(data.servers) && data.servers.length > 0) {
        discoveredServers = data.servers;
      }
    }
    if (!opUrl) {
      throw new Error(
        `Could not discover Operator URL via _sshcast.${domain} DNS TXT; enter an Operator URL override.`
      );
    }
    if (servers.length === 0) {
      servers = [DEFAULT_SWARM_DOMAIN];
    }
    return { operatorUrl: opUrl, servers };
  }

  function restoreSavedState() {
    const defaultWs = defaultWsUrlFromLocation();
    if (defaultWs && !$("ws-url-input").value) {
      $("ws-url-input").value = defaultWs;
    }
    try {
      const savedBundle = sessionStorage.getItem(STORAGE_BUNDLE_KEY) || localStorage.getItem(STORAGE_BUNDLE_KEY);
      const savedWs = sessionStorage.getItem(STORAGE_WS_URL_KEY) || localStorage.getItem(STORAGE_WS_URL_KEY);
      if (savedBundle) {
        $("bundle-input").value = savedBundle;
        $("remember-session-chk").checked = true;
        applyBundle(savedBundle, false);
      }
      if (savedWs) {
        $("ws-url-input").value = savedWs;
      }
    } catch (_) {}
    updateIdentityUI();
  }

  function certNeedsRenewal(info) {
    if (!info || !info.has_user_cert) return false;
    if (info.user_cert_expired) return true;
    const exp = Number(info.cert_expires_at_unix_sec || 0);
    if (!exp) return false;
    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec >= exp) return true;
    const iss = Number(info.cert_issued_at_unix_sec || 0);
    const total = Math.max(0, exp - iss);
    const half = Math.floor(total / 2);
    const threshold = total >= 7200 ? Math.max(half, 3600) : half;
    return (exp - nowSec) <= threshold;
  }

  async function maybeRenewUserCert(force) {
    const opUrl = currentOperatorUrl();
    if (!wasmEngine || !currentBundleInfo || !opUrl || certRenewInFlight) {
      return false;
    }
    if (!force && !certNeedsRenewal(currentBundleInfo)) {
      return false;
    }
    certRenewInFlight = true;
    try {
      const authRes = wasmEngine.call({
        op: "build_renew_node_auth",
        now_unix_ms: Date.now(),
        nonce_b64: randomBytesB64(16),
      });
      if (!authRes.ok || !authRes.node_auth_proto_b64) {
        logEvent("warn", `Could not build cert renewal auth: ${authRes.error || "unknown"}`);
        return false;
      }
      const url = `${opUrl}/api/v1/renew`;
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ node_auth_proto_b64: authRes.node_auth_proto_b64 }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok || !data.ok || !data.cert_token) {
        logEvent("warn", `Operator cert renewal rejected (${resp.status}): ${data.error || "unknown"}`);
        return false;
      }
      const nowSec = Math.floor(Date.now() / 1000);
      const upd = wasmEngine.call({
        op: "update_user_cert",
        cert_token: data.cert_token,
        now_unix_sec: nowSec,
      });
      if (!upd.ok) {
        logEvent("error", `Renewed cert rejected by WASM verifier: ${upd.error}`);
        return false;
      }
      currentBundleInfo.has_user_cert = true;
      currentBundleInfo.user_cert_expired = false;
      currentBundleInfo.cert_issued_at_unix_sec = upd.cert_issued_at_unix_sec;
      currentBundleInfo.cert_expires_at_unix_sec = upd.cert_expires_at_unix_sec;
      if (upd.updated_bundle_str) {
        currentBundleInfo.bundle_str = upd.updated_bundle_str;
        $("bundle-input").value = upd.updated_bundle_str;
        if ($("remember-session-chk").checked) {
          try {
            sessionStorage.setItem(STORAGE_BUNDLE_KEY, upd.updated_bundle_str);
          } catch (_) {}
        }
      }
      updateBundleStatusText();
      logEvent("ok", `Renewed short-lived UserCert from ${opUrl}`);
      return true;
    } catch (err) {
      logEvent("warn", `Cert renewal request failed: ${err.message || err}`);
      return false;
    } finally {
      certRenewInFlight = false;
    }
  }

  function updateBundleStatusText() {
    if (!currentBundleInfo) {
      $("bundle-status").textContent = "";
      $("bundle-status").className = "status-text";
      return;
    }
    const res = currentBundleInfo;
    const certNote = res.has_user_cert
      ? res.user_cert_expired
        ? " [Operator-Cert Expired — renewing...]"
        : " [Operator-Certified]"
      : "";
    $("bundle-status").textContent = `Verified CLIENT grant: node="${res.node_id}" user="${res.user_id}"${certNote}`;
    $("bundle-status").className = res.user_cert_expired ? "status-text text-warn" : "status-text text-ok";
  }

  function applyLoadedBundleResult(res, connectAfter) {
    currentBundleInfo = res;
    if (res.operator_url) {
      const normOp = normalizeHttpUrl(res.operator_url);
      if (normOp) {
        discoveredOperatorUrl = normOp;
        if (!$("enroll-operator-input").value.trim()) {
          $("enroll-operator-input").placeholder = normOp;
        }
      }
    }
    const cleanBundle = res.bundle_str || $("bundle-input").value.trim();
    $("bundle-input").value = cleanBundle;
    updateBundleStatusText();

    const currentWsInput = $("ws-url-input").value.trim();
    const locWs = defaultWsUrlFromLocation();
    if (!currentWsInput) {
      $("ws-url-input").value = locWs || res.ws_url || "";
    }

    if (Array.isArray(res.dns_domains) && res.dns_domains.length > 0) {
      const dom = res.dns_domains[0];
      fetchCoordinators(dom)
        .then(async (data) => {
          if (data && data.operator_url) {
            discoveredOperatorUrl = normalizeHttpUrl(data.operator_url);
            $("enroll-operator-input").placeholder = discoveredOperatorUrl;
          }
          if (data && Array.isArray(data.servers) && data.servers.length > 0) {
            discoveredServers = data.servers;
            if (!res.ws_url) {
              const wsUrl = deriveWsFromCoordinatorUrl(data.servers[0]);
              logEvent(
                "info",
                `Resolved _sshcast.${dom} TXT coordinators: ${data.servers.join(", ")}`
              );
              if (!$("ws-url-input").value.trim()) {
                $("ws-url-input").value = wsUrl;
              }
            }
          }
          updateIdentityUI();
          if (currentOperatorUrl() && certNeedsRenewal(currentBundleInfo)) {
            await maybeRenewUserCert(false);
          }
        })
        .catch(() => {});
    } else if (currentOperatorUrl() && certNeedsRenewal(currentBundleInfo)) {
      maybeRenewUserCert(false);
    }

    // Never persist user root keys (.rk_ or scu1_) to Web Storage — only stripped node sc1_ bundles.
    if ($("remember-session-chk").checked && cleanBundle && !cleanBundle.includes(".rk_")) {
      try {
        sessionStorage.setItem(STORAGE_BUNDLE_KEY, cleanBundle);
        sessionStorage.setItem(STORAGE_WS_URL_KEY, $("ws-url-input").value.trim());
      } catch (_) {}
    }

    logEvent(
      "info",
      `Loaded enrollment bundle for node="${res.node_id}" (${res.user_id})`
    );
    updateIdentityUI();
    if (connectAfter) {
      connectWebSocket();
    }
  }

  function applyBundle(bundleStr, connectAfter) {
    if (!wasmEngine) {
      logEvent("error", "WASM engine is not ready yet.");
      return false;
    }
    const trimmed = (bundleStr || "").trim();
    if (!trimmed) {
      logEvent("warn", "Please sign in with GitHub or paste a valid sc1_... client enrollment bundle.");
      return false;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const res = wasmEngine.call({
      op: "set_bundle",
      bundle_str: trimmed,
      now_unix_sec: nowSec,
    });
    if (!res.ok) {
      $("bundle-status").textContent = res.error || "Invalid bundle";
      $("bundle-status").className = "status-text text-err";
      logEvent("error", res.error || "Invalid enrollment bundle");
      return false;
    }
    applyLoadedBundleResult(res, connectAfter);
    return true;
  }

  function updateIdentityUI() {
    if (!wasmEngine) return;
    const status = wasmEngine.call({ op: "get_identity_status" });
    if (!status.ok) return;

    const hasBundle = Boolean(status.has_bundle);
    const hasRk = Boolean(status.has_user_root_key);
    const opUrl = currentOperatorUrl();

    const badge = $("root-key-badge");
    const summaryBox = $("identity-summary-box");
    const signOutBtn = $("btn-sign-out");

    if (hasBundle || hasRk) {
      summaryBox.classList.remove("hidden");
      signOutBtn.classList.remove("hidden");
      $("id-user-id").textContent = status.user_id || "-";
      $("id-user-pubkey").textContent = status.user_pubkey_token || "-";
      $("id-node-id").textContent = status.node_id || "(not enrolled)";
      $("id-root-key-state").textContent = hasRk
        ? "Loaded in WASM Memory (Ephemeral — clears on reload)"
        : "Not Loaded (Node-Only Mode)";
      if (hasRk) {
        badge.textContent = "Root Key in Memory";
        badge.className = "badge badge-ok";
      } else {
        badge.textContent = "Node-Only Mode";
        badge.className = "badge badge-warn";
      }
    } else {
      summaryBox.classList.add("hidden");
      signOutBtn.classList.add("hidden");
      badge.textContent = "Not Signed In";
      badge.className = "badge badge-neutral";
    }

    $("btn-export-root-key").disabled = !hasRk;
    $("btn-mint-bundle").disabled = !hasRk;
    $("root-key-required-hint").classList.toggle("hidden", hasRk);

    const canManageVault = Boolean(hasRk && hasBundle && opUrl);
    $("btn-set-vault").disabled = !canManageVault;
    $("btn-remove-vault").disabled = !canManageVault;
    if (!hasRk || !hasBundle) {
      $("vault-badge").textContent = "Unavailable";
      $("vault-badge").className = "badge badge-neutral";
      $("vault-status-text").textContent = hasRk
        ? "Enroll or load a client bundle to manage the Operator recovery vault."
        : "Requires a User Root key in WASM memory.";
    } else if (!opUrl) {
      $("vault-badge").textContent = "No Operator URL";
      $("vault-badge").className = "badge badge-warn";
      $("vault-status-text").textContent = "Configure an Operator URL to query or update the recovery vault.";
    }

    updateMintIncludeRootKeyState();
    syncPairingApproverListener(status, opUrl);
    if (canManageVault) {
      refreshRecoveryVaultStatus();
    }
  }

  function updateMintIncludeRootKeyState() {
    const role = $("mint-role-select").value;
    const chk = $("mint-include-rk-chk");
    const isClient = role === "CLIENT";
    chk.disabled = !isClient;
    if (!isClient) {
      chk.checked = false;
    }
  }

  async function postOperatorJson(opUrl, path, payload, bearerToken, signal) {
    const url = `${opUrl.replace(/\/+$/, "")}${path}`;
    const headers = { "Content-Type": "application/json" };
    if (bearerToken) {
      headers.Authorization = `Bearer ${bearerToken}`;
    }
    const resp = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal,
    });
    const data = await resp.json().catch(() => ({}));
    return { status: resp.status, ok: resp.ok, data };
  }

  // =========================================================================
  // GitHub OAuth Signup / Pairing / Recovery Unlock / Lost-Key Reset
  // =========================================================================

  function closeEnrollPopup() {
    if (activeEnroll && activeEnroll.popup) {
      try {
        if (!activeEnroll.popup.closed) {
          activeEnroll.popup.close();
        }
      } catch (_) {}
      activeEnroll.popup = null;
    }
  }

  function clearActiveEnrollState() {
    if (!activeEnroll) return;
    if (activeEnroll.pollTimer) {
      clearTimeout(activeEnroll.pollTimer);
      activeEnroll.pollTimer = null;
    }
    closeEnrollPopup();
    activeEnroll = null;
  }

  function setEnrollProgressUI(visible, text, authUrl, levelClass) {
    const box = $("enroll-progress-box");
    const txt = $("enroll-progress-text");
    const link = $("enroll-auth-link");
    box.classList.toggle("hidden", !visible);
    txt.textContent = text || "";
    txt.className = levelClass ? `status-text ${levelClass}` : "status-text";
    if (authUrl) {
      link.href = authUrl;
      link.classList.remove("hidden");
    } else {
      link.href = "#";
      link.classList.add("hidden");
    }
  }

  function hidePairingRequiredUI() {
    $("pairing-required-box").classList.add("hidden");
    $("unlock-vault-section").classList.add("hidden");
    $("unlock-passphrase-input").value = "";
    $("unlock-vault-status").textContent = "";
  }

  function showPairingRequiredUI(info, sasCode) {
    const box = $("pairing-required-box");
    const isNewPairingId =
      !activeEnroll ||
      !activeEnroll.pairingInfo ||
      activeEnroll.pairingInfo.pairing_id !== info.pairing_id;

    if (activeEnroll) {
      activeEnroll.pairingInfo = info;
    }

    const acctLabel = info.github_login
      ? `@${info.github_login} (${info.existing_user_pubkey})`
      : info.existing_user_pubkey;
    $("pairing-account-info").textContent = `Account: ${acctLabel}`;
    $("pairing-sas-code").textContent = sasCode || "---";

    const hasVault = Boolean(info.has_recovery_vault && info.recovery_vault);
    $("unlock-vault-section").classList.toggle("hidden", !hasVault);
    if (isNewPairingId) {
      $("unlock-passphrase-input").value = "";
      $("unlock-vault-status").textContent = "";
    }
    box.classList.remove("hidden");
  }

  async function cancelActiveEnrollment(reasonMsg) {
    const cur = activeEnroll;
    if (!cur) return;
    clearActiveEnrollState();
    hidePairingRequiredUI();
    $("btn-github-login").disabled = false;
    if (wasmEngine) {
      wasmEngine.call({ op: "cancel_pending_enrollment" });
    }
    try {
      await postOperatorJson(
        cur.operatorUrl,
        "/api/v1/enroll/cancel",
        { state: cur.state },
        cur.pollToken
      );
    } catch (_) {}
    if (reasonMsg) {
      setEnrollProgressUI(true, reasonMsg, "", "text-warn");
      logEvent("warn", reasonMsg);
    } else {
      setEnrollProgressUI(false, "", "", "");
    }
  }

  async function startGitHubLogin() {
    if (!wasmEngine) {
      logEvent("error", "WASM engine is not ready yet.");
      return;
    }

    // Open the OAuth popup synchronously in the user click gesture before any await
    // so Safari/Firefox popup blockers allow it.
    let popup = null;
    try {
      popup = window.open("", "sshcast_github_oauth", "popup,width=640,height=760");
    } catch (_) {
      popup = null;
    }

    if (activeEnroll) {
      await cancelActiveEnrollment("");
    }

    hidePairingRequiredUI();
    $("btn-github-login").disabled = true;
    setEnrollProgressUI(true, "Discovering operator and initializing enrollment...", "", "");

    try {
      const { operatorUrl, servers } = await resolveOperatorAndServersForEnroll();
      const nodeName = $("enroll-node-input").value.trim() || "browser-workstation";

      const beginRes = wasmEngine.call({
        op: "begin_github_enrollment",
        servers,
        operator_url: operatorUrl,
        node_name: nodeName,
        candidate_user_seed_b64: randomBytesB64(32),
        node_seed_b64: randomBytesB64(32),
        eph_secret_b64: randomBytesB64(32),
      });
      if (!beginRes.ok || !beginRes.start_body) {
        throw new Error(beginRes.error || "Failed to initialize enrollment keys in WASM");
      }

      const startResp = await postOperatorJson(
        operatorUrl,
        "/api/v1/enroll/start",
        beginRes.start_body,
        null
      );
      if (!startResp.ok || !startResp.data.ok || !startResp.data.auth_url) {
        throw new Error(
          startResp.data.error || `Operator /api/v1/enroll/start failed (HTTP ${startResp.status})`
        );
      }

      const { state, poll_token: pollToken, auth_url: authUrl } = startResp.data;
      const myToken = ++enrollSeq;
      activeEnroll = {
        token: myToken,
        operatorUrl,
        state,
        pollToken,
        authUrl,
        popup,
        pollTimer: null,
        pairingInfo: null,
        inFlight: false,
      };

      let popupNavigated = false;
      if (popup && !popup.closed) {
        try {
          popup.location.href = authUrl;
          popupNavigated = true;
        } catch (_) {}
      }

      setEnrollProgressUI(
        true,
        popupNavigated
          ? "Complete GitHub sign-in in the opened window. Waiting for authorization..."
          : "Popup blocked or unavailable. Click 'Open GitHub Sign-In' below to authenticate.",
        authUrl,
        ""
      );
      logEvent("info", `Started GitHub enrollment via ${operatorUrl}`);
      scheduleEnrollPoll(myToken, 1500);
    } catch (err) {
      if (popup && !popup.closed) {
        try {
          popup.close();
        } catch (_) {}
      }
      wasmEngine.call({ op: "cancel_pending_enrollment" });
      $("btn-github-login").disabled = false;
      setEnrollProgressUI(true, err.message || String(err), "", "text-err");
      logEvent("error", `GitHub enrollment failed: ${err.message || err}`);
    }
  }

  function scheduleEnrollPoll(token, delayMs) {
    if (!activeEnroll || activeEnroll.token !== token) return;
    activeEnroll.pollTimer = setTimeout(() => pollEnrollmentTick(token), delayMs);
  }

  async function pollEnrollmentTick(token) {
    const cur = activeEnroll;
    if (!cur || cur.token !== token) return;
    if (cur.inFlight) {
      scheduleEnrollPoll(token, 2000);
      return;
    }
    cur.inFlight = true;

    try {
      const pollUrl = `${cur.operatorUrl}/api/v1/enroll/poll?state=${encodeURIComponent(cur.state)}`;
      const resp = await fetch(pollUrl, {
        method: "GET",
        headers: { Authorization: `Bearer ${cur.pollToken}` },
        cache: "no-cache",
      });
      const data = await resp.json().catch(() => ({}));

      if (!activeEnroll || activeEnroll.token !== token) return;

      const statusStr = String(data.status || "");
      if (["banned", "denied", "canceled", "expired"].includes(statusStr)) {
        const msg = data.error ? `${statusStr}: ${data.error}` : statusStr;
        clearActiveEnrollState();
        hidePairingRequiredUI();
        wasmEngine.call({ op: "cancel_pending_enrollment" });
        $("btn-github-login").disabled = false;
        setEnrollProgressUI(true, `Enrollment rejected (${msg})`, "", "text-err");
        logEvent("error", `GitHub enrollment rejected (${msg})`);
        return;
      }

      if (resp.status >= 400 || data.ok === false) {
        const errMsg = data.error || `HTTP ${resp.status}`;
        if (resp.status >= 500) {
          scheduleEnrollPoll(token, 2500);
          return;
        }
        clearActiveEnrollState();
        hidePairingRequiredUI();
        wasmEngine.call({ op: "cancel_pending_enrollment" });
        $("btn-github-login").disabled = false;
        setEnrollProgressUI(true, `Enrollment failed: ${errMsg}`, "", "text-err");
        logEvent("error", `GitHub enrollment failed: ${errMsg}`);
        return;
      }

      switch (statusStr) {
        case "pending":
        case "": {
          scheduleEnrollPoll(token, 2000);
          break;
        }
        case "awaiting_approval": {
          closeEnrollPopup();
          setEnrollProgressUI(
            true,
            "GitHub sign-in completed; waiting for operator administrator approval in /console/...",
            "",
            "text-warn"
          );
          scheduleEnrollPoll(token, 2000);
          break;
        }
        case "approved": {
          closeEnrollPopup();
          clearActiveEnrollState();
          hidePairingRequiredUI();
          const nowSec = Math.floor(Date.now() / 1000);
          const fin = wasmEngine.call({
            op: "finalize_approved_enrollment",
            cert_token: data.cert_token,
            now_unix_sec: nowSec,
          });
          $("btn-github-login").disabled = false;
          if (!fin.ok) {
            setEnrollProgressUI(true, fin.error || "Enrollment finalization failed", "", "text-err");
            logEvent("error", `Enrollment finalization failed: ${fin.error}`);
            return;
          }
          setEnrollProgressUI(true, `Signed in as ${fin.user_id}!`, "", "text-ok");
          logEvent("ok", `Completed GitHub signup/login for ${fin.user_id}`);
          applyLoadedBundleResult(fin, true);
          break;
        }
        case "pairing_required": {
          closeEnrollPopup();
          const sasRes = wasmEngine.call({
            op: "compute_pairing_sas",
            existing_user_pubkey: data.existing_user_pubkey || "",
          });
          if (!sasRes.ok) {
            throw new Error(sasRes.error || "Failed to compute pairing SAS");
          }
          setEnrollProgressUI(
            true,
            "GitHub sign-in verified. Confirm this browser workstation below.",
            "",
            "text-warn"
          );
          showPairingRequiredUI(data, sasRes.sas_code);
          scheduleEnrollPoll(token, 2000);
          break;
        }
        case "paired": {
          closeEnrollPopup();
          clearActiveEnrollState();
          hidePairingRequiredUI();
          const nowSec = Math.floor(Date.now() / 1000);
          const pairedRes = wasmEngine.call({
            op: "complete_paired_enrollment",
            pairing_id: data.pairing_id,
            existing_user_pubkey: data.existing_user_pubkey,
            approver_eph_x25519_pub_b64: data.approver_eph_x25519_pub_b64,
            approver_signature_b64: data.approver_signature_b64,
            handoff_nonce_b64: data.handoff_nonce_b64,
            encrypted_handoff_b64: data.encrypted_handoff_b64,
            now_unix_sec: nowSec,
          });
          $("btn-github-login").disabled = false;
          if (!pairedRes.ok) {
            setEnrollProgressUI(
              true,
              pairedRes.error || "Failed to decrypt pairing handoff",
              "",
              "text-err"
            );
            logEvent("error", `Pairing handoff failed: ${pairedRes.error}`);
            return;
          }
          setEnrollProgressUI(
            true,
            `Paired with '${data.approver_node_id || "existing workstation"}' as ${pairedRes.user_id}!`,
            "",
            "text-ok"
          );
          logEvent(
            "ok",
            `Device pairing approved by '${data.approver_node_id || "workstation"}' for ${pairedRes.user_id}`
          );
          applyLoadedBundleResult(pairedRes, false);
          if (pairedRes.needs_cert_renewal) {
            await maybeRenewUserCert(true);
            updateIdentityUI();
          }
          connectWebSocket();
          break;
        }
        default: {
          scheduleEnrollPoll(token, 2000);
          break;
        }
      }
    } catch (err) {
      if (activeEnroll && activeEnroll.token === token) {
        logEvent("warn", `Enrollment poll transient error: ${err.message || err}`);
        scheduleEnrollPoll(token, 2500);
      }
    } finally {
      if (activeEnroll && activeEnroll.token === token) {
        activeEnroll.inFlight = false;
      }
    }
  }

  async function unlockWithRecoveryPassphrase() {
    if (!wasmEngine || !activeEnroll || !activeEnroll.pairingInfo) return;
    const info = activeEnroll.pairingInfo;
    const vault = info.recovery_vault;
    if (!vault || !vault.kdf_params) {
      $("unlock-vault-status").textContent = "Operator did not provide a recovery vault.";
      $("unlock-vault-status").className = "status-text text-err";
      return;
    }
    const passphrase = $("unlock-passphrase-input").value;
    if (!passphrase) {
      $("unlock-vault-status").textContent = "Enter your recovery passphrase.";
      $("unlock-vault-status").className = "status-text text-err";
      return;
    }

    const btn = $("btn-unlock-vault");
    btn.disabled = true;
    $("unlock-vault-status").textContent = "Deriving scrypt key in background worker...";
    $("unlock-vault-status").className = "status-text";

    try {
      const kdfRes = await deriveScryptKeyAsync(
        passphrase,
        vault.salt_b64,
        vault.kdf_params.log_n,
        vault.kdf_params.r,
        vault.kdf_params.p
      );
      if (!kdfRes.ok || !kdfRes.derived_key_b64) {
        throw new Error(kdfRes.error || "scrypt key derivation failed");
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const unlockRes = wasmEngine.call({
        op: "unlock_recovery_vault",
        vault,
        existing_user_pubkey: info.existing_user_pubkey,
        derived_key_b64: kdfRes.derived_key_b64,
        now_unix_sec: nowSec,
        now_unix_ms: Date.now(),
        auth_nonce_b64: randomBytesB64(16),
      });

      if (!unlockRes.ok) {
        if (unlockRes.wrong_passphrase) {
          $("unlock-vault-status").textContent =
            "Incorrect recovery passphrase. Try again or approve on an existing workstation.";
          $("unlock-vault-status").className = "status-text text-err";
          $("unlock-passphrase-input").select();
          return;
        }
        throw new Error(unlockRes.error || "Failed to decrypt recovery vault");
      }

      const opUrl = activeEnroll.operatorUrl;
      const state = activeEnroll.state;
      const pollToken = activeEnroll.pollToken;

      clearActiveEnrollState();
      hidePairingRequiredUI();
      $("btn-github-login").disabled = false;

      // Renew short-lived UserCert from operator immediately using the recovered root key's node grant
      if (opUrl && unlockRes.renew_node_auth_proto_b64) {
        try {
          const renewResp = await postOperatorJson(
            opUrl,
            "/api/v1/renew",
            { node_auth_proto_b64: unlockRes.renew_node_auth_proto_b64 },
            null
          );
          if (!renewResp.ok || !renewResp.data.ok || !renewResp.data.cert_token) {
            throw new Error(
              renewResp.data.error || `Operator renewal failed (HTTP ${renewResp.status})`
            );
          }
          const upd = wasmEngine.call({
            op: "update_user_cert",
            cert_token: renewResp.data.cert_token,
            now_unix_sec: Math.floor(Date.now() / 1000),
          });
          if (!upd.ok) {
            throw new Error(upd.error || "Operator returned invalid UserCert");
          }
          unlockRes.has_user_cert = true;
          unlockRes.user_cert_expired = false;
          unlockRes.cert_issued_at_unix_sec = upd.cert_issued_at_unix_sec;
          unlockRes.cert_expires_at_unix_sec = upd.cert_expires_at_unix_sec;
          if (upd.updated_bundle_str) {
            unlockRes.bundle_str = upd.updated_bundle_str;
          }
        } catch (renewErr) {
          logEvent("warn", `Initial UserCert renewal after unlock failed (${renewErr.message || renewErr}); will retry.`);
        }
      }

      // Cancel the pending pairing request on the operator so desktop approvers dismiss it
      postOperatorJson(opUrl, "/api/v1/enroll/cancel", { state }, pollToken).catch(() => {});

      setEnrollProgressUI(
        true,
        `Unlocked root key via recovery passphrase (${unlockRes.user_id})!`,
        "",
        "text-ok"
      );
      logEvent("ok", `Unlocked Sshcast root key via recovery passphrase for ${unlockRes.user_id}`);
      applyLoadedBundleResult(unlockRes, true);
    } catch (err) {
      $("unlock-vault-status").textContent = err.message || String(err);
      $("unlock-vault-status").className = "status-text text-err";
      logEvent("error", `Recovery vault unlock failed: ${err.message || err}`);
    } finally {
      btn.disabled = false;
    }
  }

  async function confirmResetRootKey() {
    if (!wasmEngine || !activeEnroll) return;
    const confirmText = $("reset-confirm-input").value.trim();
    if (confirmText !== "RESET") {
      $("reset-dialog-status").textContent = "Type RESET in all caps to confirm.";
      $("reset-dialog-status").className = "status-text text-err";
      return;
    }

    const btn = $("btn-confirm-reset-root-key");
    btn.disabled = true;
    $("reset-dialog-status").textContent = "Replacing account root key on Operator...";
    $("reset-dialog-status").className = "status-text";

    try {
      const { operatorUrl, state, pollToken } = activeEnroll;
      const replaceResp = await postOperatorJson(
        operatorUrl,
        "/api/v1/enroll/replace",
        { state },
        pollToken
      );
      if (!replaceResp.ok || !replaceResp.data.ok || !replaceResp.data.cert_token) {
        throw new Error(
          replaceResp.data.error || `Root key replacement failed (HTTP ${replaceResp.status})`
        );
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const fin = wasmEngine.call({
        op: "finalize_approved_enrollment",
        cert_token: replaceResp.data.cert_token,
        now_unix_sec: nowSec,
      });
      if (!fin.ok) {
        throw new Error(fin.error || "Failed to finalize replacement enrollment");
      }

      $("dialog-reset-root-key").close();
      $("reset-confirm-input").value = "";
      $("reset-dialog-status").textContent = "";
      clearActiveEnrollState();
      hidePairingRequiredUI();
      $("btn-github-login").disabled = false;

      setEnrollProgressUI(
        true,
        `Replaced lost root key and enrolled '${fin.node_id}'!`,
        "",
        "text-ok"
      );
      logEvent("ok", `Replaced lost Sshcast root key for ${fin.user_id}`);
      applyLoadedBundleResult(fin, true);
    } catch (err) {
      $("reset-dialog-status").textContent = err.message || String(err);
      $("reset-dialog-status").className = "status-text text-err";
      logEvent("error", `Root key reset failed: ${err.message || err}`);
    } finally {
      btn.disabled = false;
    }
  }

  // =========================================================================
  // Background Device Pairing Approver Listener (Desktop Parity)
  // =========================================================================

  function renderApproverPairingBanner(req, sasCode) {
    activeApproverPairing = req;
    $("approver-pairing-id-badge").textContent = req.pairing_id;
    $("approver-req-node").textContent = req.node_name || "(unknown)";
    $("approver-req-os").textContent = req.os_name || "(unknown)";
    $("approver-req-gh").textContent = req.github_login ? `@${req.github_login}` : "(unknown)";
    $("approver-req-sas").textContent = sasCode;
    $("approver-pairing-status").textContent = "";
    $("approver-pairing-status").className = "status-text";
    $("btn-approve-pairing").disabled = false;
    $("btn-deny-pairing").disabled = false;
    $("pairing-approver-card").classList.remove("hidden");

    playAlertBeep();
    if ("Notification" in window && Notification.permission === "granted") {
      try {
        new Notification(`New Sshcast Device Pairing: ${req.node_name}`, {
          body: `Verification Code: ${sasCode}\nOS: ${req.os_name || "unknown"}`,
          tag: `pairing-${req.pairing_id}`,
        });
      } catch (_) {}
    }
  }

  function hideApproverPairingBanner() {
    activeApproverPairing = null;
    $("pairing-approver-card").classList.add("hidden");
  }

  function syncPairingApproverListener(idStatus, opUrl) {
    const canListen = Boolean(
      wasmEngine && idStatus && idStatus.has_user_root_key && idStatus.has_bundle && opUrl
    );
    const desiredKey = canListen
      ? `${idStatus.user_pubkey_token}|${idStatus.node_id}|${opUrl}`
      : "";
    if (desiredKey === pairingListenerKey) {
      return;
    }
    pairingListenerKey = desiredKey;
    if (pairingPollAbort) {
      pairingPollAbort.abort();
      pairingPollAbort = null;
    }
    hideApproverPairingBanner();
    if (desiredKey) {
      runPairingApproverLoop(desiredKey, opUrl);
    }
  }

  async function runPairingApproverLoop(sessionKey, opUrl) {
    let backoffMs = 2000;
    while (pairingListenerKey === sessionKey && wasmEngine) {
      const now = Date.now();
      for (const [pid, ts] of handledPairings.entries()) {
        if (now - ts > 10 * 60 * 1000) handledPairings.delete(pid);
      }

      const authRes = wasmEngine.call({
        op: "build_operator_node_auth",
        now_unix_ms: Date.now(),
        nonce_b64: randomBytesB64(16),
      });
      if (!authRes.ok || !authRes.node_auth_proto_b64) {
        await sleepMs(5000);
        continue;
      }

      pairingPollAbort = new AbortController();
      try {
        const resp = await postOperatorJson(
          opUrl,
          "/api/v1/pairing/poll",
          {
            node_auth_proto_b64: authRes.node_auth_proto_b64,
            timeout_secs: 25,
          },
          null,
          pairingPollAbort.signal
        );
        if (pairingListenerKey !== sessionKey) break;

        if (!resp.ok || !resp.data.ok) {
          throw new Error(resp.data.error || `HTTP ${resp.status}`);
        }
        backoffMs = 2000;
        const requests = Array.isArray(resp.data.requests) ? resp.data.requests : [];

        if (
          activeApproverPairing &&
          !requests.some((r) => r.pairing_id === activeApproverPairing.pairing_id)
        ) {
          hideApproverPairingBanner();
        }

        const nextReq = requests.find((r) => !handledPairings.has(r.pairing_id));
        if (
          nextReq &&
          (!activeApproverPairing || activeApproverPairing.pairing_id !== nextReq.pairing_id)
        ) {
          const sasRes = wasmEngine.call({
            op: "compute_incoming_pairing_sas",
            eph_x25519_pub_b64: nextReq.eph_x25519_pub_b64,
          });
          if (sasRes.ok && sasRes.sas_code) {
            renderApproverPairingBanner(nextReq, sasRes.sas_code);
            logEvent(
              "info",
              `Incoming pairing request from '${nextReq.node_name}' (SAS ${sasRes.sas_code})`
            );
          }
        }
      } catch (err) {
        if (err && err.name === "AbortError") break;
        if (pairingListenerKey !== sessionKey) break;
        await sleepMs(backoffMs);
        backoffMs = Math.min(backoffMs * 2, 30000);
      } finally {
        pairingPollAbort = null;
      }
    }
  }

  async function respondToActivePairing(approved) {
    if (!wasmEngine || !activeApproverPairing) return;
    const req = activeApproverPairing;
    const opUrl = currentOperatorUrl();
    if (!opUrl) return;

    $("btn-approve-pairing").disabled = true;
    $("btn-deny-pairing").disabled = true;
    $("approver-pairing-status").textContent = approved
      ? "Sealing encrypted pairing handoff..."
      : "Sending denial...";
    $("approver-pairing-status").className = "status-text";

    try {
      let payload;
      if (approved) {
        const handoff = wasmEngine.call({
          op: "approve_pairing_request",
          pairing_id: req.pairing_id,
          node_name: req.node_name,
          node_pubkey_b64: req.node_pubkey_b64,
          eph_x25519_pub_b64: req.eph_x25519_pub_b64,
          operator_url: opUrl,
          now_unix_sec: Math.floor(Date.now() / 1000),
          now_unix_ms: Date.now(),
          approver_eph_secret_b64: randomBytesB64(32),
          handoff_nonce_b64: randomBytesB64(12),
          auth_nonce_b64: randomBytesB64(16),
        });
        if (!handoff.ok || !handoff.envelope) {
          throw new Error(handoff.error || "Failed to encrypt pairing handoff");
        }
        payload = {
          node_auth_proto_b64: handoff.node_auth_proto_b64,
          pairing_id: req.pairing_id,
          approved: true,
          approver_eph_x25519_pub_b64: handoff.envelope.approver_eph_x25519_pub_b64,
          approver_signature_b64: handoff.envelope.approver_signature_b64,
          handoff_nonce_b64: handoff.envelope.handoff_nonce_b64,
          encrypted_handoff_b64: handoff.envelope.encrypted_handoff_b64,
        };
      } else {
        const authRes = wasmEngine.call({
          op: "build_operator_node_auth",
          now_unix_ms: Date.now(),
          nonce_b64: randomBytesB64(16),
        });
        if (!authRes.ok) {
          throw new Error(authRes.error || "Failed to build node auth");
        }
        payload = {
          node_auth_proto_b64: authRes.node_auth_proto_b64,
          pairing_id: req.pairing_id,
          approved: false,
        };
      }

      const resp = await postOperatorJson(opUrl, "/api/v1/pairing/respond", payload, null);
      if (!resp.ok || !resp.data.ok) {
        throw new Error(resp.data.error || `Operator error (HTTP ${resp.status})`);
      }

      handledPairings.set(req.pairing_id, Date.now());
      hideApproverPairingBanner();
      logEvent(
        approved ? "ok" : "warn",
        `${approved ? "Approved" : "Denied"} pairing request from '${req.node_name}' (${req.pairing_id}).`
      );
    } catch (err) {
      $("approver-pairing-status").textContent = err.message || String(err);
      $("approver-pairing-status").className = "status-text text-err";
      $("btn-approve-pairing").disabled = false;
      $("btn-deny-pairing").disabled = false;
      logEvent("error", `Pairing response failed: ${err.message || err}`);
    }
  }

  // =========================================================================
  // Recovery Passphrase Vault & Node Enrollment Bundle Minting
  // =========================================================================

  async function refreshRecoveryVaultStatus() {
    if (!wasmEngine) return;
    const opUrl = currentOperatorUrl();
    if (!opUrl || !currentBundleInfo) return;

    const authRes = wasmEngine.call({
      op: "build_operator_node_auth",
      now_unix_ms: Date.now(),
      nonce_b64: randomBytesB64(16),
    });
    if (!authRes.ok) return;

    try {
      const resp = await postOperatorJson(
        opUrl,
        "/api/v1/recovery-vault/status",
        { node_auth_proto_b64: authRes.node_auth_proto_b64 },
        null
      );
      if (!resp.ok || !resp.data.ok) {
        $("vault-badge").textContent = "Error";
        $("vault-badge").className = "badge badge-warn";
        $("vault-status-text").textContent = resp.data.error || `HTTP ${resp.status}`;
        return;
      }
      if (resp.data.configured) {
        const ts = resp.data.updated_at
          ? new Date(resp.data.updated_at * 1000).toLocaleString()
          : "unknown";
        $("vault-badge").textContent = "Configured";
        $("vault-badge").className = "badge badge-ok";
        $("vault-status-text").textContent = `Encrypted recovery vault stored on ${opUrl} (updated: ${ts}).`;
      } else {
        $("vault-badge").textContent = "Not Set";
        $("vault-badge").className = "badge badge-neutral";
        $("vault-status-text").textContent = `No recovery passphrase configured on ${opUrl}.`;
      }
    } catch (err) {
      $("vault-badge").textContent = "Unreachable";
      $("vault-badge").className = "badge badge-warn";
      $("vault-status-text").textContent = err.message || String(err);
    }
  }

  async function setRecoveryVault() {
    if (!wasmEngine) return;
    const opUrl = currentOperatorUrl();
    if (!opUrl) {
      $("vault-action-status").textContent = "No Operator URL configured.";
      $("vault-action-status").className = "status-text text-err";
      return;
    }

    const pass1 = $("vault-pass-1").value;
    const pass2 = $("vault-pass-2").value;
    if (pass1.length < 8) {
      $("vault-action-status").textContent = "Recovery passphrase must be at least 8 characters.";
      $("vault-action-status").className = "status-text text-err";
      return;
    }
    if (pass1 !== pass2) {
      $("vault-action-status").textContent = "Passphrases do not match.";
      $("vault-action-status").className = "status-text text-err";
      return;
    }

    $("btn-set-vault").disabled = true;
    $("btn-remove-vault").disabled = true;
    $("vault-action-status").textContent = "Deriving scrypt vault key in background worker...";
    $("vault-action-status").className = "status-text";

    try {
      const saltB64 = randomBytesB64(16);
      const nonceB64 = randomBytesB64(12);
      const kdfRes = await deriveScryptKeyAsync(pass1, saltB64, 15, 8, 1);
      if (!kdfRes.ok || !kdfRes.derived_key_b64) {
        throw new Error(kdfRes.error || "scrypt key derivation failed");
      }

      const encRes = wasmEngine.call({
        op: "encrypt_recovery_vault",
        derived_key_b64: kdfRes.derived_key_b64,
        salt_b64: saltB64,
        nonce_b64: nonceB64,
        log_n: 15,
        r: 8,
        p: 1,
        now_unix_ms: Date.now(),
        auth_nonce_b64: randomBytesB64(16),
      });
      if (!encRes.ok || !encRes.vault) {
        throw new Error(encRes.error || "Failed to encrypt recovery vault");
      }

      const resp = await postOperatorJson(
        opUrl,
        "/api/v1/recovery-vault",
        {
          node_auth_proto_b64: encRes.node_auth_proto_b64,
          vault: encRes.vault,
        },
        null
      );
      if (!resp.ok || !resp.data.ok) {
        throw new Error(resp.data.error || `Upload failed (HTTP ${resp.status})`);
      }

      $("vault-pass-1").value = "";
      $("vault-pass-2").value = "";
      $("vault-action-status").textContent = "Recovery passphrase vault encrypted and uploaded.";
      $("vault-action-status").className = "status-text text-ok";
      logEvent("ok", `Uploaded encrypted recovery vault to ${opUrl}`);
      await refreshRecoveryVaultStatus();
    } catch (err) {
      $("vault-action-status").textContent = err.message || String(err);
      $("vault-action-status").className = "status-text text-err";
      logEvent("error", `Failed to set recovery vault: ${err.message || err}`);
    } finally {
      updateIdentityUI();
    }
  }

  async function removeRecoveryVault() {
    if (!wasmEngine) return;
    const opUrl = currentOperatorUrl();
    if (!opUrl) return;

    const authRes = wasmEngine.call({
      op: "build_operator_node_auth",
      now_unix_ms: Date.now(),
      nonce_b64: randomBytesB64(16),
    });
    if (!authRes.ok) {
      $("vault-action-status").textContent = authRes.error || "Failed to authenticate";
      $("vault-action-status").className = "status-text text-err";
      return;
    }

    $("btn-remove-vault").disabled = true;
    try {
      const resp = await postOperatorJson(
        opUrl,
        "/api/v1/recovery-vault/delete",
        { node_auth_proto_b64: authRes.node_auth_proto_b64 },
        null
      );
      if (!resp.ok || !resp.data.ok) {
        throw new Error(resp.data.error || `HTTP ${resp.status}`);
      }
      $("vault-action-status").textContent = "Removed recovery vault from Operator.";
      $("vault-action-status").className = "status-text text-warn";
      logEvent("warn", `Removed recovery vault from ${opUrl}`);
      await refreshRecoveryVaultStatus();
    } catch (err) {
      $("vault-action-status").textContent = err.message || String(err);
      $("vault-action-status").className = "status-text text-err";
    } finally {
      updateIdentityUI();
    }
  }

  function mintNodeBundle() {
    if (!wasmEngine) return;
    const nodeId = $("mint-node-input").value.trim();
    const role = $("mint-role-select").value;
    const expiresDays = Math.max(0, parseInt($("mint-expires-input").value || "0", 10) || 0);
    const includeRootKey = role === "CLIENT" && $("mint-include-rk-chk").checked;
    const domain = $("enroll-domain-input").value.trim();
    const servers =
      currentBundleInfo && Array.isArray(currentBundleInfo.servers) && currentBundleInfo.servers.length > 0
        ? currentBundleInfo.servers
        : domain
        ? [domain]
        : [DEFAULT_SWARM_DOMAIN];

    const res = wasmEngine.call({
      op: "mint_enrollment_bundle",
      node_id: nodeId,
      role,
      servers,
      expires_days: expiresDays,
      include_root_key: includeRootKey,
      now_unix_sec: Math.floor(Date.now() / 1000),
      node_seed_b64: randomBytesB64(32),
    });
    if (!res.ok) {
      $("mint-status").textContent = res.error || "Failed to generate bundle";
      $("mint-status").className = "status-text text-err";
      $("mint-output-box").classList.add("hidden");
      return;
    }

    lastMintedBundle = res.bundle_str || "";
    lastMintedCommand = res.command_hint || "";
    $("mint-command-out").textContent = lastMintedCommand;
    $("mint-output-box").classList.remove("hidden");
    $("mint-status").textContent = `Generated signed ${res.role} bundle for "${res.node_id}".`;
    $("mint-status").className = "status-text text-ok";
    logEvent("ok", `Minted ${res.role} enrollment bundle for node "${res.node_id}"`);
  }

  // =========================================================================
  // Root Key Import / Export & Sign Out
  // =========================================================================

  function importRootKeyToken() {
    if (!wasmEngine) return;
    const tok = $("root-key-import-input").value.trim();
    if (!tok) {
      $("root-key-status").textContent = "Paste a scu1_... user root key token first.";
      $("root-key-status").className = "status-text text-err";
      return;
    }
    const res = wasmEngine.call({
      op: "import_user_root_key",
      token: tok,
    });
    if (!res.ok) {
      $("root-key-status").textContent = res.error || "Invalid root key token";
      $("root-key-status").className = "status-text text-err";
      return;
    }
    $("root-key-import-input").value = "";
    $("root-key-status").textContent = `Loaded root key for ${res.user_id} in WASM memory (not saved to Web Storage).`;
    $("root-key-status").className = "status-text text-ok";
    logEvent("ok", `Imported scu1_ root key for ${res.user_id} into WASM memory`);
    updateIdentityUI();
  }

  function openExportRootKeyDialog() {
    if (!wasmEngine) return;
    const res = wasmEngine.call({ op: "export_user_root_key" });
    if (!res.ok || !res.root_key_token) {
      $("root-key-status").textContent = res.error || "No root key in WASM memory";
      $("root-key-status").className = "status-text text-err";
      return;
    }
    $("export-root-key-token").textContent = res.root_key_token;
    $("dialog-export-root-key").showModal();
  }

  function signOutAndClearMemory() {
    disconnectWebSocket();
    cancelActiveEnrollment("");
    currentBundleInfo = null;
    $("bundle-input").value = "";
    $("root-key-import-input").value = "";
    $("root-key-status").textContent = "";
    $("bundle-status").textContent = "";
    $("vault-action-status").textContent = "";
    $("mint-output-box").classList.add("hidden");
    setEnrollProgressUI(false, "", "", "");
    try {
      sessionStorage.removeItem(STORAGE_BUNDLE_KEY);
      sessionStorage.removeItem(STORAGE_WS_URL_KEY);
      localStorage.removeItem(STORAGE_BUNDLE_KEY);
      localStorage.removeItem(STORAGE_WS_URL_KEY);
    } catch (_) {}
    if (wasmEngine) {
      wasmEngine.call({ op: "clear_identity" });
    }
    updateIdentityUI();
    logEvent("info", "Signed out and cleared identity + root key from WASM memory and browser storage.");
  }

  // =========================================================================
  // Coordinator WebSocket & SSH Signing Engine
  // =========================================================================

  function updateConnBadge(state, detail) {
    const badge = $("conn-status-badge");
    const sub = $("conn-detail-text");
    if (state === "connected") {
      badge.textContent = "Connected & Authenticated";
      badge.className = "badge badge-ok";
    } else if (state === "connecting") {
      badge.textContent = "Connecting...";
      badge.className = "badge badge-warn";
    } else {
      badge.textContent = "Disconnected";
      badge.className = "badge badge-neutral";
    }
    if (sub && detail !== undefined) {
      sub.textContent = detail;
    }
  }

  function sendFrameB64(frameB64) {
    if (!ws || ws.readyState !== WebSocket.OPEN || !frameB64) return false;
    const raw = b64ToUint8Array(frameB64);
    ws.send(raw.buffer);
    return true;
  }

  function sendStatusFrame() {
    if (!wasmEngine || !ws || ws.readyState !== WebSocket.OPEN) return;
    const forceActive = $("force-active-chk").checked;
    const res = wasmEngine.call({
      op: "build_status_frame",
      last_input_epoch_ms: lastInputEpochMs,
      force_active: forceActive,
      os: "browser-wasm",
    });
    if (res.ok && res.frame_b64) {
      sendFrameB64(res.frame_b64);
    }
  }

  function requestZellijHosts(refresh) {
    if (!wasmEngine || !ws || ws.readyState !== WebSocket.OPEN) return;
    const res = wasmEngine.call({
      op: "build_request_zellij_hosts_frame",
      refresh: Boolean(refresh),
    });
    if (res.ok && res.frame_b64) {
      sendFrameB64(res.frame_b64);
    }
  }

  function connectWebSocket() {
    if (!wasmEngine) return;
    if (!currentBundleInfo) {
      const bundleText = $("bundle-input").value.trim();
      if (!applyBundle(bundleText, false)) return;
    }
    const wsUrl = $("ws-url-input").value.trim() || currentBundleInfo.ws_url;
    if (!wsUrl) {
      logEvent("error", "Missing Coordinator WebSocket URL (wss://.../ws/workstation)");
      return;
    }

    manualDisconnect = false;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (ws) {
      try {
        ws.onclose = null;
        ws.close();
      } catch (_) {}
      ws = null;
    }

    updateConnBadge("connecting", `Connecting to ${wsUrl}...`);
    logEvent("info", `Opening WebSocket connection to ${wsUrl}...`);

    try {
      ws = new WebSocket(wsUrl);
      ws.binaryType = "arraybuffer";
    } catch (err) {
      updateConnBadge("disconnected", `Failed: ${err.message || err}`);
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      wsConnected = true;
      wsAuthenticated = false;
      reconnectAttempt = 0;
      const hs = wasmEngine.call({
        op: "build_auth_handshake_frame",
        now_unix_ms: Date.now(),
        nonce_hex: Array.from(crypto.getRandomValues(new Uint8Array(16)))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
      });
      if (!hs.ok) {
        logEvent("error", `Failed to build AuthHandshake: ${hs.error}`);
        ws.close();
        return;
      }
      sendFrameB64(hs.frame_b64);
      sendStatusFrame();
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        sendStatusFrame();
      }, 25000);
    };

    ws.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return;
      const bytes = new Uint8Array(ev.data);
      const b64 = uint8ArrayToB64(bytes);
      const decoded = wasmEngine.call({
        op: "decode_server_frame",
        frame_b64: b64,
        now_unix_sec: Math.floor(Date.now() / 1000),
      });
      if (!decoded.ok) {
        logEvent("warn", `Failed to decode server frame: ${decoded.error}`);
        return;
      }
      handleServerFrame(decoded);
    };

    ws.onerror = () => {
      logEvent("warn", "WebSocket transport error.");
    };

    ws.onclose = (ev) => {
      const wasAuthed = wsAuthenticated;
      wsConnected = false;
      wsAuthenticated = false;
      if (heartbeatTimer) {
        clearInterval(heartbeatTimer);
        heartbeatTimer = null;
      }
      updateConnBadge(
        "disconnected",
        `Closed (code ${ev.code}${ev.reason ? ": " + ev.reason : ""})`
      );
      logEvent("warn", `WebSocket disconnected (code ${ev.code}).`);
      if (!manualDisconnect) {
        if (!wasAuthed && currentOperatorUrl() && currentBundleInfo && currentBundleInfo.has_user_cert) {
          maybeRenewUserCert(true).finally(() => scheduleReconnect());
        } else {
          scheduleReconnect();
        }
      }
    };
  }

  function scheduleReconnect() {
    if (manualDisconnect || reconnectTimer) return;
    const delayMs = Math.min(1000 * Math.pow(1.6, reconnectAttempt), 15000);
    reconnectAttempt++;
    updateConnBadge(
      "connecting",
      `Reconnecting in ${(delayMs / 1000).toFixed(1)}s...`
    );
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectWebSocket();
    }, delayMs);
  }

  function disconnectWebSocket() {
    manualDisconnect = true;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
    if (ws) {
      try {
        ws.close();
      } catch (_) {}
      ws = null;
    }
    updateConnBadge("disconnected", "Disconnected by user");
    logEvent("info", "Disconnected from coordinator.");
  }

  function handleServerFrame(decoded) {
    switch (decoded.frame_type) {
      case "heartbeat": {
        if (!wsAuthenticated) {
          wsAuthenticated = true;
          logEvent(
            "ok",
            `Authenticated with coordinator as "${currentBundleInfo ? currentBundleInfo.node_id : "workstation"}" (${heldKeys.length} SSH key(s) advertised)`
          );
          sendStatusFrame();
        }
        const ts = new Date().toLocaleTimeString();
        updateConnBadge(
          "connected",
          `Node: ${currentBundleInfo ? currentBundleInfo.node_id : ""} | Last heartbeat: ${ts}`
        );
        break;
      }
      case "zellij_host_list": {
        zellijHosts = decoded.hosts || [];
        renderZellijHosts();
        break;
      }
      case "cancel_sign_request": {
        const reqId = decoded.request_id;
        logEvent("info", `SignRequest ${reqId} cancelled by coordinator (handled elsewhere or timed out).`);
        pendingQueue = pendingQueue.filter((r) => r.request_id !== reqId);
        if (activePromptReq && activePromptReq.request_id === reqId) {
          activePromptReq = null;
          showNextPendingRequest();
        }
        updatePendingBadge();
        break;
      }
      case "sign_request_invalid": {
        if (decoded.ack_frame_b64) sendFrameB64(decoded.ack_frame_b64);
        if (decoded.deny_frame_b64) sendFrameB64(decoded.deny_frame_b64);
        logEvent(
          "error",
          `REJECTED invalid SignRequest ${decoded.request_id}: ${decoded.error}`
        );
        break;
      }
      case "sign_request": {
        if (decoded.ack_frame_b64) {
          sendFrameB64(decoded.ack_frame_b64);
        }
        const req = decoded.request;
        logEvent(
          "info",
          `Incoming SignRequest ${req.request_id} from ${req.verified_node_id}: tool="${req.primary_tool}" cmd="${req.primary_cmdline}" key=${req.key_fingerprint}`
        );

        if (req.has_matching_key && matchesApprovalPolicy(req)) {
          logEvent(
            "ok",
            `Auto-approved SignRequest ${req.request_id} (${req.primary_tool} on ${req.verified_node_id}) via 15m policy`
          );
          executeSignDecision(req.request_id, true);
          return;
        }

        if (
          (activePromptReq && activePromptReq.request_id === req.request_id) ||
          pendingQueue.some((r) => r.request_id === req.request_id)
        ) {
          return;
        }

        pendingQueue.push(req);
        updatePendingBadge();
        notifyUserOfSignRequest(req);
        if (!activePromptReq) {
          showNextPendingRequest();
        }
        break;
      }
    }
  }

  function playAlertBeep() {
    if (!$("sound-alert-chk").checked) return;
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      const ctx = new Ctx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.setValueAtTime(1174.66, ctx.currentTime + 0.09);
      gain.gain.setValueAtTime(0.12, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.25);
    } catch (_) {}
  }

  function notifyUserOfSignRequest(req) {
    playAlertBeep();
    document.title = `(${pendingQueue.length + (activePromptReq ? 1 : 0)}) SSH Sign Request!`;
    if ("Notification" in window && Notification.permission === "granted") {
      try {
        new Notification(`SSH Sign Request: ${req.primary_tool} @ ${req.verified_node_id}`, {
          body: `${req.primary_cmdline}\nTarget user: ${req.target_username || "N/A"}\nKey: ${req.key_comment || req.key_fingerprint}`,
          tag: req.request_id,
        });
      } catch (_) {}
    }
  }

  function updatePendingBadge() {
    const total = pendingQueue.length + (activePromptReq ? 1 : 0);
    const badge = $("pending-count-badge");
    if (badge) {
      badge.textContent = `${total} Pending`;
      badge.className = total > 0 ? "badge badge-warn" : "badge badge-neutral";
    }
    if (total === 0) {
      document.title = originalTitle;
    }
  }

  function showNextPendingRequest() {
    const modal = $("sign-approval-card");
    const idleBox = $("sign-idle-box");
    if (pendingQueue.length === 0) {
      activePromptReq = null;
      modal.classList.add("hidden");
      idleBox.classList.remove("hidden");
      updatePendingBadge();
      return;
    }
    activePromptReq = pendingQueue.shift();
    updatePendingBadge();

    const r = activePromptReq;
    const fullCmd = r.primary_cmdline || r.cmdline || r.comm;
    $("req-host").textContent = r.verified_node_id || r.hostname;
    $("req-target-user").textContent = r.is_userauth_request
      ? `${r.target_username} (${r.service_name || "ssh-connection"})`
      : "Raw Challenge (Non-userauth)";
    $("req-tool").textContent = fullCmd && fullCmd !== r.primary_tool
      ? `${r.primary_tool} (${fullCmd})`
      : r.primary_tool;
    $("req-cmdline").textContent = fullCmd;
    $("req-cwd").textContent = r.cwd || "(unknown)";
    $("req-proc").textContent = `${r.comm} (pid=${r.pid}, uid=${r.uid})`;
    $("req-key").textContent = r.key_comment
      ? `${r.key_comment} (${r.key_fingerprint})`
      : r.key_fingerprint;
    $("req-id").textContent = r.request_id;

    const ancList = $("req-ancestors");
    ancList.textContent = "";
    if (r.ancestors && r.ancestors.length > 0) {
      for (const a of r.ancestors) {
        const li = document.createElement("li");
        li.textContent = `[pid ${a.pid}] ${a.comm}: ${a.cmdline}`;
        ancList.appendChild(li);
      }
    } else {
      const li = document.createElement("li");
      li.textContent = "(no parent process ancestry reported)";
      ancList.appendChild(li);
    }

    const warnEl = $("req-missing-key-warn");
    const approveBtns = [
      $("btn-approve-once"),
      $("btn-approve-tool-15m"),
      $("btn-approve-host-15m"),
    ];
    if (!r.has_matching_key) {
      warnEl.classList.remove("hidden");
      approveBtns.forEach((b) => (b.disabled = true));
    } else {
      warnEl.classList.add("hidden");
      approveBtns.forEach((b) => (b.disabled = false));
    }

    $("btn-approve-tool-15m").textContent = `Approve '${r.primary_tool}' on ${r.verified_node_id} (15m)`;
    $("btn-approve-host-15m").textContent = `Approve ALL on ${r.verified_node_id} (15m)`;

    idleBox.classList.add("hidden");
    modal.classList.remove("hidden");
  }

  function executeSignDecision(requestId, approved) {
    if (!wasmEngine) return;
    const res = wasmEngine.call({
      op: "decide_sign_request",
      request_id: requestId,
      approved: Boolean(approved),
    });
    if (res.frame_b64) {
      sendFrameB64(res.frame_b64);
    }
    if (!res.ok) {
      logEvent("error", `Sign decision for ${requestId} failed: ${res.error}`);
    } else if (approved) {
      logEvent("ok", `Signed and approved request ${requestId}.`);
    } else {
      logEvent("warn", `Denied SignRequest ${requestId}.`);
    }
  }

  function addApprovalPolicy(host, tool) {
    const expiresAtMs = Date.now() + 15 * 60 * 1000;
    approvalPolicies = approvalPolicies.filter(
      (p) => !(p.host === host && p.tool === tool)
    );
    approvalPolicies.push({
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      host,
      tool,
      expiresAtMs,
    });
    renderPoliciesUI();
    logEvent(
      "info",
      `Added 15-minute auto-approve rule: tool="${tool}" on host="${host}"`
    );
  }

  function matchesApprovalPolicy(req) {
    const now = Date.now();
    approvalPolicies = approvalPolicies.filter((p) => p.expiresAtMs > now);
    for (const p of approvalPolicies) {
      if (
        p.host === req.verified_node_id &&
        (p.tool === "*" || p.tool === req.primary_tool)
      ) {
        return true;
      }
    }
    return false;
  }

  function renderPoliciesUI() {
    const now = Date.now();
    approvalPolicies = approvalPolicies.filter((p) => p.expiresAtMs > now);
    const tbody = $("policies-tbody");
    if (!tbody) return;
    tbody.textContent = "";
    if (approvalPolicies.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.className = "empty-cell";
      td.textContent = "No active 15-minute auto-approve rules.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const p of approvalPolicies) {
      const remSec = Math.max(0, Math.ceil((p.expiresAtMs - now) / 1000));
      const mins = Math.floor(remSec / 60);
      const secs = remSec % 60;

      const tr = document.createElement("tr");

      const tdHost = document.createElement("td");
      const hostCode = document.createElement("code");
      hostCode.textContent = p.host;
      tdHost.appendChild(hostCode);

      const tdTool = document.createElement("td");
      const toolCode = document.createElement("code");
      toolCode.textContent = p.tool === "*" ? "ALL (*)" : p.tool;
      tdTool.appendChild(toolCode);

      const tdExp = document.createElement("td");
      tdExp.textContent = `${mins}m ${secs}s`;

      const tdAct = document.createElement("td");
      const revokeBtn = document.createElement("button");
      revokeBtn.type = "button";
      revokeBtn.className = "btn btn-sm btn-danger";
      revokeBtn.textContent = "Revoke";
      revokeBtn.addEventListener("click", () => {
        approvalPolicies = approvalPolicies.filter((item) => item.id !== p.id);
        renderPoliciesUI();
      });
      tdAct.appendChild(revokeBtn);

      tr.appendChild(tdHost);
      tr.appendChild(tdTool);
      tr.appendChild(tdExp);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    }
  }

  function refreshKeysUI() {
    if (!wasmEngine) return;
    const res = wasmEngine.call({ op: "list_ssh_keys" });
    if (!res.ok) return;
    heldKeys = res.keys || [];
    const tbody = $("keys-tbody");
    tbody.textContent = "";
    if (heldKeys.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.className = "empty-cell";
      td.textContent = "No SSH keys loaded in browser WASM agent yet. Generate or import a key below.";
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      for (const k of heldKeys) {
        const tr = document.createElement("tr");

        const tdType = document.createElement("td");
        const typeSpan = document.createElement("span");
        typeSpan.className = "badge badge-ok";
        typeSpan.textContent = k.key_type;
        tdType.appendChild(typeSpan);

        const tdFp = document.createElement("td");
        const fpCode = document.createElement("code");
        fpCode.textContent = k.fingerprint_sha256;
        tdFp.appendChild(fpCode);

        const tdComment = document.createElement("td");
        tdComment.textContent = k.comment || "(no comment)";

        const tdAct = document.createElement("td");
        const actRow = document.createElement("div");
        actRow.className = "row";
        actRow.style.marginTop = "0";

        if (k.authorized_key_line) {
          const copyBtn = document.createElement("button");
          copyBtn.type = "button";
          copyBtn.className = "btn btn-sm";
          copyBtn.textContent = "Copy Pub";
          copyBtn.addEventListener("click", () => {
            copyToClipboard(k.authorized_key_line, copyBtn);
          });
          actRow.appendChild(copyBtn);
        }

        const rmBtn = document.createElement("button");
        rmBtn.type = "button";
        rmBtn.className = "btn btn-sm btn-danger";
        rmBtn.textContent = "Remove";
        rmBtn.addEventListener("click", () => {
          wasmEngine.call({ op: "remove_ssh_key", fingerprint_sha256: k.fingerprint_sha256 });
          logEvent("info", `Removed SSH key ${k.fingerprint_sha256} from WASM agent.`);
          refreshKeysUI();
          sendStatusFrame();
        });
        actRow.appendChild(rmBtn);
        tdAct.appendChild(actRow);

        tr.appendChild(tdType);
        tr.appendChild(tdFp);
        tr.appendChild(tdComment);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      }
    }
    $("keys-count-badge").textContent = `${heldKeys.length} Key(s)`;
  }

  function generateEphemeralSshKey() {
    if (!wasmEngine) return;
    const comment = $("gen-key-comment-input").value.trim() || "browser-ephemeral";
    const res = wasmEngine.call({
      op: "generate_ssh_key",
      seed_b64: randomBytesB64(32),
      comment,
    });
    if (!res.ok || !res.added_key) {
      $("key-add-status").textContent = res.error || "Failed to generate ephemeral SSH key";
      $("key-add-status").className = "status-text text-err";
      return;
    }
    const k = res.added_key;
    $("gen-key-pub-line").textContent = k.authorized_key_line || "";
    $("gen-key-output").classList.remove("hidden");
    $("key-add-status").textContent = `Generated ephemeral ${k.key_type} ${k.fingerprint_sha256} (${k.comment})`;
    $("key-add-status").className = "status-text text-ok";
    logEvent(
      "ok",
      `Generated ephemeral SSH key in WASM memory: ${k.fingerprint_sha256} (${k.comment})`
    );
    refreshKeysUI();
    sendStatusFrame();
  }

  function addKeyFromPemInput() {
    if (!wasmEngine) return;
    const pem = $("ssh-key-pem-input").value.trim();
    const passphrase = $("ssh-key-passphrase-input").value;
    if (!pem) {
      $("key-add-status").textContent = "Paste or select an OpenSSH private key first.";
      $("key-add-status").className = "status-text text-err";
      return;
    }
    const res = wasmEngine.call({
      op: "add_ssh_key",
      pem,
      passphrase,
    });
    if (!res.ok) {
      $("key-add-status").textContent = res.error || "Failed to load key";
      $("key-add-status").className = "status-text text-err";
      if (res.needs_passphrase) {
        $("ssh-key-passphrase-input").focus();
      }
      logEvent("error", `Failed to add SSH key: ${res.error}`);
      return;
    }
    $("ssh-key-pem-input").value = "";
    $("ssh-key-passphrase-input").value = "";
    $("ssh-key-file-input").value = "";
    const k = res.added_key;
    $("key-add-status").textContent = `Loaded ${k.key_type} ${k.fingerprint_sha256} (${k.comment || "no comment"})`;
    $("key-add-status").className = "status-text text-ok";
    logEvent(
      "ok",
      `Loaded SSH private key into WASM agent: ${k.fingerprint_sha256} (${k.comment || "no comment"})`
    );
    refreshKeysUI();
    sendStatusFrame();
  }

  function renderZellijHosts() {
    const tbody = $("zellij-hosts-tbody");
    if (!tbody) return;
    tbody.textContent = "";
    if (!zellijHosts || zellijHosts.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 3;
      td.className = "empty-cell";
      td.textContent = "No online Zellij relay hosts reported for this user.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const h of zellijHosts) {
      const tr = document.createElement("tr");

      const tdNode = document.createElement("td");
      const nodeCode = document.createElement("code");
      nodeCode.textContent = h.node_id;
      tdNode.appendChild(nodeCode);

      const tdStatus = document.createElement("td");
      const stBadge = document.createElement("span");
      stBadge.className = h.zellij_enabled ? "badge badge-ok" : "badge badge-neutral";
      stBadge.textContent = h.zellij_enabled ? "Online" : "Disabled";
      tdStatus.appendChild(stBadge);

      const tdSess = document.createElement("td");
      const sessions = h.sessions || [];
      if (sessions.length === 0) {
        const empty = document.createElement("span");
        empty.className = "muted";
        empty.textContent = "No active sessions";
        tdSess.appendChild(empty);
      } else {
        for (const s of sessions) {
          const sb = document.createElement("span");
          sb.className = `badge ${s.exited ? "badge-neutral" : "badge-ok"}`;
          sb.style.marginRight = "4px";
          sb.textContent = s.created_info ? `${s.name} (${s.created_info})` : s.name;
          tdSess.appendChild(sb);
        }
      }

      tr.appendChild(tdNode);
      tr.appendChild(tdStatus);
      tr.appendChild(tdSess);
      tbody.appendChild(tr);
    }
  }

  function wireEvents() {
    const markActivity = () => {
      lastInputEpochMs = Date.now();
    };
    window.addEventListener("mousemove", markActivity, { passive: true });
    window.addEventListener("keydown", markActivity, { passive: true });
    window.addEventListener("click", markActivity, { passive: true });

    window.addEventListener("beforeunload", () => {
      if (activeEnroll) {
        closeEnrollPopup();
        try {
          fetch(`${activeEnroll.operatorUrl}/api/v1/enroll/cancel`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${activeEnroll.pollToken}`,
            },
            body: JSON.stringify({ state: activeEnroll.state }),
            keepalive: true,
          });
        } catch (_) {}
      }
    });

    // GitHub OAuth & Pairing / Recovery events
    $("github-enroll-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      startGitHubLogin();
    });

    $("btn-cancel-enroll").addEventListener("click", () => {
      cancelActiveEnrollment("GitHub enrollment canceled.");
    });

    $("btn-sign-out").addEventListener("click", () => {
      signOutAndClearMemory();
    });

    $("unlock-vault-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      unlockWithRecoveryPassphrase();
    });

    $("btn-open-reset-dialog").addEventListener("click", () => {
      $("reset-confirm-input").value = "";
      $("reset-dialog-status").textContent = "";
      $("dialog-reset-root-key").showModal();
      $("reset-confirm-input").focus();
    });

    $("btn-close-reset-dialog").addEventListener("click", () => {
      $("dialog-reset-root-key").close();
    });

    $("reset-root-key-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      confirmResetRootKey();
    });

    // Approver pairing events
    $("btn-approve-pairing").addEventListener("click", () => {
      respondToActivePairing(true);
    });
    $("btn-deny-pairing").addEventListener("click", () => {
      respondToActivePairing(false);
    });

    // Manual bundle & root key import/export
    $("btn-connect").addEventListener("click", () => {
      if (applyBundle($("bundle-input").value, false)) {
        connectWebSocket();
      }
    });

    $("btn-disconnect").addEventListener("click", () => {
      disconnectWebSocket();
    });

    $("btn-clear-storage").addEventListener("click", () => {
      sessionStorage.removeItem(STORAGE_BUNDLE_KEY);
      sessionStorage.removeItem(STORAGE_WS_URL_KEY);
      localStorage.removeItem(STORAGE_BUNDLE_KEY);
      localStorage.removeItem(STORAGE_WS_URL_KEY);
      logEvent("info", "Cleared saved enrollment bundle from browser storage.");
    });

    $("btn-import-root-key").addEventListener("click", () => {
      importRootKeyToken();
    });

    $("btn-export-root-key").addEventListener("click", () => {
      openExportRootKeyDialog();
    });

    $("btn-copy-exported-rk").addEventListener("click", (ev) => {
      copyToClipboard($("export-root-key-token").textContent, ev.currentTarget);
    });

    $("btn-close-export-dialog").addEventListener("click", () => {
      $("export-root-key-token").textContent = "";
      $("dialog-export-root-key").close();
    });

    $("dialog-export-root-key").addEventListener("close", () => {
      $("export-root-key-token").textContent = "";
    });

    // Recovery Vault & Bundle Minting
    $("set-vault-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      setRecoveryVault();
    });

    $("btn-remove-vault").addEventListener("click", () => {
      removeRecoveryVault();
    });

    $("mint-role-select").addEventListener("change", () => {
      updateMintIncludeRootKeyState();
    });

    $("mint-bundle-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      mintNodeBundle();
    });

    $("btn-copy-mint-cmd").addEventListener("click", (ev) => {
      copyToClipboard(lastMintedCommand, ev.currentTarget);
    });

    $("btn-copy-mint-token").addEventListener("click", (ev) => {
      copyToClipboard(lastMintedBundle, ev.currentTarget);
    });

    $("enroll-operator-input").addEventListener("change", () => {
      updateIdentityUI();
    });

    // Header controls & notifications
    $("force-active-chk").addEventListener("change", () => {
      sendStatusFrame();
    });

    $("btn-enable-notifications").addEventListener("click", async () => {
      if (!("Notification" in window)) {
        logEvent("warn", "Browser desktop notifications are not supported in this context.");
        return;
      }
      const perm = await Notification.requestPermission();
      logEvent("info", `Desktop notification permission: ${perm}`);
    });

    // SSH Key Ring controls
    $("btn-generate-ssh-key").addEventListener("click", () => {
      generateEphemeralSshKey();
    });

    $("btn-copy-gen-pubkey").addEventListener("click", (ev) => {
      copyToClipboard($("gen-key-pub-line").textContent, ev.currentTarget);
    });

    $("ssh-key-file-input").addEventListener("change", (ev) => {
      const file = ev.target.files && ev.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        $("ssh-key-pem-input").value = String(reader.result || "");
        $("key-add-status").textContent = `Selected file "${file.name}". Click "Load Key into WASM Agent" (enter passphrase if encrypted).`;
        $("key-add-status").className = "status-text";
      };
      reader.readAsText(file);
    });

    $("btn-add-ssh-key").addEventListener("click", () => {
      addKeyFromPemInput();
    });

    // Signing approvals
    $("btn-approve-once").addEventListener("click", () => {
      if (!activePromptReq) return;
      const reqId = activePromptReq.request_id;
      activePromptReq = null;
      executeSignDecision(reqId, true);
      showNextPendingRequest();
    });

    $("btn-approve-tool-15m").addEventListener("click", () => {
      if (!activePromptReq) return;
      const req = activePromptReq;
      activePromptReq = null;
      addApprovalPolicy(req.verified_node_id, req.primary_tool);
      executeSignDecision(req.request_id, true);
      showNextPendingRequest();
    });

    $("btn-approve-host-15m").addEventListener("click", () => {
      if (!activePromptReq) return;
      const req = activePromptReq;
      activePromptReq = null;
      addApprovalPolicy(req.verified_node_id, "*");
      executeSignDecision(req.request_id, true);
      showNextPendingRequest();
    });

    $("btn-deny-req").addEventListener("click", () => {
      if (!activePromptReq) return;
      const reqId = activePromptReq.request_id;
      activePromptReq = null;
      executeSignDecision(reqId, false);
      showNextPendingRequest();
    });

    $("btn-refresh-zellij").addEventListener("click", () => {
      requestZellijHosts(true);
    });

    policyCleanupTimer = setInterval(() => {
      if (approvalPolicies.length > 0) {
        renderPoliciesUI();
      }
    }, 1000);
  }

  window.addEventListener("DOMContentLoaded", () => {
    wireEvents();
    initWasm();
  });
})();

// Sockcast Browser Workstation (WASM + WebSocket Client)
// Supports both Rust wasm32-unknown-unknown (sockcast_proto.wasm) and Go wasm (sockcast_wasm.wasm).

(() => {
  "use strict";

  const STORAGE_BUNDLE_KEY = "sockcast_wasm_bundle_v1";
  const STORAGE_WS_URL_KEY = "sockcast_wasm_ws_url_v1";
  const STORAGE_KEYS_KEY = "sockcast_wasm_ssh_keys_v1";

  let wasmEngine = null; // { type: "rust-wasm" | "go-wasm", call(reqObj): respObj }
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
  let heldKeys = [];
  let pendingQueue = []; // array of SignRequestInfo
  let activePromptReq = null;
  let approvalPolicies = []; // { id, host, tool, expiresAtMs }
  let zellijHosts = [];
  let originalTitle = document.title;

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

  async function tryLoadRustWasm() {
    try {
      const resp = await fetch("./sockcast_proto.wasm", { cache: "no-cache" });
      if (!resp.ok) return null;
      const buf = await resp.arrayBuffer();
      const magic = new Uint8Array(buf, 0, 4);
      if (
        magic.length < 4 ||
        magic[0] !== 0x00 ||
        magic[1] !== 0x61 ||
        magic[2] !== 0x73 ||
        magic[3] !== 0x6d
      ) {
        return null;
      }
      const { instance } = await WebAssembly.instantiate(buf, {});
      const ex = instance.exports;
      if (
        typeof ex.sockcast_wasm_alloc !== "function" ||
        typeof ex.sockcast_wasm_call !== "function"
      ) {
        return null;
      }
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();
      return {
        type: "rust-wasm (sockcast_proto.wasm)",
        call(reqObj) {
          const reqBytes = encoder.encode(JSON.stringify(reqObj));
          const ptr = ex.sockcast_wasm_alloc(reqBytes.length);
          new Uint8Array(ex.memory.buffer, ptr, reqBytes.length).set(reqBytes);
          const resLen = ex.sockcast_wasm_call(ptr, reqBytes.length);
          ex.sockcast_wasm_free(ptr, reqBytes.length);
          const resPtr = ex.sockcast_wasm_result_ptr();
          const resBytes = new Uint8Array(ex.memory.buffer, resPtr, resLen);
          return JSON.parse(decoder.decode(resBytes));
        },
      };
    } catch (_) {
      return null;
    }
  }

  async function loadGoWasm() {
    if (typeof Go === "undefined") {
      throw new Error("wasm_exec.js is not loaded");
    }
    const go = new Go();
    const resp = await fetch("./sockcast_wasm.wasm");
    if (!resp.ok) {
      throw new Error(`Failed to fetch sockcast_wasm.wasm: HTTP ${resp.status}`);
    }
    let result;
    if (WebAssembly.instantiateStreaming) {
      try {
        result = await WebAssembly.instantiateStreaming(resp, go.importObject);
      } catch (_) {
        const fallbackResp = await fetch("./sockcast_wasm.wasm");
        const buf = await fallbackResp.arrayBuffer();
        result = await WebAssembly.instantiate(buf, go.importObject);
      }
    } else {
      const buf = await resp.arrayBuffer();
      result = await WebAssembly.instantiate(buf, go.importObject);
    }
    go.run(result.instance);
    for (let i = 0; i < 50; i++) {
      if (globalThis.__sockcastGoWasm) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    if (!globalThis.__sockcastGoWasm) {
      throw new Error("WASM module did not register __sockcastGoWasm");
    }
    return {
      type: "wasm (sockcast_wasm.wasm)",
      call(reqObj) {
        const raw = globalThis.__sockcastGoWasm.callJSON(JSON.stringify(reqObj));
        return JSON.parse(raw);
      },
    };
  }

  async function initWasm() {
    const badge = $("wasm-engine-badge");
    try {
      badge.textContent = "Loading WASM Engine...";
      let eng = await tryLoadRustWasm();
      if (!eng) {
        eng = await loadGoWasm();
      }
      wasmEngine = eng;
      badge.textContent = `Engine: ${eng.type}`;
      badge.className = "badge badge-ok";
      logEvent("info", `Initialized WebAssembly engine: ${eng.type}`);
      restoreSavedState();
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
      const savedKeysJson = sessionStorage.getItem(STORAGE_KEYS_KEY);
      if (savedKeysJson) {
        const pems = JSON.parse(savedKeysJson);
        if (Array.isArray(pems)) {
          for (const item of pems) {
            if (item && item.pem) {
              wasmEngine.call({
                op: "add_ssh_key",
                pem: item.pem,
                passphrase: item.passphrase || "",
              });
            }
          }
          refreshKeysUI();
        }
      }
    } catch (_) {}
  }

  function applyBundle(bundleStr, connectAfter) {
    if (!wasmEngine) {
      logEvent("error", "WASM engine is not ready yet.");
      return false;
    }
    const trimmed = (bundleStr || "").trim();
    if (!trimmed) {
      logEvent("warn", "Please paste a valid sc1_... client enrollment bundle.");
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
    currentBundleInfo = res;
    $("bundle-status").textContent = `Verified CLIENT grant: node="${res.node_id}" user="${res.user_id}"`;
    $("bundle-status").className = "status-text text-ok";

    const currentWsInput = $("ws-url-input").value.trim();
    const locWs = defaultWsUrlFromLocation();
    if (!currentWsInput) {
      $("ws-url-input").value = locWs || res.ws_url || "";
    }

    if ($("remember-session-chk").checked) {
      try {
        sessionStorage.setItem(STORAGE_BUNDLE_KEY, trimmed);
        sessionStorage.setItem(STORAGE_WS_URL_KEY, $("ws-url-input").value.trim());
      } catch (_) {}
    }

    logEvent(
      "info",
      `Loaded enrollment bundle for node="${res.node_id}" (${res.user_id})`
    );
    if (connectAfter) {
      connectWebSocket();
    }
    return true;
  }

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
    const bundleText = $("bundle-input").value.trim();
    if (!currentBundleInfo) {
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
        scheduleReconnect();
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
        // 1. Immediately send SignAck so coordinator locks request to this workstation
        if (decoded.ack_frame_b64) {
          sendFrameB64(decoded.ack_frame_b64);
        }
        const req = decoded.request;
        logEvent(
          "info",
          `Incoming SignRequest ${req.request_id} from ${req.verified_node_id}: tool="${req.primary_tool}" cmd="${req.primary_cmdline}" key=${req.key_fingerprint}`
        );

        // 2. Check if matching 15m policy exists
        if (req.has_matching_key && matchesApprovalPolicy(req)) {
          logEvent(
            "ok",
            `Auto-approved SignRequest ${req.request_id} (${req.primary_tool} on ${req.verified_node_id}) via 15m policy`
          );
          executeSignDecision(req.request_id, true);
          return;
        }

        // 3. Queue for interactive user approval
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
    document.title = `🔔 (${pendingQueue.length + (activePromptReq ? 1 : 0)}) SSH Sign Request!`;
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
    $("req-host").textContent = r.verified_node_id || r.hostname;
    $("req-target-user").textContent = r.is_userauth_request
      ? `${r.target_username} (${r.service_name || "ssh-connection"})`
      : "Raw Challenge (Non-userauth)";
    $("req-tool").textContent = r.primary_tool;
    $("req-cmdline").textContent = r.primary_cmdline || r.cmdline || r.comm;
    $("req-cwd").textContent = r.cwd || "(unknown)";
    $("req-proc").textContent = `${r.comm} (pid=${r.pid}, uid=${r.uid})`;
    $("req-key").textContent = r.key_comment
      ? `${r.key_comment} (${r.key_fingerprint})`
      : r.key_fingerprint;
    $("req-id").textContent = r.request_id;

    const ancList = $("req-ancestors");
    ancList.innerHTML = "";
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
      tool, // "*" or tool name
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
    tbody.innerHTML = "";
    if (approvalPolicies.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4" class="empty-cell">No active 15-minute auto-approve rules.</td>`;
      tbody.appendChild(tr);
      return;
    }
    for (const p of approvalPolicies) {
      const remSec = Math.max(0, Math.ceil((p.expiresAtMs - now) / 1000));
      const mins = Math.floor(remSec / 60);
      const secs = remSec % 60;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escapeHtml(p.host)}</code></td>
        <td><code>${escapeHtml(p.tool === "*" ? "ALL (*)" : p.tool)}</code></td>
        <td>${mins}m ${secs}s</td>
        <td><button class="btn btn-sm btn-danger" data-revoke-id="${escapeHtml(p.id)}">Revoke</button></td>
      `;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll("[data-revoke-id]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-revoke-id");
        approvalPolicies = approvalPolicies.filter((p) => p.id !== id);
        renderPoliciesUI();
      });
    });
  }

  function refreshKeysUI() {
    if (!wasmEngine) return;
    const res = wasmEngine.call({ op: "list_ssh_keys" });
    if (!res.ok) return;
    heldKeys = res.keys || [];
    const tbody = $("keys-tbody");
    tbody.innerHTML = "";
    if (heldKeys.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4" class="empty-cell">No SSH keys loaded in browser WASM agent yet. Load an OpenSSH private key below.</td>`;
      tbody.appendChild(tr);
    } else {
      for (const k of heldKeys) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><span class="badge badge-ok">${escapeHtml(k.key_type)}</span></td>
          <td><code>${escapeHtml(k.fingerprint_sha256)}</code></td>
          <td>${escapeHtml(k.comment || "(no comment)")}</td>
          <td><button class="btn btn-sm btn-danger" data-rm-fp="${escapeHtml(k.fingerprint_sha256)}">Remove</button></td>
        `;
        tbody.appendChild(tr);
      }
      tbody.querySelectorAll("[data-rm-fp]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const fp = btn.getAttribute("data-rm-fp");
          wasmEngine.call({ op: "remove_ssh_key", fingerprint_sha256: fp });
          logEvent("info", `Removed SSH key ${fp} from WASM agent.`);
          refreshKeysUI();
          sendStatusFrame();
        });
      });
    }
    $("keys-count-badge").textContent = `${heldKeys.length} Key(s)`;
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
    tbody.innerHTML = "";
    if (!zellijHosts || zellijHosts.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="3" class="empty-cell">No online Zellij relay hosts reported for this user.</td>`;
      tbody.appendChild(tr);
      return;
    }
    for (const h of zellijHosts) {
      const sessions = h.sessions || [];
      const sessHtml =
        sessions.length === 0
          ? `<span class="muted">No active sessions</span>`
          : sessions
              .map(
                (s) =>
                  `<span class="badge ${s.exited ? "badge-neutral" : "badge-ok"}">${escapeHtml(
                    s.name
                  )}${s.created_info ? " (" + escapeHtml(s.created_info) + ")" : ""}</span>`
              )
              .join(" ");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escapeHtml(h.node_id)}</code></td>
        <td>${h.zellij_enabled ? '<span class="badge badge-ok">Online</span>' : '<span class="badge badge-neutral">Disabled</span>'}</td>
        <td>${sessHtml}</td>
      `;
      tbody.appendChild(tr);
    }
  }

  function escapeHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function wireEvents() {
    const markActivity = () => {
      lastInputEpochMs = Date.now();
    };
    window.addEventListener("mousemove", markActivity, { passive: true });
    window.addEventListener("keydown", markActivity, { passive: true });
    window.addEventListener("click", markActivity, { passive: true });

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
      sessionStorage.removeItem(STORAGE_KEYS_KEY);
      localStorage.removeItem(STORAGE_BUNDLE_KEY);
      localStorage.removeItem(STORAGE_WS_URL_KEY);
      logEvent("info", "Cleared saved enrollment bundle from browser storage.");
    });

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

// Web Worker running RFC 7914 scrypt key derivation inside an isolated WASM instance
// so the main UI thread stays responsive and the 32 MiB scrypt buffer is freed on terminate().

"use strict";

function runScryptInWasm(instance, reqObj) {
  const ex = instance.exports;
  if (
    typeof ex.sshcast_wasm_alloc !== "function" ||
    typeof ex.sshcast_wasm_call !== "function"
  ) {
    throw new Error("sshcast_wasm.wasm is missing sshcast-client FFI exports");
  }
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const reqBytes = encoder.encode(JSON.stringify(reqObj));
  const ptr = ex.sshcast_wasm_alloc(reqBytes.length);
  new Uint8Array(ex.memory.buffer, ptr, reqBytes.length).set(reqBytes);
  const resLen = ex.sshcast_wasm_call(ptr, reqBytes.length);
  ex.sshcast_wasm_free(ptr, reqBytes.length);
  const resPtr = ex.sshcast_wasm_result_ptr();
  const resBytes = new Uint8Array(ex.memory.buffer, resPtr, resLen);
  return JSON.parse(decoder.decode(resBytes));
}

self.onmessage = async (ev) => {
  const data = ev.data || {};
  try {
    const wasmUrl = data.wasmUrl || "./sshcast_wasm.wasm";
    const resp = await fetch(wasmUrl, { cache: "default" });
    if (!resp.ok) {
      throw new Error(`Failed to fetch ${wasmUrl}: HTTP ${resp.status}`);
    }
    const buf = await resp.arrayBuffer();
    const { instance } = await WebAssembly.instantiate(buf, {});
    const result = runScryptInWasm(instance, {
      op: "derive_scrypt_key",
      passphrase: data.passphrase || "",
      salt_b64: data.salt_b64 || "",
      log_n: data.log_n,
      r: data.r,
      p: data.p,
    });
    self.postMessage(result);
  } catch (err) {
    self.postMessage({
      ok: false,
      error: err && err.message ? err.message : String(err),
    });
  }
};

/* Backend requests: the api() client, session reset and the zone, record and DDNS loaders. */
"use strict";

/* ================= API ================= */

function resetSessionData() {
  recordsRequest++;
  ddnsRequest++;
  state.records = [];
  state.recordsTotal = 0;
  state.recordsZoneId = null;
  state.recordsAttemptedZoneId = null;
  state.recordsError = null;
  state.recordsLoading = false;
  state.selection.clear();
  state.ddns = null;
  state.ddnsLoading = false;
  state.ddnsUpdating = false;
  state.ddnsUpdateResult = null;
}

/**
 * Calls the backend. Besides method/json/raw/text, callers that change the session say so:
 * rotatesSession: a successful call issues a new session, so older responses are stale.
 * clearsRecoveryCodes: the call ends the previous login, whose unsaved recovery codes are dropped.
 */
async function api(path, opts = {}) {
  const authentication = authGeneration;
  const page = pageGeneration;
  const zoneId = state.zoneId;
  const init = {
    method: opts.method || "GET",
    credentials: "same-origin",
    headers: { "X-Requested-With": "fetch" },
  };
  if (opts.json !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.json);
  } else if (opts.raw !== undefined) {
    init.headers["Content-Type"] = opts.rawType || "text/plain";
    init.body = opts.raw;
  }
  let resp;
  try {
    resp = await fetch(path, init);
  } catch {
    throw new Error(t("error.network"));
  }
  if (resp.status === 401 && !path.startsWith("/api/auth/")) {
    if (authentication === authGeneration && page === pageGeneration && zoneId === state.zoneId) {
      authGeneration++;
      state.authed = false;
      resetSessionData();
      state.pendingBackupCodes = null;
      invalidatePageRequests();
      render();
    }
    throw new Error("unauthorized");
  }
  const sameAuthentication = authentication === authGeneration;
  if (resp.ok && init.method === "POST" && sameAuthentication && opts.rotatesSession) {
    authGeneration++;
    resetSessionData();
    if (opts.clearsRecoveryCodes) state.pendingBackupCodes = null;
  }
  if (resp.ok && sameAuthentication && opts.authContext) opts.authContext.generation = authGeneration;
  const ct = resp.headers.get("content-type") || "";
  if (opts.text) {
    const body = await resp.text();
    if (!resp.ok) {
      let msg = body;
      try { msg = JSON.parse(body).error || body; } catch { /* keep raw */ }
      throw new Error(msg);
    }
    return body;
  }
  if (ct.includes("application/json")) {
    const data = await resp.json();
    if (!resp.ok) {
      const err = new Error(data.error || `HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }
  if (!resp.ok) {
    const err = new Error(`HTTP ${resp.status}`);
    err.status = resp.status;
    throw err;
  }
  return null;
}

/* ================= Data loading ================= */

async function loadZones() {
  const authentication = authGeneration;
  const zones = await api("/api/zones");
  if (authentication !== authGeneration || !state.authed) return;
  state.zones = zones;
  const preferred = readStored("cfddns.zone", null);
  if (preferred && state.zones.some((z) => z.id === preferred)) {
    state.zoneId = preferred;
  } else if (state.zones.length > 0) {
    state.zoneId = state.zones[0].id;
  } else {
    state.zoneId = null;
  }
}

async function loadRecords() {
  if (!state.zoneId) { state.records = []; state.recordsTotal = 0; state.recordsZoneId = null; return; }
  const zoneId = state.zoneId;
  const generation = pageGeneration;
  const authentication = authGeneration;
  const request = ++recordsRequest;
  const current = () => request === recordsRequest && generation === pageGeneration && authentication === authGeneration
    && state.authed && state.route === "records" && state.zoneId === zoneId;
  state.recordsLoading = true;
  state.recordsAttemptedZoneId = zoneId;
  state.recordsError = null;
  state.selection.clear();
  renderRecordsTable();
  try {
    const data = await api(`/api/zones/${zoneId}/records`);
    if (!current()) return;
    state.records = data.records || [];
    state.recordsTotal = data.total ?? state.records.length;
    state.recordsZoneId = zoneId;
    state.selection.clear();
    state.page = 1;
  } catch (e) {
    if (current()) state.recordsError = e.message;
  } finally {
    if (current()) state.recordsLoading = false;
  }
}

async function loadDdns() {
  const generation = pageGeneration;
  const authentication = authGeneration;
  const request = ++ddnsRequest;
  const current = () => request === ddnsRequest && generation === pageGeneration && authentication === authGeneration
    && state.authed && state.route === "dashboard";
  state.ddnsLoading = true;
  renderDashboardCards();
  try {
    const status = await api("/api/ddns/status");
    if (current()) state.ddns = status;
  } catch (e) {
    if (current()) state.ddns = { error: e.message, domains: [] };
  } finally {
    if (current()) state.ddnsLoading = false;
  }
}

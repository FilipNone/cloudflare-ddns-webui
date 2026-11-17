"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
// CI runs only this file, so it pulls in the appearance suite and shares its loader.
const { loadApp } = require("./appearance.test.cjs");

const appSource = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");

function classes(initial = []) {
  const names = new Set(initial);
  return {
    add: (name) => { names.add(name); },
    remove: (name) => { names.delete(name); },
    toggle: (name, on = !names.has(name)) => { if (on) names.add(name); else names.delete(name); return on; },
    contains: (name) => names.has(name),
  };
}

// The session flags each auth call site in app.js must pass to api().
const SESSION_FLAGS = {
  setup: { rotatesSession: true, clearsRecoveryCodes: true },
  login: { rotatesSession: true, clearsRecoveryCodes: true },
  "login/2fa": { rotatesSession: true, clearsRecoveryCodes: true },
  logout: { rotatesSession: true, clearsRecoveryCodes: true },
  password: { rotatesSession: true },
  "2fa/confirm": { rotatesSession: true },
  "2fa/disable": { rotatesSession: true },
};

function authCall(endpoint) {
  return `api('/api/auth/${endpoint}', ${JSON.stringify({ method: "POST", json: {}, ...SESSION_FLAGS[endpoint] })})`;
}

// Replaces mselect with a stand-in that records its options and can pick values.
function fakeSelects(context, run) {
  const selects = [];
  context.fakeSelect = (opts) => {
    const select = {
      opts, value: opts.value ?? "", disabled: !!opts.disabled,
      mget() { return this.value; },
      mset(value) { this.value = value; },
      msetDisabled(value) { this.disabled = value; },
      pick(value) { this.value = value; opts.onChange?.(value); },
    };
    selects.push(select);
    return select;
  };
  run("mselect = fakeSelect");
  return selects;
}

function app({ localStorage = { getItem: () => null, setItem() {} } } = {}) {
  const nodes = new Map();
  const document = {
    documentElement: { classList: { toggle() {} } },
    getElementById: (id) => nodes.get(id) || null,
    querySelectorAll: () => [],
    addEventListener() {},
    removeEventListener() {},
  };
  const context = vm.createContext({
    document,
    localStorage,
    location: { hash: "#/records" },
    window: { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} },
    setTimeout,
    clearTimeout,
    console,
    URL,
  });
  loadApp(context);
  vm.runInContext("state.authed = true; state.zoneId = 'zone-a'; const actualRender = render; const actualRenderRecordsTable = renderRecordsTable; const actualRenderDashboardCards = renderDashboardCards; renderRecordsTable = () => {}; renderDashboardCards = () => {};", context);
  return { context, nodes, run: (code) => vm.runInContext(code, context) };
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test("late zone response never replaces the current zone's records", async () => {
  const { context, run } = app();
  const old = deferred(), current = deferred();
  context.request = (url) => url.includes("zone-a") ? old.promise : current.promise;
  run("api = request;");
  const first = run("loadRecords()");
  run("state.zoneId = 'zone-b';");
  const second = run("loadRecords()");
  current.resolve({ records: [{ id: "b" }], total: 1 });
  await second;
  old.resolve({ records: [{ id: "a" }], total: 1 });
  await first;
  assert.equal(run("state.records[0].id"), "b");
  assert.equal(run("state.recordsZoneId"), "zone-b");
});

test("page navigation discards pending records and dashboard responses", async () => {
  const { context, run } = app();
  const response = deferred();
  context.request = () => response.promise;
  run("api = request; render = () => {}; closeModal = () => {}; closeMSelects = () => {};");
  const loading = run("loadRecords()");
  run("navigate('settings');");
  response.resolve({ records: [{ id: "stale" }] });
  await loading;
  assert.equal(run("state.records.length"), 0);

  const ddns = deferred();
  context.request = () => ddns.promise;
  run("navigate('dashboard');");
  const status = run("loadDdns()");
  run("navigate('records');");
  ddns.resolve({ ipv4: "192.0.2.1", domains: [] });
  await status;
  assert.equal(run("state.ddns"), null);
});

test("a failed initial records load does not recursively retry", async () => {
  const { context, nodes, run } = app();
  let requests = 0;
  context.request = async () => { requests++; if (requests > 3) return new Promise(() => {}); throw new Error("synthetic failure"); };
  nodes.set("page", { innerHTML: "" });
  run("api = request; toast = () => {}; state.zones = [{id:'zone-a',name:'example.com'}]; mselect = () => ({}); el = (id) => id === 'page' ? document.getElementById(id) : ({ addEventListener() {}, setAttribute() {}, insertBefore() {}, children: [null, null] });");
  run("renderRecords()");
  await new Promise((resolve) => setImmediate(resolve));
  run("renderRecords()");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(requests, 1);
  assert.equal(run("state.recordsError"), "synthetic failure");
});

test("metadata keep, set and clear have explicit distinct wire values", () => {
  const { run } = app();
  assert.equal(run("JSON.stringify(metadataPatch('comment', 'keep', 'ignored'))"), "{}");
  assert.equal(run("JSON.stringify(metadataPatch('comment', 'set', ' reviewed '))"), '{"comment":"reviewed"}');
  assert.equal(run("JSON.stringify(metadataPatch('comment', 'clear', 'ignored'))"), '{"comment":""}');
  assert.equal(run("JSON.stringify(metadataPatch('tags', 'clear', 'ignored'))"), '{"tags":[]}');
  assert.equal(run("JSON.stringify(metadataPatch('tags', 'set', ' owner:test, review:yes '))"), '{"tags":["owner:test","review:yes"]}');
  assert.throws(() => run("metadataPatch('comment', 'set', ' ')"));
  assert.throws(() => run("metadataPatch('tags', 'set', ', ')"));
});

test("record comments follow the server's 500-byte limit", () => {
  const { run } = app();
  // The server counts UTF-8 bytes, so 250 two-byte letters fit and 251 do not.
  assert.equal(run("metadataPatch('comment', 'set', 'a'.repeat(500)).comment.length"), 500);
  assert.equal(run("metadataPatch('comment', 'set', '\\u00e9'.repeat(250)).comment.length"), 250);
  assert.throws(() => run("metadataPatch('comment', 'set', 'a'.repeat(501))"), /500 bytes/);
  assert.throws(() => run("metadataPatch('comment', 'set', '\\u00e9'.repeat(251))"), /500 bytes/);
  assert.throws(() => run("metadataPatch('comment', 'set', 'tab\\there')"), /control characters/);
  assert.equal(run("utf8Length('\\u{1F600}')"), 4);
  assert.doesNotMatch(appSource, /maxlength="100"/);
});

test("DDNS failure evidence is retained and escaped after status refresh", async () => {
  const { context, run } = app();
  run("state.route = 'dashboard'; state.ddnsUpdateResult = { success:false, log:['<synthetic failure>'], outcomes:[] };");
  context.request = async () => ({ domains: [], configured: true });
  run("api = request;");
  await run("loadDdns()");
  assert.equal(run("state.ddnsUpdateResult.success"), false);
  assert.match(run("ddnsUpdateLog()"), /&lt;synthetic failure&gt;/);
  assert.match(run("ddnsUpdateLog()"), /role="status"/);
});

test("single record payload omits kept metadata and explicitly clears chosen fields", () => {
  const { context, run } = app();
  let commentMode = "keep", tagsMode = "clear";
  context.modal = {
    querySelectorAll: () => [],
    querySelector: (selector) => ({
      "#f-proxied": { checked: false },
      "#f-content": { value: "192.0.2.1" },
      "#f-comment": { value: "unmodified" },
      "#f-tags": { value: "owner:test" },
      "#f-comment-mode": { mget: () => commentMode },
      "#f-tags-mode": { mget: () => tagsMode },
    })[selector] || null,
  };
  const payload = () => JSON.parse(run("JSON.stringify(buildPayload(modal, 'A', 'example.com', {name:'www.example.com'}, {mget:()=> '300'}))"));
  assert.equal(Object.hasOwn(payload(), "comment"), false);
  assert.deepEqual(payload().tags, []);
  commentMode = "clear";
  tagsMode = "keep";
  assert.equal(payload().comment, "");
  assert.equal(Object.hasOwn(payload(), "tags"), false);
  commentMode = "set";
  tagsMode = "set";
  assert.equal(payload().comment, "unmodified");
  assert.deepEqual(payload().tags, ["owner:test"]);
});

for (const failure of ["partial", "request"]) {
  test(`DDNS ${failure} failure remains visible after the update handler refreshes status`, async () => {
    const { context, nodes, run } = app();
    const section = { innerHTML: "" };
    const update = { addEventListener: (_, callback) => { update.click = callback; } };
    nodes.set("stat-grid", { innerHTML: "" });
    nodes.set("ddns-section", section);
    nodes.set("ddns-update", update);
    nodes.set("ddns-refresh", { addEventListener() {} });
    const toasts = [];
    context.notify = (message, kind) => toasts.push({ message, kind });
    context.request = async (url) => {
      if (url.endsWith("/update")) {
        if (failure === "request") throw new Error("<request failure>");
        return { success: false, log: ["<provider failure>"], outcomes: [{ domain: "example.com", record_type: "A", status: "failed", error: "denied" }] };
      }
      return { domains: [], configured: true };
    };
    run("api = request; toast = notify; state.route = 'dashboard'; state.ddns = {configured:true,domains:[]}; renderDashboardCards = actualRenderDashboardCards; renderDashboardCards();");
    await update.click();
    assert.equal(run("state.ddnsUpdateResult.success"), false);
    assert.equal(run("state.ddnsUpdating"), false);
    assert.match(section.innerHTML, /DDNS update failed or partially completed/);
    assert.match(section.innerHTML, failure === "partial" ? /&lt;provider failure&gt;/ : /&lt;request failure&gt;/);
    assert.deepEqual(toasts.map((toast) => toast.kind), ["error"]);
  });
}

test("a stale request failure cannot end the current zone load or surface its error", async () => {
  const { context, run } = app();
  const old = deferred(), current = deferred();
  context.request = (url) => url.includes("zone-a") ? old.promise : current.promise;
  run("api = request;");
  const first = run("loadRecords()");
  run("state.zoneId = 'zone-b';");
  const second = run("loadRecords()");
  old.reject(new Error("stale failure"));
  await first;
  assert.equal(run("state.recordsLoading"), true);
  assert.equal(run("state.recordsError"), null);
  current.resolve({ records: [{ id: "b" }] });
  await second;
  assert.equal(run("state.recordsLoading"), false);
  assert.equal(run("state.records[0].id"), "b");
});

test("leaving and returning to the same page does not revive its old request", async () => {
  const { context, run } = app();
  const response = deferred();
  context.request = () => response.promise;
  run("api = request; render = () => {}; closeModal = () => {}; closeMSelects = () => {};");
  const pending = run("loadRecords()");
  run("navigate('settings'); navigate('records');");
  response.resolve({ records: [{ id: "stale" }] });
  await pending;
  assert.equal(run("state.records.length"), 0);
  assert.equal(run("state.recordsLoading"), false);
  assert.equal(run("state.recordsAttemptedZoneId"), null);
});

test("zone dropdown opens without a blocking body overlay and supports arrow navigation", () => {
  const { context, run } = app();
  class Element {
    constructor(tag) {
      this.tag = tag;
      this.className = "";
      this.children = [];
      this.dataset = {};
      this.attributes = {};
      this.handlers = {};
      this.classList = {
        contains: (name) => this.className.split(" ").includes(name),
        add: (name) => { if (!this.classList.contains(name)) this.className += ` ${name}`; },
        remove: (name) => { this.className = this.className.split(" ").filter((value) => value !== name).join(" "); },
        toggle: (name, force) => { const on = force ?? !this.classList.contains(name); this.classList[on ? "add" : "remove"](name); },
      };
    }
    append(...children) { this.children.push(...children); children.forEach((child) => { child.parentElement = this; }); }
    appendChild(child) { this.append(child); }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener(event, handler) { this.handlers[event] = handler; }
    focus() { context.document.activeElement = this; }
    click() { this.handlers.click?.({ stopPropagation() {} }); }
    getBoundingClientRect() { return { top: 10, bottom: 40 }; }
    querySelectorAll(selector) {
      const children = this.children.flatMap((child) => [child, ...child.querySelectorAll("*")]);
      if (selector === "*") return children;
      return children.filter((child) => selector.split(",").some((part) => part.trim().startsWith(".")
        ? part.trim().slice(1).split(".").every((name) => child.classList.contains(name)) : child.tag === part.trim()));
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  }
  const body = new Element("body");
  context.document.createElement = (tag) => new Element(tag);
  context.document.querySelectorAll = (selector) => body.querySelectorAll(selector);
  context.window.innerHeight = 844;
  const select = run("mselect({id:'test-zone',label:'Zone',options:[{value:'a',label:'example.com'},{value:'b',label:'example.net'}],value:'a'})");
  body.appendChild(select);
  const button = select.children[0];
  button.click();
  assert.equal(select.classList.contains("open"), true);
  assert.equal(button.attributes["aria-expanded"], "true");
  assert.equal(body.children.length, 1);
  select.handlers.keydown({ key: "ArrowDown", preventDefault() {} });
  assert.equal(context.document.activeElement.dataset.value, "a");
  run("closeMSelects()");
  assert.equal(select.classList.contains("open"), false);
  assert.equal(button.attributes["aria-expanded"], "false");
});

function response(status, body = {}) {
  return { status, ok: status >= 200 && status < 300, headers: { get: () => "application/json" }, json: async () => body };
}

function securityApp() {
  const fixture = app();
  const { context, nodes, run } = fixture;
  let currentModal = null;
  const root = {
    querySelector: () => currentModal,
    querySelectorAll: () => [],
    get innerHTML() { return ""; },
    set innerHTML(value) { if (value === "") { if (currentModal) currentModal.isConnected = false; currentModal = null; } },
  };
  nodes.set("modal-root", root);
  nodes.set("recovery-notice", { innerHTML: "" });
  nodes.set("backup-codes-reopen", { addEventListener(_, callback) { this.click = callback; } });
  context.createModal = () => {
    if (currentModal) currentModal.isConnected = false;
    const fields = new Map();
    currentModal = {
      isConnected: true,
      dataset: {},
      querySelectorAll: () => [],
      querySelector: (selector) => {
        if (!fields.has(selector)) fields.set(selector, {
          value: selector.includes("code") ? "123456" : "synthetic-password",
          classList: classes(),
          addEventListener(event, callback) { this.handlers ||= {}; this.handlers[event] = callback; this.click = callback; },
          replaceWith(replacement) { fields.set(selector, replacement); },
        });
        return fields.get(selector);
      },
    };
    return currentModal;
  };
  context.document.querySelector = () => null;
  run("openModal = createModal; render = () => {}; toast = () => {}; renderSecurityBody = () => {}; state.route = 'settings';");
  return { ...fixture, modal: () => currentModal };
}

for (const change of ["session", "page", "zone"]) {
  test(`actual API ignores an obsolete 401 after ${change} context changes`, async () => {
    const { context, run } = securityApp();
    const pending = deferred();
    context.fetch = (url) => url.startsWith("/api/zones/") ? pending.promise : Promise.resolve(response(200));
    const request = run("api('/api/zones/zone-a/records')");
    const rejected = assert.rejects(request);
    if (change === "session") await run(authCall("password"));
    if (change === "page") run("navigate('dashboard')");
    if (change === "zone") run("state.zoneId = 'zone-b'");
    pending.resolve(response(401, { error: "obsolete session" }));
    await rejected;
    assert.equal(run("state.authed"), true);
  });
}

test("actual API still logs out on a current authenticated request's 401", async () => {
  const { context, nodes, run, modal } = securityApp();
  run("state.pendingBackupCodes = ['synthetic-code']; showBackupCodesModal(state.pendingBackupCodes)");
  const codes = modal();
  context.fetch = async () => response(401, { error: "expired" });
  await assert.rejects(run("api('/api/zones')"));
  assert.equal(run("state.authed"), false);
  assert.equal(run("state.pendingBackupCodes"), null);
  assert.equal(codes.isConnected, false);
  run("state.authed = true; renderRecoveryNotice()");
  assert.equal(nodes.get("recovery-notice").innerHTML, "");
});

for (const endpoint of ["logout", "login", "login/2fa", "setup"]) {
  test(`successful ${endpoint} clears the previous authentication's recovery codes`, async () => {
    const { context, nodes, run } = securityApp();
    context.fetch = async () => response(200);
    run("state.pendingBackupCodes = ['synthetic-old-code']");
    await run(authCall(endpoint));
    assert.equal(run("state.pendingBackupCodes"), null);
    run("renderRecoveryNotice()");
    assert.equal(nodes.get("recovery-notice").innerHTML, "");
  });
}

test("logout clears recovery codes even when its request fails", async () => {
  const { context, nodes, run } = securityApp();
  for (const id of ["mobile-menu-btn", "mobile-nav-backdrop", "collapse-btn", "logout-btn"]) {
    nodes.set(id, { addEventListener(_, callback) { this.click = callback; } });
  }
  nodes.set("app", { innerHTML: "", querySelector: () => ({}), querySelectorAll: () => [] });
  run("state.configured = true; renderTopbarActions = () => {}; renderSettings = () => {}; actualRender(); state.pendingBackupCodes = ['synthetic-old-code']");
  context.fetch = async () => response(500, { error: "synthetic logout failure" });
  await nodes.get("logout-btn").click();
  assert.equal(run("state.authed"), false);
  assert.equal(run("state.pendingBackupCodes"), null);
  run("state.authed = true; renderRecoveryNotice()");
  assert.equal(nodes.get("recovery-notice").innerHTML, "");
});

for (const boundary of ["logout/login", "login", "expired/login"]) {
  test(`late enrollment confirmation cannot restore recovery codes after ${boundary}`, async () => {
    const { context, nodes, run, modal } = securityApp();
    const pending = deferred();
    context.fetch = (url) => url.endsWith("/confirm") ? pending.promise
      : Promise.resolve(response(url === "/api/zones" ? 401 : 200));
    run("show2faEnrollment({secret:'SYNTHETIC',qr_svg:''})");
    const confirming = modal().querySelector("#t2fa-confirm").click();
    await new Promise((resolve) => setImmediate(resolve));
    if (boundary === "logout/login") await run(authCall("logout"));
    if (boundary === "expired/login") await assert.rejects(run("api('/api/zones')"));
    await run(authCall("login"));
    run("state.authed = true; openModal('replacement')");
    const replacement = modal();
    pending.resolve(response(200, { backup_codes: ["synthetic-obsolete-code"] }));
    await confirming;
    assert.equal(run("state.pendingBackupCodes"), null);
    assert.equal(run("state.totpEnabled"), false);
    assert.equal(replacement.isConnected, true);
    assert.equal(nodes.get("recovery-notice").innerHTML, "");
  });
}

test("successful enrollment retains recovery codes after navigation during confirmation", async () => {
  const { context, nodes, run, modal } = securityApp();
  const pending = deferred();
  context.fetch = () => pending.promise;
  run("show2faEnrollment({secret:'SYNTHETIC',qr_svg:''})");
  const confirming = modal().querySelector("#t2fa-confirm").click();
  run("navigate('dashboard')");
  pending.resolve(response(200, { backup_codes: ["synthetic-code-1", "synthetic-code-2"] }));
  await confirming;
  assert.equal(run("JSON.stringify(state.pendingBackupCodes)"), '["synthetic-code-1","synthetic-code-2"]');
  assert.match(nodes.get("recovery-notice").innerHTML, /backup-codes-reopen/);
});

for (const dismiss of ["close", "escape"]) {
  test(`enrollment ${dismiss} dismissal cancels pending enrollment through actual API`, async () => {
    const { context, run } = securityApp();
    const requests = [];
    context.fetch = async (url) => { requests.push(url); return response(200); };
    run("show2faEnrollment({secret:'SYNTHETIC',qr_svg:''})");
    run(dismiss === "escape" ? "escClose({key:'Escape'})" : "closeModal()");
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(requests, ["/api/auth/2fa/cancel"]);
  });
}

test("confirmation blocks user dismissal and never cancels an in-flight commit", async () => {
  const { context, run, modal } = securityApp();
  const pending = deferred();
  const requests = [];
  context.fetch = (url) => { requests.push(url); return pending.promise; };
  run("show2faEnrollment({secret:'SYNTHETIC',qr_svg:''})");
  const enrollment = modal();
  const confirming = enrollment.querySelector("#t2fa-confirm").click();
  run("closeModal({type:'click'})");
  const stayedOpen = enrollment.isConnected;
  pending.resolve(response(200, { backup_codes: ["synthetic-code"] }));
  await confirming;
  assert.equal(stayedOpen, true);
  assert.deepEqual(requests, ["/api/auth/2fa/confirm"]);
});

for (const operation of ["password", "disable"]) {
  test(`late ${operation} success does not close an unrelated modal`, async () => {
    const { context, run, modal } = securityApp();
    const pending = deferred();
    context.fetch = () => pending.promise;
    run(operation === "password" ? "openPasswordModal()" : "open2faDisableModal()");
    const mutation = modal().querySelector(operation === "password" ? "#pw-submit" : "#d2fa-confirm").click();
    run("openModal('unrelated')");
    const unrelated = modal();
    pending.resolve(response(200));
    await mutation;
    assert.equal(unrelated.isConnected, true);
  });
}

test("late disable success cannot mutate a newer authenticated session", async () => {
  const { context, run, modal } = securityApp();
  const pending = deferred();
  context.fetch = (url) => url.endsWith("/disable") ? pending.promise : Promise.resolve(response(200));
  run("state.totpEnabled = true; open2faDisableModal()");
  const mutation = modal().querySelector("#d2fa-confirm").click();
  await run(authCall("logout"));
  await run(authCall("login"));
  pending.resolve(response(200));
  await mutation;
  assert.equal(run("state.totpEnabled"), true);
});

test("a single intervening session rotation also invalidates late disable success", async () => {
  const { context, run, modal } = securityApp();
  const pending = deferred();
  context.fetch = (url) => url.endsWith("/disable") ? pending.promise : Promise.resolve(response(200));
  run("state.totpEnabled = true; open2faDisableModal()");
  const mutation = modal().querySelector("#d2fa-confirm").click();
  await run(authCall("login"));
  pending.resolve(response(200));
  await mutation;
  assert.equal(run("state.totpEnabled"), true);
});

test("old enrollment cancellation completes before a new enrollment begins", async () => {
  const { context, run, modal } = securityApp();
  const cancellation = deferred();
  const requests = [];
  context.fetch = (url) => {
    requests.push(url);
    return url.endsWith("/cancel") ? cancellation.promise : Promise.resolve(response(200, { secret: "SYNTHETIC" }));
  };
  run("show2faEnrollment({secret:'SYNTHETIC',qr_svg:''}); closeModal(); open2faSetupModal()");
  const beginning = modal().querySelector("#begin-2fa-submit").click();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(requests, ["/api/auth/2fa/cancel"]);
  cancellation.resolve(response(200));
  await beginning;
  assert.deepEqual(requests, ["/api/auth/2fa/cancel", "/api/auth/2fa/begin"]);
});

test("closed enrollment begin is canceled before a replacement begin request", async () => {
  const { context, run, modal } = securityApp();
  const firstResponse = deferred();
  const requests = [];
  context.fetch = (url) => {
    requests.push(url);
    return requests.length === 1 ? firstResponse.promise : Promise.resolve(response(200, { secret: "SYNTHETIC" }));
  };
  run("open2faSetupModal()");
  const first = modal().querySelector("#begin-2fa-submit").click();
  await new Promise((resolve) => setImmediate(resolve));
  run("closeModal(); open2faSetupModal()");
  const second = modal().querySelector("#begin-2fa-submit").click();
  firstResponse.resolve(response(200, { secret: "SYNTHETIC" }));
  await Promise.all([first, second]);
  assert.deepEqual(requests, ["/api/auth/2fa/begin", "/api/auth/2fa/cancel", "/api/auth/2fa/begin"]);
});

test("recovery codes can be reopened after dismissal and are cleared only by acknowledgement", () => {
  const { context, nodes, run, modal } = securityApp();
  const writes = [];
  context.localStorage.setItem = (...args) => writes.push(args);
  run("state.pendingBackupCodes = ['synthetic-code']; showBackupCodesModal(state.pendingBackupCodes); closeModal(); renderRecoveryNotice()");
  assert.equal(run("state.pendingBackupCodes.length"), 1);
  nodes.get("backup-codes-reopen").click();
  modal().querySelector("#bc-done").click();
  assert.equal(run("state.pendingBackupCodes"), null);
  assert.equal(nodes.get("recovery-notice").innerHTML, "");
  assert.deepEqual(writes, []);
});

test("actual import flow sends original invalid UTF-8 bytes for backend rejection", async () => {
  const { context, run, modal } = securityApp();
  const original = Buffer.concat([Buffer.from('$TTL 300\n@ TXT "'), Buffer.from([0xff]), Buffer.from('"\n')]);
  const blob = new Blob([original]);
  const file = { name: "synthetic-invalid.zone", size: blob.size, text: () => blob.text(), arrayBuffer: () => blob.arrayBuffer() };
  let sent;
  context.fetch = async (url, init) => {
    assert.match(url, /^\/api\/zones\/zone-a\/import\?filename=synthetic-invalid\.zone$/);
    assert.equal(init.headers["Content-Type"], "text/plain");
    sent = Buffer.from(init.body);
    try { new TextDecoder("utf-8", { fatal: true }).decode(sent); }
    catch { return response(400, { error: "Invalid UTF-8 zone file" }); }
    return response(200, { recs_added: 1, total_records_parsed: 1 });
  };
  run("openImportModal()");
  const importModal = modal();
  importModal.querySelector("#dropzone").handlers.drop({ preventDefault() {}, stopPropagation() {}, dataTransfer: { files: [file] } });
  await importModal.querySelector("#i-submit").click();
  assert.deepEqual(sent, original);
  assert.equal(importModal.querySelector("#import-error").textContent, "Invalid UTF-8 zone file");
  assert.equal(importModal.isConnected, true);
  assert.equal(importModal.querySelector("#i-submit").disabled, false);
});

test("valid import bytes reach the captured zone unchanged", async () => {
  const { context, run, modal } = securityApp();
  const original = Buffer.from('$TTL 300\n@ TXT "caf\u00e9"\n');
  const blob = new Blob([original]);
  const file = { name: "synthetic-valid.zone", size: blob.size, arrayBuffer: () => blob.arrayBuffer() };
  let sent;
  context.fetch = async (url, init) => {
    assert.match(url, /^\/api\/zones\/zone-a\/import\?/);
    sent = Buffer.from(init.body);
    return response(200, { recs_added: 1, total_records_parsed: 1 });
  };
  run("openImportModal()");
  const importModal = modal();
  importModal.querySelector("#dropzone").handlers.drop({ preventDefault() {}, stopPropagation() {}, dataTransfer: { files: [file] } });
  run("state.zoneId = 'zone-b'");
  await importModal.querySelector("#i-submit").click();
  assert.deepEqual(sent, original);
  assert.equal(importModal.isConnected, false);
});

test("closing an import during the raw-byte read prevents its request", async () => {
  const { context, run, modal } = securityApp();
  const read = deferred();
  const file = { name: "synthetic.zone", size: 32, arrayBuffer: () => read.promise };
  let requests = 0;
  context.fetch = async () => { requests++; return response(200); };
  run("openImportModal()");
  const importModal = modal();
  importModal.querySelector("#dropzone").handlers.drop({ preventDefault() {}, stopPropagation() {}, dataTransfer: { files: [file] } });
  const importing = importModal.querySelector("#i-submit").click();
  run("closeModal()");
  read.resolve(new ArrayBuffer(32));
  await importing;
  assert.equal(requests, 0);
});

function ddnsApp() {
  const fixture = securityApp();
  const { context, nodes, run } = fixture;
  const section = { innerHTML: "" };
  const update = { addEventListener(_, callback) { this.click = callback; } };
  const toasts = [];
  nodes.set("stat-grid", { innerHTML: "" });
  nodes.set("ddns-section", section);
  nodes.set("ddns-update", update);
  nodes.set("ddns-refresh", { addEventListener() {} });
  context.notify = (message, kind) => toasts.push({ message, kind });
  run("toast = notify; state.route = 'dashboard'; state.ddns = {configured:true,domains:[]}; renderDashboardCards = actualRenderDashboardCards; renderDashboardCards()");
  return { ...fixture, section, update, toasts };
}

for (const failure of ["partial", "network"]) {
  test(`DDNS ${failure} failure replaces old success after navigation in the same session`, async () => {
    const { context, run, update, section, toasts } = ddnsApp();
    const pending = deferred();
    context.fetch = () => pending.promise;
    run("state.ddnsUpdateResult = {success:true,log:['old success'],outcomes:[]}");
    const mutation = update.click();
    run("navigate('settings')");
    if (failure === "partial") pending.resolve(response(200, { success: false, log: ["<new partial failure>"], outcomes: [] }));
    else pending.reject(new Error("synthetic network failure"));
    await mutation;
    assert.equal(run("state.ddnsUpdateResult.success"), false);
    assert.equal(run("state.ddnsUpdating"), false);
    run("navigate('dashboard'); renderDashboardCards()");
    assert.match(section.innerHTML, /DDNS update failed or partially completed/);
    assert.doesNotMatch(section.innerHTML, /old success/);
    assert.deepEqual(toasts.map((toast) => toast.kind), ["error"]);
  });
}

for (const rotate of ["logout", "login", "password"]) {
  test(`DDNS late outcome is discarded and updating clears after ${rotate}`, async () => {
    const { context, run, update, toasts } = ddnsApp();
    const pending = deferred();
    context.fetch = (url) => url === "/api/ddns/update" ? pending.promise : Promise.resolve(response(200, { domains: [], configured: true }));
    run("state.ddnsUpdateResult = {success:true,log:['old session success'],outcomes:[]}");
    const mutation = update.click();
    await run(authCall(rotate));
    const clearedAtRotation = run("!state.ddnsUpdating && state.ddnsUpdateResult === null");
    pending.resolve(response(200, { success: false, log: ["obsolete session outcome"], outcomes: [] }));
    await mutation;
    assert.equal(clearedAtRotation, true);
    assert.equal(run("state.ddnsUpdateResult"), null);
    assert.deepEqual(toasts, []);
  });
}

for (const oldResponse of ["success", "failure", "unauthorized"]) {
  test(`obsolete DDNS ${oldResponse} completion cannot end a new session's update`, async () => {
    const { context, run, update } = ddnsApp();
    const old = deferred(), current = deferred();
    let requests = 0;
    context.fetch = (url) => url === "/api/ddns/update"
      ? (++requests === 1 ? old.promise : current.promise)
      : Promise.resolve(response(200, { domains: [], configured: true }));
    const first = update.click();
    await run(authCall("login"));
    run("navigate('dashboard'); renderDashboardCards()");
    const second = update.click();
    if (oldResponse === "success") old.resolve(response(200, { success: true, log: ["obsolete success"], outcomes: [] }));
    else if (oldResponse === "unauthorized") old.resolve(response(401, { error: "obsolete session" }));
    else old.reject(new Error("obsolete failure"));
    await first;
    const loadingAfterOldResponse = run("state.ddnsUpdating");
    current.resolve(response(200, { success: false, log: ["current failure"], outcomes: [] }));
    await second;
    assert.equal(requests, 2);
    assert.equal(run("state.authed"), true);
    assert.equal(loadingAfterOldResponse, true);
    assert.equal(run("state.ddnsUpdating"), false);
    assert.equal(run("state.ddnsUpdateResult.log[0]"), "current failure");
  });
}

test("current DDNS unauthorized response clears the expired session's outcome and loading", async () => {
  const { context, run, update, toasts } = ddnsApp();
  context.fetch = async () => response(401, { error: "expired session" });
  run("state.ddnsUpdateResult = {success:true,log:['old success'],outcomes:[]}");
  await update.click();
  assert.equal(run("state.authed"), false);
  assert.equal(run("state.ddnsUpdating"), false);
  assert.equal(run("state.ddnsUpdateResult"), null);
  assert.deepEqual(toasts, []);
});

test("phones force cards without replacing the saved desktop view", () => {
  const { run } = app();
  run("state.view = 'list'; viewMedia.matches = true");
  assert.equal(run("currentView()"), "card");
  assert.equal(run("state.view"), "list");
  assert.doesNotMatch(run("viewControls()"), /data-view="list"/);
  run("viewMedia.matches = false");
  assert.equal(run("currentView()"), "list");
  assert.match(run("viewControls()"), /data-view="card"/);
});

for (const view of ["list", "card"]) {
  test(`record ${view} view renders escaped content and preserves action controls`, () => {
    const { nodes, run } = app();
    const wrap = { innerHTML: "", querySelectorAll: () => [] };
    nodes.set("table-wrap", wrap);
    run(`state.view = '${view}'; state.recordsZoneId = state.zoneId; state.records = [{id:'synthetic', type:'TXT', name:'review.example.com', content:'<img src=x>', ttl:300, tags:['<tag>'], comment:'<comment>'}]; renderPagination = () => {}; actualRenderRecordsTable()`);
    assert.match(wrap.innerHTML, view === "card" ? /class="record-cards"/ : /<table class="data">/);
    assert.match(wrap.innerHTML, /&lt;img src=x&gt;/);
    assert.match(wrap.innerHTML, /&lt;comment&gt;/);
    assert.match(wrap.innerHTML, /data-edit="synthetic"/);
    assert.match(wrap.innerHTML, /data-delete="synthetic"/);
    assert.match(wrap.innerHTML, /data-select="synthetic"/);
    assert.doesNotMatch(wrap.innerHTML, /<img src=x>/);
  });
}

test("phone DDNS cards retain status, addresses and update controls", () => {
  const { run, section } = ddnsApp();
  run("viewMedia.matches = true; state.ddns.domains = [{domain:'example.com', record_type:'A', detected_ip:'192.0.2.1', dns_ips:['192.0.2.2'], error:'<provider error>'}]; renderDashboardCards()");
  assert.match(section.innerHTML, /class="ddns-cards"/);
  assert.match(section.innerHTML, /192\.0\.2\.1/);
  assert.match(section.innerHTML, /192\.0\.2\.2/);
  assert.match(section.innerHTML, /&lt;provider error&gt;/);
  assert.match(section.innerHTML, /id="ddns-update"/);
  assert.doesNotMatch(section.innerHTML, /<table class="data">/);
});

test("card selection, editing and deletion use the same record identity", () => {
  const { context, nodes, run } = app();
  const controls = Object.fromEntries(["select", "edit", "delete"].map((action) => [action, {
    dataset: { [action]: "synthetic" }, addEventListener(_, callback) { this.click = callback; },
    focus() { context.document.activeElement = this; },
  }]));
  nodes.set("table-wrap", { set innerHTML(_) { context.document.activeElement = null; }, querySelectorAll: (selector) => {
    const action = selector.match(/^\[data-(select|edit|delete)\]$/)?.[1];
    return action ? [controls[action]] : [];
  } });
  const edited = [];
  const deleted = [];
  context.editRecord = (record) => edited.push(record.id);
  context.deleteRecord = (ids) => deleted.push(ids);
  run("state.view = 'card'; state.recordsZoneId = state.zoneId; state.records = [{id:'synthetic', type:'A', name:'review.example.com', content:'192.0.2.1', ttl:300}]; renderPagination = () => {}; openRecordModal = editRecord; openBulkDeleteModal = deleteRecord; renderRecordsTable = actualRenderRecordsTable; renderRecordsTable()");
  context.document.activeElement = controls.select;
  controls.select.click();
  assert.equal(run("state.selection.has('synthetic')"), true);
  assert.equal(context.document.activeElement, controls.select);
  controls.select.click();
  assert.equal(run("state.selection.size"), 0);
  run("state.selection.add('checked-elsewhere')");
  controls.edit.click();
  controls.delete.click();
  assert.deepEqual(edited, ["synthetic"]);
  assert.equal(JSON.stringify(deleted), '[["synthetic"]]');
  assert.equal(run("JSON.stringify([...state.selection])"), '["checked-elsewhere"]');
});

test("a row delete sends only that record, and the checkboxes survive a failed delete", async () => {
  const { context, run, modal } = securityApp();
  let sent;
  context.fetch = async (url, init) => {
    sent = JSON.parse(init.body);
    return response(502, { error: "synthetic upstream failure" });
  };
  run("state.selection = new Set(['checked-a', 'checked-b']); openBulkDeleteModal(['row'])");
  await modal().querySelector("#d-confirm").click();
  assert.deepEqual(sent, { action: "delete", ids: ["row"] });
  assert.equal(run("JSON.stringify([...state.selection])"), '["checked-a","checked-b"]');
});

test("saving a preference survives blocked storage", () => {
  const blocked = { getItem: () => null, setItem() { throw new Error("synthetic QuotaExceededError"); } };
  const { run } = app({ localStorage: blocked });
  run("render = () => {}; refreshRecords = () => {}");
  assert.doesNotThrow(() => run("writeStored('cfddns.zone', 'zone-b')"));
  assert.doesNotThrow(() => run("setTheme('dark')"));
  assert.equal((appSource.match(/localStorage\.setItem\(/g) || []).length, 1, "only writeStored writes to storage");
});

test("the toolbar delete button deletes the checked records", () => {
  const { context, nodes, run } = app();
  const controls = new Map();
  context.control = (id) => {
    if (!controls.has(id)) controls.set(id, { addEventListener(_, callback) { this.click = callback; }, setAttribute() {}, insertBefore() {}, children: [null, null] });
    return controls.get(id);
  };
  const dialogs = [];
  context.captureModal = (html) => { dialogs.push(html); return { querySelector: () => ({ addEventListener() {} }) }; };
  nodes.set("page", { innerHTML: "" });
  run("state.zones = [{id:'zone-a',name:'example.com'}]; state.recordsZoneId = 'zone-a'; mselect = () => ({}); el = (id) => id === 'page' ? document.getElementById(id) : control(id); openModal = captureModal; renderRecords(); state.selection = new Set(['a', 'b'])");
  controls.get("bulk-delete").click({ type: "click" });
  assert.equal(dialogs.length, 1);
  assert.match(dialogs[0], /Delete 2 records\?/);
});

for (const action of ["delete", "update"]) {
  for (const outcome of ["partial", "total"]) {
    test(`bulk ${action} with a ${outcome} failure shows an error toast`, async () => {
      const { context, run, modal } = securityApp();
      const toasts = [];
      context.notify = (message, kind) => toasts.push({ message, kind });
      context.fetch = async () => response(200, outcome === "total"
        ? { results: [{ id: "a", ok: false, error: "synthetic denied" }, { id: "b", ok: false, error: "synthetic denied" }], succeeded: 0, failed: 2 }
        : { results: [{ id: "a", ok: true }, { id: "b", ok: false, error: "synthetic denied" }], succeeded: 1, failed: 1 });
      run("toast = notify; state.records = [{id:'a',type:'A',name:'a.example.com'},{id:'b',type:'A',name:'b.example.com'}]; state.selection = new Set(['a', 'b'])");
      if (action === "delete") {
        run("openBulkDeleteModal()");
        await modal().querySelector("#d-confirm").click();
      } else {
        const selects = fakeSelects(context, run);
        run("openBulkEditModal()");
        selects[0].pick("300");
        await modal().querySelector("#b-apply").click();
      }
      assert.equal(toasts.length, 1);
      assert.equal(toasts[0].kind, "error");
      assert.match(toasts[0].message, /synthetic denied/);
      const verb = action === "delete" ? "deleted" : "updated";
      assert.match(toasts[0].message, outcome === "total" ? new RegExp(`No records were ${verb}`) : /1 failed/);
    });
  }
}

test("bulk edit locks TTL to Auto while Proxied is chosen and restores it afterwards", async () => {
  const { context, run, modal } = securityApp();
  const selects = fakeSelects(context, run);
  let sent;
  context.fetch = async (url, init) => {
    sent = JSON.parse(init.body);
    return response(200, { results: [{ id: "a", ok: true }], succeeded: 1, failed: 0 });
  };
  run("state.records = [{id:'a',type:'A',name:'a.example.com',proxied:false}]; state.selection = new Set(['a']); openBulkEditModal()");
  const bulk = modal();
  const [ttl, proxy] = selects;
  const hint = bulk.querySelector("#b-ttl-hint");
  ttl.pick("300");
  proxy.pick("true");
  assert.equal(ttl.value, "1");
  assert.equal(ttl.disabled, true);
  assert.equal(hint.classList.contains("u-hidden"), false);
  proxy.pick("");
  assert.equal(ttl.value, "300");
  assert.equal(ttl.disabled, false);
  assert.equal(hint.classList.contains("u-hidden"), true);
  proxy.pick("true");
  await bulk.querySelector("#b-apply").click();
  assert.deepEqual(sent.patch, { ttl: 1, proxied: true });
});

for (const ttl of [30, 14400]) {
  test(`editing a record with the unlisted TTL ${ttl} keeps a labelled TTL option`, () => {
    const { context, run } = securityApp();
    const selects = fakeSelects(context, run);
    context.record = { id: "a", type: "A", name: "a.example.com", content: "192.0.2.1", ttl, proxied: false };
    run("state.zones = [{id:'zone-a',name:'example.com'}]; openRecordModal(record)");
    const select = selects.find((candidate) => candidate.opts.id === "f-ttl-slot");
    const option = select.opts.options.find((candidate) => candidate.value === String(ttl));
    assert.ok(option);
    assert.equal(option.label, run(`fmtTtl(${ttl})`));
    assert.equal(select.value, String(ttl));
    const values = [...select.opts.options].map((candidate) => Number(candidate.value));
    assert.deepEqual(values, [...values].sort((a, b) => a - b));
  });
}

test("list view selection and sorting use focusable native controls", () => {
  const { nodes, run } = app();
  const wrap = { innerHTML: "", querySelectorAll: () => [] };
  nodes.set("table-wrap", wrap);
  run("state.view = 'list'; state.recordsZoneId = state.zoneId; state.records = [{id:'synthetic', type:'A', name:'review.example.com', content:'192.0.2.1', ttl:300}]; renderPagination = () => {}; actualRenderRecordsTable()");
  assert.doesNotMatch(wrap.innerHTML, /<span class="checkbox/);
  assert.match(wrap.innerHTML, /<input type="checkbox" class="checkbox" id="select-all" aria-label="Select all on this page">/);
  assert.match(wrap.innerHTML, /<input type="checkbox" class="checkbox" data-select="synthetic" aria-label="Select review\.example\.com">/);
  assert.match(wrap.innerHTML, /<th class="sortable" aria-sort="ascending"><button type="button" class="sort-btn" data-sort="name">/);
  assert.match(wrap.innerHTML, /<th class="sortable"><button type="button" class="sort-btn" data-sort="type">/);
  assert.doesNotMatch(wrap.innerHTML, /<th[^>]*data-sort/);
});

test("sorting keeps focus on the re-rendered header button", () => {
  const { context, nodes, run } = app();
  const sortButton = { dataset: { sort: "type" }, addEventListener(_, callback) { this.click = callback; } };
  const replacement = { focus() { context.document.activeElement = this; } };
  nodes.set("table-wrap", {
    set innerHTML(_) { context.document.activeElement = null; },
    querySelectorAll: (selector) => selector === "[data-sort]" ? [sortButton] : [],
    querySelector: (selector) => selector === '[data-sort="type"]' ? replacement : null,
  });
  run("state.recordsZoneId = state.zoneId; state.records = [{id:'a', type:'A', name:'a.example.com', content:'192.0.2.1', ttl:300}]; renderPagination = () => {}; renderRecordsTable = actualRenderRecordsTable; renderRecordsTable()");
  context.document.activeElement = sortButton;
  sortButton.click();
  assert.equal(run("state.sort.key"), "type");
  assert.equal(context.document.activeElement, replacement);
});

test("corrupted saved preferences fall back to defaults instead of stopping the app", () => {
  const saved = { "cfddns.columns": "{not json", "cfddns.perPage": "abc", "cfddns.theme": "neon", "cfddns.lang": "xx", "cfddns.view": "grid" };
  const { run } = app({ localStorage: { getItem: (key) => saved[key] ?? null, setItem() {} } });
  assert.equal(run("JSON.stringify(state.columns)"), run("JSON.stringify(DEFAULT_COLUMNS)"));
  assert.equal(run("state.perPage"), 20);
  assert.equal(run("state.view"), "list");
  assert.equal(run("currentTheme()"), "system");
  assert.equal(run("lang"), "en");
});

test("saved columns keep only known boolean keys and page size only offered values", () => {
  const saved = { "cfddns.columns": '{"name":false,"created":true,"type":"yes","bogus":true}', "cfddns.perPage": "50" };
  const { run } = app({ localStorage: { getItem: (key) => saved[key] ?? null, setItem() {} } });
  assert.equal(run("state.columns.name"), false);
  assert.equal(run("state.columns.created"), true);
  assert.equal(run("state.columns.type"), true);
  assert.equal(run("Object.hasOwn(state.columns, 'bogus')"), false);
  assert.equal(run("state.perPage"), 50);
  for (const size of ["7", "1e2", "-20", "null"]) {
    const other = app({ localStorage: { getItem: (key) => key === "cfddns.perPage" ? size : null, setItem() {} } });
    assert.equal(other.run("state.perPage"), 20, size);
  }
});

test("unavailable storage does not stop the app from loading", () => {
  const { run } = app({ localStorage: { getItem() { throw new Error("synthetic SecurityError"); }, setItem() {} } });
  assert.equal(run("state.perPage"), 20);
  assert.equal(run("currentTheme()"), "system");
});

test("translation values containing replacement patterns stay literal", () => {
  const { context, run } = app();
  context.fileName = "a$&b$'c$`d$1.zone";
  assert.equal(run("t('modal.import.file_selected', { name: fileName, size: '1 B' })"), "Selected: a$&b$'c$`d$1.zone (1 B)");
  assert.equal(run("t('{n} of {n}', { n: 2 })"), "2 of 2");
  context.braced = "{size}.zone";
  assert.equal(run("t('modal.import.file_selected', { name: braced, size: '1 B' })"), "Selected: {size}.zone (1 B)");
  assert.equal(run("t('{missing} stays', {})"), "{missing} stays");
});

test("only .html translation keys carry markup and tHtml escapes everything else", () => {
  const { context, run } = app();
  for (const [key, value] of JSON.parse(run("JSON.stringify(Object.entries(I18N.en))"))) {
    assert.equal(value.includes("<"), key.endsWith(".html"), key);
  }
  assert.match(run("tHtml('modal.import.drop.html')"), /<strong>/);
  assert.equal(run("tHtml('missing <b> key')"), "missing &lt;b&gt; key");
  context.markup = "<img src=x>";
  assert.equal(run("tHtml('{name}.html', { name: markup })"), "&lt;img src=x&gt;.html");
  // Markup keys may only be read through tHtml.
  assert.doesNotMatch(appSource, /\bt\(\s*["'`][^"'`]*\.html["'`]/);
});

test("numeric fields reject empty and non-decimal values", () => {
  const { run } = app();
  for (const value of ["", " ", "1e3", "0x10", "-1", "1.5", "65536"]) assert.equal(run(`V.uint(${JSON.stringify(value)}, 0, 65535)`), false, value);
  for (const value of ["0", "80", " 443 ", "65535"]) assert.equal(run(`V.uint(${JSON.stringify(value)}, 0, 65535)`), true, value);
});

test("IPv6 validation follows the URL parser", () => {
  const { run } = app();
  for (const value of [":::", "1::2::3", "12345::", "::1]/x", "2001:db8::g", "192.0.2.1", "fe80::1%eth0", ""]) {
    assert.equal(run(`V.ipv6(${JSON.stringify(value)})`), false, value);
  }
  for (const value of ["::1", "2001:db8::1", " 2001:db8::1 ", "::ffff:192.0.2.1", "2001:DB8:0:0:0:0:0:1"]) {
    assert.equal(run(`V.ipv6(${JSON.stringify(value)})`), true, value);
  }
});

// Builds input stand-ins from the real form markup so validation sees the same attributes.
function formModal(html, values) {
  const inputs = [...html.matchAll(/<input\b([^>]*)>/g)].map(([, attrs]) => {
    const attr = (name) => attrs.match(new RegExp(`(?:^|\\s)${name}="([^"]*)"`))?.[1];
    const id = attr("id");
    return {
      id, type: attr("type") || "text", min: attr("min") || "", max: attr("max") || "",
      required: /(?:^|\s)required(?:\s|$|=)/.test(attrs), dataset: attr("data-v") ? { v: attr("data-v") } : {},
      value: values[id] ?? "", classList: classes(),
    };
  });
  const errors = new Map();
  const matches = (input, selector) => selector.split(",").some((part) => {
    const simple = part.trim().replace(/^#type-fields\s+/, "");
    if (simple === "input") return true;
    if (simple === "[data-v]") return !!input.dataset.v;
    if (simple === "input[type=number]") return input.type === "number";
    if (simple === "input[required]") return input.required;
    throw new Error(`unsupported selector in test stand-in: ${simple}`);
  });
  return {
    inputs, errors, dataset: {},
    querySelectorAll: (selector) => inputs.filter((input) => matches(input, selector)),
    querySelector: (selector) => {
      const byId = inputs.find((input) => `#${input.id}` === selector);
      if (byId) return byId;
      const error = selector.match(/^\[data-err="([^"]+)"\]$/)?.[1];
      if (error) {
        if (!errors.has(error)) errors.set(error, { textContent: "", classList: classes() });
        return errors.get(error);
      }
      if (selector.endsWith("-mode")) return { mget: () => "keep" };
      return { value: "", checked: false };
    },
  };
}

const requiredCases = {
  TXT: [{ "f-content": "" }, "f-content", "v=spf1 -all"],
  CAA: [{ "f-caa-flags": "0", "f-caa-value": "" }, "f-caa-value", "letsencrypt.org"],
  SVCB: [{ "f-svc-priority": "1", "f-svc-target": "" }, "f-svc-target", "."],
  HTTPS: [{ "f-svc-priority": "1", "f-svc-target": "" }, "f-svc-target", "example.com"],
  SRV: [{ "f-srv-priority": "0", "f-srv-weight": "5", "f-srv-port": "", "f-srv-target": "mc.example.com" }, "f-srv-port", "25565"],
  MX: [{ "f-content": "mail.example.com", "f-priority": "" }, "f-priority", "10"],
};

for (const [type, [values, empty, filled]] of Object.entries(requiredCases)) {
  test(`${type} records cannot be saved with an empty required field`, () => {
    const { context, run } = app();
    run("toast = () => {}");
    context.modal = formModal(run(`typeSpecificFields('${type}', null)`), values);
    const save = () => run(`buildPayload(modal, '${type}', 'example.com', {name:'review.example.com'}, {mget:()=>'1'})`);
    assert.equal(save(), null);
    const error = context.modal.errors.get(empty);
    assert.equal(error.textContent, "This field is required.");
    assert.equal(error.classList.contains("visible"), true);
    context.modal.inputs.find((input) => input.id === empty).value = filled;
    assert.notEqual(save(), null);
  });
}

test("session lifetimes under an hour are not shown as 0 h", () => {
  const { run } = app();
  assert.equal(run("fmtDuration(86400)"), "24 h");
  assert.equal(run("fmtDuration(300)"), "5 min");
  assert.equal(run("fmtDuration(5400)"), "90 min");
  assert.equal(run("fmtDuration(45)"), "45 s");
  assert.doesNotMatch(appSource, /sessionTtl \/ 3600/);
});

test("validators accept what the server accepts", () => {
  const { run } = app();
  const check = (fn, value) => run(`V.${fn}(${JSON.stringify(value)})`);
  // shortName turns "_sip._tcp.example.com" into "_sip._tcp", so the short form must pass.
  for (const name of ["_sip._tcp", "_sip._tcp.voice", "_xmpp._TCP", "_sips._tls"]) assert.equal(check("srvName", name), true, name);
  for (const name of ["@", "sip._tcp", "_sip._sctp", "_sip"]) assert.equal(check("srvName", name), false, name);
  for (const ip of ["192.0.2.1", "0.0.0.0", "10.0.0.255"]) assert.equal(check("ipv4", ip), true, ip);
  for (const ip of ["010.0.0.1", "192.0.2.01", "256.0.0.1"]) assert.equal(check("ipv4", ip), false, ip);
  for (const host of ["example.xn--p1ai", "mail.example.com", "localhost"]) assert.equal(check("domain", host), true, host);
  for (const host of ["example.-com", "example.com-"]) assert.equal(check("domain", host), false, host);
});

test("a number field holding unparseable text says so instead of 'required'", () => {
  const { run, context } = app();
  context.field = { type: "number", value: "", required: true, min: "0", max: "65535", dataset: {}, validity: { badInput: true } };
  assert.equal(run("fieldError(field)"), "Enter a number between 0 and 65535.");
  context.field.validity.badInput = false;
  assert.equal(run("fieldError(field)"), "This field is required.");
});

test("an invalid SRV name explains the SRV naming pattern", () => {
  const { context, run } = app();
  const error = { textContent: "", classList: classes() };
  const name = { value: "game", classList: classes() };
  context.modal = { dataset: {}, querySelectorAll: () => [], querySelector: (selector) => ({ "#f-name": name, '[data-err="f-name"]': error })[selector] || null };
  run("toast = () => {}");
  assert.equal(run("buildPayload(modal, 'SRV', 'example.com', null, {mget:()=>'1'})"), null);
  assert.equal(error.textContent, "SRV names must look like _service._tcp.name");
  assert.equal(error.classList.contains("visible"), true);
  name.value = "bad name";
  assert.equal(run("buildPayload(modal, 'A', 'example.com', null, {mget:()=>'1'})"), null);
  assert.equal(error.textContent, "Letters, digits, hyphens, dots, underscores and * only.");
});

test("auth call sites declare how they change the session", () => {
  const calls = [...appSource.matchAll(/api\("\/api\/auth\/([^"?]+)"([^;]*);/g)];
  const seen = new Set();
  for (const [, endpoint, options] of calls) {
    seen.add(endpoint);
    const flags = {
      rotatesSession: /rotatesSession:\s*true/.test(options),
      clearsRecoveryCodes: /clearsRecoveryCodes:\s*true/.test(options),
    };
    assert.deepEqual(flags, { rotatesSession: false, clearsRecoveryCodes: false, ...SESSION_FLAGS[endpoint] }, endpoint);
  }
  for (const endpoint of Object.keys(SESSION_FLAGS)) assert.ok(seen.has(endpoint), endpoint);
  assert.doesNotMatch(appSource.slice(appSource.indexOf("async function api("), appSource.indexOf("/* ================= Modern select")), /"\/api\/auth\/(?:setup|login|logout|password|2fa)/);
});

test("logout invalidates and renders once", async () => {
  const { context, nodes, run } = securityApp();
  for (const id of ["mobile-menu-btn", "mobile-nav-backdrop", "collapse-btn", "logout-btn"]) {
    nodes.set(id, { addEventListener(_, callback) { this.click = callback; } });
  }
  nodes.set("app", { innerHTML: "", querySelector: () => ({}), querySelectorAll: () => [] });
  run("state.configured = true; renderTopbarActions = () => {}; renderSettings = () => {}; actualRender(); var renders = 0; render = () => { renders++; }");
  context.fetch = async () => response(200);
  const generation = run("pageGeneration");
  await nodes.get("logout-btn").click();
  assert.equal(run("renders"), 1);
  assert.equal(run("pageGeneration") - generation, 1);
  assert.equal(run("state.authed"), false);
});

test("user-visible strings come from the translation table", () => {
  for (const literal of [/title="Refresh"/, /"Custom color"/, /textContent = "Default"/, /"File too large/, /"Authentication changed/, /"network error/]) {
    assert.doesNotMatch(appSource.slice(appSource.indexOf("/* ================= Icons")), literal);
  }
});

test("view switching persists preference and focuses the replacement control", () => {
  const { context, run } = app();
  const button = { dataset: { view: "card" }, addEventListener(_, callback) { this.click = callback; } };
  const replacement = { focus() { context.document.activeElement = this; } };
  const writes = [];
  context.document.querySelectorAll = () => [button];
  context.document.querySelector = () => replacement;
  context.redraw = () => { context.document.activeElement = null; };
  context.localStorage.setItem = (...args) => writes.push(args);
  run("wireViewControls(redraw)");
  context.document.activeElement = button;
  button.click();
  assert.equal(run("state.view"), "card");
  assert.deepEqual(writes, [["cfddns.view", "card"]]);
  assert.equal(context.document.activeElement, replacement);
});

test("the security table separator does not add asymmetric status-row spacing", () => {
  const css = fs.readFileSync(path.join(__dirname, "style.css"), "utf8");
  assert.match(css, /#security-body\s*>\s*\.kv-table\s*\+\s*\.settings-sep\s*\{\s*margin-top:\s*0;/);
});

test("enabled security status keeps its badge centered beside wrapping backup text", () => {
  const { context, nodes, run } = productionApp();
  const body = { innerHTML: "" };
  nodes.set("security-body", body);
  nodes.set("pw-change-btn", context.document.createElement("button"));
  run("state.totpEnabled = true; state.backupCodesRemaining = 8; renderSecurityBody()");
  assert.match(body.innerHTML, /class="security-factor-status">\s*<span class="badge green">Enabled<\/span>\s*<span class="cell-muted">8 backup codes remaining<\/span>\s*<\/div>/);
  const css = fs.readFileSync(path.join(__dirname, "style.css"), "utf8");
  assert.match(css, /\.security-factor-status\s*\{[^}]*display:\s*flex;[^}]*align-items:\s*center;/);
});

test("cards share list filtering, sorting and pagination", () => {
  const { nodes, run } = app();
  const wrap = { innerHTML: "", querySelectorAll: () => [] };
  nodes.set("table-wrap", wrap);
  run("state.view = 'card'; state.recordsZoneId = state.zoneId; state.perPage = 1; state.typeFilter = 'A'; state.search = 'review'; state.sort = {key:'ttl',dir:-1}; state.records = [{id:'low',type:'A',name:'review-low.example.com',ttl:60},{id:'high',type:'A',name:'review-high.example.com',ttl:300},{id:'filtered',type:'TXT',name:'review.example.com',ttl:600}]; renderPagination = () => {}; actualRenderRecordsTable()");
  assert.match(wrap.innerHTML, /data-row="high"/);
  assert.doesNotMatch(wrap.innerHTML, /data-row="low"|data-row="filtered"/);
  run("state.page = 2; actualRenderRecordsTable()");
  assert.match(wrap.innerHTML, /data-row="low"/);
  assert.doesNotMatch(wrap.innerHTML, /data-row="high"/);
});

test("obsolete zone boot cannot strand a new session's records load", async () => {
  const { context, run } = app();
  const oldZones = deferred(), records = deferred();
  context.fetch = (url) => url === "/api/zones" ? oldZones.promise : url.includes("/records") ? records.promise : Promise.resolve(response(200));
  const oldBoot = run("loadZones()");
  await run(authCall("login"));
  run("state.zoneId = 'zone-b'; state.zones = [{id:'zone-b',name:'new.example.com'}]");
  const loading = run("loadRecords()");
  oldZones.resolve(response(200, [{ id: "zone-a", name: "example.com" }]));
  await oldBoot;
  records.resolve(response(200, { records: [{ id: "current" }], total: 1 }));
  await loading;
  assert.equal(run("state.zoneId"), "zone-b");
  assert.equal(run("state.records[0]?.id"), "current");
  assert.equal(run("state.recordsLoading"), false);
});

test("old authentication metadata cannot overwrite a newer boot or dashboard", async () => {
  const { context, run } = app();
  const me = deferred();
  let renders = 0;
  context.redraw = () => { renders++; };
  context.fetch = (url) => url === "/api/auth/me" ? me.promise : Promise.resolve(response(200, []));
  run("render = redraw; toast = () => {}");
  const boot = run("bootAuthed()");
  await run(authCall("login"));
  run("state.sessionTtl = 7200; state.totpEnabled = true; state.ddns = {configured:true, domains:[]}");
  me.resolve(response(200, { authenticated: true, session_ttl: 300, totp_enabled: false }));
  await boot;
  assert.equal(run("state.sessionTtl"), 7200);
  assert.equal(run("state.totpEnabled"), true);
  assert.equal(run("state.ddns?.configured"), true);
  assert.equal(renders, 0);
});

for (const boundary of ["expiry", "login"]) {
  test(`${boundary} clears records cache and errors for a fresh authenticated load`, async () => {
    const { context, run } = securityApp();
    run("state.records = [{id:'old'}]; state.recordsZoneId = state.zoneId; state.recordsAttemptedZoneId = state.zoneId; state.recordsError = 'old error'; state.ddns = {error:'old error'}");
    context.fetch = async () => response(boundary === "expiry" ? 401 : 200);
    if (boundary === "expiry") await assert.rejects(run("api('/api/ddns/update', {method:'POST',json:{}})"));
    else await run(authCall("login"));
    assert.equal(run("state.records.length"), 0);
    assert.equal(run("state.recordsZoneId"), null);
    assert.equal(run("state.recordsAttemptedZoneId"), null);
    assert.equal(run("state.recordsError"), null);
    assert.equal(run("state.ddns"), null);
  });
}

function productionApp() {
  const nodes = new Map();
  class Element {
    constructor(id = "") {
      this.id = id;
      this.children = [];
      this.handlers = {};
      this.dataset = {};
      this.value = "synthetic-password";
      this.disabled = false;
      this.classList = { remove() {}, add() {}, toggle() {}, contains() { return false; } };
    }
    set innerHTML(html) {
      this.html = html;
      for (const child of this.children) {
        child.innerHTML = "";
        if (nodes.get(child.id) === child) nodes.delete(child.id);
      }
      this.children = [];
      for (const match of html.matchAll(/<([a-z][a-z0-9-]*)\b([^>]*)>/g)) {
        const id = match[2].match(/\bid="([^"]+)"/);
        if (!id) continue;
        const child = new Element(id[1]);
        child.disabled = /\bdisabled\b/.test(match[2]);
        child.parentElement = this;
        this.children.push(child);
        nodes.set(child.id, child);
      }
    }
    get innerHTML() { return this.html || ""; }
    addEventListener(event, handler) { this.handlers[event] = handler; }
    setAttribute() {}
    querySelector(selector) { return selector === ".main" ? new Element() : null; }
    querySelectorAll() { return []; }
    appendChild(child) { this.children.push(child); child.parentElement = this; }
    remove() {}
    async click() { if (!this.disabled) return this.handlers.click?.({ preventDefault() {} }); }
    async submit() { return this.handlers.submit?.({ preventDefault() {} }); }
  }
  for (const id of ["app", "modal-root", "toast-root"]) nodes.set(id, new Element(id));
  const context = vm.createContext({
    document: {
      documentElement: { classList: { toggle() {} }, style: { setProperty() {} } },
      getElementById: (id) => nodes.get(id) || null,
      querySelectorAll: () => [], querySelector: () => null,
      addEventListener() {}, removeEventListener() {}, createElement: () => new Element(),
    },
    localStorage: { getItem: () => null, setItem() {} },
    location: { hash: "#/dashboard" },
    window: { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} },
    console,
    setTimeout: (...args) => { const timer = setTimeout(...args); timer.unref(); return timer; },
    clearTimeout,
    URL,
  });
  loadApp(context);
  return { context, nodes, run: (code) => vm.runInContext(code, context) };
}

test("production expiry, login and fresh status enable another Update Now without reload", async () => {
  const { context, nodes, run } = productionApp();
  let expired = true, updates = 0, statuses = 0;
  const requests = [];
  context.fetch = async (url, init) => {
    requests.push({ url, method: init.method });
    if (url === "/api/ddns/update") {
      updates++;
      return expired ? response(401, { error: "expired" }) : response(200, { success: true, log: [], outcomes: [] });
    }
    if (url === "/api/auth/login") return response(200);
    if (url === "/api/auth/me") return response(200, { authenticated: true, session_ttl: 3600 });
    if (url === "/api/zones") return response(200, [{ id: "zone-a", name: "example.com" }]);
    if (url === "/api/ddns/status") {
      statuses++;
      return response(200, { configured: true, domains: [], manual_updates_enabled: true });
    }
    throw new Error(`unexpected path: ${url}`);
  };
  run("state.authed = true; state.zones = [{id:'zone-a',name:'example.com'}]; state.zoneId = 'zone-a'; state.ddns = {configured:true,domains:[],manual_updates_enabled:true}; render()");
  assert.equal(nodes.get("ddns-update").disabled, false);
  await nodes.get("ddns-update").click();
  assert.equal(run("state.authed"), false);
  assert.equal(run("state.ddnsUpdating || state.ddnsLoading"), false);
  assert.ok(nodes.get("login-form"));
  assert.equal(nodes.has("ddns-update"), false);
  expired = false;
  await nodes.get("login-form").submit();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(requests.slice(1).map((request) => request.url), ["/api/auth/login", "/api/auth/me", "/api/zones", "/api/ddns/status"]);
  assert.equal(statuses, 1);
  assert.equal(run("state.authed"), true);
  assert.equal(nodes.get("ddns-update").disabled, false);
  await nodes.get("ddns-update").click();
  assert.equal(updates, 2);
  assert.equal(statuses, 2);
  assert.equal(run("state.ddnsUpdating || state.ddnsLoading"), false);
  assert.equal(nodes.get("ddns-update").disabled, false);
  assert.equal(run("state.ddnsUpdateResult.success"), true);
  assert.equal(requests.filter((request) => request.url === "/api/ddns/update").every((request) => request.method === "POST"), true);
});

test("an obsolete boot's final continuation preserves a newer dashboard snapshot", async () => {
  const { context, run } = productionApp();
  const oldZones = deferred();
  let listings = 0;
  context.fetch = async (url) => {
    if (url === "/api/zones") return ++listings === 1 ? oldZones.promise : response(200, [{ id: "zone-b", name: "new.example.com" }]);
    if (url === "/api/ddns/status") return response(200, { configured: true, domains: [], ipv4: "192.0.2.2" });
    return response(200, { authenticated: true });
  };
  run("state.authed = true");
  const oldBoot = run("bootAuthed()");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(listings, 1);
  await run(authCall("login"));
  await run("bootAuthed()");
  await new Promise((resolve) => setImmediate(resolve));
  const latest = run("state.ddns");
  assert.equal(latest.ipv4, "192.0.2.2");
  oldZones.resolve(response(200, [{ id: "zone-a", name: "example.com" }]));
  await oldBoot;
  assert.equal(run("state.zoneId"), "zone-b");
  assert.equal(run("state.ddns"), latest);
  assert.equal(run("state.ddnsLoading"), false);
});

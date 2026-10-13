"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function app() {
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
    localStorage: { getItem: () => null, setItem() {} },
    location: { hash: "#/records" },
    window: { matchMedia: () => ({ matches: false, addEventListener() {} }), addEventListener() {} },
    setTimeout,
    clearTimeout,
    console,
  });
  const source = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");
  vm.runInContext(source.slice(0, source.indexOf("(async function boot()")), context);
  vm.runInContext("state.authed = true; state.zoneId = 'zone-a'; const actualRender = render; const actualRenderDashboardCards = renderDashboardCards; renderRecordsTable = () => {}; renderDashboardCards = () => {};", context);
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
      querySelectorAll: () => [],
      querySelector: (selector) => {
        if (!fields.has(selector)) fields.set(selector, {
          value: selector.includes("code") ? "123456" : "synthetic-password",
          classList: { remove() {}, add() {} },
          addEventListener(event, callback) { this.handlers ||= {}; this.handlers[event] = callback; this.click = callback; },
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
    if (change === "session") await run("api('/api/auth/password', {method:'POST',json:{}})");
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
    await run(`api('/api/auth/${endpoint}', {method:'POST',json:{}})`);
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
    if (boundary === "logout/login") await run("api('/api/auth/logout', {method:'POST'})");
    if (boundary === "expired/login") await assert.rejects(run("api('/api/zones')"));
    await run("api('/api/auth/login', {method:'POST',json:{password:'synthetic-password'}})");
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
  await run("api('/api/auth/logout', {method:'POST'})");
  await run("api('/api/auth/login', {method:'POST',json:{password:'synthetic-password'}})");
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
  await run("api('/api/auth/login', {method:'POST',json:{password:'synthetic-password'}})");
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
    await run(`api('/api/auth/${rotate}', {method:'POST',json:{}})`);
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
    await run("api('/api/auth/login', {method:'POST',json:{}})");
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

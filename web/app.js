/* Cloudflare DDNS Web UI — vanilla JS SPA. No build step, no frameworks. */
"use strict";

/* ================= i18n ================= */

const I18N = {
  en: {
    "app.name": "Cloudflare DDNS",
    "nav.dashboard": "Dashboard",
    "nav.records": "DNS Records",
    "nav.settings": "Settings",
    "nav.collapse": "Collapse",
    "nav.logout": "Log out",
    "login.title": "Sign in",
    "login.subtitle": "Enter your admin password to manage your DNS.",
    "login.password": "Password",
    "login.submit": "Sign in",
    "login.error": "Invalid password. Please try again.",
    "login.wait": "Signing in…",
    "topbar.language": "Language",
    "topbar.refresh": "Refresh",
    "dash.title": "Dashboard",
    "dash.ipv4": "Public IPv4",
    "dash.ipv6": "Public IPv6",
    "dash.zones": "Zones",
    "dash.records": "Records in zone",
    "dash.na": "Not available",
    "dash.ddns.title": "DDNS domains",
    "dash.ddns.desc": "Sync status of the domains configured via the DOMAINS environment variable.",
    "dash.ddns.not_configured": "No DDNS domains configured.",
    "dash.ddns.hint": "Set the DOMAINS environment variable (same as cloudflare-ddns) to enable sync status and on-demand updates.",
    "dash.ddns.update_now": "Update now",
    "dash.ddns.updating": "Updating…",
    "dash.ddns.domain": "Domain",
    "dash.ddns.type": "Type",
    "dash.ddns.detected": "Detected IP",
    "dash.ddns.dns": "DNS record",
    "dash.ddns.status": "Status",
    "dash.ddns.synced": "In sync",
    "dash.ddns.out_of_sync": "Out of sync",
    "dash.ddns.error": "Error",
    "dash.ddns.missing": "No record",
    "records.title": "DNS Records",
    "records.add": "Add record",
    "records.import": "Import",
    "records.export": "Export",
    "records.search": "Search records…",
    "records.all_types": "All types",
    "records.columns": "Columns",
    "records.selected": "{n} selected",
    "records.edit": "Edit",
    "records.delete": "Delete",
    "records.clear": "Clear selection",
    "records.showing": "Showing {from}–{to} of {total}",
    "records.per_page": "Rows per page",
    "records.empty.title": "No records found",
    "records.empty.desc": "No DNS records match your current filters, or this zone has no records yet.",
    "records.loading": "Loading records…",
    "col.type": "Type",
    "col.name": "Name",
    "col.content": "Content",
    "col.proxy": "Proxy status",
    "col.ttl": "TTL",
    "col.tags": "Tags",
    "col.comment": "Comment",
    "col.updated": "Last updated",
    "col.created": "Created",
    "col.actions": "Actions",
    "proxy.proxied": "Proxied",
    "proxy.dns_only": "DNS only",
    "proxy.na": "Not proxiable",
    "ttl.auto": "Auto",
    "modal.add.title": "Add DNS record",
    "modal.edit.title": "Edit DNS record",
    "modal.type": "Type",
    "modal.name": "Name",
    "modal.name.hint": "Use @ for the zone root.",
    "modal.content": "Content",
    "modal.content.A": "IPv4 address",
    "modal.content.AAAA": "IPv6 address",
    "modal.content.CNAME": "Domain",
    "modal.content.TXT": "Content",
    "modal.content.MX": "Mail server",
    "modal.content.NS": "Name server",
    "modal.content.PTR": "Domain",
    "modal.priority": "Priority",
    "modal.srv.priority": "Priority",
    "modal.srv.weight": "Weight",
    "modal.srv.port": "Port",
    "modal.srv.target": "Target",
    "modal.caa.flags": "Flags",
    "modal.caa.tag": "Tag",
    "modal.caa.value": "Value",
    "modal.ttl": "TTL",
    "modal.proxy": "Proxy status",
    "modal.proxy.hint": "Proxy this record through Cloudflare (orange cloud).",
    "modal.tags": "Tags",
    "modal.tags.hint": "Comma-separated, e.g. cf-proxied:true",
    "modal.comment": "Comment",
    "modal.save": "Save",
    "modal.create": "Create",
    "modal.cancel": "Cancel",
    "modal.required": "This field is required.",
    "modal.bulk.title": "Edit {n} records",
    "modal.bulk.keep": "Keep as is",
    "modal.bulk.ttl": "TTL",
    "modal.bulk.proxy": "Proxy status",
    "modal.bulk.proxy.on": "Proxied",
    "modal.bulk.proxy.off": "DNS only",
    "modal.bulk.proxy.blocked": "Proxy cannot be changed: the selection contains record types that are not proxiable (only A, AAAA and CNAME are).",
    "modal.bulk.comment": "Comment",
    "modal.bulk.comment.keep": "Keep existing",
    "modal.bulk.comment.replace": "Replace with",
    "modal.bulk.comment.clear": "Clear comments",
    "modal.bulk.apply": "Apply to {n} records",
    "modal.delete.title": "Delete records",
    "modal.delete.one": "Delete this record?",
    "modal.delete.many": "Delete {n} records? This cannot be undone.",
    "modal.delete.confirm": "Delete",
    "modal.import.title": "Import DNS records",
    "modal.import.desc": "Upload a BIND zone file. Cloudflare parses it natively — comments and cf_tags (e.g. cf-proxied:true) are honoured, exactly like the dashboard import.",
    "modal.import.drop": "Drop your zone file here, or <strong>browse</strong>",
    "modal.import.submit": "Import",
    "modal.import.result": "Imported {added} of {parsed} records.",
    "settings.title": "Settings",
    "settings.lang.title": "Language",
    "settings.lang.desc": "Interface language. More languages are coming soon.",
    "settings.token.title": "Cloudflare API token",
    "settings.token.desc": "The web UI talks to Cloudflare with an API token supplied via the CLOUDFLARE_API_TOKEN environment variable. Create it with the following preset:",
    "settings.token.step1": "Open <strong>My Profile → API Tokens</strong> in the Cloudflare dashboard.",
    "settings.token.step2": "Click <strong>Create Token</strong> and choose the <strong>Edit zone DNS</strong> template.",
    "settings.token.step3": "Keep permissions <code>Zone → DNS → Edit</code> and add <code>Zone → Zone → Read</code>.",
    "settings.token.step4": "Under <strong>Zone Resources</strong> pick <em>Include → Specific zone</em> for least privilege (or <em>All zones</em>).",
    "settings.token.step5": "Create the token and set it as <code>CLOUDFLARE_API_TOKEN</code> (or mount it via <code>CLOUDFLARE_API_TOKEN_FILE</code>).",
    "settings.security.title": "Security",
    "settings.security.desc": "Current security posture of this installation.",
    "settings.security.session": "Session lifetime",
    "settings.security.password": "Admin password",
    "settings.security.password.value": "Set via ADMIN_PASSWORD (PBKDF2-hashed in memory)",
    "settings.security.cookies": "Secure cookies",
    "settings.security.cookies.hint": "Set SECURE_COOKIES=true when serving the UI over HTTPS (recommended on Dokploy).",
    "settings.about.title": "About",
    "settings.about.version": "Version",
    "settings.about.source": "Source code",
    "settings.about.upstream": "Based on the philosophy of",
    "common.yes": "Yes",
    "common.no": "No",
    "common.close": "Close",
    "common.copy": "Click to copy",
    "common.copied": "Copied to clipboard",
    "toast.saved": "Record saved",
    "toast.created": "Record created",
    "toast.deleted": "Record deleted",
    "toast.bulk_delete": "Deleted {ok} records{fail_part}",
    "toast.bulk_update": "Updated {ok} records{fail_part}",
    "toast.fail_suffix": ", {n} failed",
    "toast.error": "Error",
    "toast.exported": "Zone file exported",
    "toast.updated_ddns": "DDNS update finished",
    "confirm": "Confirm",
  },
};

const LANGS = [{ code: "en", name: "English" }];

let lang = localStorage.getItem("cfddns.lang") || "en";
function t(key, vars) {
  let s = (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, v);
  return s;
}

/* ================= Icons ================= */

const I = {
  cloud: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>',
  cloudFill: '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>',
  dashboard: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>',
  dns: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  settings: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>',
  logout: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>',
  search: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>',
  plus: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  edit: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>',
  trash: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  download: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>',
  upload: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/></svg>',
  columns: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 3v18M15 3v18"/></svg>',
  chevronDown: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="m6 9 6 6 6-6"/></svg>',
  chevronLeft: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="m15 18-6-6 6-6"/></svg>',
  chevronRight: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="m9 18 6-6-6-6"/></svg>',
  globe: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  refresh: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>',
  close: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  check: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  collapse: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 3v18"/><path d="m14 9-3 3 3 3"/></svg>',
  menu: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="18" y2="18"/></svg>',
  bolt: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
  file: '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>',
  shield: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>',
};

/* ================= State ================= */

const RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "PTR", "HTTPS", "SVCB"];
const PROXIABLE = ["A", "AAAA", "CNAME"];
const TTL_OPTIONS = [
  [1, "Auto"], [60, "1 min"], [120, "2 min"], [300, "5 min"], [600, "10 min"],
  [1800, "30 min"], [3600, "1 hour"], [7200, "2 hours"], [18000, "5 hours"],
  [43200, "12 hours"], [86400, "1 day"],
];

const DEFAULT_COLUMNS = {
  type: true, name: true, content: true, proxy: true, ttl: true,
  tags: true, comment: true, updated: false, created: false,
};
const COLUMN_ORDER = ["type", "name", "content", "proxy", "ttl", "tags", "comment", "updated", "created"];

const state = {
  authed: false,
  booted: false,
  route: location.hash.replace("#/", "") || "dashboard",
  zones: [],
  zoneId: null,
  records: [],
  recordsTotal: 0,
  recordsZoneId: null,
  recordsLoading: false,
  search: "",
  typeFilter: "",
  sort: { key: "name", dir: 1 },
  page: 1,
  perPage: parseInt(localStorage.getItem("cfddns.perPage") || "20", 10),
  selection: new Set(),
  columns: { ...DEFAULT_COLUMNS, ...JSON.parse(localStorage.getItem("cfddns.columns") || "{}") },
  sidebarCollapsed: localStorage.getItem("cfddns.sidebar") === "collapsed",
  ddns: null,
  ddnsLoading: false,
  sessionTtl: null,
  config: null,
};

/* ================= Helpers ================= */

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function el(id) { return document.getElementById(id); }

function currentZone() { return state.zones.find((z) => z.id === state.zoneId) || null; }

function fmtTtl(ttl) {
  if (ttl === 1 || ttl == null) return t("ttl.auto");
  const opt = TTL_OPTIONS.find(([v]) => v === ttl);
  if (opt) return opt[1];
  if (ttl % 3600 === 0) return `${ttl / 3600} h`;
  if (ttl % 60 === 0) return `${ttl / 60} min`;
  return `${ttl}s`;
}

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(lang === "en" ? "en-US" : lang, {
      year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  } catch { return iso; }
}

function toast(msg, kind = "ok") {
  const root = el("toast-root");
  const div = document.createElement("div");
  div.className = `toast ${kind}`;
  div.textContent = msg;
  root.appendChild(div);
  setTimeout(() => {
    div.classList.add("out");
    setTimeout(() => div.remove(), 350);
  }, 4000);
}

/* ================= API ================= */

async function api(path, opts = {}) {
  const init = {
    method: opts.method || "GET",
    credentials: "same-origin",
    headers: { "X-Requested-With": "fetch" },
  };
  if (opts.json !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.json);
  } else if (opts.raw !== undefined) {
    init.headers["Content-Type"] = "text/plain";
    init.body = opts.raw;
  }
  let resp;
  try {
    resp = await fetch(path, init);
  } catch {
    throw new Error("network error — is the server reachable?");
  }
  if (resp.status === 401 && !path.startsWith("/api/auth/")) {
    state.authed = false;
    render();
    throw new Error("unauthorized");
  }
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
    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
    return data;
  }
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return null;
}

/* ================= Data loading ================= */

async function loadZones() {
  state.zones = await api("/api/zones");
  const preferred = localStorage.getItem("cfddns.zone");
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
  state.recordsLoading = true;
  renderRecordsTable();
  try {
    const data = await api(`/api/zones/${state.zoneId}/records`);
    state.records = data.records || [];
    state.recordsTotal = data.total ?? state.records.length;
    state.recordsZoneId = state.zoneId;
    state.selection.clear();
    state.page = 1;
  } finally {
    state.recordsLoading = false;
  }
}

async function loadDdns() {
  state.ddnsLoading = true;
  renderDashboardCards();
  try {
    state.ddns = await api("/api/ddns/status");
  } catch (e) {
    state.ddns = { error: e.message, domains: [] };
  } finally {
    state.ddnsLoading = false;
  }
}

/* ================= Render: root ================= */

function render() {
  const app = el("app");
  if (!state.authed) {
    renderLogin(app);
    return;
  }
  const route = state.route;
  app.innerHTML = `
    <div class="layout ${state.sidebarCollapsed ? "collapsed" : ""}" id="layout">
      <aside class="sidebar">
        <div class="sidebar-brand">
          <img src="/static/favicon.svg" alt="logo">
          <span>${esc(t("app.name"))}</span>
        </div>
        <nav class="sidebar-nav">
          <button class="nav-item ${route === "dashboard" ? "active" : ""}" data-nav="dashboard">${I.dashboard}<span>${esc(t("nav.dashboard"))}</span></button>
          <button class="nav-item ${route === "records" ? "active" : ""}" data-nav="records">${I.dns}<span>${esc(t("nav.records"))}</span></button>
          <button class="nav-item ${route === "settings" ? "active" : ""}" data-nav="settings">${I.settings}<span>${esc(t("nav.settings"))}</span></button>
        </nav>
        <div class="sidebar-footer">
          <button class="nav-item" id="collapse-btn" title="${esc(t("nav.collapse"))}">${I.collapse}<span>${esc(t("nav.collapse"))}</span></button>
          <button class="nav-item" id="logout-btn">${I.logout}<span>${esc(t("nav.logout"))}</span></button>
        </div>
      </aside>
      <div class="main">
        <header class="topbar">
          <h1>${esc(t(route === "dashboard" ? "dash.title" : route === "records" ? "records.title" : "settings.title"))}</h1>
          <div class="topbar-actions" id="topbar-actions"></div>
        </header>
        <main class="content" id="page"></main>
      </div>
    </div>`;

  app.querySelectorAll("[data-nav]").forEach((btn) =>
    btn.addEventListener("click", () => navigate(btn.dataset.nav))
  );
  el("collapse-btn").addEventListener("click", () => {
    state.sidebarCollapsed = !state.sidebarCollapsed;
    localStorage.setItem("cfddns.sidebar", state.sidebarCollapsed ? "collapsed" : "expanded");
    el("layout").classList.toggle("collapsed", state.sidebarCollapsed);
  });
  el("logout-btn").addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch { /* ignore */ }
    state.authed = false;
    render();
  });

  renderTopbarActions();
  if (route === "dashboard") renderDashboard();
  else if (route === "records") renderRecords();
  else renderSettings();
}

function navigate(route) {
  state.route = route;
  location.hash = `#/${route}`;
  render();
}

window.addEventListener("hashchange", () => {
  const route = location.hash.replace("#/", "") || "dashboard";
  if (route !== state.route) { state.route = route; render(); }
});

function renderTopbarActions() {
  const box = el("topbar-actions");
  if (!box) return;
  let html = "";
  if (state.route === "records" && state.zones.length > 0) {
    html += `<select class="select u-zone-select" id="zone-select">
      ${state.zones.map((z) => `<option value="${esc(z.id)}" ${z.id === state.zoneId ? "selected" : ""}>${esc(z.name)}</option>`).join("")}
    </select>`;
  }
  html += `
    <div class="dropdown">
      <button class="btn icon" id="lang-btn" title="${esc(t("topbar.language"))}">${I.globe}</button>
      <div class="menu" id="lang-menu">
        <div class="menu-label">${esc(t("topbar.language"))}</div>
        ${LANGS.map((l) => `<button class="menu-item" data-lang="${l.code}"><span class="check">${l.code === lang ? I.check : ""}</span>${esc(l.name)}${l.code === "en" ? "" : ""}</button>`).join("")}
      </div>
    </div>
    <div class="dropdown">
      <button class="avatar" id="user-btn" title="Admin">A</button>
      <div class="menu" id="user-menu">
        <button class="menu-item" id="menu-logout">${I.logout} ${esc(t("nav.logout"))}</button>
      </div>
    </div>`;
  box.innerHTML = html;

  const zoneSelect = el("zone-select");
  if (zoneSelect) {
    zoneSelect.addEventListener("change", async () => {
      state.zoneId = zoneSelect.value;
      localStorage.setItem("cfddns.zone", state.zoneId);
      state.search = ""; state.typeFilter = "";
      await refreshRecords();
    });
  }
  bindDropdown("lang-btn", "lang-menu");
  bindDropdown("user-btn", "user-menu");
  box.querySelectorAll("[data-lang]").forEach((b) =>
    b.addEventListener("click", () => {
      lang = b.dataset.lang;
      localStorage.setItem("cfddns.lang", lang);
      render();
    })
  );
  const menuLogout = el("menu-logout");
  if (menuLogout) menuLogout.addEventListener("click", () => el("logout-btn").click());
}

function bindDropdown(btnId, menuId) {
  const btn = el(btnId), menu = el(menuId);
  if (!btn || !menu) return;
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const open = menu.classList.contains("open");
    closeAllMenus();
    if (!open) {
      menu.classList.add("open");
      const overlay = document.createElement("div");
      overlay.className = "menu-overlay";
      overlay.addEventListener("click", () => { closeAllMenus(); overlay.remove(); });
      document.body.appendChild(overlay);
    }
  });
}

function closeAllMenus() {
  document.querySelectorAll(".menu.open").forEach((m) => m.classList.remove("open"));
  document.querySelectorAll(".menu-overlay").forEach((o) => o.remove());
}

/* ================= Render: login ================= */

function renderLogin(app) {
  app.innerHTML = `
    <div class="login-wrap">
      <form class="login-card" id="login-form">
        <div class="login-logo">
          <img src="/static/favicon.svg" alt="logo">
          <h1>${esc(t("app.name"))}</h1>
        </div>
        <p class="login-sub">${esc(t("login.subtitle"))}</p>
        <div class="login-error" id="login-error"></div>
        <label class="field">
          <span>${esc(t("login.password"))}</span>
          <input class="input" type="password" id="login-password" autocomplete="current-password" required autofocus>
        </label>
        <button class="btn primary u-w100" type="submit" id="login-submit">${esc(t("login.submit"))}</button>
      </form>
    </div>`;
  const form = el("login-form");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = el("login-submit");
    const errBox = el("login-error");
    errBox.classList.remove("visible");
    btn.disabled = true;
    btn.textContent = t("login.wait");
    try {
      await api("/api/auth/login", { method: "POST", json: { password: el("login-password").value } });
      state.authed = true;
      await bootAuthed();
    } catch (err) {
      errBox.textContent = err.message === "unauthorized" ? t("login.error") : err.message;
      errBox.classList.add("visible");
      btn.disabled = false;
      btn.textContent = t("login.submit");
    }
  });
}

/* ================= Render: dashboard ================= */

function renderDashboard() {
  const page = el("page");
  page.innerHTML = `
    <div class="stat-grid" id="stat-grid"></div>
    <div id="ddns-section"></div>`;
  renderDashboardCards();
  if (state.ddns === null) loadDdns().then(renderDashboard);
}

function renderDashboardCards() {
  const grid = el("stat-grid");
  if (!grid) return;
  const d = state.ddns;
  const ipv4 = d ? (d.ipv4 || null) : null;
  const ipv6 = d ? (d.ipv6 || null) : null;
  const loading = state.ddnsLoading || d === null;
  grid.innerHTML = `
    <div class="stat-card">
      <div class="stat-label">${I.globe} ${esc(t("dash.ipv4"))}</div>
      <div class="stat-value ${!ipv4 ? "na" : ""}">${loading ? '<div class="spinner small"></div>' : esc(ipv4 || (d && d.ipv4_error) || t("dash.na"))}</div>
      ${d && d.configured === false ? "" : ""}
    </div>
    <div class="stat-card">
      <div class="stat-label">${I.globe} ${esc(t("dash.ipv6"))}</div>
      <div class="stat-value ${!ipv6 ? "na" : ""}">${loading ? '<div class="spinner small"></div>' : esc(ipv6 || (d && d.ipv6_error) || t("dash.na"))}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">${I.dns} ${esc(t("dash.zones"))}</div>
      <div class="stat-value">${state.zones.length}</div>
    </div>`;

  const section = el("ddns-section");
  if (!section) return;
  if (d && d.configured === false) {
    section.innerHTML = `
      <div class="card"><div class="card-pad">
        <div class="card-title">${esc(t("dash.ddns.title"))}</div>
        <div class="card-desc">${esc(t("dash.ddns.desc"))}</div>
        <div class="empty-state u-empty-sm">
          ${I.file}
          <h4>${esc(t("dash.ddns.not_configured"))}</h4>
          <p>${esc(t("dash.ddns.hint"))}</p>
        </div>
      </div></div>`;
    return;
  }
  const rows = (d && d.domains ? d.domains : []).map((dom) => {
    let statusBadge;
    if (dom.error) statusBadge = `<span class="badge red">${esc(t("dash.ddns.error"))}</span>`;
    else if (dom.in_sync) statusBadge = `<span class="badge green">${esc(t("dash.ddns.synced"))}</span>`;
    else if (dom.dns_ips.length === 0) statusBadge = `<span class="badge yellow">${esc(t("dash.ddns.missing"))}</span>`;
    else statusBadge = `<span class="badge yellow">${esc(t("dash.ddns.out_of_sync"))}</span>`;
    return `<tr>
      <td class="name-cell">${esc(dom.domain)}</td>
      <td><span class="badge">${esc(dom.record_type)}</span></td>
      <td class="mono">${esc(dom.detected_ip || "—")}</td>
      <td class="mono">${esc(dom.dns_ips.join(", ") || "—")}</td>
      <td>${statusBadge}${dom.error ? `<div class="cell-muted u-err-detail">${esc(dom.error)}</div>` : ""}</td>
    </tr>`;
  }).join("");
  section.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <div>
          <div class="card-title">${esc(t("dash.ddns.title"))}</div>
        </div>
        <div class="u-flex1"></div>
        <button class="btn ghost sm" id="ddns-refresh">${I.refresh} ${esc(t("topbar.refresh"))}</button>
        <button class="btn primary sm" id="ddns-update">${I.bolt} ${esc(t("dash.ddns.update_now"))}</button>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead><tr>
            <th>${esc(t("dash.ddns.domain"))}</th>
            <th>${esc(t("dash.ddns.type"))}</th>
            <th>${esc(t("dash.ddns.detected"))}</th>
            <th>${esc(t("dash.ddns.dns"))}</th>
            <th>${esc(t("dash.ddns.status"))}</th>
          </tr></thead>
          <tbody>${state.ddnsLoading ? `<tr><td colspan="5"><div class="skeleton"></div></td></tr>` : rows || `<tr><td colspan="5" class="cell-muted u-cell-empty">${esc(t("dash.ddns.not_configured"))}</td></tr>`}</tbody>
        </table>
      </div>
      <div id="ddns-log" class="u-logbox"></div>
    </div>`;

  const refreshBtn = el("ddns-refresh");
  if (refreshBtn) refreshBtn.addEventListener("click", async () => { await loadDdns(); renderDashboard(); });
  const updateBtn = el("ddns-update");
  if (updateBtn) updateBtn.addEventListener("click", async () => {
    updateBtn.disabled = true;
    updateBtn.innerHTML = `<div class="spinner small"></div> ${esc(t("dash.ddns.updating"))}`;
    try {
      const res = await api("/api/ddns/update", { method: "POST", json: {} });
      const logBox = el("ddns-log");
      logBox.style.display = "block";
      logBox.innerHTML = `<div class="log-output">${esc(res.log.join("\n"))}</div>`;
      toast(t("toast.updated_ddns"));
    } catch (e) {
      toast(e.message, "error");
    }
    await loadDdns();
    renderDashboard();
  });
}

/* ================= Render: records page ================= */

async function refreshRecords() {
  await loadRecords();
  renderRecords();
}

function filteredRecords() {
  let out = state.records;
  if (state.typeFilter) out = out.filter((r) => r.type === state.typeFilter);
  if (state.search) {
    const q = state.search.toLowerCase();
    out = out.filter((r) =>
      r.name.toLowerCase().includes(q) ||
      (r.content || "").toLowerCase().includes(q) ||
      (r.comment || "").toLowerCase().includes(q) ||
      (r.tags || []).some((tag) => tag.toLowerCase().includes(q))
    );
  }
  const { key, dir } = state.sort;
  out = [...out].sort((a, b) => {
    let av, bv;
    switch (key) {
      case "type": av = a.type; bv = b.type; break;
      case "content": av = a.content || ""; bv = b.content || ""; break;
      case "ttl": av = a.ttl ?? 0; bv = b.ttl ?? 0; break;
      case "updated": av = a.modified_on || ""; bv = b.modified_on || ""; break;
      case "created": av = a.created_on || ""; bv = b.created_on || ""; break;
      default: av = a.name; bv = b.name;
    }
    if (av < bv) return -dir;
    if (av > bv) return dir;
    return 0;
  });
  return out;
}

function renderRecords() {
  const page = el("page");
  if (state.zones.length === 0) {
    page.innerHTML = `<div class="card"><div class="empty-state">${I.file}<h4>${esc(t("records.empty.title"))}</h4><p>No zones available for this API token.</p></div></div>`;
    return;
  }
  // Records are stale (first visit or zone switch) — fetch, then re-render.
  if (state.zoneId && state.recordsZoneId !== state.zoneId && !state.recordsLoading) {
    loadRecords()
      .then(renderRecords)
      .catch((e) => { toast(e.message, "error"); renderRecords(); });
  }
  page.innerHTML = `
    <div class="page-head">
      <h2>${esc(t("records.title"))}</h2>
      <div class="actions">
        <button class="btn" id="import-btn">${I.upload} ${esc(t("records.import"))}</button>
        <button class="btn" id="export-btn">${I.download} ${esc(t("records.export"))}</button>
        <button class="btn primary" id="add-btn">${I.plus} ${esc(t("records.add"))}</button>
      </div>
    </div>
    <div class="card">
      <div class="toolbar">
        <div class="search-box">${I.search}<input class="input" id="search-input" placeholder="${esc(t("records.search"))}" value="${esc(state.search)}"></div>
        <select class="select" id="type-filter">
          <option value="">${esc(t("records.all_types"))}</option>
          ${RECORD_TYPES.map((tp) => `<option value="${tp}" ${state.typeFilter === tp ? "selected" : ""}>${tp}</option>`).join("")}
        </select>
        <div class="u-flex1"></div>
        <div class="dropdown">
          <button class="btn" id="columns-btn">${I.columns} ${esc(t("records.columns"))}</button>
          <div class="menu" id="columns-menu">
            <div class="menu-label">${esc(t("records.columns"))}</div>
            ${COLUMN_ORDER.map((c) => `<button class="menu-item" data-col="${c}"><span class="check">${state.columns[c] ? I.check : ""}</span>${esc(t("col." + c))}</button>`).join("")}
          </div>
        </div>
        <button class="btn icon" id="refresh-btn" title="${esc(t("topbar.refresh"))}">${I.refresh}</button>
      </div>
      <div class="bulkbar" id="bulkbar">
        <span id="bulk-count"></span>
        <div class="sep"></div>
        <button class="btn sm" id="bulk-edit">${I.edit} ${esc(t("records.edit"))}</button>
        <button class="btn sm danger" id="bulk-delete">${I.trash} ${esc(t("records.delete"))}</button>
        <div class="u-flex1"></div>
        <button class="btn sm ghost" id="bulk-clear">${esc(t("records.clear"))}</button>
      </div>
      <div class="table-wrap" id="table-wrap"></div>
      <div class="pagination" id="pagination"></div>
    </div>`;

  el("search-input").addEventListener("input", (e) => {
    state.search = e.target.value;
    state.page = 1;
    renderRecordsTable();
  });
  el("type-filter").addEventListener("change", (e) => {
    state.typeFilter = e.target.value;
    state.page = 1;
    renderRecordsTable();
  });
  bindDropdown("columns-btn", "columns-menu");
  document.querySelectorAll("#columns-menu [data-col]").forEach((b) =>
    b.addEventListener("click", () => {
      state.columns[b.dataset.col] = !state.columns[b.dataset.col];
      localStorage.setItem("cfddns.columns", JSON.stringify(state.columns));
      closeAllMenus();
      renderRecords();
    })
  );
  el("refresh-btn").addEventListener("click", refreshRecords);
  el("add-btn").addEventListener("click", () => openRecordModal(null));
  el("export-btn").addEventListener("click", exportZone);
  el("import-btn").addEventListener("click", openImportModal);
  el("bulk-edit").addEventListener("click", openBulkEditModal);
  el("bulk-delete").addEventListener("click", openBulkDeleteModal);
  el("bulk-clear").addEventListener("click", () => { state.selection.clear(); renderRecordsTable(); });

  renderRecordsTable();
}

function renderRecordsTable() {
  const wrap = el("table-wrap");
  if (!wrap) return;

  if (state.recordsLoading) {
    wrap.innerHTML = `<table class="data"><tbody>
      ${Array.from({ length: 5 }).map(() => `<tr class="skeleton-row"><td colspan="8"><div class="skeleton"></div></td></tr>`).join("")}
    </tbody></table>`;
    el("pagination").innerHTML = "";
    updateBulkbar();
    return;
  }

  const all = filteredRecords();
  const total = all.length;
  const pages = Math.max(1, Math.ceil(total / state.perPage));
  if (state.page > pages) state.page = pages;
  const from = (state.page - 1) * state.perPage;
  const rows = all.slice(from, from + state.perPage);

  const c = state.columns;
  const headCols = [];
  headCols.push(`<th class="u-w-check"><span class="checkbox" id="select-all"></span></th>`);
  const sortTh = (key, label) => {
    const arrow = state.sort.key === key ? `<span class="sort-arrow">${state.sort.dir === 1 ? "▲" : "▼"}</span>` : "";
    return `<th class="sortable" data-sort="${key}">${esc(label)}${arrow}</th>`;
  };
  if (c.type) headCols.push(sortTh("type", t("col.type")));
  if (c.name) headCols.push(sortTh("name", t("col.name")));
  if (c.content) headCols.push(sortTh("content", t("col.content")));
  if (c.proxy) headCols.push(`<th>${esc(t("col.proxy"))}</th>`);
  if (c.ttl) headCols.push(sortTh("ttl", t("col.ttl")));
  if (c.tags) headCols.push(`<th>${esc(t("col.tags"))}</th>`);
  if (c.comment) headCols.push(`<th>${esc(t("col.comment"))}</th>`);
  if (c.updated) headCols.push(sortTh("updated", t("col.updated")));
  if (c.created) headCols.push(sortTh("created", t("col.created")));
  headCols.push(`<th class="u-w-actions">${esc(t("col.actions"))}</th>`);

  const bodyRows = rows.map((r) => {
    const selected = state.selection.has(r.id);
    const cells = [];
    cells.push(`<td><span class="checkbox ${selected ? "checked" : ""}" data-select="${esc(r.id)}"></span></td>`);
    if (c.type) cells.push(`<td><span class="badge">${esc(r.type)}</span></td>`);
    if (c.name) cells.push(`<td class="name-cell" title="${esc(r.name)}">${esc(r.name)}</td>`);
    if (c.content) {
      const content = r.type === "SRV" && r.data
        ? `${r.data.priority ?? ""} ${r.data.weight ?? ""} ${r.data.port ?? ""} ${r.data.target ?? r.content}`
        : r.content;
      cells.push(`<td class="mono truncate cell-copy" data-copy="${esc(r.content)}" title="${esc(t("common.copy"))}: ${esc(r.content)}">${esc(content)}</td>`);
    }
    if (c.proxy) {
      if (r.proxiable) {
        const on = !!r.proxied;
        cells.push(`<td><button class="cloud-btn ${on ? "on" : "off"}" data-proxy="${esc(r.id)}" data-proxy-state="${on}" title="${esc(on ? t("proxy.proxied") : t("proxy.dns_only"))}">${on ? I.cloudFill : I.cloud}<span>${esc(on ? t("proxy.proxied") : t("proxy.dns_only"))}</span></button></td>`);
      } else {
        cells.push(`<td><span class="cloud-btn disabled" title="${esc(t("proxy.na"))}">${I.cloud}<span class="cell-muted">—</span></span></td>`);
      }
    }
    if (c.ttl) cells.push(`<td>${esc(fmtTtl(r.ttl))}</td>`);
    if (c.tags) cells.push(`<td class="truncate">${(r.tags || []).map((tag) => `<span class="tag-chip">${esc(tag)}</span>`).join("") || '<span class="cell-muted">—</span>'}</td>`);
    if (c.comment) cells.push(`<td class="truncate cell-muted" title="${esc(r.comment || "")}">${esc(r.comment || "—")}</td>`);
    if (c.updated) cells.push(`<td class="cell-muted u-nowrap">${esc(fmtDate(r.modified_on))}</td>`);
    if (c.created) cells.push(`<td class="cell-muted u-nowrap">${esc(fmtDate(r.created_on))}</td>`);
    cells.push(`<td class="u-nowrap">
      <button class="btn ghost icon sm" data-edit="${esc(r.id)}" title="${esc(t("records.edit"))}">${I.edit}</button>
      <button class="btn ghost icon sm danger" data-delete="${esc(r.id)}" title="${esc(t("records.delete"))}">${I.trash}</button>
    </td>`);
    return `<tr class="${selected ? "selected" : ""}" data-row="${esc(r.id)}">${cells.join("")}</tr>`;
  }).join("");

  wrap.innerHTML = rows.length === 0
    ? `<div class="empty-state">${I.file}<h4>${esc(t("records.empty.title"))}</h4><p>${esc(t("records.empty.desc"))}</p></div>`
    : `<table class="data"><thead><tr>${headCols.join("")}</tr></thead><tbody>${bodyRows}</tbody></table>`;

  // Wire events
  const selectAll = el("select-all");
  if (selectAll) {
    const pageIds = rows.map((r) => r.id);
    const selectedOnPage = pageIds.filter((id) => state.selection.has(id)).length;
    selectAll.classList.toggle("checked", selectedOnPage > 0 && selectedOnPage === pageIds.length);
    selectAll.classList.toggle("indeterminate", selectedOnPage > 0 && selectedOnPage < pageIds.length);
    selectAll.addEventListener("click", () => {
      if (selectedOnPage === pageIds.length) pageIds.forEach((id) => state.selection.delete(id));
      else pageIds.forEach((id) => state.selection.add(id));
      renderRecordsTable();
    });
  }
  wrap.querySelectorAll("[data-select]").forEach((cb) =>
    cb.addEventListener("click", () => {
      const id = cb.dataset.select;
      if (state.selection.has(id)) state.selection.delete(id);
      else state.selection.add(id);
      renderRecordsTable();
    })
  );
  wrap.querySelectorAll("[data-sort]").forEach((th) =>
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.sort.key === key) state.sort.dir *= -1;
      else state.sort = { key, dir: 1 };
      renderRecordsTable();
    })
  );
  wrap.querySelectorAll("[data-copy]").forEach((td) =>
    td.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(td.dataset.copy); toast(t("common.copied")); } catch { /* clipboard unavailable */ }
    })
  );
  wrap.querySelectorAll("[data-proxy]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      const id = btn.dataset.proxy;
      const on = btn.dataset.proxyState === "true";
      btn.disabled = true;
      try {
        await api(`/api/zones/${state.zoneId}/records/bulk`, {
          method: "POST",
          json: { action: "update", ids: [id], patch: { proxied: !on } },
        });
        const rec = state.records.find((r) => r.id === id);
        if (rec) rec.proxied = !on;
        renderRecordsTable();
      } catch (e) {
        toast(e.message, "error");
        btn.disabled = false;
      }
    })
  );
  wrap.querySelectorAll("[data-edit]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const rec = state.records.find((r) => r.id === btn.dataset.edit);
      if (rec) openRecordModal(rec);
    })
  );
  wrap.querySelectorAll("[data-delete]").forEach((btn) =>
    btn.addEventListener("click", () => {
      state.selection = new Set([btn.dataset.delete]);
      openBulkDeleteModal();
    })
  );

  renderPagination(total, from, rows.length);
  updateBulkbar();
}

function renderPagination(total, from, shown) {
  const box = el("pagination");
  if (!box) return;
  if (total === 0) { box.innerHTML = ""; return; }
  const pages = Math.max(1, Math.ceil(total / state.perPage));
  box.innerHTML = `
    <span>${esc(t("records.showing", { from: from + 1, to: from + shown, total }))}</span>
    <div class="spacer"></div>
    <span>${esc(t("records.per_page"))}</span>
    <select class="select" id="per-page">
      ${[20, 50, 100].map((n) => `<option value="${n}" ${state.perPage === n ? "selected" : ""}>${n}</option>`).join("")}
    </select>
    <div class="page-btns">
      <button class="btn icon sm" id="page-prev" ${state.page <= 1 ? "disabled" : ""}>${I.chevronLeft}</button>
      <button class="btn icon sm" id="page-next" ${state.page >= pages ? "disabled" : ""}>${I.chevronRight}</button>
    </div>`;
  el("per-page").addEventListener("change", (e) => {
    state.perPage = parseInt(e.target.value, 10);
    localStorage.setItem("cfddns.perPage", String(state.perPage));
    state.page = 1;
    renderRecordsTable();
  });
  el("page-prev").addEventListener("click", () => { state.page--; renderRecordsTable(); });
  el("page-next").addEventListener("click", () => { state.page++; renderRecordsTable(); });
}

function updateBulkbar() {
  const bar = el("bulkbar");
  if (!bar) return;
  const n = state.selection.size;
  bar.classList.toggle("visible", n > 0);
  const count = el("bulk-count");
  if (count) count.textContent = t("records.selected", { n });
}

/* ================= Modals ================= */

function openModal(html, wide) {
  const root = el("modal-root");
  root.innerHTML = `
    <div class="modal-overlay" id="modal-overlay">
      <div class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true">
        ${html}
      </div>
    </div>`;
  el("modal-overlay").addEventListener("mousedown", (e) => {
    if (e.target.id === "modal-overlay") closeModal();
  });
  document.addEventListener("keydown", escClose);
  root.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", closeModal));
  return root.querySelector(".modal");
}

function escClose(e) { if (e.key === "Escape") closeModal(); }
function closeModal() {
  el("modal-root").innerHTML = "";
  document.removeEventListener("keydown", escClose);
}

function modalHead(title) {
  return `<div class="modal-head"><h3>${esc(title)}</h3><button class="modal-close" data-close>${I.close}</button></div>`;
}

/* ----- Add / edit record ----- */

function typeSpecificFields(type, rec) {
  const d = (rec && rec.data) || {};
  if (type === "MX") {
    return `
      <label class="field"><span>${esc(t("modal.content.MX"))} *</span>
        <input class="input" id="f-content" value="${esc(rec ? rec.content : "")}" placeholder="mail.example.com" required></label>
      <label class="field"><span>${esc(t("modal.priority"))} *</span>
        <input class="input" id="f-priority" type="number" min="0" max="65535" value="${esc(rec && rec.priority != null ? rec.priority : 10)}" required></label>`;
  }
  if (type === "SRV") {
    return `
      <div class="form-grid">
        <label class="field"><span>${esc(t("modal.srv.priority"))} *</span>
          <input class="input" id="f-srv-priority" type="number" min="0" max="65535" value="${esc(d.priority ?? 0)}" required></label>
        <label class="field"><span>${esc(t("modal.srv.weight"))} *</span>
          <input class="input" id="f-srv-weight" type="number" min="0" max="65535" value="${esc(d.weight ?? 5)}" required></label>
        <label class="field"><span>${esc(t("modal.srv.port"))} *</span>
          <input class="input" id="f-srv-port" type="number" min="0" max="65535" value="${esc(d.port ?? "")}" placeholder="25565" required></label>
        <label class="field"><span>${esc(t("modal.srv.target"))} *</span>
          <input class="input" id="f-srv-target" value="${esc(d.target ?? "")}" placeholder="mc.example.com" required></label>
      </div>`;
  }
  if (type === "CAA") {
    return `
      <div class="form-grid">
        <label class="field"><span>${esc(t("modal.caa.flags"))} *</span>
          <input class="input" id="f-caa-flags" type="number" min="0" max="255" value="${esc(d.flags ?? 0)}" required></label>
        <label class="field"><span>${esc(t("modal.caa.tag"))} *</span>
          <select class="select" id="f-caa-tag">
            ${["issue", "issuewild", "iodef"].map((tag) => `<option ${d.tag === tag ? "selected" : ""}>${tag}</option>`).join("")}
          </select></label>
        <label class="field full"><span>${esc(t("modal.caa.value"))} *</span>
          <input class="input" id="f-caa-value" value="${esc(d.value ?? "")}" placeholder="letsencrypt.org" required></label>
      </div>`;
  }
  const labelKey = `modal.content.${type}`;
  const label = t(labelKey) === labelKey ? t("modal.content") : t(labelKey);
  const placeholders = {
    A: "192.0.2.1", AAAA: "2001:db8::1", CNAME: "example.com",
    TXT: "v=spf1 include:example.com ~all", NS: "ns1.example.com", PTR: "example.com",
    HTTPS: "1 . alpn=h3", SVCB: "1 . alpn=h3",
  };
  return `<label class="field"><span>${esc(label)} *</span>
    <input class="input" id="f-content" value="${esc(rec ? rec.content : "")}" placeholder="${esc(placeholders[type] || "")}" required></label>`;
}

function openRecordModal(rec) {
  const isEdit = !!rec;
  const zone = currentZone();
  const zoneName = zone ? zone.name : "";
  const type = rec ? rec.type : "A";

  const modal = openModal(`
    ${modalHead(isEdit ? t("modal.edit.title") : t("modal.add.title"))}
    <div class="modal-body">
      <div class="form-grid">
        <label class="field"><span>${esc(t("modal.type"))}</span>
          <select class="select" id="f-type" ${isEdit ? "disabled" : ""}>
            ${RECORD_TYPES.map((tp) => `<option value="${tp}" ${tp === type ? "selected" : ""}>${tp}</option>`).join("")}
          </select></label>
        <label class="field"><span>${esc(t("modal.name"))} *</span>
          <div class="input-group">
            <input class="input" id="f-name" value="${esc(rec ? shortName(rec.name, zoneName) : "")}" placeholder="@" required ${isEdit ? "disabled" : ""}>
            <span class="suffix">.${esc(zoneName)}</span>
          </div>
          <div class="field-hint">${esc(t("modal.name.hint"))}</div></label>
      </div>
      <div id="type-fields">${typeSpecificFields(type, rec)}</div>
      <div class="form-grid">
        <label class="field"><span>${esc(t("modal.ttl"))}</span>
          <select class="select" id="f-ttl">
            ${TTL_OPTIONS.map(([v, lbl]) => `<option value="${v}" ${rec && rec.ttl === v ? "selected" : (!rec && v === 1 ? "selected" : "")}>${v === 1 ? t("ttl.auto") : lbl}</option>`).join("")}
          </select></label>
        <div class="field">
          <span>&nbsp;</span>
          <div class="switch-row u-mb0">
            <label class="switch"><input type="checkbox" id="f-proxied" ${rec && rec.proxied ? "checked" : ""} ${PROXIABLE.includes(type) ? "" : "disabled"}><span class="track"></span></label>
            <span class="lbl">${esc(t("modal.proxy"))}</span>
          </div>
        </div>
      </div>
      <label class="field"><span>${esc(t("modal.tags"))}</span>
        <input class="input" id="f-tags" value="${esc(rec && rec.tags ? rec.tags.join(", ") : "")}" placeholder="cf-proxied:true">
        <div class="field-hint">${esc(t("modal.tags.hint"))}</div></label>
      <label class="field"><span>${esc(t("modal.comment"))}</span>
        <input class="input" id="f-comment" value="${esc(rec && rec.comment ? rec.comment : "")}" maxlength="100"></label>
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="f-save">${esc(isEdit ? t("modal.save") : t("modal.create"))}</button>
    </div>`, true);

  const typeSel = modal.querySelector("#f-type");
  const fieldsBox = modal.querySelector("#type-fields");
  const proxiedInput = modal.querySelector("#f-proxied");
  typeSel.addEventListener("change", () => {
    fieldsBox.innerHTML = typeSpecificFields(typeSel.value, null);
    const ok = PROXIABLE.includes(typeSel.value);
    proxiedInput.disabled = !ok;
    if (!ok) proxiedInput.checked = false;
  });

  modal.querySelector("#f-save").addEventListener("click", async () => {
    const saveBtn = modal.querySelector("#f-save");
    const tp = isEdit ? rec.type : typeSel.value;
    const payload = buildPayload(modal, tp, zoneName, isEdit ? rec : null);
    if (!payload) return;
    saveBtn.disabled = true;
    saveBtn.innerHTML = `<div class="spinner small"></div>`;
    try {
      if (isEdit) {
        await api(`/api/zones/${state.zoneId}/records/${rec.id}`, { method: "PUT", json: payload });
        toast(t("toast.saved"));
      } else {
        await api(`/api/zones/${state.zoneId}/records`, { method: "POST", json: payload });
        toast(t("toast.created"));
      }
      closeModal();
      await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      saveBtn.disabled = false;
      saveBtn.textContent = isEdit ? t("modal.save") : t("modal.create");
    }
  });
}

function shortName(fqdn, zoneName) {
  if (fqdn === zoneName) return "@";
  if (zoneName && fqdn.endsWith(`.${zoneName}`)) return fqdn.slice(0, -(zoneName.length + 1));
  return fqdn;
}

function fullName(short, zoneName) {
  const s = short.trim().toLowerCase();
  if (s === "@" || s === "") return zoneName;
  if (s.endsWith(`.${zoneName}`)) return s;
  return `${s}.${zoneName}`;
}

function buildPayload(modal, type, zoneName, rec) {
  const val = (sel) => { const x = modal.querySelector(sel); return x ? x.value.trim() : ""; };
  const name = isEditNameDisabled(modal) ? (rec ? rec.name : "") : fullName(val("#f-name"), zoneName);
  const ttl = parseInt(val("#f-ttl"), 10) || 1;
  const proxied = PROXIABLE.includes(type) ? modal.querySelector("#f-proxied").checked : false;
  const comment = val("#f-comment") || null;
  const tagsRaw = val("#f-tags");
  const tags = tagsRaw ? tagsRaw.split(",").map((x) => x.trim()).filter(Boolean) : null;

  const payload = { type, name, ttl, proxied, comment, tags };
  if (type === "MX") {
    payload.content = val("#f-content");
    payload.priority = parseInt(val("#f-priority"), 10);
    if (!payload.content || isNaN(payload.priority)) { toast(t("modal.required"), "error"); return null; }
  } else if (type === "SRV") {
    const data = {
      priority: parseInt(val("#f-srv-priority"), 10),
      weight: parseInt(val("#f-srv-weight"), 10),
      port: parseInt(val("#f-srv-port"), 10),
      target: val("#f-srv-target"),
    };
    if ([data.priority, data.weight, data.port].some(isNaN) || !data.target) { toast(t("modal.required"), "error"); return null; }
    payload.data = data;
    payload.content = `${data.weight} ${data.port} ${data.target}`;
  } else if (type === "CAA") {
    const data = { flags: parseInt(val("#f-caa-flags"), 10), tag: val("#f-caa-tag"), value: val("#f-caa-value") };
    if (isNaN(data.flags) || !data.value) { toast(t("modal.required"), "error"); return null; }
    payload.data = data;
    payload.content = `${data.flags} ${data.tag} "${data.value}"`;
  } else {
    payload.content = val("#f-content");
    if (!payload.content) { toast(t("modal.required"), "error"); return null; }
  }
  if (!payload.name) { toast(t("modal.required"), "error"); return null; }
  return payload;
}

function isEditNameDisabled(modal) {
  const n = modal.querySelector("#f-name");
  return n && n.disabled;
}

/* ----- Bulk edit ----- */

function openBulkEditModal() {
  const selected = state.records.filter((r) => state.selection.has(r.id));
  if (selected.length === 0) return;
  const allProxiable = selected.every((r) => PROXIABLE.includes(r.type));
  const nonProxiableTypes = [...new Set(selected.filter((r) => !PROXIABLE.includes(r.type)).map((r) => r.type))];

  const modal = openModal(`
    ${modalHead(t("modal.bulk.title", { n: selected.length }))}
    <div class="modal-body">
      <div class="form-grid">
        <label class="field"><span>${esc(t("modal.bulk.ttl"))}</span>
          <select class="select" id="b-ttl">
            <option value="">${esc(t("modal.bulk.keep"))}</option>
            ${TTL_OPTIONS.map(([v, lbl]) => `<option value="${v}">${v === 1 ? t("ttl.auto") : lbl}</option>`).join("")}
          </select></label>
        <label class="field"><span>${esc(t("modal.bulk.proxy"))}</span>
          <select class="select" id="b-proxied" ${allProxiable ? "" : "disabled"}>
            <option value="">${esc(t("modal.bulk.keep"))}</option>
            <option value="true">${esc(t("modal.bulk.proxy.on"))}</option>
            <option value="false">${esc(t("modal.bulk.proxy.off"))}</option>
          </select></label>
      </div>
      ${allProxiable ? "" : `<div class="login-error visible u-mb16">${esc(t("modal.bulk.proxy.blocked"))} (${esc(nonProxiableTypes.join(", "))})</div>`}
      <label class="field"><span>${esc(t("modal.bulk.comment"))}</span>
        <select class="select" id="b-comment-mode">
          <option value="keep">${esc(t("modal.bulk.comment.keep"))}</option>
          <option value="replace">${esc(t("modal.bulk.comment.replace"))}</option>
          <option value="clear">${esc(t("modal.bulk.comment.clear"))}</option>
        </select></label>
      <label class="field u-hidden" id="b-comment-wrap">
        <input class="input" id="b-comment" maxlength="100"></label>
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="b-apply">${esc(t("modal.bulk.apply", { n: selected.length }))}</button>
    </div>`);

  const modeSel = modal.querySelector("#b-comment-mode");
  const commentWrap = modal.querySelector("#b-comment-wrap");
  modeSel.addEventListener("change", () => {
    commentWrap.classList.toggle("u-hidden", modeSel.value !== "replace");
  });

  modal.querySelector("#b-apply").addEventListener("click", async () => {
    const applyBtn = modal.querySelector("#b-apply");
    const patch = {};
    const ttlV = modal.querySelector("#b-ttl").value;
    if (ttlV) patch.ttl = parseInt(ttlV, 10);
    const proxV = modal.querySelector("#b-proxied").value;
    if (proxV) patch.proxied = proxV === "true";
    if (modeSel.value !== "keep") {
      patch.comment_set = true;
      patch.comment = modeSel.value === "replace" ? modal.querySelector("#b-comment").value.trim() : "";
    }
    if (Object.keys(patch).length === 0) { closeModal(); return; }
    applyBtn.disabled = true;
    applyBtn.innerHTML = `<div class="spinner small"></div>`;
    try {
      const res = await api(`/api/zones/${state.zoneId}/records/bulk`, {
        method: "POST",
        json: { action: "update", ids: [...state.selection], patch },
      });
      toast(t("toast.bulk_update", { ok: res.succeeded, fail_part: res.failed ? t("toast.fail_suffix", { n: res.failed }) : "" }), res.failed ? "info" : "ok");
      closeModal();
      await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      applyBtn.disabled = false;
      applyBtn.textContent = t("modal.bulk.apply", { n: selected.length });
    }
  });
}

/* ----- Delete (single or bulk) ----- */

function openBulkDeleteModal() {
  const n = state.selection.size;
  if (n === 0) return;
  const modal = openModal(`
    ${modalHead(t("modal.delete.title"))}
    <div class="modal-body">
      <p class="u-note">${esc(n === 1 ? t("modal.delete.one") : t("modal.delete.many", { n }))}</p>
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn danger" id="d-confirm">${I.trash} ${esc(t("modal.delete.confirm"))}</button>
    </div>`);
  modal.querySelector("#d-confirm").addEventListener("click", async () => {
    const btn = modal.querySelector("#d-confirm");
    btn.disabled = true;
    btn.innerHTML = `<div class="spinner small"></div>`;
    try {
      const res = await api(`/api/zones/${state.zoneId}/records/bulk`, {
        method: "POST",
        json: { action: "delete", ids: [...state.selection] },
      });
      toast(t("toast.bulk_delete", { ok: res.succeeded, fail_part: res.failed ? t("toast.fail_suffix", { n: res.failed }) : "" }), res.failed ? "info" : "ok");
      closeModal();
      await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      btn.disabled = false;
      btn.innerHTML = `${I.trash} ${esc(t("modal.delete.confirm"))}`;
    }
  });
}

/* ----- Import / export ----- */

function openImportModal() {
  const modal = openModal(`
    ${modalHead(t("modal.import.title"))}
    <div class="modal-body">
      <p class="u-note-sm">${esc(t("modal.import.desc"))}</p>
      <div class="dropzone" id="dropzone">
        ${I.file}
        <div class="u-mt8" id="drop-label">${t("modal.import.drop")}</div>
      </div>
      <input type="file" id="file-input" accept=".txt,.zone,text/plain" class="u-hidden">
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="i-submit" disabled>${I.upload} ${esc(t("modal.import.submit"))}</button>
    </div>`);

  let file = null;
  const dz = modal.querySelector("#dropzone");
  const fi = modal.querySelector("#file-input");
  const submit = modal.querySelector("#i-submit");
  const label = modal.querySelector("#drop-label");

  dz.addEventListener("click", () => fi.click());
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("drag"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("drag"));
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    dz.classList.remove("drag");
    if (e.dataTransfer.files.length) { file = e.dataTransfer.files[0]; label.textContent = file.name; submit.disabled = false; }
  });
  fi.addEventListener("change", () => {
    if (fi.files.length) { file = fi.files[0]; label.textContent = file.name; submit.disabled = false; }
  });

  submit.addEventListener("click", async () => {
    if (!file) return;
    submit.disabled = true;
    submit.innerHTML = `<div class="spinner small"></div>`;
    try {
      const text = await file.text();
      const res = await api(`/api/zones/${state.zoneId}/import?filename=${encodeURIComponent(file.name)}`, {
        method: "POST", raw: text,
      });
      toast(t("modal.import.result", { added: res.recs_added ?? "?", parsed: res.total_records_parsed ?? "?" }));
      closeModal();
      await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      submit.disabled = false;
      submit.innerHTML = `${I.upload} ${esc(t("modal.import.submit"))}`;
    }
  });
}

async function exportZone() {
  const zone = currentZone();
  try {
    const text = await api(`/api/zones/${state.zoneId}/export`, { text: true });
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${zone ? zone.name : "zone"}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast(t("toast.exported"));
  } catch (e) {
    toast(e.message, "error");
  }
}

/* ================= Render: settings ================= */

function renderSettings() {
  const page = el("page");
  page.innerHTML = `
    <div class="settings-grid">
      <div class="card"><div class="card-pad">
        <div class="card-title">${esc(t("settings.lang.title"))}</div>
        <div class="card-desc">${esc(t("settings.lang.desc"))}</div>
        <select class="select u-lang-select" id="settings-lang">
          ${LANGS.map((l) => `<option value="${l.code}" ${l.code === lang ? "selected" : ""}>${esc(l.name)}</option>`).join("")}
        </select>
      </div></div>

      <div class="card"><div class="card-pad">
        <div class="card-title">${I.shield} ${esc(t("settings.token.title"))}</div>
        <div class="card-desc">${esc(t("settings.token.desc"))}</div>
        <ol class="token-steps">
          <li>${t("settings.token.step1")}</li>
          <li>${t("settings.token.step2")}</li>
          <li>${t("settings.token.step3")}</li>
          <li>${t("settings.token.step4")}</li>
          <li>${t("settings.token.step5")}</li>
        </ol>
        <div class="u-mt14">
          <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer">dash.cloudflare.com/profile/api-tokens ↗</a>
        </div>
      </div></div>

      <div class="card"><div class="card-pad">
        <div class="card-title">${esc(t("settings.security.title"))}</div>
        <div class="card-desc">${esc(t("settings.security.desc"))}</div>
        <table class="kv-table">
          <tr><td>${esc(t("settings.security.session"))}</td><td class="mono">${state.sessionTtl ? `${Math.round(state.sessionTtl / 3600)} h` : "—"}</td></tr>
          <tr><td>${esc(t("settings.security.password"))}</td><td>${esc(t("settings.security.password.value"))}</td></tr>
          <tr><td>${esc(t("settings.security.cookies"))}</td><td><span class="cell-muted">${esc(t("settings.security.cookies.hint"))}</span></td></tr>
        </table>
      </div></div>

      <div class="card"><div class="card-pad">
        <div class="card-title">${esc(t("settings.about.title"))}</div>
        <table class="kv-table">
          <tr><td>${esc(t("settings.about.version"))}</td><td class="mono">v${esc(state.config ? state.config.version : "?")}</td></tr>
          <tr><td>${esc(t("settings.about.upstream"))}</td><td><a href="https://github.com/timothymiller/cloudflare-ddns" target="_blank" rel="noopener noreferrer">cloudflare-ddns</a></td></tr>
        </table>
      </div></div>
    </div>`;
  el("settings-lang").addEventListener("change", (e) => {
    lang = e.target.value;
    localStorage.setItem("cfddns.lang", lang);
    render();
  });
}

/* ================= Boot ================= */

async function bootAuthed() {
  try {
    const me = await api("/api/auth/me");
    state.sessionTtl = me.session_ttl;
  } catch { /* non-fatal */ }
  try {
    await loadZones();
  } catch (e) {
    toast(e.message, "error");
  }
  state.ddns = null;
  render();
  if (state.route === "records") {
    state.recordsLoading = true;
    renderRecordsTable();
    loadRecords().then(renderRecords).catch((e) => { toast(e.message, "error"); renderRecords(); });
  }
}

(async function boot() {
  try {
    state.config = await api("/api/config");
  } catch { /* server may still be starting */ }
  try {
    const me = await api("/api/auth/me");
    state.authed = !!me.authenticated;
    state.sessionTtl = me.session_ttl;
  } catch {
    state.authed = false;
  }
  if (state.authed) await bootAuthed();
  else render();
})();

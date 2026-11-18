/* Shared basics, loaded first: saved preferences, constants, app state, formatters and validators. */
"use strict";

const THEMES = ["system", "light", "dark"];

/* Theme applied immediately at parse time (before first paint). */
(function () {
  var mode = currentTheme();
  var dark = mode === "dark" || (mode === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
})();

/* ================= Saved preferences ================= */

// Saved values are strings anyone can edit, and storage can be blocked, so a read never throws.
// parse returns undefined to reject a value; the caller then gets the fallback.
function readStored(key, fallback, parse = (raw) => raw) {
  try {
    const raw = localStorage.getItem(key);
    const value = raw === null ? undefined : parse(raw);
    return value === undefined ? fallback : value;
  } catch {
    return fallback;
  }
}

// A blocked or full storage must not stop the action that saves a preference.
function writeStored(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // The preference just isn't remembered.
  }
}

// Kept here because the theme code at the top of this file calls it before ui.js loads.
function currentTheme() { return readStored("cfddns.theme", "system", (raw) => THEMES.includes(raw) ? raw : undefined); }

/* ================= Constants & state ================= */

const RECORD_TYPES = ["A", "AAAA", "CAA", "CNAME", "HTTPS", "MX", "NS", "PTR", "SRV", "SVCB", "TXT"];
const PROXIABLE = ["A", "AAAA", "CNAME"];
const TTL_OPTIONS = [
  [1, "Auto"], [60, "1 min"], [120, "2 min"], [300, "5 min"], [600, "10 min"],
  [1800, "30 min"], [3600, "1 hour"], [7200, "2 hours"], [18000, "5 hours"],
  [43200, "12 hours"], [86400, "1 day"],
];
const ACCENT_PRESETS = ["#f6821f", "#3b82f6", "#22c55e", "#a855f7", "#ef4444", "#14b8a6", "#eab308", "#ec4899"];
const PER_PAGE_OPTIONS = [20, 50, 100];

const DEFAULT_COLUMNS = {
  type: true, name: true, content: true, proxy: true, ttl: true,
  tags: true, comment: true, updated: false, created: false,
};
const COLUMN_ORDER = ["type", "name", "content", "proxy", "ttl", "tags", "comment", "updated", "created"];

// Keeps only known columns with boolean values, so an edited entry cannot add or break columns.
function parseColumns(raw) {
  const saved = JSON.parse(raw);
  const columns = { ...DEFAULT_COLUMNS };
  for (const key of COLUMN_ORDER) if (typeof saved?.[key] === "boolean") columns[key] = saved[key];
  return columns;
}

const state = {
  authed: false,
  configured: true,
  totpEnabled: false,
  passkeySupported: false,
  passkeys: [],
  route: location.hash.replace("#/", "") || "dashboard",
  zones: [],
  zoneId: null,
  records: [],
  recordsTotal: 0,
  recordsZoneId: null,
  recordsLoading: false,
  recordsAttemptedZoneId: null,
  recordsError: null,
  search: "",
  typeFilter: "",
  sort: { key: "name", dir: 1 },
  page: 1,
  perPage: readStored("cfddns.perPage", PER_PAGE_OPTIONS[0], (raw) => PER_PAGE_OPTIONS.find((n) => String(n) === raw)),
  view: readStored("cfddns.view", "list") === "card" ? "card" : "list",
  selection: new Set(),
  columns: readStored("cfddns.columns", { ...DEFAULT_COLUMNS }, parseColumns),
  sidebarCollapsed: readStored("cfddns.sidebar", "") === "collapsed",
  mobileNavOpen: false,
  ddns: null,
  ddnsLoading: false,
  ddnsUpdating: false,
  ddnsUpdateResult: null,
  sessionTtl: null,
  backupCodesRemaining: 0,
  config: null,
  pendingChallenge: null,
  pendingBackupCodes: null,
};

let authGeneration = 0;
let pageGeneration = 0;
let recordsRequest = 0;
let ddnsRequest = 0;

const viewMedia = window.matchMedia("(max-width: 600px)");
viewMedia.addEventListener("change", () => {
  if (state.authed && ["dashboard", "records"].includes(state.route)) render();
});

function currentView() { return viewMedia.matches ? "card" : state.view; }

function viewControls() {
  if (viewMedia.matches) return "";
  return `<div class="view-switch" role="group" aria-label="${esc(t("records.view"))}">
    ${["list", "card"].map((view) => `<button class="btn sm ${currentView() === view ? "active" : ""}" data-view="${view}" aria-pressed="${currentView() === view}">${esc(t("records.view." + view))}</button>`).join("")}</div>`;
}

function wireViewControls(redraw) {
  document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => {
    state.view = button.dataset.view;
    writeStored("cfddns.view", state.view);
    redraw();
    document.querySelector(`[data-view="${state.view}"]`)?.focus();
  }));
}

function invalidatePageRequests() {
  pageGeneration++;
  recordsRequest++;
  ddnsRequest++;
  if (state.recordsLoading) state.recordsAttemptedZoneId = null;
  state.recordsLoading = false;
  state.ddnsLoading = false;
  state.mobileNavOpen = false;
  closeMSelects();
  closeModal(true);
}

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

// Uses the largest unit that divides evenly, so a 5-minute session shows "5 min" instead of "0 h".
function fmtDuration(secs) {
  if (secs % 3600 === 0) return `${secs / 3600} h`;
  if (secs % 60 === 0) return `${secs / 60} min`;
  return `${secs} s`;
}

function fmtDate(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString(lang === "en" ? "en-US" : lang, {
      year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  } catch { return iso; }
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// TTL choices for a select. A record may already use a TTL the list does not offer
// (for example 30 or 14400); that value is added as its own option so the select can show it.
function ttlOptions(current) {
  const options = TTL_OPTIONS.map(([v, lbl]) => ({ value: String(v), label: v === 1 ? t("ttl.auto") : lbl }));
  if (Number.isInteger(current) && !TTL_OPTIONS.some(([v]) => v === current)) {
    options.push({ value: String(current), label: fmtTtl(current) });
    options.sort((a, b) => Number(a.value) - Number(b.value));
  }
  return options;
}

// SRV records show their parsed fields; Cloudflare's content string omits the priority.
function displayContent(r) {
  if (r.type !== "SRV" || !r.data) return r.content;
  return `${r.data.priority ?? ""} ${r.data.weight ?? ""} ${r.data.port ?? ""} ${r.data.target ?? r.content}`;
}

/* ================= Validation ================= */

const V = {
  // Leading zeros are rejected because the server's address parser rejects them.
  ipv4(v) { return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(v.trim()) && v.trim().split(".").every((o) => +o <= 255 && !/^0\d/.test(o)); },
  ipv6(v) {
    const s = v.trim();
    // The character check stops input such as "::1]/x" from closing the bracket early;
    // the URL parser then applies the full IPv6 grammar (one "::", at most 8 groups).
    if (!s.includes(":") || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
    try {
      new URL(`http://[${s}]/`);
      return true;
    } catch {
      return false;
    }
  },
  // The last label may hold digits and hyphens so IDN TLDs such as xn--p1ai pass.
  domain(v) { return /^(\*\.)?([a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.?$/.test(v.trim()) || /^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9])?\.?$/.test(v.trim()); },
  recordName(v) { return v === "@" || /^[a-zA-Z0-9_*]([a-zA-Z0-9._-]*)$/.test(v.trim()); },
  // "_sip._tcp" alone is valid: the form adds the zone name, as for any other record.
  srvName(v) { return /^_[a-z0-9-]+\._(tcp|udp|tls)(\..+)?$/i.test(v.trim()); },
  // Digits only: Number() would accept "", "1e3" and "0x10", which parseInt later reads differently.
  uint(v, min, max) {
    const s = String(v).trim();
    return /^\d+$/.test(s) && Number(s) >= min && Number(s) <= max;
  },
};

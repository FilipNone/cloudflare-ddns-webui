/* Cloudflare DDNS Web UI - vanilla JS SPA. No build step, no frameworks. */
/* Entry script, loaded last: page shell, navigation and boot. */
"use strict";

/* ================= Render: root ================= */

function render() {
  closeMSelects();
  const app = el("app");
  if (!state.configured) { renderSetup(app); return; }
  if (!state.authed) { renderLogin(app); return; }
  const route = state.route;
  app.innerHTML = `
    <div class="layout ${state.sidebarCollapsed ? "collapsed" : ""} ${state.mobileNavOpen ? "mobile-open" : ""}" id="layout">
      <aside class="sidebar" id="sidebar">
        <div class="sidebar-brand">
          ${brandLogo()}
          <span>${esc(t("app.name"))}</span>
        </div>
        <nav class="sidebar-nav">
          <button class="nav-item ${route === "dashboard" ? "active" : ""}" data-nav="dashboard" aria-label="${esc(t("nav.dashboard"))}">${I.dashboard}<span class="nav-label">${esc(t("nav.dashboard"))}</span></button>
          <button class="nav-item ${route === "records" ? "active" : ""}" data-nav="records" aria-label="${esc(t("nav.records"))}">${I.dns}<span class="nav-label">${esc(t("nav.records"))}</span></button>
          <button class="nav-item ${route === "settings" ? "active" : ""}" data-nav="settings" aria-label="${esc(t("nav.settings"))}">${I.settings}<span class="nav-label">${esc(t("nav.settings"))}</span></button>
        </nav>
        <div class="sidebar-footer">
          <button class="nav-item" id="collapse-btn" title="${esc(t("nav.collapse"))}">${I.collapse}<span class="nav-label">${esc(t("nav.collapse"))}</span></button>
          <button class="nav-item" id="logout-btn" aria-label="${esc(t("nav.logout"))}">${I.logout}<span class="nav-label">${esc(t("nav.logout"))}</span></button>
        </div>
      </aside>
      <button class="mobile-nav-backdrop" id="mobile-nav-backdrop" aria-label="${esc(t("common.close"))}" tabindex="-1"></button>
      <div class="main">
        <header class="topbar">
          <button class="btn icon mobile-menu-btn" id="mobile-menu-btn" aria-label="${esc(t("nav.menu"))}" aria-controls="sidebar" aria-expanded="${state.mobileNavOpen}">${I.collapse}</button>
          <h1>${esc(t(route === "dashboard" ? "dash.title" : route === "records" ? "records.title" : "settings.title"))}</h1>
          <div class="topbar-actions" id="topbar-actions"></div>
        </header>
        <div id="recovery-notice"></div>
        <main class="content" id="page"></main>
      </div>
    </div>`;

  el("mobile-menu-btn").addEventListener("click", () => toggleMobileNav(!state.mobileNavOpen));
  el("mobile-nav-backdrop").addEventListener("click", () => toggleMobileNav(false));
  app.querySelector(".main").inert = state.mobileNavOpen;

  app.querySelectorAll("[data-nav]").forEach((btn) =>
    btn.addEventListener("click", () => navigate(btn.dataset.nav))
  );
  el("collapse-btn").addEventListener("click", () => {
    state.sidebarCollapsed = !state.sidebarCollapsed;
    writeStored("cfddns.sidebar", state.sidebarCollapsed ? "collapsed" : "expanded");
    el("layout").classList.toggle("collapsed", state.sidebarCollapsed);
  });
  el("logout-btn").addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST", rotatesSession: true, clearsRecoveryCodes: true }); } catch { /* ignore */ }
    state.authed = false;
    resetSessionData();
    state.pendingBackupCodes = null;
    // navigate() also invalidates pending page requests and renders.
    navigate("dashboard");
  });

  renderTopbarActions();
  if (route === "dashboard") renderDashboard();
  else if (route === "records") renderRecords();
  else renderSettings();
  renderRecoveryNotice();
}

function toggleMobileNav(open) {
  state.mobileNavOpen = open;
  el("layout")?.classList.toggle("mobile-open", open);
  el("mobile-menu-btn")?.setAttribute("aria-expanded", String(open));
  const main = el("layout")?.querySelector(".main");
  if (main) main.inert = open;
  if (open) el("sidebar")?.querySelector(".nav-item.active")?.focus();
  else el("mobile-menu-btn")?.focus();
}

window.addEventListener("resize", () => {
  if (window.innerWidth > 900 && state.mobileNavOpen) toggleMobileNav(false);
  closeMSelects();
});

function navigate(route) {
  invalidatePageRequests();
  state.route = route;
  location.hash = `#/${route}`;
  render();
}

window.addEventListener("hashchange", () => {
  const route = location.hash.replace("#/", "") || "dashboard";
  if (route !== state.route) { invalidatePageRequests(); state.route = route; render(); }
});

function renderTopbarActions() {
  const box = el("topbar-actions");
  if (!box) return;
  box.innerHTML = "";
  if (state.route === "records" && state.zones.length > 0) {
    const zoneSelect = mselect({
      id: "zone-select",
      label: t("modal.zone"),
      cls: "u-zone-select",
      options: state.zones.map((z) => ({ value: z.id, label: z.name })),
      value: state.zoneId,
      onChange: async (v) => {
        closeModal();
        state.zoneId = v;
        writeStored("cfddns.zone", v);
        state.search = ""; state.typeFilter = "";
        await refreshRecords();
      },
    });
    box.appendChild(zoneSelect);
  }
}

/* ================= Boot ================= */

async function bootAuthed() {
  const authentication = authGeneration;
  const current = () => authentication === authGeneration && state.authed;
  try {
    const me = await api("/api/auth/me");
    if (!current()) return;
    state.sessionTtl = me.session_ttl;
    state.totpEnabled = !!me.totp_enabled;
    state.backupCodesRemaining = me.backup_codes_remaining ?? 0;
  } catch { /* non-fatal */ }
  if (!current()) return;
  try {
    await loadZones();
  } catch (e) {
    if (current()) toast(e.message, "error");
  }
  if (!current()) return;
  state.ddns = null;
  state.ddnsLoading = false;
  render();
}

(async function boot() {
  applyTheme();
  try {
    state.config = await api("/api/config");
    state.configured = state.config.configured !== false;
    applyAccent(state.config.accent);
    refreshBranding();
  } catch { /* server may still be starting */ }
  if (!state.configured) { render(); return; }
  try {
    const me = await api("/api/auth/me");
    state.authed = !!me.authenticated;
    state.sessionTtl = me.session_ttl;
    state.totpEnabled = !!me.totp_enabled;
    state.backupCodesRemaining = me.backup_codes_remaining ?? 0;
  } catch {
    state.authed = false;
  }
  if (state.authed) await bootAuthed();
  else render();
})();

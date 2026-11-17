/* Dashboard page: IP and zone cards, DDNS status and the manual update. */
"use strict";

/* ================= Render: dashboard ================= */

function renderDashboard() {
  if (!state.authed || state.route !== "dashboard") return;
  const page = el("page");
  if (!page) return;
  page.innerHTML = `
    <div class="stat-grid" id="stat-grid"></div>
    <div id="ddns-section"></div>`;
  renderDashboardCards();
  if (state.ddns === null && !state.ddnsLoading) loadDdns().then(renderDashboard);
}

function ddnsUpdateLog() {
  const result = state.ddnsUpdateResult;
  if (!result) return "";
  const lines = [...(result.log || [])];
  for (const outcome of result.outcomes || []) {
    lines.push(`${outcome.domain} ${outcome.record_type}: ${outcome.status}${outcome.error ? ` - ${outcome.error}` : ""}`);
  }
  return `<div id="ddns-log" class="u-logbox visible" role="status">
    <div class="card-title">${esc(t("dash.ddns.last_update"))}</div>
    <div class="${result.success ? "login-notice" : "login-error visible"}">${esc(t(result.success ? "toast.updated_ddns" : "dash.ddns.update_failed"))}</div>
    <div class="log-output">${esc(lines.join("\n"))}</div></div>`;
}

function ipStatCard(family, d, loading) {
  const ip = d && d[family];
  const value = loading ? '<div class="spinner small"></div>' : esc(ip || (d && d[`${family}_error`]) || t("dash.na"));
  return `<div class="stat-card">
      <div class="stat-label">${I.globe} ${esc(t(`dash.${family}`))}</div>
      <div class="stat-value ${ip ? "" : "na"}">${value}</div>
    </div>`;
}

function ddnsUnconfiguredCard() {
  return `
      <div class="card"><div class="card-pad">
        <div class="card-title">${esc(t("dash.ddns.title"))}</div>
        <div class="card-desc">${esc(t("dash.ddns.desc"))}</div>
        <div class="empty-state u-empty-sm">
          ${I.file}
          <h4>${esc(t("dash.ddns.not_configured"))}</h4>
          <p>${esc(t("dash.ddns.hint"))}</p>
        </div>
      </div>${ddnsUpdateLog()}</div>`;
}

function ddnsStatusBadge(dom) {
  if (dom.error) return `<span class="badge red">${esc(t("dash.ddns.error"))}</span>`;
  if (dom.in_sync) return `<span class="badge green">${esc(t("dash.ddns.synced"))}</span>`;
  if (dom.dns_ips.length === 0) return `<span class="badge yellow">${esc(t("dash.ddns.missing"))}</span>`;
  return `<span class="badge yellow">${esc(t("dash.ddns.out_of_sync"))}</span>`;
}

function ddnsCard(dom) {
  return `<article class="ddns-card">
      <div class="record-card-head"><strong>${esc(dom.domain)}</strong><span class="badge">${esc(dom.record_type)}</span></div>
      <dl class="record-details">
        <div><dt>${esc(t("dash.ddns.detected"))}</dt><dd class="mono">${esc(dom.detected_ip || "-")}</dd></div>
        <div><dt>${esc(t("dash.ddns.dns"))}</dt><dd class="mono">${esc(dom.dns_ips.join(", ") || "-")}</dd></div>
      </dl>
      <div class="record-card-foot">${ddnsStatusBadge(dom)}</div>
      ${dom.error ? `<p class="cell-muted record-error">${esc(dom.error)}</p>` : ""}</article>`;
}

function ddnsRow(dom) {
  return `<tr>
      <td class="name-cell">${esc(dom.domain)}</td>
      <td><span class="badge">${esc(dom.record_type)}</span></td>
      <td class="mono">${esc(dom.detected_ip || "-")}</td>
      <td class="mono">${esc(dom.dns_ips.join(", ") || "-")}</td>
      <td>${ddnsStatusBadge(dom)}${dom.error ? `<div class="cell-muted u-err-detail">${esc(dom.error)}</div>` : ""}</td>
    </tr>`;
}

function ddnsDomainList(domains) {
  const empty = esc(t("dash.ddns.not_configured"));
  if (currentView() === "card") {
    const cards = domains.map(ddnsCard).join("");
    return `<div class="ddns-cards">${state.ddnsLoading ? '<div class="skeleton"></div>' : cards || `<p class="cell-muted">${empty}</p>`}</div>`;
  }
  const rows = domains.map(ddnsRow).join("");
  return `<div class="table-wrap">
        <table class="data">
          <thead><tr>
            <th>${esc(t("dash.ddns.domain"))}</th>
            <th>${esc(t("dash.ddns.type"))}</th>
            <th>${esc(t("dash.ddns.detected"))}</th>
            <th>${esc(t("dash.ddns.dns"))}</th>
            <th>${esc(t("dash.ddns.status"))}</th>
          </tr></thead>
          <tbody>${state.ddnsLoading ? `<tr><td colspan="5"><div class="skeleton"></div></td></tr>` : rows || `<tr><td colspan="5" class="cell-muted u-cell-empty">${empty}</td></tr>`}</tbody>
        </table>
      </div>`;
}

function renderDashboardCards() {
  const grid = el("stat-grid");
  if (!grid) return;
  const d = state.ddns;
  const loading = state.ddnsLoading || d === null;
  grid.innerHTML = `
    ${ipStatCard("ipv4", d, loading)}
    ${ipStatCard("ipv6", d, loading)}
    <div class="stat-card">
      <div class="stat-label">${I.dns} ${esc(t("dash.zones"))}</div>
      <div class="stat-value">${state.zones.length}</div>
    </div>`;

  const section = el("ddns-section");
  if (!section) return;
  if (d && d.configured === false) {
    section.innerHTML = ddnsUnconfiguredCard();
    return;
  }
  const updateDisabled = state.ddnsUpdating || state.ddnsLoading || !d || d.error || d.manual_updates_enabled === false;
  section.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <div class="card-title u-mb0">${esc(t("dash.ddns.title"))}</div>
        <div class="u-flex1"></div>
        ${viewControls()}
        <button class="btn ghost sm" id="ddns-refresh" ${state.ddnsLoading ? "disabled" : ""}>${I.refresh} ${esc(t("records.refresh"))}</button>
        <button class="btn primary sm" id="ddns-update" ${updateDisabled ? "disabled" : ""}>${I.bolt} ${esc(t(state.ddnsUpdating ? "dash.ddns.updating" : "dash.ddns.update_now"))}</button>
      </div>
      ${d?.error ? `<div class="card-pad login-error visible" role="alert">${esc(d.error)}</div>` : ""}
      ${d?.contract_version ? `<div class="card-pad cell-muted">${esc(t("dash.ddns.contract", { contract: d.contract_version }))}</div>` : ""}
      ${ddnsDomainList(d && d.domains ? d.domains : [])}
      ${ddnsUpdateLog()}
    </div>`;

  wireViewControls(renderDashboardCards);
  const refreshBtn = el("ddns-refresh");
  if (refreshBtn) refreshBtn.addEventListener("click", async () => { await loadDdns(); renderDashboard(); });
  const updateBtn = el("ddns-update");
  if (updateBtn) updateBtn.addEventListener("click", runDdnsUpdate);
}

async function runDdnsUpdate() {
  if (state.ddnsUpdating) return;
  const authentication = authGeneration;
  const current = () => authentication === authGeneration && state.authed;
  state.ddnsUpdating = true;
  renderDashboardCards();
  try {
    const res = await api("/api/ddns/update", { method: "POST", json: {} });
    if (!current()) return;
    state.ddnsUpdateResult = res;
    toast(t(res.success ? "toast.updated_ddns" : "dash.ddns.update_failed"), res.success ? "ok" : "error");
  } catch (e) {
    if (!current()) return;
    state.ddnsUpdateResult = { success: false, log: [e.message], outcomes: [] };
    toast(e.message, "error");
  } finally {
    if (current()) {
      state.ddnsUpdating = false;
      if (state.route === "dashboard") renderDashboardCards();
    }
  }
  if (current()) {
    if (state.route === "dashboard") {
      renderDashboardCards();
      await loadDdns();
      if (current()) renderDashboard();
    } else state.ddns = null;
  }
}

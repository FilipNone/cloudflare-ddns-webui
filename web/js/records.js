/* DNS records page: toolbar, filters, list and card views, selection and pagination. */
"use strict";

/* ================= Render: records page ================= */

async function refreshRecords() {
  if (!state.authed || state.route !== "records") return;
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
  if (!state.authed || state.route !== "records") return;
  const page = el("page");
  if (!page) return;
  if (state.zones.length === 0) {
    page.innerHTML = `<div class="card"><div class="empty-state">${I.file}<h4>${esc(t("records.empty.title"))}</h4><p>${esc(t("records.no_zones"))}</p></div></div>`;
    return;
  }
  if (state.zoneId && state.recordsZoneId !== state.zoneId && state.recordsAttemptedZoneId !== state.zoneId && !state.recordsLoading) {
    loadRecords().then(renderRecords);
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
      <div class="toolbar" id="records-toolbar">
        <div class="search-box">${I.search}<input class="input" id="search-input" placeholder="${esc(t("records.search"))}" value="${esc(state.search)}"></div>
        <div class="u-flex1"></div>
        ${viewControls()}
        <div class="dropdown ${currentView() === "card" ? "u-hidden" : ""}">
          <button class="btn" id="columns-btn">${I.columns} ${esc(t("records.columns"))}</button>
          <div class="menu" id="columns-menu">
            <div class="menu-label">${esc(t("records.columns"))}</div>
            ${COLUMN_ORDER.map((c) => `<button class="menu-item" data-col="${c}"><span class="check">${state.columns[c] ? I.check : ""}</span>${esc(t("col." + c))}</button>`).join("")}
          </div>
        </div>
        <button class="btn icon" id="refresh-btn" title="${esc(t("records.refresh"))}" aria-label="${esc(t("records.refresh"))}">${I.refresh}</button>
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

  // Type filter (modern select)
  const typeFilterSelect = mselect({
    options: [{ value: "", label: t("records.all_types") }, ...RECORD_TYPES.map((tp) => ({ value: tp, label: tp }))],
    value: state.typeFilter,
    onChange: (v) => { state.typeFilter = v; state.page = 1; renderRecordsTable(); },
  });
  el("records-toolbar").insertBefore(typeFilterSelect, el("records-toolbar").children[1]);

  el("search-input").addEventListener("input", (e) => {
    state.search = e.target.value;
    state.page = 1;
    renderRecordsTable();
  });
  wireViewControls(renderRecords);
  if (currentView() === "card") {
    el("records-toolbar").insertBefore(mselect({
      label: t("records.sort"),
      options: SORT_KEYS.flatMap((key) => [1, -1].map((dir) => ({ value: `${key}:${dir}`, label: `${t("col." + key)} ${dir === 1 ? "\u2191" : "\u2193"}` }))),
      value: `${state.sort.key}:${state.sort.dir}`,
      onChange: (value) => { const [key, dir] = value.split(":"); state.sort = { key, dir: Number(dir) }; renderRecordsTable(); },
    }), el("refresh-btn"));
  }
  bindDropdown("columns-btn", "columns-menu");
  document.querySelectorAll("#columns-menu [data-col]").forEach((b) =>
    b.addEventListener("click", () => {
      state.columns[b.dataset.col] = !state.columns[b.dataset.col];
      writeStored("cfddns.columns", JSON.stringify(state.columns));
      closeMSelects();
      renderRecords();
    })
  );
  el("refresh-btn").addEventListener("click", refreshRecords);
  el("add-btn").addEventListener("click", () => openRecordModal(null));
  el("export-btn").addEventListener("click", exportZone);
  el("import-btn").addEventListener("click", openImportModal);
  el("bulk-edit").addEventListener("click", openBulkEditModal);
  // Wrapped so the click event is not taken as the list of ids.
  el("bulk-delete").addEventListener("click", () => openBulkDeleteModal());
  el("bulk-clear").addEventListener("click", () => { state.selection.clear(); renderRecordsTable(); });

  renderRecordsTable();
}

// List view cells, keyed like COLUMN_ORDER.
const RECORD_CELLS = {
  type: (r) => `<td><span class="badge">${esc(r.type)}</span></td>`,
  name: (r) => `<td class="name-cell" title="${esc(r.name)}">${esc(r.name)}</td>`,
  content: (r) => `<td class="mono truncate cell-copy" data-copy="${esc(r.content)}" title="${esc(t("common.copy"))}: ${esc(r.content)}">${esc(displayContent(r))}</td>`,
  proxy: (r) => {
    if (!r.proxiable) return `<td><span class="proxy-pill" title="${esc(t("proxy.na"))}">${I.cloud}<span class="cell-muted">-</span></span></td>`;
    const on = !!r.proxied;
    return `<td><span class="proxy-pill ${on ? "on" : "off"}">${on ? I.cloudFill : I.cloud}<span>${esc(on ? t("proxy.proxied") : t("proxy.dns_only"))}</span></span></td>`;
  },
  ttl: (r) => `<td>${esc(fmtTtl(r.ttl))}</td>`,
  tags: (r) => `<td class="truncate">${(r.tags || []).map((tag) => `<span class="tag-chip">${esc(tag)}</span>`).join("") || '<span class="cell-muted">-</span>'}</td>`,
  comment: (r) => `<td class="truncate cell-muted" title="${esc(r.comment || "")}">${esc(r.comment || "-")}</td>`,
  updated: (r) => `<td class="cell-muted u-nowrap">${esc(fmtDate(r.modified_on))}</td>`,
  created: (r) => `<td class="cell-muted u-nowrap">${esc(fmtDate(r.created_on))}</td>`,
};
const SORT_KEYS = ["name", "type", "content", "ttl", "updated", "created"];

function visibleColumns() { return COLUMN_ORDER.filter((key) => state.columns[key]); }

function sortHeader(key) {
  const active = state.sort.key === key;
  const arrow = active ? `<span class="sort-arrow" aria-hidden="true">${state.sort.dir === 1 ? "▲" : "▼"}</span>` : "";
  const sort = active ? ` aria-sort="${state.sort.dir === 1 ? "ascending" : "descending"}"` : "";
  return `<th class="sortable"${sort}><button type="button" class="sort-btn" data-sort="${key}">${esc(t("col." + key))}${arrow}</button></th>`;
}

function recordsTableHead() {
  const cols = visibleColumns().map((key) => SORT_KEYS.includes(key) ? sortHeader(key) : `<th>${esc(t("col." + key))}</th>`);
  return `<tr><th class="u-w-check"><input type="checkbox" class="checkbox" id="select-all" aria-label="${esc(t("records.select_all"))}"></th>${cols.join("")}<th class="u-w-actions">${esc(t("col.actions"))}</th></tr>`;
}

function recordRow(r) {
  const selected = state.selection.has(r.id);
  return `<tr class="${selected ? "selected" : ""}" data-row="${esc(r.id)}">`
    + `<td><input type="checkbox" class="checkbox" data-select="${esc(r.id)}" aria-label="${esc(t("records.select", { name: r.name }))}"${selected ? " checked" : ""}></td>`
    + visibleColumns().map((key) => RECORD_CELLS[key](r)).join("")
    + `<td class="u-nowrap">
      <button class="btn ghost icon sm" data-edit="${esc(r.id)}" title="${esc(t("records.edit"))}">${I.edit}</button>
      <button class="btn ghost icon sm danger" data-delete="${esc(r.id)}" title="${esc(t("records.delete"))}">${I.trash}</button>
    </td></tr>`;
}

function recordsSkeleton() {
  if (currentView() === "card") return `<div class="record-cards">${Array.from({ length: 3 }, () => '<div class="record-card"><div class="skeleton"></div></div>').join("")}</div>`;
  return `<table class="data"><tbody>
      ${Array.from({ length: 5 }).map(() => `<tr class="skeleton-row"><td colspan="8"><div class="skeleton"></div></td></tr>`).join("")}
    </tbody></table>`;
}

function recordsListHtml(rows) {
  if (rows.length === 0) return `<div class="empty-state">${I.file}<h4>${esc(t("records.empty.title"))}</h4><p>${esc(t("records.empty.desc"))}</p></div>`;
  if (currentView() === "card") return `<label class="card-select-all"><input type="checkbox" id="select-all">${esc(t("records.select_all"))}</label><div class="record-cards">${rows.map(recordCard).join("")}</div>`;
  return `<table class="data"><thead>${recordsTableHead()}</thead><tbody>${rows.map(recordRow).join("")}</tbody></table>`;
}

function renderRecordsTable() {
  const wrap = el("table-wrap");
  if (!wrap) return;

  if (state.recordsLoading || state.recordsError || state.recordsZoneId !== state.zoneId) {
    wrap.innerHTML = state.recordsLoading ? recordsSkeleton()
      : `<div class="card-pad login-error visible" role="alert">${esc(state.recordsError || t("records.empty.desc"))}</div>`;
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

  wrap.innerHTML = recordsListHtml(rows);
  wireRecordsTable(wrap, rows);
  renderPagination(total, from, rows.length);
  updateBulkbar();
}

// Re-rendering replaces the controls, so handlers move focus to the replacement
// when the clicked control had it (keyboard users keep their place).
function wireRecordsTable(wrap, rows) {
  const selectAll = el("select-all");
  if (selectAll) {
    const pageIds = rows.map((r) => r.id);
    const selectedOnPage = pageIds.filter((id) => state.selection.has(id)).length;
    selectAll.checked = selectedOnPage > 0 && selectedOnPage === pageIds.length;
    selectAll.indeterminate = selectedOnPage > 0 && selectedOnPage < pageIds.length;
    selectAll.addEventListener("click", () => {
      const focused = document.activeElement === selectAll;
      if (selectedOnPage === pageIds.length) pageIds.forEach((id) => state.selection.delete(id));
      else pageIds.forEach((id) => state.selection.add(id));
      renderRecordsTable();
      if (focused) el("select-all")?.focus();
    });
  }
  wrap.querySelectorAll("[data-select]").forEach((cb) =>
    cb.addEventListener("click", () => {
      const id = cb.dataset.select;
      const focused = document.activeElement === cb;
      if (state.selection.has(id)) state.selection.delete(id);
      else state.selection.add(id);
      renderRecordsTable();
      if (focused) [...wrap.querySelectorAll("[data-select]")].find((item) => item.dataset.select === id)?.focus();
    })
  );
  wrap.querySelectorAll("[data-sort]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const key = btn.dataset.sort;
      const focused = document.activeElement === btn;
      if (state.sort.key === key) state.sort.dir *= -1;
      else state.sort = { key, dir: 1 };
      renderRecordsTable();
      if (focused) wrap.querySelector(`[data-sort="${key}"]`)?.focus();
    })
  );
  wrap.querySelectorAll("[data-copy]").forEach((td) =>
    td.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(td.dataset.copy); toast(t("common.copied")); } catch { /* clipboard unavailable */ }
    })
  );
  wrap.querySelectorAll("[data-edit]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const rec = state.records.find((r) => r.id === btn.dataset.edit);
      if (rec) openRecordModal(rec);
    })
  );
  // A row's own delete button leaves the checkbox selection alone.
  wrap.querySelectorAll("[data-delete]").forEach((btn) =>
    btn.addEventListener("click", () => openBulkDeleteModal([btn.dataset.delete]))
  );
}

function recordCard(r) {
  const selected = state.selection.has(r.id);
  return `<article class="record-card ${selected ? "selected" : ""}" data-row="${esc(r.id)}">
    <div class="record-card-head">
      <input type="checkbox" data-select="${esc(r.id)}" aria-label="${esc(t("records.select", { name: r.name }))}" ${selected ? "checked" : ""}>
      <strong>${esc(r.name)}</strong><span class="badge">${esc(r.type)}</span>
    </div>
    <button class="record-content mono cell-copy" data-copy="${esc(r.content)}" title="${esc(t("common.copy"))}">${esc(displayContent(r))}</button>
    <dl class="record-details">
      <div><dt>${esc(t("col.proxy"))}</dt><dd><span class="proxy-pill ${r.proxiable ? r.proxied ? "on" : "off" : ""}">${r.proxied ? I.cloudFill : I.cloud} ${esc(t(r.proxiable ? r.proxied ? "proxy.proxied" : "proxy.dns_only" : "proxy.na"))}</span></dd></div>
      <div><dt>${esc(t("col.ttl"))}</dt><dd>${esc(fmtTtl(r.ttl))}</dd></div>
      ${r.comment ? `<div class="record-detail-full"><dt>${esc(t("col.comment"))}</dt><dd>${esc(r.comment)}</dd></div>` : ""}
      ${r.tags?.length ? `<div class="record-detail-full"><dt>${esc(t("col.tags"))}</dt><dd>${r.tags.map((tag) => `<span class="tag-chip">${esc(tag)}</span>`).join("")}</dd></div>` : ""}
      ${["updated", "created"].filter((key) => state.columns[key]).map((key) => `<div class="record-detail-full"><dt>${esc(t("col." + key))}</dt><dd>${esc(fmtDate(key === "updated" ? r.modified_on : r.created_on))}</dd></div>`).join("")}
    </dl>
    <div class="record-card-foot">
      <button class="btn sm" data-edit="${esc(r.id)}">${I.edit} ${esc(t("records.edit"))}</button>
      <button class="btn sm danger" data-delete="${esc(r.id)}">${I.trash} ${esc(t("records.delete"))}</button>
    </div></article>`;
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
    <span id="per-page-slot"></span>
    <div class="page-btns">
      <button class="btn icon sm" id="page-prev" ${state.page <= 1 ? "disabled" : ""}>${I.chevronLeft}</button>
      <button class="btn icon sm" id="page-next" ${state.page >= pages ? "disabled" : ""}>${I.chevronRight}</button>
    </div>`;
  el("per-page-slot").replaceWith(mselect({
    options: PER_PAGE_OPTIONS.map((n) => ({ value: String(n), label: String(n) })),
    value: String(state.perPage),
    onChange: (v) => {
      state.perPage = parseInt(v, 10);
      writeStored("cfddns.perPage", String(state.perPage));
      state.page = 1;
      renderRecordsTable();
    },
  }));
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

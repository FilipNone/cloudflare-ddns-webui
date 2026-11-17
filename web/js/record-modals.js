/* Record dialogs: add and edit, bulk edit, delete, and zone file import and export. */
"use strict";

/* ----- Comment and tags ----- */

// Same limit as MAX_RECORD_COMMENT in src/config.rs, which counts UTF-8 bytes.
const MAX_COMMENT_BYTES = 500;

function utf8Length(s) {
  let bytes = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    bytes += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
  }
  return bytes;
}

function metadataPatch(field, mode, raw) {
  if (mode === "keep") return {};
  if (mode === "clear") return { [field]: field === "tags" ? [] : "" };
  const value = field === "tags" ? raw.split(",").map((tag) => tag.trim()).filter(Boolean) : raw.trim();
  if (!value.length) throw new Error(t("modal.metadata.empty"));
  // The server rejects the same comments; checking here keeps the form open with the text intact.
  if (field === "comment" && (utf8Length(value) > MAX_COMMENT_BYTES || /[\u0000-\u001f\u007f-\u009f]/.test(value))) {
    throw new Error(t("modal.comment.invalid", { max: MAX_COMMENT_BYTES }));
  }
  return { [field]: value };
}

function metadataFields(prefix, rec, keep) {
  return ["comment", "tags"].map((field) => `<div class="field metadata-field">
    <span>${esc(t("modal." + field))}</span>
    ${keep ? `<span id="${prefix}-${field}-mode"></span>` : ""}
    <label class="field ${keep ? "u-hidden" : ""}" id="${prefix}-${field}-wrap">
      <input class="input" id="${prefix}-${field}" aria-label="${esc(t("modal." + field))}" value="${esc(field === "tags" ? (rec?.tags || []).join(", ") : rec?.comment || "")}" ${field === "comment" ? `maxlength="${MAX_COMMENT_BYTES}"` : 'placeholder="owner:test"'}>
      <div class="field-hint">${esc(t(`modal.${field}.hint`))}</div>
    </label></div>`).join("");
}

function wireMetadata(modal, prefix) {
  for (const field of ["comment", "tags"]) {
    modal.querySelector(`#${prefix}-${field}-mode`).replaceWith(mselect({
      id: `${prefix}-${field}-mode`,
      label: t("modal." + field),
      options: ["keep", "set", "clear"].map((mode) => ({ value: mode, label: t("modal.metadata." + mode) })),
      value: "keep",
      onChange: (mode) => modal.querySelector(`#${prefix}-${field}-wrap`).classList.toggle("u-hidden", mode !== "set"),
    }));
  }
}

/* ----- Add / edit record ----- */

// One labelled input of the record form. Fields are required unless optional is set;
// markValidity() writes the error text, so the error element starts empty.
function inputField(id, labelKey, value, { type = "text", max = 65535, placeholder = "", v = "", full = false, optional = false, hint = "" } = {}) {
  const attrs = [
    `class="input" id="${id}"`,
    type === "number" ? `type="number" min="0" max="${max}"` : "",
    `value="${esc(value)}"`,
    placeholder ? `placeholder="${esc(placeholder)}"` : "",
    v ? `data-v="${v}"` : "",
    optional ? "" : "required",
  ].filter(Boolean).join(" ");
  return `<label class="field${full ? " full" : ""}"><span>${esc(t(labelKey))}${optional ? "" : " *"}</span>
          <input ${attrs}>
          ${hint ? `<div class="field-hint">${esc(hint)}</div>` : `<div class="field-error" data-err="${id}"></div>`}</label>`;
}

function typeSpecificFields(type, rec) {
  const d = (rec && rec.data) || {};
  if (type === "MX") {
    return inputField("f-content", "modal.content.MX", rec ? rec.content : "", { placeholder: "mail.example.com", v: "domain" })
      + inputField("f-priority", "modal.priority", rec && rec.priority != null ? rec.priority : 10, { type: "number" });
  }
  if (type === "SRV") {
    return `
      <div class="form-grid">
        ${inputField("f-srv-priority", "modal.srv.priority", d.priority ?? 0, { type: "number" })}
        ${inputField("f-srv-weight", "modal.srv.weight", d.weight ?? 5, { type: "number" })}
        ${inputField("f-srv-port", "modal.srv.port", d.port ?? "", { type: "number", placeholder: "25565" })}
        ${inputField("f-srv-target", "modal.srv.target", d.target ?? "", { placeholder: "mc.example.com", v: "domain" })}
      </div>`;
  }
  if (type === "CAA") {
    return `
      <div class="form-grid">
        ${inputField("f-caa-flags", "modal.caa.flags", d.flags ?? 0, { type: "number", max: 255 })}
        <div class="field"><span>${esc(t("modal.caa.tag"))} *</span><span id="f-caa-tag-slot"></span></div>
        ${inputField("f-caa-value", "modal.caa.value", d.value ?? "", { placeholder: "letsencrypt.org", full: true })}
      </div>`;
  }
  if (type === "HTTPS" || type === "SVCB") {
    return `
      <div class="form-grid">
        ${inputField("f-svc-priority", "modal.svc.priority", d.priority ?? 1, { type: "number" })}
        ${inputField("f-svc-target", "modal.svc.target", d.target ?? "", { placeholder: ". or example.com" })}
        ${inputField("f-svc-value", "modal.svc.value", d.value ?? "", { placeholder: 'alpn="h3,h2"', full: true, optional: true, hint: t("modal.svc.value.hint") })}
      </div>`;
  }
  const labelKey = `modal.content.${type}`;
  const placeholders = {
    A: "192.0.2.1", AAAA: "2001:db8::1", CNAME: "example.com",
    TXT: "v=spf1 include:example.com ~all", NS: "ns1.example.com", PTR: "example.com",
  };
  const validators = { A: "ipv4", AAAA: "ipv6", CNAME: "domain", NS: "domain", PTR: "domain" };
  return inputField("f-content", t(labelKey) === labelKey ? "modal.content" : labelKey, rec ? rec.content : "", {
    placeholder: placeholders[type] || "", v: validators[type] || "",
  });
}

function wireTypeSelectValidation(modal) {
  // CAA tag modern select.
  const tagSlot = modal.querySelector("#f-caa-tag-slot");
  if (tagSlot) {
    const current = (modal.dataset.caaTag || "issue");
    tagSlot.replaceWith(mselect({
      id: "f-caa-tag-slot",
      options: ["issue", "issuewild", "iodef"].map((tag) => ({ value: tag, label: tag })),
      value: current,
      onChange: (v) => { modal.dataset.caaTag = v; },
    }));
  }
  // Live validation.
  modal.querySelectorAll("#type-fields input").forEach((input) => {
    input.addEventListener("input", () => markValidity(modal, input));
  });
}

const INVALID_KEYS = { ipv4: "modal.invalid.ipv4", ipv6: "modal.invalid.ipv6", domain: "modal.invalid.domain" };

// The error message for one form input, or "" when the value is acceptable.
function fieldError(input) {
  // A number input reports "" for text such as "-" or "e", so check badInput before the empty check.
  if (input.type === "number" && input.validity?.badInput) {
    return t("modal.invalid.number", { min: Number(input.min || 0), max: Number(input.max || 65535) });
  }
  const val = input.value.trim();
  if (val === "") return input.required ? t("modal.required") : "";
  const kind = input.dataset.v;
  if (kind && !V[kind](val)) return t(INVALID_KEYS[kind]);
  if (input.type === "number") {
    const min = Number(input.min || 0), max = Number(input.max || 65535);
    if (!V.uint(val, min, max)) return t("modal.invalid.number", { min, max });
  }
  return "";
}

// While typing, only fields with content are flagged; a save attempt (submitted) also flags empty required fields.
function markValidity(modal, input, submitted = false) {
  const message = fieldError(input);
  const show = message !== "" && (submitted || input.value.trim() !== "");
  input.classList.toggle("invalid", show);
  const err = modal.querySelector(`[data-err="${input.id}"]`);
  if (err) {
    err.textContent = message;
    err.classList.toggle("visible", show);
  }
  return message === "";
}

// SRV names follow _service._proto.name, so they get their own message.
function markName(modal, type, submitted = false) {
  const input = modal.querySelector("#f-name");
  const value = input.value.trim();
  const ok = type === "SRV" ? V.srvName(value) : V.recordName(value);
  const show = !ok && (submitted || value !== "");
  input.classList.toggle("invalid", show);
  const err = modal.querySelector('[data-err="f-name"]');
  err.textContent = t(type === "SRV" ? "modal.invalid.srvname" : "modal.invalid.name");
  err.classList.toggle("visible", show);
  return ok;
}

// Proxied records always use TTL 1 (Auto) and the backend enforces that, so the TTL select
// shows Auto and locks while proxied. Turning the proxy off brings back the earlier choice.
function lockTtlWhenProxied(ttlSelect, hint) {
  let before = null;
  return (proxied) => {
    if (proxied && before === null) {
      before = ttlSelect.mget();
      ttlSelect.mset("1");
    }
    if (!proxied && before !== null) {
      ttlSelect.mset(before);
      before = null;
    }
    ttlSelect.msetDisabled(proxied);
    hint.classList.toggle("u-hidden", !proxied);
  };
}

function recordModalHtml(rec, zoneName, type) {
  const isEdit = !!rec;
  return `
    ${modalHead(isEdit ? t("modal.edit.title") : t("modal.add.title"))}
    <div class="modal-body">
      <div class="zone-suffix-banner">${I.dns} <span>${esc(t("modal.zone"))}:</span> <strong>${esc(zoneName)}</strong></div>
      <div class="form-grid">
        <div class="field"><span>${esc(t("modal.type"))}</span><span id="f-type-slot"></span></div>
        <label class="field"><span>${esc(t("modal.name"))} *</span>
          <input class="input" id="f-name" value="${esc(rec ? shortName(rec.name, zoneName) : "")}" placeholder="subdomain" ${isEdit ? "disabled" : ""}>
          <div class="field-hint">${esc(t("modal.name.hint", { zone: zoneName }))}</div>
          <div class="field-error" data-err="f-name"></div></label>
      </div>
      <div id="type-fields">${typeSpecificFields(type, rec)}</div>
      <div class="form-grid">
        <div class="field"><span>${esc(t("modal.ttl"))}</span><span id="f-ttl-slot"></span>
          <div class="field-hint u-hidden" id="f-ttl-hint">${esc(t("modal.ttl.proxied"))}</div></div>
        <div class="field">
          <span>&nbsp;</span>
          <div class="switch-row">
            <label class="switch"><input type="checkbox" id="f-proxied" ${rec?.proxied ? "checked" : ""} ${PROXIABLE.includes(type) ? "" : "disabled"}><span class="track"></span></label>
            <span class="lbl">${esc(t("modal.proxy"))}</span>
          </div>
        </div>
      </div>
      ${metadataFields("f", rec, isEdit)}
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="f-save">${esc(isEdit ? t("modal.save") : t("modal.create"))}</button>
    </div>`;
}

function openRecordModal(rec) {
  const isEdit = !!rec;
  const zone = currentZone();
  const zoneId = state.zoneId;
  const zoneName = zone ? zone.name : "";
  const type = rec ? rec.type : "A";

  const modal = openModal(recordModalHtml(rec, zoneName, type), true);
  modal.dataset.caaTag = (rec && rec.data && rec.data.tag) || "issue";
  let currentType = type;
  if (isEdit) wireMetadata(modal, "f");

  // TTL modern select.
  const ttlSelect = mselect({
    id: "f-ttl-slot",
    options: ttlOptions(rec?.ttl),
    value: String(rec ? rec.ttl ?? 1 : 1),
  });
  modal.querySelector("#f-ttl-slot").replaceWith(ttlSelect);
  const proxiedInput = modal.querySelector("#f-proxied");
  const lockTtl = lockTtlWhenProxied(ttlSelect, modal.querySelector("#f-ttl-hint"));
  const syncTtlAvailability = () => lockTtl(proxiedInput.checked && PROXIABLE.includes(currentType));

  // Type modern select.
  modal.querySelector("#f-type-slot").replaceWith(mselect({
    id: "f-type-slot",
    options: RECORD_TYPES.map((tp) => ({ value: tp, label: tp })),
    value: type,
    disabled: isEdit,
    onChange: (v) => {
      currentType = v;
      modal.querySelector("#type-fields").innerHTML = typeSpecificFields(v, null);
      proxiedInput.disabled = !PROXIABLE.includes(v);
      if (proxiedInput.disabled) proxiedInput.checked = false;
      syncTtlAvailability();
      wireTypeSelectValidation(modal);
      // SRV names follow different rules, so recheck a name that was already typed.
      if (!isEdit) markName(modal, v);
    },
  }));

  proxiedInput.addEventListener("change", syncTtlAvailability);
  syncTtlAvailability();
  wireTypeSelectValidation(modal);
  modal.querySelector("#f-name").addEventListener("input", () => markName(modal, currentType));

  modal.querySelector("#f-save").addEventListener("click", async () => {
    const payload = buildPayload(modal, currentType, zoneName, isEdit ? rec : null, ttlSelect);
    if (!payload) return;
    const restore = showBusy(modal.querySelector("#f-save"));
    try {
      if (isEdit) {
        await api(`/api/zones/${zoneId}/records/${rec.id}`, { method: "PUT", json: payload });
        toast(t("toast.saved"));
      } else {
        await api(`/api/zones/${zoneId}/records`, { method: "POST", json: payload });
        toast(t("toast.created"));
      }
      if (modal.isConnected) closeModal();
      if (state.zoneId === zoneId) await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      restore();
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
  if (s.endsWith(`.${zoneName}`) || s === zoneName) return s;
  return `${s}.${zoneName}`;
}

function buildPayload(modal, type, zoneName, rec, ttlSelect) {
  const val = (sel) => { const x = modal.querySelector(sel); return x ? x.value.trim() : ""; };
  const isEdit = !!rec;

  // Validate all visible inputs first.
  let allOk = true;
  modal.querySelectorAll("#type-fields input").forEach((input) => {
    if (!markValidity(modal, input, true)) allOk = false;
  });
  if (!isEdit && !markName(modal, type, true)) allOk = false;
  if (!allOk) { toast(t("modal.invalid"), "error"); return null; }

  const name = isEdit ? rec.name : fullName(val("#f-name"), zoneName);
  const proxied = PROXIABLE.includes(type) ? modal.querySelector("#f-proxied").checked : false;
  const ttl = proxied ? 1 : parseInt(ttlSelect.mget(), 10) || 1;
  const payload = { type, name, ttl, proxied };
  try {
    for (const field of ["comment", "tags"]) {
      const raw = val(`#f-${field}`);
      const mode = isEdit ? modal.querySelector(`#f-${field}-mode`).mget() : raw ? "set" : "keep";
      Object.assign(payload, metadataPatch(field, mode, raw));
    }
  } catch (e) {
    toast(e.message, "error");
    return null;
  }
  if (type === "MX") {
    payload.content = val("#f-content");
    payload.priority = parseInt(val("#f-priority"), 10);
  } else if (type === "SRV") {
    payload.data = {
      priority: parseInt(val("#f-srv-priority"), 10),
      weight: parseInt(val("#f-srv-weight"), 10),
      port: parseInt(val("#f-srv-port"), 10),
      target: val("#f-srv-target"),
    };
    payload.content = `${payload.data.weight} ${payload.data.port} ${payload.data.target}`;
  } else if (type === "CAA") {
    payload.data = { flags: parseInt(val("#f-caa-flags"), 10), tag: modal.dataset.caaTag || "issue", value: val("#f-caa-value") };
    payload.content = `${payload.data.flags} ${payload.data.tag} "${payload.data.value}"`;
  } else if (type === "HTTPS" || type === "SVCB") {
    payload.data = { priority: parseInt(val("#f-svc-priority"), 10), target: val("#f-svc-target") };
    const svcValue = val("#f-svc-value");
    if (svcValue) payload.data.value = svcValue;
    payload.content = `${payload.data.priority} ${payload.data.target}${svcValue ? " " + svcValue : ""}`;
  } else {
    payload.content = val("#f-content");
  }
  return payload;
}

/* ----- Bulk edit ----- */

// The bulk endpoint answers 200 with per-record results, so failures must be read from the body.
function bulkResultToast(action, res) {
  const ok = res.succeeded || 0;
  const failed = res.failed || 0;
  if (!failed) {
    toast(t(`toast.bulk_${action}`, { ok }));
    return;
  }
  const summary = ok ? t(`toast.bulk_${action}.partial`, { ok, n: failed }) : t(`toast.bulk_${action}.none`, { n: failed });
  const error = (res.results || []).find((item) => !item.ok)?.error;
  toast(error ? t("toast.with_error", { summary, error }) : summary, "error");
}

function openBulkEditModal() {
  const zoneId = state.zoneId;
  const selected = state.records.filter((r) => state.selection.has(r.id));
  if (selected.length === 0) return;
  const allProxiable = selected.every((r) => PROXIABLE.includes(r.type));
  const nonProxiableTypes = [...new Set(selected.filter((r) => !PROXIABLE.includes(r.type)).map((r) => r.type))];

  const modal = openModal(`
    ${modalHead(t("modal.bulk.title", { n: selected.length }))}
    <div class="modal-body">
      <div class="form-grid">
        <div class="field"><span>${esc(t("modal.bulk.ttl"))}</span><span id="b-ttl-slot"></span>
          <div class="field-hint u-hidden" id="b-ttl-hint">${esc(t("modal.ttl.proxied"))}</div></div>
        <div class="field"><span>${esc(t("modal.bulk.proxy"))}</span><span id="b-proxy-slot"></span></div>
      </div>
      ${allProxiable ? "" : `<div class="login-error visible u-mb16">${esc(t("modal.bulk.proxy.blocked"))} (${esc(nonProxiableTypes.join(", "))})</div>`}
      ${metadataFields("b", null, true)}
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="b-apply">${esc(t("modal.bulk.apply", { n: selected.length }))}</button>
    </div>`);

  const ttlSelect = mselect({
    options: [{ value: "", label: t("modal.bulk.keep") }, ...ttlOptions()],
    value: "",
  });
  modal.querySelector("#b-ttl-slot").replaceWith(ttlSelect);
  const lockTtl = lockTtlWhenProxied(ttlSelect, modal.querySelector("#b-ttl-hint"));

  const proxySelect = mselect({
    options: [
      { value: "", label: t("modal.bulk.keep") },
      { value: "true", label: t("modal.bulk.proxy.on") },
      { value: "false", label: t("modal.bulk.proxy.off") },
    ],
    value: "",
    disabled: !allProxiable,
    onChange: (v) => lockTtl(v === "true"),
  });
  modal.querySelector("#b-proxy-slot").replaceWith(proxySelect);

  wireMetadata(modal, "b");

  modal.querySelector("#b-apply").addEventListener("click", async () => {
    const patch = {};
    const ttlV = ttlSelect.mget();
    if (ttlV) patch.ttl = parseInt(ttlV, 10);
    const proxV = proxySelect.mget();
    if (proxV) patch.proxied = proxV === "true";
    try {
      for (const field of ["comment", "tags"]) {
        Object.assign(patch, metadataPatch(field, modal.querySelector(`#b-${field}-mode`).mget(), modal.querySelector(`#b-${field}`).value));
      }
    } catch (e) {
      toast(e.message, "error");
      return;
    }
    if (Object.keys(patch).length === 0) { closeModal(); return; }
    const restore = showBusy(modal.querySelector("#b-apply"));
    try {
      const res = await api(`/api/zones/${zoneId}/records/bulk`, {
        method: "POST",
        json: { action: "update", ids: selected.map((record) => record.id), patch },
      });
      bulkResultToast("update", res);
      if (modal.isConnected) closeModal();
      if (state.zoneId === zoneId) await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      restore();
    }
  });
}

/* ----- Delete (single or bulk) ----- */

// ids defaults to the checkbox selection; a row's delete button passes just its own id.
function openBulkDeleteModal(ids = [...state.selection]) {
  const zoneId = state.zoneId;
  const n = ids.length;
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
    const restore = showBusy(modal.querySelector("#d-confirm"));
    try {
      const res = await api(`/api/zones/${zoneId}/records/bulk`, {
        method: "POST",
        json: { action: "delete", ids },
      });
      bulkResultToast("delete", res);
      if (modal.isConnected) closeModal();
      if (state.zoneId === zoneId) await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      restore();
    }
  });
}

/* ----- Import / export ----- */

function openImportModal() {
  const zoneId = state.zoneId;
  const modal = openModal(`
    ${modalHead(t("modal.import.title"))}
    <div class="modal-body">
      <p class="u-note-sm">${esc(t("modal.import.desc"))}</p>
      <div class="dropzone" id="dropzone">
        ${I.file}
        <div class="u-mt8" id="drop-label">${tHtml("modal.import.drop.html")}</div>
      </div>
      <input type="file" id="file-input" accept=".txt,.zone,text/plain" class="u-hidden">
      <div class="field-error" id="import-error"></div>
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
  const errBox = modal.querySelector("#import-error");

  function setFile(f) {
    errBox.classList.remove("visible");
    if (!f) return;
    file = null;
    submit.disabled = true;
    if (f.size > 2 * 1024 * 1024) {
      showError(errBox, t("modal.import.too_big"));
      return;
    }
    file = f;
    label.textContent = t("modal.import.file_selected", { name: f.name, size: fmtBytes(f.size) });
    submit.disabled = false;
  }

  dz.addEventListener("click", () => fi.click());
  dz.addEventListener("dragover", (e) => { e.preventDefault(); e.stopPropagation(); dz.classList.add("drag"); });
  dz.addEventListener("dragleave", (e) => { e.preventDefault(); dz.classList.remove("drag"); });
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    dz.classList.remove("drag");
    if (e.dataTransfer.files && e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });
  fi.addEventListener("change", () => { if (fi.files.length) setFile(fi.files[0]); });

  submit.addEventListener("click", async () => {
    if (!file) return;
    const selectedFile = file;
    const restore = showBusy(submit);
    try {
      const bytes = await selectedFile.arrayBuffer();
      if (!modal.isConnected) return;
      const res = await api(`/api/zones/${zoneId}/import?filename=${encodeURIComponent(selectedFile.name)}`, {
        method: "POST", raw: bytes,
      });
      const added = res.recs_added ?? 0;
      const parsed = res.total_records_parsed ?? 0;
      toast(t("modal.import.result", { added, parsed }), added > 0 ? "ok" : "info");
      if (parsed > added) {
        toast(t("modal.import.skipped", { n: parsed - added }), "info");
      }
      if (modal.isConnected) closeModal();
      if (state.zoneId === zoneId) await refreshRecords();
    } catch (e) {
      showError(errBox, e.message);
      restore();
    }
  });
}

async function exportZone() {
  const zone = currentZone();
  try {
    const text = await api(`/api/zones/${state.zoneId}/export`, { text: true });
    downloadText(`${zone ? zone.name : "zone"}.txt`, text);
    toast(t("toast.exported"));
  } catch (e) {
    toast(e.message, "error");
  }
}

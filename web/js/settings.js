/* Settings page: appearance, security, 2FA enrollment, recovery codes and password change. */
"use strict";

/* ================= Render: settings ================= */

function appearanceCard() {
  return `<div class="card"><div class="card-pad">
        <div class="card-title">${I.palette} ${esc(t("settings.appearance.title"))}</div>
        <div class="card-desc">${esc(t("settings.appearance.desc"))}</div>
        <div class="settings-row">
          <div class="grow">
            <div class="lbl">${esc(t("settings.theme"))}</div>
          </div>
          <span id="settings-theme-slot"></span>
        </div>
        <div class="settings-sep"></div>
        <div class="settings-row">
          <div class="grow">
            <div class="lbl">${esc(t("settings.lang.title"))}</div>
            <div class="hint">${esc(t("settings.lang.desc"))}</div>
          </div>
          <span id="settings-lang-slot"></span>
        </div>
        <div class="settings-sep"></div>
        <div class="settings-row u-row-start">
          <div class="grow">
            <div class="lbl">${esc(t("settings.accent"))}</div>
            <div class="hint">${esc(t("settings.accent.hint"))}</div>
            <div class="swatch-row u-mt8" id="accent-row"></div>
          </div>
        </div>
        <div class="settings-sep"></div>
        <div class="settings-row">
          <div class="grow">
            <div class="lbl">${esc(t("settings.icon"))}</div>
            <div class="hint">${esc(t("settings.icon.hint"))}</div>
          </div>
          ${brandLogo("icon-preview", "icon-preview")}
          <button class="btn sm" id="icon-upload">${I.upload} ${esc(t("settings.icon.upload"))}</button>
          <button class="btn sm ghost" id="icon-reset">${esc(t("settings.icon.reset"))}</button>
          <input type="file" id="icon-input" accept="image/png,image/jpeg,image/webp,image/gif" class="u-hidden">
        </div>
      </div></div>`;
}

function tokenCard() {
  return `<div class="card"><div class="card-pad">
        <div class="card-title">${I.key} ${esc(t("settings.token.title"))}</div>
        <div class="card-desc">${esc(t("settings.token.desc"))}</div>
        <ol class="token-steps">
          ${[1, 2, 3, 4, 5].map((step) => `<li>${tHtml(`settings.token.step${step}.html`)}</li>`).join("\n          ")}
        </ol>
        <div class="u-mt14">
          <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer">dash.cloudflare.com/profile/api-tokens ↗</a>
        </div>
      </div></div>`;
}

function aboutCard() {
  return `<div class="card"><div class="card-pad">
        <div class="card-title">${esc(t("settings.about.title"))}</div>
        <table class="kv-table">
          <tr><td>${esc(t("settings.about.version"))}</td><td class="mono">v${esc(state.config ? state.config.version : "?")}</td></tr>
          <tr><td>${esc(t("settings.about.source"))}</td><td><a href="${esc(state.config?.github || "")}" target="_blank" rel="noopener noreferrer">GitHub</a></td></tr>
          <tr><td>${esc(t("settings.about.upstream"))}</td><td><a href="https://github.com/timothymiller/cloudflare-ddns" target="_blank" rel="noopener noreferrer">cloudflare-ddns</a></td></tr>
        </table>
      </div></div>`;
}

function renderSettings() {
  const page = el("page");
  page.innerHTML = `
    <div class="settings-grid">
      ${appearanceCard()}

      <div class="card"><div class="card-pad">
        <div class="card-title">${I.shield} ${esc(t("settings.security.title"))}</div>
        <div class="card-desc">${esc(t("settings.security.desc"))}</div>
        <div id="security-body"></div>
      </div></div>

      ${tokenCard()}

      ${aboutCard()}
    </div>`;

  // Theme select
  const themeSelect = mselect({
    id: "settings-theme-select",
    label: t("settings.theme"),
    options: THEMES.map((mode) => ({ value: mode, label: t("settings.theme." + mode) })),
    value: currentTheme(),
    onChange: (v) => setTheme(v, themeSelect.querySelector(".mselect-btn")),
  });
  el("settings-theme-slot").replaceWith(themeSelect);

  // Language select
  el("settings-lang-slot").replaceWith(mselect({
    cls: "u-lang-select",
    options: LANGS.map((l) => ({ value: l.code, label: l.name })),
    value: lang,
    onChange: (v) => { lang = v; writeStored("cfddns.lang", v); render(); },
  }));

  renderAccentRow();
  wireIconSettings();
  renderSecurityBody();
}

function renderAccentRow() {
  const row = el("accent-row");
  if (!row) return;
  const current = (state.config && state.config.accent) || "#f6821f";
  row.innerHTML = "";
  ACCENT_PRESETS.forEach((color) => {
    const b = document.createElement("button");
    b.className = `swatch ${current.toLowerCase() === color ? "selected" : ""}`;
    b.type = "button";
    b.title = color;
    b.style.setProperty("--swatch-color", color);
    b.setAttribute("aria-label", color);
    b.setAttribute("aria-pressed", String(current.toLowerCase() === color));
    b.addEventListener("click", () => saveAccent(color));
    row.appendChild(b);
  });
  const custom = document.createElement("label");
  custom.className = `swatch swatch-custom ${ACCENT_PRESETS.includes(current.toLowerCase()) ? "" : "selected"}`;
  custom.style.setProperty("--swatch-color", current);
  custom.innerHTML = I.edit;
  const picker = document.createElement("input");
  picker.type = "color";
  picker.className = "color-input";
  picker.value = /^#[0-9a-fA-F]{6}$/.test(current) ? current : "#f6821f";
  picker.title = t("settings.accent.custom");
  picker.setAttribute("aria-label", t("settings.accent.custom"));
  picker.addEventListener("change", () => saveAccent(picker.value));
  custom.appendChild(picker);
  row.appendChild(custom);
  const reset = document.createElement("button");
  reset.className = "btn sm ghost";
  reset.textContent = t("settings.accent.default");
  reset.addEventListener("click", () => saveAccent(null));
  row.appendChild(reset);
}

async function saveAccent(color) {
  try {
    await api("/api/ui/accent", { method: "POST", json: { accent: color } });
    state.config.accent = color;
    // Refresh the derived palette without waiting for a reload.
    applyAccent(color);
    toast(t("toast.accent"));
    renderAccentRow();
  } catch (e) {
    toast(e.message, "error");
  }
}

function wireIconSettings() {
  const input = el("icon-input");
  el("icon-upload").addEventListener("click", () => input.click());
  input.addEventListener("change", async () => {
    if (!input.files.length) return;
    const f = input.files[0];
    if (f.size > 512 * 1024) { toast(t("settings.icon.too_big"), "error"); input.value = ""; return; }
    const okTypes = ["image/png", "image/jpeg", "image/webp", "image/gif"];
    if (!okTypes.includes(f.type)) { toast(t("settings.icon.bad_type"), "error"); input.value = ""; return; }
    try {
      const buf = await f.arrayBuffer();
      await api(`/api/ui/icon?mime=${encodeURIComponent(f.type)}`, {
        method: "POST", raw: buf, rawType: f.type,
      });
      toast(t("toast.icon"));
      state.config.has_icon = true;
      // Update favicon immediately.
      refreshBranding();
    } catch (e) {
      toast(e.message, "error");
    }
    input.value = "";
  });
  el("icon-reset").addEventListener("click", async () => {
    try {
      await api("/api/ui/icon", { method: "DELETE" });
      toast(t("toast.icon"));
      state.config.has_icon = false;
      refreshBranding();
    } catch (e) {
      toast(e.message, "error");
    }
  });
}

/* ----- Security section ----- */

function renderSecurityBody() {
  const body = el("security-body");
  if (!body) return;
  const totpOn = state.totpEnabled;
  body.innerHTML = `
    <table class="kv-table">
      <tr><td>${esc(t("settings.security.session"))}</td><td class="mono">${state.sessionTtl ? esc(fmtDuration(state.sessionTtl)) : "-"}</td></tr>
      <tr><td>${esc(t("settings.security.cookies"))}</td><td><span class="cell-muted">${esc(t("settings.security.cookies.hint"))}</span></td></tr>
      <tr><td>${esc(t("settings.2fa.title"))}</td><td>
        <div class="security-factor-status">
        <span class="badge ${totpOn ? "green" : "grey"}">${esc(totpOn ? t("settings.2fa.status.on") : t("settings.2fa.status.off"))}</span>
        ${totpOn ? `<span class="cell-muted">${esc(t("settings.2fa.backup_count", { n: state.backupCodesRemaining }))}</span>` : ""}
        </div>
      </td></tr>
      <tr><td>${esc(t("settings.passkey.title"))}</td><td>
        <div class="security-factor-status">
          <span class="badge ${state.passkeys.length ? "green" : "grey"}">${esc(state.passkeys.length ? t("settings.passkey.status.on") : t("settings.passkey.status.off"))}</span>
          ${state.passkeys.length ? `<span class="cell-muted">${esc(t("settings.passkey.count", { n: state.passkeys.length }))}</span>` : ""}
        </div>
      </td></tr>
    </table>
    <div class="settings-sep"></div>
    <div class="settings-row">
      <div class="grow">
        <div class="lbl">${esc(t("settings.2fa.title"))}</div>
        <div class="hint">${esc(t("settings.2fa.desc"))}</div>
      </div>
      ${totpOn
        ? `<button class="btn sm danger" id="2fa-disable-btn">${esc(t("settings.2fa.disable"))}</button>`
        : `<button class="btn sm primary" id="2fa-enable-btn">${esc(t("settings.2fa.enable"))}</button>`}
    </div>
    <div class="settings-sep"></div>
    <div class="settings-row u-row-start">
      <div class="grow">
        <div class="lbl">${esc(t("settings.passkey.title"))}</div>
        <div class="hint">${esc(state.passkeySupported ? t("settings.passkey.desc") : t("settings.passkey.unavailable"))}</div>
        <div class="passkey-list" id="passkey-list">
          ${state.passkeys.map((passkey) => `<div class="passkey-item">
            <div class="grow"><strong>${esc(passkey.name)}</strong><div class="hint">${esc(t("settings.passkey.created", { date: new Date(passkey.created_at * 1000).toLocaleDateString() }))}</div></div>
            <button class="btn sm" data-passkey-rename="${esc(passkey.id)}">${esc(t("settings.passkey.rename"))}</button>
            <button class="btn sm danger" data-passkey-remove="${esc(passkey.id)}">${esc(t("settings.passkey.remove"))}</button>
          </div>`).join("")}
        </div>
      </div>
      <button class="btn sm primary" id="passkey-add-btn" ${state.passkeySupported ? "" : "disabled"}>${esc(t("settings.passkey.add"))}</button>
    </div>
    <div class="settings-sep"></div>
    <div class="settings-row">
      <div class="grow">
        <div class="lbl">${esc(t("settings.password.change"))}</div>
      </div>
      <button class="btn sm" id="pw-change-btn">${esc(t("settings.password.change"))}</button>
    </div>`;

  const enableBtn = el("2fa-enable-btn");
  if (enableBtn) enableBtn.addEventListener("click", open2faSetupModal);
  const disableBtn = el("2fa-disable-btn");
  if (disableBtn) disableBtn.addEventListener("click", open2faDisableModal);
  el("passkey-add-btn")?.addEventListener("click", openPasskeyAddModal);
  body.querySelectorAll?.("[data-passkey-rename]").forEach((button) => button.addEventListener("click", () => {
    const passkey = state.passkeys.find((item) => item.id === button.dataset.passkeyRename);
    if (passkey) openPasskeyRenameModal(passkey);
  }));
  body.querySelectorAll?.("[data-passkey-remove]").forEach((button) => button.addEventListener("click", () => {
    const passkey = state.passkeys.find((item) => item.id === button.dataset.passkeyRemove);
    if (passkey) openPasskeyRemoveModal(passkey);
  }));
  el("pw-change-btn").addEventListener("click", openPasswordModal);
}

function passkeyStepUpFields(prefix) {
  return `<label class="field"><span>${esc(t("settings.passkey.name"))}</span>
      <input class="input" id="${prefix}-name" maxlength="64" autocomplete="off"></label>
    <label class="field"><span>${esc(t("settings.password.current"))}</span>
      <input class="input" id="${prefix}-password" type="password" autocomplete="current-password"></label>
    ${state.totpEnabled ? `<label class="field"><span>${esc(t("settings.password.code"))}</span>
      <input class="input" id="${prefix}-code" autocomplete="one-time-code"></label>` : ""}`;
}

function openPasskeyAddModal() {
  if (!passkeyCapable()) { toast(t("settings.passkey.browser_unavailable"), "error"); return; }
  const modal = openModal(`
    ${modalHead(t("settings.passkey.add"))}
    <div class="modal-body">
      <p class="u-note-sm">${esc(t("settings.passkey.add_desc"))}</p>
      <div class="login-error" id="passkey-add-error"></div>
      ${passkeyStepUpFields("passkey-add")}
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="passkey-add-submit">${esc(t("settings.passkey.add"))}</button>
    </div>`);
  modal.querySelector("#passkey-add-submit").addEventListener("click", async () => {
    const btn = modal.querySelector("#passkey-add-submit");
    const errorBox = modal.querySelector("#passkey-add-error");
    const name = modal.querySelector("#passkey-add-name").value.trim();
    const password = modal.querySelector("#passkey-add-password").value;
    const code = modal.querySelector("#passkey-add-code")?.value.trim() || null;
    if (!name || !password || (state.totpEnabled && !code)) { showError(errorBox, t("modal.required")); return; }
    btn.disabled = true;
    errorBox.classList.remove("visible");
    const session = { generation: authGeneration };
    try {
      const start = await api("/api/auth/passkeys/register/start", {
        method: "POST", json: { name, password, code },
      });
      const credential = await navigator.credentials.create({
        publicKey: passkeyCreationOptions(start.options),
      });
      if (!credential) throw new Error(t("passkey.cancelled"));
      const passkey = await api("/api/auth/passkeys/register/finish", {
        method: "POST",
        json: { flow: start.flow, credential: registrationCredentialJSON(credential) },
        authContext: session,
        rotatesSession: true,
      });
      if (session.generation !== authGeneration || !state.authed) return;
      state.passkeys.push(passkey);
      if (modal.isConnected) closeModal();
      toast(t("toast.passkey.added"));
      renderSecurityBody();
    } catch (error) {
      showError(errorBox, passkeyError(error));
      btn.disabled = false;
    }
  });
}

function openPasskeyRenameModal(passkey) {
  const modal = openModal(`
    ${modalHead(t("settings.passkey.rename"))}
    <div class="modal-body">
      <div class="login-error" id="passkey-rename-error"></div>
      <label class="field"><span>${esc(t("settings.passkey.name"))}</span>
        <input class="input" id="passkey-rename-name" maxlength="64" value="${esc(passkey.name)}" autocomplete="off"></label>
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="passkey-rename-submit">${esc(t("settings.passkey.rename"))}</button>
    </div>`);
  modal.querySelector("#passkey-rename-submit").addEventListener("click", async () => {
    const btn = modal.querySelector("#passkey-rename-submit");
    const errorBox = modal.querySelector("#passkey-rename-error");
    const name = modal.querySelector("#passkey-rename-name").value.trim();
    if (!name) { showError(errorBox, t("modal.required")); return; }
    btn.disabled = true;
    try {
      await api(`/api/auth/passkeys/${encodeURIComponent(passkey.id)}`, { method: "PUT", json: { name } });
      passkey.name = name;
      if (modal.isConnected) closeModal();
      toast(t("toast.passkey.renamed"));
      renderSecurityBody();
    } catch (error) {
      showError(errorBox, error.message);
      btn.disabled = false;
    }
  });
}

function openPasskeyRemoveModal(passkey) {
  const modal = openModal(`
    ${modalHead(t("settings.passkey.remove"))}
    <div class="modal-body">
      <p class="u-note-sm">${esc(t("settings.passkey.remove_desc", { name: passkey.name }))}</p>
      <div class="login-error" id="passkey-remove-error"></div>
      <label class="field"><span>${esc(t("settings.password.current"))}</span>
        <input class="input" id="passkey-remove-password" type="password" autocomplete="current-password"></label>
      ${state.totpEnabled ? `<label class="field"><span>${esc(t("settings.password.code"))}</span>
        <input class="input" id="passkey-remove-code" autocomplete="one-time-code"></label>` : ""}
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn danger" id="passkey-remove-submit">${esc(t("settings.passkey.remove"))}</button>
    </div>`);
  modal.querySelector("#passkey-remove-submit").addEventListener("click", async () => {
    const btn = modal.querySelector("#passkey-remove-submit");
    const errorBox = modal.querySelector("#passkey-remove-error");
    const password = modal.querySelector("#passkey-remove-password").value;
    const code = modal.querySelector("#passkey-remove-code")?.value.trim() || null;
    if (!password || (state.totpEnabled && !code)) { showError(errorBox, t("modal.required")); return; }
    btn.disabled = true;
    const session = { generation: authGeneration };
    try {
      await api(`/api/auth/passkeys/${encodeURIComponent(passkey.id)}`, {
        method: "DELETE",
        json: { password, code },
        authContext: session,
        rotatesSession: true,
      });
      if (session.generation !== authGeneration || !state.authed) return;
      state.passkeys = state.passkeys.filter((item) => item.id !== passkey.id);
      if (modal.isConnected) closeModal();
      toast(t("toast.passkey.removed"));
      renderSecurityBody();
    } catch (error) {
      showError(errorBox, error.message);
      btn.disabled = false;
    }
  });
}

/* ----- 2FA setup ----- */

let enrollmentOperation = Promise.resolve();

function withEnrollmentOperation(operation) {
  const pending = enrollmentOperation.then(operation);
  enrollmentOperation = pending.catch(() => {});
  return pending;
}

function open2faSetupModal() {
  const modal = openModal(`
    ${modalHead(t("settings.2fa.enable"))}
    <div class="modal-body">
      <div class="login-error" id="begin-2fa-error" role="alert"></div>
      <label class="field"><span>${esc(t("settings.password.current"))}</span>
        <input class="input" id="begin-2fa-password" type="password" autocomplete="current-password"></label>
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="begin-2fa-submit">${esc(t("settings.2fa.enable"))}</button>
    </div>`);
  modal.querySelector("#begin-2fa-submit").addEventListener("click", async () => {
    const authentication = authGeneration;
    const btn = modal.querySelector("#begin-2fa-submit");
    const error = modal.querySelector("#begin-2fa-error");
    const password = modal.querySelector("#begin-2fa-password").value;
    if (!password) { showError(error, t("modal.required")); return; }
    btn.disabled = true;
    error.classList.remove("visible");
    try {
      await withEnrollmentOperation(async () => {
        if (authentication !== authGeneration || !modal.isConnected || !state.authed) return;
        const begin = await api("/api/auth/2fa/begin", { method: "POST", json: { password } });
        if (authentication !== authGeneration) return;
        if (modal.isConnected && state.authed && state.route === "settings") show2faEnrollment(begin);
        else await api("/api/auth/2fa/cancel", { method: "POST", json: {} });
      });
    } catch (e) {
      showError(error, e.message);
      btn.disabled = false;
    }
  });
}

function show2faEnrollment(begin) {
  const authentication = authGeneration;
  let confirming = false;
  let completed = false;
  const modal = openModal(`
    ${modalHead(t("settings.2fa.enable"))}
    <div class="modal-body">
      <p class="u-note-sm">${esc(t("settings.2fa.scan"))}</p>
      <div class="qr-box">${begin.qr_svg || ""}</div>
      <div class="secret-row u-mb16">
        <code>${esc(begin.secret)}</code>
        <button class="btn icon sm" id="copy-secret" title="${esc(t("common.copy"))}">${I.copy}</button>
      </div>
      <div class="login-error" id="t2fa-error"></div>
      <label class="field"><span>${esc(t("settings.2fa.code"))}</span>
        <input class="input" id="t2fa-code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" maxlength="6"></label>
    </div>
    <div class="modal-foot">
      <button class="btn" id="t2fa-cancel">${esc(t("settings.2fa.cancel"))}</button>
      <button class="btn primary" id="t2fa-confirm">${esc(t("settings.2fa.confirm"))}</button>
    </div>`);

  modal.querySelector("#copy-secret").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(begin.secret); toast(t("common.copied")); } catch { /* no clipboard */ }
  });
  modal.onDismiss = () => {
    if (!confirming && !completed && authentication === authGeneration) {
      completed = true;
      withEnrollmentOperation(() => authentication === authGeneration
        ? api("/api/auth/2fa/cancel", { method: "POST", json: {} }) : undefined).catch((e) => toast(e.message, "error"));
    }
  };
  modal.querySelector("#t2fa-cancel").addEventListener("click", () => closeModal());

  modal.querySelector("#t2fa-confirm").addEventListener("click", async () => {
    if (confirming || authentication !== authGeneration || !state.authed) return;
    confirming = true;
    modal.closeBlocked = true;
    modal.querySelectorAll("[data-close], #t2fa-cancel").forEach((button) => { button.disabled = true; });
    const btn = modal.querySelector("#t2fa-confirm");
    const errBox = modal.querySelector("#t2fa-error");
    errBox.classList.remove("visible");
    btn.disabled = true;
    const session = { generation: authentication };
    try {
      const code = modal.querySelector("#t2fa-code").value.trim();
      const res = await withEnrollmentOperation(() => {
        if (authentication !== authGeneration || !state.authed) throw new Error(t("error.auth_changed"));
        return api("/api/auth/2fa/confirm", { method: "POST", json: { code }, authContext: session, rotatesSession: true });
      });
      completed = true;
      if (session.generation !== authGeneration || !state.authed) return;
      state.pendingBackupCodes = [...res.backup_codes];
      state.totpEnabled = true;
      state.backupCodesRemaining = res.backup_codes.length;
      modal.closeBlocked = false;
      renderRecoveryNotice();
      if (modal.isConnected && state.authed) showBackupCodesModal(state.pendingBackupCodes);
    } catch (e) {
      showError(errBox, e.message);
      btn.disabled = false;
    } finally {
      confirming = false;
      modal.closeBlocked = false;
      modal.querySelectorAll("[data-close], #t2fa-cancel").forEach((button) => { button.disabled = false; });
      if (!modal.isConnected && !completed) modal.onDismiss();
    }
  });
}

function renderRecoveryNotice() {
  const notice = el("recovery-notice");
  if (!notice) return;
  notice.innerHTML = state.authed && state.pendingBackupCodes ? `<div class="login-notice recovery-notice" role="status">
    <p>${esc(t("settings.2fa.backup.pending"))}</p>
    <button class="btn sm" id="backup-codes-reopen">${esc(t("settings.2fa.backup.reopen"))}</button></div>` : "";
  el("backup-codes-reopen")?.addEventListener("click", () => showBackupCodesModal(state.pendingBackupCodes));
}

function showBackupCodesModal(codes) {
  if (!codes || !state.authed) return;
  const modal = openModal(`
    ${modalHead(t("settings.2fa.backup.title"))}
    <div class="modal-body">
      <p class="u-note-sm">${esc(t("settings.2fa.backup.desc"))}</p>
      <div class="backup-grid">
        ${codes.map((c) => `<div class="backup-code">${esc(c)}</div>`).join("")}
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn" id="bc-download">${I.download} ${esc(t("settings.2fa.backup.download"))}</button>
      <button class="btn primary" id="bc-done">${esc(t("settings.2fa.backup.done"))}</button>
    </div>`, true);
  modal.querySelector("#bc-download").addEventListener("click", () => {
    const text = `Cloudflare DDNS Web UI - backup recovery codes
Generated: ${new Date().toISOString()}

Each code can be used once to sign in if you lose access to your
authenticator app. Store them somewhere safe.

${codes.join("\n")}
`;
    downloadText("cloudflare-ddns-backup-codes.txt", text);
  });
  modal.querySelector("#bc-done").addEventListener("click", () => {
    state.pendingBackupCodes = null;
    if (modal.isConnected) closeModal();
    renderRecoveryNotice();
    toast(t("toast.2fa.enabled"));
    renderSecurityBody();
  });
}

/* ----- 2FA disable ----- */

function open2faDisableModal() {
  const modal = openModal(`
    ${modalHead(t("settings.2fa.disable"))}
    <div class="modal-body">
      <p class="u-note-sm">${esc(t("settings.2fa.disable.hint"))}</p>
      <div class="login-error" id="d2fa-error"></div>
      <label class="field"><span>${esc(t("login.2fa.code"))}</span>
        <input class="input" id="d2fa-code" inputmode="text" autocomplete="one-time-code" placeholder="123456"></label>
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn danger" id="d2fa-confirm">${esc(t("settings.2fa.disable"))}</button>
    </div>`);
  modal.querySelector("#d2fa-confirm").addEventListener("click", async () => {
    const session = { generation: authGeneration };
    const btn = modal.querySelector("#d2fa-confirm");
    const errBox = modal.querySelector("#d2fa-error");
    errBox.classList.remove("visible");
    btn.disabled = true;
    try {
      await api("/api/auth/2fa/disable", {
        method: "POST",
        json: { code: modal.querySelector("#d2fa-code").value.trim() },
        authContext: session,
        rotatesSession: true,
      });
      if (session.generation !== authGeneration || !state.authed) return;
      state.totpEnabled = false;
      state.backupCodesRemaining = 0;
      if (modal.isConnected) closeModal();
      toast(t("toast.2fa.disabled"));
      renderSecurityBody();
    } catch (e) {
      showError(errBox, e.message);
      btn.disabled = false;
    }
  });
}

/* ----- Change password ----- */

function openPasswordModal() {
  const totpOn = state.totpEnabled;
  const modal = openModal(`
    ${modalHead(t("settings.password.change"))}
    <div class="modal-body">
      <div class="login-error" id="pw-error"></div>
      <label class="field"><span>${esc(t("settings.password.current"))}</span>
        <input class="input" type="password" id="pw-current" autocomplete="current-password"></label>
      ${totpOn ? `
      <label class="field"><span>${esc(t("settings.password.code"))}</span>
        <input class="input" id="pw-code" inputmode="text" autocomplete="one-time-code" placeholder="123456">
        <div class="field-hint">${esc(t("settings.password.code.hint"))}</div></label>` : ""}
      <label class="field"><span>${esc(t("settings.password.new"))}</span>
        <input class="input" type="password" id="pw-new" autocomplete="new-password"></label>
      <label class="field"><span>${esc(t("settings.password.confirm"))}</span>
        <input class="input" type="password" id="pw-confirm" autocomplete="new-password"></label>
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="pw-submit">${esc(t("settings.password.submit"))}</button>
    </div>`);
  modal.querySelector("#pw-submit").addEventListener("click", async () => {
    const session = { generation: authGeneration };
    const btn = modal.querySelector("#pw-submit");
    const errBox = modal.querySelector("#pw-error");
    errBox.classList.remove("visible");
    const val = (id) => modal.querySelector(id).value;
    if (val("#pw-new").length < 8) { showError(errBox, t("setup.short")); return; }
    if (val("#pw-new") !== val("#pw-confirm")) { showError(errBox, t("setup.mismatch")); return; }
    btn.disabled = true;
    try {
      await api("/api/auth/password", {
        method: "POST",
        json: {
          current_password: val("#pw-current"),
          code: totpOn ? val("#pw-code").trim() : null,
          new_password: val("#pw-new"),
          confirm: val("#pw-confirm"),
        },
        authContext: session,
        rotatesSession: true,
      });
      if (session.generation !== authGeneration || !state.authed) return;
      if (modal.isConnected) closeModal();
      toast(t("toast.password"));
    } catch (e) {
      showError(errBox, e.message);
      btn.disabled = false;
    }
  });
}

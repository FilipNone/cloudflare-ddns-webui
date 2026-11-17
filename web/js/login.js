/* Signed-out screens: first-run setup, password sign-in and the 2FA step. */
"use strict";

/* ================= Render: first-run setup ================= */

function renderSetup(app) {
  app.innerHTML = loginShell(`
    <form class="login-card" id="setup-form">
      <div class="login-logo">
        ${brandLogo()}
        <h1>${esc(t("app.name"))}</h1>
      </div>
      <p class="login-sub">${esc(t("setup.subtitle"))}</p>
      <div class="login-error" id="setup-error"></div>
      <label class="field">
        <span>${esc(t("setup.password"))}</span>
        <input class="input" type="password" id="setup-password" autocomplete="new-password" required autofocus>
      </label>
      <label class="field">
        <span>${esc(t("setup.confirm"))}</span>
        <input class="input" type="password" id="setup-confirm" autocomplete="new-password" required>
        <div class="field-hint">${esc(t("setup.hint"))}</div>
      </label>
      <button class="btn primary u-w100" type="submit" id="setup-submit">${esc(t("setup.submit"))}</button>
    </form>`);
  wireLoginShell();

  el("setup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errBox = el("setup-error");
    const btn = el("setup-submit");
    errBox.classList.remove("visible");
    const password = el("setup-password").value;
    const confirm = el("setup-confirm").value;
    if (password.length < 8) { showError(errBox, t("setup.short")); return; }
    if (password !== confirm) { showError(errBox, t("setup.mismatch")); return; }
    btn.disabled = true;
    try {
      await api("/api/auth/setup", { method: "POST", json: { password, confirm }, rotatesSession: true, clearsRecoveryCodes: true });
      state.configured = true;
      state.authed = true;
      await bootAuthed();
    } catch (err) {
      showError(errBox, err.message);
      btn.disabled = false;
    }
  });
}

/* ================= Render: login ================= */

function loginShell(cardHtml) {
  return `
    <div class="login-wrap">
      <div class="login-corner">
        <button class="btn icon" type="button" data-theme-btn="1" title="${esc(t("settings.theme." + currentTheme()))}" aria-label="${esc(t("settings.theme"))}">${themeIcon()}</button>
        <div class="dropdown">
          <button class="btn icon" id="login-lang-btn" title="${esc(t("settings.lang.title"))}">${I.globe}</button>
          <div class="menu" id="login-lang-menu">
            <div class="menu-label">${esc(t("settings.lang.title"))}</div>
            ${LANGS.map((l) => `<button class="menu-item" data-lang="${l.code}"><span class="check">${l.code === lang ? I.check : ""}</span>${esc(l.name)}</button>`).join("")}
          </div>
        </div>
      </div>
      ${cardHtml}
      <div class="login-footer">
        <a href="${esc(state.config?.github || "https://github.com/FilipNone/cloudflare-ddns-webui")}" target="_blank" rel="noopener noreferrer">${I.github} ${esc(t("login.github"))}</a>
      </div>
    </div>`;
}

function wireLoginShell() {
  document.querySelectorAll("[data-theme-btn]").forEach((b) => b.addEventListener("click", cycleTheme));
  bindDropdown("login-lang-btn", "login-lang-menu");
  document.querySelectorAll("#login-lang-menu [data-lang]").forEach((b) =>
    b.addEventListener("click", () => {
      lang = b.dataset.lang;
      writeStored("cfddns.lang", lang);
      render();
    })
  );
}

function renderLogin(app) {
  if (state.pendingChallenge) { renderLogin2fa(app); return; }
  app.innerHTML = loginShell(`
    <form class="login-card" id="login-form">
      <div class="login-logo">
        ${brandLogo()}
        <h1>${esc(t("app.name"))}</h1>
      </div>
      <p class="login-sub">${esc(t("login.subtitle"))}</p>
      <div class="login-error" id="login-error"></div>
      <label class="field">
        <span>${esc(t("login.password"))}</span>
        <input class="input" type="password" id="login-password" autocomplete="current-password" required autofocus>
      </label>
      <button class="btn primary u-w100" type="submit" id="login-submit">${esc(t("login.submit"))}</button>
    </form>`);
  wireLoginShell();

  el("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = el("login-submit");
    const errBox = el("login-error");
    errBox.classList.remove("visible");
    btn.disabled = true;
    btn.textContent = t("login.wait");
    try {
      const res = await api("/api/auth/login", {
        method: "POST", json: { password: el("login-password").value }, rotatesSession: true, clearsRecoveryCodes: true,
      });
      if (res.requires_2fa) {
        state.pendingChallenge = res.challenge;
        render();
        return;
      }
      state.authed = true;
      await bootAuthed();
    } catch (err) {
      showError(errBox, err.status === 401 ? t("login.error") : err.message);
      btn.disabled = false;
      btn.textContent = t("login.submit");
    }
  });
}

function renderLogin2fa(app) {
  app.innerHTML = loginShell(`
    <form class="login-card" id="login2fa-form">
      <div class="login-logo">
        ${brandLogo()}
        <h1>${esc(t("login.2fa.title"))}</h1>
      </div>
      <p class="login-sub">${esc(t("login.2fa.subtitle"))}</p>
      <div class="login-error" id="login2fa-error"></div>
      <label class="field">
        <span>${esc(t("login.2fa.code"))}</span>
        <input class="input" type="text" id="login2fa-code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" required autofocus>
      </label>
      <button class="btn primary u-w100" type="submit" id="login2fa-submit">${esc(t("login.2fa.submit"))}</button>
      <button class="btn ghost u-w100 u-mt8" type="button" id="login2fa-back">${esc(t("login.2fa.back"))}</button>
    </form>`);
  wireLoginShell();

  el("login2fa-back").addEventListener("click", () => { state.pendingChallenge = null; render(); });
  el("login2fa-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = el("login2fa-submit");
    const errBox = el("login2fa-error");
    errBox.classList.remove("visible");
    btn.disabled = true;
    try {
      const res = await api("/api/auth/login/2fa", {
        method: "POST",
        json: { challenge: state.pendingChallenge, code: el("login2fa-code").value.trim() },
        rotatesSession: true,
        clearsRecoveryCodes: true,
      });
      state.pendingChallenge = null;
      state.authed = true;
      if (res.backup_code_used) {
        toast(t("login.2fa.backup_used", { n: res.backup_codes_remaining }), "info");
      }
      await bootAuthed();
    } catch (err) {
      showError(errBox, err.message);
      btn.disabled = false;
    }
  });
}

/* Signed-out screens: first-run setup, password sign-in and the 2FA step. */
"use strict";

function passkeyCapable() {
  return !!(state.config?.passkey_supported && window.PublicKeyCredential && navigator.credentials);
}

function base64urlToBuffer(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const bytes = atob(padded);
  return Uint8Array.from(bytes, (byte) => byte.charCodeAt(0)).buffer;
}

function bufferToBase64url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function passkeyCreationOptions(options) {
  const publicKey = options.publicKey;
  publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  publicKey.user.id = base64urlToBuffer(publicKey.user.id);
  (publicKey.excludeCredentials || []).forEach((credential) => {
    credential.id = base64urlToBuffer(credential.id);
  });
  return publicKey;
}

function passkeyRequestOptions(options) {
  const publicKey = options.publicKey;
  publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  (publicKey.allowCredentials || []).forEach((credential) => {
    credential.id = base64urlToBuffer(credential.id);
  });
  return publicKey;
}

function registrationCredentialJSON(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      transports: typeof response.getTransports === "function" ? response.getTransports() : [],
    },
    extensions: credential.getClientExtensionResults(),
  };
}

function authenticationCredentialJSON(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults(),
  };
}

function passkeyError(error) {
  if (error?.name === "NotAllowedError") return t("passkey.cancelled");
  if (error?.name === "InvalidStateError") return t("passkey.already_registered");
  if (error?.name === "SecurityError") return t("passkey.security_error");
  return error?.message || t("passkey.failed");
}

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
      ${passkeyCapable() ? `<div class="login-divider"><span>${esc(t("login.or"))}</span></div>
      <button class="btn u-w100" type="button" id="passkey-login">${I.key} ${esc(t("passkey.sign_in"))}</button>` : ""}
    </form>`);
  wireLoginShell();

  el("passkey-login")?.addEventListener("click", async () => {
    const btn = el("passkey-login");
    const errBox = el("login-error");
    errBox.classList.remove("visible");
    btn.disabled = true;
    try {
      const start = await api("/api/auth/passkey/start", { method: "POST" });
      const credential = await navigator.credentials.get({
        publicKey: passkeyRequestOptions(start.options),
      });
      if (!credential) throw new Error(t("passkey.cancelled"));
      await api("/api/auth/passkey/finish", {
        method: "POST",
        json: { flow: start.flow, credential: authenticationCredentialJSON(credential) },
        rotatesSession: true,
        clearsRecoveryCodes: true,
      });
      state.authed = true;
      await bootAuthed();
    } catch (error) {
      showError(errBox, passkeyError(error));
      btn.disabled = false;
    }
  });

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

/* Shared UI: icons, theme and branding, toasts, select menus, dropdowns and the modal frame. */
"use strict";

/* ================= Icons ================= */

const I = {
  cloud: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>',
  cloudFill: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>',
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
  bolt: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
  file: '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>',
  shield: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>',
  sun: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>',
  moon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>',
  monitor: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>',
  github: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.27-.01-1.17-.02-2.12-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.03 1.76 2.69 1.25 3.35.96.1-.75.4-1.25.72-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.78 0c2.21-1.49 3.18-1.18 3.18-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.7 5.4-5.27 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.8-.01 3.18 0 .31.21.68.8.56A10.52 10.52 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5z"/></svg>',
  key: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
  copy: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>',
  palette: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="13.5" cy="6.5" r=".5" fill="currentColor"/><circle cx="17.5" cy="10.5" r=".5" fill="currentColor"/><circle cx="8.5" cy="7.5" r=".5" fill="currentColor"/><circle cx="6.5" cy="12.5" r=".5" fill="currentColor"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"/></svg>',
};

/* ================= Theme ================= */

const themeMedia = window.matchMedia("(prefers-color-scheme: dark)");
themeMedia.addEventListener("change", () => applyTheme());
let themeTransition = null;
let iconRevision = Date.now();

function applyTheme() {
  const mode = currentTheme();
  const dark = mode === "dark" || (mode === "system" && themeMedia.matches);
  document.documentElement.classList.toggle("dark", dark);
  if (state.config) applyAccent(state.config.accent);
}

function setTheme(mode, origin) {
  if (!THEMES.includes(mode)) return;
  writeStored("cfddns.theme", mode);
  themeTransition?.skipTransition();
  const root = document.documentElement;
  const dark = mode === "dark" || (mode === "system" && themeMedia.matches);
  if (!origin || root.classList.contains("dark") === dark
    || window.matchMedia("(prefers-reduced-motion: reduce)").matches
    || !document.startViewTransition || !root.animate) {
    applyTheme();
    return;
  }
  const rect = origin.getBoundingClientRect();
  const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
  const radius = Math.hypot(Math.max(x, window.innerWidth - x), Math.max(y, window.innerHeight - y));
  root.classList.add("theme-changing");
  try {
    const transition = document.startViewTransition(applyTheme);
    themeTransition = transition;
    transition.ready.then(() => {
      root.animate({ clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${radius}px at ${x}px ${y}px)`] }, {
        duration: 450, easing: "ease-in-out", pseudoElement: "::view-transition-new(root)",
      });
    }).catch(() => { applyTheme(); transition.skipTransition(); });
    transition.finished.catch(() => {}).finally(() => {
      if (themeTransition !== transition) return;
      themeTransition = null;
      root.classList.remove("theme-changing");
    });
  } catch {
    root.classList.remove("theme-changing");
    applyTheme();
  }
}

function applyAccent(color) {
  const accent = /^#[0-9a-f]{6}$/i.test(color || "") ? color.toLowerCase() : "#f6821f";
  const rgb = [1, 3, 5].map((offset) => parseInt(accent.slice(offset, offset + 2), 16));
  const luminance = (values) => {
    const linear = values.map((value) => value / 255 <= 0.04045 ? value / 255 / 12.92 : ((value / 255 + 0.055) / 1.055) ** 2.4);
    return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
  };
  const light = luminance(rgb) > 0.179;
  const hover = rgb.map((value) => Math.round(value * 0.88 + (light ? 255 : 0) * 0.12));
  const dark = document.documentElement.classList.contains("dark");
  const surfaces = dark ? [[9, 9, 11], [13, 13, 16], [16, 16, 19], [20, 20, 23], [26, 26, 31]] : [[244, 244, 246], [255, 255, 255], [240, 240, 243]];
  const backgrounds = surfaces.flatMap((surface) => [surface, surface.map((value, i) => value * 0.88 + rgb[i] * 0.12)]);
  let foreground = rgb;
  for (let step = 0; step <= 100; step++) {
    foreground = rgb.map((value) => Math.round(value * (1 - step / 100) + (dark ? 255 : 0) * step / 100));
    const text = luminance(foreground);
    if (backgrounds.every((background) => {
      const surface = luminance(background);
      return (Math.max(text, surface) + 0.05) / (Math.min(text, surface) + 0.05) >= 4.5;
    })) break;
  }
  const style = document.documentElement.style;
  style.setProperty("--accent", accent);
  style.setProperty("--accent-hover", `rgb(${hover.join(", ")})`);
  style.setProperty("--accent-text", `rgb(${foreground.join(", ")})`);
  style.setProperty("--accent-soft", `rgba(${rgb.join(", ")}, 0.12)`);
  style.setProperty("--accent-contrast", light ? "#000000" : "#ffffff");
}

function iconUrl() { return `/static/favicon.svg?v=${iconRevision}`; }

function brandLogo(cls = "", id = "") {
  const custom = !!state.config?.has_icon;
  return `<span class="brand-logo ${custom ? "brand-custom" : "brand-default"} ${cls}"><img data-brand-logo ${id ? `id="${id}"` : ""} src="${custom ? iconUrl() : `/static/default-logo.svg?v=${iconRevision}`}" alt="logo"></span>`;
}

function refreshBranding() {
  iconRevision++;
  const custom = !!state.config?.has_icon;
  document.querySelectorAll("[data-brand-logo]").forEach((img) => {
    img.src = custom ? iconUrl() : `/static/default-logo.svg?v=${iconRevision}`;
    img.parentElement?.classList.toggle("brand-custom", custom);
    img.parentElement?.classList.toggle("brand-default", !custom);
  });
  document.querySelectorAll('link[rel="icon"]').forEach((link) => { link.href = iconUrl(); });
}

function themeIcon() {
  const mode = currentTheme();
  return mode === "dark" ? I.moon : mode === "light" ? I.sun : I.monitor;
}

function cycleTheme(event) {
  const next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
  setTheme(next, event?.currentTarget);
  document.querySelectorAll("[data-theme-btn]").forEach((b) => {
    b.innerHTML = themeIcon();
    b.title = t("settings.theme." + next);
  });
}

/* ================= Helpers ================= */

function showError(box, message) {
  box.textContent = message;
  box.classList.add("visible");
}

// Shows a spinner while a request runs. Call the returned function to restore the button.
function showBusy(btn) {
  const label = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner small"></div>';
  return () => {
    btn.disabled = false;
    btn.innerHTML = label;
  };
}

function downloadText(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
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
  }, 4500);
}

/* ================= Modern select component ================= */

function closeMSelects() {
  document.querySelectorAll(".mselect.open, .dropdown.open").forEach((m) => {
    m.classList.remove("open");
    m.querySelector("button")?.setAttribute("aria-expanded", "false");
  });
  document.querySelectorAll(".menu.open").forEach((m) => m.classList.remove("open"));
}

document.addEventListener("click", (e) => {
  if (!e.target.closest(".mselect, .dropdown")) closeMSelects();
});
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  const trigger = document.querySelector(".mselect.open > button, .dropdown.open > button");
  if (trigger) {
    e.preventDefault();
    e.stopImmediatePropagation();
    closeMSelects();
    trigger.focus();
  } else if (state.mobileNavOpen) {
    e.preventDefault();
    toggleMobileNav(false);
  }
});

function mselectOption(o, onPick) {
  const item = document.createElement("button");
  item.type = "button";
  item.className = "mselect-option";
  item.dataset.value = o.value;
  const check = document.createElement("span");
  check.className = "check";
  const text = document.createElement("span");
  text.textContent = o.label;
  item.append(check, text);
  item.addEventListener("click", onPick);
  return item;
}

/**
 * Build a modern dropdown. opts: {id, label, options: [{value,label}], value,
 * placeholder, disabled, cls, onChange}
 */
function mselect(opts) {
  const wrap = document.createElement("div");
  wrap.className = `mselect ${opts.cls || ""}`;
  if (opts.id) wrap.id = opts.id;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "mselect-btn";
  btn.disabled = !!opts.disabled;
  btn.setAttribute("aria-expanded", "false");
  if (opts.label) btn.setAttribute("aria-label", opts.label);
  const label = document.createElement("span");
  label.className = "ms-label";
  const caret = document.createElement("span");
  caret.className = "ms-caret";
  caret.innerHTML = I.chevronDown;
  btn.append(label, caret);
  const menu = document.createElement("div");
  menu.className = "mselect-menu";
  wrap.append(btn, menu);

  wrap.mset = (v) => {
    wrap.dataset.value = v ?? "";
    const opt = opts.options.find((o) => String(o.value) === String(v));
    label.textContent = opt ? opt.label : (opts.placeholder || "");
    menu.querySelectorAll(".mselect-option").forEach((x) => {
      const selected = x.dataset.value === String(v);
      x.classList.toggle("selected", selected);
      x.querySelector(".check").innerHTML = selected ? I.check : "";
    });
  };
  wrap.mget = () => wrap.dataset.value ?? "";
  wrap.msetDisabled = (d) => { btn.disabled = d; };

  for (const o of opts.options) {
    menu.appendChild(mselectOption(o, () => {
      wrap.mset(o.value);
      closeMSelects();
      btn.focus();
      if (opts.onChange) opts.onChange(o.value);
    }));
  }
  wrap.mset(opts.value);

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const wasOpen = wrap.classList.contains("open");
    closeMSelects();
    if (wasOpen) return;
    // Flip up when near the bottom of the viewport.
    const rect = btn.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom;
    menu.classList.toggle("up", spaceBelow < 280 && rect.top > spaceBelow);
    wrap.classList.add("open");
    btn.setAttribute("aria-expanded", "true");
  });

  wrap.addEventListener("keydown", (e) => {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    if (!wrap.classList.contains("open")) btn.click();
    const items = [...menu.querySelectorAll(".mselect-option")];
    if (!items.length) return;
    const index = items.indexOf(document.activeElement);
    const next = e.key === "Home" ? 0 : e.key === "End" ? items.length - 1
      : e.key === "ArrowDown" ? (index + 1) % items.length : (index <= 0 ? items.length : index) - 1;
    items[next].focus();
  });
  return wrap;
}

/* Simple dropdown menu (login language, record columns) */
function bindDropdown(btnId, menuId) {
  const btn = el(btnId), menu = el(menuId);
  if (!btn || !menu) return;
  btn.setAttribute("aria-expanded", "false");
  btn.setAttribute("aria-controls", menuId);
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const wasOpen = menu.classList.contains("open");
    closeMSelects();
    if (!wasOpen) {
      // Flip up when near the bottom.
      const rect = btn.getBoundingClientRect();
      menu.classList.toggle("up", window.innerHeight - rect.bottom < 300 && rect.top > 320);
      menu.classList.add("open");
      btn.parentElement.classList.add("open");
      btn.setAttribute("aria-expanded", "true");
    }
  });
}

/* ================= Modals ================= */

let modalReturnFocus = null;

function openModal(html, wide) {
  closeMSelects();
  const root = el("modal-root");
  if (root.firstElementChild) closeModal(true);
  if (!root.firstElementChild) modalReturnFocus = document.activeElement;
  root.innerHTML = `
    <div class="modal-overlay" id="modal-overlay">
      <div class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        ${html}
      </div>
    </div>`;
  el("modal-overlay").addEventListener("mousedown", (e) => {
    if (e.target.id === "modal-overlay") closeModal();
  });
  document.addEventListener("keydown", escClose);
  root.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", closeModal));
  (root.querySelector("input:not([disabled]):not([type=file])") || root.querySelector("button"))?.focus();
  return root.querySelector(".modal");
}

function escClose(e) {
  if (e.key === "Escape" && !e.defaultPrevented) closeModal();
  if (e.key !== "Tab") return;
  const items = [...el("modal-root").querySelectorAll("button:not([disabled]), input:not([disabled]), textarea, a[href], [tabindex='0']")]
    .filter((item) => item.getClientRects().length > 0);
  if (!items.length) return;
  const first = items[0], last = items[items.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}
function closeModal(force = false) {
  const modal = el("modal-root").querySelector(".modal");
  if (modal?.closeBlocked && force !== true) return;
  if (modal?.onDismiss) modal.onDismiss();
  closeMSelects();
  el("modal-root").innerHTML = "";
  document.removeEventListener("keydown", escClose);
  if (modalReturnFocus?.isConnected) modalReturnFocus.focus();
  modalReturnFocus = null;
}

function modalHead(title) {
  return `<div class="modal-head"><h3 id="modal-title">${esc(title)}</h3><button class="modal-close" data-close aria-label="${esc(t("common.close"))}">${I.close}</button></div>`;
}

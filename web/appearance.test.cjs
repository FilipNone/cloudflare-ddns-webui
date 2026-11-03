"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");
const css = fs.readFileSync(path.join(__dirname, "style.css"), "utf8");

function rgb(color) {
  if (color.startsWith("#")) return [1, 3, 5].map((offset) => parseInt(color.slice(offset, offset + 2), 16));
  return color.match(/[\d.]+/g).slice(0, 3).map(Number);
}

function luminance(color) {
  const values = rgb(color).map((value) => value / 255 <= 0.04045 ? value / 255 / 12.92 : ((value / 255 + 0.055) / 1.055) ** 2.4);
  return values[0] * 0.2126 + values[1] * 0.7152 + values[2] * 0.0722;
}

function contrast(first, second) {
  const a = luminance(first), b = luminance(second);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

function node(tag = "div") {
  const classes = new Set();
  return {
    tagName: tag.toUpperCase(), children: [], dataset: {}, events: {}, attributes: {},
    style: { values: {}, setProperty(key, value) { this.values[key] = value; }, removeProperty(key) { delete this.values[key]; } },
    classList: {
      toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
      contains(name) { return classes.has(name); }, add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
    },
    appendChild(child) { this.children.push(child); return child; },
    append(...children) { this.children.push(...children); },
    addEventListener(event, callback) { this.events[event] = callback; },
    setAttribute(key, value) { this.attributes[key] = value; },
    querySelectorAll() { return []; }, querySelector() { return null; },
    replaceWith(replacement) { this.replacement = replacement; },
    getBoundingClientRect() { return { left: 20, top: 30, width: 40, height: 40 }; },
    click() { this.clicked = true; }, focus() {},
  };
}

function app({ reducedMotion = false } = {}) {
  const nodes = new Map();
  const storage = new Map();
  const root = node("html");
  const favicon = node("link");
  const logo = node("img");
  const document = {
    documentElement: root, activeElement: null,
    getElementById: (id) => nodes.get(id) || null,
    querySelectorAll: (selector) => selector === 'link[rel="icon"]' ? [favicon] : selector === "[data-brand-logo]" ? [logo, nodes.get("icon-preview")].filter(Boolean) : [],
    createElement: node, addEventListener() {}, removeEventListener() {},
  };
  const context = vm.createContext({
    document, localStorage: { getItem: (key) => storage.get(key) || null, setItem: (key, value) => storage.set(key, value) },
    location: { hash: "#/settings" },
    window: { innerWidth: 800, innerHeight: 600, matchMedia: (query) => ({ matches: query.includes("reduced-motion") && reducedMotion, addEventListener() {} }), addEventListener() {} },
    setTimeout, clearTimeout, console,
  });
  vm.runInContext(source.slice(0, source.indexOf("(async function boot()")), context);
  vm.runInContext("state.config = { accent: null, has_icon: false, version: 'synthetic' }; toast = () => {};", context);
  return { context, nodes, root, document, storage, favicon, logo, run: (code) => vm.runInContext(code, context) };
}

test("accent initialization validates colors and updates all derived accent tokens", () => {
  const { root, run } = app();
  run("applyAccent('#123456')");
  assert.equal(root.style.values["--accent"], "#123456");
  assert.notEqual(root.style.values["--accent-hover"], "#d96c0e");
  assert.ok(root.style.values["--accent-soft"].includes("18, 52, 86"));
  run("applyAccent('red; color: transparent')");
  assert.equal(root.style.values["--accent"], "#f6821f");
});

test("theme boot preserves the server accent while configuration is pending", () => {
  const { root, run } = app();
  root.style.setProperty("--accent", "#123456");
  run("state.config = null; applyTheme()");
  assert.equal(root.style.values["--accent"], "#123456");
});

test("saving and resetting accent update the current palette immediately", async () => {
  const { root, run } = app();
  run("api = async () => ({}); renderAccentRow = () => {};");
  await run("saveAccent('#22c55e')");
  assert.equal(root.style.values["--accent"], "#22c55e");
  assert.ok(root.style.values["--accent-soft"].includes("34, 197, 94"));
  await run("saveAccent(null)");
  assert.equal(run("state.config.accent"), null);
  assert.equal(root.style.values["--accent"], "#f6821f");
});

test("custom color has a square swatch with a pencil and accessible picker", () => {
  const { nodes, run } = app();
  const row = node(); nodes.set("accent-row", row);
  run("state.config.accent = '#123456'; renderAccentRow()");
  const custom = row.children.find((child) => child.className?.includes("swatch-custom"));
  assert.ok(custom);
  assert.match(custom.innerHTML, /svg/);
  const picker = custom.children.find((child) => child.type === "color");
  assert.ok(picker);
  assert.equal(picker.attributes["aria-label"], "Custom color");
  assert.equal(picker.value, "#123456");
  assert.match(css, /\.swatch-custom\s*\{[^}]*position:\s*relative/);
});

test("setup wires the same theme and language controls as login", () => {
  const { nodes, run } = app();
  nodes.set("setup-form", node("form"));
  run("let wired = 0; wireLoginShell = () => wired++; renderSetup({innerHTML:''});");
  assert.equal(run("wired"), 1);
});

test("signed-in topbar contains no theme control", () => {
  const { nodes, run } = app();
  const actions = node(); nodes.set("topbar-actions", actions);
  run("state.route = 'settings'; renderTopbarActions()");
  assert.equal(actions.children.length, 0);
});

test("theme transition radiates from the activating button", async () => {
  const { context, document, root, run } = app();
  let animation;
  root.animate = (frames, options) => { animation = { frames, options }; return { finished: Promise.resolve() }; };
  document.startViewTransition = (update) => { update(); return { ready: Promise.resolve(), finished: Promise.resolve(), skipTransition() {} }; };
  context.origin = node("button");
  run("setTheme('dark', origin)");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(root.classList.contains("dark"), true);
  assert.ok(animation);
  assert.match(animation.frames.clipPath[0], /circle\(0px at 40px 50px\)/);
  assert.equal(animation.options.pseudoElement, "::view-transition-new(root)");
});

for (const fallback of ["reduced motion", "unsupported", "throwing"]) {
  test(`theme changes safely with ${fallback} transition support`, () => {
    const { context, document, root, run } = app({ reducedMotion: fallback === "reduced motion" });
    let calls = 0;
    root.animate = () => {};
    if (fallback !== "unsupported") document.startViewTransition = () => { calls++; throw new Error("synthetic unsupported transition"); };
    context.origin = node("button");
    assert.doesNotThrow(() => run("setTheme('dark', origin)"));
    assert.equal(root.classList.contains("dark"), true);
    assert.equal(calls, fallback === "throwing" ? 1 : 0);
  });
}

test("branding upload and reset synchronize every logo, favicon and configuration", async () => {
  const { nodes, favicon, logo, run } = app();
  const input = node("input"); input.files = [{ type: "image/png", size: 32, arrayBuffer: async () => new ArrayBuffer(32) }];
  const preview = node("img");
  nodes.set("icon-input", input); nodes.set("icon-preview", preview);
  nodes.set("icon-upload", node("button")); nodes.set("icon-reset", node("button"));
  run("api = async () => ({}); wireIconSettings()");
  await input.events.change();
  assert.equal(run("state.config.has_icon"), true);
  assert.equal(logo.src, favicon.href);
  assert.equal(preview.src, favicon.href);
  assert.match(run("brandLogo()"), /brand-custom/);
  assert.ok(run("brandLogo()").includes(favicon.href.replace("http://localhost", "")));
  const uploaded = favicon.href;
  await nodes.get("icon-reset").events.click();
  assert.equal(run("state.config.has_icon"), false);
  assert.notEqual(favicon.href, uploaded);
  assert.match(logo.src, /\/static\/default-logo\.svg\?v=/);
  assert.match(run("brandLogo()"), /brand-default/);
});

test("failed appearance writes preserve the current accent and branding", async () => {
  const { nodes, root, favicon, run } = app();
  const input = node("input"); input.files = [{ type: "image/png", size: 32, arrayBuffer: async () => new ArrayBuffer(32) }];
  nodes.set("icon-input", input); nodes.set("icon-preview", node("img"));
  nodes.set("icon-upload", node("button")); nodes.set("icon-reset", node("button"));
  run("state.config.accent = '#123456'; applyAccent(state.config.accent); api = async () => { throw new Error('synthetic failure'); }; wireIconSettings();");
  await run("saveAccent('#ffffff')");
  assert.equal(root.style.values["--accent"], "#123456");
  assert.equal(run("state.config.accent"), "#123456");
  await input.events.change();
  assert.equal(run("state.config.has_icon"), false);
  assert.equal(favicon.href, undefined);
  run("state.config.has_icon = true;");
  await nodes.get("icon-reset").events.click();
  assert.equal(run("state.config.has_icon"), true);
});

test("contrast follows a custom accent rather than an orange-specific theme", () => {
  const { root, run } = app();
  run("applyAccent('#ffffff')");
  assert.equal(root.style.values["--accent-contrast"], "#000000");
  run("applyAccent('#000000')");
  assert.equal(root.style.values["--accent-contrast"], "#ffffff");
});

test("accent foreground and primary hover remain readable for custom colors in both themes", () => {
  const { root, run } = app();
  for (const theme of ["light", "dark"]) {
    for (const color of ["#000000", "#ffffff", "#6366f1", "#8060c0", "#f6821f", "#3b82f6", "#22c55e", "#a855f7", "#ef4444", "#14b8a6", "#eab308", "#ec4899"]) {
      run(`state.config.accent = '${color}'; setTheme('${theme}');`);
      const values = root.style.values;
      const foreground = values["--accent-text"] || values["--accent-hover"];
      const backgrounds = theme === "dark" ? ["#09090b", "#0d0d10", "#101013", "#141417", "#1a1a1f"] : ["#f4f4f6", "#ffffff", "#f0f0f3"];
      for (const surface of backgrounds) {
        const tinted = `rgb(${rgb(surface).map((value, index) => value * 0.88 + rgb(color)[index] * 0.12).join(", ")})`;
        assert.ok(contrast(foreground, surface) >= 4.5, `${color} ${theme} text on ${surface}`);
        assert.ok(contrast(foreground, tinted) >= 4.5, `${color} ${theme} active text`);
      }
      assert.ok(contrast(values["--accent-contrast"], color) >= 4.5, `${color} primary text`);
      assert.ok(contrast(values["--accent-contrast"], values["--accent-hover"]) >= 4.5, `${color} hovered primary text`);
    }
  }
});

test("a rejected view transition still applies the theme and clears transient state", async () => {
  const { context, document, root, run } = app();
  root.animate = () => {};
  let skipped = false;
  document.startViewTransition = () => ({ ready: Promise.reject(new Error("synthetic skipped transition")), finished: Promise.reject(new Error("synthetic skipped transition")), skipTransition() { skipped = true; } });
  context.origin = node("button");
  run("setTheme('dark', origin)");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(root.classList.contains("dark"), true);
  assert.equal(root.classList.contains("theme-changing"), false);
  assert.equal(skipped, true);
});

test("default logo keeps its own two-tone colors and raster images keep aspect", () => {
  assert.doesNotMatch(css, /mask(?:-image)?:[^;]*default-logo\.svg/);
  assert.doesNotMatch(css, /\.brand-default[^}]*visibility:\s*hidden/);
  assert.match(css, /\.brand-logo[^}]*object-fit:\s*contain/);
  assert.match(css, /\.kv-table td\s*\{[^}]*vertical-align:\s*middle/);
});

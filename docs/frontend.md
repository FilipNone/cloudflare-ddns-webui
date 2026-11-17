# Frontend

Vanilla JavaScript, HTML and CSS compiled into the binary. No package manager, framework or build step, ever.

## Scripts

`web/index.html` loads ten classic scripts with `defer` in a fixed order, and they share one global scope:

```text
js/core.js           saved preferences, constants, state, formatters, validators
js/i18n.js           strings, t(), tHtml()
js/ui.js             icons, theme, toasts, select menus, dropdowns, modal frame
js/api.js            api() client, session reset, loaders
js/login.js          setup, sign-in, 2FA step
js/dashboard.js      DDNS page
js/records.js        records page: filters, list and cards, selection, pagination
js/record-modals.js  add/edit, bulk edit, delete, import/export dialogs
js/settings.js       appearance, security, 2FA, recovery codes, password
app.js               entry script, always last: page shell, navigation, boot
```

- Code that runs while a file loads may only use what that file or an earlier one defines. Function declarations from a later file are not visible yet.
- A new script needs a `defer` tag with `?v=__VERSION__` in `index.html` and an entry in `SCRIPTS` in `src/routes.rs`. A Rust test and a Node test check that both lists match.
- The Node tests read the order from `index.html`, join the files, and stop before `boot()`.

## CSP and escaping

The CSP is `default-src 'self'`, with no inline scripts or styles.

- No `style=` attributes, inline handlers, `eval` or `new Function`. Set dynamic styles with `el.style.setProperty` or classes.
- Every server or user value inserted with `innerHTML` goes through `esc()`, attributes included.
- Translation keys whose text contains markup end in `.html` and are read only through `tHtml()`, which escapes interpolated values.

## Conventions

- All strings live in the `I18N` table in `js/i18n.js`; use `t()`.
- `localStorage` access goes through `readStored()` and `writeStored()`, which never throw.
- `api()` sends `X-Requested-With: fetch`. Auth calls that issue a new session pass `{ rotatesSession: true }`.
- Request bodies must match the backend structs exactly (the server rejects unknown fields).
- Mirror the backend rules: only A, AAAA and CNAME can be proxied, proxied means TTL 1, TTL is 1 or 30 to 86400, and comments are at most 500 UTF-8 bytes.

## Design reference

The layout follows the Cloudflare dashboard's DNS records page and its add-record form. Copy structure, spacing and interaction only. Where roadmap.md asks for different labels, defaults or animations, follow the roadmap. Don't copy Cloudflare's scripts, stylesheets, fonts, icons or logos; colours and sizes live in `web/style.css`.

Check visible changes in a browser at 1440x900 and 390x844 against a `--serve` instance (see workflow.md).

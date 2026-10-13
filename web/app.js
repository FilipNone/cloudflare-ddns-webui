/* Cloudflare DDNS Web UI - vanilla JS SPA. No build step, no frameworks. */
"use strict";

/* Theme applied immediately at parse time (before first paint). */
(function () {
  var mode = localStorage.getItem("cfddns.theme") || "system";
  var dark = mode === "dark" || (mode === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
})();

/* ================= i18n ================= */

const I18N = {
  en: {
    "app.name": "Cloudflare DDNS",
    "nav.dashboard": "Dashboard",
    "nav.records": "DNS Records",
    "nav.settings": "Settings",
    "nav.collapse": "Collapse",
    "nav.logout": "Log out",
    "nav.menu": "Navigation menu",
    "login.title": "Sign in",
    "login.subtitle": "Enter your admin password to manage your DNS.",
    "login.password": "Password",
    "login.submit": "Sign in",
    "login.error": "Invalid password. Please try again.",
    "login.wait": "Signing in...",
    "login.2fa.title": "Two-factor authentication",
    "login.2fa.subtitle": "Enter the 6-digit code from your authenticator app, or one of your backup codes.",
    "login.2fa.code": "Authentication code",
    "login.2fa.submit": "Verify",
    "login.2fa.back": "Back to sign in",
    "login.2fa.backup_used": "Signed in with a backup code. {n} backup codes remaining.",
    "login.github": "View on GitHub",
    "setup.title": "Welcome",
    "setup.subtitle": "Create the admin password for this installation. This only happens once.",
    "setup.password": "New password",
    "setup.confirm": "Confirm password",
    "setup.hint": "At least 8 characters.",
    "setup.submit": "Create password",
    "setup.mismatch": "Passwords do not match.",
    "setup.short": "Password must be at least 8 characters long.",
    "dash.title": "Dashboard",
    "dash.ipv4": "Public IPv4",
    "dash.ipv6": "Public IPv6",
    "dash.zones": "Zones",
    "dash.na": "Not available",
    "dash.ddns.title": "DDNS domains",
    "dash.ddns.desc": "Sync status of the domains configured via the DOMAINS environment variable.",
    "dash.ddns.not_configured": "No DDNS domains configured.",
    "dash.ddns.hint": "Set the DOMAINS environment variable (same as cloudflare-ddns) to enable sync status and on-demand updates.",
    "dash.ddns.update_now": "Update now",
    "dash.ddns.updating": "Updating...",
    "dash.ddns.domain": "Domain",
    "dash.ddns.type": "Type",
    "dash.ddns.detected": "Detected IP",
    "dash.ddns.dns": "DNS record",
    "dash.ddns.status": "Status",
    "dash.ddns.synced": "In sync",
    "dash.ddns.out_of_sync": "Out of sync",
    "dash.ddns.error": "Error",
    "dash.ddns.missing": "No record",
    "dash.ddns.update_failed": "DDNS update failed or partially completed",
    "dash.ddns.last_update": "Last manual update",
    "dash.ddns.contract": "Manual update contract: {contract}. Companion daemon status is not observed.",
    "records.title": "DNS Records",
    "records.add": "Add record",
    "records.import": "Import",
    "records.export": "Export",
    "records.search": "Search records...",
    "records.all_types": "All types",
    "records.columns": "Columns",
    "records.refresh": "Refresh",
    "records.selected": "{n} selected",
    "records.edit": "Edit",
    "records.delete": "Delete",
    "records.clear": "Clear selection",
    "records.showing": "Showing {from}-{to} of {total}",
    "records.per_page": "Rows per page",
    "records.empty.title": "No records found",
    "records.empty.desc": "No DNS records match your current filters, or this zone has no records yet.",
    "records.no_zones": "No zones available for this API token.",
    "col.type": "Type",
    "col.name": "Name",
    "col.content": "Content",
    "col.proxy": "Proxy status",
    "col.ttl": "TTL",
    "col.tags": "Tags",
    "col.comment": "Comment",
    "col.updated": "Last updated",
    "col.created": "Created",
    "col.actions": "Actions",
    "proxy.proxied": "Proxied",
    "proxy.dns_only": "DNS only",
    "proxy.na": "Not proxiable",
    "ttl.auto": "Auto",
    "modal.add.title": "Add DNS record",
    "modal.edit.title": "Edit DNS record",
    "modal.zone": "Zone",
    "modal.type": "Type",
    "modal.name": "Name",
    "modal.name.hint": "Use @ for the zone root. The record is created as name.{zone}",
    "modal.content": "Content",
    "modal.content.A": "IPv4 address",
    "modal.content.AAAA": "IPv6 address",
    "modal.content.CNAME": "Domain",
    "modal.content.TXT": "Content",
    "modal.content.MX": "Mail server",
    "modal.content.NS": "Name server",
    "modal.content.PTR": "Domain",
    "modal.priority": "Priority",
    "modal.srv.priority": "Priority",
    "modal.srv.weight": "Weight",
    "modal.srv.port": "Port",
    "modal.srv.target": "Target",
    "modal.caa.flags": "Flags",
    "modal.caa.tag": "Tag",
    "modal.caa.value": "Value",
    "modal.svc.priority": "Priority",
    "modal.svc.target": "Destination",
    "modal.svc.value": "Value (optional)",
    "modal.svc.value.hint": "Space-separated SvcParams, e.g. alpn=\"h3,h2\" ipv4hint=192.0.2.1",
    "modal.ttl": "TTL",
    "modal.ttl.proxied": "TTL is managed by Cloudflare while the record is proxied.",
    "modal.proxy": "Proxy status",
    "modal.proxy.hint": "Proxy this record through Cloudflare (orange cloud).",
    "modal.tags": "Tags",
    "modal.tags.hint": "Comma-separated, e.g. cf-proxied:true",
    "modal.comment": "Comment",
    "modal.save": "Save",
    "modal.create": "Create",
    "modal.cancel": "Cancel",
    "modal.required": "This field is required.",
    "modal.invalid": "Invalid value",
    "modal.invalid.ipv4": "Enter a valid IPv4 address (e.g. 192.0.2.1).",
    "modal.invalid.ipv6": "Enter a valid IPv6 address (e.g. 2001:db8::1).",
    "modal.invalid.domain": "Enter a valid domain name.",
    "modal.invalid.number": "Enter a number between {min} and {max}.",
    "modal.invalid.name": "Letters, digits, hyphens, dots, underscores and * only.",
    "modal.invalid.srvname": "SRV names must look like _service._tcp.name",
    "modal.bulk.title": "Edit {n} records",
    "modal.bulk.keep": "Keep as is",
    "modal.bulk.ttl": "TTL",
    "modal.bulk.proxy": "Proxy status",
    "modal.bulk.proxy.on": "Proxied",
    "modal.bulk.proxy.off": "DNS only",
    "modal.bulk.proxy.blocked": "Proxy cannot be changed: the selection contains record types that are not proxiable (only A, AAAA and CNAME are).",
    "modal.bulk.comment": "Comment",
    "modal.bulk.comment.keep": "Keep existing",
    "modal.bulk.comment.replace": "Replace with",
    "modal.bulk.comment.clear": "Clear comments",
    "modal.metadata.keep": "Keep existing",
    "modal.metadata.set": "Set value",
    "modal.metadata.clear": "Clear value",
    "modal.metadata.empty": "Enter a value or choose Clear value.",
    "modal.bulk.apply": "Apply to {n} records",
    "modal.delete.title": "Delete records",
    "modal.delete.one": "Delete this record?",
    "modal.delete.many": "Delete {n} records? This cannot be undone.",
    "modal.delete.confirm": "Delete",
    "modal.import.title": "Import DNS records",
    "modal.import.desc": "Upload a BIND zone file. Cloudflare parses it natively and appends new records - existing records are never replaced. Comments and cf_tags (e.g. cf-proxied:true) are honoured, exactly like the dashboard import.",
    "modal.import.drop": "Drop your zone file here, or <strong>browse</strong>",
    "modal.import.file_selected": "Selected: {name} ({size})",
    "modal.import.submit": "Import",
    "modal.import.result": "Imported {added} of {parsed} records.",
    "modal.import.skipped": "{n} records were skipped (already existing or unsupported).",
    "modal.import.empty": "The file contains no importable DNS records.",
    "settings.title": "Settings",
    "settings.appearance.title": "Appearance",
    "settings.appearance.desc": "Theme and branding of the interface.",
    "settings.theme": "Theme",
    "settings.theme.system": "System default",
    "settings.theme.light": "Light",
    "settings.theme.dark": "Dark",
    "settings.lang.title": "Language",
    "settings.lang.desc": "Interface language. More languages are coming soon.",
    "settings.accent": "Accent color",
    "settings.accent.hint": "Pick a preset or any custom color.",
    "settings.icon": "Logo & favicon",
    "settings.icon.hint": "PNG, JPEG, WebP or GIF, max 512 KB. Applied to the logo and used as the favicon.",
    "settings.icon.upload": "Upload image",
    "settings.icon.reset": "Reset to default",
    "settings.icon.too_big": "Image is larger than 512 KB.",
    "settings.icon.bad_type": "Unsupported format - use PNG, JPEG, WebP or GIF.",
    "settings.security.title": "Security",
    "settings.security.desc": "Password and two-factor authentication.",
    "settings.security.session": "Session lifetime",
    "settings.security.cookies": "Secure cookies",
    "settings.security.cookies.hint": "Set SECURE_COOKIES=true when serving the UI over HTTPS (recommended on Dokploy).",
    "settings.password.change": "Change password",
    "settings.password.current": "Current password",
    "settings.password.new": "New password",
    "settings.password.confirm": "Confirm new password",
    "settings.password.code": "2FA or backup code",
    "settings.password.code.hint": "Required because 2FA is enabled.",
    "settings.password.submit": "Update password",
    "settings.password.done": "Password updated.",
    "settings.2fa.title": "Two-factor authentication",
    "settings.2fa.desc": "Require a TOTP code from an authenticator app at sign-in, with one-time backup codes for recovery.",
    "settings.2fa.status.on": "Enabled",
    "settings.2fa.status.off": "Disabled",
    "settings.2fa.backup_count": "{n} backup codes remaining",
    "settings.2fa.enable": "Enable 2FA",
    "settings.2fa.disable": "Disable 2FA",
    "settings.2fa.scan": "Scan this QR code with your authenticator app (Aegis, Bitwarden, Google Authenticator...), then enter the 6-digit code to confirm.",
    "settings.2fa.manual": "Or enter the secret manually:",
    "settings.2fa.code": "6-digit code",
    "settings.2fa.confirm": "Confirm & activate",
    "settings.2fa.cancel": "Cancel",
    "settings.2fa.backup.title": "Save your backup codes",
    "settings.2fa.backup.desc": "These codes are shown only once. Each can be used a single time if you lose access to your authenticator app.",
    "settings.2fa.backup.download": "Download as .txt",
    "settings.2fa.backup.done": "Done",
    "settings.2fa.backup.pending": "Your new recovery codes have not been acknowledged. Keep this page open until you have saved them.",
    "settings.2fa.backup.reopen": "View recovery codes",
    "settings.2fa.disable.hint": "Enter a current 2FA code (or a backup code) to disable two-factor authentication.",
    "settings.token.title": "Cloudflare API token",
    "settings.token.desc": "The web UI talks to Cloudflare with an API token supplied via the CLOUDFLARE_API_TOKEN environment variable. Create it with the following preset:",
    "settings.token.step1": "Open <strong>My Profile -> API Tokens</strong> in the Cloudflare dashboard.",
    "settings.token.step2": "Click <strong>Create Token</strong> and choose the <strong>Edit zone DNS</strong> template.",
    "settings.token.step3": "Keep permissions <code>Zone -> DNS -> Edit</code> and add <code>Zone -> Zone -> Read</code>.",
    "settings.token.step4": "Under <strong>Zone Resources</strong> pick <em>Include -> Specific zone</em> for least privilege (or <em>All zones</em>).",
    "settings.token.step5": "Create the token and set it as <code>CLOUDFLARE_API_TOKEN</code> (or mount it via <code>CLOUDFLARE_API_TOKEN_FILE</code>).",
    "settings.about.title": "About",
    "settings.about.version": "Version",
    "settings.about.source": "Source code",
    "settings.about.upstream": "Based on the philosophy of",
    "common.yes": "Yes",
    "common.no": "No",
    "common.close": "Close",
    "common.copy": "Click to copy",
    "common.copied": "Copied to clipboard",
    "common.enabled": "Enabled",
    "common.disabled": "Disabled",
    "toast.saved": "Record saved",
    "toast.created": "Record created",
    "toast.deleted": "Record deleted",
    "toast.bulk_delete": "Deleted {ok} records{fail_part}",
    "toast.bulk_update": "Updated {ok} records{fail_part}",
    "toast.fail_suffix": ", {n} failed",
    "toast.error": "Error",
    "toast.exported": "Zone file exported",
    "toast.updated_ddns": "DDNS update finished",
    "toast.accent": "Accent color updated",
    "toast.icon": "Logo updated",
    "toast.2fa.enabled": "Two-factor authentication enabled",
    "toast.2fa.disabled": "Two-factor authentication disabled",
    "toast.password": "Password updated",
  },
};

const LANGS = [{ code: "en", name: "English" }];

let lang = localStorage.getItem("cfddns.lang") || "en";
function t(key, vars) {
  let s = (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, v);
  return s;
}

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

/* ================= Constants & state ================= */

const RECORD_TYPES = ["A", "AAAA", "CAA", "CNAME", "HTTPS", "MX", "NS", "PTR", "SRV", "SVCB", "TXT"];
const PROXIABLE = ["A", "AAAA", "CNAME"];
const TTL_OPTIONS = [
  [1, "Auto"], [60, "1 min"], [120, "2 min"], [300, "5 min"], [600, "10 min"],
  [1800, "30 min"], [3600, "1 hour"], [7200, "2 hours"], [18000, "5 hours"],
  [43200, "12 hours"], [86400, "1 day"],
];
const ACCENT_PRESETS = ["#f6821f", "#3b82f6", "#22c55e", "#a855f7", "#ef4444", "#14b8a6", "#eab308", "#ec4899"];
// NOTE: .sw-0..sw-7 classes in style.css must stay in the same order.

const DEFAULT_COLUMNS = {
  type: true, name: true, content: true, proxy: true, ttl: true,
  tags: true, comment: true, updated: false, created: false,
};
const COLUMN_ORDER = ["type", "name", "content", "proxy", "ttl", "tags", "comment", "updated", "created"];

const state = {
  authed: false,
  configured: true,
  totpEnabled: false,
  route: location.hash.replace("#/", "") || "dashboard",
  zones: [],
  zoneId: null,
  records: [],
  recordsTotal: 0,
  recordsZoneId: null,
  recordsLoading: false,
  recordsAttemptedZoneId: null,
  recordsError: null,
  search: "",
  typeFilter: "",
  sort: { key: "name", dir: 1 },
  page: 1,
  perPage: parseInt(localStorage.getItem("cfddns.perPage") || "20", 10),
  selection: new Set(),
  columns: { ...DEFAULT_COLUMNS, ...JSON.parse(localStorage.getItem("cfddns.columns") || "{}") },
  sidebarCollapsed: localStorage.getItem("cfddns.sidebar") === "collapsed",
  mobileNavOpen: false,
  ddns: null,
  ddnsLoading: false,
  ddnsUpdating: false,
  ddnsUpdateResult: null,
  sessionTtl: null,
  backupCodesRemaining: 0,
  config: null,
  pendingChallenge: null,
  pendingBackupCodes: null,
};

let authGeneration = 0;
let pageGeneration = 0;
let recordsRequest = 0;
let ddnsRequest = 0;

function invalidatePageRequests() {
  pageGeneration++;
  recordsRequest++;
  ddnsRequest++;
  if (state.recordsLoading) state.recordsAttemptedZoneId = null;
  state.recordsLoading = false;
  state.ddnsLoading = false;
  state.mobileNavOpen = false;
  closeMSelects();
  closeModal(true);
}

/* ================= Theme ================= */

const themeMedia = window.matchMedia("(prefers-color-scheme: dark)");
themeMedia.addEventListener("change", () => applyTheme());

function currentTheme() { return localStorage.getItem("cfddns.theme") || "system"; }

function applyTheme() {
  const mode = currentTheme();
  const dark = mode === "dark" || (mode === "system" && themeMedia.matches);
  document.documentElement.classList.toggle("dark", dark);
}

function setTheme(mode) {
  localStorage.setItem("cfddns.theme", mode);
  applyTheme();
}

function themeIcon() {
  const mode = currentTheme();
  return mode === "dark" ? I.moon : mode === "light" ? I.sun : I.monitor;
}

function cycleTheme() {
  const order = ["system", "light", "dark"];
  const next = order[(order.indexOf(currentTheme()) + 1) % order.length];
  setTheme(next);
  document.querySelectorAll("[data-theme-btn]").forEach((b) => {
    b.innerHTML = themeIcon();
    b.title = t("settings.theme." + (next === "system" ? "system" : next));
  });
}

/* ================= Helpers ================= */

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function el(id) { return document.getElementById(id); }

function currentZone() { return state.zones.find((z) => z.id === state.zoneId) || null; }

function fmtTtl(ttl) {
  if (ttl === 1 || ttl == null) return t("ttl.auto");
  const opt = TTL_OPTIONS.find(([v]) => v === ttl);
  if (opt) return opt[1];
  if (ttl % 3600 === 0) return `${ttl / 3600} h`;
  if (ttl % 60 === 0) return `${ttl / 60} min`;
  return `${ttl}s`;
}

function fmtDate(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString(lang === "en" ? "en-US" : lang, {
      year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  } catch { return iso; }
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
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

/* ================= Validation ================= */

const V = {
  ipv4(v) { return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(v.trim()) && v.trim().split(".").every((o) => +o <= 255); },
  ipv6(v) { return /^[0-9a-fA-F:]+$/.test(v.trim()) && v.includes(":"); },
  domain(v) { return /^(\*\.)?([a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.?$/.test(v.trim()) || /^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9])?\.?$/.test(v.trim()); },
  recordName(v) { return v === "@" || /^[a-zA-Z0-9_*]([a-zA-Z0-9._-]*)$/.test(v.trim()); },
  srvName(v) { return /^_[a-zA-Z0-9-]+\._(tcp|udp)\..+$/.test(v.trim()) || v === "@"; },
  uint(v, min, max) { const n = Number(v); return Number.isInteger(n) && n >= min && n <= max; },
};

/* ================= API ================= */

async function api(path, opts = {}) {
  const authentication = authGeneration;
  const page = pageGeneration;
  const zoneId = state.zoneId;
  const init = {
    method: opts.method || "GET",
    credentials: "same-origin",
    headers: { "X-Requested-With": "fetch" },
  };
  if (opts.json !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.json);
  } else if (opts.raw !== undefined) {
    init.headers["Content-Type"] = opts.rawType || "text/plain";
    init.body = opts.raw;
  }
  let resp;
  try {
    resp = await fetch(path, init);
  } catch {
    throw new Error("network error - is the server reachable?");
  }
  if (resp.status === 401 && !path.startsWith("/api/auth/")) {
    if (authentication === authGeneration && page === pageGeneration && zoneId === state.zoneId) {
      authGeneration++;
      state.authed = false;
      state.ddnsUpdating = false;
      state.ddnsUpdateResult = null;
      state.pendingBackupCodes = null;
      invalidatePageRequests();
      render();
    }
    throw new Error("unauthorized");
  }
  const sameAuthentication = authentication === authGeneration;
  if (resp.ok && init.method === "POST" && sameAuthentication
    && ["/api/auth/setup", "/api/auth/login", "/api/auth/login/2fa", "/api/auth/logout", "/api/auth/password", "/api/auth/2fa/confirm", "/api/auth/2fa/disable"].includes(path)) {
    authGeneration++;
    recordsRequest++;
    ddnsRequest++;
    if (state.recordsLoading) state.recordsAttemptedZoneId = null;
    state.recordsLoading = false;
    state.ddnsLoading = false;
    state.ddnsUpdating = false;
    state.ddnsUpdateResult = null;
    if (["/api/auth/setup", "/api/auth/login", "/api/auth/login/2fa", "/api/auth/logout"].includes(path)) {
      state.pendingBackupCodes = null;
    }
  }
  if (resp.ok && sameAuthentication && opts.authContext) opts.authContext.generation = authGeneration;
  const ct = resp.headers.get("content-type") || "";
  if (opts.text) {
    const body = await resp.text();
    if (!resp.ok) {
      let msg = body;
      try { msg = JSON.parse(body).error || body; } catch { /* keep raw */ }
      throw new Error(msg);
    }
    return body;
  }
  if (ct.includes("application/json")) {
    const data = await resp.json();
    if (!resp.ok) {
      const err = new Error(data.error || `HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }
  if (!resp.ok) {
    const err = new Error(`HTTP ${resp.status}`);
    err.status = resp.status;
    throw err;
  }
  return null;
}

/* ================= Modern select component ================= */

let openMSelect = null;

function closeMSelects() {
  document.querySelectorAll(".mselect.open, .dropdown.open").forEach((m) => {
    m.classList.remove("open");
    m.querySelector("button")?.setAttribute("aria-expanded", "false");
  });
  document.querySelectorAll(".menu.open").forEach((m) => m.classList.remove("open"));
  openMSelect = null;
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

/**
 * Build a modern dropdown. opts: {id, options: [{value,label,group?}], value,
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

  const getValue = () => wrap.dataset.value ?? "";
  const setLabel = (v) => {
    const opt = opts.options.find((o) => String(o.value) === String(v));
    label.textContent = opt ? opt.label : (opts.placeholder || "");
  };

  let lastGroup = null;
  for (const o of opts.options) {
    if (o.group && o.group !== lastGroup) {
      lastGroup = o.group;
      const g = document.createElement("div");
      g.className = "mselect-group";
      g.textContent = o.group;
      menu.appendChild(g);
    }
    const item = document.createElement("button");
    item.type = "button";
    item.className = "mselect-option";
    item.dataset.value = o.value;
    item.innerHTML = `<span class="check">${String(o.value) === String(opts.value) ? I.check : ""}</span><span>${esc(o.label)}</span>`;
    if (String(o.value) === String(opts.value)) item.classList.add("selected");
    item.addEventListener("click", () => {
      wrap.dataset.value = o.value;
      setLabel(o.value);
      menu.querySelectorAll(".mselect-option").forEach((x) => {
        x.classList.toggle("selected", x.dataset.value === String(o.value));
        x.querySelector(".check").innerHTML = x.dataset.value === String(o.value) ? I.check : "";
      });
      closeMSelects();
      btn.focus();
      if (opts.onChange) opts.onChange(o.value);
    });
    menu.appendChild(item);
  }

  wrap.dataset.value = opts.value ?? "";
  setLabel(opts.value);

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
    openMSelect = wrap;
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

  wrap.mset = (v) => {
    wrap.dataset.value = v;
    setLabel(v);
    menu.querySelectorAll(".mselect-option").forEach((x) => {
      x.classList.toggle("selected", x.dataset.value === String(v));
      x.querySelector(".check").innerHTML = x.dataset.value === String(v) ? I.check : "";
    });
  };
  wrap.mget = getValue;
  wrap.msetDisabled = (d) => { btn.disabled = d; };
  wrap.msetOptions = (newOptions, value) => {
    opts.options = newOptions;
    menu.innerHTML = "";
    let lg = null;
    for (const o of newOptions) {
      if (o.group && o.group !== lg) {
        lg = o.group;
        const g = document.createElement("div");
        g.className = "mselect-group";
        g.textContent = o.group;
        menu.appendChild(g);
      }
      const item = document.createElement("button");
      item.type = "button";
      item.className = "mselect-option";
      item.dataset.value = o.value;
      item.innerHTML = `<span class="check">${String(o.value) === String(value) ? I.check : ""}</span><span>${esc(o.label)}</span>`;
      if (String(o.value) === String(value)) item.classList.add("selected");
      item.addEventListener("click", () => {
        wrap.dataset.value = o.value;
        setLabel(o.value);
        closeMSelects();
        if (opts.onChange) opts.onChange(o.value);
      });
      menu.appendChild(item);
    }
    wrap.mset(value);
  };
  return wrap;
}

/* Simple dropdown menu (topbar/columns) */
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

/* ================= Data loading ================= */

async function loadZones() {
  state.zones = await api("/api/zones");
  const preferred = localStorage.getItem("cfddns.zone");
  if (preferred && state.zones.some((z) => z.id === preferred)) {
    state.zoneId = preferred;
  } else if (state.zones.length > 0) {
    state.zoneId = state.zones[0].id;
  } else {
    state.zoneId = null;
  }
}

async function loadRecords() {
  if (!state.zoneId) { state.records = []; state.recordsTotal = 0; state.recordsZoneId = null; return; }
  const zoneId = state.zoneId;
  const generation = pageGeneration;
  const authentication = authGeneration;
  const request = ++recordsRequest;
  const current = () => request === recordsRequest && generation === pageGeneration && authentication === authGeneration
    && state.authed && state.route === "records" && state.zoneId === zoneId;
  state.recordsLoading = true;
  state.recordsAttemptedZoneId = zoneId;
  state.recordsError = null;
  state.selection.clear();
  renderRecordsTable();
  try {
    const data = await api(`/api/zones/${zoneId}/records`);
    if (!current()) return;
    state.records = data.records || [];
    state.recordsTotal = data.total ?? state.records.length;
    state.recordsZoneId = zoneId;
    state.selection.clear();
    state.page = 1;
  } catch (e) {
    if (current()) state.recordsError = e.message;
  } finally {
    if (current()) state.recordsLoading = false;
  }
}

async function loadDdns() {
  const generation = pageGeneration;
  const authentication = authGeneration;
  const request = ++ddnsRequest;
  const current = () => request === ddnsRequest && generation === pageGeneration && authentication === authGeneration
    && state.authed && state.route === "dashboard";
  state.ddnsLoading = true;
  renderDashboardCards();
  try {
    const status = await api("/api/ddns/status");
    if (current()) state.ddns = status;
  } catch (e) {
    if (current()) state.ddns = { error: e.message, domains: [] };
  } finally {
    if (current()) state.ddnsLoading = false;
  }
}

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
          <img src="/static/favicon.svg?v=${state.config?.version || "1"}" alt="logo">
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
    localStorage.setItem("cfddns.sidebar", state.sidebarCollapsed ? "collapsed" : "expanded");
    el("layout").classList.toggle("collapsed", state.sidebarCollapsed);
  });
  el("logout-btn").addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch { /* ignore */ }
    state.authed = false;
    state.ddnsUpdating = false;
    invalidatePageRequests();
    state.records = []; state.recordsZoneId = null; state.recordsAttemptedZoneId = null;
    state.ddns = null; state.ddnsUpdateResult = null;
    state.pendingBackupCodes = null;
    navigate("dashboard");
    render();
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
        localStorage.setItem("cfddns.zone", v);
        state.search = ""; state.typeFilter = "";
        await refreshRecords();
      },
    });
    box.appendChild(zoneSelect);
  }
  const themeBtn = document.createElement("button");
  themeBtn.className = "btn icon";
  themeBtn.dataset.themeBtn = "1";
  themeBtn.title = t("settings.theme." + currentTheme());
  themeBtn.innerHTML = themeIcon();
  themeBtn.addEventListener("click", cycleTheme);
  box.appendChild(themeBtn);
}

/* ================= Render: first-run setup ================= */

function renderSetup(app) {
  app.innerHTML = loginShell(`
    <form class="login-card" id="setup-form">
      <div class="login-logo">
        <img src="/static/favicon.svg" alt="logo">
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

  el("setup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errBox = el("setup-error");
    const btn = el("setup-submit");
    errBox.classList.remove("visible");
    const password = el("setup-password").value;
    const confirm = el("setup-confirm").value;
    if (password.length < 8) { errBox.textContent = t("setup.short"); errBox.classList.add("visible"); return; }
    if (password !== confirm) { errBox.textContent = t("setup.mismatch"); errBox.classList.add("visible"); return; }
    btn.disabled = true;
    try {
      await api("/api/auth/setup", { method: "POST", json: { password, confirm } });
      state.configured = true;
      state.authed = true;
      await bootAuthed();
    } catch (err) {
      errBox.textContent = err.message;
      errBox.classList.add("visible");
      btn.disabled = false;
    }
  });
}

/* ================= Render: login ================= */

function loginShell(cardHtml) {
  return `
    <div class="login-wrap">
      <div class="login-corner">
        <button class="btn icon" data-theme-btn="1" title="${esc(t("settings.theme." + currentTheme()))}">${themeIcon()}</button>
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
      localStorage.setItem("cfddns.lang", lang);
      render();
    })
  );
}

function renderLogin(app) {
  if (state.pendingChallenge) { renderLogin2fa(app); return; }
  app.innerHTML = loginShell(`
    <form class="login-card" id="login-form">
      <div class="login-logo">
        <img src="/static/favicon.svg" alt="logo">
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
      const res = await api("/api/auth/login", { method: "POST", json: { password: el("login-password").value } });
      if (res.requires_2fa) {
        state.pendingChallenge = res.challenge;
        render();
        return;
      }
      state.authed = true;
      await bootAuthed();
    } catch (err) {
      errBox.textContent = err.status === 401 ? t("login.error") : err.message;
      errBox.classList.add("visible");
      btn.disabled = false;
      btn.textContent = t("login.submit");
    }
  });
}

function renderLogin2fa(app) {
  app.innerHTML = loginShell(`
    <form class="login-card" id="login2fa-form">
      <div class="login-logo">
        <img src="/static/favicon.svg" alt="logo">
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
      });
      state.pendingChallenge = null;
      state.authed = true;
      if (res.backup_code_used) {
        toast(t("login.2fa.backup_used", { n: res.backup_codes_remaining }), "info");
      }
      await bootAuthed();
    } catch (err) {
      errBox.textContent = err.message;
      errBox.classList.add("visible");
      btn.disabled = false;
    }
  });
}

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

function renderDashboardCards() {
  const grid = el("stat-grid");
  if (!grid) return;
  const d = state.ddns;
  const loading = state.ddnsLoading || d === null;
  grid.innerHTML = `
    <div class="stat-card">
      <div class="stat-label">${I.globe} ${esc(t("dash.ipv4"))}</div>
      <div class="stat-value ${!(d && d.ipv4) ? "na" : ""}">${loading ? '<div class="spinner small"></div>' : esc((d && d.ipv4) || (d && d.ipv4_error) || t("dash.na"))}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">${I.globe} ${esc(t("dash.ipv6"))}</div>
      <div class="stat-value ${!(d && d.ipv6) ? "na" : ""}">${loading ? '<div class="spinner small"></div>' : esc((d && d.ipv6) || (d && d.ipv6_error) || t("dash.na"))}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">${I.dns} ${esc(t("dash.zones"))}</div>
      <div class="stat-value">${state.zones.length}</div>
    </div>`;

  const section = el("ddns-section");
  if (!section) return;
  if (d && d.configured === false) {
    section.innerHTML = `
      <div class="card"><div class="card-pad">
        <div class="card-title">${esc(t("dash.ddns.title"))}</div>
        <div class="card-desc">${esc(t("dash.ddns.desc"))}</div>
        <div class="empty-state u-empty-sm">
          ${I.file}
          <h4>${esc(t("dash.ddns.not_configured"))}</h4>
          <p>${esc(t("dash.ddns.hint"))}</p>
        </div>
      </div>${ddnsUpdateLog()}</div>`;
    return;
  }
  const rows = (d && d.domains ? d.domains : []).map((dom) => {
    let statusBadge;
    if (dom.error) statusBadge = `<span class="badge red">${esc(t("dash.ddns.error"))}</span>`;
    else if (dom.in_sync) statusBadge = `<span class="badge green">${esc(t("dash.ddns.synced"))}</span>`;
    else if (dom.dns_ips.length === 0) statusBadge = `<span class="badge yellow">${esc(t("dash.ddns.missing"))}</span>`;
    else statusBadge = `<span class="badge yellow">${esc(t("dash.ddns.out_of_sync"))}</span>`;
    return `<tr>
      <td class="name-cell">${esc(dom.domain)}</td>
      <td><span class="badge">${esc(dom.record_type)}</span></td>
      <td class="mono">${esc(dom.detected_ip || "-")}</td>
      <td class="mono">${esc(dom.dns_ips.join(", ") || "-")}</td>
      <td>${statusBadge}${dom.error ? `<div class="cell-muted u-err-detail">${esc(dom.error)}</div>` : ""}</td>
    </tr>`;
  }).join("");
  section.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <div class="card-title u-mb0">${esc(t("dash.ddns.title"))}</div>
        <div class="u-flex1"></div>
        <button class="btn ghost sm" id="ddns-refresh" ${state.ddnsLoading ? "disabled" : ""}>${I.refresh} ${esc(t("records.refresh"))}</button>
        <button class="btn primary sm" id="ddns-update" ${state.ddnsUpdating || state.ddnsLoading || !d || d.error || d.manual_updates_enabled === false ? "disabled" : ""}>${I.bolt} ${esc(t(state.ddnsUpdating ? "dash.ddns.updating" : "dash.ddns.update_now"))}</button>
      </div>
      ${d?.error ? `<div class="card-pad login-error visible" role="alert">${esc(d.error)}</div>` : ""}
      ${d?.contract_version ? `<div class="card-pad cell-muted">${esc(t("dash.ddns.contract", { contract: d.contract_version }))}</div>` : ""}
      <div class="table-wrap">
        <table class="data">
          <thead><tr>
            <th>${esc(t("dash.ddns.domain"))}</th>
            <th>${esc(t("dash.ddns.type"))}</th>
            <th>${esc(t("dash.ddns.detected"))}</th>
            <th>${esc(t("dash.ddns.dns"))}</th>
            <th>${esc(t("dash.ddns.status"))}</th>
          </tr></thead>
          <tbody>${state.ddnsLoading ? `<tr><td colspan="5"><div class="skeleton"></div></td></tr>` : rows || `<tr><td colspan="5" class="cell-muted u-cell-empty">${esc(t("dash.ddns.not_configured"))}</td></tr>`}</tbody>
        </table>
      </div>
      ${ddnsUpdateLog()}
    </div>`;

  const refreshBtn = el("ddns-refresh");
  if (refreshBtn) refreshBtn.addEventListener("click", async () => { await loadDdns(); renderDashboard(); });
  const updateBtn = el("ddns-update");
  if (updateBtn) updateBtn.addEventListener("click", async () => {
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
  });
}

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
        <div class="dropdown">
          <button class="btn" id="columns-btn">${I.columns} ${esc(t("records.columns"))}</button>
          <div class="menu" id="columns-menu">
            <div class="menu-label">${esc(t("records.columns"))}</div>
            ${COLUMN_ORDER.map((c) => `<button class="menu-item" data-col="${c}"><span class="check">${state.columns[c] ? I.check : ""}</span>${esc(t("col." + c))}</button>`).join("")}
          </div>
        </div>
        <button class="btn icon" id="refresh-btn" title="Refresh">${I.refresh}</button>
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
  bindDropdown("columns-btn", "columns-menu");
  document.querySelectorAll("#columns-menu [data-col]").forEach((b) =>
    b.addEventListener("click", () => {
      state.columns[b.dataset.col] = !state.columns[b.dataset.col];
      localStorage.setItem("cfddns.columns", JSON.stringify(state.columns));
      closeMSelects();
      renderRecords();
    })
  );
  el("refresh-btn").addEventListener("click", refreshRecords);
  el("add-btn").addEventListener("click", () => openRecordModal(null));
  el("export-btn").addEventListener("click", exportZone);
  el("import-btn").addEventListener("click", openImportModal);
  el("bulk-edit").addEventListener("click", openBulkEditModal);
  el("bulk-delete").addEventListener("click", openBulkDeleteModal);
  el("bulk-clear").addEventListener("click", () => { state.selection.clear(); renderRecordsTable(); });

  renderRecordsTable();
}

function renderRecordsTable() {
  const wrap = el("table-wrap");
  if (!wrap) return;

  if (state.recordsLoading) {
    wrap.innerHTML = `<table class="data"><tbody>
      ${Array.from({ length: 5 }).map(() => `<tr class="skeleton-row"><td colspan="8"><div class="skeleton"></div></td></tr>`).join("")}
    </tbody></table>`;
    el("pagination").innerHTML = "";
    updateBulkbar();
    return;
  }

  if (state.recordsError || state.recordsZoneId !== state.zoneId) {
    wrap.innerHTML = `<div class="card-pad login-error visible" role="alert">${esc(state.recordsError || t("records.empty.desc"))}</div>`;
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

  const c = state.columns;
  const headCols = [];
  headCols.push(`<th class="u-w-check"><span class="checkbox" id="select-all"></span></th>`);
  const sortTh = (key, label) => {
    const arrow = state.sort.key === key ? `<span class="sort-arrow">${state.sort.dir === 1 ? "▲" : "▼"}</span>` : "";
    return `<th class="sortable" data-sort="${key}">${esc(label)}${arrow}</th>`;
  };
  if (c.type) headCols.push(sortTh("type", t("col.type")));
  if (c.name) headCols.push(sortTh("name", t("col.name")));
  if (c.content) headCols.push(sortTh("content", t("col.content")));
  if (c.proxy) headCols.push(`<th>${esc(t("col.proxy"))}</th>`);
  if (c.ttl) headCols.push(sortTh("ttl", t("col.ttl")));
  if (c.tags) headCols.push(`<th>${esc(t("col.tags"))}</th>`);
  if (c.comment) headCols.push(`<th>${esc(t("col.comment"))}</th>`);
  if (c.updated) headCols.push(sortTh("updated", t("col.updated")));
  if (c.created) headCols.push(sortTh("created", t("col.created")));
  headCols.push(`<th class="u-w-actions">${esc(t("col.actions"))}</th>`);

  const bodyRows = rows.map((r) => {
    const selected = state.selection.has(r.id);
    const cells = [];
    cells.push(`<td><span class="checkbox ${selected ? "checked" : ""}" data-select="${esc(r.id)}"></span></td>`);
    if (c.type) cells.push(`<td><span class="badge">${esc(r.type)}</span></td>`);
    if (c.name) cells.push(`<td class="name-cell" title="${esc(r.name)}">${esc(r.name)}</td>`);
    if (c.content) {
      const content = r.type === "SRV" && r.data
        ? `${r.data.priority ?? ""} ${r.data.weight ?? ""} ${r.data.port ?? ""} ${r.data.target ?? r.content}`
        : r.content;
      cells.push(`<td class="mono truncate cell-copy" data-copy="${esc(r.content)}" title="${esc(t("common.copy"))}: ${esc(r.content)}">${esc(content)}</td>`);
    }
    if (c.proxy) {
      if (r.proxiable) {
        const on = !!r.proxied;
        cells.push(`<td><span class="proxy-pill ${on ? "on" : "off"}">${on ? I.cloudFill : I.cloud}<span>${esc(on ? t("proxy.proxied") : t("proxy.dns_only"))}</span></span></td>`);
      } else {
        cells.push(`<td><span class="proxy-pill" title="${esc(t("proxy.na"))}">${I.cloud}<span class="cell-muted">-</span></span></td>`);
      }
    }
    if (c.ttl) cells.push(`<td>${esc(fmtTtl(r.ttl))}</td>`);
    if (c.tags) cells.push(`<td class="truncate">${(r.tags || []).map((tag) => `<span class="tag-chip">${esc(tag)}</span>`).join("") || '<span class="cell-muted">-</span>'}</td>`);
    if (c.comment) cells.push(`<td class="truncate cell-muted" title="${esc(r.comment || "")}">${esc(r.comment || "-")}</td>`);
    if (c.updated) cells.push(`<td class="cell-muted u-nowrap">${esc(fmtDate(r.modified_on))}</td>`);
    if (c.created) cells.push(`<td class="cell-muted u-nowrap">${esc(fmtDate(r.created_on))}</td>`);
    cells.push(`<td class="u-nowrap">
      <button class="btn ghost icon sm" data-edit="${esc(r.id)}" title="${esc(t("records.edit"))}">${I.edit}</button>
      <button class="btn ghost icon sm danger" data-delete="${esc(r.id)}" title="${esc(t("records.delete"))}">${I.trash}</button>
    </td>`);
    return `<tr class="${selected ? "selected" : ""}" data-row="${esc(r.id)}">${cells.join("")}</tr>`;
  }).join("");

  wrap.innerHTML = rows.length === 0
    ? `<div class="empty-state">${I.file}<h4>${esc(t("records.empty.title"))}</h4><p>${esc(t("records.empty.desc"))}</p></div>`
    : `<table class="data"><thead><tr>${headCols.join("")}</tr></thead><tbody>${bodyRows}</tbody></table>`;

  const selectAll = el("select-all");
  if (selectAll) {
    const pageIds = rows.map((r) => r.id);
    const selectedOnPage = pageIds.filter((id) => state.selection.has(id)).length;
    selectAll.classList.toggle("checked", selectedOnPage > 0 && selectedOnPage === pageIds.length);
    selectAll.classList.toggle("indeterminate", selectedOnPage > 0 && selectedOnPage < pageIds.length);
    selectAll.addEventListener("click", () => {
      if (selectedOnPage === pageIds.length) pageIds.forEach((id) => state.selection.delete(id));
      else pageIds.forEach((id) => state.selection.add(id));
      renderRecordsTable();
    });
  }
  wrap.querySelectorAll("[data-select]").forEach((cb) =>
    cb.addEventListener("click", () => {
      const id = cb.dataset.select;
      if (state.selection.has(id)) state.selection.delete(id);
      else state.selection.add(id);
      renderRecordsTable();
    })
  );
  wrap.querySelectorAll("[data-sort]").forEach((th) =>
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.sort.key === key) state.sort.dir *= -1;
      else state.sort = { key, dir: 1 };
      renderRecordsTable();
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
  wrap.querySelectorAll("[data-delete]").forEach((btn) =>
    btn.addEventListener("click", () => {
      state.selection = new Set([btn.dataset.delete]);
      openBulkDeleteModal();
    })
  );

  renderPagination(total, from, rows.length);
  updateBulkbar();
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
    options: [20, 50, 100].map((n) => ({ value: String(n), label: String(n) })),
    value: String(state.perPage),
    onChange: (v) => {
      state.perPage = parseInt(v, 10);
      localStorage.setItem("cfddns.perPage", String(state.perPage));
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

function renderRecoveryNotice() {
  const notice = el("recovery-notice");
  if (!notice) return;
  notice.innerHTML = state.authed && state.pendingBackupCodes ? `<div class="login-notice recovery-notice" role="status">
    <p>${esc(t("settings.2fa.backup.pending"))}</p>
    <button class="btn sm" id="backup-codes-reopen">${esc(t("settings.2fa.backup.reopen"))}</button></div>` : "";
  el("backup-codes-reopen")?.addEventListener("click", () => showBackupCodesModal(state.pendingBackupCodes));
}

function modalHead(title) {
  return `<div class="modal-head"><h3 id="modal-title">${esc(title)}</h3><button class="modal-close" data-close aria-label="${esc(t("common.close"))}">${I.close}</button></div>`;
}

function metadataPatch(field, mode, raw) {
  if (mode === "keep") return {};
  if (mode === "clear") return { [field]: field === "tags" ? [] : "" };
  const value = field === "tags" ? raw.split(",").map((tag) => tag.trim()).filter(Boolean) : raw.trim();
  if (!value.length) throw new Error(t("modal.metadata.empty"));
  return { [field]: value };
}

function metadataFields(prefix, rec, keep) {
  return ["comment", "tags"].map((field) => `<div class="field metadata-field">
    <span>${esc(t("modal." + field))}</span>
    ${keep ? `<span id="${prefix}-${field}-mode"></span>` : ""}
    <label class="field ${keep ? "u-hidden" : ""}" id="${prefix}-${field}-wrap">
      <input class="input" id="${prefix}-${field}" aria-label="${esc(t("modal." + field))}" value="${esc(field === "tags" ? (rec?.tags || []).join(", ") : rec?.comment || "")}" ${field === "comment" ? 'maxlength="100"' : 'placeholder="owner:test"'}>
      ${field === "tags" ? `<div class="field-hint">${esc(t("modal.tags.hint"))}</div>` : ""}
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

function typeSpecificFields(type, rec) {
  const d = (rec && rec.data) || {};
  if (type === "MX") {
    return `
      <label class="field"><span>${esc(t("modal.content.MX"))} *</span>
        <input class="input" id="f-content" value="${esc(rec ? rec.content : "")}" placeholder="mail.example.com" data-v="domain">
        <div class="field-error" data-err="f-content">${esc(t("modal.invalid.domain"))}</div></label>
      <label class="field"><span>${esc(t("modal.priority"))} *</span>
        <input class="input" id="f-priority" type="number" min="0" max="65535" value="${esc(rec && rec.priority != null ? rec.priority : 10)}">
        <div class="field-error" data-err="f-priority">${esc(t("modal.invalid.number", { min: 0, max: 65535 }))}</div></label>`;
  }
  if (type === "SRV") {
    return `
      <div class="form-grid">
        <label class="field"><span>${esc(t("modal.srv.priority"))} *</span>
          <input class="input" id="f-srv-priority" type="number" min="0" max="65535" value="${esc(d.priority ?? 0)}">
          <div class="field-error" data-err="f-srv-priority">${esc(t("modal.invalid.number", { min: 0, max: 65535 }))}</div></label>
        <label class="field"><span>${esc(t("modal.srv.weight"))} *</span>
          <input class="input" id="f-srv-weight" type="number" min="0" max="65535" value="${esc(d.weight ?? 5)}">
          <div class="field-error" data-err="f-srv-weight">${esc(t("modal.invalid.number", { min: 0, max: 65535 }))}</div></label>
        <label class="field"><span>${esc(t("modal.srv.port"))} *</span>
          <input class="input" id="f-srv-port" type="number" min="0" max="65535" value="${esc(d.port ?? "")}" placeholder="25565">
          <div class="field-error" data-err="f-srv-port">${esc(t("modal.invalid.number", { min: 0, max: 65535 }))}</div></label>
        <label class="field"><span>${esc(t("modal.srv.target"))} *</span>
          <input class="input" id="f-srv-target" value="${esc(d.target ?? "")}" placeholder="mc.example.com" data-v="domain">
          <div class="field-error" data-err="f-srv-target">${esc(t("modal.invalid.domain"))}</div></label>
      </div>`;
  }
  if (type === "CAA") {
    return `
      <div class="form-grid">
        <label class="field"><span>${esc(t("modal.caa.flags"))} *</span>
          <input class="input" id="f-caa-flags" type="number" min="0" max="255" value="${esc(d.flags ?? 0)}">
          <div class="field-error" data-err="f-caa-flags">${esc(t("modal.invalid.number", { min: 0, max: 255 }))}</div></label>
        <div class="field"><span>${esc(t("modal.caa.tag"))} *</span><span id="f-caa-tag-slot"></span></div>
        <label class="field full"><span>${esc(t("modal.caa.value"))} *</span>
          <input class="input" id="f-caa-value" value="${esc(d.value ?? "")}" placeholder="letsencrypt.org">
          <div class="field-error" data-err="f-caa-value">${esc(t("modal.required"))}</div></label>
      </div>`;
  }
  if (type === "HTTPS" || type === "SVCB") {
    return `
      <div class="form-grid">
        <label class="field"><span>${esc(t("modal.svc.priority"))} *</span>
          <input class="input" id="f-svc-priority" type="number" min="0" max="65535" value="${esc(d.priority ?? 1)}">
          <div class="field-error" data-err="f-svc-priority">${esc(t("modal.invalid.number", { min: 0, max: 65535 }))}</div></label>
        <label class="field"><span>${esc(t("modal.svc.target"))} *</span>
          <input class="input" id="f-svc-target" value="${esc(d.target ?? "")}" placeholder=". or example.com">
          <div class="field-error" data-err="f-svc-target">${esc(t("modal.required"))}</div></label>
        <label class="field full"><span>${esc(t("modal.svc.value"))}</span>
          <input class="input" id="f-svc-value" value="${esc(d.value ?? "")}" placeholder='alpn="h3,h2"'>
          <div class="field-hint">${esc(t("modal.svc.value.hint"))}</div></label>
      </div>`;
  }
  const labelKey = `modal.content.${type}`;
  const label = t(labelKey) === labelKey ? t("modal.content") : t(labelKey);
  const placeholders = {
    A: "192.0.2.1", AAAA: "2001:db8::1", CNAME: "example.com",
    TXT: "v=spf1 include:example.com ~all", NS: "ns1.example.com", PTR: "example.com",
  };
  const validators = { A: "ipv4", AAAA: "ipv6", CNAME: "domain", NS: "domain", PTR: "domain" };
  const errKeys = { A: "modal.invalid.ipv4", AAAA: "modal.invalid.ipv6", CNAME: "modal.invalid.domain", NS: "modal.invalid.domain", PTR: "modal.invalid.domain" };
  const v = validators[type];
  return `<label class="field"><span>${esc(label)} *</span>
    <input class="input" id="f-content" value="${esc(rec ? rec.content : "")}" placeholder="${esc(placeholders[type] || "")}" ${v ? `data-v="${v}"` : ""}>
    ${v ? `<div class="field-error" data-err="f-content">${esc(t(errKeys[type]))}</div>` : `<div class="field-error" data-err="f-content">${esc(t("modal.required"))}</div>`}</label>`;
}

function wireTypeSelectValidation(modal, type) {
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
  modal.querySelectorAll("[data-v]").forEach((input) => {
    input.addEventListener("input", () => markValidity(modal, input));
  });
  if (type === "SRV") {
    modal.querySelectorAll("#f-srv-priority, #f-srv-weight, #f-srv-port").forEach((input) =>
      input.addEventListener("input", () => markValidity(modal, input))
    );
  }
}

function markValidity(modal, input) {
  const kind = input.dataset.v;
  let ok = true;
  const val = input.value.trim();
  if (kind === "ipv4") ok = V.ipv4(val);
  else if (kind === "ipv6") ok = V.ipv6(val);
  else if (kind === "domain") ok = val !== "" && V.domain(val);
  else if (input.type === "number") ok = V.uint(val, Number(input.min || 0), Number(input.max || 65535));
  else ok = val !== "";
  input.classList.toggle("invalid", !ok && val !== "");
  const err = modal.querySelector(`[data-err="${input.id}"]`);
  if (err) err.classList.toggle("visible", !ok && val !== "");
  return ok;
}

function openRecordModal(rec) {
  const isEdit = !!rec;
  const zone = currentZone();
  const zoneId = state.zoneId;
  const zoneName = zone ? zone.name : "";
  const type = rec ? rec.type : "A";
  const initialProxied = rec ? !!rec.proxied : false;

  const modal = openModal(`
    ${modalHead(isEdit ? t("modal.edit.title") : t("modal.add.title"))}
    <div class="modal-body">
      <div class="zone-suffix-banner">${I.dns} <span>${esc(t("modal.zone"))}:</span> <strong>${esc(zoneName)}</strong></div>
      <div class="form-grid">
        <div class="field"><span>${esc(t("modal.type"))}</span><span id="f-type-slot"></span></div>
        <label class="field"><span>${esc(t("modal.name"))} *</span>
          <input class="input" id="f-name" value="${esc(rec ? shortName(rec.name, zoneName) : "")}" placeholder="subdomain" ${isEdit ? "disabled" : ""}>
          <div class="field-hint">${esc(t("modal.name.hint", { zone: zoneName }))}</div>
          <div class="field-error" data-err="f-name">${esc(t("modal.invalid.name"))}</div></label>
      </div>
      <div id="type-fields">${typeSpecificFields(type, rec)}</div>
      <div class="form-grid">
        <div class="field"><span>${esc(t("modal.ttl"))}</span><span id="f-ttl-slot"></span>
          <div class="field-hint u-hidden" id="f-ttl-hint">${esc(t("modal.ttl.proxied"))}</div></div>
        <div class="field">
          <span>&nbsp;</span>
          <div class="switch-row">
            <label class="switch"><input type="checkbox" id="f-proxied" ${initialProxied ? "checked" : ""} ${PROXIABLE.includes(type) ? "" : "disabled"}><span class="track"></span></label>
            <span class="lbl">${esc(t("modal.proxy"))}</span>
          </div>
        </div>
      </div>
      ${metadataFields("f", rec, isEdit)}
    </div>
    <div class="modal-foot">
      <button class="btn" data-close>${esc(t("modal.cancel"))}</button>
      <button class="btn primary" id="f-save">${esc(isEdit ? t("modal.save") : t("modal.create"))}</button>
    </div>`, true);

  modal.dataset.caaTag = (rec && rec.data && rec.data.tag) || "issue";
  let currentType = type;
  if (isEdit) wireMetadata(modal, "f");

  // Type modern select.
  const typeSlot = modal.querySelector("#f-type-slot");
  typeSlot.replaceWith(mselect({
    id: "f-type-slot",
    options: RECORD_TYPES.map((tp) => ({ value: tp, label: tp })),
    value: type,
    disabled: isEdit,
    onChange: (v) => {
      currentType = v;
      modal.querySelector("#type-fields").innerHTML = typeSpecificFields(v, null);
      const ok = PROXIABLE.includes(v);
      const proxiedInput = modal.querySelector("#f-proxied");
      proxiedInput.disabled = !ok;
      if (!ok) proxiedInput.checked = false;
      syncTtlAvailability();
      wireTypeSelectValidation(modal, v);
    },
  }));

  // TTL modern select.
  const ttlSlot = modal.querySelector("#f-ttl-slot");
  const ttlSelect = mselect({
    id: "f-ttl-slot",
    options: TTL_OPTIONS.map(([v, lbl]) => ({ value: String(v), label: v === 1 ? t("ttl.auto") : lbl })),
    value: String(rec ? rec.ttl ?? 1 : 1),
  });
  ttlSlot.replaceWith(ttlSelect);

  const proxiedInput = modal.querySelector("#f-proxied");
  function syncTtlAvailability() {
    const proxied = proxiedInput.checked && PROXIABLE.includes(currentType);
    ttlSelect.msetDisabled(proxied);
    if (proxied) ttlSelect.mset("1");
    modal.querySelector("#f-ttl-hint").classList.toggle("u-hidden", !proxied);
  }
  proxiedInput.addEventListener("change", syncTtlAvailability);
  syncTtlAvailability();
  wireTypeSelectValidation(modal, currentType);

  // Name validation.
  const nameInput = modal.querySelector("#f-name");
  nameInput.addEventListener("input", () => {
    const ok = currentType === "SRV" ? V.srvName(nameInput.value) : V.recordName(nameInput.value);
    nameInput.classList.toggle("invalid", !ok && nameInput.value !== "");
    modal.querySelector('[data-err="f-name"]').classList.toggle("visible", !ok && nameInput.value !== "");
  });

  modal.querySelector("#f-save").addEventListener("click", async () => {
    const saveBtn = modal.querySelector("#f-save");
    const payload = buildPayload(modal, currentType, zoneName, isEdit ? rec : null, ttlSelect);
    if (!payload) return;
    saveBtn.disabled = true;
    saveBtn.innerHTML = `<div class="spinner small"></div>`;
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
      saveBtn.disabled = false;
      saveBtn.textContent = isEdit ? t("modal.save") : t("modal.create");
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
  modal.querySelectorAll("#type-fields [data-v], #type-fields input[type=number]").forEach((input) => {
    if (!markValidity(modal, input)) allOk = false;
  });
  const nameRaw = isEdit ? "" : val("#f-name");
  if (!isEdit) {
    const nameOk = type === "SRV" ? V.srvName(nameRaw) : V.recordName(nameRaw);
    if (!nameOk) {
      modal.querySelector("#f-name").classList.add("invalid");
      modal.querySelector('[data-err="f-name"]').classList.add("visible");
      allOk = false;
    }
  }
  if (!allOk) { toast(t("modal.invalid"), "error"); return null; }

  const name = isEdit ? rec.name : fullName(nameRaw, zoneName);
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
        <div class="field"><span>${esc(t("modal.bulk.ttl"))}</span><span id="b-ttl-slot"></span></div>
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
    options: [{ value: "", label: t("modal.bulk.keep") }, ...TTL_OPTIONS.map(([v, lbl]) => ({ value: String(v), label: v === 1 ? t("ttl.auto") : lbl }))],
    value: "",
  });
  modal.querySelector("#b-ttl-slot").replaceWith(ttlSelect);

  const proxySelect = mselect({
    options: [
      { value: "", label: t("modal.bulk.keep") },
      { value: "true", label: t("modal.bulk.proxy.on") },
      { value: "false", label: t("modal.bulk.proxy.off") },
    ],
    value: "",
    disabled: !allProxiable,
  });
  modal.querySelector("#b-proxy-slot").replaceWith(proxySelect);

  wireMetadata(modal, "b");

  modal.querySelector("#b-apply").addEventListener("click", async () => {
    const applyBtn = modal.querySelector("#b-apply");
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
    applyBtn.disabled = true;
    applyBtn.innerHTML = `<div class="spinner small"></div>`;
    try {
      const res = await api(`/api/zones/${zoneId}/records/bulk`, {
        method: "POST",
        json: { action: "update", ids: selected.map((record) => record.id), patch },
      });
      toast(t("toast.bulk_update", { ok: res.succeeded, fail_part: res.failed ? t("toast.fail_suffix", { n: res.failed }) : "" }), res.failed ? "info" : "ok");
      if (modal.isConnected) closeModal();
      if (state.zoneId === zoneId) await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      applyBtn.disabled = false;
      applyBtn.textContent = t("modal.bulk.apply", { n: selected.length });
    }
  });
}

/* ----- Delete (single or bulk) ----- */

function openBulkDeleteModal() {
  const zoneId = state.zoneId;
  const ids = [...state.selection];
  const n = state.selection.size;
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
    const btn = modal.querySelector("#d-confirm");
    btn.disabled = true;
    btn.innerHTML = `<div class="spinner small"></div>`;
    try {
      const res = await api(`/api/zones/${zoneId}/records/bulk`, {
        method: "POST",
        json: { action: "delete", ids },
      });
      toast(t("toast.bulk_delete", { ok: res.succeeded, fail_part: res.failed ? t("toast.fail_suffix", { n: res.failed }) : "" }), res.failed ? "info" : "ok");
      if (modal.isConnected) closeModal();
      if (state.zoneId === zoneId) await refreshRecords();
    } catch (e) {
      toast(e.message, "error");
      btn.disabled = false;
      btn.innerHTML = `${I.trash} ${esc(t("modal.delete.confirm"))}`;
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
        <div class="u-mt8" id="drop-label">${t("modal.import.drop")}</div>
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
      errBox.textContent = "File too large (max 2 MiB).";
      errBox.classList.add("visible");
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
    submit.disabled = true;
    submit.innerHTML = `<div class="spinner small"></div>`;
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
      errBox.textContent = e.message;
      errBox.classList.add("visible");
      submit.disabled = false;
      submit.innerHTML = `${I.upload} ${esc(t("modal.import.submit"))}`;
    }
  });
}

async function exportZone() {
  const zone = currentZone();
  try {
    const text = await api(`/api/zones/${state.zoneId}/export`, { text: true });
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${zone ? zone.name : "zone"}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast(t("toast.exported"));
  } catch (e) {
    toast(e.message, "error");
  }
}

/* ================= Render: settings ================= */

function renderSettings() {
  const page = el("page");
  page.innerHTML = `
    <div class="settings-grid">
      <div class="card"><div class="card-pad">
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
          <img class="icon-preview" id="icon-preview" src="/static/favicon.svg" alt="icon">
          <button class="btn sm" id="icon-upload">${I.upload} ${esc(t("settings.icon.upload"))}</button>
          <button class="btn sm ghost" id="icon-reset">${esc(t("settings.icon.reset"))}</button>
          <input type="file" id="icon-input" accept="image/png,image/jpeg,image/webp,image/gif" class="u-hidden">
        </div>
      </div></div>

      <div class="card"><div class="card-pad">
        <div class="card-title">${I.shield} ${esc(t("settings.security.title"))}</div>
        <div class="card-desc">${esc(t("settings.security.desc"))}</div>
        <div id="security-body"></div>
      </div></div>

      <div class="card"><div class="card-pad">
        <div class="card-title">${I.key} ${esc(t("settings.token.title"))}</div>
        <div class="card-desc">${esc(t("settings.token.desc"))}</div>
        <ol class="token-steps">
          <li>${t("settings.token.step1")}</li>
          <li>${t("settings.token.step2")}</li>
          <li>${t("settings.token.step3")}</li>
          <li>${t("settings.token.step4")}</li>
          <li>${t("settings.token.step5")}</li>
        </ol>
        <div class="u-mt14">
          <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer">dash.cloudflare.com/profile/api-tokens ↗</a>
        </div>
      </div></div>

      <div class="card"><div class="card-pad">
        <div class="card-title">${esc(t("settings.about.title"))}</div>
        <table class="kv-table">
          <tr><td>${esc(t("settings.about.version"))}</td><td class="mono">v${esc(state.config ? state.config.version : "?")}</td></tr>
          <tr><td>${esc(t("settings.about.source"))}</td><td><a href="${esc(state.config?.github || "")}" target="_blank" rel="noopener noreferrer">GitHub</a></td></tr>
          <tr><td>${esc(t("settings.about.upstream"))}</td><td><a href="https://github.com/timothymiller/cloudflare-ddns" target="_blank" rel="noopener noreferrer">cloudflare-ddns</a></td></tr>
        </table>
      </div></div>
    </div>`;

  // Theme select
  el("settings-theme-slot").replaceWith(mselect({
    options: [
      { value: "system", label: t("settings.theme.system") },
      { value: "light", label: t("settings.theme.light") },
      { value: "dark", label: t("settings.theme.dark") },
    ],
    value: currentTheme(),
    onChange: (v) => { setTheme(v); renderTopbarActions(); },
  }));

  // Language select
  el("settings-lang-slot").replaceWith(mselect({
    cls: "u-lang-select",
    options: LANGS.map((l) => ({ value: l.code, label: l.name })),
    value: lang,
    onChange: (v) => { lang = v; localStorage.setItem("cfddns.lang", v); render(); },
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
  ACCENT_PRESETS.forEach((color, i) => {
    const b = document.createElement("button");
    b.className = `swatch sw-${i} ${current.toLowerCase() === color ? "selected" : ""}`;
    b.title = color;
    b.addEventListener("click", () => saveAccent(color));
    row.appendChild(b);
  });
  const picker = document.createElement("input");
  picker.type = "color";
  picker.className = "color-input";
  picker.value = /^#[0-9a-fA-F]{6}$/.test(current) ? current : "#f6821f";
  picker.title = "Custom color";
  picker.addEventListener("change", () => saveAccent(picker.value));
  row.appendChild(picker);
  const reset = document.createElement("button");
  reset.className = "btn sm ghost";
  reset.textContent = "Default";
  reset.addEventListener("click", () => saveAccent(null));
  row.appendChild(reset);
}

async function saveAccent(color) {
  try {
    await api("/api/ui/accent", { method: "POST", json: { accent: color } });
    state.config.accent = color;
    document.documentElement.style.setProperty("--accent", color || "");
    if (color) document.documentElement.style.setProperty("--accent", color);
    else document.documentElement.style.removeProperty("--accent");
    // Recompute hover color minimally: keep hover as-is (server injects on next load).
    toast(t("toast.accent"));
    renderAccentRow();
  } catch (e) {
    toast(e.message, "error");
  }
}

function wireIconSettings() {
  const input = el("icon-input");
  const preview = el("icon-preview");
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
      preview.src = `/static/favicon.svg?v=${Date.now()}`;
      // Update favicon immediately.
      document.querySelectorAll('link[rel="icon"]').forEach((l) => { l.href = `/static/favicon.svg?v=${Date.now()}`; });
    } catch (e) {
      toast(e.message, "error");
    }
    input.value = "";
  });
  el("icon-reset").addEventListener("click", async () => {
    try {
      await api("/api/ui/icon", { method: "DELETE" });
      toast(t("toast.icon"));
      preview.src = "/static/favicon.svg";
      document.querySelectorAll('link[rel="icon"]').forEach((l) => { l.href = "/static/favicon.svg"; });
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
      <tr><td>${esc(t("settings.security.session"))}</td><td class="mono">${state.sessionTtl ? `${Math.round(state.sessionTtl / 3600)} h` : "-"}</td></tr>
      <tr><td>${esc(t("settings.security.cookies"))}</td><td><span class="cell-muted">${esc(t("settings.security.cookies.hint"))}</span></td></tr>
      <tr><td>${esc(t("settings.2fa.title"))}</td><td>
        <span class="badge ${totpOn ? "green" : "grey"}">${esc(totpOn ? t("settings.2fa.status.on") : t("settings.2fa.status.off"))}</span>
        ${totpOn ? `<span class="cell-muted u-ml8">${esc(t("settings.2fa.backup_count", { n: state.backupCodesRemaining }))}</span>` : ""}
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
  el("pw-change-btn").addEventListener("click", openPasswordModal);
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
    if (!password) { error.textContent = t("modal.required"); error.classList.add("visible"); return; }
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
      error.textContent = e.message;
      error.classList.add("visible");
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
        if (authentication !== authGeneration || !state.authed) throw new Error("Authentication changed. Sign in again.");
        return api("/api/auth/2fa/confirm", { method: "POST", json: { code }, authContext: session });
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
      errBox.textContent = e.message;
      errBox.classList.add("visible");
      btn.disabled = false;
    } finally {
      confirming = false;
      modal.closeBlocked = false;
      modal.querySelectorAll("[data-close], #t2fa-cancel").forEach((button) => { button.disabled = false; });
      if (!modal.isConnected && !completed) modal.onDismiss();
    }
  });
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
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cloudflare-ddns-backup-codes.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
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
      });
      if (session.generation !== authGeneration || !state.authed) return;
      state.totpEnabled = false;
      state.backupCodesRemaining = 0;
      if (modal.isConnected) closeModal();
      toast(t("toast.2fa.disabled"));
      renderSecurityBody();
    } catch (e) {
      errBox.textContent = e.message;
      errBox.classList.add("visible");
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
    if (val("#pw-new").length < 8) { errBox.textContent = t("setup.short"); errBox.classList.add("visible"); return; }
    if (val("#pw-new") !== val("#pw-confirm")) { errBox.textContent = t("setup.mismatch"); errBox.classList.add("visible"); return; }
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
      });
      if (session.generation !== authGeneration || !state.authed) return;
      if (modal.isConnected) closeModal();
      toast(t("toast.password"));
    } catch (e) {
      errBox.textContent = e.message;
      errBox.classList.add("visible");
      btn.disabled = false;
    }
  });
}

/* ================= Boot ================= */

async function bootAuthed() {
  try {
    const me = await api("/api/auth/me");
    state.sessionTtl = me.session_ttl;
    state.totpEnabled = !!me.totp_enabled;
    state.backupCodesRemaining = me.backup_codes_remaining ?? 0;
  } catch { /* non-fatal */ }
  try {
    await loadZones();
  } catch (e) {
    toast(e.message, "error");
  }
  state.ddns = null;
  render();
}

(async function boot() {
  applyTheme();
  try {
    state.config = await api("/api/config");
    state.configured = state.config.configured !== false;
    if (state.config.accent) {
      document.documentElement.style.setProperty("--accent", state.config.accent);
    }
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

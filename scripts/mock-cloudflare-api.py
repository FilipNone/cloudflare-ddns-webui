#!/usr/bin/env python3
"""Mock Cloudflare API v4 for local web UI development.

Seeded with three zones under the reserved .example TLD and documentation-range
addresses: acme.example (a business), homelab.example (self-hosting) and
rossi.example (personal use).
Usage: python3 scripts/mock-cloudflare-api.py [port]  (default 8787)
Then run the web UI with CLOUDFLARE_API_BASE=http://127.0.0.1:8787/client/v4
"""
import copy
import json
import ipaddress
import re
import shlex
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from email.parser import BytesParser
from email.policy import default
from urllib.parse import urlparse, parse_qs

DEFAULT_PORT = 8787
NOW = "2026-07-29T17:25:21.000000Z"
ACME = "3c6f1d8a2b9e4f7c8d1a5e2b6f9c3d01"
HOMELAB = "3c6f1d8a2b9e4f7c8d1a5e2b6f9c3d02"
ROSSI = "3c6f1d8a2b9e4f7c8d1a5e2b6f9c3d03"
# In name order, which is how the app asks Cloudflare for them.
ZONES = [
    {"id": ACME, "name": "acme.example", "status": "active", "paused": False, "type": "full"},
    {"id": HOMELAB, "name": "homelab.example", "status": "active", "paused": False, "type": "full"},
    {"id": ROSSI, "name": "rossi.example", "status": "active", "paused": False, "type": "full"},
]
# Base64 of "synthetic-dkim-key".
DKIM_KEY = "c3ludGhldGljLWRraW0ta2V5"


def rec(rtype, name, content, proxied=None, ttl=1, comment=None, tags=None, priority=None, data=None):
    proxiable = rtype in ("A", "AAAA", "CNAME")
    return {
        "id": uuid.uuid4().hex[:32],
        "type": rtype,
        "name": name,
        "content": content,
        "proxiable": proxiable,
        "proxied": bool(proxied) if proxiable else False,
        "ttl": ttl,
        "comment": comment,
        "tags": tags or [],
        "priority": priority,
        "created_on": NOW,
        "modified_on": NOW,
        "data": data,
    }


def srv(name, priority, weight, port, target, comment=None):
    # Cloudflare leaves the priority out of an SRV record's content.
    return rec("SRV", name, f"{weight} {port} {target}", ttl=3600, comment=comment, priority=priority,
               data={"priority": priority, "weight": weight, "port": port, "target": target})


def caa(name, tag, value):
    return rec("CAA", name, f'0 {tag} "{value}"', ttl=3600,
               data={"flags": 0, "tag": tag, "value": value})


RECORDS = {
    # A business on a paid plan, so its records use tags. Hosted mail and office phones.
    ACME: [
        rec("A", "acme.example", "198.51.100.20", True, comment="Website load balancer",
            tags=["team:web", "env:prod"]),
        rec("AAAA", "acme.example", "2001:db8:20::20", True, tags=["team:web", "env:prod"]),
        rec("CNAME", "www.acme.example", "acme.example", True, tags=["team:web", "env:prod"]),
        rec("A", "shop.acme.example", "198.51.100.21", True, comment="Online shop",
            tags=["team:web", "env:prod"]),
        rec("A", "api.acme.example", "198.51.100.22", True, tags=["team:backend", "env:prod"]),
        rec("A", "staging.acme.example", "198.51.100.23", True, comment="Staging, staff only",
            tags=["team:web", "env:staging"]),
        rec("A", "vpn.acme.example", "198.51.100.30", False, 300, "Office VPN gateway", ["team:it"]),
        rec("CNAME", "status.acme.example", "acme.status-host.example", False, 3600, "Status page",
            ["team:it"]),
        rec("CNAME", "help.acme.example", "acme.helpdesk.example", False, 3600, "Customer helpdesk",
            ["team:support"]),
        rec("MX", "acme.example", "mx.mailcloud.example", ttl=3600, priority=0),
        rec("TXT", "acme.example", '"v=spf1 include:spf.mailcloud.example include:mail.crm.example -all"',
            ttl=3600),
        rec("TXT", "acme.example", '"mailcloud-verification=synthetic-acme-0001"', ttl=3600),
        rec("TXT", "_dmarc.acme.example", '"v=DMARC1; p=reject; rua=mailto:dmarc@acme.example"', ttl=3600),
        rec("TXT", "selector1._domainkey.acme.example", f'"v=DKIM1; k=rsa; p={DKIM_KEY}"', ttl=3600),
        rec("CNAME", "autodiscover.acme.example", "autodiscover.mailcloud.example", False, 3600),
        rec("TXT", "_mta-sts.acme.example", '"v=STSv1; id=20260701"', ttl=3600),
        srv("_sip._tls.acme.example", 100, 1, 443, "sip.voip.example", "Office phones"),
        caa("acme.example", "issue", "ca.example"),
        caa("acme.example", "iodef", "mailto:security@acme.example"),
    ],
    # Self-hosting from a home connection behind a reverse proxy, with mail on a VPS.
    HOMELAB: [
        # The smoke groups run DDNS against these three, so keep their values.
        rec("A", "homelab.example", "203.0.113.10", False, 1),
        rec("AAAA", "homelab.example", "2001:db8::10", False, 300),
        rec("CNAME", "www.homelab.example", "homelab.example", True, 1),
        rec("CNAME", "*.homelab.example", "homelab.example", False, 1, "Reverse proxy catch-all"),
        rec("CNAME", "cloud.homelab.example", "homelab.example", True, 1, "Nextcloud"),
        rec("CNAME", "photos.homelab.example", "homelab.example", True, 1, "Immich"),
        rec("CNAME", "git.homelab.example", "homelab.example", True, 1, "Forgejo"),
        rec("CNAME", "media.homelab.example", "homelab.example", False, 1, "Jellyfin, DNS only for video"),
        rec("CNAME", "vpn.homelab.example", "homelab.example", False, 1, "WireGuard, UDP is not proxied"),
        rec("CNAME", "matrix.homelab.example", "homelab.example", True, 1, "Synapse"),
        srv("_matrix._tcp.homelab.example", 10, 5, 8448, "matrix.homelab.example", "Matrix federation"),
        rec("CNAME", "mc.homelab.example", "homelab.example", False, 1, "Minecraft"),
        srv("_minecraft._tcp.homelab.example", 0, 5, 25565, "mc.homelab.example"),
        rec("A", "mail.homelab.example", "203.0.113.25", False, 3600, "Mail VPS with a static IP"),
        rec("AAAA", "mail.homelab.example", "2001:db8:25::25", False, 3600, "Mail VPS with a static IP"),
        rec("MX", "homelab.example", "mail.homelab.example", ttl=3600, priority=10),
        rec("TXT", "homelab.example", '"v=spf1 mx -all"', ttl=3600),
        rec("TXT", "_dmarc.homelab.example", '"v=DMARC1; p=reject; rua=mailto:postmaster@homelab.example"',
            ttl=3600),
        rec("TXT", "mail._domainkey.homelab.example", f'"v=DKIM1; k=rsa; p={DKIM_KEY}"', ttl=3600),
        caa("homelab.example", "issue", "ca.example"),
        caa("homelab.example", "issuewild", "ca.example"),
    ],
    # Personal use: a small website, a blog on a hosting service and hosted mail.
    ROSSI: [
        rec("A", "rossi.example", "192.0.2.10", True),
        rec("AAAA", "rossi.example", "2001:db8:10::10", True),
        rec("CNAME", "www.rossi.example", "rossi.example", True),
        rec("CNAME", "blog.rossi.example", "rossi.blog-host.example", False, 1, "Blog"),
        rec("MX", "rossi.example", "mx1.mailhost.example", ttl=3600, priority=10),
        rec("MX", "rossi.example", "mx2.mailhost.example", ttl=3600, priority=20),
        rec("TXT", "rossi.example", '"v=spf1 include:_spf.mailhost.example ~all"', ttl=3600),
        rec("TXT", "rossi.example", '"site-verification=synthetic-rossi-0001"', ttl=3600),
        rec("TXT", "_dmarc.rossi.example", '"v=DMARC1; p=quarantine; rua=mailto:dmarc@rossi.example"',
            ttl=3600),
        rec("CNAME", "mail1._domainkey.rossi.example", "mail1.dkim.mailhost.example", False, 3600),
    ],
}
# Handler threads share RECORDS. Hold LOCK for every read and write.
LOCK = threading.Lock()

def bind_export(zone, records):
    """Zone file with the SOA and the apex A and AAAA records. Cloudflare exports
    every record; these are enough for the export and reimport checks."""
    lines = [";;", f";; Domain: {zone}.", ";; Synthetic local fixture", ";; SOA Record",
             f"{zone}. 3600 IN SOA ns.{zone}. hostmaster.{zone}. 1 10000 2400 604800 3600", ""]
    for rtype in ("A", "AAAA"):
        lines.append(f";; {rtype} Records")
        lines += [f"{zone}. {r['ttl']} IN {rtype} {r['content']}"
                  for r in records if r["name"] == zone and r["type"] == rtype]
    return "\n".join(lines) + "\n"


# Built from the seed, so later changes to RECORDS don't show up in it.
EXPORT_BIND = {z["id"]: bind_export(z["name"], RECORDS[z["id"]]) for z in ZONES}


def envelope(result, page=1, per_page=100):
    total = len(result) if isinstance(result, list) else 1
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": result,
        "result_info": {"page": page, "per_page": per_page, "total_pages": 1, "total_count": total},
    }


def error_envelope(message, code=1000):
    return {"success": False, "errors": [{"code": code, "message": message}],
            "messages": [], "result": None}


def json_object(body):
    """Decode a JSON object request body. Returns None if it is malformed or not an object."""
    try:
        value = json.loads(body or b"{}")
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def snapshot_records():
    """Deep copy of RECORDS, taken under LOCK."""
    with LOCK:
        return copy.deepcopy(RECORDS)


def reset_records(records):
    """Replace every zone's records with a deep copy of `records`."""
    with LOCK:
        RECORDS.clear()
        RECORDS.update(copy.deepcopy(records))


# Batch operation lists in the order Cloudflare applies them.
BATCH_KEYS = ("deletes", "patches", "puts", "posts")
# Free plan limit on the items in one batch, the smallest of any plan.
BATCH_LIMIT = 200
PATCH_FIELDS = ("content", "ttl", "proxied", "comment", "tags", "priority", "data", "name")


def batch_item_ids(payload):
    """Record IDs named by a batch body, in Cloudflare's order. Skips malformed items."""
    ids = []
    for key in BATCH_KEYS:
        items = payload.get(key) if isinstance(payload, dict) else None
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                ids.append(item["id"])
    return ids


def apply_batch(records, payload):
    """Apply a batch body to `records` like Cloudflare: check every item first,
    and change nothing when one fails. Returns (status, reply).

    Only deletes and patches are supported. Records are changed in place, so
    callers that hold a record dict see the update.
    """
    if payload is None:
        return 400, error_envelope("request body must be a JSON object")
    unknown = sorted(set(payload) - set(BATCH_KEYS))
    if unknown:
        return 400, error_envelope(f"unknown batch field {unknown[0]}")
    if payload.get("puts") or payload.get("posts"):
        return 400, error_envelope("mock: batch puts and posts are not supported")
    lists = {key: payload.get(key, []) for key in ("deletes", "patches")}
    for key, items in lists.items():
        if not isinstance(items, list):
            return 400, error_envelope(f"{key} must be a list")
    if sum(len(items) for items in lists.values()) > BATCH_LIMIT:
        return 400, error_envelope(f"a batch may contain at most {BATCH_LIMIT} records")
    by_id = {r["id"]: r for r in records}
    deleted = set()
    for key, items in lists.items():
        for item in items:
            rid = item.get("id") if isinstance(item, dict) else None
            if not isinstance(rid, str):
                return 400, error_envelope(f"every item in {key} needs an id")
            # A record deleted earlier in the batch no longer exists for later items.
            if rid not in by_id or rid in deleted:
                return 404, error_envelope("Record not found", 81044)
            if key == "deletes":
                deleted.add(rid)
    result = {key: [] for key in BATCH_KEYS}
    for item in payload.get("deletes", []):
        found = by_id[item["id"]]
        records.remove(found)
        result["deletes"].append(found)
    for item in payload.get("patches", []):
        found = by_id[item["id"]]
        for k in PATCH_FIELDS:
            if k in item:
                found[k] = item[k]
        found["modified_on"] = "2026-07-29T18:30:00.000000Z"
        result["patches"].append(found)
    return 200, envelope(result)


def parse_bind(text, zone_name):
    """Parse the synthetic import subset; reject unhandled syntax, never invent rows."""
    origin = zone_name + "."
    default_ttl = None
    last_ttl = None
    previous_owner = None
    result = []

    def owner_name(value):
        if value == "@":
            return origin.rstrip(".")
        return (value.rstrip(".") if value.endswith(".") else value + "." + origin.rstrip(".")).lower()

    def ttl_seconds(value):
        if not re.fullmatch(r"(?:[0-9]+[wdhms]?)+", value.lower()):
            raise ValueError("invalid TTL")
        seconds = sum(int(number) * {"": 1, "s": 1, "m": 60, "h": 3600,
                                    "d": 86400, "w": 604800}[unit]
                      for number, unit in re.findall(r"([0-9]+)([wdhms]?)", value.lower()))
        if seconds > 2147483647:
            raise ValueError("TTL exceeds zone-file range")
        return seconds

    for number, line in enumerate(text.splitlines(), 1):
        lexer = shlex.shlex(line, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ";"
        fields = list(lexer)
        if not fields:
            continue
        if fields[0].upper() == "$ORIGIN" and len(fields) == 2:
            origin = fields[1].lower()
            if origin.rstrip(".") != zone_name and not origin.rstrip(".").endswith("." + zone_name):
                raise ValueError("origin outside synthetic zone")
            continue
        if fields[0].upper() == "$TTL" and len(fields) == 2:
            default_ttl = ttl_seconds(fields[1])
            continue
        if fields[0].startswith("$") or any("(" in field or ")" in field for field in fields):
            raise ValueError(f"unsupported directive or multiline syntax at line {number}")
        if line[0].isspace():
            if previous_owner is None:
                raise ValueError("missing inherited owner")
            name = previous_owner
        else:
            name = owner_name(fields.pop(0))
            previous_owner = name
        if name != zone_name and not name.endswith("." + zone_name):
            raise ValueError("owner outside synthetic zone")
        ttl = default_ttl if default_ttl is not None else last_ttl
        seen_class = False
        seen_ttl = False
        while fields and (fields[0].upper() == "IN" or fields[0][0].isdigit()):
            token = fields.pop(0)
            if token.upper() == "IN":
                if seen_class:
                    raise ValueError("duplicate class")
                seen_class = True
            else:
                if seen_ttl:
                    raise ValueError("duplicate TTL")
                ttl = ttl_seconds(token)
                seen_ttl = True
                last_ttl = ttl
        if not fields or ttl is None:
            raise ValueError("missing record type or TTL")
        rtype = fields.pop(0).upper()
        if rtype in ("SOA", "NS"):
            if rtype == "NS" and len(fields) != 1:
                raise ValueError("invalid NS record")
            if rtype == "SOA" and (len(fields) != 7 or not fields[2].isdigit()):
                raise ValueError("invalid SOA record")
            result.append(None)
            continue
        if rtype in ("A", "AAAA"):
            if len(fields) != 1:
                raise ValueError("invalid address record")
            address = ipaddress.ip_address(fields[0])
            if address.version != {"A": 4, "AAAA": 6}[rtype]:
                raise ValueError("wrong address family")
            content = str(address)
        elif rtype in ("CNAME", "PTR") and len(fields) == 1:
            content = owner_name(fields[0])
        elif rtype == "TXT" and fields:
            content = "".join(fields)
        elif rtype == "MX" and len(fields) == 2:
            priority = int(fields[0])
            result.append(rec(rtype, name, owner_name(fields[1]), ttl=ttl, priority=priority))
            continue
        else:
            raise ValueError(f"unsupported record syntax at line {number}")
        result.append(rec(rtype, name, content, ttl=ttl))
    if not result:
        raise ValueError("empty zone file")
    return result


def import_body(body, content_type):
    if not content_type.startswith("multipart/form-data"):
        return body
    message = BytesParser(policy=default).parsebytes(
        b"Content-Type: " + content_type.encode("ascii") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
    files = [part for part in message.iter_parts()
             if part.get_param("name", header="content-disposition") == "file"]
    if len(files) != 1:
        raise ValueError("expected exactly one zone file part")
    return files[0].get_payload(decode=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text, status=200):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0:
            raise ValueError("negative Content-Length")
        return self.rfile.read(length) if length else b""

    def _zone_records(self, zone_id):
        return RECORDS.setdefault(zone_id, [])

    def _dispatch(self, method):
        # Read the body once here and pass it on, so overrides of route() can
        # inspect it without consuming it.
        try:
            body = self._body()
        except ValueError:
            return self._json(error_envelope("invalid Content-Length"), 400)
        return self.route(method, body)

    def route(self, method, body):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        prefix = "/client/v4/"
        if not path.startswith(prefix):
            return self._json(error_envelope("not found"), 404)
        rest = path[len(prefix):]
        parts = [p for p in rest.split("/") if p]

        # /zones
        if parts == ["zones"] and method == "GET":
            name = qs.get("name", [None])[0]
            zones = ZONES if not name else [z for z in ZONES if z["name"] == name]
            return self._json(envelope(zones, 1, 50))

        # /zones/{z}/dns_records...
        if len(parts) >= 3 and parts[0] == "zones" and parts[2] == "dns_records":
            with LOCK:
                status, reply = self._dns_records(method, parts[1], parts[3:], qs, body)
                # Copy before releasing the lock so no other thread changes the rows being sent.
                reply = copy.deepcopy(reply)
            if isinstance(reply, str):
                return self._text(reply, status)
            return self._json(reply, status)

        return self._json(error_envelope(f"mock: unhandled {method} {path}"), 404)

    def _dns_records(self, method, zone_id, rest, qs, body):
        """Handle /zones/{zone_id}/dns_records/{rest...}. The caller holds LOCK.

        Returns (status, reply), where reply is a JSON object or BIND text.
        """
        records = self._zone_records(zone_id)

        if not rest and method == "GET":
            rtype = qs.get("type", [None])[0]
            # DDNS lookups send name.exact; plain name is kept for manual testing.
            name = qs.get("name.exact", qs.get("name", [None]))[0]
            out = records
            if rtype:
                out = [r for r in out if r["type"] == rtype]
            if name:
                out = [r for r in out if r["name"].lower() == name.lower()]
            return 200, envelope(out)

        if not rest and method == "POST":
            payload = json_object(body)
            if payload is None:
                return 400, error_envelope("request body must be a JSON object")
            r = rec(
                payload.get("type", "A"),
                payload.get("name", "x.homelab.example"),
                payload.get("content", ""),
                payload.get("proxied"),
                payload.get("ttl", 1),
                payload.get("comment"),
                payload.get("tags"),
                payload.get("priority"),
                payload.get("data"),
            )
            records.append(r)
            return 201, envelope(r)

        if rest == ["export"] and method == "GET":
            if zone_id not in EXPORT_BIND:
                return 404, error_envelope("mock: unknown zone")
            return 200, EXPORT_BIND[zone_id]

        if rest == ["import"] and method == "POST":
            # Extract the zone file from the multipart body (or raw body).
            zone_name = next((z["name"] for z in ZONES if z["id"] == zone_id), None)
            if zone_name is None:
                return 404, error_envelope("mock: unknown zone")
            try:
                bind = import_body(body, self.headers.get("Content-Type", ""))
                imported = parse_bind(bind.decode("utf-8"), zone_name)
            except (ValueError, UnicodeError) as exc:
                return 400, error_envelope(str(exc))
            added = 0
            for row in imported:
                if row is None:
                    continue  # SOA/NS are skipped by Cloudflare imports
                if any(r["name"] == row["name"] and r["type"] == row["type"] and r["content"] == row["content"] for r in records):
                    continue  # duplicate - skipped, not replaced
                records.append(row)
                added += 1
            return 200, envelope({"recs_added": added, "total_records_parsed": len(imported)})

        # Checked before the record ID routes below, which would read "batch" as an ID.
        if rest == ["batch"] and method == "POST":
            return apply_batch(records, json_object(body))

        if len(rest) == 1:
            rid = rest[0]
            found = next((r for r in records if r["id"] == rid), None)
            if not found:
                return 404, error_envelope("Record not found", 81044)
            if method == "DELETE":
                records.remove(found)
                return 200, envelope({"id": rid})
            if method in ("PATCH", "PUT"):
                payload = json_object(body)
                if payload is None:
                    return 400, error_envelope("request body must be a JSON object")
                for k in PATCH_FIELDS:
                    if k in payload:
                        found[k] = payload[k]
                found["modified_on"] = "2026-07-29T18:30:00.000000Z"
                return 200, envelope(found)

        return 404, error_envelope(f"mock: unhandled {method} {urlparse(self.path).path}")

    do_GET = lambda self: self._dispatch("GET")
    do_POST = lambda self: self._dispatch("POST")
    do_PUT = lambda self: self._dispatch("PUT")
    do_PATCH = lambda self: self._dispatch("PATCH")
    do_DELETE = lambda self: self._dispatch("DELETE")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    print(f"Mock Cloudflare API on http://127.0.0.1:{port}/client/v4")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

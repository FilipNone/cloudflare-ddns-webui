#!/usr/bin/env python3
"""Mock Cloudflare API v4 for local web UI development.

Seeded only with example.com records and documentation-range addresses.
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
ZONES = [
    {"id": "0123456789abcdef0123456789abcdef", "name": "example.com", "status": "active", "paused": False, "type": "full"},
]


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


RECORDS = {
    "0123456789abcdef0123456789abcdef": [
        rec("A", "example.com", "203.0.113.10", False, 1),
        rec("AAAA", "example.com", "2001:db8::10", False, 300),
        rec("CNAME", "www.example.com", "example.com", True, 1),
    ],
}
# Handler threads share RECORDS. Hold LOCK for every read and write.
LOCK = threading.Lock()

EXPORT_BIND = """;;
;; Domain: example.com.
;; Synthetic local fixture
;; SOA Record
example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 10000 2400 604800 3600

;; A Records
example.com. 1 IN A 203.0.113.10
;; AAAA Records
example.com. 300 IN AAAA 2001:db8::10
"""


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
                payload.get("name", "x.example.com"),
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
            return 200, EXPORT_BIND

        if rest == ["import"] and method == "POST":
            # Extract the zone file from the multipart body (or raw body).
            zone_name = next((z["name"] for z in ZONES if z["id"] == zone_id), "example.com")
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

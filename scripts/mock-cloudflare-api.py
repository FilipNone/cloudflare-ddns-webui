#!/usr/bin/env python3
"""Mock Cloudflare API v4 for local web UI development.

Seeded with the records from the real filipnone.eu zone export.
Usage: python3 scripts/mock-cloudflare-api.py [port]  (default 8787)
Then run the web UI with CLOUDFLARE_API_BASE=http://127.0.0.1:8787/client/v4
"""
import json
import re
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

NOW = "2026-07-29T17:25:21.000000Z"
ZONES = [
    {"id": "z1filipnone", "name": "filipnone.eu", "status": "active", "paused": False, "type": "full"},
    {"id": "z2example", "name": "example.com", "status": "active", "paused": False, "type": "full"},
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
    "z1filipnone": [
        rec("A", "aiometadata.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "apps.filipnone.eu", "95.233.221.253", True, 1, None, ["cf-proxied:true"]),
        rec("A", "ddns.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "immich.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "jackett.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "magnetio.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "mc.filipnone.eu", "95.233.221.253", False, 1, None, ["cf-proxied:false"]),
        rec("A", "panel.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "portainer.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "send.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("A", "sftp.filipnone.eu", "95.233.221.253", False, 1, None, ["cf-proxied:false"]),
        rec("A", "wings.filipnone.eu", "95.233.221.253", True, 1, "Managed by cloudflare-ddns", ["cf-proxied:true"]),
        rec("MX", "send.filipnone.eu", "feedback-smtp.eu-west-1.amazonses.com", None, 3600, None, [], 10),
        rec("SRV", "_minecraft._tcp.mc.filipnone.eu", "5 25575 mc.filipnone.eu", None, 1, None, [], None,
            {"priority": 0, "weight": 5, "port": 25575, "target": "mc.filipnone.eu"}),
        rec("TXT", "resend._domainkey.filipnone.eu", "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwfxU6s+DD9ba3WlUdLs5vX40ibWBnHXoQlA7V/ZiI1py8VszTKNbqOlfqv0L6lQfPyQWClX5wHLoAbai+YbfJL5KPm51FrcR3vb0oeBpSAUzsAOKyM6r7EIBrOjiGHQY3KUogH1DjkdYiJc//Gg9JJJfstpF5mhCaodUB6vYWWwIDAQAB", None, 3600),
        rec("TXT", "send.filipnone.eu", "v=spf1 include:amazonses.com ~all", None, 3600),
    ],
    "z2example": [
        rec("A", "example.com", "203.0.113.10", False, 1),
        rec("CNAME", "www.example.com", "example.com", True, 1),
    ],
}

EXPORT_BIND = """;;\n;; Domain:     filipnone.eu.\n;; Exported:   2026-07-29 17:25:21\n;;\n;; SOA Record\nfilipnone.eu\t3600\tIN\tSOA\taisha.ns.cloudflare.com. dns.cloudflare.com. 2053701252 10000 2400 604800 3600\n\n;; A Records\naiometadata.filipnone.eu.\t1\tIN\tA\t95.233.221.253 ; Managed by cloudflare-ddns cf_tags=cf-proxied:true\nfilipnone.eu.\t1\tIN\tA\t95.233.221.253 ; Managed by cloudflare-ddns cf_tags=cf-proxied:true\nmc.filipnone.eu.\t1\tIN\tA\t95.233.221.253 ; cf_tags=cf-proxied:false\n"""


def envelope(result, page=1, per_page=100):
    total = len(result) if isinstance(result, list) else 1
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": result,
        "result_info": {"page": page, "per_page": per_page, "total_pages": 1, "total_count": total},
    }


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
        return self.rfile.read(length) if length else b""

    def _zone_records(self, zone_id):
        return RECORDS.setdefault(zone_id, [])

    def route(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        prefix = "/client/v4/"
        if not path.startswith(prefix):
            return self._json({"success": False, "errors": [{"message": "not found"}]}, 404)
        rest = path[len(prefix):]
        parts = [p for p in rest.split("/") if p]

        # /zones
        if parts == ["zones"] and method == "GET":
            name = qs.get("name", [None])[0]
            zones = ZONES if not name else [z for z in ZONES if z["name"] == name]
            return self._json(envelope(zones, 1, 50))

        # /zones/{z}/dns_records...
        if len(parts) >= 3 and parts[0] == "zones" and parts[2] == "dns_records":
            zone_id = parts[1]
            records = self._zone_records(zone_id)

            if len(parts) == 3 and method == "GET":
                rtype = qs.get("type", [None])[0]
                name = qs.get("name", [None])[0]
                out = records
                if rtype:
                    out = [r for r in out if r["type"] == rtype]
                if name:
                    out = [r for r in out if r["name"].lower() == name.lower()]
                return self._json(envelope(out))

            if len(parts) == 3 and method == "POST":
                payload = json.loads(self._body() or b"{}")
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
                return self._json(envelope(r), 201)

            if len(parts) == 4 and parts[3] == "export" and method == "GET":
                return self._text(EXPORT_BIND)

            if len(parts) == 4 and parts[3] == "import" and method == "POST":
                body = self._body()
                # Extract the zone file from the multipart body (or raw body).
                bind = body
                if b"Content-Disposition" in body:
                    marker = b"\r\n\r\n"
                    start = body.find(marker)
                    if start != -1:
                        end = body.rfind(b"\r\n--")
                        bind = body[start + len(marker):end if end != -1 else len(body)]
                added = 0
                parsed = 0
                zone_name = next((z["name"] for z in ZONES if z["id"] == zone_id), "example.com")
                for line in bind.decode("utf-8", "replace").splitlines():
                    line = line.split(";", 1)[0].strip()
                    if not line or "\tIN\t" not in line and " IN " not in line:
                        continue
                    parts_l = line.replace("\t", " ").split()
                    if len(parts_l) < 5:
                        continue
                    name, ttl_s, _in, rtype = parts_l[0], parts_l[1], parts_l[2], parts_l[3]
                    content = " ".join(parts_l[4:]).strip('"')
                    if rtype in ("SOA", "NS"):
                        parsed += 1
                        continue  # SOA/NS are skipped by Cloudflare imports
                    if rtype not in ("A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "PTR"):
                        parsed += 1
                        continue
                    parsed += 1
                    if any(r["name"] == name.rstrip(".") and r["type"] == rtype and r["content"] == content for r in records):
                        continue  # duplicate - skipped, not replaced
                    prio = None
                    data = None
                    if rtype == "MX" and len(parts_l) >= 6:
                        prio = int(parts_l[4]); content = " ".join(parts_l[5:])
                    if rtype == "SRV" and len(parts_l) >= 8:
                        data = {"priority": int(parts_l[4]), "weight": int(parts_l[5]), "port": int(parts_l[6]), "target": parts_l[7].rstrip(".")}
                        content = f"{data['weight']} {data['port']} {data['target']}"
                    records.append(rec(rtype, name.rstrip("."), content, None, int(ttl_s) if ttl_s.isdigit() else 1, None, [], prio, data))
                    added += 1
                return self._json(envelope({"recs_added": added, "total_records_parsed": parsed}))

            if len(parts) == 4:
                rid = parts[3]
                found = next((r for r in records if r["id"] == rid), None)
                if not found:
                    return self._json({"success": False, "errors": [{"code": 81044, "message": "Record not found"}]}, 404)
                if method == "DELETE":
                    records.remove(found)
                    return self._json(envelope({"id": rid}))
                if method in ("PATCH", "PUT"):
                    payload = json.loads(self._body() or b"{}")
                    for k in ("content", "ttl", "proxied", "comment", "tags", "priority", "data", "name"):
                        if k in payload and payload[k] is not None:
                            found[k] = payload[k]
                    found["modified_on"] = "2026-07-29T18:30:00.000000Z"
                    return self._json(envelope(found))

        return self._json({"success": False, "errors": [{"message": f"mock: unhandled {method} {path}"}]}, 404)

    do_GET = lambda self: self.route("GET")
    do_POST = lambda self: self.route("POST")
    do_PUT = lambda self: self.route("PUT")
    do_PATCH = lambda self: self.route("PATCH")
    do_DELETE = lambda self: self.route("DELETE")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    print(f"Mock Cloudflare API on http://127.0.0.1:{port}/client/v4")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

"""Local lab for the dangling scenario: a fake DNS resolver and a fake provider web server.

Both listen on 127.0.0.1 only. The DNS server answers A, AAAA and CNAME queries for the synthetic zone
in zone.json (every name, the CNAME chain and the final records, NXDOMAIN when the chain ends at a
name that does not exist), like a recursive resolver would. The web server answers by Host header with
the page a provider shows for an unclaimed name (zone.json "http"), or a plain page. Nothing here talks
to the network: the provider names in the zone are only strings.

usage: python3 lab.py <zone.json> <dns-port> <http-port>
"""
import http.server
import json
import socket
import socketserver
import struct
import sys
import threading

zone = json.load(open(sys.argv[1]))
dns_port, http_port = int(sys.argv[2]), int(sys.argv[3])
records = {k.lower(): v for k, v in zone["records"].items()}
pages = {k.lower(): v for k, v in zone.get("http", {}).items()}

A, AAAA, CNAME = 1, 28, 5


def qname(data, off):
    labels = []
    while data[off]:
        n = data[off]
        labels.append(data[off + 1:off + 1 + n].decode())
        off += n + 1
    return ".".join(labels).lower(), off + 1


def encode(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) + b"\0"


def rr(name, typ, rdata):
    return encode(name) + struct.pack(">HHIH", typ, 1, 300, len(rdata)) + rdata


def answer(name, typ):
    """The answer section and rcode for a query, following the CNAME chain inside the zone."""
    out, seen = [], set()
    while name in records and name not in seen:
        seen.add(name)
        r = records[name]
        if "cname" in r:
            out.append(rr(name, CNAME, encode(r["cname"])))
            if typ == CNAME:
                return out, 0
            name = r["cname"].lower()
            continue
        if typ == A:
            out += [rr(name, A, socket.inet_aton(ip)) for ip in r.get("a", [])]
        if typ == AAAA:
            out += [rr(name, AAAA, socket.inet_pton(socket.AF_INET6, ip)) for ip in r.get("aaaa", [])]
        return out, r.get("rcode", 0)
    return out, 3  # NXDOMAIN: the name, or the end of its chain, does not exist


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            qid, flags = struct.unpack(">HH", data[:4])
            name, off = qname(data, 12)
            typ = struct.unpack(">H", data[off:off + 2])[0]
            question = data[12:off + 4]
            ans, rcode = answer(name, typ)
            hdr = struct.pack(">HHHHHH", qid, 0x8180 | (flags & 0x0100) | rcode, 1, len(ans), 0, 0)
            sock.sendto(hdr + question + b"".join(ans), self.client_address)
        except Exception:
            pass


class Web(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        page = pages.get(host)
        body = (page or {"status": 200, "body": "<html><body>Welcome</body></html>"})
        data = body["body"].encode()
        self.send_response(body["status"])
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


socketserver.ThreadingUDPServer.allow_reuse_address = True
dns = socketserver.ThreadingUDPServer(("127.0.0.1", dns_port), DNS)
web = http.server.ThreadingHTTPServer(("127.0.0.1", http_port), Web)
threading.Thread(target=dns.serve_forever, daemon=True).start()
print(f"lab: dns 127.0.0.1:{dns_port}, http 127.0.0.1:{http_port}", flush=True)
web.serve_forever()

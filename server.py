#!/usr/bin/env python3
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlparse

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
TIMEOUT = 10
USER_AGENT = "BifProtect-Testeur/1.0"

# --- Sécurité : le service ne doit pas devenir un proxy vers des réseaux privés. ---

def public_ips(hostname):
    infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    ips = sorted({item[4][0] for item in infos})
    if not ips:
        raise ValueError("Domaine non résolu.")
    for raw in ips:
        ip = ipaddress.ip_address(raw)
        if not ip.is_global:
            raise ValueError("Le domaine pointe vers une adresse non publique.")
    return ips

def validate_site_url(raw):
    parsed = urlparse(raw)
    if parsed.scheme.lower() != "https":
        raise ValueError("Le site doit utiliser HTTPS.")
    if not parsed.hostname:
        raise ValueError("Domaine invalide.")
    if parsed.username or parsed.password:
        raise ValueError("Les identifiants dans l'URL sont interdits.")
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Une adresse IP directe n'est pas acceptée.")
    if "." not in host:
        raise ValueError("Nom de domaine invalide.")
    return parsed

class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = validate_site_url(newurl)
        public_ips(parsed.hostname)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

SAFE_OPENER = urllib.request.build_opener(SafeRedirectHandler())

def open_safe(url, method="GET"):
    parsed = validate_site_url(url)
    public_ips(parsed.hostname)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
        method=method,
    )
    return SAFE_OPENER.open(req, timeout=TIMEOUT)

# --- Identité entreprise : pré-vérification publique du SIRET. ---

def identity(siret):
    try:
        url = "https://recherche-entreprises.api.gouv.fr/search?q=" + quote(siret)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))
        results = data.get("results") or []
        if not results:
            return {"found": False}
        item = results[0]
        return {
            "found": True,
            "nom": item.get("nom_complet") or item.get("nom_raison_sociale") or "",
            "etat": item.get("etat_administratif") or "",
        }
    except Exception as exc:
        return {"found": False, "error": str(exc)}

# --- DNS ---

def dns_probe(hostname):
    try:
        ips = public_ips(hostname)
        ipv4 = [x for x in ips if ":" not in x]
        ipv6 = [x for x in ips if ":" in x]
        return {"ipv4": ipv4, "ipv6": ipv6}
    except Exception as exc:
        return {"ipv4": [], "ipv6": [], "error": str(exc)}

# --- HTTP / en-têtes ---

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def http_probe(url):
    result = {
        "reachable": False,
        "status_code": None,
        "https": True,
        "final_url": None,
        "security_headers": {},
        "server": None,
        "error": None,
    }
    try:
        with open_safe(url, "GET") as response:
            result["reachable"] = True
            result["status_code"] = response.status
            result["final_url"] = response.geturl()
            result["server"] = response.headers.get("Server")
            for header in SECURITY_HEADERS:
                value = response.headers.get(header)
                if value:
                    result["security_headers"][header.lower()] = value
    except Exception as exc:
        result["error"] = str(exc)
    return result

# --- TLS ---

def tls_probe(hostname):
    result = {"valid": False, "subject": None, "issuer": None, "tls_version": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls_socket:
                cert = tls_socket.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result.update(
                    valid=True,
                    subject=subject.get("commonName"),
                    issuer=issuer.get("commonName"),
                    tls_version=tls_socket.version(),
                )
    except Exception as exc:
        result["error"] = str(exc)
    return result

# --- Score V1 : volontairement simple et explicable. ---

def calculate_score(company, dns, http, tls):
    score = 100
    reasons = []

    if not company.get("found"):
        score -= 10
        reasons.append("SIRET non retrouvé via la source publique interrogée.")

    if company.get("found") and company.get("etat") not in ("A", ""):
        score -= 15
        reasons.append("État administratif de l'établissement à vérifier.")

    if not dns.get("ipv4"):
        score -= 20
        reasons.append("Aucune adresse IPv4 publique résolue.")

    if not http.get("reachable"):
        score -= 25
        reasons.append("Site non accessible.")

    if not tls.get("valid"):
        score -= 20
        reasons.append("Certificat TLS non validé.")

    penalties = [
        ("strict-transport-security", 8, "HSTS absent"),
        ("content-security-policy", 8, "CSP absente"),
        ("x-content-type-options", 4, "X-Content-Type-Options absent"),
        ("x-frame-options", 4, "X-Frame-Options absent"),
    ]
    for header, penalty, reason in penalties:
        if header not in http.get("security_headers", {}):
            score -= penalty
            reasons.append(reason)

    score = max(0, min(100, score))
    decision = (
        "ELIGIBLE" if score >= 80
        else "SURVEILLANCE_RENFORCEE" if score >= 60
        else "CONTROLE_COMPLEMENTAIRE"
    )
    return {
        "score": score,
        "decision": decision,
        "reasons": reasons,
        "version_bareme": "1.0",
    }

class Handler(BaseHTTPRequestHandler):
    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json({"status": "ok"})
            return
        if self.path in ("/", "/index.html"):
            body = (Path("static") / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        if self.path != "/api/check":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            siret = str(payload.get("siret", "")).strip()
            site = str(payload.get("site", "")).strip()

            if not re.fullmatch(r"\d{14}", siret):
                self.send_json({"detail": "SIRET invalide : 14 chiffres attendus."}, 400)
                return

            parsed = validate_site_url(site)
            hostname = parsed.hostname

            company = identity(siret)
            dns = dns_probe(hostname)
            http = http_probe(site)
            tls = tls_probe(hostname)

            self.send_json({
                "identity": company,
                "hostname": hostname,
                "controls": {
                    "dns": dns,
                    "http": http,
                    "tls": tls,
                },
                "decision": calculate_score(company, dns, http, tls),
            })
        except ValueError as exc:
            self.send_json({"detail": str(exc)}, 400)
        except Exception as exc:
            self.send_json({"detail": "Erreur interne : " + str(exc)}, 500)

if __name__ == "__main__":
    print(f"BifProtect Testeur V1 — écoute sur {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

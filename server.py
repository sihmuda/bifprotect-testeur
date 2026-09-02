#!/usr/bin/env python3
import html
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
from urllib.parse import quote, urlencode, urljoin, urlparse

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
TIMEOUT = 12
USER_AGENT = "BifProtect-Testeur/2.0 (+https://bifprotect.fr)"
MAX_LEGAL_PAGES = 6
MAX_PAGE_BYTES = 700_000

# Sources publiques utilisées par BifProtect.
RECHERCHE_ENTREPRISES_URL = "https://recherche-entreprises.api.gouv.fr/search"
BODACC_API_URL = os.environ.get(
    "BODACC_API_URL",
    "https://bodacc-datadila.opendatasoft.com/api/explore/v2.1/catalog/datasets/annonces-commerciales/records",
)

# --- Réseau : le service ne doit pas devenir un proxy vers des réseaux privés. ---

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
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"},
        method=method,
    )
    return SAFE_OPENER.open(req, timeout=TIMEOUT)


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_text(url, max_bytes=MAX_PAGE_BYTES):
    with open_safe(url, "GET") as response:
        data = response.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        return data[:max_bytes].decode(response.headers.get_content_charset() or "utf-8", errors="replace"), response.geturl(), truncated


# --- Identité légale : SIRENE / Annuaire des Entreprises (API publique). ---

def _find_establishment(results, siret):
    for company in results:
        if company.get("siren") == siret[:9]:
            for est in company.get("matching_etablissements") or []:
                if est.get("siret") == siret:
                    return company, est
            siege = company.get("siege") or {}
            if siege.get("siret") == siret:
                return company, siege
    return None, None


def identity(siret):
    try:
        url = RECHERCHE_ENTREPRISES_URL + "?q=" + quote(siret) + "&per_page=20"
        data = fetch_json(url)
        results = data.get("results") or []
        company, establishment = _find_establishment(results, siret)

        if not company:
            # Second passage : recherche sur le SIREN si l'API n'a pas indexé le SIRET.
            url = RECHERCHE_ENTREPRISES_URL + "?q=" + quote(siret[:9]) + "&per_page=20"
            data = fetch_json(url)
            results = data.get("results") or []
            company, establishment = _find_establishment(results, siret)

        if not company:
            return {"found": False, "siret": siret, "siren": siret[:9]}

        legal_state = company.get("etat_administratif") or ""
        establishment_state = (establishment or {}).get("etat_administratif") or ""
        return {
            "found": True,
            "siret": siret,
            "siren": company.get("siren") or siret[:9],
            "nom": company.get("nom_complet") or company.get("nom_raison_sociale") or "",
            "nom_raison_sociale": company.get("nom_raison_sociale") or "",
            "etat": legal_state,
            "etat_libelle": "Active" if legal_state == "A" else "Cessée" if legal_state == "C" else legal_state,
            "etablissement_actif": establishment_state == "A",
            "etablissement_etat": establishment_state,
            "etablissement": establishment or {},
            "date_creation": company.get("date_creation"),
            "date_fermeture": company.get("date_fermeture"),
            "date_mise_a_jour": company.get("date_mise_a_jour"),
            "date_mise_a_jour_rne": company.get("date_mise_a_jour_rne"),
            "siege": company.get("siege") or {},
            "nature_juridique": company.get("nature_juridique"),
        }
    except Exception as exc:
        return {"found": False, "siret": siret, "siren": siret[:9], "error": str(exc)}


# --- BODACC : radiations et procédures collectives. Source officielle DILA. ---

def _record_siren(record, siren):
    values = record.get("registre") or []
    if isinstance(values, str):
        values = [values]
    compact = {re.sub(r"\D", "", str(v)) for v in values}
    return siren in compact


def _record_text(record):
    chunks = []
    for key in ("familleavis_lib", "typeavis_lib", "commercant", "jugement", "acte", "radiationaurcs", "modificationsgenerales", "divers", "listepersonnes"):
        value = record.get(key)
        if value is not None:
            chunks.append(str(value))
    return " ".join(chunks).lower()


def _is_collective(record):
    family = str(record.get("familleavis_lib") or "").lower()
    text = _record_text(record)
    return "procédure" in family or "collective" in family or any(
        word in text for word in ("liquidation judiciaire", "redressement judiciaire", "sauvegarde judiciaire")
    )


def _is_radiation(record):
    family = str(record.get("familleavis_lib") or "").lower()
    text = _record_text(record)
    return "radiation" in family or bool(record.get("radiationaurcs")) or "radiation du rcs" in text


def bodacc_status(siren):
    """Returns a conservative legal-status signal from official BODACC open data.

    BODACC publishes notices; it is not itself the sole source of truth for SIRENE status.
    We therefore combine this signal with the SIRENE state above.
    """
    base = {
        "available": False,
        "source": "BODACC / DILA",
        "radiation_detected": False,
        "procedures": [],
        "active_procedure": None,
        "latest_relevant_date": None,
        "error": None,
    }
    try:
        query = urlencode({"limit": 100, "order_by": "dateparution desc", "where": f"registre like '{siren}'"})
        try:
            data = fetch_json(BODACC_API_URL + "?" + query)
            records = [r for r in (data.get("results") or []) if _record_siren(r, siren)]
        except Exception:
            # Fallback si le moteur Opendatasoft refuse le filtre sur le champ tableau.
            params = urlencode({"limit": 100, "order_by": "dateparution desc", "q": siren})
            data = fetch_json(BODACC_API_URL + "?" + params)
            records = [r for r in (data.get("results") or []) if _record_siren(r, siren)]
        base["available"] = True

        relevant = []
        for record in records:
            if not (_is_collective(record) or _is_radiation(record)):
                continue
            date = record.get("dateparution") or ""
            relevant.append((date, record))
        relevant.sort(key=lambda x: x[0], reverse=True)

        for date, record in relevant:
            text = _record_text(record)
            family = str(record.get("familleavis_lib") or "")
            if _is_radiation(record):
                base["radiation_detected"] = True
            if _is_collective(record):
                if "liquidation" in text:
                    kind = "LIQUIDATION_JUDICIAIRE"
                elif "redressement" in text:
                    kind = "REDRESSEMENT_JUDICIAIRE"
                elif "sauvegarde" in text:
                    kind = "SAUVEGARDE"
                else:
                    kind = "PROCEDURE_COLLECTIVE"
                base["procedures"].append({
                    "type": kind,
                    "date": date,
                    "famille": family,
                    "tribunal": record.get("tribunal"),
                    "url": record.get("url_complete"),
                    "text": re.sub(r"\s+", " ", text)[:500],
                })

        # Les avis sont chronologiques. Pour une décision conservatoire, on retient le dernier avis.
        if relevant:
            base["latest_relevant_date"] = relevant[0][0]
            latest_text = _record_text(relevant[0][1])
            if _is_collective(relevant[0][1]):
                if "liquidation" in latest_text:
                    base["active_procedure"] = "LIQUIDATION_JUDICIAIRE"
                elif "redressement" in latest_text:
                    base["active_procedure"] = "REDRESSEMENT_JUDICIAIRE"
                elif "sauvegarde" in latest_text:
                    base["active_procedure"] = "SAUVEGARDE"
                else:
                    base["active_procedure"] = "PROCEDURE_COLLECTIVE"
        return base
    except Exception as exc:
        base["error"] = str(exc)
        return base


# --- Rattachement entreprise ↔ domaine ---

LEGAL_LINK_KEYWORDS = (
    "mentions légales", "mentions legales", "informations légales", "informations legales",
    "cgv", "conditions générales", "conditions generales", "legal notice", "legal",
    "qui sommes-nous", "qui sommes nous", "à propos", "a propos", "about", "contact",
)


def normalize_text(value):
    value = html.unescape(value or "")
    value = re.sub(r"<script\b[^>]*>.*?</script>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<style\b[^>]*>.*?</style>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _domain_candidates(base_url, html_text):
    links = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html_text, flags=re.I)
    base = urlparse(base_url)
    candidates = []
    for href in links:
        absolute = urljoin(base_url, href)
        try:
            p = validate_site_url(absolute)
        except Exception:
            continue
        if p.hostname != base.hostname:
            continue
        label = normalize_text(href).lower()
        if any(k in label for k in LEGAL_LINK_KEYWORDS) or any(k in absolute.lower() for k in LEGAL_LINK_KEYWORDS):
            candidates.append(absolute)
    # Keep order and uniqueness.
    return list(dict.fromkeys(candidates))[:MAX_LEGAL_PAGES]


def domain_link_probe(site, company):
    result = {
        "status": "NON_VERIFIE",
        "score": 0,
        "evidence": [],
        "pages_checked": [],
        "error": None,
    }
    if not company.get("found"):
        result["error"] = "Entreprise non retrouvée : rattachement impossible."
        return result

    siret = company.get("siret", "")
    siren = company.get("siren", siret[:9])
    names = [company.get("nom") or "", company.get("nom_raison_sociale") or ""]
    names = [re.sub(r"[^a-z0-9]+", "", x.lower()) for x in names if x]

    try:
        home_text, final_url, truncated = fetch_text(site)
        pages = [(site, home_text)]
        candidates = _domain_candidates(final_url, home_text)
        for candidate in candidates:
            try:
                text, resolved, _ = fetch_text(candidate)
                pages.append((resolved, text))
            except Exception:
                continue

        seen = set()
        for page_url, raw in pages:
            if page_url in seen:
                continue
            seen.add(page_url)
            clean = normalize_text(raw)
            lower = clean.lower()
            siret_found = bool(re.search(rf"(?<!\d){re.escape(siret[:3])}[\s.-]?{re.escape(siret[3:6])}[\s.-]?{re.escape(siret[6:9])}[\s.-]?{re.escape(siret[9:])}(?!\d)", clean))
            siren_found = bool(re.search(rf"(?<!\d){re.escape(siren[:3])}[\s.-]?{re.escape(siren[3:6])}[\s.-]?{re.escape(siren[6:])}(?!\d)", clean))
            name_found = any(len(n) >= 6 and n in re.sub(r"[^a-z0-9]+", "", lower) for n in names)
            if siret_found:
                result["score"] = max(result["score"], 100)
                result["evidence"].append({"type": "SIRET", "page": page_url, "strength": "FORTE"})
            elif siren_found:
                result["score"] = max(result["score"], 90)
                result["evidence"].append({"type": "SIREN", "page": page_url, "strength": "FORTE"})
            elif name_found:
                result["score"] = max(result["score"], 45)
                result["evidence"].append({"type": "DENOMINATION", "page": page_url, "strength": "FAIBLE"})
            result["pages_checked"].append(page_url)

        if result["score"] >= 90:
            result["status"] = "VERIFIE"
        elif result["score"] >= 40:
            result["status"] = "PROBABLE"
        else:
            result["status"] = "NON_ETABLI"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


# --- DNS / HTTP / TLS ---

def dns_probe(hostname):
    try:
        ips = public_ips(hostname)
        ipv4 = [x for x in ips if ":" not in x]
        ipv6 = [x for x in ips if ":" in x]
        return {"ipv4": ipv4, "ipv6": ipv6, "error": None}
    except Exception as exc:
        return {"ipv4": [], "ipv6": [], "error": str(exc)}


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


# --- Score : technique + garde juridique. ---

def calculate_score(company, legal, link, dns, http, tls):
    score = 100
    reasons = []

    # Les contrôles techniques conservent la logique V1.
    if not dns.get("ipv4"):
        score -= 20
        reasons.append("Aucune adresse IPv4 publique résolue.")
    if not http.get("reachable"):
        score -= 25
        reasons.append("Site non accessible.")
    if not tls.get("valid"):
        score -= 20
        reasons.append("Certificat TLS non validé.")

    for header, penalty, reason in [
        ("strict-transport-security", 8, "HSTS absent"),
        ("content-security-policy", 8, "CSP absente"),
        ("x-content-type-options", 4, "X-Content-Type-Options absent"),
        ("x-frame-options", 4, "X-Frame-Options absent"),
    ]:
        if header not in http.get("security_headers", {}):
            score -= penalty
            reasons.append(reason)

    # Le statut juridique est un garde-fou : il ne se compense pas par un bon score technique.
    legal_gate = True
    if not company.get("found"):
        legal_gate = False
        reasons.append("SIRET non retrouvé dans la source publique interrogée.")
    elif company.get("etat") != "A":
        legal_gate = False
        reasons.append("Unité légale non active / cessée.")
    if company.get("found") and not company.get("etablissement_actif"):
        legal_gate = False
        reasons.append("L'établissement correspondant au SIRET n'est pas actif.")

    if legal.get("radiation_detected"):
        legal_gate = False
        reasons.append("Une radiation est signalée dans les annonces BODACC.")
    if legal.get("active_procedure") == "LIQUIDATION_JUDICIAIRE":
        legal_gate = False
        reasons.append("Une liquidation judiciaire est signalée.")
    elif legal.get("active_procedure") == "REDRESSEMENT_JUDICIAIRE":
        reasons.append("Un redressement judiciaire est signalé : contrôle renforcé requis.")
    elif legal.get("active_procedure") == "SAUVEGARDE":
        reasons.append("Une procédure de sauvegarde est signalée : contrôle renforcé requis.")

    if legal.get("available") is False:
        legal_gate = False
        reasons.append("Le contrôle BODACC n'a pas pu être effectué : statut juridique à confirmer.")

    # Le rattachement du domaine est un contrôle bloquant : une simple ressemblance de marque ne suffit pas.
    if link.get("status") != "VERIFIE":
        legal_gate = False
        if link.get("status") == "PROBABLE":
            reasons.append("Le lien entre le domaine et le SIRET est seulement probable ; preuve juridique directe requise.")
        else:
            reasons.append("Le lien entre le domaine et le SIRET n'a pas été établi.")

    score = max(0, min(100, score))
    if not legal_gate:
        decision = "NON_ELIGIBLE" if any(
            x in reasons for x in (
                "Unité légale non active / cessée.",
                "L'établissement correspondant au SIRET n'est pas actif.",
                "Une radiation est signalée dans les annonces BODACC.",
                "Une liquidation judiciaire est signalée.",
                "Le lien entre le domaine et le SIRET n'a pas été établi.",
            )
        ) else "CONTROLE_COMPLEMENTAIRE"
    elif legal.get("active_procedure") in ("REDRESSEMENT_JUDICIAIRE", "SAUVEGARDE"):
        decision = "SURVEILLANCE_RENFORCEE"
    elif score >= 80:
        decision = "ELIGIBLE"
    elif score >= 60:
        decision = "SURVEILLANCE_RENFORCEE"
    else:
        decision = "CONTROLE_COMPLEMENTAIRE"

    return {
        "score": score,
        "decision": decision,
        "legal_gate": legal_gate,
        "reasons": reasons,
        "version_bareme": "2.0",
    }


class Handler(BaseHTTPRequestHandler):
    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json({"status": "ok", "version": "2.0"})
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
            legal = bodacc_status(company.get("siren", siret[:9])) if company.get("found") else {
                "available": False,
                "source": "BODACC / DILA",
                "radiation_detected": False,
                "procedures": [],
                "active_procedure": None,
                "latest_relevant_date": None,
                "error": "SIREN indisponible",
            }
            link = domain_link_probe(site, company)
            dns = dns_probe(hostname)
            http = http_probe(site)
            tls = tls_probe(hostname)
            decision = calculate_score(company, legal, link, dns, http, tls)

            self.send_json({
                "identity": company,
                "legal": legal,
                "domain_link": link,
                "hostname": hostname,
                "controls": {"dns": dns, "http": http, "tls": tls},
                "decision": decision,
            })
        except ValueError as exc:
            self.send_json({"detail": str(exc)}, 400)
        except Exception as exc:
            self.send_json({"detail": "Erreur interne : " + str(exc)}, 500)


if __name__ == "__main__":
    print(f"BifProtect Testeur V2 — écoute sur {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

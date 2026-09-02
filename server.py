#!/usr/bin/env python3
import html
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.request
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
TIMEOUT = 10
USER_AGENT = "BifProtect-Testeur/2.9"

SEARCH_API = "https://recherche-entreprises.api.gouv.fr/search?q="
BODACC_API = "https://bodacc-datadila.opendatasoft.com/api/explore/v2.1/catalog/datasets/annonces-commerciales/records"

# --- Sécurité réseau : pas de proxy vers des réseaux privés ---

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
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method=method)
    return SAFE_OPENER.open(req, timeout=TIMEOUT)


# --- Helpers ---

def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def normalize_text(value):
    value = html.unescape(str(value or "")).lower()
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def normalize_name(value):
    value = normalize_text(value)
    value = re.sub(r"[^a-z0-9à-ÿ]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def organizational_domain(hostname):
    """Retourne une approximation prudente du domaine organisationnel (eTLD+1).

    BifProtect doit pouvoir suivre www et les sous-domaines officiels (ex.
    marketplace.cdiscount.com) sans considérer un domaine tiers comme faisant
    partie du site. Pour les suffixes composés courants, on conserve 3 labels.
    """
    host = (hostname or "").strip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = [x for x in host.split(".") if x]
    if len(labels) < 2:
        return host
    compound_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
        "co.nz", "net.nz", "org.nz", "co.jp", "ne.jp", "com.br", "com.mx",
        "com.tr", "com.sg", "com.hk", "co.za", "co.kr", "co.in", "co.il"
    }
    suffix = ".".join(labels[-2:])
    if suffix in compound_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_organizational_domain(host_a, host_b):
    return organizational_domain(host_a) == organizational_domain(host_b)


def name_tokens(value):
    stop = {
        "sa", "sas", "sasu", "sarl", "eurl", "sci", "sarl", "association", "de", "des", "du", "la", "le",
        "les", "et", "en", "a", "au", "aux", "the", "company", "co", "france", "international"
    }
    return {t for t in normalize_name(value).split() if len(t) >= 4 and t not in stop}


# --- Identité entreprise (SIREN) ---

def _normalize_admin_state(value):
    """Retourne A/F lorsque l'état administratif de l'unité légale est explicite."""
    if isinstance(value, dict):
        value = value.get("value") or value.get("code")
    value = str(value or "").strip().upper()
    return value if value in {"A", "F"} else None


def _active_establishment_count(item):
    """Compte les établissements explicitement actifs lorsqu'ils sont présents dans la réponse."""
    entries = []
    siege = item.get("siege") or {}
    if siege:
        entries.append(siege)
    entries.extend(item.get("matching_etablissements") or [])
    seen = set()
    count = 0
    for etab in entries:
        siret = str(etab.get("siret") or "")
        key = siret or id(etab)
        if key in seen:
            continue
        seen.add(key)
        if _normalize_admin_state(etab.get("etat_administratif")) == "A":
            count += 1
    return count


def identity(siren):
    """Vérifie l'unité légale à partir du SIREN. Aucun SIRET n'est requis par BifProtect."""
    siren = re.sub(r"\D", "", str(siren or ""))
    if not re.fullmatch(r"\d{9}", siren):
        return {"found": False, "siren": siren, "source": "Recherche d'entreprises", "error": "SIREN invalide."}
    try:
        data = fetch_json(SEARCH_API + quote(siren))
        results = data.get("results") or []
        chosen = None
        for item in results:
            if str(item.get("siren") or "") == siren:
                chosen = item
                break
        if chosen is None and results:
            chosen = results[0]

        if chosen is None:
            return {"found": False, "siren": siren, "source": "Recherche d'entreprises"}

        state = _normalize_admin_state(chosen.get("etat_administratif"))
        siege = chosen.get("siege") or {}
        siege_state = _normalize_admin_state(siege.get("etat_administratif"))
        return {
            "found": True,
            "siren": siren,
            "nom": chosen.get("nom_complet") or chosen.get("nom_raison_sociale") or "",
            "etat": state,
            "date_fermeture": chosen.get("date_fermeture"),
            "siege_siret": siege.get("siret") or "",
            "siege_state": siege_state,
            "active_establishments": _active_establishment_count(chosen),
            "source": "Recherche d'entreprises",
        }
    except Exception as exc:
        return {"found": False, "siren": siren, "source": "Recherche d'entreprises", "error": str(exc)}


# --- BODACC : procédures collectives / radiations publiées ---

def _json_field(value):
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {"_text": str(value)}


def _record_text(record):
    parts = []
    for key in ("jugement", "acte", "modificationsgenerales", "radiationaurcs", "divers", "typeavis_lib", "familleavis_lib"):
        value = record.get(key)
        if value:
            obj = _json_field(value)
            parts.append(json.dumps(obj, ensure_ascii=False) if isinstance(obj, dict) else str(obj))
    return normalize_text(" ".join(parts))


def legal_status(siren):
    result = {
        "available": False,
        "source": "BODACC / DILA",
        "radiation": False,
        "liquidation": False,
        "redressement": False,
        "sauvegarde": False,
        "records": [],
        "error": None,
    }
    if not siren:
        result["error"] = "SIREN indisponible."
        return result
    try:
        where = f'registre like "{siren}"'
        params = f"?where={quote(where)}&order_by=dateparution%20desc&limit=50"
        data = fetch_json(BODACC_API + params)
        records = data.get("results") or []
        result["available"] = True
        result["records"] = records[:20]

        # Le BODACC est un historique : une ancienne ouverture de procédure ne doit
        # pas rester bloquante si une annonce ultérieure clôture la procédure.
        procedure_events = []
        for rec in records:
            text = _record_text(rec)
            radiation_field = normalize_text(rec.get("radiationaurcs"))
            nature = normalize_text(_json_field(rec.get("jugement")).get("nature", ""))

            if radiation_field or "radiation" in text:
                result["radiation"] = True

            if nature and any(k in nature for k in (
                "liquidation", "redressement", "sauvegarde", "procedure collective",
                "procédure collective", "plan de sauvegarde", "plan de redressement"
            )):
                procedure_events.append((str(rec.get("dateparution") or ""), nature))

        procedure_events.sort(reverse=True)
        if procedure_events:
            latest = procedure_events[0][1]
            closure = any(x in latest for x in (
                "clôture", "cloture", "fin de la procédure", "fin de la procedure",
                "résolution du plan", "resolution du plan", "clôture pour insuffisance",
                "cloture pour insuffisance"
            ))
            if not closure:
                if "liquidation judiciaire" in latest or "ouverture de liquidation" in latest or "conversion en liquidation" in latest:
                    result["liquidation"] = True
                elif "redressement judiciaire" in latest or "ouverture d'une procédure de redressement" in latest:
                    result["redressement"] = True
                elif "sauvegarde" in latest:
                    result["sauvegarde"] = True

        # Les informations brutes restent visibles pour audit, mais on limite la charge utile.
        result["records"] = [
            {
                "date": r.get("dateparution"),
                "famille": r.get("familleavis_lib"),
                "type": r.get("typeavis_lib"),
                "nature": _json_field(r.get("jugement")).get("nature", "") if r.get("jugement") else "",
                "url": r.get("url_complete") or "",
            }
            for r in result["records"]
        ]
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


# --- Rattachement domaine ↔ entreprise ---

class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.links = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        text = data.strip()
        if text:
            self.parts.append(text)
            if self._in_title:
                self.title += " " + text


def _contains_registration(raw, siren):
    """Détecte un SIREN/SIRET dans HTML, texte brut ou PDF.

    Les mentions légales de certains sites sont servies uniquement en PDF.
    Une simple recherche dans les octets du PDF ne suffit pas lorsque le texte
    est compressé : on extrait donc le texte avec pypdf avant la recherche.
    """
    if not raw:
        return None
    if isinstance(raw, (bytes, bytearray)):
        blob = bytes(raw)
        if blob.startswith(b"%PDF"):
            try:
                from pypdf import PdfReader
                reader = PdfReader(io.BytesIO(blob))
                text = "\n".join((page.extract_text() or "") for page in reader.pages)
            except Exception:
                text = blob.decode("latin-1", errors="ignore")
        else:
            text = blob.decode("latin-1", errors="ignore")
    else:
        text = str(raw)
    if siren:
        compact = re.sub(r"\D", "", text)
        if siren in compact:
            return f"SIREN {siren}"
        pat = r"\b" + r"\D*".join(map(re.escape, [siren[i:i+3] for i in range(0, 9, 3)])) + r"\b"
        if re.search(pat, text):
            return f"SIREN {siren}"
    return None


def extract_site_evidence(url, siren, company_name):
    """Établit le rattachement domaine ↔ SIREN.

    Une preuve directe est recherchée sur le domaine organisationnel du site,
    y compris www et les sous-domaines officiels. Les pages HTML, PDF, liens
    légaux et sitemaps sont inspectés sans suivre des domaines tiers.
    """
    result = {
        "status": "UNKNOWN",
        "label": "Non déterminé",
        "direct_proof": False,
        "score": 0,
        "pages_checked": [],
        "evidence": [],
        "error": None,
    }
    try:
        base = validate_site_url(url)
        base_org = organizational_domain(base.hostname)
        root = f"{base.scheme}://{base.netloc}"
        legal_terms = (
            "mentions", "mention-legale", "mentions-legales", "legal", "legal-notice",
            "cgv", "conditions", "terms", "impressum", "qui-sommes", "a-propos",
            "about", "rgpd", "privacy", "confidentialite", "cookies", "company"
        )
        direct_paths = [
            "mentions-legales", "mentions-legales/", "mentions_legales", "mentions_legales/",
            "legal-notice", "legal-notice/", "legal", "legal/", "cgv", "cgv/",
            "conditions-generales-de-vente", "conditions-generales-de-vente/",
            "contact", "a-propos", "about", "resources/RWD/other/mentions_legales.pdf",
            "mentions_legales.pdf", "mentions-legales.pdf", "legal-notice.pdf"
        ]
        candidates = [url] + [urljoin(root + "/", path) for path in direct_paths]
        seen = set()
        combined = []
        discovered = []
        sitemap_urls = []

        def allowed(candidate):
            try:
                p = urlparse(candidate)
                return p.scheme.lower() == "https" and same_organizational_domain(p.hostname, base_org)
            except Exception:
                return False

        def add_candidate(candidate, force=False):
            if not candidate:
                return
            try:
                p = urlparse(candidate)
                if not allowed(candidate):
                    return
                low = candidate.lower()
                path_low = p.path.lower()
                is_pdf = path_low.endswith(".pdf") or ".pdf?" in low
                is_legal = force or is_pdf or any(k in low for k in legal_terms)
                if is_legal and candidate not in seen:
                    discovered.append(candidate)
            except Exception:
                return

        def parse_html(raw, final_url):
            parser = TextExtractor()
            parser.feed(raw.decode("utf-8", errors="ignore"))
            combined.append(normalize_text(" ".join(parser.parts)))
            for href in parser.links:
                try:
                    candidate = urljoin(final_url, href)
                    # Tout lien PDF ou page juridique du même domaine organisationnel
                    # est candidat, y compris sur un sous-domaine officiel.
                    add_candidate(candidate)
                except Exception:
                    pass

        def check_candidate(candidate):
            if candidate in seen:
                return
            if not allowed(candidate):
                return
            seen.add(candidate)
            try:
                with open_safe(candidate, "GET") as response:
                    final_url = response.geturl()
                    if not allowed(final_url):
                        return
                    content_type = (response.headers.get("Content-Type") or "").lower()
                    raw = response.read(900_000)
                    result["pages_checked"].append(final_url)
                    proof = _contains_registration(raw, siren)
                    if proof:
                        result["direct_proof"] = True
                        result["score"] = 100
                        result["evidence"].append(f"{proof} retrouvé sur {final_url}")
                    if "html" in content_type or final_url.lower().split("?", 1)[0].endswith((".html", ".htm", "/")):
                        parse_html(raw, final_url)
            except Exception:
                return

        # Première passe : page saisie + variantes légales connues.
        for candidate in candidates:
            check_candidate(candidate)

        # Deuxième passe : liens légaux/PDF découverts sur les pages du même domaine.
        for candidate in discovered[:40]:
            check_candidate(candidate)
            if result["direct_proof"]:
                break

        # Troisième passe : robots.txt et sitemaps. Cela permet de retrouver une
        # page légale/PDF non liée directement depuis la page d'accueil.
        robots = urljoin(root + "/", "robots.txt")
        try:
            with open_safe(robots, "GET") as response:
                raw = response.read(200_000)
                text = raw.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        sm = line.split(":", 1)[1].strip()
                        if allowed(sm):
                            sitemap_urls.append(sm)
        except Exception:
            pass
        if not sitemap_urls:
            sitemap_urls.append(urljoin(root + "/", "sitemap.xml"))

        for sm in sitemap_urls[:3]:
            try:
                if not allowed(sm):
                    continue
                with open_safe(sm, "GET") as response:
                    raw = response.read(800_000)
                    xml = raw.decode("utf-8", errors="ignore")
                    for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", xml, flags=re.I | re.S):
                        loc = html.unescape(loc.strip())
                        if allowed(loc):
                            low = loc.lower()
                            if any(k in low for k in legal_terms) or low.endswith(".pdf"):
                                add_candidate(loc, force=True)
            except Exception:
                continue
        for candidate in discovered[:60]:
            check_candidate(candidate)
            if result["direct_proof"]:
                break

        corpus = normalize_text(" ".join(combined))
        domain_tokens = name_tokens(base.hostname.replace("www.", "").split(".")[0])
        company_tokens = name_tokens(company_name)
        overlap = company_tokens & domain_tokens
        if overlap:
            result["score"] = max(result["score"], min(75, 40 + 10 * len(overlap)))
            result["evidence"].append("Le nom de domaine partage des éléments significatifs avec la raison sociale.")
        if company_tokens:
            page_overlap = {t for t in company_tokens if t in corpus}
            if page_overlap:
                result["score"] = max(result["score"], min(85, 45 + 8 * len(page_overlap)))
                result["evidence"].append("La raison sociale apparaît ou est cohérente avec le contenu du site.")

        if result["direct_proof"]:
            result["status"] = "VERIFIED"
            result["label"] = "Vérifié"
        elif result["score"] >= 50:
            result["status"] = "PROBABLE"
            result["label"] = "Probable — justificatif requis"
        else:
            result["status"] = "UNCONFIRMED"
            result["label"] = "Non établi — justificatif requis"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        result["status"] = "UNKNOWN"
        result["label"] = "Contrôle complémentaire requis"
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
        "reachable": False, "status_code": None, "https": True, "final_url": None,
        "security_headers": {}, "server": None, "error": None,
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
                result.update(valid=True, subject=subject.get("commonName"), issuer=issuer.get("commonName"), tls_version=tls_socket.version())
    except Exception as exc:
        result["error"] = str(exc)
    return result


# --- Barème / décision ---

def calculate_score(company, legal, domain_link, dns, http, tls):
    score = 100
    reasons = []
    blockers = []
    complementary = []

    # Garde-fou juridique principal : BifProtect identifie désormais l'entreprise par SIREN.
    # Aucun établissement précis n'est imposé à la souscription.
    if not company.get("found"):
        score -= 20
        blockers.append("SIREN non retrouvé dans la source publique interrogée.")
    elif company.get("etat") == "F":
        blockers.append("L'entreprise est déclarée cessée.")
    elif company.get("etat") not in {"A", "F"}:
        complementary.append("L'état administratif de l'entreprise n'a pas pu être confirmé automatiquement.")

    if legal.get("available"):
        if legal.get("radiation"):
            blockers.append("Une radiation est signalée dans les annonces BODACC.")
        if legal.get("liquidation"):
            blockers.append("Une procédure de liquidation judiciaire est signalée.")
        if legal.get("redressement"):
            complementary.append("Une procédure de redressement judiciaire est signalée.")
        if legal.get("sauvegarde"):
            complementary.append("Une procédure de sauvegarde est signalée.")
    else:
        complementary.append("Le contrôle BODACC n'a pas pu être réalisé automatiquement.")

    if domain_link.get("status") != "VERIFIED":
        complementary.append("Le lien entre le domaine et le SIREN n'est pas établi par une preuve juridique directe : justificatif requis avant validation définitive.")

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

    score = max(0, min(100, score))

    # Règle métier demandée : le complémentaire n'empêche pas la souscription.
    # Il empêche uniquement la validation définitive tant que le justificatif n'est pas fourni.
    if blockers:
        decision = "NON_ELIGIBLE"
        decision_label = "NON ÉLIGIBLE"
    elif complementary:
        decision = "ELIGIBLE_SOUS_RESERVE"
        decision_label = "ÉLIGIBLE SOUS RÉSERVE"
    elif score >= 80:
        decision = "ELIGIBLE"
        decision_label = "ÉLIGIBLE"
    elif score >= 60:
        decision = "SURVEILLANCE_RENFORCEE"
        decision_label = "SURVEILLANCE RENFORCÉE"
    else:
        decision = "CONTROLE_COMPLEMENTAIRE"
        decision_label = "CONTRÔLE COMPLÉMENTAIRE"

    reasons.extend(complementary)
    return {
        "score": score,
        "decision": decision,
        "decision_label": decision_label,
        "can_subscribe": not bool(blockers),
        "final_validation": not bool(blockers) and not bool(complementary),
        "justificatif_required": bool(complementary) and not bool(blockers),
        "blockers": blockers,
        "complementary": complementary,
        "reasons": reasons,
        "version_bareme": "2.9",
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
            self.send_json({"status": "ok", "version": "2.9"})
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
            siren = str(payload.get("siren", "")).strip()
            site = str(payload.get("site", "")).strip()
            if not re.fullmatch(r"\d{9}", siren):
                self.send_json({"detail": "SIREN invalide : 9 chiffres attendus."}, 400)
                return
            parsed = validate_site_url(site)
            hostname = parsed.hostname

            company = identity(siren)
            legal = legal_status(company.get("siren") or siren)
            dns = dns_probe(hostname)
            http = http_probe(site)
            tls = tls_probe(hostname)
            domain_link = extract_site_evidence(site, company.get("siren") or siren, company.get("nom", ""))
            decision = calculate_score(company, legal, domain_link, dns, http, tls)

            self.send_json({
                "identity": company,
                "legal": legal,
                "domain_link": domain_link,
                "hostname": hostname,
                "controls": {"dns": dns, "http": http, "tls": tls},
                "decision": decision,
            })
        except ValueError as exc:
            self.send_json({"detail": str(exc)}, 400)
        except Exception as exc:
            self.send_json({"detail": "Erreur interne : " + str(exc)}, 500)


if __name__ == "__main__":
    print(f"BifProtect Testeur V2.9 — écoute sur {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

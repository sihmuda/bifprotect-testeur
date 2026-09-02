#!/usr/bin/env python3
import html
import io
import ipaddress
import json
import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.error
import urllib.request
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
TIMEOUT = 4
MAX_PAGE_BYTES = 1_500_000
# UA navigateur standard pour éviter de transformer le contrôle en signature de bot.
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
LEGAL_USER_AGENT = USER_AGENT

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


def open_safe(url, method="GET", user_agent=None):
    parsed = validate_site_url(url)
    public_ips(parsed.hostname)
    headers = {
        "User-Agent": user_agent or USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf;q=0.8,*/*;q=0.7",
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.7",
        "Referer": f"https://{parsed.hostname}/",
    }
    req = urllib.request.Request(url, headers=headers, method=method)
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
    """Établit rapidement le rattachement domaine ↔ entreprise.

    La vérification publique doit rester non intrusive et surtout ne pas transformer
    une absence de preuve en une exploration interminable. On privilégie :
      1. la page d'accueil ;
      2. les principales pages légales du même hôte / www ;
      3. les liens légaux explicitement découverts dans l'accueil.
    Les sous-domaines arbitraires et le sitemap ne sont plus explorés automatiquement.
    """
    result = {"status":"UNKNOWN","label":"Non déterminé","direct_proof":False,
              "score":0,"pages_checked":[],"evidence":[],"error":None}
    try:
        base = validate_site_url(url)
        base_org = organizational_domain(base.hostname)
        base_host = base.hostname.lower().strip(".")
        legal_terms = ("mentions", "mention-legale", "mentions-legales", "legal", "legal-notice",
                       "cgv", "conditions", "terms", "impressum", "qui-sommes", "a-propos",
                       "about", "rgpd", "privacy", "confidentialite", "cookies", "company")
        direct_paths = [
            "mentions-legales", "mentions_legales", "legal-notice", "legal", "cgv",
            "conditions-generales-de-vente", "cgu", "dc/cgu", "dc/cgv", "dc/cookies",
            "dc/privacy", "dc/mentions-legales", "a-propos", "about",
            "resources/RWD/other/mentions_legales.pdf", "mentions_legales.pdf", "mentions-legales.pdf"
        ]
        seen=set(); discovered=[]; combined=[]

        def allowed(candidate):
            try:
                p=urlparse(candidate)
                return p.scheme.lower()=="https" and same_organizational_domain(p.hostname, base_org)
            except Exception:
                return False

        def add_candidate(candidate, force=False):
            if not candidate or not allowed(candidate): return
            try:
                low=candidate.lower(); path_low=urlparse(candidate).path.lower()
                is_pdf=path_low.endswith('.pdf')
                is_legal=force or is_pdf or any(k in low for k in legal_terms)
                if is_legal and candidate not in seen and candidate not in discovered:
                    discovered.append(candidate)
            except Exception:
                return

        def parse_html(raw, final_url):
            parser=TextExtractor(); parser.feed(raw.decode('utf-8',errors='ignore'))
            text=normalize_text(" ".join(parser.parts)); combined.append(text)
            for href in parser.links:
                try: add_candidate(urljoin(final_url,href))
                except Exception: pass

        def page_proves_base(text, final_url):
            if not text: return False
            host=(urlparse(final_url).hostname or "").lower().strip('.')
            if host == base_host: return True
            tokens={base_org, "www."+base_org, base_host}
            return any(t in normalize_text(text) for t in tokens)

        def page_proves_company_role(text, final_url):
            if not text or not company_name: return False
            host=(urlparse(final_url).hostname or "").lower().strip('.')
            if not same_organizational_domain(host, base_org): return False
            normalized_text=normalize_text(text)
            company_tokens=name_tokens(company_name)
            if len(company_tokens) >= 2:
                name_hit=sum(1 for t in company_tokens if t in normalized_text) >= 2
            else:
                name_hit=bool(company_tokens) and next(iter(company_tokens)) in normalized_text
            if not name_hit: return False
            role_terms=(
                "exploitant", "vendeur", "editeur", "éditeur", "responsable du traitement",
                "proprietaire", "propriétaire", "societe", "société", "site marchand",
                "conditions de vente", "conditions generales de vente", "conditions générales de vente",
                "propriete intellectuelle", "propriété intellectuelle", "agissant pour le compte de",
                "responsable de traitement"
            )
            return any(term in normalized_text for term in role_terms)

        def check_candidate(candidate):
            if candidate in seen or not allowed(candidate): return False
            seen.add(candidate)
            try:
                with open_safe(candidate,"GET", user_agent=LEGAL_USER_AGENT) as response:
                    final_url=response.geturl()
                    if not allowed(final_url): return False
                    ctype=(response.headers.get("Content-Type") or "").lower()
                    raw=response.read(800_000)
                    result["pages_checked"].append(final_url)
                    proof=_contains_registration(raw,siren)
                    page_text=""
                    is_pdf=ctype.startswith("application/pdf") or final_url.lower().split('?',1)[0].endswith('.pdf')
                    if not is_pdf:
                        parser=TextExtractor(); parser.feed(raw.decode('utf-8',errors='ignore'))
                        page_text=" ".join(parser.parts)
                    if proof:
                        # Le SIREN est l'identifiant légal de l'entreprise : s'il est
                        # retrouvé sur une page du même domaine organisationnel, la preuve
                        # est directe, y compris pour une page HTML qui ne répète pas son
                        # propre domaine dans le texte.
                        if same_organizational_domain(final_url, base_org):
                            result["direct_proof"]=True; result["score"]=100
                            result["evidence"].append(f"{proof} retrouvé sur {final_url}")
                            return True
                    if page_text and page_proves_company_role(page_text, final_url):
                        result["direct_proof"]=True; result["score"]=100
                        result["evidence"].append(f"Entreprise identifiée juridiquement sur {final_url}")
                        return True
                    if not is_pdf:
                        parse_html(raw,final_url)
            except Exception:
                return False
            return False

        # Accueil d'abord : une seule requête permet de détecter rapidement une preuve
        # et de découvrir les véritables liens légaux du site.
        home_candidates=[f"https://{base_host}/"]
        if base_host != "www."+base_org:
            home_candidates.append(f"https://www.{base_org}/")
        # Certains grands marchands publient leurs mentions légales sur un
        # sous-domaine fonctionnel (ex. marketplace.cdiscount.com) plutôt que
        # directement sur www. On vérifie seulement quelques sous-domaines
        # conventionnels, sans exploration arbitraire.
        for sub in ("marketplace", "legal", "corporate"):
            home_candidates.append(f"https://{sub}.{base_org}/")
        home_candidates=list(dict.fromkeys(home_candidates))

        with ThreadPoolExecutor(max_workers=min(2,len(home_candidates))) as pool:
            futures=[pool.submit(check_candidate,c) for c in home_candidates]
            for future in as_completed(futures):
                try:
                    if future.result() and result["direct_proof"]: break
                except Exception: pass

        if not result["direct_proof"]:
            # Pages légales prioritaires, uniquement sur le domaine saisi et www.
            priority=[]
            hosts=[base_host, f"www.{base_org}", f"marketplace.{base_org}", f"legal.{base_org}", f"corporate.{base_org}"]
            hosts=list(dict.fromkeys(hosts))
            for host in hosts:
                for path in direct_paths:
                    candidate=f"https://{host}/{path}"
                    if candidate not in priority: priority.append(candidate)

            with ThreadPoolExecutor(max_workers=12) as pool:
                futures=[pool.submit(check_candidate,c) for c in priority]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception: pass

        if not result["direct_proof"] and discovered:
            # Seulement les liens légaux réellement découverts sur l'accueil / pages déjà lues.
            candidates=list(dict.fromkeys(discovered))[:20]
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures=[pool.submit(check_candidate,c) for c in candidates]
                for future in as_completed(futures):
                    try: future.result()
                    except Exception: pass

        corpus=normalize_text(" ".join(combined))
        domain_tokens=name_tokens(base_org.split('.')[0])
        company_tokens=name_tokens(company_name)
        overlap=company_tokens & domain_tokens
        if overlap:
            result["score"]=max(result["score"],min(75,40+10*len(overlap)))
            result["evidence"].append("Le nom de domaine partage des éléments significatifs avec la raison sociale.")
        if company_tokens:
            page_overlap={t for t in company_tokens if t in corpus}
            if page_overlap:
                result["score"]=max(result["score"],min(85,45+8*len(page_overlap)))
                result["evidence"].append("La raison sociale apparaît ou est cohérente avec le contenu du site.")
        if result["direct_proof"]:
            result["status"]="VERIFIED"; result["label"]="Vérifié"
        elif result["score"]>=50:
            result["status"]="PROBABLE"; result["label"]="Probable — justificatif requis"
        else:
            result["status"]="UNCONFIRMED"; result["label"]="Non établi — justificatif requis"
        return result
    except Exception as exc:
        result["error"]=str(exc); result["status"]="UNKNOWN"; result["label"]="Contrôle complémentaire requis"; return result

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


BOT_PROTECTION_MARKERS = (
    "cf-chl", "cloudflare", "just a moment", "checking your browser",
    "verify you are human", "verify you are a human", "captcha",
    "recaptcha", "hcaptcha", "access denied", "automated access",
    "bot detection", "bot protection", "enable javascript and cookies",
    "checking if the site connection is secure", "perimeterx", "datadome",
    "incapsula", "akamai bot", "security check"
)

def _looks_like_bot_protection(status_code, headers, body):
    text = normalize_text(body)[:300_000]
    server = normalize_text(headers.get("Server", ""))
    powered = normalize_text(headers.get("X-Powered-By", ""))
    combined = " ".join((text, server, powered))
    if status_code in (403, 429):
        return True
    return any(marker in combined for marker in BOT_PROTECTION_MARKERS)


def http_probe(url):
    result = {
        "reachable": False,
        "status_code": None,
        "https": True,
        "final_url": None,
        "security_headers": {},
        "server": None,
        "error": None,
        "automated_access_blocked": False,
        "technical_measurement": "UNKNOWN",
    }
    try:
        with open_safe(url,"GET") as response:
            raw = response.read(MAX_PAGE_BYTES)
            result["reachable"] = True
            result["status_code"] = response.status
            result["final_url"] = response.geturl()
            result["server"] = response.headers.get("Server")
            if _looks_like_bot_protection(response.status, response.headers, raw.decode("utf-8", errors="ignore")):
                result["automated_access_blocked"] = True
                result["technical_measurement"] = "BLOCKED"
                return result
            for header in SECURITY_HEADERS:
                value = response.headers.get(header)
                if value:
                    result["security_headers"][header.lower()] = value
            result["technical_measurement"] = "MEASURED"
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(MAX_PAGE_BYTES)
        except Exception:
            pass
        result["status_code"] = exc.code
        result["server"] = exc.headers.get("Server") if exc.headers else None
        result["error"] = str(exc)
        if _looks_like_bot_protection(exc.code, exc.headers or {}, body.decode("utf-8", errors="ignore")):
            result["automated_access_blocked"] = True
            result["technical_measurement"] = "BLOCKED"
        else:
            result["technical_measurement"] = "ERROR"
    except Exception as exc:
        result["error"] = str(exc)
        result["technical_measurement"] = "ERROR"
    return result


def tls_probe(hostname):
    result = {
        "valid": False,
        "subject": None,
        "issuer": None,
        "tls_version": None,
        "error": None,
    }
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

# --- Barème / décision ---

def calculate_score(company, legal, domain_link, dns, http, tls):
    score = 100
    reasons = []
    blockers = []
    complementary = []
    technical_complementary = []

    if not company.get("found"):
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

    # Un signal non mesurable ne doit jamais être traité comme une non-conformité.
    if not dns.get("ipv4"):
        score -= 20
        reasons.append("DNS / IPv4 non résolu")

    access_blocked = bool(http.get("automated_access_blocked"))
    http_measured = http.get("technical_measurement") == "MEASURED"

    if not http.get("reachable") and not access_blocked:
        score -= 25
        reasons.append("Site non accessible")

    if not tls.get("valid"):
        score -= 20
        reasons.append("Certificat TLS non validé")

    if http_measured:
        for header, penalty, reason in [
            ("strict-transport-security", 8, "HSTS absent"),
            ("content-security-policy", 8, "CSP absente"),
            ("x-content-type-options", 4, "X-Content-Type-Options absent"),
            ("x-frame-options", 4, "X-Frame-Options absent"),
        ]:
            if header not in http.get("security_headers", {}):
                score -= penalty
                reasons.append(reason)
    elif access_blocked:
        technical_complementary.append("L'accès automatisé au site est protégé ; les en-têtes HTTP n'ont pas pu être mesurés depuis notre point de contrôle.")
    else:
        technical_complementary.append("Les contrôles HTTP n'ont pas pu être mesurés.")

    technical_score_available = not access_blocked
    score = max(0, min(100, score)) if technical_score_available else None
    technical_issue_count = len(reasons)
    technical_unknown_count = 1 if access_blocked else 0

    # Les blocages juridiques priment. Une mesure technique incomplète ne doit
    # jamais être transformée en score artificiel : elle déclenche un contrôle
    # complémentaire sans être assimilée à une défaillance du site.
    if blockers:
        decision = "NON_ELIGIBLE"
        decision_label = "NON ÉLIGIBLE"
    elif not technical_score_available:
        decision = "CONTROLE_COMPLEMENTAIRE"
        decision_label = "CONTRÔLE COMPLÉMENTAIRE"
    elif score < 60:
        decision = "CONTROLE_COMPLEMENTAIRE"
        decision_label = "CONTRÔLE COMPLÉMENTAIRE"
    elif score < 80:
        decision = "SURVEILLANCE_RENFORCEE"
        decision_label = "SURVEILLANCE RENFORCÉE"
    elif complementary:
        decision = "ELIGIBLE_SOUS_RESERVE"
        decision_label = "ÉLIGIBLE SOUS RÉSERVE"
    else:
        decision = "ELIGIBLE"
        decision_label = "ÉLIGIBLE"

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
        "technical_complementary": technical_complementary,
        "reasons": reasons,
        "technical_issue_count": technical_issue_count,
        "technical_unknown_count": technical_unknown_count,
        "automated_access_blocked": access_blocked,
        "technical_measurement": "PARTIAL" if access_blocked else ("MEASURED" if http_measured else "LIMITED"),
        "technical_score_available": technical_score_available,
        "version_bareme": "3.12",
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
            self.send_json({"status": "ok", "version": "3.12"})
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
            # L'interface préremplit https://www.; accepter aussi un simple domaine
            # si l'utilisateur remplace entièrement le contenu du champ.
            if site and not re.match(r"^https?://", site, re.I):
                site = "https://www." + site.lstrip("/")
            if not re.fullmatch(r"\d{9}", siren):
                self.send_json({"detail": "SIREN invalide : 9 chiffres attendus."}, 400)
                return
            parsed = validate_site_url(site)
            hostname = parsed.hostname

            # Les contrôles indépendants sont exécutés en parallèle afin de réduire
            # fortement le temps d'attente sans supprimer de contrôles.
            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = {
                    "company": pool.submit(identity, siren),
                    "legal": pool.submit(legal_status, siren),
                    "dns": pool.submit(dns_probe, hostname),
                    "http": pool.submit(http_probe, site),
                    "tls": pool.submit(tls_probe, hostname),
                }
                results = {name: future.result() for name, future in futures.items()}

            company = results["company"]
            legal = results["legal"]
            dns = results["dns"]
            http = results["http"]
            tls = results["tls"]
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
    print(f"BifProtect Testeur V3.12 — écoute sur {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

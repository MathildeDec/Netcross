"""
netcross_report.security_report -- rapport de securite consolide et
tableau de bord (CVE-5, issue #139, parent #133).

Regroupe les constats produits par les modules de detection passive de
vulnerabilites (CVE-1 fingerprinting de versions, CVE-2 signatures
d'exploits, CVE-3 alertes Expert Info, CVE-4 correlation CVE) en un seul
rapport : services detectes classes par criticite, exploits, anomalies,
CVE confirmees, plus une synthese chiffree.

Ce module ne DETECTE rien : il lit `Report.service_fingerprints` et
`Report.security_findings` (voir `netcross_core.models.Report` pour le
format des dicts), les regroupe, les classe par severite et les met en
forme. Un `Report` sans constat amont donne donc un rapport vide -- la
garantie "aucun faux positif sur trafic normal" repose sur les
detecteurs amont, celle de ce module est de ne jamais en ajouter :

- un service n'est marque vulnerable que si un constat CVE le designe
  explicitement (meme service ET meme version, et meme hote/port quand le
  constat les precise) -- jamais par simple ressemblance de nom ;
- aucune severite n'est inventee : elle vient du constat, sinon du score
  CVSS quand il existe, sinon "faible" (valeur la plus basse, un constat
  mal renseigne reste visible sans peser dans le score).

Rendu texte uniquement pour l'instant (`format_security_report` /
`print_security_report`, meme separation que `netcross_report.
session_objects`) ; une sortie HTML/PDF consommera le meme
`SecurityReport`.
"""

from __future__ import annotations

from dataclasses import dataclass, field


from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
# Du plus grave au moins grave : l'indice sert de rang de tri.
SEVERITIES: tuple[str, ...] = ("critique", "elevee", "moyenne", "faible")

# Poids d'un constat dans le score de risque global (0-100, plafonne).
SEVERITY_WEIGHTS: dict[str, int] = {"critique": 40, "elevee": 20, "moyenne": 8, "faible": 2}

CATEGORY_EXPLOIT = "exploit"
CATEGORY_ANOMALY = "anomalie"
CATEGORY_CVE = "cve"

# Plafond d'affichage par section du rendu texte (meme esprit que les
# "... N supplementaires" de netcross_core.report_text).
MAX_ROWS_PER_SECTION = 50

_SEVERITY_ALIASES = {
    "critique": "critique",
    "critical": "critique",
    "elevee": "elevee",
    "elevée": "elevee",
    "élevee": "elevee",
    "élevée": "elevee",
    "haute": "elevee",
    "high": "elevee",
    "moyenne": "moyenne",
    "medium": "moyenne",
    "faible": "faible",
    "low": "faible",
}

_CATEGORY_ALIASES = {
    "exploit": CATEGORY_EXPLOIT,
    "exploits": CATEGORY_EXPLOIT,
    "anomalie": CATEGORY_ANOMALY,
    "anomalies": CATEGORY_ANOMALY,
    "anomaly": CATEGORY_ANOMALY,
    "cve": CATEGORY_CVE,
    "cves": CATEGORY_CVE,
}


@dataclass(slots=True)
class SecurityItem:
    """Un constat de securite normalise (exploit, anomalie ou CVE)."""

    category: str
    severity: str
    detail: str
    cve_id: str | None = None
    cvss: float | None = None
    service: str | None = None
    version: str | None = None
    host: str | None = None
    port: int | None = None
    point: str | None = None


@dataclass(slots=True)
class ServiceEntry:
    """Un service detecte, avec sa criticite (None si aucune CVE connue)."""

    service: str
    version: str | None = None
    host: str | None = None
    port: int | None = None
    points: list[str] = field(default_factory=list)
    severity: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    # Issue #259 : le hash JA4/HASSH et sa forme lisible etaient produits
    # par fingerprint.report.build_fingerprint_records puis silencieusement
    # jetes ici -- ServiceEntry n'avait aucun champ pour les porter, et
    # _build_services ne lisait que service/version/host/port/point. La
    # fonctionnalite entiere (issue #143) etait donc invisible de bout en
    # bout malgre 26 tests unitaires verts : ils testaient le calcul, jamais
    # le rendu.
    fingerprint: str | None = None
    fingerprint_readable: str | None = None

    @property
    def vulnerable(self) -> bool:
        return self.severity is not None


@dataclass(slots=True)
class SecurityDashboard:
    """Synthese chiffree du rapport.

    `score` : score de risque 0-100 (somme des poids `SEVERITY_WEIGHTS`
    de tous les constats, plafonnee a 100) ; 0 = rien de detecte.
    `level` : severite du pire constat, None s'il n'y en a aucun."""

    services_total: int = 0
    services_vulnerable: int = 0
    exploits: int = 0
    anomalies: int = 0
    cves: int = 0
    by_severity: dict[str, int] = field(default_factory=lambda: dict.fromkeys(SEVERITIES, 0))
    score: int = 0
    level: str | None = None


@dataclass(slots=True)
class SecurityReport:
    services: list[ServiceEntry] = field(default_factory=list)
    exploits: list[SecurityItem] = field(default_factory=list)
    anomalies: list[SecurityItem] = field(default_factory=list)
    cves: list[SecurityItem] = field(default_factory=list)
    dashboard: SecurityDashboard = field(default_factory=SecurityDashboard)


# -- normalisation -------------------------------------------------------


def _opt_str(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _opt_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.debug("exception TypeError/ValueError gérée silencieusement")
        return None


def _opt_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        logger.debug("exception TypeError/ValueError gérée silencieusement")
        return None


def severity_from_cvss(cvss: float) -> str:
    """Tranches CVSS v3 de la NVD : >=9.0 critique, >=7.0 elevee, >=4.0
    moyenne, sinon faible (0.0 = 'none' inclus)."""
    if cvss >= 9.0:
        return "critique"
    if cvss >= 7.0:
        return "elevee"
    if cvss >= 4.0:
        return "moyenne"
    return "faible"


def _normalise_severity(raw, cvss: float | None) -> str:
    key = _opt_str(raw)
    if key is not None and key.lower() in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key.lower()]
    if cvss is not None:
        return severity_from_cvss(cvss)
    return "faible"


def _to_item(raw) -> SecurityItem | None:
    """Dict amont -> SecurityItem ; None pour une entree inexploitable
    (pas un dict) plutot que de faire echouer tout le rapport."""
    if not isinstance(raw, dict):
        return None
    cvss = _opt_float(raw.get("cvss"))
    category = _CATEGORY_ALIASES.get((_opt_str(raw.get("category")) or "").lower(), CATEGORY_ANOMALY)
    return SecurityItem(
        category=category,
        severity=_normalise_severity(raw.get("severity"), cvss),
        detail=_opt_str(raw.get("detail")) or "",
        cve_id=_opt_str(raw.get("cve_id")),
        cvss=cvss,
        service=_opt_str(raw.get("service")),
        version=_opt_str(raw.get("version")),
        host=_opt_str(raw.get("host")),
        port=_opt_int(raw.get("port")),
        point=_opt_str(raw.get("point")),
    )


def _item_sort_key(item: SecurityItem):
    return (SEVERITIES.index(item.severity), -(item.cvss or 0.0), item.cve_id or "", item.detail)


def _cve_matches_service(cve: SecurityItem, entry: ServiceEntry) -> bool:
    """Une CVE designe un service detecte ssi meme nom (insensible a la
    casse) ET meme version ; hote/port ne comptent que si la CVE les
    precise. Un constat sans nom de service ou sans version identique ne
    rattache jamais rien (pas de correspondance approximative)."""
    if cve.service is None or cve.service.lower() != entry.service.lower():
        return False
    if cve.version != entry.version:
        return False
    if cve.host is not None and cve.host != entry.host:
        return False
    return not (cve.port is not None and cve.port != entry.port)


def _build_services(fingerprints, cves: list[SecurityItem]) -> list[ServiceEntry]:
    merged: dict[tuple, ServiceEntry] = {}
    for raw in fingerprints or []:
        if not isinstance(raw, dict):
            continue
        service = _opt_str(raw.get("service"))
        if service is None:
            continue
        version = _opt_str(raw.get("version"))
        host = _opt_str(raw.get("host"))
        port = _opt_int(raw.get("port"))
        fingerprint = _opt_str(raw.get("fingerprint"))
        readable = _opt_str(raw.get("banner"))
        # L'empreinte fait partie de l'identite de l'entree : deux JA4
        # differents vus sur le meme hote sont deux clients differents, les
        # fusionner effacerait l'information la plus utile de la section.
        key = (host, port, service.lower(), version, fingerprint)
        entry = merged.get(key)
        if entry is None:
            entry = merged[key] = ServiceEntry(
                service=service,
                version=version,
                host=host,
                port=port,
                fingerprint=fingerprint,
                fingerprint_readable=readable,
            )
        point = _opt_str(raw.get("point"))
        if point is not None and point not in entry.points:
            entry.points.append(point)

    for entry in merged.values():
        matching = [c for c in cves if _cve_matches_service(c, entry)]
        if matching:
            entry.severity = min((c.severity for c in matching), key=SEVERITIES.index)
            entry.cve_ids = sorted({c.cve_id for c in matching if c.cve_id})
        entry.points.sort()

    def _rank(e: ServiceEntry):
        sev = SEVERITIES.index(e.severity) if e.severity else len(SEVERITIES)
        return (
            sev,
            -len(e.cve_ids),
            e.service.lower(),
            e.version or "",
            e.host or "",
            e.port or 0,
            e.fingerprint or "",
        )

    return sorted(merged.values(), key=_rank)


# -- construction --------------------------------------------------------


def build_security_report(report) -> SecurityReport:
    """Consolide `report.service_fingerprints` et `report.security_findings`
    en un `SecurityReport` (sections triees par severite decroissante, puis
    CVSS decroissant) et calcule le tableau de bord."""
    items = [i for i in (_to_item(raw) for raw in (report.security_findings or [])) if i is not None]
    exploits = sorted((i for i in items if i.category == CATEGORY_EXPLOIT), key=_item_sort_key)
    anomalies = sorted((i for i in items if i.category == CATEGORY_ANOMALY), key=_item_sort_key)
    cves = sorted((i for i in items if i.category == CATEGORY_CVE), key=_item_sort_key)
    services = _build_services(report.service_fingerprints, cves)

    dash = SecurityDashboard(
        services_total=len(services),
        services_vulnerable=sum(1 for s in services if s.vulnerable),
        exploits=len(exploits),
        anomalies=len(anomalies),
        cves=len(cves),
    )
    for item in items:
        dash.by_severity[item.severity] += 1
    dash.score = min(100, sum(SEVERITY_WEIGHTS[sev] * n for sev, n in dash.by_severity.items()))
    dash.level = next((sev for sev in SEVERITIES if dash.by_severity[sev]), None)
    return SecurityReport(services=services, exploits=exploits, anomalies=anomalies, cves=cves, dashboard=dash)


# -- rendu texte -----------------------------------------------------------


def _target(host: str | None, port: int | None) -> str:
    if host is None:
        return ""
    return f"{host}:{port}" if port is not None else host


def _service_label(service: str | None, version: str | None) -> str:
    if service is None:
        return ""
    return f"{service}/{version}" if version else service


def _format_item(item: SecurityItem) -> str:
    parts = [f"[{item.severity}]"]
    if item.cve_id:
        parts.append(item.cve_id + (f" (CVSS {item.cvss:.1f})" if item.cvss is not None else ""))
    label = _service_label(item.service, item.version)
    if label:
        parts.append(label)
    target = _target(item.host, item.port)
    if target:
        parts.append(f"@ {target}")
    line = " ".join(parts)
    if item.detail:
        line += f" -- {item.detail}"
    if item.point:
        line += f" (point {item.point})"
    return "  " + line


# Prefixe d'affichage du hash, par type de service d'empreinte. L'issue
# #143 demandait explicitement la forme "JA4=xy123" / "HASSH=xy123" ; la
# deduire du champ `service` evite de trainer un champ de plus dans le
# dict produit par fingerprint.report.
_FINGERPRINT_PREFIXES = {"tls/ja4": "JA4", "ssh/hassh": "HASSH"}

# La forme lisible (liste complete des ciphers/extensions ou des
# algorithmes negocies) fait plusieurs centaines de caracteres. Elle est
# tronquee a l'affichage : le hash suffit a comparer deux empreintes, la
# chaine sert a comprendre CE QUI a ete propose, et un rapport texte reste
# lisible. La valeur complete demeure dans le champ du dataclass pour les
# consommateurs programmatiques (JSON, API).
MAX_READABLE_LEN = 120


def _format_fingerprint(entry: ServiceEntry) -> str:
    """Rend la partie empreinte d'une ligne de service, ou "" si l'entree
    n'en porte pas (cas des services detectes par banniere, CVE-1)."""
    if not entry.fingerprint:
        return ""
    prefixe = _FINGERPRINT_PREFIXES.get(entry.service.lower(), "empreinte")
    rendu = f" {prefixe}={entry.fingerprint}"
    lisible = entry.fingerprint_readable
    if lisible:
        if len(lisible) > MAX_READABLE_LEN:
            lisible = lisible[: MAX_READABLE_LEN - 3] + "..."
        rendu += f" [{lisible}]"
    return rendu


def _format_service(entry: ServiceEntry) -> str:
    tag = f"[{entry.severity}]" if entry.severity else "[ok]"
    label = _service_label(entry.service, entry.version)
    target = _target(entry.host, entry.port)
    line = f"  {tag} {label}" + (f" @ {target}" if target else "")
    line += _format_fingerprint(entry)
    if entry.cve_ids:
        line += " -- " + ", ".join(entry.cve_ids)
    elif entry.vulnerable:
        line += " -- CVE non identifiee"
    else:
        line += " -- aucune vulnerabilite connue"
    if entry.points:
        line += f" (point(s) {', '.join(entry.points)})"
    return line


def _section(title: str, rows: list[str], empty_msg: str) -> list[str]:
    lines = ["", f"-- {title} --"]
    if not rows:
        lines.append(f"  {empty_msg}")
        return lines
    lines.extend(rows[:MAX_ROWS_PER_SECTION])
    if len(rows) > MAX_ROWS_PER_SECTION:
        lines.append(f"  ... {len(rows) - MAX_ROWS_PER_SECTION} ligne(s) supplementaire(s) non affichee(s)")
    return lines


def _bar(score: int, width: int = 20) -> str:
    filled = round(width * score / 100)
    return "#" * filled + "-" * (width - filled)


def format_security_report(sr: SecurityReport) -> list[str]:
    """Rendu texte du rapport, une chaine par ligne (jamais de `print()`
    ici, meme separation que `netcross_report.session_objects`)."""
    d = sr.dashboard
    lines = ["=" * 70, "RAPPORT DE SECURITE (detection passive de vulnerabilites)", "=" * 70]

    lines += ["", "-- Tableau de bord securite --"]
    level = d.level or "aucun constat"
    lines.append(f"  score de risque global : {d.score}/100 [{_bar(d.score)}] (niveau : {level})")
    lines.append(f"  services detectes : {d.services_total} (dont {d.services_vulnerable} vulnerable(s))")
    lines.append(f"  exploits detectes : {d.exploits}")
    lines.append(f"  anomalies (Expert Info) : {d.anomalies}")
    lines.append(f"  CVE confirmees : {d.cves}")
    lines.append("  repartition par severite : " + ", ".join(f"{sev}={d.by_severity[sev]}" for sev in SEVERITIES))

    lines += _section(
        "Services detectes (classes par criticite)",
        [_format_service(s) for s in sr.services],
        "aucun service identifie",
    )
    lines += _section(
        "Tentatives d'exploitation detectees",
        [_format_item(i) for i in sr.exploits],
        "aucune tentative d'exploitation detectee",
    )
    lines += _section(
        "Anomalies (alertes Expert Info correlees)",
        [_format_item(i) for i in sr.anomalies],
        "aucune anomalie correlee",
    )
    lines += _section(
        "CVE confirmees (version + CVE-ID + score CVSS)",
        [_format_item(i) for i in sr.cves],
        "aucune CVE confirmee",
    )
    return lines


def print_security_report(sr: SecurityReport) -> None:
    """Ecrit `format_security_report()` sur stdout."""
    for line in format_security_report(sr):
        print(line)


# -- serialisation (socle commun aux sorties JSON, HTML et PDF) -------------


def security_report_to_dict(sr: SecurityReport) -> dict:
    """Represente le rapport en structures Python serialisables.

    Socle unique des trois sorties non textuelles (JSON, HTML, PDF) : sans
    lui, chacune re-parcourrait les dataclasses a sa facon et divergerait
    au premier champ ajoute -- exactement ce qui a produit l'issue #259
    (un champ present dans les donnees, absent d'un rendu).

    Les champs valant None sont CONSERVES plutot que retires. Un
    consommateur doit pouvoir distinguer « non renseigne » de « cle que
    cette version de netcross ne produit pas » ; et la regle de tracabilite
    du projet veut qu'une information absente soit dite, pas passee sous
    silence.
    """
    return {
        "dashboard": {
            "score": sr.dashboard.score,
            "level": sr.dashboard.level,
            "services_total": sr.dashboard.services_total,
            "services_vulnerable": sr.dashboard.services_vulnerable,
            "exploits": sr.dashboard.exploits,
            "anomalies": sr.dashboard.anomalies,
            "cves": sr.dashboard.cves,
            "by_severity": dict(sr.dashboard.by_severity),
        },
        "services": [
            {
                "service": s.service,
                "version": s.version,
                "host": s.host,
                "port": s.port,
                "points": list(s.points),
                "severity": s.severity,
                "vulnerable": s.vulnerable,
                "cve_ids": list(s.cve_ids),
                # Forme lisible NON tronquee, contrairement au rendu texte :
                # une sortie machine n'a pas de contrainte de largeur, et
                # tronquer ici priverait un consommateur de la liste
                # complete des ciphers (issue #259).
                "fingerprint": s.fingerprint,
                "fingerprint_readable": s.fingerprint_readable,
            }
            for s in sr.services
        ],
        **{
            cle: [
                {
                    "category": i.category,
                    "severity": i.severity,
                    "detail": i.detail,
                    "cve_id": i.cve_id,
                    "cvss": i.cvss,
                    "service": i.service,
                    "version": i.version,
                    "host": i.host,
                    "port": i.port,
                    "point": i.point,
                }
                for i in items
            ]
            for cle, items in (("exploits", sr.exploits), ("anomalies", sr.anomalies), ("cves", sr.cves))
        },
    }

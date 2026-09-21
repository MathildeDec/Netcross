"""
netcross_core.security.findings -- alimentation de
`Report.service_fingerprints` et `Report.security_findings` a partir des
modules de detection CVE-1 a CVE-4 (issue #139, CVE-5, parent #133).

`netcross_report.security_report` (rendu du rapport de securite) ne
detecte rien : il lit deux listes de dicts a plat sur `Report`. Ce module
est le maillon qui les remplit, en traduisant les sorties des quatre
detecteurs dans le format de constat documente sur `Report` :

- CVE-1 (#135) `application.banners.build_service_fingerprints` ->
  `Report.service_fingerprints` (services et versions vus sur le fil) ;
- CVE-2 (#136) `exploit_signatures.Detection` -> constats `exploit` ;
- CVE-3 (#137) `Report.exploit_suspicion_flows` -> constats `anomalie`
  (fuzzing / overflow / dos) ;
- CVE-4 (#138) `security.correlate_banner` -> constats `cve`, un par CVE
  applicable a la version EXACTE d'un service detecte ;
- FLOW-3 (#144) `dns_tunnel.detect_dns_tunneling` -> constats `anomalie`
  (tunneling DNS : suspicion par domaine, ou volume DNS anormal) ;
- SCENARIO-1 (#147) `beaconing.detect_beaconing` -> constats `anomalie`
  (beaconing C2 : communications periodiques vers une destination externe).

Trois principes, pour respecter le critere d'acceptation « aucun faux
positif sur trafic normal » :

- ce module n'invente aucun signal : sans detection, sans suspicion et
  sans CVE applicable, `security_findings` reste vide ;
- une CVE n'est rattachee qu'au service dont la banniere `service/version`
  l'a produite (jamais a une banniere composite qui melangerait plusieurs
  produits) ;
- la severite est deduite d'une correspondance explicite (tables
  ci-dessous), jamais d'un mot du texte ; ces tables sont volontairement
  prudentes : une signature d'exploit est une TENTATIVE (pas une
  compromission confirmee), une suspicion Expert Info est un INDICE a
  confirmer (voir `expert_correlation`).

Contrat de couches : netcross_core uniquement (+ pcap_parser pour relire
les charges utiles brutes, comme `tls_diagnostics`). Le rendu vit dans
`netcross_report.security_report`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

import pcap_parser
from netcross_core.application.banners import build_service_fingerprints
from netcross_core.exploit_signatures import Detection, Signature, detect_exploits
from netcross_core.models import Pkt, Report
from netcross_core.security import correlate_banner
from netcross_core.security.beaconing import detect_beaconing
from netcross_core.security.dns_tunnel import detect_dns_tunneling

# Severite d'une signature d'exploit (vocabulaire de exploit_signatures :
# anomalie / a_surveiller / info) -> severite du rapport de securite. Une
# detection est une tentative observee, pas une compromission confirmee :
# « critique » reste reserve aux CVE a fort score CVSS confirmees sur une
# version exacte (voir netcross_report.security_report.severity_from_cvss).
EXPLOIT_SEVERITY: dict[str, str] = {"anomalie": "elevee", "a_surveiller": "moyenne", "info": "faible"}

# Severite d'une suspicion Expert Info (fuzzing/overflow/dos, voir
# security.expert_correlation) : toutes « moyenne » -- un indice qui peut
# aussi venir d'un equipement bogue ou d'une capture tronquee.
SUSPICION_SEVERITY: dict[str, str] = {"fuzzing": "moyenne", "overflow": "moyenne", "dos": "moyenne"}

# Longueur maximale de la description NVD reprise dans le detail d'une CVE.
MAX_CVE_DETAIL_CHARS = 160


def _ellipsis(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


# -- CVE-2 : signatures d'exploits ---------------------------------------


def scan_capture_exploits(label: str, path: str, signatures: Sequence[Signature] | None = None) -> list[Detection]:
    """Relit une capture via pcap_parser (charge utile brute, que `Pkt` ne
    garde pas) et applique les signatures d'exploits (base par defaut si
    `signatures` est None). Comme `tls_diagnostics.parse_tls_capture`,
    n'echoue pas sur une capture illisible : liste vide (le message
    d'erreur est deja emis par pcap_parser)."""
    raw_packets = pcap_parser.parse_capture(path, raise_on_error=False)
    return detect_exploits(raw_packets, signatures, point=label)


def exploit_findings(detections: Iterable[Detection]) -> list[dict[str, Any]]:
    """Un constat `exploit` par (signature, point, source, destination,
    port destination) : une rafale de requetes identiques ne noie pas le
    rapport, elle est resumee par son nombre d'occurrences. L'hote/port du
    constat sont ceux de la CIBLE (destination), l'extrait de preuve est
    celui de la premiere occurrence."""
    grouped: dict[tuple, dict[str, Any]] = {}
    for d in detections:
        key = (d.signature_id, d.point, d.src, d.dst, d.dport)
        entry = grouped.get(key)
        if entry is None:
            cves = ", ".join(d.cves)
            detail = f"{d.name} ({d.signature_id}) depuis {d.src}"
            if cves:
                detail += f" -- {cves}"
            if d.frame_number is not None:
                detail += f" -- trame {d.frame_number}"
            grouped[key] = {
                "severity": EXPLOIT_SEVERITY.get(d.severity, "faible"),
                "category": "exploit",
                "detail": detail,
                "host": d.dst,
                "port": d.dport,
                "point": d.point or None,
                "_count": 1,
            }
        else:
            entry["_count"] += 1
    findings = []
    for entry in grouped.values():
        count = entry.pop("_count")
        if count > 1:
            entry["detail"] += f" -- {count} occurrences"
        findings.append(entry)
    return findings


# -- CVE-3 : suspicions issues des alertes Expert Info ---------------------


def anomaly_findings(suspicions: Iterable[dict]) -> list[dict[str, Any]]:
    """Un constat `anomalie` par suspicion de `Report.exploit_suspicion_flows`
    (fuzzing / overflow / dos). Les paquets malformes isoles
    (`Report.expert_malformed*`) ne sont volontairement PAS remontes ici :
    seuls les motifs correles constituent un indice d'attaque."""
    findings = []
    for s in suspicions:
        kind = str(s.get("kind", ""))
        protocols = ", ".join(f"{p}={n}" for p, n in (s.get("protocols") or {}).items())
        frames = ", ".join(str(f) for f in (s.get("frames") or []))
        detail = f"suspicion de {kind} sur {s.get('flow', '?')} : {s.get('count', 0)} paquet(s) en cause"
        if protocols:
            detail += f" ({protocols})"
        if frames:
            detail += f" -- trames {frames}"
        findings.append(
            {
                "severity": SUSPICION_SEVERITY.get(kind, "faible"),
                "category": "anomalie",
                "detail": detail,
                "point": s.get("point") or None,
            }
        )
    return findings


# -- FLOW-3 : tunneling DNS ------------------------------------------------

_DNS_SIGNAL_LABELS = {
    "long_label": "label > 63 caracteres",
    "long_name": "noms > 100 caracteres",
    "high_entropy": "sous-domaines a haute entropie",
    "large_response": "reponses volumineuses",
    "dominant_domain": "domaine dominant",
    "regular_timing": "requetes a intervalles reguliers",
}


def dns_tunnel_findings(suspicions: Iterable[dict]) -> list[dict[str, Any]]:
    """Un constat `anomalie` par suspicion de `dns_tunnel.detect_dns_tunneling`.
    La severite est celle calculee par `security.dns_tunnel` (moyenne, elevee
    si des signaux corroborants s'ajoutent, faible pour le seul volume) : une
    suspicion reste un INDICE a confirmer, jamais une compromission averee."""
    findings = []
    for s in suspicions:
        if s.get("kind") == "volume":
            detail = (
                f"volume DNS anormal : {s.get('dns_packets', 0)} paquets DNS sur "
                f"{s.get('total_packets', 0)} ({float(s.get('ratio', 0.0)) * 100:.0f} % du trafic du point)"
            )
        else:
            signals = ", ".join(_DNS_SIGNAL_LABELS.get(sig, sig) for sig in s.get("signals") or [])
            detail = (
                f"suspicion de tunneling DNS vers {s.get('domain', '?')} : {signals} "
                f"-- {s.get('queries', 0)} requete(s), {s.get('unique_subdomains', 0)} sous-domaine(s) distinct(s), "
                f"entropie moyenne {s.get('mean_entropy', 0.0)} bits/car"
            )
            frames = ", ".join(str(f) for f in s.get("frames") or [])
            if frames:
                detail += f" -- trames {frames}"
        findings.append(
            {
                "severity": s.get("severity") or "faible",
                "category": "anomalie",
                "detail": detail,
                "point": s.get("point") or None,
            }
        )
    return findings


# -- SCENARIO-1 : beaconing C2 ---------------------------------------------

_BEACON_SIGNAL_LABELS = {
    "periodic": "intervalles reguliers",
    "small_payload": "petites requetes",
    "stable_size": "volume constant",
    "asymmetric_ratio": "plus d'octets recus qu'envoyes",
    "off_hours": "activite hors heures de bureau",
}


def beaconing_findings(suspicions: Iterable[dict]) -> list[dict[str, Any]]:
    """Un constat `anomalie` par suspicion de `beaconing.detect_beaconing`.
    La severite est celle calculee par `security.beaconing` (moyenne, elevee
    si un signal faible corrobore) : une periodicite reste un INDICE a
    confirmer (un heartbeat legitime est aussi regulier), jamais une
    compromission averee."""
    findings = []
    for s in suspicions:
        signals = ", ".join(_BEACON_SIGNAL_LABELS.get(sig, sig) for sig in s.get("signals") or [])
        detail = (
            f"suspicion de beaconing C2 de {s.get('src', '?')} vers {s.get('dst', '?')}:{s.get('dport', '?')}"
            f"/{s.get('proto', '?')} : {signals} "
            f"-- {s.get('checkins', 0)} check-in(s), intervalle moyen {s.get('mean_interval', 0.0)} s "
            f"(ecart-type {s.get('interval_stddev', 0.0)} s), score de confiance {s.get('score', 0.0)}"
        )
        frames = ", ".join(str(f) for f in s.get("frames") or [])
        if frames:
            detail += f" -- trames {frames}"
        findings.append(
            {
                "severity": s.get("severity") or "faible",
                "category": "anomalie",
                "detail": detail,
                "point": s.get("point") or None,
            }
        )
    return findings


# -- CVE-4 : correlation version -> CVE -------------------------------------


def cve_findings(fingerprints: Iterable[dict], conn) -> list[dict[str, Any]]:
    """Un constat `cve` par (CVE, service, version, hote, port) applicable
    a un service detecte. La banniere soumise a la base est reconstruite
    depuis `service` + `version` du fingerprint (jamais le texte source
    complet, qui peut citer plusieurs produits) : le constat porte donc
    toujours le service et la version qui l'ont produit, ce qui permet a
    `security_report` de le rattacher a la bonne ligne de service. Un
    service sans version connue n'est pas correle."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for fp in fingerprints:
        service, version = fp.get("service"), fp.get("version")
        if not service or not version:
            continue
        for match in correlate_banner(conn, f"{service}/{version}"):
            key = (match.cve_id, service.lower(), version, fp.get("host"), fp.get("port"))
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "severity": match.cvss_severity,
                    "category": "cve",
                    "cve_id": match.cve_id,
                    "cvss": match.cvss_score,
                    "detail": _ellipsis(match.description, MAX_CVE_DETAIL_CHARS),
                    "service": service,
                    "version": version,
                    "host": fp.get("host"),
                    "port": fp.get("port"),
                    "point": fp.get("point"),
                }
            )
    return findings


# -- assemblage -----------------------------------------------------------


def apply_security_findings(
    report: Report,
    all_packets: Iterable[Pkt],
    *,
    detections: Iterable[Detection] = (),
    cve_conn=None,
) -> None:
    """Remplit `report.service_fingerprints` et `report.security_findings`
    (remplacement, pas ajout : deux appels donnent le meme resultat).

    `detections` : sorties de `scan_capture_exploits` (CVE-2), a fournir
    par l'appelant car elles exigent la charge utile brute. `cve_conn` :
    connexion a la base CVE locale (CVE-4) ; None = pas de correlation CVE
    (les services restent listes, sans criticite). Les suspicions Expert
    Info (CVE-3) sont lues sur `report.exploit_suspicion_flows`, deja
    calcule par `analyse()` ; le tunneling DNS (FLOW-3) et le beaconing C2
    (SCENARIO-1) sont calcules ici depuis `all_packets`."""
    packets = list(all_packets)  # parcouru par plusieurs detecteurs
    report.service_fingerprints = build_service_fingerprints(packets)
    findings = (
        exploit_findings(detections)
        + anomaly_findings(report.exploit_suspicion_flows)
        + dns_tunnel_findings(detect_dns_tunneling(packets).suspicions)
        + beaconing_findings(detect_beaconing(packets).suspicions)
    )
    if cve_conn is not None:
        findings += cve_findings(report.service_fingerprints, cve_conn)
    report.security_findings = findings

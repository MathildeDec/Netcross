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
- SCENARIO-7 (#153) `tls_audit.audit_tls_certificates` -> constats `anomalie`
  (certificat expire, auto-signe, algorithme faible, noms suspects...), un par
  probleme et par certificat distinct, avec le score de risque TLS du serveur.

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
from netcross_core.fingerprint.report import build_fingerprint_records
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt, Report
from netcross_core.security import correlate_banner
from netcross_core.security.beaconing import detect_beaconing
from netcross_core.security.dga import detect_dga
from netcross_core.security.dns_tunnel import detect_dns_tunneling
from netcross_core.security.fast_flux import detect_fast_flux
from netcross_core.security.lateral_movement import detect_lateral_movement
from netcross_core.security.protocol_mismatch import (
    count_protocol_mismatches,
    detect_protocol_mismatches,
    protocol_mismatch_findings,
)
from netcross_core.security.tls_audit import (
    DEFAULT_POLICY,
    TlsAuditPolicy,
    TlsAuditResult,
    audit_tls_certificates,
)

logger = get_logger(__name__)

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


# -- SCENARIO-7 : audit des certificats TLS ---------------------------------


def tls_audit_findings(audit: TlsAuditResult) -> list[dict[str, Any]]:
    """Un constat `anomalie` par (certificat distinct, probleme) de
    `tls_audit.audit_tls_certificates`. La severite est celle de la politique
    d'audit (jamais « critique ») ; l'hote/port du constat sont ceux du SERVEUR
    qui a presente le certificat et le detail rappelle le score de risque TLS
    de ce serveur. Un certificat sain ne produit aucun constat."""
    scores = {(s["host"], s["port"]): s["score"] for s in audit.servers}
    findings = []
    for cert in audit.certificates:
        subject = cert.get("subject") or f"serie {cert.get('serial')}"
        for issue in cert["issues"]:
            detail = f"audit TLS : {issue.detail} -- certificat {subject}"
            if cert.get("issuer") and cert.get("issuer") != cert.get("subject"):
                detail += f", emetteur {cert['issuer']}"
            detail += f" -- score TLS du serveur {scores.get((cert['host'], cert['port']), 0)}/100"
            if cert.get("frame") is not None:
                detail += f" -- trame {cert['frame']}"
            findings.append(
                {
                    "severity": issue.severity,
                    "category": "anomalie",
                    "detail": detail,
                    "host": cert["host"],
                    "port": cert["port"],
                    "point": cert.get("point") or None,
                }
            )
    return findings


# -- SCENARIO-3 : mouvements lateraux ---------------------------------------


def lateral_movement_findings(events: list[dict]) -> list[dict[str, Any]]:
    """Un constat `anomalie` par evenement de mouvement lateral detecte.
    La severite depend du type : brute_force = elevee, port_scan et
    host_scan = moyenne, unusual_protocol et new_connection = faible.
    Un mouvement lateral reste un INDICE a confirmer (un scan peut etre
    un audit legitime), jamais une compromission averee."""
    severity_map = {
        "brute_force": "elevee",
        "port_scan": "moyenne",
        "host_scan": "moyenne",
        "unusual_protocol": "faible",
        "new_connection": "faible",
    }
    findings: list[dict[str, Any]] = []
    for ev in events:
        ev_type = ev.get("type", "unknown")
        findings.append(
            {
                "severity": severity_map.get(ev_type, "faible"),
                "category": "anomalie",
                "detail": (
                    f"mouvement lateral ({ev_type}) : {ev.get('details', '?')} "
                    f"-- source {ev.get('source', '?')}, score {ev.get('score', 0.0)}"
                ),
                "point": ev.get("point") or None,
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


# -- SCENARIO-6 : DGA et fast flux -----------------------------------------


def dga_findings(alerts: list[dict]) -> list[dict[str, Any]]:
    """Un constat `anomalie` par alerte DGA. Severite `elevee` si score >= 0.8,
    `moyenne` sinon. Un domaine DGA reste un INDICE a confirmer."""
    findings: list[dict[str, Any]] = []
    for a in alerts:
        score = a.get("score", 0.0)
        severity = "elevee" if score >= 0.8 else "moyenne"
        findings.append(
            {
                "severity": severity,
                "category": "anomalie",
                "detail": (f"domaine DGA suspect : {a.get('domain', '?')} -- score {score} ({a.get('reason', '?')})"),
                "point": a.get("point") or None,
            }
        )
    return findings


def fast_flux_findings(alerts: list[dict]) -> list[dict[str, Any]]:
    """Un constat `anomalie` par alerte fast flux. Severite `elevee` pour
    ip_rotation, `moyenne` pour high_nxdomain."""
    severity_map = {"ip_rotation": "elevee", "high_nxdomain": "moyenne"}
    findings: list[dict[str, Any]] = []
    for a in alerts:
        a_type = a.get("alert_type", "unknown")
        findings.append(
            {
                "severity": severity_map.get(a_type, "moyenne"),
                "category": "anomalie",
                "detail": (
                    f"fast flux ({a_type}) : {a.get('domain', '?')} "
                    f"-- {a.get('reason', '?')}, score {a.get('score', 0.0)}"
                ),
                "point": a.get("point") or None,
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
    tls_policy: TlsAuditPolicy | None = None,
) -> None:
    """Remplit `report.service_fingerprints` et `report.security_findings`
    (remplacement, pas ajout : deux appels donnent le meme resultat).

    `detections` : sorties de `scan_capture_exploits` (CVE-2), a fournir
    par l'appelant car elles exigent la charge utile brute. `cve_conn` :
    connexion a la base CVE locale (CVE-4) ; None = pas de correlation CVE
    (les services restent listes, sans criticite). Les suspicions Expert
    Info (CVE-3) sont lues sur `report.exploit_suspicion_flows`, deja
    calcule par `analyse()` ; le tunneling DNS (FLOW-3) et l'audit des
    certificats TLS (SCENARIO-7, politique `tls_policy`, defaut prudent de
    `tls_audit.DEFAULT_POLICY`) sont calcules ici depuis `all_packets`.

    `service_fingerprints` contient aussi les empreintes JA4/HASSH
    (issue #143, FLOW-2) -- integration demandee avec CVE-1 (#135) : ce
    sont des entrees de plus dans la MEME liste (cle `service` valant
    "TLS/JA4" ou "SSH/HASSH" plutot qu'un nom de logiciel), voir
    `netcross_core.fingerprint.report.build_fingerprint_records`."""
    all_packets = list(all_packets)
    report.service_fingerprints = build_service_fingerprints(all_packets) + build_fingerprint_records(all_packets)
    # FLOW-1 (#142) : mismatches de protocole/port (SSH sur 443, DNS sur
    # 443, tunneling ICMP...) -- detectes depuis les champs deja decodes de Pkt
    protocol_mismatch_details = detect_protocol_mismatches(all_packets)
    report.protocol_mismatches = count_protocol_mismatches(all_packets)
    report.protocol_mismatch_details = protocol_mismatch_details

    # SCENARIO-6 (#152) : DGA et fast flux -- detectes depuis les champs DNS de Pkt.
    dga_result = detect_dga(all_packets)
    report.dga_alerts = [
        {
            "point": a.point,
            "domain": a.domain,
            "score": a.score,
            "reason": a.reason,
            "entropy": a.entropy,
            "consonant_ratio": a.consonant_ratio,
            "rare_bigram_ratio": a.rare_bigram_ratio,
            "length": a.length,
            "nxdomain_ratio": a.nxdomain_ratio,
        }
        for a in dga_result.alerts
    ]
    ff_result = detect_fast_flux(all_packets)
    report.fast_flux_alerts = [
        {
            "point": a.point,
            "domain": a.domain,
            "alert_type": a.alert_type,
            "score": a.score,
            "reason": a.reason,
            "ips": a.ips,
            "nxdomain_ratio": a.nxdomain_ratio,
        }
        for a in ff_result.alerts
    ]
    # SCENARIO-3 (#149) : mouvements lateraux (scans, brute force, protocoles
    # inhabituels, nouvelles connexions) -- detectes depuis les champs Pkt.
    lateral_result = detect_lateral_movement(all_packets)
    report.lateral_movement_events = [
        {
            "point": ev.point,
            "source": ev.source,
            "type": ev.event_type,
            "details": ev.details,
            "score": ev.score,
            "targets": ev.targets,
        }
        for ev in lateral_result.events
    ]

    findings = (
        exploit_findings(detections)
        + anomaly_findings(report.exploit_suspicion_flows)
        + dns_tunnel_findings(detect_dns_tunneling(all_packets).suspicions)
        + beaconing_findings(detect_beaconing(all_packets).suspicions)
        + protocol_mismatch_findings(protocol_mismatch_details)
        + dga_findings(report.dga_alerts)
        + fast_flux_findings(report.fast_flux_alerts)
        + lateral_movement_findings(report.lateral_movement_events)
        + tls_audit_findings(audit_tls_certificates(all_packets, tls_policy or DEFAULT_POLICY))
    )
    if cve_conn is not None:
        findings += cve_findings(report.service_fingerprints, cve_conn)
    report.security_findings = findings
    logger.info(
        "security_findings : {} constats ({} services, {} fingerprints)",
        len(findings),
        len(report.service_fingerprints),
        len(report.protocol_mismatch_details),
    )

"""
netcross_core.security.tls_audit -- issue #153 (SCENARIO-7, parent #141) :
audit des certificats TLS presents dans les captures.

Exploite les champs deja decodes de `Pkt` (`tls_cert_not_before`,
`tls_cert_not_after`, `tls_cert_san`, `tls_cert_serial`, `tls_server_hello`,
`ts`, `src`, `dst`) : aucune nouvelle dissection tshark.

Limites assumees (voir aussi `analysis._analyse_tls_certificate` et
`pcap_parser.protocols.extract_tls_certificate`) :
- PAS de Subject/Issuer : tshark -T ek ne les expose pas sur le
  certificat feuille. La detection "auto-signe (issuer == subject)" n'est
  donc PAS possible. Idem pour les algorithmes de signature (MD5, SHA1,
  RSA < 2048) : non exposes en EK.
- PAS de chaine de confiance : une capture reseau passive n'a pas acces
  au magasin de confiance du client. La detection "chaine incomplete"
  n'est pas possible non plus.
- Un seul certificat feuille par connexion (le dernier observe ecrase le
  precedent en cas de handshakes multiples).

Constats produits (un dict par anomalie, meme format que dns_tunnel /
beaconing) :

- **expired** (HIGH) : notAfter < horodatage du paquet (le certificat
  etait deja expire au moment de la capture) ;
- **not_yet_valid** (MEDIUM) : notBefore > horodatage du paquet
  (certificat deploye en avance, ou horloge serveur desynchronisee) ;
- **long_validity** (LOW) : validite > 398 jours (norme CA/Browser
  Forum depuis 2020) ;
- **wildcard_san** (LOW) : un SAN contient un wildcard (*.example.com) ;
- **ip_in_san** (INFO) : un SAN contient une adresse IP ;
- **missing_san** (LOW) : aucun SAN present sur le certificat ;
- **long_san** (LOW) : un SAN depasse 64 caracteres (nom suspect).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netcross_core.models import Pkt

# -- Constantes ---------------------------------------------------------------

FINDING_EXPIRED = "expired"
FINDING_NOT_YET_VALID = "not_yet_valid"
FINDING_LONG_VALIDITY = "long_validity"
FINDING_WILDCARD_SAN = "wildcard_san"
FINDING_IP_IN_SAN = "ip_in_san"
FINDING_MISSING_SAN = "missing_san"
FINDING_LONG_SAN = "long_san"

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

# Norme CA/Browser Forum : validite maximale 398 jours (depuis sept. 2020).
_MAX_VALIDITY_DAYS = 398

# Seuil de longueur pour un SAN suspect (noms tres longs, potentiellement
# malveillants ou encodes).
_LONG_SAN_THRESHOLD = 64

# Pattern pour detecter une adresse IPv4 dans un SAN.
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Pattern pour detecter un wildcard dans un SAN.
_WILDCARD_RE = re.compile(r"^\*\.")


@dataclass(frozen=True)
class TlsAuditThresholds:
    """Seuils de l'audit TLS (voir la docstring du module). Tous parametrables."""

    max_validity_days: int = _MAX_VALIDITY_DAYS
    long_san_threshold: int = _LONG_SAN_THRESHOLD


DEFAULT_THRESHOLDS = TlsAuditThresholds()


@dataclass
class TlsAuditResult:
    """Sortie de `audit_tls_certificates`, meme forme que les autres detecteurs."""

    findings: list[dict] = field(default_factory=list)


def _parse_tls_date(s: str | None) -> datetime | None:
    """Convertit une date tshark ("YYYY-MM-DD HH:MM:SS (UTC)") en datetime UTC.
    Renvoie None si le format ne correspond pas."""
    if s is None:
        return None
    try:
        return datetime.strptime(s.removesuffix(" (UTC)"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _is_ip_address(name: str) -> bool:
    return bool(_IPV4_RE.match(name))


def audit_tls_certificates(
    packets: Iterable[Pkt],
    thresholds: TlsAuditThresholds = DEFAULT_THRESHOLDS,
) -> TlsAuditResult:
    """
    Audite les certificats TLS vus dans les paquets et renvoie les
    anomalies detectees (expirés, non encore valides, validite excessive,
    SAN wildcard, IP dans SAN, SAN manquant, SAN trop long).

    Un constat est emis par paquet porteur d'un certificat (tls_cert_serial
    non nul). Les doublons (meme serveur, meme anomalie) sont dedupliques
    sur (server, finding_type, detail).
    """
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for pk in packets:
        if pk.tls_cert_serial is None:
            continue

        server = pk.dst
        capture_ts = datetime.fromtimestamp(pk.ts, tz=timezone.utc)

        not_before = _parse_tls_date(pk.tls_cert_not_before)
        not_after = _parse_tls_date(pk.tls_cert_not_after)

        # -- expired / not_yet_valid --
        if not_after is not None and capture_ts > not_after:
            detail = f"notAfter={pk.tls_cert_not_after} < capture={capture_ts.isoformat()}"
            key = (server, FINDING_EXPIRED, detail)
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "type": FINDING_EXPIRED,
                        "severity": SEVERITY_HIGH,
                        "server": server,
                        "detail": detail,
                        "serial": pk.tls_cert_serial,
                        "frame": pk.frame_number,
                    }
                )

        if not_before is not None and capture_ts < not_before:
            detail = f"notBefore={pk.tls_cert_not_before} > capture={capture_ts.isoformat()}"
            key = (server, FINDING_NOT_YET_VALID, detail)
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "type": FINDING_NOT_YET_VALID,
                        "severity": SEVERITY_MEDIUM,
                        "server": server,
                        "detail": detail,
                        "serial": pk.tls_cert_serial,
                        "frame": pk.frame_number,
                    }
                )

        # -- long validity --
        if not_before is not None and not_after is not None:
            validity_days = (not_after - not_before).days
            if validity_days > thresholds.max_validity_days:
                detail = f"validite={validity_days}j > {thresholds.max_validity_days}j (norme CA/Browser Forum)"
                key = (server, FINDING_LONG_VALIDITY, detail)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "type": FINDING_LONG_VALIDITY,
                            "severity": SEVERITY_LOW,
                            "server": server,
                            "detail": detail,
                            "serial": pk.tls_cert_serial,
                            "frame": pk.frame_number,
                        }
                    )

        # -- SAN analysis --
        san = pk.tls_cert_san
        if san is None or len(san) == 0:
            detail = "aucun SAN present sur le certificat"
            key = (server, FINDING_MISSING_SAN, detail)
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "type": FINDING_MISSING_SAN,
                        "severity": SEVERITY_LOW,
                        "server": server,
                        "detail": detail,
                        "serial": pk.tls_cert_serial,
                        "frame": pk.frame_number,
                    }
                )
        else:
            for name in san:
                # wildcard
                if _WILDCARD_RE.match(name):
                    detail = f"SAN wildcard: {name}"
                    key = (server, FINDING_WILDCARD_SAN, detail)
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            {
                                "type": FINDING_WILDCARD_SAN,
                                "severity": SEVERITY_LOW,
                                "server": server,
                                "detail": detail,
                                "serial": pk.tls_cert_serial,
                                "frame": pk.frame_number,
                            }
                        )

                # IP in SAN
                if _is_ip_address(name):
                    detail = f"IP dans SAN: {name}"
                    key = (server, FINDING_IP_IN_SAN, detail)
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            {
                                "type": FINDING_IP_IN_SAN,
                                "severity": SEVERITY_INFO,
                                "server": server,
                                "detail": detail,
                                "serial": pk.tls_cert_serial,
                                "frame": pk.frame_number,
                            }
                        )

                # Long SAN
                if len(name) > thresholds.long_san_threshold:
                    detail = f"SAN long ({len(name)} chars): {name[:40]}..."
                    key = (server, FINDING_LONG_SAN, detail)
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            {
                                "type": FINDING_LONG_SAN,
                                "severity": SEVERITY_LOW,
                                "server": server,
                                "detail": detail,
                                "serial": pk.tls_cert_serial,
                                "frame": pk.frame_number,
                            }
                        )

    return TlsAuditResult(findings=findings)

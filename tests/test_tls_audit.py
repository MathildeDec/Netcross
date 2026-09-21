"""
Tests de netcross_core.security.tls_audit (issue #153, SCENARIO-7).
Audit des certificats TLS : expired, not_yet_valid, long_validity,
wildcard_san, ip_in_san, missing_san, long_san.
"""

from __future__ import annotations

from conftest import make_pkt

from netcross_core.security.tls_audit import (
    FINDING_EXPIRED,
    FINDING_IP_IN_SAN,
    FINDING_LONG_SAN,
    FINDING_LONG_VALIDITY,
    FINDING_MISSING_SAN,
    FINDING_NOT_YET_VALID,
    FINDING_WILDCARD_SAN,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    TlsAuditThresholds,
    audit_tls_certificates,
)

# -- Helpers -------------------------------------------------------------------


def _finding_types(result) -> list[str]:
    return [f["type"] for f in result.findings]


def _tls_pkt(**overrides):
    """Pkt avec certificat TLS valide par defaut."""
    defaults = {
        "ts": 1_700_000_000.0,  # Nov 2023 UTC
        "tls_cert_not_before": "2023-01-01 00:00:00 (UTC)",
        "tls_cert_not_after": "2024-01-01 00:00:00 (UTC)",
        "tls_cert_san": ("example.com",),
        "tls_cert_serial": "ABCD1234",
        "tls_server_hello": True,
    }
    defaults.update(overrides)
    return make_pkt(**defaults)


# -- Tests: certificat expire --------------------------------------------------


def test_cert_expired():
    """notAfter < capture_ts -> finding expired (HIGH)."""
    pkt = _tls_pkt(
        tls_cert_not_after="2020-01-01 00:00:00 (UTC)",
    )
    result = audit_tls_certificates([pkt])
    types = _finding_types(result)
    assert FINDING_EXPIRED in types
    expired = next(f for f in result.findings if f["type"] == FINDING_EXPIRED)
    assert expired["severity"] == SEVERITY_HIGH
    assert expired["serial"] == "ABCD1234"


def test_cert_not_expired_valid():
    """Certificat dans sa fenetre de validite -> pas de finding expired."""
    pkt = _tls_pkt(
        tls_cert_not_before="2023-06-01 00:00:00 (UTC)",
        tls_cert_not_after="2024-06-01 00:00:00 (UTC)",
    )
    result = audit_tls_certificates([pkt])
    assert FINDING_EXPIRED not in _finding_types(result)


# -- Tests: certificat non encore valide --------------------------------------


def test_cert_not_yet_valid():
    """notBefore > capture_ts -> finding not_yet_valid (MEDIUM)."""
    pkt = _tls_pkt(
        tls_cert_not_before="2025-01-01 00:00:00 (UTC)",
    )
    result = audit_tls_certificates([pkt])
    types = _finding_types(result)
    assert FINDING_NOT_YET_VALID in types
    finding = next(f for f in result.findings if f["type"] == FINDING_NOT_YET_VALID)
    assert finding["severity"] == SEVERITY_MEDIUM


# -- Tests: validite excessive ------------------------------------------------


def test_cert_long_validity():
    """Validite > 398 jours -> finding long_validity (LOW)."""
    pkt = _tls_pkt(
        tls_cert_not_before="2020-01-01 00:00:00 (UTC)",
        tls_cert_not_after="2025-01-01 00:00:00 (UTC)",
    )
    result = audit_tls_certificates([pkt])
    types = _finding_types(result)
    assert FINDING_LONG_VALIDITY in types
    finding = next(f for f in result.findings if f["type"] == FINDING_LONG_VALIDITY)
    assert finding["severity"] == SEVERITY_LOW


def test_cert_validity_under_threshold():
    """Validite <= 398 jours -> pas de finding long_validity."""
    pkt = _tls_pkt(
        tls_cert_not_before="2023-06-01 00:00:00 (UTC)",
        tls_cert_not_after="2024-06-01 00:00:00 (UTC)",
    )
    result = audit_tls_certificates([pkt])
    assert FINDING_LONG_VALIDITY not in _finding_types(result)


# -- Tests: SAN wildcard ------------------------------------------------------


def test_wildcard_san():
    """SAN avec wildcard -> finding wildcard_san (LOW)."""
    pkt = _tls_pkt(tls_cert_san=("*.example.com", "example.com"))
    result = audit_tls_certificates([pkt])
    types = _finding_types(result)
    assert FINDING_WILDCARD_SAN in types
    finding = next(f for f in result.findings if f["type"] == FINDING_WILDCARD_SAN)
    assert finding["severity"] == SEVERITY_LOW
    assert "*.example.com" in finding["detail"]


# -- Tests: IP dans SAN -------------------------------------------------------


def test_ip_in_san():
    """SAN avec IP -> finding ip_in_san (INFO)."""
    pkt = _tls_pkt(tls_cert_san=("10.0.0.1", "example.com"))
    result = audit_tls_certificates([pkt])
    types = _finding_types(result)
    assert FINDING_IP_IN_SAN in types
    finding = next(f for f in result.findings if f["type"] == FINDING_IP_IN_SAN)
    assert finding["severity"] == SEVERITY_INFO


# -- Tests: SAN manquant ------------------------------------------------------


def test_missing_san():
    """Aucun SAN -> finding missing_san (LOW)."""
    pkt = _tls_pkt(tls_cert_san=None)
    result = audit_tls_certificates([pkt])
    types = _finding_types(result)
    assert FINDING_MISSING_SAN in types


def test_empty_san():
    """SAN vide (tuple vide) -> finding missing_san."""
    pkt = _tls_pkt(tls_cert_san=())
    result = audit_tls_certificates([pkt])
    assert FINDING_MISSING_SAN in _finding_types(result)


# -- Tests: SAN trop long -----------------------------------------------------


def test_long_san():
    """SAN > 64 chars -> finding long_san (LOW)."""
    long_name = "a" * 80 + ".example.com"
    pkt = _tls_pkt(tls_cert_san=(long_name,))
    result = audit_tls_certificates([pkt])
    types = _finding_types(result)
    assert FINDING_LONG_SAN in types


def test_short_san_no_alert():
    """SAN court -> pas de finding long_san."""
    pkt = _tls_pkt(tls_cert_san=("short.example.com",))
    result = audit_tls_certificates([pkt])
    assert FINDING_LONG_SAN not in _finding_types(result)


# -- Tests: aucun certificat ---------------------------------------------------


def test_no_cert_packets():
    """Paquets sans certificat -> aucun finding."""
    pkt = make_pkt(tls_cert_serial=None, tls_cert_not_before=None, tls_cert_not_after=None, tls_cert_san=None)
    result = audit_tls_certificates([pkt])
    assert result.findings == []


# -- Tests: deduplication ------------------------------------------------------


def test_dedup_same_server_same_finding():
    """Deux paquets avec meme serveur + meme anomalie -> un seul finding."""
    pkt1 = _tls_pkt(
        tls_cert_not_after="2020-01-01 00:00:00 (UTC)",
        tls_cert_san=("*.example.com",),
    )
    pkt2 = _tls_pkt(
        frame_number=2,
        tls_cert_not_after="2020-01-01 00:00:00 (UTC)",
        tls_cert_san=("*.example.com",),
    )
    result = audit_tls_certificates([pkt1, pkt2])
    expired = [f for f in result.findings if f["type"] == FINDING_EXPIRED]
    wildcards = [f for f in result.findings if f["type"] == FINDING_WILDCARD_SAN]
    assert len(expired) == 1
    assert len(wildcards) == 1


# -- Tests: seuils personnalisables -------------------------------------------


def test_custom_max_validity():
    """Seuil de validite personnalise."""
    pkt = _tls_pkt(
        tls_cert_not_before="2023-06-01 00:00:00 (UTC)",
        tls_cert_not_after="2024-06-01 00:00:00 (UTC)",
    )
    # Validite = 366 jours. Avec seuil a 365, cela doit declencher.
    custom = TlsAuditThresholds(max_validity_days=365)
    result = audit_tls_certificates([pkt], thresholds=custom)
    assert FINDING_LONG_VALIDITY in _finding_types(result)


# -- Tests: format de date non reconnu ----------------------------------------


def test_unparseable_date_ignored():
    """Date dans un format inattendu -> paquet ignore, pas de plantage."""
    pkt = _tls_pkt(
        tls_cert_not_before="not-a-date",
        tls_cert_not_after="also-not-a-date",
    )
    result = audit_tls_certificates([pkt])
    # Pas de finding expired/not_yet_valid/long_validity, mais SAN present
    types = _finding_types(result)
    assert FINDING_EXPIRED not in types
    assert FINDING_NOT_YET_VALID not in types
    assert FINDING_LONG_VALIDITY not in types

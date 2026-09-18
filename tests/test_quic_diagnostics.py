"""
netcross_core.quic_diagnostics -- derivation de cles QUIC v1 validee
contre les vecteurs de test OFFICIELS de la RFC 9001 Annexe A.2/A.3 (pas
uniquement contre des paquets construits par ce module lui-meme, qui
serait une preuve circulaire -- exactement la demarche decrite dans le
docstring du module et dans claude.md). Le reste du pipeline (parsing
d'en-tete long, retrait de la protection d'en-tete, dechiffrement AEAD)
est valide par un aller-retour chiffrement/dechiffrement complet -- la
seule maniere de le tester sans un vrai tshark (jamais disponible dans
aucun environnement de developpement de ce projet, voir claude.md).
"""

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from netcross_core.quic_diagnostics import (
    QUIC_V1,
    QUIC_V1_INITIAL_SALT,
    QuicEvent,
    _decrypt_initial,
    _extract_client_hello_from_crypto,
    _parse_long_header,
    _read_varint,
    derive_initial_secrets,
    derive_packet_protection_keys,
    diagnose_quic,
)

DCID = bytes.fromhex("8394c8f03e515708")

# -- vecteurs officiels, RFC 9001 Annexe A.2 (Client Initial) et A.3
# (Server Initial) -- recopies tels quels, PAS calcules par ce module.
RFC_INITIAL_SECRET = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
RFC_CLIENT_INITIAL_SECRET = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
RFC_SERVER_INITIAL_SECRET = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
RFC_CLIENT_KEY = "1f369613dd76d5467730efcbe3b1a22d"
RFC_CLIENT_IV = "fa044b2f42a3fd3b46fb255c"
RFC_CLIENT_HP = "9f50449e04a0e810283a1e9933adedd2"


def test_derive_initial_secrets_vecteur_officiel_rfc9001_a2_a3():
    client_secret, server_secret = derive_initial_secrets(DCID)
    assert client_secret.hex() == RFC_CLIENT_INITIAL_SECRET
    assert server_secret.hex() == RFC_SERVER_INITIAL_SECRET


def test_derive_packet_protection_keys_vecteur_officiel_client():
    client_secret, _ = derive_initial_secrets(DCID)
    key, iv, hp = derive_packet_protection_keys(client_secret)
    assert key.hex() == RFC_CLIENT_KEY
    assert iv.hex() == RFC_CLIENT_IV
    assert hp.hex() == RFC_CLIENT_HP


def test_quic_v1_initial_salt_est_bien_le_sel_publie_par_la_rfc():
    assert QUIC_V1_INITIAL_SALT.hex() == "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"


# -- _read_varint (RFC 9000 section 16) --------------------------------------


def test_read_varint_1_octet():
    # 0b00_111111 = 63, prefixe 00 -> longueur 1
    assert _read_varint(bytes([0x3F]), 0) == (63, 1)


def test_read_varint_2_octets():
    # exemple RFC 9000 16 : 0x7bbd -> 15293, longueur 2 (prefixe 01)
    assert _read_varint(bytes([0x7B, 0xBD]), 0) == (15293, 2)


def test_read_varint_4_octets():
    # exemple RFC 9000 16 : 0x9d7f3e7d -> 494878333, longueur 4 (prefixe 10)
    assert _read_varint(bytes([0x9D, 0x7F, 0x3E, 0x7D]), 0) == (494878333, 4)


def test_read_varint_hors_limites_renvoie_none():
    assert _read_varint(b"", 0) is None
    assert _read_varint(bytes([0x7B]), 0) is None  # annonce 2 octets, n'en a qu'1


def test_read_varint_avance_bien_l_index_de_depart():
    b = bytes([0xFF, 0x3F])  # 1 octet de bruit, puis varint 1 octet (0x3f=63)
    assert _read_varint(b, 1) == (63, 2)


# -- _parse_long_header -------------------------------------------------------


def _build_initial_header(dcid=DCID, scid=b"", token=b"", remaining_len=20) -> bytes:
    first_byte = 0xC3  # long header(1) fixed(1) type=Initial(00) reserved+pnlen(11)
    header = bytes([first_byte]) + struct.pack("!I", QUIC_V1)
    header += bytes([len(dcid)]) + dcid
    header += bytes([len(scid)]) + scid
    header += bytes([len(token)]) + token  # varint 1 octet pour token_len < 64
    header += bytes([0x40 | (remaining_len >> 8), remaining_len & 0xFF])  # varint 2 octets
    return header


def test_parse_long_header_champs_extraits():
    header = _build_initial_header(remaining_len=20)
    payload = header + b"\x00" * 20
    info = _parse_long_header(payload)
    assert info is not None
    assert info["version"] == QUIC_V1
    assert info["dcid"] == DCID
    assert info["pn_offset"] == len(header)
    assert info["remaining_len"] == 20


def test_parse_long_header_rejette_short_header():
    assert _parse_long_header(bytes([0x40]) + b"\x00" * 10) is None


def test_parse_long_header_rejette_version_non_v1():
    header = bytearray(_build_initial_header())
    header[1:5] = struct.pack("!I", 0x00000002)  # QUIC v2, non gere
    assert _parse_long_header(bytes(header) + b"\x00" * 20) is None


def test_parse_long_header_paquet_tronque():
    assert _parse_long_header(_build_initial_header()[:-1]) is None


# -- aller-retour chiffrement/dechiffrement complet ---------------------------
# Construit un vrai paquet Initial "a la main" (chiffre avec les cles
# derivees plus haut, protection d'en-tete appliquee par le meme XOR que
# celui utilise pour la lever -- operation symetrique), puis verifie que
# _decrypt_initial() retrouve exactement le texte clair d'origine. Seule
# maniere de valider tout le pipeline crypto sans un vrai tshark.


def _protect_header(buf: bytearray, pn_offset: int, hp_key: bytes) -> None:
    pn_length = (buf[0] & 0x03) + 1  # lu AVANT le XOR (bits en clair a ce stade)
    sample = bytes(buf[pn_offset + 4 : pn_offset + 4 + 16])
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    buf[0] ^= mask[0] & 0x0F
    for i in range(pn_length):
        buf[pn_offset + i] ^= mask[1 + i]


def _build_encrypted_initial(plaintext: bytes, packet_number: int = 2) -> bytes:
    client_secret, _ = derive_initial_secrets(DCID)
    key, iv, hp = derive_packet_protection_keys(client_secret)

    pn_bytes = packet_number.to_bytes(1, "big")  # pn_length=1
    remaining_len = len(pn_bytes) + len(plaintext) + 16  # pn + ciphertext + tag(GCM)
    fixed_header = bytearray(_build_initial_header(remaining_len=remaining_len))
    fixed_header[0] = (fixed_header[0] & 0xFC) | (len(pn_bytes) - 1)  # encode pn_length=1
    fixed_header = bytes(fixed_header)

    nonce = bytearray(iv)
    pn_padded = packet_number.to_bytes(len(nonce), "big")
    for i in range(len(nonce)):
        nonce[i] ^= pn_padded[i]

    aad = fixed_header + pn_bytes
    ciphertext = AESGCM(key).encrypt(bytes(nonce), plaintext, aad)

    buf = bytearray(fixed_header + pn_bytes + ciphertext)
    pn_offset = len(fixed_header)
    _protect_header(buf, pn_offset, hp)
    return bytes(buf)


def test_pipeline_chiffrement_dechiffrement_aller_retour():
    original_plaintext = b"\x01\x00\x00\x08trame CRYPTO simulee"
    packet = _build_encrypted_initial(original_plaintext, packet_number=2)

    header_info = _parse_long_header(packet)
    assert header_info is not None
    assert header_info["dcid"] == DCID

    client_secret, _ = derive_initial_secrets(header_info["dcid"])
    recovered = _decrypt_initial(packet, client_secret, header_info)
    assert recovered == original_plaintext


def test_pipeline_dechiffrement_echoue_proprement_sur_mauvais_dcid():
    packet = _build_encrypted_initial(b"donnees quelconques")
    header_info = _parse_long_header(packet)
    wrong_secret, _ = derive_initial_secrets(b"\x00" * 8)  # mauvais DCID
    assert _decrypt_initial(packet, wrong_secret, header_info) is None


# -- _extract_client_hello_from_crypto ----------------------------------------


def test_extract_client_hello_from_crypto_trame_simple():
    ch_body = b"corps-clienthello-simule"
    crypto_frame = (
        bytes([0x06])  # type CRYPTO
        + bytes([len(b"")])  # offset varint = 0 (1 octet, valeur 0)
        + bytes([len(ch_body)])  # length varint (1 octet, < 64)
        + ch_body
    )
    result = _extract_client_hello_from_crypto(crypto_frame)
    assert result == ch_body


def test_extract_client_hello_from_crypto_offset_non_nul_hors_perimetre():
    crypto_frame = bytes([0x06, 0x01, 0x05]) + b"xxxxx"  # offset=1 -> fragmente
    assert _extract_client_hello_from_crypto(crypto_frame) is None


def test_extract_client_hello_from_crypto_padding_puis_crypto():
    ch_body = b"abc"
    frame = bytes([0x00, 0x00]) + bytes([0x06, 0x00, len(ch_body)]) + ch_body
    assert _extract_client_hello_from_crypto(frame) == ch_body


def test_extract_client_hello_from_crypto_type_inconnu_arrete_le_parsing():
    assert _extract_client_hello_from_crypto(bytes([0x1C, 0x00, 0x00])) is None


# -- diagnose_quic --------------------------------------------------------------


def _quic_ev(**overrides) -> QuicEvent:
    defaults = {
        "point": "A",
        "ts": 0.0,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": 1,
        "dport": 443,
        "dcid": b"\x01\x02",
        "decryptable": True,
        "sni": "example.com",
    }
    defaults.update(overrides)
    return QuicEvent(**defaults)


def test_diagnose_quic_sni_vu_partout_est_info():
    events = [_quic_ev(point="A"), _quic_ev(point="B")]
    findings = diagnose_quic(events, points_order=["A", "B"])
    assert any(f.severity == "info" and "tous les points" in f.message for f in findings)


def test_diagnose_quic_sni_disparait_signale_a_surveiller():
    events = [_quic_ev(point="A")]  # jamais vu en B
    findings = diagnose_quic(events, points_order=["A", "B"])
    suspects = [f for f in findings if f.severity == "a_surveiller"]
    assert len(suspects) == 1
    assert "bloque" in suspects[0].message or "filtre" in suspects[0].message


def test_diagnose_quic_echecs_de_dechiffrement_comptes_par_point():
    events = [_quic_ev(point="A", decryptable=False, sni=None) for _ in range(3)]
    findings = diagnose_quic(events, points_order=["A"])
    assert any("3 paquet" in f.message for f in findings)


def test_diagnose_quic_sans_points_order_ne_compare_pas_entre_points():
    events = [_quic_ev(point="A", decryptable=False, sni=None)]
    findings = diagnose_quic(events, points_order=None)
    assert all(f.severity == "info" for f in findings)

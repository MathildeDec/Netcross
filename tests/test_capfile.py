"""
pcap_parser.capfile -- cadrage binaire pcap/pcapng et decoupage par
taille (Job 35, issue #155). Aucun outil externe : les fichiers sont
fabriques et relus par tests/pcap_builders.py, comme le reste de la suite
(voir conftest.py -- pas de dependance a tshark/editcap).
"""

import os
import struct

import pytest
from pcap_builders import (
    DSB,
    IDB,
    SHB,
    dsb,
    epb,
    frame,
    frame_index,
    idb,
    pcap_bytes,
    pcapng_packets,
    read_pcap,
    read_pcapng,
    shb,
    synthetic_packets,
    write_bytes,
    write_pcap,
)

from pcap_parser.capfile import (
    FORMAT_NSECPCAP,
    FORMAT_PCAP,
    FORMAT_PCAPNG,
    detect_format,
    format_extension,
    has_packets,
    split_by_size,
)

# Un enregistrement pcap de 100 octets de donnees occupe 116 octets fichier.
RECORD = 116
PCAP_HEADER = 24


# -- detect_format / format_extension / has_packets ---------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, FORMAT_PCAP),
        ({"endian": ">"}, FORMAT_PCAP),
        ({"nsec": True}, FORMAT_NSECPCAP),
        ({"nsec": True, "endian": ">"}, FORMAT_NSECPCAP),
    ],
)
def test_detect_format_pcap(tmp_path, kwargs, expected):
    path = tmp_path / "x.bin"  # l'extension ne compte pas, seulement les octets magiques
    path.write_bytes(pcap_bytes([], **kwargs))
    assert detect_format(str(path)) == expected


def test_detect_format_pcapng(tmp_path):
    path = tmp_path / "x.pcap"  # extension trompeuse volontaire
    write_bytes(path, shb(), idb())
    assert detect_format(str(path)) == FORMAT_PCAPNG


def test_detect_format_inconnu_ou_vide(tmp_path):
    (tmp_path / "gz").write_bytes(b"\x1f\x8b\x08\x00 fichier compresse")
    (tmp_path / "vide").write_bytes(b"")
    assert detect_format(str(tmp_path / "gz")) is None
    assert detect_format(str(tmp_path / "vide")) is None


def test_format_extension():
    assert format_extension(FORMAT_PCAP) == ".pcap"
    assert format_extension(FORMAT_NSECPCAP) == ".pcap"
    assert format_extension(FORMAT_PCAPNG) == ".pcapng"
    assert format_extension(None) == ".pcapng"  # comme editcap sans -F


def test_has_packets_pcap(tmp_path):
    vide, plein, tronque = tmp_path / "v.pcap", tmp_path / "p.pcap", tmp_path / "t.pcap"
    vide.write_bytes(pcap_bytes([]))
    plein.write_bytes(pcap_bytes(synthetic_packets(1)))
    tronque.write_bytes(pcap_bytes([])[:10])  # en-tete global incomplet
    assert has_packets(str(vide)) is False
    assert has_packets(str(plein)) is True
    assert has_packets(str(tronque)) is False


def test_has_packets_pcapng(tmp_path):
    vide, plein = tmp_path / "v.pcapng", tmp_path / "p.pcapng"
    write_bytes(vide, shb(), idb())
    write_bytes(plein, shb(), idb(), epb(frame(0)))
    assert has_packets(str(vide)) is False
    assert has_packets(str(plein)) is True


def test_has_packets_format_inconnu_ne_jette_pas_le_fichier(tmp_path):
    (tmp_path / "gz").write_bytes(b"\x1f\x8b\x08\x00 compresse")
    assert has_packets(str(tmp_path / "gz")) is True


# -- split_by_size : pcap classique -------------------------------------------


def test_split_by_size_pcap_taille_exacte(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(100))
    limite = PCAP_HEADER + 10 * RECORD  # exactement 10 paquets par segment

    segments = split_by_size(str(src), str(tmp_path / "cap"), limite)

    assert [os.path.basename(s) for s in segments] == [f"cap_{i:05d}.pcap" for i in range(10)]
    for seg in segments:
        assert os.path.getsize(seg) == limite
        assert len(read_pcap(seg)[1]) == 10


def test_split_by_size_pcap_respecte_la_limite_et_conserve_tout_dans_l_ordre(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(1000))
    limite = 15_000  # ne tombe pas juste : le dernier segment est plus petit

    segments = split_by_size(str(src), str(tmp_path / "cap"), limite)

    assert len(segments) > 1
    assert all(os.path.getsize(s) <= limite for s in segments)
    # aucun paquet perdu ni duplique, ordre d'origine conserve
    indices = [frame_index(data) for seg in segments for _s, _f, data in read_pcap(seg)[1]]
    assert indices == list(range(1000))
    # timestamps conserves tels quels
    _hdr, first = read_pcap(segments[0])
    assert first[0][:2] == (1_700_000_000, 0)


def test_split_by_size_pcap_recopie_l_en_tete_global_dans_chaque_segment(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(30), endian=">", nsec=True)  # endianness + ns conservees
    original_header = read_pcap(src)[0]

    segments = split_by_size(str(src), str(tmp_path / "cap"), PCAP_HEADER + 10 * RECORD)

    assert len(segments) == 3
    assert all(read_pcap(seg)[0] == original_header for seg in segments)
    assert all(detect_format(seg) == FORMAT_NSECPCAP for seg in segments)


def test_split_by_size_un_paquet_plus_gros_que_la_limite_a_son_propre_segment(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    segments = split_by_size(str(src), str(tmp_path / "cap"), 10)  # < un seul paquet

    # jamais de segment vide : un paquet par segment, meme s'il depasse la limite
    assert len(segments) == 5
    assert all(len(read_pcap(seg)[1]) == 1 for seg in segments)


def test_split_by_size_capture_sans_paquet_ne_cree_aucun_fichier(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, [])
    assert split_by_size(str(src), str(tmp_path / "cap"), 1000) == []
    assert list(tmp_path.glob("cap_*")) == []


def test_split_by_size_ignore_le_dernier_enregistrement_tronque(tmp_path):
    src = tmp_path / "cap.pcap"
    src.write_bytes(pcap_bytes(synthetic_packets(10))[:-30])  # capture interrompue en cours d'ecriture

    segments = split_by_size(str(src), str(tmp_path / "cap"), PCAP_HEADER + 4 * RECORD)

    indices = [frame_index(data) for seg in segments for _s, _f, data in read_pcap(seg)[1]]
    assert indices == list(range(9))  # le 10e (incomplet) est ignore, pas d'erreur


def test_split_by_size_pcap_corrompu_leve_et_ne_laisse_aucun_segment(tmp_path):
    src = tmp_path / "cap.pcap"
    bon = pcap_bytes(synthetic_packets(5))
    # 6e enregistrement : longueur capturee aberrante (~4 Gio)
    mauvais = struct.pack("<IIII", 1, 0, 0xFFFFFFF0, 0xFFFFFFF0)
    src.write_bytes(bon + mauvais)

    with pytest.raises(ValueError, match="corrompu"):
        split_by_size(str(src), str(tmp_path / "cap"), PCAP_HEADER + 2 * RECORD)

    assert list(tmp_path.glob("cap_*")) == []  # les segments deja ecrits sont nettoyes


# -- split_by_size : pcapng ---------------------------------------------------


def _pcapng_capture(count, endian="<", interfaces=1):
    blocks = [shb(endian)] + [idb(endian=endian)] * interfaces
    for i in range(count):
        blocks.append(epb(frame(i), ts_us=i, interface=i % interfaces, endian=endian))
    return blocks


@pytest.mark.parametrize("endian", ["<", ">"])
def test_split_by_size_pcapng_conserve_tout_et_chaque_segment_est_autonome(tmp_path, endian):
    src = tmp_path / "cap.pcapng"
    write_bytes(src, *_pcapng_capture(200, endian=endian, interfaces=2))
    limite = 3000

    segments = split_by_size(str(src), str(tmp_path / "cap"), limite)

    assert len(segments) > 1
    assert all(seg.endswith(".pcapng") and os.path.getsize(seg) <= limite for seg in segments)
    for seg in segments:
        types = [b[0] for b in read_pcapng(seg)]
        # SHB puis les DEUX IDB en tete de chaque segment : sans eux, les
        # paquets qui referencent l'interface 1 seraient illisibles
        assert types[:3] == [SHB, IDB, IDB]
    packets = [p for seg in segments for p in pcapng_packets(seg)]
    assert [frame_index(d) for _i, d in packets] == list(range(200))
    assert [i for i, _d in packets] == [n % 2 for n in range(200)]  # numeros d'interface conserves


def test_split_by_size_pcapng_duplique_les_secrets_de_dechiffrement(tmp_path):
    src = tmp_path / "cap.pcapng"
    write_bytes(src, shb(), idb(), dsb(), *[epb(frame(i)) for i in range(60)])

    segments = split_by_size(str(src), str(tmp_path / "cap"), 1500)

    assert len(segments) > 1
    assert all(DSB in [b[0] for b in read_pcapng(seg)] for seg in segments)


def test_split_by_size_pcapng_plusieurs_sections(tmp_path):
    src = tmp_path / "cap.pcapng"
    # deux sections concatenees, d'endianness DIFFERENTES, chacune avec ses interfaces
    section_a = [shb("<"), idb(endian="<")] + [epb(frame(i), endian="<") for i in range(20)]
    section_b = [shb(">"), idb(endian=">")] + [epb(frame(100 + i), endian=">") for i in range(20)]
    write_bytes(src, *section_a, *section_b)

    segments = split_by_size(str(src), str(tmp_path / "cap"), 1500)

    indices = [frame_index(d) for seg in segments for _i, d in pcapng_packets(seg)]
    assert indices == list(range(20)) + list(range(100, 120))
    # un segment qui demarre dans la 2e section doit porter le SHB/IDB de CETTE section
    dernier = read_pcapng(segments[-1])
    assert [b[0] for b in dernier[:2]] == [SHB, IDB]
    assert dernier[0][1][:4] == b"\x1a\x2b\x3c\x4d"  # byte-order magic big-endian


def test_split_by_size_pcapng_sans_paquet_ne_cree_aucun_fichier(tmp_path):
    src = tmp_path / "cap.pcapng"
    write_bytes(src, shb(), idb())
    assert split_by_size(str(src), str(tmp_path / "cap"), 1000) == []
    assert list(tmp_path.glob("cap_*")) == []


def test_split_by_size_pcapng_corrompu_leve_et_ne_laisse_aucun_segment(tmp_path):
    src = tmp_path / "cap.pcapng"
    mauvais_bloc = struct.pack("<II", 6, 0xFFFFFFF0)  # longueur aberrante
    write_bytes(src, *_pcapng_capture(20), mauvais_bloc)

    with pytest.raises(ValueError, match="corrompu"):
        split_by_size(str(src), str(tmp_path / "cap"), 800)

    assert list(tmp_path.glob("cap_*")) == []


# -- split_by_size : garde-fous -------------------------------------------------


def test_split_by_size_refuse_un_format_non_reconnu(tmp_path):
    src = tmp_path / "cap.pcap.gz"
    src.write_bytes(b"\x1f\x8b\x08\x00 compresse")
    with pytest.raises(ValueError, match="format non reconnu"):
        split_by_size(str(src), str(tmp_path / "cap"), 1000)


@pytest.mark.parametrize("max_bytes", [0, -5])
def test_split_by_size_refuse_une_limite_invalide(tmp_path, max_bytes):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    with pytest.raises(ValueError, match=">= 1"):
        split_by_size(str(src), str(tmp_path / "cap"), max_bytes)


def test_split_by_size_n_ecrase_jamais_un_fichier_existant(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(50))
    existant = tmp_path / "cap_00001.pcap"
    existant.write_bytes(b"a ne pas toucher")

    with pytest.raises(FileExistsError):
        split_by_size(str(src), str(tmp_path / "cap"), PCAP_HEADER + 10 * RECORD)

    assert existant.read_bytes() == b"a ne pas toucher"
    assert not (tmp_path / "cap_00000.pcap").exists()  # le segment deja ecrit est nettoye

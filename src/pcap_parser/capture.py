"""
pcap_parser.capture -- couche 6 (orchestration) : point d'entree public
du package. Compose les couches du dessous (ek_source -> packet) pour
offrir la meme API que l'ancienne parsing.py :
parse_capture(), parse_captures_parallel(), plus une nouveaute,
iter_live(), pour la capture en direct sur interface -- meme pipeline
de dissection, juste une source differente (tshark -i au lieu de -r).
"""

from __future__ import annotations

import sys
from collections.abc import Iterator, Sequence

from pcap_parser.ek_source import TsharkError, TsharkNotFoundError, iter_ek_records
from pcap_parser.packet import RawPacket, build_packet


def parse_capture(path: str, raise_on_error: bool = False) -> list[RawPacket]:
    """
    Lit un fichier de capture via tshark -T ek et renvoie la liste des
    RawPacket decodes. En cas d'erreur de lecture, imprime sur stderr et
    renvoie [] (sauf raise_on_error=True, utilise par
    parse_captures_parallel pour ne jamais confondre "0 paquet" avec
    "echec de lecture").

    Ce package ignore volontairement la notion de "label"/point de
    capture -- c'est un concept d'analyse multi-points qui appartient a
    l'appelant (cf. l'adaptateur netcross_core/parsing.py, qui associe
    chaque RawPacket a son label lors de la conversion en Pkt).
    """
    packets: list[RawPacket] = []
    try:
        for record in iter_ek_records(path=path):
            pkt = build_packet(record.ts, record.layers)
            if pkt is not None:
                packets.append(pkt)
    except (TsharkNotFoundError, TsharkError) as e:
        if raise_on_error:
            raise
        print(f"impossible de lire {path} : {e}", file=sys.stderr)
        return []
    return packets


def _parse_capture_timed(label: str, path: str):
    """Wrapper picklable pour ProcessPoolExecutor -- identique dans
    l'esprit a l'ancienne version, mais le "CPU-bound" qui justifiait le
    multiprocessing avec l'ancien decodeur est nettement moins vrai avec
    tshark
    (dissection en C, tshark lui-meme tourne dans son propre processus)
    -- on garde neanmoins le parallelisme par fichier : plusieurs
    process tshark concurrents restent plus rapides qu'un seul flux
    sequentiel sur de gros lots de captures. label n'est utilise que
    pour identifier le fichier dans per_file_stats."""
    import time

    t0 = time.time()
    pkts = parse_capture(path, raise_on_error=True)
    return pkts, time.time() - t0


def parse_captures_parallel(
    captures: Sequence[tuple[str, str]], max_workers: int | None = None
) -> tuple[list[RawPacket], list[dict]]:
    """
    Comme appeler parse_capture() sur chaque (label, path) de `captures`,
    mais un processus tshark par fichier en parallele.

    Renvoie (all_packets, per_file_stats), meme format que l'ancienne
    version : per_file_stats est une liste d'un dict par fichier --
    TOUJOURS present, succes ou echec -- avec les cles label, path,
    count, seconds, error (None si reussi).
    """
    from concurrent.futures import ProcessPoolExecutor, as_completed

    all_packets: list[RawPacket] = []
    per_file_stats: list[dict] = []

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_capture = {
            executor.submit(_parse_capture_timed, label, path): (label, path) for label, path in captures
        }
        for future in as_completed(future_to_capture):
            label, path = future_to_capture[future]
            try:
                pkts, seconds = future.result()
                all_packets.extend(pkts)
                per_file_stats.append(
                    {
                        "label": label,
                        "path": path,
                        "count": len(pkts),
                        "seconds": seconds,
                        "error": None,
                    }
                )
            except Exception as e:  # noqa: BLE001 -- catch-all volontaire : un
                # fichier en echec (tshark absent, pcap corrompu, permission...)
                # ne doit jamais interrompre le traitement parallele des autres.
                per_file_stats.append(
                    {
                        "label": label,
                        "path": path,
                        "count": 0,
                        "seconds": None,
                        "error": f"{type(e).__name__}: {e}",
                    }
                )

    order = {(label, path): i for i, (label, path) in enumerate(captures)}
    per_file_stats.sort(key=lambda s: order[(s["label"], s["path"])])

    return all_packets, per_file_stats


def iter_live(interface: str, bpf_filter: str | None = None, stop_event=None) -> Iterator[RawPacket]:
    """
    Capture en direct sur `interface` (ex: "eth0") et yield un RawPacket
    au fil de l'eau. Meme pipeline de dissection que parse_capture, la
    seule difference est la source tshark (-i au lieu de -r) : aucune
    duplication de logique de decodage entre batch et live.

    S'arrete proprement (et termine le processus tshark) si l'appelant
    cesse d'iterer -- via `break`, une exception, ou la fermeture
    explicite du generateur.

    stop_event (threading.Event, optionnel) : a positionner depuis un
    AUTRE thread que celui qui consomme ce generateur pour demander
    l'arret sans attendre le prochain paquet -- voir iter_ek_records
    pour le detail (utile pour un bouton "Arreter" reactif meme sur une
    interface sans trafic).
    """
    for record in iter_ek_records(interface=interface, bpf_filter=bpf_filter, stop_event=stop_event):
        pkt = build_packet(record.ts, record.layers)
        if pkt is not None:
            yield pkt

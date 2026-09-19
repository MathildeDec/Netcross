"""
pcap_parser.capture -- couche 6 (orchestration) : point d'entree public
du package. Compose les couches du dessous (ek_source -> packet) pour
offrir la meme API que l'ancienne parsing.py :
parse_capture(), parse_captures_parallel(), plus une nouveaute,
iter_live(), pour la capture en direct sur interface -- meme pipeline
de dissection, juste une source differente (tshark -i au lieu de -r).

CaptureRingBuffer (Job 37, issue #157) complete l'orchestration cote
retention disque : gere la rotation d'une serie de fichiers de capture
(nombre max, duree max par fichier, suppression automatique du plus
ancien) -- independamment de iter_live/parse_capture, voir sa docstring.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
from collections import deque
from collections.abc import Iterator, Sequence
from pathlib import Path

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


class CaptureRingBuffer:
    """
    Ring buffer de fichiers de capture (Job 37, issue #157) : en capture
    continue (Job 33 -- voir netcross_core.live_diff.LiveDiffEngine), le
    fichier de capture grandirait indefiniment sans mecanisme de
    rotation. Cette classe gere une serie de fichiers de taille/duree
    fixe dans un repertoire donne, en supprimant automatiquement le plus
    ancien des que `max_files` est depasse.

    Volontairement ignorante de tshark : elle ne capture ni n'ecrit
    aucun paquet elle-meme (RawPacket/Pkt ne portent pas les octets
    bruts de la trame -- voir pcap_parser.packet), elle decide juste
    QUAND ouvrir un nouveau fichier (rotate()/maybe_rotate()) et QUELS
    fichiers conserver sur disque. C'est a l'appelant d'ecrire
    reellement dans current_path (typiquement un `tshark -w`/`-b`
    pointe sur ce chemin, en reutilisant extra_args -- voir ek_source.
    _build_args) -- ou, plus simplement, d'appeler maybe_rotate() en
    continu depuis une boucle de capture deja existante, comme le fait
    LiveDiffEngine._add_packet() sur son propre flux `iter_live`, pour
    avancer l'horloge de rotation sans jamais interrompre le diff live.

    - directory : repertoire de destination des fichiers (cree au besoin)
    - prefix : prefixe du nom de fichier (defaut "capture")
    - max_files : nombre maximal de fichiers conserves simultanement (defaut 10)
    - max_duration_per_file : duree maximale en secondes avant rotation
      automatique (defaut 60.0)
    - extension : suffixe de fichier (defaut ".pcapng")
    """

    def __init__(
        self,
        directory: str,
        prefix: str = "capture",
        max_files: int = 10,
        max_duration_per_file: float = 60.0,
        extension: str = ".pcapng",
    ) -> None:
        if max_files < 1:
            raise ValueError("max_files doit etre >= 1")
        if max_duration_per_file <= 0:
            raise ValueError("max_duration_per_file doit etre > 0")
        self.directory = directory
        self.prefix = prefix
        self.max_files = max_files
        self.max_duration_per_file = max_duration_per_file
        self.extension = extension
        self._files: deque[str] = deque()
        self._rotation_started_ts: float | None = None
        self._sequence = 0

    @property
    def files(self) -> tuple[str, ...]:
        """Fichiers actuellement suivis, du plus ancien au plus recent."""
        return tuple(self._files)

    @property
    def current_path(self) -> str | None:
        """Chemin du fichier de capture courant (None avant la premiere rotation)."""
        return self._files[-1] if self._files else None

    def rotate(self, now: float | None = None) -> str:
        """Ouvre immediatement un nouveau fichier de capture et le rend
        courant, en supprimant le plus ancien si `max_files` est
        depasse. Renvoie le chemin du nouveau fichier.

        Le fichier est cree vide (touch) -- c'est a l'appelant d'y
        ecrire reellement les paquets (voir docstring de la classe).
        """
        ts = time.time() if now is None else now
        os.makedirs(self.directory, exist_ok=True)
        self._sequence += 1
        path = os.path.join(self.directory, f"{self.prefix}_{self._sequence:06d}{self.extension}")
        Path(path).touch(exist_ok=True)
        self._files.append(path)
        self._rotation_started_ts = ts
        self._prune()
        return path

    def maybe_rotate(self, now: float | None = None) -> str | None:
        """Ouvre un nouveau fichier SEULEMENT si `max_duration_per_file`
        secondes se sont ecoulees depuis la derniere rotation (ou si
        aucune rotation n'a encore eu lieu). Renvoie le nouveau chemin,
        ou None si la rotation n'etait pas encore necessaire -- pensee
        pour etre appelee a chaque paquet/tick d'une boucle de capture
        deja existante sans jamais la ralentir (voir LiveDiffEngine).
        """
        ts = time.time() if now is None else now
        if self._rotation_started_ts is None or (ts - self._rotation_started_ts) >= self.max_duration_per_file:
            return self.rotate(ts)
        return None

    def _prune(self) -> None:
        """Supprime le(s) plus ancien(s) fichier(s) au-dela de max_files."""
        while len(self._files) > self.max_files:
            oldest = self._files.popleft()
            with contextlib.suppress(FileNotFoundError):
                os.remove(oldest)

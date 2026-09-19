"""
pcap_parser.capture -- couche 6 (orchestration) : point d'entree public
du package. Compose les couches du dessous (ek_source -> packet) pour
offrir la meme API que l'ancienne parsing.py :
parse_capture(), parse_captures_parallel(), plus une nouveaute,
iter_live(), pour la capture en direct sur interface -- meme pipeline
de dissection, juste une source differente (tshark -i au lieu de -r) --
et iter_live_multi(), sa variante simultanee sur plusieurs interfaces
d'une meme machine (un processus tshark par interface, flux fusionnes
en temps reel, chaque paquet porte le label de son interface).
"""

from __future__ import annotations

import contextlib
import queue
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

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


# -- iter_live_multi : capture simultanee sur plusieurs interfaces -------------

# Delai (secondes) au bout duquel le thread de relais de stop_event constate
# que le generateur est deja termine (erreur, fermeture par l'appelant) et
# s'arrete. Sans effet sur la reactivite a stop_event : Event.wait() rend la
# main a l'instant ou l'evenement est positionne, pas a l'echeance du delai.
_LIVE_MULTI_RELAY_POLL_SECONDS = 0.1

# Paquets decodes en attente de consommation, toutes interfaces confondues.
# Borne la memoire quand l'appelant est plus lent que la capture : les threads
# producteurs se bloquent alors sur la file (contre-pression, comme un
# consommateur lent bloque la lecture du pipe tshark dans iter_live).
_LIVE_MULTI_QUEUE_MAXSIZE = 10_000

# Delai maximal accorde a l'arret de tous les threads : chaque tshark peut
# mettre jusqu'a ~3 s a se terminer (cf. iter_ek_records, wait(timeout=3)
# puis kill), en parallele d'une interface a l'autre.
_LIVE_MULTI_SHUTDOWN_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class _SourceDone:
    """Une interface a fini (tshark termine, arret demande ou EOF)."""

    label: str


@dataclass(frozen=True)
class _SourceFailed:
    """Une interface a echoue : l'exception est relayee a l'appelant."""

    label: str
    error: Exception


def _validate_live_sources(interfaces: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    """Verifie la liste (label, interface) et la renvoie sous forme de liste."""
    sources = list(interfaces)
    if not sources:
        raise ValueError("iter_live_multi : au moins une interface est requise")
    for label, interface in sources:
        if not label or not interface:
            raise ValueError(f"iter_live_multi : label et interface sont obligatoires (recu : {(label, interface)!r})")
    labels = [label for label, _interface in sources]
    duplicates = sorted({label for label in labels if labels.count(label) > 1})
    if duplicates:
        raise ValueError(
            f"iter_live_multi : label(s) en double ({', '.join(duplicates)}) -- un label distinct par interface"
        )
    return sources


def _live_source_worker(
    label: str,
    interface: str,
    bpf_filter: str | None,
    halt: threading.Event,
    out: queue.Queue,
) -> None:
    """Thread : lit UNE interface via iter_ek_records et pousse (label,
    RawPacket) dans `out`, puis _SourceDone (ou _SourceFailed en cas
    d'erreur). L'arret vient de `halt` : iter_ek_records termine alors le
    processus tshark, la lecture voit l'EOF (apres avoir rendu les paquets
    deja recus) et la boucle se termine d'elle-meme."""
    try:
        records = iter_ek_records(interface=interface, bpf_filter=bpf_filter, stop_event=halt)
        try:
            for record in records:
                pkt = build_packet(record.ts, record.layers)
                if pkt is not None:
                    out.put((label, pkt))
        finally:
            close = getattr(records, "close", None)
            if close is not None:
                close()  # termine tshark proprement, meme si la boucle a ete interrompue
    except Exception as e:  # noqa: BLE001 -- thread de fond : toute erreur (tshark absent,
        # interface inconnue, permission...) doit etre relayee a l'appelant, pas perdue.
        out.put(_SourceFailed(label, e))
    else:
        out.put(_SourceDone(label))


def _relay_stop(stop_event: threading.Event, halt: threading.Event) -> None:
    """Thread : positionne `halt` des que `stop_event` (celui de l'appelant)
    l'est, ou s'arrete des que `halt` l'est deja (generateur termine)."""
    while not halt.is_set():
        if stop_event.wait(_LIVE_MULTI_RELAY_POLL_SECONDS):
            halt.set()
            return


def _drain_queue(out: queue.Queue) -> None:
    """Vide la file sans bloquer -- debloque les producteurs bloques sur une file pleine."""
    while not out.empty():
        with contextlib.suppress(queue.Empty):  # course avec un autre consommateur : sans gravite
            out.get_nowait()


def _shutdown_live_sources(out: queue.Queue, threads: Sequence[threading.Thread]) -> None:
    """Attend la fin de tous les threads en continuant a vider la file (un
    producteur bloque sur put() ne pourrait sinon jamais se terminer)."""
    deadline = time.monotonic() + _LIVE_MULTI_SHUTDOWN_TIMEOUT_SECONDS
    for thread in threads:
        while thread.is_alive() and time.monotonic() < deadline:
            _drain_queue(out)
            thread.join(timeout=0.05)


def _raise_source_failure(failure: _SourceFailed) -> None:
    """Releve l'erreur d'une interface. TsharkError est reconstruite avec le
    label en prefixe (le message tshark seul ne dit pas quelle interface est
    en cause) ; toute autre exception (dont TsharkNotFoundError) est relevee telle quelle."""
    error = failure.error
    if isinstance(error, TsharkError):
        raise TsharkError(f"[{failure.label}] {error}", returncode=error.returncode, stderr=error.stderr) from error
    raise error


def _iter_live_multi(
    sources: list[tuple[str, str]],
    stop_event: threading.Event | None,
    bpf_filter: str | None,
) -> Iterator[tuple[str, RawPacket]]:
    halt = threading.Event()  # arret interne : stop_event de l'appelant, erreur ou fermeture
    out: queue.Queue = queue.Queue(maxsize=_LIVE_MULTI_QUEUE_MAXSIZE)
    threads = [
        threading.Thread(
            target=_live_source_worker,
            args=(label, interface, bpf_filter, halt, out),
            name=f"iter_live_multi[{label}]",
            daemon=True,
        )
        for label, interface in sources
    ]
    if stop_event is not None:
        threads.append(
            threading.Thread(target=_relay_stop, args=(stop_event, halt), name="iter_live_multi[stop]", daemon=True)
        )
    try:
        for thread in threads:
            thread.start()
        remaining = len(sources)
        while remaining:
            item = out.get()
            if isinstance(item, _SourceDone):
                remaining -= 1
            elif isinstance(item, _SourceFailed):
                _raise_source_failure(item)
            else:
                yield item
    finally:
        # Quelle que soit la sortie (fin normale, erreur, break/close() de
        # l'appelant) : arreter TOUS les tshark encore actifs et attendre les
        # threads. Positionner halt libere aussi les threads de surveillance
        # d'iter_ek_records (un par processus), sinon en attente indefinie.
        halt.set()
        _shutdown_live_sources(out, threads)


def iter_live_multi(
    interfaces: Sequence[tuple[str, str]],
    stop_event: threading.Event | None = None,
    *,
    bpf_filter: str | None = None,
) -> Iterator[tuple[str, RawPacket]]:
    """
    Capture en direct SIMULTANEE sur plusieurs interfaces et yield
    (label, RawPacket) au fil de l'eau, tous flux confondus.

    `interfaces` : sequence de (label, interface), ex.
    [("LAN", "eth0"), ("WAN", "eth1")]. Un processus tshark (donc un
    thread de lecture) par interface, meme pipeline de dissection que
    iter_live. Chaque paquet est etiquete du label de son interface : ce
    package n'en fait rien (le label est un concept d'analyse
    multi-points, cf. parse_capture), il le transporte simplement pour
    que l'appelant -- netcross_core.parsing.parse_live_multi -- l'associe
    au point de capture. Les labels doivent etre distincts ; liste vide,
    label/interface vide ou label en double levent ValueError des
    l'appel (pas au premier next()).

    Ordre de sortie : ordre d'ARRIVEE (fusion en temps reel), pas un tri
    par horodatage -- deux interfaces peuvent livrer leurs paquets avec un
    leger decalage par rapport a RawPacket.ts (dissection + threads).

    bpf_filter : meme filtre BPF applique a chaque interface (optionnel).

    Arret : comme iter_live, `stop_event` (threading.Event) positionne
    depuis un AUTRE thread termine TOUS les tshark en meme temps, meme
    sur des interfaces sans trafic ; le generateur rend alors les paquets
    deja decodes puis se termine. Fermer le generateur (break, exception,
    close()) arrete aussi tous les processus.

    Erreur sur une interface (tshark absent, interface inconnue,
    permission insuffisante...) : abandon immediat de TOUTE la capture --
    les autres interfaces sont arretees et l'exception est levee chez
    l'appelant (TsharkError prefixee par le label de l'interface fautive,
    ou TsharkNotFoundError). Choix volontairement plus strict que la GUI
    et les CLIs, ou un point en erreur laisse les autres continuer : ici
    les flux sont consommes ensemble (ex. diff live contre un baseline),
    et un flux manquant fausserait tout le resultat -- mieux vaut echouer
    franchement.
    """
    sources = _validate_live_sources(interfaces)
    return _iter_live_multi(sources, stop_event, bpf_filter)

"""
pcap_parser.ek_source -- couche 1 : execution de tshark -T ek et lecture
du flux NDJSON qui en resulte, fichier pcap ou interface live.

Cette couche ne connait rien aux protocoles applicatifs : elle expose
uniquement des dicts "layers" bruts (un par paquet), tels que tshark les
produit. Toute la semantique reseau vit dans les couches au-dessus
(tunnels.py, protocols.py, packet.py).

Pourquoi tshark -T ek :
- decodage en C dans tshark (dissecteurs Wireshark), pas en Python pur
  paquet par paquet -> gain de vitesse important sur de grosses captures
- -T ek (Elastic/Kafka bulk NDJSON) produit un objet JSON par paquet sur
  une seule ligne, ce qui permet un vrai streaming ligne par ligne (utile
  pour parse_capture comme pour la capture live), contrairement a
  une lecture qui chargerait tout le fichier en memoire avant de rendre
  la main
- les tunnels (GRE/VXLAN/GTP-U/ERSPAN/CAPWAP) et les protocoles
  applicatifs (RTP/DHCP/SIP) sont deja disseques nativement par
  Wireshark -- on n'a plus besoin de reimplementer leur decodage a la
  main comme le faisait l'ancien decodeur (cf. parse_capwap_data() dans
  l'ancienne version, remplace par le dissecteur capwap natif, cf.
  tunnels.py)
"""

from __future__ import annotations

import calendar
import contextlib
import datetime
import json
import re
import shutil
import subprocess
import threading
import urllib.parse
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import IO

from loguru import logger

# frame_frame_time_epoch : "2026-08-20T20:19:51.632525000Z" (nanosecondes).
# Nettement plus precis que le "timestamp" racine du bulk EK (millisecondes
# seulement) -- important pour des mesures de latence inter-points fines.
_FRAME_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)Z?$")


def _parse_frame_time_epoch(value: str | None) -> float | None:
    if not value:
        return None
    m = _FRAME_TIME_RE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, se, frac = m.groups()
    dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), tzinfo=datetime.timezone.utc)
    frac_seconds = int(frac[:9].ljust(9, "0")) / 1e9
    return calendar.timegm(dt.timetuple()) + frac_seconds


class TsharkNotFoundError(RuntimeError):
    """tshark n'est pas installe / pas dans le PATH."""


class TsharkError(RuntimeError):
    """tshark a demarre mais a echoue (fichier illisible, interface
    inconnue, permissions insuffisantes...). Porte le code de retour et
    stderr pour que l'appelant puisse construire un message utile."""

    def __init__(self, message: str, returncode: int | None = None, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class InvalidCaptureSourceError(ValueError):
    """Source de capture live malformee (Job 46, issue #166) : URL
    rpcap:// ou ssh:// avec un hote, un port ou une interface distante
    manquant/invalide. Leve cote Python, avant tout lancement de
    tshark, pour un message clair plutot que l'echec bas niveau que
    tshark produirait de toute facon (device/preference inconnue)."""


def _require_host(host: str | None, source: str) -> str:
    if not host:
        raise InvalidCaptureSourceError(f"hote manquant dans la source de capture : {source!r}")
    return host


def _parsed_port(parsed: urllib.parse.ParseResult, source: str) -> int | None:
    # parsed.port leve ValueError (pas au moment du urlparse() mais a
    # l'ACCES de l'attribut) si le port n'est pas un entier -- il
    # valide deja la plage 0-65535, mais 0 n'a pas de sens pour un
    # serveur rpcap/sshdump, d'ou la verification 1-65535 ci-dessous.
    try:
        port = parsed.port
    except ValueError as e:
        raise InvalidCaptureSourceError(f"port invalide dans la source de capture : {source!r}") from e
    if port is not None and not (1 <= port <= 65535):
        raise InvalidCaptureSourceError(f"port hors plage (1-65535) dans la source de capture : {source!r}")
    return port


def _resolve_rpcap_source(source: str, parsed: urllib.parse.ParseResult) -> tuple[str, list[str]]:
    # rpcap:// est nativement compris par tshark/dumpcap (libpcap sait
    # parler le protocole RPCAP) : on transmet l'URL D'ORIGINE telle
    # quelle a -i, sans la reconstruire -- seule la VALIDATION est
    # faite ici, pour echouer cote Python avec un message clair (hote/
    # port/interface manquant) plutot que de laisser tshark echouer
    # avec "There is no device named ...". Verifie empiriquement sur
    # tshark 4.2.2 : `-i rpcap://host:port/iface` est accepte tel quel.
    _require_host(parsed.hostname, source)
    port = _parsed_port(parsed, source)
    if port is None:
        raise InvalidCaptureSourceError(f"port manquant dans la source rpcap:// : {source!r}")
    if not parsed.path.lstrip("/"):
        raise InvalidCaptureSourceError(f"interface distante manquante dans la source rpcap:// : {source!r}")
    return source, []


def _resolve_ssh_source(source: str, parsed: urllib.parse.ParseResult) -> tuple[str, list[str]]:
    # sshdump est une interface EXTCAP, pas un device libpcap direct :
    # ses parametres ne se passent ni en "-i ssh://...", ni en flags
    # directs sur tshark (--remote-host, essaye et refuse -- "unrecognized
    # option"), ni en "-o sshdump:remote-host=..." (refuse -- "unknown
    # preference"). Seule la forme "-o extcap.<interface>.<option>:<valeur>"
    # est reconnue (point comme separateur nom/valeur -- ":" comme tout -o
    # tshark, pas "="). Noms exacts et confirmation empirique sur tshark
    # 4.2.2 : `sshdump --extcap-interface sshdump --extcap-config` liste
    # les options (--remote-host, --remote-port, ...) : `tshark -G
    # currentprefs` confirme les noms de preference correspondants
    # (extcap.sshdump.remotehost, .remoteport, .remoteusername,
    # .remotepassword) ; `-i sshdump -o extcap.sshdump.remotehost:X ...`
    # est accepte et tente reellement la connexion (erreur reseau, pas
    # une erreur d'argument).
    #
    # Le mot de passe, s'il est fourni, finit en clair dans les arguments
    # du processus tshark (donc visible via /proc ou `ps aux` pour tout
    # utilisateur local) -- c'est une limite de sshdump lui-meme, pas de
    # ce module. Preferer une cle SSH (non geree ici, cf. issue) pour un
    # usage sensible.
    host = _require_host(parsed.hostname, source)
    port = _parsed_port(parsed, source) or 22
    remote_interface = parsed.path.lstrip("/")
    prefs = [
        f"extcap.sshdump.remotehost:{host}",
        f"extcap.sshdump.remoteport:{port}",
    ]
    if parsed.username:
        prefs.append(f"extcap.sshdump.remoteusername:{urllib.parse.unquote(parsed.username)}")
    if parsed.password:
        prefs.append(f"extcap.sshdump.remotepassword:{urllib.parse.unquote(parsed.password)}")
    if remote_interface:
        prefs.append(f"extcap.sshdump.remoteinterface:{remote_interface}")
    return "sshdump", prefs


def _resolve_live_source(source: str) -> tuple[str, list[str]]:
    """
    Traduit une source de capture live en (valeur -i, prefs -o
    supplementaires) pour tshark -- detecte le type depuis l'URL (Job
    46, issue #166) :

    - interface locale (pas de schema), ex. "eth0" : inchangee, aucune
      pref supplementaire -- comportement historique, avant #166.
    - "rpcap://hote:port/interface" : capture distante via le protocole
      RPCAP (demon rpcapd sur la machine distante).
    - "ssh://[utilisateur[:mot_de_passe]@]hote[:port]/interface" :
      capture distante via SSH (extcap sshdump, sans demon a
      installer sur la machine distante -- juste un serveur SSH).
      Port par defaut 22 si absent.
    - "-" ou "pipe://" : lecture depuis un pipe/stdin (tshark -i -),
      ex. `mkfifo capture.fifo && qqchose > capture.fifo` en amont.

    Leve InvalidCaptureSourceError si l'URL rpcap:// ou ssh:// est
    malformee (hote/port/interface manquant ou invalide).
    """
    if source in ("-", "pipe://", "pipe"):
        return "-", []
    if source.startswith("rpcap://"):
        return _resolve_rpcap_source(source, urllib.parse.urlparse(source))
    if source.startswith("ssh://"):
        return _resolve_ssh_source(source, urllib.parse.urlparse(source))
    return source, []


# Preferences tshark activees par defaut. rtp.heuristic_rtp est le point
# important : sans elle, tshark ne reconnait le RTP que sur les ports
# annonces via SDP (SIP/H.323...) -- exactement le meme angle mort que
# l'ancienne detection heuristique par octets dans parsing.py, donc on
# la garde active pour au moins egaler le comportement precedent.
#
# ip.check_checksum/tcp.check_checksum/udp.check_checksum (Job 43/issue
# #163) : DESACTIVEES par defaut cote tshark (cout de recalcul, bruit
# historique avec l'offload materiel) -- sans elles, le champ EK
# "*.checksum.status" reste TOUJOURS a "2" (Unverified), quelle que soit
# la validite reelle du checksum (verifie empiriquement, pcap scapy
# synthetique avec checksum TCP/IP volontairement invalide, tshark
# 4.2.2 : statut "2" dans les deux cas sans cette preference). Activees
# ici pour que netcross_core.forensic.validate_checksums() ait une
# donnee exploitable -- voir pcap_parser.packet pour l'extraction du
# statut et netcross_core.forensic pour la distinction offload (0x0000)
# vs invalide.
DEFAULT_PREFS: Sequence[str] = (
    "rtp.heuristic_rtp:TRUE",
    "ip.check_checksum:TRUE",
    "tcp.check_checksum:TRUE",
    "udp.check_checksum:TRUE",
)


def _tshark_path() -> str:
    path = shutil.which("tshark")
    if path is None:
        raise TsharkNotFoundError(
            "tshark introuvable dans le PATH -- installer le paquet "
            "'tshark' (apt install tshark / dnf install wireshark-cli)."
        )
    return path


def _build_args(
    *,
    path: str | None = None,
    interface: str | None = None,
    bpf_filter: str | None = None,
    display_filter: str | None = None,
    extra_prefs: Sequence[str] = (),
    extra_args: Sequence[str] = (),
    lua_scripts: Sequence[str] = (),
) -> list:
    if (path is None) == (interface is None):
        raise ValueError("fournir soit path= (batch), soit interface= (live), pas les deux")

    args = [_tshark_path()]
    source_prefs: Sequence[str] = ()
    if path is not None:
        args += ["-r", path]
    else:
        # -l : flush ligne par ligne (indispensable pour du live streaming,
        # sinon tshark bufferise sa sortie et rien n'arrive avant un bon
        # moment). -Q : reduit le bruit sur stderr (pas de compteur de
        # paquets capture).
        assert interface is not None  # garanti par le check path/interface ci-dessus
        # _resolve_live_source (Job 46, #166) detecte rpcap://, ssh:// et
        # pipe/"-" depuis la chaine `interface` et renvoie la vraie valeur
        # -i (inchangee pour une interface locale) plus les prefs -o
        # necessaires (sshdump uniquement -- extcap, pas un device direct).
        resolved_interface, source_prefs = _resolve_live_source(interface)
        args += ["-i", resolved_interface, "-l", "-Q"]

    if bpf_filter:
        args += ["-f", bpf_filter]
    if display_filter:
        args += ["-Y", display_filter]
    for pref in (*DEFAULT_PREFS, *source_prefs, *extra_prefs):
        args += ["-o", pref]
    for script in lua_scripts:
        args += ["-X", f"lua_script:{script}"]
    args += ["-T", "ek"]
    args += list(extra_args)
    return args


def _iter_ndjson_records(stream: IO[str]) -> Iterator[dict]:
    """Lit le flux ligne par ligne et yield chaque objet JSON qui contient
    une cle "layers" (les lignes "index" du format bulk Elastic sont
    ignorees -- elles ne portent aucune donnee de paquet, juste un
    marqueur d'index pour un bulk insert Elasticsearch)."""
    for raw_line in stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # une ligne tronquee/corrompue ne doit pas faire tomber tout
            # le flux -- on la saute et on continue sur la suivante
            continue
        if "layers" in obj:
            yield obj


@dataclass
class EkRecord:
    ts: float  # secondes depuis epoch, precision nanoseconde (frame_frame_time_epoch)
    layers: dict


def _terminate_on_event(proc: subprocess.Popen, stop_event: threading.Event) -> None:
    """Tourne dans un thread daemon dedie : dort (sans polling) jusqu'a ce
    que stop_event soit positionne, puis termine `proc` immediatement.

    Necessaire car la boucle de lecture principale est bloquee sur un
    appel systeme (lecture du pipe stdout du sous-processus) : un simple
    `if stop_event.is_set(): break` verifie APRES chaque paquet ne suffit
    pas sur une interface totalement silencieuse, ou aucun paquet ne
    declenchera jamais ce test. Terminer le processus depuis un thread
    separe debloque la lecture par EOF quel que soit le trafic (valide :
    voir test_stop_mechanism.py, arret en ~1s meme sans aucune sortie)."""
    stop_event.wait()
    if proc.poll() is None:
        proc.terminate()


def iter_ek_records(
    *,
    path: str | None = None,
    interface: str | None = None,
    bpf_filter: str | None = None,
    display_filter: str | None = None,
    extra_prefs: Sequence[str] = (),
    extra_args: Sequence[str] = (),
    lua_scripts: Sequence[str] = (),
    stop_event: threading.Event | None = None,
) -> Iterator[EkRecord]:
    """
    Lance tshark -T ek et yield un EkRecord par paquet, au fil de l'eau.

    Mode batch : path="capture.pcapng" (le processus tshark se termine
    de lui-meme une fois le fichier lu).
    Mode live : interface="eth0" (le generateur ne se termine que si
    l'appelant s'arrete d'iterer -- fermer le generateur ou lever
    GeneratorExit tue proprement le processus tshark, cf. finally).

    stop_event (mode live uniquement, optionnel) : threading.Event que
    l'appelant peut positionner depuis un AUTRE thread pour demander
    l'arret. Contrairement a fermer le generateur (qui ne prend effet
    qu'au prochain paquet recu), stop_event termine le sous-processus
    tshark directement -- reactif meme sur une interface sans trafic.
    Sans objet en mode batch (le processus se termine de lui-meme).

    Leve TsharkNotFoundError si tshark n'est pas installe, ou TsharkError
    si le processus tshark a echoue (code de retour non nul et aucun
    paquet produit).
    """
    args = _build_args(
        path=path,
        interface=interface,
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extra_prefs=extra_prefs,
        extra_args=extra_args,
        lua_scripts=lua_scripts,
    )
    logger.debug("tshark args : {}", args)

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # bufsize=1 : line-buffered, necessaire pour le live
    )
    if stop_event is not None:
        threading.Thread(target=_terminate_on_event, args=(proc, stop_event), daemon=True).start()
    produced_any = False
    try:
        assert proc.stdout is not None
        for obj in _iter_ndjson_records(proc.stdout):
            produced_any = True
            frame = obj["layers"].get("frame") or {}
            ts = _parse_frame_time_epoch(frame.get("frame_frame_time_epoch"))
            if ts is None:
                # repli : "timestamp" racine du bulk EK, en millisecondes
                # -- moins precis, mais toujours present.
                try:
                    ts = int(float(obj.get("timestamp", 0))) / 1000.0
                except (TypeError, ValueError):
                    ts = 0.0
            yield EkRecord(ts=ts, layers=obj["layers"])
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        stderr_text = ""
        if proc.stderr is not None:
            with contextlib.suppress(OSError, ValueError):
                # best-effort uniquement : ce texte n'enrichit qu'un message
                # d'erreur eventuel plus bas -- son absence ne fait perdre
                # aucune fonctionnalite, juste un message legerement moins detaille.
                stderr_text = proc.stderr.read() or ""
        if proc.returncode not in (0, None, -15) and not produced_any:
            # -15 = SIGTERM, normal quand on arrete nous-memes un live
            # capture. Un code d'echec alors qu'aucun paquet n'est sorti
            # signale un vrai probleme (fichier illisible, interface
            # inconnue, permissions) -- a faire remonter, pas a avaler.
            raise TsharkError(
                f"tshark a echoue (code {proc.returncode}) : {stderr_text.strip()}",
                returncode=proc.returncode,
                stderr=stderr_text,
            )

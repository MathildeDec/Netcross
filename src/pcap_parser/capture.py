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

merge_captures() (Job 34) est d'une autre nature : elle ne decode rien,
elle fusionne plusieurs fichiers de capture en un seul via les outils
de ligne de commande livres avec tshark (mergecap, reordercap, editcap).

replay_capture() (Job 44) est egalement d'une autre nature : elle ne lit
ni ne decode rien, elle EMET sur le reseau le contenu d'un fichier de
capture via tcpreplay (paquet systeme distinct de tshark) -- rejeu de
trafic controle pour tester un pare-feu, reproduire un probleme reseau
ou valider une configuration QoS. Voir son docstring pour l'avertissement
d'usage responsable.

split_capture() (Job 35) fait l'inverse de merge_captures : elle decoupe
UN fichier en segments (par duree, nombre de paquets ou taille), via
editcap pour les deux premiers criteres et via pcap_parser.capfile pour
la taille.
"""

from __future__ import annotations

import contextlib
import math
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from pcap_parser.capfile import detect_format, format_extension, has_packets, split_by_size
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


def _wireshark_tool_path(name: str) -> str:
    """Chemin d'un outil de ligne de commande livre avec tshark (mergecap,
    reordercap, editcap). Meme paquet systeme que tshark lui-meme : meme
    exception et meme message d'installation que ek_source._tshark_path."""
    path = shutil.which(name)
    if path is None:
        raise TsharkNotFoundError(
            f"{name} introuvable dans le PATH -- installer le paquet "
            "'tshark' (apt install tshark / dnf install wireshark-cli), "
            "qui fournit aussi mergecap, reordercap et editcap."
        )
    return path


def _run_wireshark_tool(args: list[str]) -> None:
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise TsharkError(
            f"{os.path.basename(args[0])} a echoue (code {proc.returncode}) : {proc.stderr.strip()}",
            returncode=proc.returncode,
            stderr=proc.stderr,
        )


def merge_captures(paths: Sequence[str], output_path: str, dedup: bool = False) -> None:
    """
    Fusionne plusieurs fichiers de capture (pcap/pcapng, formats
    melangeables) en UN seul fichier ordonne par timestamp de paquet.

    Ne decode rien : simple enveloppe autour des outils livres avec
    tshark -- mergecap (fusion), reordercap (garantie d'ordre) et,
    seulement si dedup=True, editcap (deduplication). Le fichier de
    sortie est en pcap classique si output_path se termine par ".pcap",
    en pcapng sinon (format par defaut de mergecap). Il est ecrit de
    facon atomique : en cas d'echec (outil absent, fichier illisible...),
    output_path n'est ni cree ni modifie.

    Alignement temporel : mergecap intercale deja les paquets par
    timestamp, mais suppose que chaque fichier d'entree est LUI-MEME
    ordonne ; reordercap est donc passe systematiquement ensuite, pour
    que l'ordre global soit garanti meme si une entree ne l'etait pas
    (captures ecrites par un tampon non FIFO, horloge qui recule...).
    L'ordre des fichiers dans `paths` est sans effet sur le resultat.

    dedup=True supprime les paquets de contenu identique ET de meme
    timestamp (fenetre de temps nulle d'editcap) -- typiquement un meme
    fichier fourni deux fois, ou deux segments qui se chevauchent sur la
    meme horloge. Deux copies d'un meme paquet vues a deux points de
    capture distincts portent des timestamps differents (horloges
    differentes) et ne sont donc PAS considerees comme des doublons --
    et une vraie retransmission (meme contenu, autre instant) est
    toujours conservee : c'est exactement la donnee que l'analyse
    multi-points cherche.

    Leve ValueError (liste vide, ou sortie identique a une entree),
    FileNotFoundError (entree absente ou repertoire de sortie inexistant),
    TsharkNotFoundError (outil absent du PATH) ou TsharkError (l'outil a
    echoue).
    """
    if not paths:
        raise ValueError("au moins un fichier de capture est requis pour la fusion")
    output_real = os.path.realpath(output_path)
    for path in paths:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"fichier de capture introuvable : {path}")
        if os.path.realpath(path) == output_real:
            raise ValueError(f"le fichier de sortie ne peut pas etre aussi une entree de la fusion : {path}")

    output_dir = os.path.dirname(output_real)
    if not os.path.isdir(output_dir):
        raise FileNotFoundError(f"repertoire de sortie introuvable : {output_dir}")

    mergecap = _wireshark_tool_path("mergecap")
    reordercap = _wireshark_tool_path("reordercap")
    editcap = _wireshark_tool_path("editcap") if dedup else None

    file_type = "pcap" if output_path.lower().endswith(".pcap") else "pcapng"
    # Intermediaires dans le repertoire de sortie (meme systeme de fichiers)
    # pour que le os.replace final soit atomique.
    with tempfile.TemporaryDirectory(dir=output_dir, prefix=".netcross-merge-") as tmp:
        merged = os.path.join(tmp, "merged")
        _run_wireshark_tool([mergecap, "-F", file_type, "-w", merged, *paths])
        ordered = os.path.join(tmp, "ordered")
        _run_wireshark_tool([reordercap, merged, ordered])
        result = ordered
        if editcap is not None:
            deduped = os.path.join(tmp, "deduped")
            _run_wireshark_tool([editcap, "-w", "0", "-F", file_type, ordered, deduped])
            result = deduped
        os.replace(result, output_real)


class TcpreplayNotFoundError(RuntimeError):
    """tcpreplay n'est pas installe / pas dans le PATH.

    tcpreplay n'est PAS livre avec le paquet tshark/wireshark (contrairement
    a mergecap/reordercap/editcap ci-dessus) -- c'est un paquet systeme
    distinct, d'ou une exception dediee plutot qu'une reutilisation de
    TsharkNotFoundError."""


class TcpreplayError(RuntimeError):
    """tcpreplay a demarre mais a echoue (interface inconnue, permissions
    insuffisantes, fichier de capture illisible...). Porte le code de
    retour et stderr pour que l'appelant puisse construire un message
    utile -- meme forme que TsharkError."""

    def __init__(self, message: str, returncode: int | None = None, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def _tcpreplay_path() -> str:
    path = shutil.which("tcpreplay")
    if path is None:
        raise TcpreplayNotFoundError(
            "tcpreplay introuvable dans le PATH -- installer le paquet "
            "'tcpreplay' (apt install tcpreplay / dnf install tcpreplay)."
        )
    return path


def _run_tcpreplay(args: list[str]) -> None:
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise TcpreplayError(
            f"tcpreplay a echoue (code {proc.returncode}) : {proc.stderr.strip()}",
            returncode=proc.returncode,
            stderr=proc.stderr,
        )


def replay_capture(path: str, interface: str, speed: float | str = 1.0, loop: int = 1) -> None:
    """
    Rejoue un fichier de capture PCAP/PCAPNG sur une interface reseau via
    tcpreplay, a vitesse controlee. Ne decode ni ne lit le contenu des
    paquets -- simple enveloppe autour du binaire tcpreplay, comme
    merge_captures() l'est pour mergecap/reordercap/editcap.

    ATTENTION -- usage responsable : cette fonction EMET du trafic reseau
    REEL sur `interface`. Ne jamais l'utiliser sur une interface connectee
    a un reseau de production sans autorisation explicite : le rejeu peut
    saturer un lien, declencher des alarmes de securite (IDS/IPS), ou
    reemettre des paquets usurpant des adresses source qui ne sont pas les
    votres. Reserver ce mecanisme a un banc de test isole (interface
    loopback/veth/bridge dedie, environnement de laboratoire), sauf besoin
    explicite et maitrise d'un rejeu sur un segment reel (test de
    pare-feu, validation de configuration QoS).

    path : fichier de capture a rejouer (pcap/pcapng).
    interface : interface reseau de sortie (ex: "eth0") -- transmise a
    tcpreplay via --intf1 (flag reellement expose par tcpreplay ; le nom
    plus court "--intf" parfois vu dans la documentation utilisateur est
    un raccourci informel, pas l'option de la commande elle-meme).

    speed : vitesse de rejeu par rapport a la vitesse d'origine mesuree
    par les timestamps du fichier (--multiplier de tcpreplay) : 1.0 =
    vitesse d'origine (valeur par defaut), 0.5 = deux fois plus lent,
    2.0 = deux fois plus rapide. Doit etre un nombre strictement positif,
    ou la chaine "topspeed" (insensible a la casse) pour rejouer aussi
    vite que l'interface/le noyau le permettent SANS respecter les
    timestamps d'origine (--topspeed de tcpreplay).

    loop : nombre de fois que le fichier est rejoue integralement (1 =
    une seule passe, valeur par defaut -- --loop de tcpreplay). Doit etre
    superieur ou egal a 1.

    Leve ValueError si speed n'est ni un nombre strictement positif ni
    "topspeed", ou si loop < 1 ; FileNotFoundError si `path` n'existe pas ;
    TcpreplayNotFoundError si tcpreplay n'est pas installe ; TcpreplayError
    si tcpreplay a demarre mais a echoue (code de retour non nul).
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"fichier de capture introuvable : {path}")
    if loop < 1:
        raise ValueError(f"loop doit etre >= 1 (recu {loop!r})")

    topspeed = isinstance(speed, str) and speed.strip().lower() == "topspeed"
    if not topspeed:
        try:
            speed = float(speed)
        except (TypeError, ValueError):
            raise ValueError(
                f"speed doit etre un nombre strictement positif ou la chaine 'topspeed' (recu {speed!r})"
            ) from None
        if speed <= 0:
            raise ValueError(f"speed doit etre strictement positif (recu {speed!r})")

    tcpreplay = _tcpreplay_path()
    args = [tcpreplay, f"--intf1={interface}", f"--loop={loop}"]
    args.append("--topspeed" if topspeed else f"--multiplier={speed}")
    args.append(path)
    _run_tcpreplay(args)


# -- split_capture -------------------------------------------------------------

SPLIT_MODES = ("time", "count", "size")


def _format_seconds(value: float) -> str:
    """60.0 -> "60", 0.5 -> "0.5" : evite de passer "60.0" a editcap alors
    qu'un entier suffit (les versions anciennes d'editcap n'acceptent que
    des secondes entieres pour -i)."""
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def _check_split_args(by: str, value: float) -> None:
    if by not in SPLIT_MODES:
        raise ValueError(f"by doit valoir l'un de {SPLIT_MODES} (recu : {by!r})")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"value doit etre un nombre > 0 (recu : {value!r})")
    if by != "time" and not float(value).is_integer():
        raise ValueError(f"by={by!r} exige une valeur entiere (recu : {value!r})")


# <stem>_<NNNNN>[_<YYYYMMDDhhmmss>].pcap|pcapng : nommage d'editcap (avec
# horodatage) et du mode size (sans). NNNNN peut depasser 5 chiffres au-dela
# de 99999 segments, d'ou \d{5,} et le tri numerique dans _list_segments.
def _list_segments(output_dir: str, stem: str) -> list[str]:
    pattern = re.compile(re.escape(stem) + r"_(\d{5,})(?:_\d{14})?\.pcap(?:ng)?")
    found = []
    for name in os.listdir(output_dir):
        m = pattern.fullmatch(name)
        if m:
            found.append((int(m.group(1)), os.path.join(output_dir, name)))
    return [path for _index, path in sorted(found)]


def split_capture(path: str, output_dir: str, by: str = "time", value: float = 60.0) -> list[str]:
    """
    Decoupe la capture `path` (pcap ou pcapng) en segments plus petits
    dans `output_dir` (cree si absent) et renvoie la liste des chemins
    crees, dans l'ordre chronologique -- directement utilisable comme
    NOM=seg1,seg2,... pour --capture (voir cross_capture_analyzer_cli).

    `by` choisit le critere, `value` sa valeur (son unite depend de `by`) :
      "time"  -- value secondes par segment (float accepte, ex : 60.0).
                 Les intervalles partent du PREMIER paquet de la capture.
                 Wrapper autour de `editcap -i`.
      "count" -- value paquets par segment (entier, ex : 10000).
                 Wrapper autour de `editcap -c`.
      "size"  -- value OCTETS au plus par fichier segment (entier, ex :
                 100_000_000 ; en-tetes recopies compris). editcap ne sait
                 pas decouper par taille : realise ici en une passe (voir
                 pcap_parser.capfile), pcap/pcapng non compresse uniquement.
                 Un segment contient toujours au moins un paquet, donc un
                 paquet plus gros que la limite depasse seul sa limite.

    Le format d'entree est conserve (pcap -> pcap, pcapng -> pcapng, pcap a
    horodatage nanoseconde inclus) ; un format non reconnu (ex : .gz) est
    ecrit en pcapng par editcap (modes time/count seulement).

    Fichiers produits : `<nom>_<NNNNN>_<YYYYMMDDhhmmss>.<ext>` pour time/count
    (nommage d'editcap, horodatage = premier paquet du segment), `<nom>_<NNNNN>
    .<ext>` pour size ; `<nom>` est le nom du fichier sans extension. Le tri par
    NNNNN est l'ordre chronologique.

    Mode time : un intervalle sans aucun paquet (silence de la capture) ferait
    produire un fichier VIDE par editcap ; ces fichiers sont supprimes, donc
    NNNNN peut presenter des trous -- ils correspondent aux silences.

    Leve ValueError (by/value invalides, ou format non pris en charge en mode
    size), FileNotFoundError (capture absente), FileExistsError si output_dir
    contient deja des segments de ce fichier (rien n'est ecrase ni melange --
    supprimer ou changer de repertoire), TsharkNotFoundError (modes
    time/count sans editcap dans le PATH) ou TsharkError (echec d'editcap,
    meme convention que merge_captures).
    """
    _check_split_args(by, value)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"capture introuvable : {path}")
    editcap = _wireshark_tool_path("editcap") if by != "size" else None

    stem = os.path.splitext(os.path.basename(path))[0]
    os.makedirs(output_dir, exist_ok=True)
    if _list_segments(output_dir, stem):
        raise FileExistsError(
            f"{output_dir} contient deja des segments de {stem!r} -- les supprimer ou choisir un autre repertoire"
        )

    if by == "size":
        return split_by_size(path, os.path.join(output_dir, stem), int(value))

    assert editcap is not None  # garanti par la ligne editcap = ... ci-dessus
    fmt = detect_format(path)
    args = [editcap]
    if fmt is not None:
        # sans -F, editcap ecrit du pcapng meme pour une entree pcap (et meme
        # dans un fichier nomme .pcap) -- le format d'origine doit etre redemande.
        args += ["-F", fmt]
    args += ["-i", _format_seconds(value)] if by == "time" else ["-c", str(int(value))]
    args += [path, os.path.join(output_dir, stem + format_extension(fmt))]

    try:
        _run_wireshark_tool(args)
    except TsharkError:
        for segment in _list_segments(output_dir, stem):  # jeu partiel trompeur : on ne le laisse pas
            os.remove(segment)
        raise
    segments = _list_segments(output_dir, stem)

    kept = []
    for segment in segments:
        if has_packets(segment):
            kept.append(segment)
        else:
            os.remove(segment)
    return kept


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


# -- export_filtered -----------------------------------------------------------


def _build_display_filter(
    time_start: float | None = None,
    time_end: float | None = None,
    endpoints: list[str] | None = None,
) -> str | None:
    """Construit un filtre d'affichage tshark (-Y) pour les criteres
    temporels et d'endpoints. Renvoie None si aucun critere n'est fourni.

    time_start/time_end : secondes relatives au premier paquet de la
    capture (frame.time_relative).
    endpoints : liste d'adresses IP a inclure (ip.addr == X).
    """
    parts: list[str] = []
    if time_start is not None:
        parts.append(f"frame.time_relative >= {float(time_start):.6f}")
    if time_end is not None:
        parts.append(f"frame.time_relative <= {float(time_end):.6f}")
    if endpoints:
        # ip.addr couvre src ET dst (ip.src==X || ip.dst==X en un seul champ)
        endpoint_filters = " || ".join(f"ip.addr == {ip}" for ip in endpoints)
        parts.append(f"({endpoint_filters})")
    return " && ".join(parts) if parts else None


def export_filtered(
    path_in: str,
    path_out: str,
    bpf_filter: str | None = None,
    time_start: float | None = None,
    time_end: float | None = None,
    endpoints: list[str] | None = None,
) -> None:
    """
    Exporte un sous-ensemble de la capture `path_in` vers `path_out`,
    filtre par criteres combinables : BPF (capture filter), plage
    temporelle (secondes relatives au premier paquet) et/ou endpoints
    (adresses IP a inclure).

    Le format de sortie (pcap ou pcapng) est deduit de l'extension de
    `path_out` (`.pcap` -> pcap classique, sinon pcapng). Aucun outil
    externe autre que tshark (deja requis par le reste du projet) :
    utilise `tshark -r in -w out -f "bpf" -Y "display_filter"`.

    BPF et filtre d'affichage sont combines : un paquet doit passer les
    DEUX pour etre ecrit. Si aucun critere n'est fourni, la capture
    entiere est recopiee (utile pour convertir de format).

    Leve FileNotFoundError (capture absente), TsharkNotFoundError (tshark
    absent du PATH), TsharkError (echec de tshark), ou ValueError
    (endpoints vides, time_start > time_end).
    """
    if not os.path.isfile(path_in):
        raise FileNotFoundError(f"capture introuvable : {path_in}")
    if endpoints is not None and len(endpoints) == 0:
        raise ValueError("endpoints ne peut pas etre une liste vide (utilisez None pour ignorer ce critere)")
    if time_start is not None and time_end is not None and float(time_start) > float(time_end):
        raise ValueError(f"time_start ({time_start}) > time_end ({time_end})")

    from pcap_parser.ek_source import _tshark_path

    tshark = _tshark_path()
    args: list[str] = [tshark, "-r", path_in, "-w", path_out]
    if bpf_filter:
        args += ["-f", bpf_filter]
    display_filter = _build_display_filter(time_start, time_end, endpoints)
    if display_filter:
        args += ["-Y", display_filter]

    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise TsharkError(
            f"tshark a echoue lors de l'export filtre (code {proc.returncode}) : {proc.stderr.strip()}",
            returncode=proc.returncode,
            stderr=proc.stderr,
        )

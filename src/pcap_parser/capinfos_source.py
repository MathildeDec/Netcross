"""
pcap_parser.capinfos_source -- lecture du commentaire de SECTION pcapng
(Section Header Block, "capture comment") d'un fichier de capture, via
`capinfos -k`.

Ne pas confondre avec le commentaire de PAQUET (Enhanced Packet Block,
option opt_comment) -- celui-la est une donnee de paquet comme une
autre, deja lue par tshark -T ek et exposee via RawPacket.comment (voir
pcap_parser.packet.build_packet). Le commentaire de section est d'une
nature differente : une metadonnee du FICHIER/de la section pcapng
elle-meme, absente par construction du format pcap classique (qui ne
porte aucune notion de commentaire, section ou paquet), et surtout PAS
rattachee a un paquet precis -- rien a en tirer via le flux NDJSON de
ek_source.py, il faut interroger le fichier separement. capinfos (deja
présent dans toute installation tshark/wireshark-cli, meme suite que
tshark) fait exactement ce travail -- pas de raison de le reimplementer
via un post-dissecteur Lua tshark (l'autre piste envisagee par l'issue
#159/Job 39).

Meme discipline que ek_source.py pour le sous-processus (shutil.which,
timeout, jamais de -> texte brut suppose bien forme), mais avec une
tolerance plus large aux erreurs : un commentaire de section est une
annotation operateur FACULTATIVE, son absence ou l'echec de sa lecture
(capinfos non installe, fichier illisible, timeout) ne doit jamais
interrompre l'analyse -- contrairement a TsharkNotFoundError/TsharkError
cote ek_source.py (tshark, lui, est indispensable au coeur du pipeline),
read_capture_comment() ne leve donc jamais : absence de commentaire et
echec de lecture sont indiscernables pour l'appelant, None dans les deux
cas.
"""

from __future__ import annotations

import shutil
import subprocess

# Prefixe de la ligne portant le commentaire de section dans la sortie
# "long report" (par defaut) de `capinfos -k`. Verifie empiriquement
# (capinfos 4.2.2, pcapng synthetique commente via `editcap
# --capture-comment`, voir la PR de Job 39/issue #159) : absente du
# rapport si le fichier n'a pas de commentaire de section (pcap
# classique, ou pcapng qui n'en porte simplement pas) -- pas de ligne
# avec une valeur vide, la ligne elle-meme n'apparait pas. Un
# commentaire multi-ligne est deja aplati par capinfos sur une seule
# ligne (retours a la ligne internes remplaces par des espaces), donc
# un parsing ligne par ligne suffit, pas besoin de gerer une
# continuation.
_COMMENT_PREFIX = "Capture comment:"

# Le fichier peut etre volumineux (capinfos doit le parcourir pour
# construire son rapport, meme s'il n'a besoin ici que de -k) -- borne
# large mais finie, meme raisonnement que le reste de ce projet
# (jamais bloquer indefiniment sur un sous-processus externe).
_TIMEOUT_SECONDS = 30


def _capinfos_path() -> str | None:
    """Contrairement a pcap_parser.ek_source._tshark_path(), ne leve
    jamais si l'executable est absent -- capinfos n'est qu'un
    complement facultatif (commentaire de section), pas un composant
    central du pipeline comme tshark : son absence degrade simplement
    vers "pas de commentaire de section disponible", jamais une erreur
    remontee a l'appelant."""
    return shutil.which("capinfos")


def _parse_capture_comment(stdout: str) -> str | None:
    """Fonction pure (aucun sous-processus) : extrait le commentaire de
    section du texte deja produit par `capinfos -k`, ou None si la
    ligne "Capture comment:" est absente. Separee de read_capture_comment()
    ci-dessous pour rester testable sans capinfos installe -- meme
    raison d'etre que _build_args()/_iter_ndjson_records() dans
    ek_source.py, testes independamment de tout sous-processus reel."""
    for line in stdout.splitlines():
        if line.startswith(_COMMENT_PREFIX):
            return line[len(_COMMENT_PREFIX) :].strip() or None
    return None


def read_capture_comment(path: str) -> str | None:
    """Lit le commentaire de section pcapng de `path` via `capinfos -k`.

    Renvoie None dans TOUS les cas ou aucun commentaire fiable n'est
    disponible : capinfos non installe, fichier introuvable/illisible/
    corrompu (capinfos sort alors en erreur sur stderr sans rien
    produire sur stdout concernant un commentaire -- verifie
    empiriquement, code de retour non nul mais jamais d'exception ici,
    voir la PR de Job 39), timeout, format pcap classique sans support
    des commentaires, ou pcapng sans commentaire de section. Ces cas ne
    sont volontairement pas distingues (pas de log, pas d'exception) :
    un commentaire de section est une simple annotation operateur, son
    absence est le cas normal, pas une erreur a signaler."""
    capinfos = _capinfos_path()
    if capinfos is None:
        return None
    try:
        proc = subprocess.run(
            [capinfos, "-k", path],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return _parse_capture_comment(proc.stdout)

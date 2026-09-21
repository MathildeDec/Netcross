"""
netcross_core.discovery.os_detect -- issue #151 (SCENARIO-5, parent #141) :
fingerprint passif d'OS par TTL, fenetre TCP et options TCP (approche
p0f-like).

Limites assumees :
- Le TTL est decremente a chaque hop : la valeur observee n'est pas le
  TTL initial de l'OS. On utilise des seuils (>= 250 = Linux/Unix,
  128 = Windows, <= 64 = Linux/switch) -- approximation grossiere.
- La fenetre TCP initiale (window) est un meilleur signal mais varie
  entre versions du meme OS.
- Aucune dependance externe : pas de p0f, pas de base de signatures.
"""

from __future__ import annotations

from netcross_core.models import Pkt


def guess_os_from_ttl(ttl: int | None) -> str | None:
    """Devine l'OS a partir du TTL observe.

    Seuils empiriques (le TTL observe est <= TTL initial a cause des
    routeurs traverses) :
    - 200-255 : Windows (TTL initial 128, peu de hops)
    - 120-199 : Windows (TTL initial 128, hops moderes)
    - 60-119 : Linux/Unix (TTL initial 64)
    - 0-59 : Linux/Unix (TTL initial 64, nombreux hops) ou equipement reseau
    """
    if ttl is None:
        return None
    if ttl >= 200:
        return "Windows"
    if ttl >= 120:
        return "Windows"
    if ttl >= 60:
        return "Linux/Unix"
    return "Linux/Unix (TTL faible)"


def guess_os_from_window(window: int | None) -> str | None:
    """Devine l'OS a partir de la fenetre TCP initiale.

    Valeurs caracteristiques (approximatives, p0f-like) :
    - 8192 : Windows (anciennes versions)
    - 16384 : Windows XP/2000
    - 65535 : Windows moderne / macOS
    - 5840 / 29200 : Linux
    - 57344 : Solaris
    """
    if window is None:
        return None
    if window in (8192, 16384, 65535):
        return "Windows/macOS"
    if window in (5840, 29200, 14600):
        return "Linux"
    if window == 57344:
        return "Solaris"
    return None


def detect_os(pkt: Pkt) -> str | None:
    """
    Combine TTL et fenetre TCP pour deviner l'OS de la source du paquet.

    Retourne None si aucune indication fiable.
    """
    ttl_guess = guess_os_from_ttl(pkt.ttl)
    win_guess = guess_os_from_window(pkt.window)

    if ttl_guess and win_guess:
        # Concordance : on retourne le TTL (plus fiable en pratique)
        if ttl_guess == win_guess or "Windows" in ttl_guess:
            return ttl_guess
        return f"{ttl_guess} / {win_guess}"
    if ttl_guess:
        return ttl_guess
    if win_guess:
        return win_guess
    return None

#!/usr/bin/env python3
"""
cross_capture_analyzer_cli.py -- interface en ligne de commande pour
netcross_core. Le moteur d'analyse lui-meme (parsing, correlation,
analyse, mise en forme) vit dans le package netcross_core/ et ne depend
d'aucune interface : ce fichier ne fait que lire les arguments, appeler
le package, et afficher/ecrire le resultat.

Voir netcross_core/__init__.py pour l'utiliser comme bibliotheque
(comme le fait deja l'app GTK4 dans netcross_gtk4/, ou le generateur
de rapport PDF dans netcross_report/) plutot que depuis cette CLI.

Prerequis :
    - tshark installe (paquet systeme tshark / wireshark-cli, voir
      install.sh) -- utilise par pcap_parser pour decoder les captures,
      y compris pour --tls/--quic/--live
    - pour --live : declencher un vrai sniffing reseau demande soit de
      lancer cette CLI en root, soit d'avoir donne au binaire dumpcap
      les capacites CAP_NET_RAW/CAP_NET_ADMIN (setcap), soit d'etre
      dans le groupe systeme dedie si la distribution en fournit un
      (selon exactement le meme prerequis que pour l'app GTK4)
    - pip install cryptography --break-system-packages (necessaire
      uniquement pour --quic, pas pour cette CLI de base)
    - pip install reportlab matplotlib networkx --break-system-packages
      (necessaire uniquement pour --pdf-report)
    - --json-report n'a besoin de rien de plus (json/datetime sont dans
      la bibliotheque standard)

Exemple d'utilisation (fichiers deja captures) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --capture DC=capture_datacenter.pcapng \
        --order LAN,WAN,DC \
        --bucket-ms 500 \
        --triage \
        --detail-csv details.csv

Exemple d'utilisation (capture en direct sur 2 interfaces, 60s max) :
    python3 cross_capture_analyzer_cli.py \
        --live LAN:eth0 \
        --live WAN:eth1:"tcp port 443" \
        --live-duration 60 \
        --order LAN,WAN \
        --triage

Exemple d'utilisation (comparaison client vs client -- "ce poste
fonctionne, pas l'autre", meme capture, memes points) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --client-group PosteA=10.0.0.5 \
        --client-group PosteB=10.0.0.12,10.0.0.13 \
        --client-reference PosteA \
        --client-diff-csv client_diff.csv

Exemple d'utilisation (rapport anonymise pour partage externe -- voir
netcross_core.redact pour le detail et les limites de --redact) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --redact --redact-map correspondance_privee.csv \
        --pdf-report rapport_a_partager.pdf

Exemple d'utilisation (historique inter-runs -- voir netcross_report.history
pour le detail ; le meme fichier .db peut etre reutilise a chaque controle
periodique du meme lien) :
    python3 cross_capture_analyzer_cli.py \
        --capture LAN=capture_lan.pcapng \
        --capture WAN=capture_wan.pcapng \
        --history-db suivi_site_a.db --history-label Site-A --history-show 10
"""

import argparse
import os
import signal
import sys
import threading
import time

from netcross_core import (
    analyse,
    compare_clients,
    correlate,
    parse_capture,
    parse_captures_parallel,
    parse_live,
    print_client_comparison,
    print_report,
    redact_packets,
    write_client_diff_csv,
    write_detail_csv,
    write_redaction_map_csv,
)


def _parse_live_spec(spec):
    """LABEL:INTERFACE[:FILTRE_BPF] -> (label, interface, bpf_ou_None).
    maxsplit=2 : un filtre BPF contenant lui-meme des ':' (adresse IPv6,
    par exemple) reste intact, seuls les 2 premiers ':' sont significatifs."""
    parts = spec.split(":", 2)
    if len(parts) < 2 or not parts[0] or not parts[1]:
        print(
            f"Format invalide pour --live: {spec} (attendu LABEL:INTERFACE[:FILTRE_BPF])",
            file=sys.stderr,
        )
        sys.exit(1)
    label, iface = parts[0], parts[1]
    bpf = parts[2] if len(parts) > 2 else None
    return label, iface, bpf


def _parse_client_group_spec(spec):
    """NOM=IP1[,IP2,...] -> (nom, {ip1, ip2, ...}). Une IP peut apparaitre
    dans plusieurs groupes (assume, non verifie ici -- voir
    netcross_core.client_diff.group_packets_by_client pour la consequence)."""
    if "=" not in spec:
        print(
            f"Format invalide pour --client-group: {spec} (attendu NOM=IP1[,IP2,...])",
            file=sys.stderr,
        )
        sys.exit(1)
    name, ips = spec.split("=", 1)
    ip_set = {ip.strip() for ip in ips.split(",") if ip.strip()}
    if not name or not ip_set:
        print(
            f"Format invalide pour --client-group: {spec} (attendu NOM=IP1[,IP2,...], nom et IP requis)",
            file=sys.stderr,
        )
        sys.exit(1)
    return name, ip_set


def _parse_capture_spec(spec, flag_name):
    """NOM=chemin1[,chemin2,...] -> (label, [chemin1, chemin2, ...]).

    Le cas courant (un seul chemin) reste NOM=chemin, inchange. La forme
    a plusieurs chemins sert a rejouer une capture segmentee (rotation
    tcpdump/tshark -b, ex: -C 100 -> capture_00000_x.pcap,
    capture_00001_x.pcap...) comme un seul point de capture continu,
    sans avoir a les fusionner au prealable (mergecap ou autre) : chaque
    chemin devient une entree (label, chemin) distincte dans la liste
    `captures` de main(), lue separement par tshark puis simplement
    concatenee -- exactement le mecanisme deja existant qui permettrait
    par ailleurs (non teste comme un vrai cas d'usage jusqu'ici) de
    fournir plusieurs fois le meme label avec des --capture separes.
    Aucun tri par timestamp n'est fait ici : les segments doivent etre
    listes par l'appelant dans l'ordre chronologique (ordre naturel
    d'une rotation tcpdump), les quelques analyses qui ont besoin d'un
    ordre strict par point (STP, timeout d'inactivite) trient deja
    explicitement en interne plutot que de faire confiance a l'ordre de
    all_packets -- voir netcross_core.analysis."""
    if "=" not in spec:
        print(
            f"Format invalide pour {flag_name}: {spec} (attendu NOM=chemin[,chemin2,...])",
            file=sys.stderr,
        )
        sys.exit(1)
    label, paths_str = spec.split("=", 1)
    paths = [p.strip() for p in paths_str.split(",")]
    if not label or not paths or any(not p for p in paths):
        print(
            f"Format invalide pour {flag_name}: {spec} (attendu NOM=chemin[,chemin2,...], "
            "nom et chemin(s) requis -- pas de segment vide, ex: virgule en trop)",
            file=sys.stderr,
        )
        sys.exit(1)
    return label, paths


def _run_live_captures(live_specs, duration):
    """Capture en direct sur un ou plusieurs points simultanement (un thread
    par point, comme l'interface graphique -- voir netcross_gtk4.app
    _begin_live_capture/_live_capture_worker) jusqu'a Ctrl+C ou
    --live-duration. Renvoie la liste de tous les paquets accumules.

    Un point en erreur (tshark absent, interface invalide, permission...)
    n'arrete pas les autres points : meme choix assume que sur la GUI,
    ou seul l'utilisateur (ou la duree max) met fin a la session complete."""
    points = [_parse_live_spec(s) for s in live_specs]
    stop_event = threading.Event()
    packets_by_point = {label: [] for label, _iface, _bpf in points}
    lock = threading.Lock()

    def _worker(label, iface, bpf):
        count = 0
        last_log = time.monotonic()
        try:
            for pkt in parse_live(label, iface, bpf_filter=bpf, stop_event=stop_event):
                with lock:
                    packets_by_point[label].append(pkt)
                count += 1
                now = time.monotonic()
                if now - last_log >= 2.0:
                    print(f"[{label}] {count} paquets...")
                    last_log = now
        except Exception as e:  # noqa: BLE001 -- thread de fond : une erreur sur
            # ce point doit etre rapportee sans arreter les autres points en cours.
            print(f"[{label}] ERREUR : {e}", file=sys.stderr)
        print(f"[{label}] capture arretee -- {count} paquet(s) au total.")

    def _on_sigint(_signum, _frame):
        print(
            "\nArret demande (Ctrl+C) -- fin de la capture en cours sur tous les points...",
            file=sys.stderr,
        )
        stop_event.set()

    def _on_duration_elapsed():
        print(
            f"\nDuree maximale ({duration}s) atteinte -- arret de la capture.",
            file=sys.stderr,
        )
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, _on_sigint)
    for label, iface, bpf in points:
        print(
            f"[{label}] capture demarree sur {iface}"
            + (f" (filtre BPF: {bpf})" if bpf else "")
            + "... (Ctrl+C pour arreter)"
        )
    threads = [threading.Thread(target=_worker, args=(label, iface, bpf), daemon=True) for label, iface, bpf in points]
    for t in threads:
        t.start()

    timer = None
    if duration:
        timer = threading.Timer(duration, _on_duration_elapsed)
        timer.daemon = True
        timer.start()

    try:
        for t in threads:
            t.join()
    finally:
        if timer:
            timer.cancel()
        signal.signal(signal.SIGINT, old_handler)

    all_packets = []
    for label, _iface, _bpf in points:
        all_packets.extend(packets_by_point[label])
    return all_packets


def main():
    ap = argparse.ArgumentParser(description="Analyse croisee de captures Wireshark multi-points")
    ap.add_argument(
        "--capture",
        action="append",
        help="NOM=chemin.pcap(ng)[,chemin2.pcap(ng),...], repetable pour chaque "
        "point de capture. Plusieurs chemins separes par des virgules pour un "
        "meme NOM permettent de rejouer une capture segmentee (rotation "
        "tcpdump/tshark, ex: -C 100) comme un seul point continu -- a lister "
        "dans l'ordre chronologique, aucun tri automatique n'est effectue. "
        "Mutuellement exclusif avec --live.",
    )
    ap.add_argument(
        "--live",
        action="append",
        metavar="LABEL:INTERFACE[:FILTRE_BPF]",
        help="Capture en direct sur une interface reseau au lieu de fichiers "
        "pcap existants (repetable pour plusieurs points simultanes, un "
        "thread par point comme sur l'interface graphique). S'arrete sur "
        "Ctrl+C ou --live-duration. Mutuellement exclusif avec --capture/"
        "--parallel/--tls/--quic (memes limitations assumees que sur la GUI).",
    )
    ap.add_argument(
        "--live-duration",
        type=int,
        default=None,
        help="Duree maximale en secondes pour --live (defaut: illimitee, s'arrete uniquement sur Ctrl+C)",
    )
    ap.add_argument("--order", help="Ordre physique des points sur le chemin reseau, ex: LAN,WAN,DC")
    ap.add_argument("--detail-csv", help="Chemin de sortie pour le detail par flux (CSV)")
    ap.add_argument(
        "--names",
        metavar="PATH",
        help="Table des noms (JSON/YAML, section 6.15) : remplace les adresses "
        "IP brutes par des noms logiques (ex: PC-COMPTA-31 -> APP-SQL-01) "
        "dans le CSV detail et le rapport JSON.",
    )
    ap.add_argument(
        "--nat-tolerant",
        action="store_true",
        help="Correle par hash de payload + fenetre temporelle au lieu de "
        "IP/port (necessaire si un NAT/PAT est traverse entre 2 points). "
        "Desactive les modules handshake SYN/SYN-ACK et decalage d'horloge.",
    )
    ap.add_argument(
        "--nat-window-ms",
        type=int,
        default=200,
        help="Largeur de la fenetre temporelle (ms) pour le mode --nat-tolerant "
        "(defaut: 200ms, a elargir si la latence WAN est plus grande)",
    )
    ap.add_argument(
        "--bucket-ms",
        type=int,
        default=1000,
        help="Largeur des fenetres temporelles (ms) pour le debit, la "
        "correlation pertes/debit et le bufferbloat (defaut: 1000ms, "
        "reduire a 50-200ms pour detecter des microbursts)",
    )
    ap.add_argument(
        "--rtp-clock-rate",
        type=int,
        default=8000,
        help="Cadence d'horloge RTP en Hz pour le calcul de gigue (defaut: "
        "8000Hz pour la voix G.711/G.729 ; utiliser 90000 pour de la video)",
    )
    ap.add_argument(
        "--idle-timeout-seconds",
        type=float,
        default=None,
        help="Silence minimal (secondes) entre deux paquets consecutifs au "
        "point amont pour detecter une coupure NAT/pare-feu silencieuse "
        "(defaut: 60s, voir netcross_core.analysis._IDLE_TIMEOUT_SECONDS). "
        "Reduire sur un lien connu pour un timeout d'etat plus agressif, "
        "augmenter pour eviter les faux positifs sur des sessions peu actives.",
    )
    ap.add_argument(
        "--triage",
        action="store_true",
        help="Affiche en plus un classement des segments par ou commencer a "
        "regarder (convergence de plusieurs categories de constats sur un "
        "meme segment). Purement informatif, n'affecte pas les autres sorties.",
    )
    ap.add_argument(
        "--triage-top-n",
        type=int,
        default=5,
        help="Nombre de segments affiches par --triage (defaut: 5)",
    )
    ap.add_argument(
        "--topn-charts",
        type=int,
        default=5,
        metavar="N",
        help="Nombre de categories affichees par graphique temporel top-N "
        "dans --pdf-report (protocole/port/IP/DSCP, un seul point de "
        "capture -- le premier de --order ou de --capture -- pour eviter "
        "de compter certains paquets en double sur un meme graphique). Le "
        "reste est regroupe sous 'autres'. Sans effet si --pdf-report "
        "n'est pas fourni (defaut: 5).",
    )
    ap.add_argument(
        "--tls",
        action="store_true",
        help="Diagnostic TLS en plus de l'analyse principale (ClientHello/SNI, "
        "ServerHello, alertes, segment ou un handshake qui aboutissait "
        "commence a echouer). Relit les memes fichiers passes a --capture "
        "avec un pipeline de decodage independant (mais toujours via tshark).",
    )
    ap.add_argument(
        "--quic",
        action="store_true",
        help="Diagnostic QUIC/HTTP3 en plus de l'analyse principale (SNI extrait "
        "en dechiffrant les paquets Initial QUICv1). Necessite cryptography. "
        "Relit les memes fichiers passes a --capture.",
    )
    ap.add_argument(
        "--pdf-report",
        help="Chemin de sortie pour un rapport PDF (triage, synthese, graphiques, "
        "detail par module). Necessite reportlab, matplotlib et networkx.",
    )
    ap.add_argument(
        "--json-report",
        help="Chemin de sortie pour un rapport JSON structure (points, constats, "
        "triage, diagnostics TLS/QUIC si --tls/--quic sont fournis) -- pour "
        "l'integration externe (dashboard, ticketing, CI). Aucune dependance "
        "supplementaire (contrairement a --pdf-report).",
    )
    ap.add_argument(
        "--rule-engine",
        action="store_true",
        help="Active le moteur d'execution de regles declaratives "
        "(netcross_report.rule_engine) : evalue chaque regle du catalogue "
        "(expert_rules) contre le Report et affiche les Finding produits. "
        "Integre egalement les resultats au --json-report si fourni. "
        "Independant du chemin procedural (build_findings) -- les deux "
        "chemins coexistent, le moteur declaratif ne le remplace pas encore.",
    )
    ap.add_argument(
        "--expert-section",
        action="store_true",
        help="Affiche en console les objets enrichis (evenements d'expertise "
        "avec cause/impact probables, diagnostics par segment, conformite aux "
        "referentiels, flux correles, signaux tshark bruts). Ces objets "
        "n'etaient jusqu'ici exposes que par --json-report. Egalement ajoutes "
        "en section dediee du --pdf-report si celui-ci est demande, que cette "
        "option soit active ou non.",
    )
    ap.add_argument(
        "--sequence-diagram",
        type=int,
        nargs="?",
        const=1,
        default=0,
        metavar="N",
        help="Ajoute au --pdf-report un diagramme de sequence des echanges "
        "pour les N flux les plus volumineux (N=1 si l'option est passee sans "
        "valeur). Une ligne par paquet ET par point de capture : le meme "
        "paquet vu a deux points apparait deux fois, l'ecart entre les deux "
        "lignes etant son temps de transit. Sans effet sans --pdf-report "
        "(les vues exigent les paquets bruts, que le rapport ne conserve pas).",
    )
    ap.add_argument(
        "--client-group",
        action="append",
        metavar="NOM=IP1[,IP2,...]",
        help="Regroupe les paquets par client (poste) plutot que par point de "
        "capture, pour une comparaison 'ce client fonctionne, pas l'autre' -- "
        "meme capture, memes points, seule la source change. Repetable (au "
        "moins 2 pour produire une comparaison) ; plusieurs IP separees par "
        "des virgules pour un meme client couvrent le cas multi-IP/DHCP. "
        "Additif : n'affecte pas l'analyse principale ci-dessus.",
    )
    ap.add_argument(
        "--client-reference",
        metavar="NOM",
        help="Nom du client de reference pour --client-group (celui qui "
        "fonctionne, ou le comportement majoritaire) -- chaque autre client "
        "est compare a lui. Par defaut : le premier --client-group fourni.",
    )
    ap.add_argument(
        "--client-diff-csv",
        help="Chemin de sortie CSV pour le detail de la comparaison "
        "--client-group (une ligne par ecart, tous clients confondus).",
    )
    ap.add_argument(
        "--parallel",
        action="store_true",
        help="Lit les fichiers de capture en parallele (un processus tshark par "
        "fichier au lieu d'un seul flux sequentiel). Le gain depend du "
        "nombre de coeurs disponibles sur la machine (aucun gain sur "
        "une machine a 1 seul coeur).",
    )
    ap.add_argument(
        "--parallel-workers",
        type=int,
        default=None,
        help="Nombre de processus pour --parallel (defaut: nombre de coeurs CPU disponibles)",
    )
    ap.add_argument(
        "--redact",
        action="store_true",
        help="Anonymise les adresses IP (RFC 5737/3849, plages de documentation) "
        "et MAC (OUI localement administre) avant l'analyse -- mapping "
        "coherent sur tout le run, pour partager un rapport ou une capture "
        "sans exposer l'adressage reel (support vendeur, ticket externe). "
        "Ne couvre que les adresses (pas les noms DNS/HTTP/SAN TLS/SIP, voir "
        "netcross_core.redact). Mutuellement exclusif avec --tls/--quic/"
        "--client-group, qui relisent des fichiers ou des IP fournies "
        "independamment de cette redaction.",
    )
    ap.add_argument(
        "--redact-map",
        metavar="CHEMIN",
        help="Avec --redact : ecrit la correspondance adresse reelle <-> "
        "pseudonyme dans un CSV local (a conserver en prive -- ne JAMAIS le "
        "transmettre avec le rapport/la capture redigee -- utile pour "
        "retrouver plus tard a quelle machine correspond un pseudonyme cite "
        "par un tiers).",
    )
    ap.add_argument(
        "--history-db",
        metavar="CHEMIN",
        help="Enregistre un resume de ce run (score de sante, nombre de "
        "constats par severite) dans une base SQLite locale, creee si "
        "absente -- pour observer une tendance dans le temps sur des runs "
        "successifs (ex: controle hebdomadaire du meme lien). Ne remplace "
        "pas --json-report/--pdf-report/--detail-csv (detail complet d'un "
        "run donne) : l'historique ne conserve qu'un resume compact par run.",
    )
    ap.add_argument(
        "--history-label",
        metavar="ETIQUETTE",
        help="Avec --history-db : etiquette libre associee a ce run (ex: nom "
        "de site/scenario), pour distinguer plusieurs historiques qui "
        "partagent le meme fichier .db. Reutilisee automatiquement comme "
        "filtre par --history-show si elle est fournie.",
    )
    ap.add_argument(
        "--history-show",
        nargs="?",
        type=int,
        const=10,
        default=None,
        metavar="N",
        help="Avec --history-db : affiche apres l'analyse les N derniers "
        "runs enregistres (y compris celui-ci), du plus recent au plus "
        "ancien -- defaut 10 si l'option est fournie sans valeur. Filtre "
        "sur --history-label si elle est fournie, sinon montre tous les "
        "runs de la base.",
    )
    args = ap.parse_args()

    if not args.capture and not args.live:
        print("Il faut fournir au moins un --capture ou un --live.", file=sys.stderr)
        sys.exit(1)
    if args.capture and args.live:
        print(
            "--capture et --live sont mutuellement exclusifs (meme limitation "
            "assumee que sur l'interface graphique : cases a cocher fichier/live).",
            file=sys.stderr,
        )
        sys.exit(1)

    # Table des noms (section 6.15) : optionnelle, chargee une fois pour
    # toutes les sorties (CSV detail + JSON). None si --names absent.
    names = None
    if args.names:
        from netcross_core.naming import NameTable

        names = NameTable.load(args.names)
        print(f"Table des noms chargee : {len(names)} entree(s) depuis {args.names}")
    if args.live:
        if args.parallel:
            print(
                "--parallel n'a pas de sens avec --live (deja un thread par point, en parallele).",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.tls or args.quic:
            print(
                "--tls/--quic ne sont pas disponibles avec --live : ils relisent "
                "les fichiers passes a --capture avec un pipeline de decodage "
                "independant, ce qui n'existe pas (encore) pour une capture en "
                "direct. Meme limitation assumee que sur l'interface graphique.",
                file=sys.stderr,
            )
            sys.exit(1)

    if args.redact_map and not args.redact:
        print("--redact-map necessite --redact.", file=sys.stderr)
        sys.exit(1)
    if args.redact and (args.tls or args.quic or args.client_group):
        print(
            "--redact n'est pas disponible avec --tls/--quic/--client-group : ces "
            "trois options relisent les fichiers passes a --capture avec leur "
            "propre pipeline (--tls/--quic), ou recoivent des adresses IP reelles "
            "directement en argument (--client-group), independamment des "
            "paquets anonymises par --redact -- les combiner laisserait filtrer "
            "des adresses reelles dans une partie du rapport sans le signaler. "
            "Voir netcross_core.redact pour le detail.",
            file=sys.stderr,
        )
        sys.exit(1)

    if (args.history_label or args.history_show is not None) and not args.history_db:
        print("--history-label/--history-show necessitent --history-db.", file=sys.stderr)
        sys.exit(1)

    client_group = None
    if args.client_group:
        client_group = {}
        for spec in args.client_group:
            name, ips = _parse_client_group_spec(spec)
            client_group.setdefault(name, set()).update(ips)
        if len(client_group) < 2:
            print(
                "--client-group necessite au moins 2 clients distincts pour produire une comparaison "
                f"(un seul fourni : {', '.join(client_group)}).",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.client_reference and args.client_reference not in client_group:
            print(
                f"--client-reference {args.client_reference!r} ne correspond a aucun --client-group fourni "
                f"(clients disponibles : {', '.join(sorted(client_group))}).",
                file=sys.stderr,
            )
            sys.exit(1)
    elif args.client_reference or args.client_diff_csv:
        print(
            "--client-reference/--client-diff-csv necessitent au moins deux --client-group.",
            file=sys.stderr,
        )
        sys.exit(1)

    captures = []
    for c in args.capture or []:
        label, paths = _parse_capture_spec(c, "--capture")
        captures.extend((label, path) for path in paths)

    all_packets = []
    if args.live:
        all_packets = _run_live_captures(args.live, args.live_duration)
        print(f"\n{len(all_packets)} paquet(s) captures au total, analyse en cours...")
    elif args.parallel:
        _cpu_count = os.cpu_count() or 1
        _effective_workers = args.parallel_workers or _cpu_count
        print(
            f"--parallel : {_effective_workers} worker(s) effectif(s) (os.cpu_count()={_cpu_count} sur cette machine)."
        )
        if _effective_workers <= 1:
            print(
                "  Avec un seul worker effectif, aucun gain de temps reel n'est a "
                "attendre par rapport a une lecture sequentielle -- seulement le "
                "cout de mise en place du pool de processus. Le parallelisme "
                "n'aide que sur un hote disposant de plusieurs coeurs CPU "
                "disponibles."
            )
        elif args.parallel_workers and args.parallel_workers > _cpu_count:
            print(
                f"  ATTENTION : {args.parallel_workers} workers demandes pour "
                f"{_cpu_count} coeur(s) CPU disponible(s) -- au-dela du nombre "
                "de coeurs, les processus tshark se disputent le CPU au lieu "
                "de s'executer reellement en parallele, ce qui peut ralentir "
                "la lecture de chaque fichier individuellement plutot que "
                "l'accelerer."
            )
        all_packets, per_file_stats = parse_captures_parallel(captures, args.parallel_workers)
        # chaque fichier est rapporte explicitement, succes ou echec -- rien
        # ne doit pouvoir passer sous silence derriere un total agrege
        any_error = False
        for s in per_file_stats:
            if s["error"]:
                any_error = True
                print(
                    f"[{s['label']}] ECHEC sur {s['path']} : {s['error']}",
                    file=sys.stderr,
                )
            else:
                print(f"[{s['label']}] {s['count']} paquets charges depuis {s['path']} ({s['seconds']:.2f}s)")
        total_seconds = sum(s["seconds"] for s in per_file_stats if s["seconds"] is not None)
        print(
            f"Temps de lecture cumule (somme des fichiers) : {total_seconds:.2f}s "
            f"-- temps reel ecoule inferieur si le parallelisme a effectivement joue "
            f"(depend du nombre de coeurs disponibles)"
        )
        if any_error:
            print(
                "\nATTENTION : au moins un fichier n'a pas pu etre lu (voir ECHEC "
                "ci-dessus) -- l'analyse continue sur les fichiers restants, mais le "
                "resultat est incomplet.",
                file=sys.stderr,
            )
    else:
        for label, path in captures:
            pkts = parse_capture(label, path)
            print(f"[{label}] {len(pkts)} paquets IP/TCP/UDP/ICMP charges depuis {path}")
            all_packets.extend(pkts)

    if args.redact:
        redactor = redact_packets(all_packets)
        print(f"\n{len(redactor)} adresse(s) anonymisee(s) (IP/MAC) avant analyse.")
        if args.redact_map:
            write_redaction_map_csv(redactor, args.redact_map)
            print(
                f"Correspondance adresse reelle <-> pseudonyme ecrite dans {args.redact_map} "
                "(a conserver en prive, ne pas transmettre avec le rapport)."
            )

    points_order = args.order.split(",") if args.order else None
    flows = correlate(all_packets, args.nat_tolerant, args.nat_window_ms)
    r = analyse(
        flows,
        points_order,
        all_packets,
        args.bucket_ms / 1000.0,
        args.nat_tolerant,
        args.rtp_clock_rate,
        args.topn_charts,
        idle_timeout_seconds=args.idle_timeout_seconds,
    )
    print_report(r)

    if client_group:
        comparison = compare_clients(
            all_packets,
            client_group,
            reference=args.client_reference,
            points_order=points_order,
            bucket_seconds=args.bucket_ms / 1000.0,
            nat_tolerant=args.nat_tolerant,
            nat_window_ms=args.nat_window_ms,
            rtp_clock_rate=args.rtp_clock_rate,
        )
        print_client_comparison(comparison)
        if args.client_diff_csv:
            write_client_diff_csv(comparison, args.client_diff_csv)
            print(f"\nDetail de la comparaison client vs client ecrit dans {args.client_diff_csv}")

    findings = None
    tls_findings = None
    quic_findings = None
    if args.triage or args.pdf_report or args.json_report or args.history_db or args.expert_section:
        # calcule dans tous les cas si --pdf-report/--json-report/--history-db :
        # les trois integrent desormais le meme classement en tete (voir
        # netcross_report.pdf / netcross_report.json_report / netcross_report.history)
        from netcross_report import build_findings, format_health_line, health_score, print_triage, rank_segments

        findings = build_findings(r)
        if args.triage:
            ranked = rank_segments(findings)
            print_triage(ranked, args.triage_top_n)
            print(format_health_line(health_score(ranked)))

    rule_engine_findings = None
    if args.rule_engine:
        from netcross_report import available_rule_ids, evaluate

        rule_engine_findings = {}
        total = 0
        print("\n" + "=" * 70)
        print("MOTEUR DE REGLES DECLARATIF (rule_engine)")
        print("=" * 70)
        for rule_id in available_rule_ids():
            rule_findings = evaluate(rule_id, r)
            rule_engine_findings[rule_id] = rule_findings
            if rule_findings:
                total += len(rule_findings)
                for f in rule_findings:
                    print(f"  [{f.severity}] {f.category} / {f.segment} -- {f.message}")
        print(f"\n{len(available_rule_ids())} regles evaluees, {total} Finding produits.")
        if not args.json_report:
            print("(utilisez --json-report pour obtenir la sortie JSON structuree)")

    if args.tls or args.quic:
        print("\n" + "=" * 70)
        print("DIAGNOSTICS TLS/QUIC (pipeline de decodage independant, relit les memes fichiers)")
        print("=" * 70)

    if args.tls:
        from netcross_core.tls_diagnostics import (
            build_handshake_status,
            diagnose_tls,
            parse_tls_capture,
            print_tls_diagnostics,
        )

        tls_events = []
        for label, path in captures:
            events = parse_tls_capture(label, path)
            print(f"[{label}] {len(events)} evenements TLS trouves dans {path}")
            tls_events.extend(events)
        status_by_point = build_handshake_status(tls_events)
        tls_findings = diagnose_tls(status_by_point, r.points)
        print_tls_diagnostics(tls_findings)

    if args.quic:
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )
        except ImportError:
            print(
                "\n--quic necessite cryptography : pip install cryptography --break-system-packages",
                file=sys.stderr,
            )
            sys.exit(1)
        quic_events = []
        for label, path in captures:
            events = parse_quic_capture(label, path)
            print(f"[{label}] {len(events)} paquets QUIC Initial trouves dans {path}")
            quic_events.extend(events)
        quic_findings = diagnose_quic(quic_events, r.points)
        print_quic_diagnostics(quic_findings)

    if args.detail_csv:
        write_detail_csv(args.detail_csv, flows, r.points, names=names)
        print(f"\nDetail par flux ecrit dans {args.detail_csv}")

    # Objets de contrat de la Session 0 (FEATURES.md section 13.3) --
    # construits UNE fois ici, puis partages par la console
    # (--expert-section), le PDF et le JSON. Avant l'issue #13, ce bloc
    # vivait sous `if args.json_report:` et n'etait donc visible que la :
    # voir netcross_report.session_objects pour l'extraction (meme
    # sequence d'appels, aucun calcul nouveau).
    session_objects = None
    if args.expert_section or args.pdf_report or args.json_report:
        from netcross_report.session_objects import build_session_objects, print_session_objects

        session_objects = build_session_objects(r, findings, flows, all_packets)
        if args.expert_section:
            print()
            print_session_objects(session_objects)

    # Vues de sequence (Job 14/issue #11) : construites seulement si un PDF
    # est demande ET l'option passee -- elles repartent des Pkt bruts deja
    # groupes par correlate(), donc aucun reparse, mais aucune raison de les
    # calculer pour rien.
    sequence_views = None
    if args.sequence_diagram and args.pdf_report:
        from netcross_report.sequence_view import top_flow_views

        sequence_views = top_flow_views(
            flows,
            flow_objects=session_objects.flows if session_objects else None,
            max_flows=args.sequence_diagram,
        )

    if args.pdf_report:
        try:
            from netcross_report import generate_pdf
        except ImportError:
            generate_pdf = None
        if generate_pdf is None:
            print(
                "\n--pdf-report necessite reportlab, matplotlib et networkx : "
                "pip install reportlab matplotlib networkx --break-system-packages",
                file=sys.stderr,
            )
            sys.exit(1)
        generate_pdf(
            r,
            args.pdf_report,
            findings=findings,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            session_objects=session_objects,
            sequence_views=sequence_views,
            meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
        )
        print(f"Rapport PDF ecrit dans {args.pdf_report}")

    if args.json_report:
        from netcross_report import generate_json_report

        # Memes objets que ci-dessus (construits une seule fois) : les
        # cles JSON produites sont inchangees par rapport aux sessions
        # precedentes -- voir netcross_report.session_objects.json_kwargs().
        generate_json_report(
            r,
            args.json_report,
            findings=findings,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            rule_engine_findings=rule_engine_findings,
            meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
            names=names,
            **session_objects.json_kwargs(),
        )
        print(f"Rapport JSON ecrit dans {args.json_report}")

    if args.history_db:
        from netcross_report import list_history, print_history, record_run

        record_run(
            r,
            args.history_db,
            findings=findings,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            meta={"Anonymisation": "adresses IP/MAC anonymisees (--redact)"} if args.redact else None,
            label=args.history_label,
        )
        label_txt = f" (etiquette: {args.history_label})" if args.history_label else ""
        print(f"\nResume de ce run enregistre dans l'historique {args.history_db}{label_txt}.")
        if args.history_show is not None:
            entries = list_history(args.history_db, limit=args.history_show, label=args.history_label)
            print_history(entries)


if __name__ == "__main__":
    main()

"""Remplit les .po fr_FR (msgstr=msgid) et en_US (traductions)."""
import re

TRANSLATIONS = {
    "netcross-gtk4": {
        "Enregistrer le filtre": "Save filter",
        "Ajouter une capture": "Add capture",
        "Ajouter un point de capture": "Add capture point",
        "Lancer l'analyse": "Run analysis",
        "Arreter et analyser": "Stop and analyze",
        "Reinitialiser la selection": "Reset selection",
        "Exporter CSV": "Export CSV",
        "Exporter JSON": "Export JSON",
        "Fichiers max :": "Max files:",
        "Duree/fichier (s) :": "Duration/file (s):",
        "Options d'analyse": "Analysis options",
        "Fenetre temporelle (ms):": "Time window (ms):",
        "Cadence RTP (Hz):": "RTP clock rate (Hz):",
        "Seuil doublons (ms):": "Duplicate threshold (ms):",
        "Top": "Top",
        "Top-N graphiques": "Top-N charts",
        "Seuil pertes (points de %):": "Loss threshold (pp):",
        "Seuil latence (ms):": "Latency threshold (ms):",
        "Avancement": "Progress",
        "Resultats": "Results",
        "Protocole": "Protocol",
        "Top-N aretes": "Top-N edges",
        "Grouper par": "Group by",
        "Trier par": "Sort by",
        "Top-N": "Top-N",
        "(lancer une analyse pour voir les statistiques)": "(run an analysis to see statistics)",
        "Nom du point de capture (ex: LAN, WAN, DC)": "Capture point name (e.g.: LAN, WAN, DC)",
        "Monter (ordre = chemin physique reseau)": "Move up (order = physical network path)",
        "Descendre": "Move down",
        "Retirer cette capture": "Remove this capture",
        "Retirer ce point de capture": "Remove this capture point",
        "Enregistrer le filtre BPF courant sous un nom": "Save current BPF filter under a name",
        "Necessite cryptography. Relit les memes fichiers.": "Requires cryptography. Re-reads the same files.",
        "Necessite cryptography. Idem TLS, baseline et courant separement.": "Requires cryptography. Same as TLS, baseline and current separately.",
        "Duree maximale atteinte -- arret automatique de la capture.": "Maximum duration reached -- automatic capture stop.",
        "--redact n'est pas disponible avec Diagnostic TLS/QUIC (voir netcross_core.redact).": "--redact is not available with TLS/QUIC diagnostics (see netcross_core.redact).",
        "Correlation des flux entre points de capture...": "Correlating flows between capture points...",
        "Mise en forme du rapport...": "Formatting report...",
        "Triage des segments...": "Triage of segments...",
        "Analyse terminee.": "Analysis complete.",
    },
    "netcross-report": {
        "Rapport de securite": "Security report",
        "Tableau de bord": "Dashboard",
        "Services detectes": "Detected services",
        "Chemin observe": "Observed path",
        "Sequence des echanges": "Exchange sequence",
        "Expertise -- objets enrichis": "Expertise -- enriched objects",
        "Evenements d'expertise": "Expertise events",
        "Diagnostics par segment": "Per-segment diagnostics",
        "Conformite aux referentiels": "Compliance with reference standards",
        "Flux correles": "Correlated flows",
        "Expertise tshark (signaux bruts)": "tshark expertise (raw signals)",
        "Par ou commencer": "Where to start",
        "Synthese": "Summary",
        "Vue d'ensemble": "Overview",
        "Topologie deduite": "Inferred topology",
        "Evolution temporelle (top-N)": "Temporal evolution (top-N)",
        "Detail par module": "Per-module detail",
        "Sauts de routeur (delta TTL)": "Router hops (TTL delta)",
        "QoS (DSCP)": "QoS (DSCP)",
        "Fragmentation / MTU": "Fragmentation / MTU",
        "Segment": "Segment",
        "Score": "Score",
        "Categories touchees": "Affected categories",
        "Constats": "Findings",
        "Trame": "Frame",
        "t (ms)": "t (ms)",
        "Delta (ms)": "Delta (ms)",
        "Source -> Destination": "Source -> Destination",
        "Point": "Point",
        "Octets": "Bytes",
        "Detail": "Detail",
        "Gravite": "Severity",
        "CVE": "CVE",
        "CVSS": "CVSS",
        "Service": "Service",
        "Cible": "Target",
        "Empreinte JA4/HASSH": "JA4/HASSH fingerprint",
        "Criticite": "Criticality",
        "Points": "Points",
        "Aucun constat notable.": "No notable finding.",
        "Aucun evenement d'expertise.": "No expertise event.",
        "Aucun diagnostic par segment.": "No per-segment diagnosis.",
        "Aucun referentiel evalue.": "No reference standard evaluated.",
        "Aucun flux correle.": "No correlated flow.",
        "Aucun segment exploitable : ni topologie deduite, ni couple de points fourni.": "No usable segment: no inferred topology, no point pair provided.",
        "Score de risque": "Risk score",
        "Tentatives d'exploitation": "Exploitation attempts",
        "Anomalies (Expert Info)": "Anomalies (Expert Info)",
        "CVE confirmees": "Confirmed CVEs",
        "Score de sante": "Health score",
        "RAPPORT DE SECURITE": "SECURITY REPORT",
        "exploits detectes": "exploits detected",
        "anomalies (Expert Info)": "anomalies (Expert Info)",
        "score de risque global": "global risk score",
        "critique": "critical",
        "elevee": "high",
        "moyenne": "medium",
        "faible": "low",
        "TRIAGE -- top segments a regarder en premier": "TRIAGE -- top segments to review first",
        "Aucun segment avec un score de preuve suffisant.": "No segment with sufficient evidence score.",
        "Sain": "Healthy",
        "Degrade": "Degraded",
        "Critique": "Critical",
        "Saturation": "Saturation",
        "Bufferbloat": "Bufferbloat",
    },
    "netcross-cli": {
        "ECHEC du decoupage": "Splitting failed",
        "ERREUR sur": "Error on",
        "--quic necessite cryptography": "--quic requires cryptography",
        "--export-pcap": "--export-pcap",
        "--adjust-time": "--adjust-time",
        "base CVE introuvable": "CVE database not found",
        "--cve-db necessite --security-report": "--cve-db requires --security-report",
        "--security-report n'est pas disponible avec --live": "--security-report is not available with --live",
        "--security-report n'est pas disponible avec --redact": "--security-report is not available with --redact",
        "--security-report n'est pas disponible avec --merge": "--security-report is not available with --merge",
        "signature(s) d'exploit detectee(s) dans": "exploit signature(s) detected in",
        "RAPPORT DE SECURITE": "SECURITY REPORT",
        "Aucune base CVE fournie (--cve-db)": "No CVE database provided (--cve-db)",
        "aucun constat": "no finding",
        "aucune tentative d'exploitation detectee": "no exploitation attempt detected",
        "aucune CVE confirmee": "no confirmed CVE",
    },
}


def fill_po(fpath, translations):
    with open(fpath, "r") as f:
        lines = f.readlines()

    result = []
    i = 0
    filled = 0
    while i < len(lines):
        line = lines[i]
        # Match msgid "..."
        m = re.match(r'^msgid "(.*)"\n$', line)
        if m and i + 1 < len(lines):
            msgid = m.group(1)
            next_line = lines[i + 1]
            if next_line.strip() == 'msgstr ""':
                result.append(line)
                if msgid in translations:
                    result.append(f'msgstr "{translations[msgid]}"\n')
                    filled += 1
                else:
                    result.append(next_line)
                i += 2
                continue
        result.append(line)
        i += 1

    with open(fpath, "w") as f:
        f.writelines(result)
    return filled


# fr_FR: msgstr = msgid (reference language)
for domain in ["netcross-gtk4", "netcross-report", "netcross-cli"]:
    fpath = f"locale/fr_FR/LC_MESSAGES/{domain}.po"
    with open(fpath, "r") as f:
        content = f.read()

    # Fill empty msgstr with the msgid value
    lines = content.split("\n")
    result = []
    i = 0
    filled = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^msgid "(.*)"$', line)
        if m and i + 1 < len(lines) and lines[i + 1].strip() == 'msgstr ""':
            msgid = m.group(1)
            result.append(line)
            result.append(f'msgstr "{msgid}"')
            filled += 1
            i += 2
            continue
        result.append(line)
        i += 1

    with open(fpath, "w") as f:
        f.write("\n".join(result))
    print(f"  fr_FR/{domain}: {filled} msgstr remplis")

# en_US: msgstr = English translation
for domain, translations in TRANSLATIONS.items():
    fpath = f"locale/en_US/LC_MESSAGES/{domain}.po"
    filled = fill_po(fpath, translations)
    print(f"  en_US/{domain}: {filled} msgstr remplis")

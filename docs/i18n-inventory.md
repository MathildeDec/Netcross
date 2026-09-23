# Inventaire i18n — issue #299

## État actuel

- **gettext** : non utilisé (aucun import `gettext` dans `src/`)
- **Fichiers .po/.mo/.pot** : aucun
- **Répertoire locale/** : inexistant
- **Tous les textes sont en français codé en dur**

## Inventaire GTK4 (`src/netcross_gtk4/`)

### app.py — 65 chaînes littérales + 21 messages utilisateur

**Boutons (Gtk.Button)**
- "Enregistrer le filtre"
- "Ajouter une capture"
- "Ajouter un point de capture"
- "Lancer l'analyse"
- "Arreter et analyser"
- "Reinitialiser la selection"
- "Exporter CSV"
- "Exporter JSON"

**Labels (Gtk.Label)**
- "Fichiers max :", "Duree/fichier (s) :"
- "Options d'analyse"
- "Fenetre temporelle (ms):", "Cadence RTP (Hz):", "Seuil doublons (ms):"
- "Top", "Top-N graphiques"
- "Seuil pertes (points de %):", "Seuil latence (ms):"
- "Avancement", "Resultats"
- "Protocole", "Top-N aretes"
- "Grouper par", "Trier par", "Top-N"
- "(lancer une analyse pour voir les statistiques)"

**Tooltips (set_tooltip_text)**
- "Nom du point de capture (ex: LAN, WAN, DC)"
- "Monter (ordre = chemin physique reseau)"
- "Descendre"
- "Retirer cette capture" / "Retirer ce point de capture"
- "Enregistrer le filtre BPF courant sous un nom"
- "Necessite cryptography. Relit les memes fichiers."
- "Necessite cryptography. Idem TLS, baseline et courant separement."

**Messages utilisateur (self._log / status_label)**
- "Duree maximale atteinte -- arret automatique de la capture."
- "--redact n'est pas disponible avec Diagnostic TLS/QUIC..."
- "[{label}] {count} paquets..."
- "[{label}] ERREUR : {e}"
- "[{label}] capture arretee -- {count} paquet(s) au total."
- "Correlation des flux entre points de capture..."
- "Mise en forme du rapport..."
- "Triage des segments..."
- "Analyse terminee."
- "ERREUR : {e}"
- "Lecture de {file} ({label})..."
- "{count} paquets dupliqué(s) détecté(s)"
- "{count} flux identifies"

### Autres modules GTK4 : 0 chaîne littérale (logique pure)

**Total GTK4 : ~86 chaînes à traduire**

## Inventaire Rapports (`src/netcross_report/`)

### pdf.py — 55 Paragraph + 23 en-têtes de tableau

**Titres de sections (H1b/H2b)**
- "Rapport de securite", "Tableau de bord"
- "Services detectes", "Chemin observe"
- "Sequence des echanges", "Expertise -- objets enrichis"
- "Evenements d'expertise", "Diagnostics par segment"
- "Conformite aux referentiels", "Flux correles"
- "Expertise tshark (signaux bruts)"
- "Par ou commencer", "Synthese", "Vue d'ensemble"
- "Topologie deduite", "Evolution temporelle (top-N)"
- "Detail par module", "Sauts de routeur (delta TTL)"
- "QoS (DSCP)", "Fragmentation / MTU"

**En-têtes de tableau**
- ["Segment", "Score", "Categories touchees", "Constats"]
- ["Trame", "t (ms)", "Delta (ms)", "Source -> Destination", "Point", "Octets", "Detail"]
- ["Gravite", "CVE", "CVSS", "Detail", "Service", "Cible", "Point"]
- ["Criticite", "Service", "Cible", "Empreinte JA4/HASSH", "CVE", "Points"]

**Messages "Aucun..."**
- "Aucun constat notable.", "Aucun evenement d'expertise."
- "Aucun diagnostic par segment.", "Aucun referentiel evalue."
- "Aucun flux correle.", "Aucun segment exploitable..."

**Labels dashboard**
- "Score de risque", "Services detectes"
- "Tentatives d'exploitation", "Anomalies (Expert Info)"
- "CVE confirmees", "Score de sante : {score}/100"

### security_report.py — 16 chaînes

**Sévérités (constantes)**
- "critique", "elevee", "moyenne", "faible" (SEVERITIES)
- "exploit", "anomalie", "cve" (categories)

**Format texte**
- "score de risque global : ..."
- "services detectes : ..."
- "exploits detectes : ..."
- "anomalies (Expert Info) : ..."
- "CVE confirmees : ..."
- "RAPPORT DE SECURITE"

### synthesis.py — 19 chaînes (verdicts de findings)
- "{n} paquets manquants a ce point ({rate:.1f}% des flux vus)"
- "latence {low}ms a faible charge vs {high}ms a forte charge"
- "{n} flux avec nombre de sauts different (ECMP/re-routage)"
- "{n} flux avec TTL variable (routage asymetrique possible)"
- "{n} paquets avec DSCP modifie..."
- "{n} flux avec priorite 802.1p (PCP) modifiee"
- "{n} datagrammes fragmentes..."
- "{n} messages ICMP Fragmentation Needed observes"
- "{n} messages ICMPv6 Packet Too Big observes"
- "Saturation", "Bufferbloat"

### rule_engine.py — 21 chaînes
- "regle inconnue du catalogue expert_rules : {rule_id!r}"
- "regle {rule_id!r} presente dans le catalogue mais sans evaluateur"
- Messages de conformité (OK/KO/N/A)

### triage.py — 9 chaînes
- "TRIAGE -- top {top_n} segments a regarder en premier"
- "Aucun segment avec un score de preuve suffisant."
- "{rank}. {segment} -- score {score:.1f}"
- HEALTH_LABELS : "Sain", "Degrade", "Critique"

### json_report.py — 15 chaînes (titres/clés)
- "Analyse croisee de captures reseau"
- "Comparaison avant / apres"

### security_html.py — 12 chaînes (HTML)
- Badges, en-têtes de table, messages "vide"

### Autres modules
- history.py : 7 chaînes (messages d'erreur base de données)
- path_metrics.py : 8 chaînes (labels de métriques)
- session_objects.py : 5 chaînes
- siem_export.py : 2 chaînes (vendor/product constants)
- charts.py : 2 chaînes

**Total Rapports : ~191 chaînes à traduire**

## CLI (`cross_capture_analyzer_cli.py` + `cross_capture_diff_cli.py`)

**90 messages utilisateur** (print stdout/stderr)
- Messages d'erreur, d'aide, de progression
- Exemples : "ECHEC du decoupage", "ERREUR sur {path}", "--quic necessite cryptography"

## Récapitulatif

| Catégorie | Modules | Chaînes à traduire |
|-----------|---------|-------------------|
| GTK4 | app.py (principal) | ~86 |
| Rapports PDF | pdf.py | ~78 |
| Rapports sécurité | security_report.py, security_html.py | ~28 |
| Rapports synthèse | synthesis.py | ~19 |
| Rapports règles | rule_engine.py | ~21 |
| Rapports triage | triage.py | ~9 |
| Rapports JSON | json_report.py | ~15 |
| Autres rapports | history, path_metrics, etc. | ~24 |
| CLI | analyzer_cli, diff_cli | ~90 |
| **Total** | **~20 modules** | **~370 chaînes** |

## Plan d'action proposé

1. **Infrastructure gettext** : créer `src/netcross_core/i18n.py` avec `setup_gettext()` + `_()` alias
2. **Fichier .pot** : extraire toutes les chaînes avec `xgettext` ou script Python
3. **Fichier .po français** : traduction de référence (fr_FR)
4. **Fichier .po anglais** : traduction anglaise (en_US)
5. **Compilation .mo** : `msgfmt` pour fr_FR et en_US
6. **Câblage GTK4** : wrapper `_()` autour de chaque chaîne littérale dans app.py
7. **Câblage rapports** : wrapper `_()` dans pdf.py, security_report.py, synthesis.py, etc.
8. **Tests** : vérifier que les chaînes sont bien marquées pour traduction

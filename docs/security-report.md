# Rapport de sécurité consolidé (CVE-5, issue #139)

`--security-report` de `cross_capture_analyzer_cli.py` produit un rapport texte
qui consolide les modules de détection passive de vulnérabilités (parent #133) :

| Section | Source | Module |
|---|---|---|
| Services détectés (version, criticité) | bannières lues sur le fil (CVE-1, #135) | `netcross_core.application.banners` |
| Tentatives d'exploitation | signatures Log4Shell, Shellshock, Heartbleed, EternalBlue, compression TLS (CVE-2, #136) | `netcross_core.exploit_signatures` |
| Anomalies | alertes Expert Info corrélées : fuzzing, overflow, dos (CVE-3, #137) | `netcross_core.security.expert_correlation` |
| Anomalies | tunneling DNS : sous-domaines à haute entropie, labels/noms trop longs, volume DNS anormal (FLOW-3, #144) | `netcross_core.security.dns_tunnel` |
| Anomalies | exfiltration : transferts sortants volumineux/asymétriques vers l'extérieur, corrélés au beaconing et au tunneling DNS, score de risque 0-100 (SCENARIO-2, #148) | `netcross_core.security.exfiltration` |
| Anomalies | audit des certificats TLS : expirés, auto-signés, MD5/SHA-1, clés faibles, validité excessive, chaîne incomplète, noms suspects, avec un score de risque TLS par serveur (SCENARIO-7, #153) | `netcross_core.security.tls_audit` |
| CVE confirmées | version exacte + CVE-ID + score CVSS (CVE-4, #138) | `netcross_core.security` (base SQLite locale) |
| Inventaire d'actifs | hôtes vus (IP, MAC, OS déduit du TTL et des options TCP, ports exposés confirmés, points), nouveaux hôtes par rapport à la baseline `--known-hosts` (SCENARIO-5, #151, #350) | `netcross_core.discovery.assets` |

Le tout est classé par sévérité (critique / élevée / moyenne / faible) et résumé par un
tableau de bord (nombre de services vulnérables, d'exploits, d'anomalies, de CVE, score de
risque global 0-100).

## Utilisation

```bash
# Base CVE locale (hors ligne au runtime), une fois :
python3 scripts/import_nvd.py --db data/cve.db --fetch --keyword apache

python3 src/cross_capture_analyzer_cli.py \\
    --capture DMZ=dmz.pcap --capture LAN=lan.pcap \\
    --security-report --cve-db data/cve.db
```

- Sans `--cve-db`, les services sont listés sans corrélation CVE ; le CLI le signale
  (« aucune vulnérabilité connue » ne veut alors pas dire « non vulnérable »).
- `--cve-db` doit désigner un fichier existant (refusé sinon, pour ne pas créer une base vide).
- Refusé avec `--live` et `--redact` : les signatures d'exploits sont cherchées dans la
  charge utile brute, relue depuis les fichiers `--capture` (comme `--tls`), donc jamais
  depuis des paquets anonymisés ou capturés en direct. Refusé aussi avec `--merge`/`--replay`.
- `--known-hosts hotes.json` (avec `--security-report`) : baseline des hôtes connus, liste JSON
  d'IP (`["10.0.0.1", "10.0.0.2"]`) ou objet `{"hosts": [...]}`. Chaque hôte de la capture absent
  de la liste est marqué `[NOUVEAU]` dans la section « Inventaire d'actifs » et produit un constat
  de sévérité moyenne (détecteur `asset_inventory`), donc aussi un événement dans l'export SIEM
  (`--siem-export cef|leef|stix`). Sans baseline, aucun hôte n'est signalé nouveau ; un fichier
  absent, illisible ou vide est refusé (sinon tous les hôtes passeraient pour nouveaux).
  L'inventaire complet est dans la clé `security_report.assets` du JSON et dans le HTML.
- `--test-net-external` (avec `--security-report`) : traite les plages de documentation TEST-NET
  (RFC 5737 : 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) comme externes pour le beaconing et
  l'exfiltration. Par défaut elles sont internes, comme pour `ipaddress` : une capture de
  démonstration qui les utilise ne lève alors aucune alerte (issue #365, voir
  [Détecteurs](detectors.md)).

## Architecture

```
Pkt.service_banners ──► build_service_fingerprints ──► Report.service_fingerprints ─┐
RawPacket (charge utile) ► exploit_signatures.detect_exploits ► exploit_findings ──┤
Report.exploit_suspicion_flows ───────────────────► anomaly_findings ─────────────┤
Pkt (champs dns_*) ► dns_tunnel.detect_dns_tunneling ► dns_tunnel_findings ───────┼► Report.security_findings
Pkt (champs tls_cert_*) ► tls_audit.audit_tls_certificates ► tls_audit_findings ───┤
service/version ──► security.correlate_banner ────► cve_findings ─────────────────┘            │
                                                                                                ▼
                                                              netcross_report.security_report (rendu texte)
```

`netcross_core.security.findings.apply_security_findings()` assemble les listes de
constats (remplacement, pas ajout : deux appels donnent le même résultat).
`netcross_report.security_report` ne détecte rien, il regroupe, classe et met en forme.

## Choix de sévérité (prudents, documentés dans `findings.py`)

- **Exploit** : `anomalie` → élevée, `a_surveiller` → moyenne, `info` → faible. Une
  signature est une *tentative observée*, pas une compromission confirmée : « critique »
  reste réservé aux CVE confirmées à CVSS ≥ 9.
- **Anomalie Expert Info** : toujours moyenne. Fuzzing/overflow/dos sont des *indices* à
  confirmer (un équipement bogue ou une capture tronquée produisent aussi des paquets
  malformés) ; les paquets malformés isolés ne sont jamais remontés.
- **Tunneling DNS** (`dns_tunnel.py`, seuils dans `DnsTunnelThresholds`) : par point puis par
  domaine enregistré. Signaux *forts* (label > 63 car., ≥ 3 noms > 100 car., ≥ 10 sous-domaines
  distincts d'entropie de Shannon moyenne ≥ 3,6 bits/car.) → moyenne ; des signaux *faibles*
  corroborants (réponses > 512 octets, domaine > 80 % des requêtes, requêtes à intervalles
  réguliers) → élevée. Les signaux faibles seuls ne lèvent rien. Le ratio DNS/trafic d'un point
  > 50 % (≥ 50 paquets DNS) est un constat distinct, faible (une capture filtrée sur le DNS le
  déclenche naturellement). Limite : le type d'enregistrement (TXT…) n'est pas décodé par `Pkt`,
  « TXT > 100 octets » est approximé par la taille de la réponse. `detect_dns_tunneling(...).domain_entropy`
  donne le score d'entropie de Shannon de chaque domaine interrogé (suspect ou non).
- **Audit des certificats TLS** (`tls_audit.py`, politique dans `TlsAuditPolicy`) : appliqué au
  certificat *feuille* de chaque serveur (couple IP/port qui l'émet), un constat par certificat
  distinct et par problème. Dates comparées à l'horodatage du **paquet**, jamais à l'heure actuelle
  (une vieille capture reste correcte).

  | Contrôle | Sévérité par défaut |
  |---|---|
  | certificat expiré (`notAfter` < date de capture) | élevée |
  | signature MD2/MD4/MD5 · clé RSA/DSA < 2048 bits ou EC < 256 bits | élevée |
  | pas encore valide · auto-signé (émetteur == sujet) · signature SHA-1 · joker trop large (`*`, `*.com`) | moyenne |
  | validité > 398 jours · chaîne incomplète (feuille sans intermédiaire) · wildcard · IP dans le SAN · nom > 100 car. · nom d'apparence aléatoire | faible |

  Jamais « critique » (réservé aux CVE confirmées). Le **score de risque par serveur** (0-100) est la
  somme de 30/15/5 points par problème distinct (élevée/moyenne/faible) de chaque certificat distinct,
  plafonnée à 100 ; il est rappelé dans le détail de chaque constat, et
  `audit_tls_certificates(...).servers` le donne pour tous les serveurs (score 0 inclus). La politique
  permet de changer les seuils (`max_validity_days`, `min_rsa_bits`, `min_ec_bits`…), de remplacer une
  sévérité (`severities`) ou de désactiver un contrôle (`disabled`) ; elle se passe à
  `apply_security_findings(..., tls_policy=...)`. Le plafond de 398 jours est celui du CA/B Forum
  depuis 2020 ; il ne s'applique qu'aux certificats publiquement approuvés et baisse par paliers
  (200 jours depuis le 15/03/2026, 100 en 2027, 47 en 2029) — d'où un seuil configurable et une
  sévérité faible.
- **Exfiltration** (`exfiltration.py`, seuils dans `ExfiltrationThresholds`) : par point puis par
  couple orienté (source, destination), **uniquement** d'une source non routable (RFC 1918, ULA…)
  vers une destination routable globalement — un téléchargement entrant ou une sauvegarde vers un
  NAS interne ne lèvent donc rien. Signaux *forts* : octets envoyés > 10 Mo, ou envoi/réception
  > 10:1 avec au moins 1 Mo envoyé (le plancher écarte un POST de formulaire). Signaux *faibles*
  (n'aggravent qu'une alerte déjà levée) : ≥ 50 % des octets hors 8h-18h UTC, destination absente
  de la baseline `--known-destinations` (liste JSON d'IP ; sans baseline, jamais émis), plus de
  1 Mo en DNS/ICMP, même hôte en beaconing vers la même destination (#147), même hôte interrogeant
  un domaine suspect de tunneling DNS (#144). Score de risque 0-100 (volume 35, ratio 25, horaire
  10, destination/protocole/corrélations 15 chacun) : ≥ 60 → élevée, sinon moyenne. Détail complet
  dans `Report.exfiltration_alerts`. Limite : « HTTP POST vers un stockage cloud » n'est pas
  identifié comme tel (corps HTTP non disponible), il remonte par le volume et le ratio.
- **CVE** : sévérité NVD reprise telle quelle (repli sur les tranches CVSS v3).

## Aucun faux positif sur trafic normal

- une CVE n'est rattachée qu'au service dont la bannière `service/version` l'a produite
  (nom **et** version exacts, hôte/port quand ils sont connus) — jamais depuis le texte source
  complet, qui peut citer plusieurs produits ;
- un service sans version, un produit hors catalogue ou une version corrigée ne produisent
  aucune CVE ;
- sans détection, sans suspicion et sans CVE applicable, le rapport est vide (score 0).

Voir `tests/test_security_findings.py` (trafic HTTP/TLS/DNS légitime, version corrigée,
paquet malformé isolé, CLI de bout en bout).

## Sorties (issue #218)

Le rapport de sécurité existait uniquement en texte sur la sortie
standard. Il alimente désormais quatre rendus, tous construits sur le
**même socle** `security_report_to_dict()` — trois sérialisations
indépendantes divergeraient au premier champ ajouté, et c'est exactement
ce qui a produit l'issue #259.

```bash
netcross --capture POINT_A=a.pcap --security-report \
         --security-html rapport-secu.html \
         --json-report rapport.json \
         --pdf-report rapport.pdf
```

| Sortie | Forme lisible des empreintes | Notes |
|---|---|---|
| **Texte** (stdout) | tronquée à 120 caractères, `...` visible | rendu par défaut |
| **JSON** (`--json-report`, clé `security_report`) | **complète** | une sortie machine n'a pas de contrainte de largeur |
| **HTML** (`--security-html`) | complète, tableaux filtrables | fichier unique, sans ressource externe |
| **PDF** (`--pdf-report`) | tronquée à 90 caractères, `...` visible | section dédiée, tableaux plafonnés à 40 lignes avec le total réel écrit dessous |

### Ce que disent les sorties quand il n'y a rien à dire

Règle de traçabilité appliquée partout : une information absente est
écrite, pas omise.

- **Texte, HTML, PDF** : chaque section vide affiche son message
  (`aucune tentative d'exploitation detectee`), jamais une section
  escamotée. Une section absente fait douter de l'outil ; une section
  vide est un résultat d'analyse.
- **JSON sans `--security-report`** : la clé existe quand même, avec le
  motif.

  ```json
  {"security_report": null,
   "security_report_absent": "non demande (--security-report absent de l'appel)"}
  ```

  Sans cela, « non demandé », « demandé, rien trouvé » et « version de
  netcross qui ne produit pas cette clé » seraient indistinguables.
- **JSON avec `--security-report` mais sans constat** : un objet complet
  avec des listes vides et un score de 0 — ce qui est un résultat, pas
  une absence.
- **PDF sans `--security-report`** : **aucune** section de sécurité. Une
  section vide laisserait croire qu'une analyse de sécurité a eu lieu
  sans rien trouver, alors qu'elle n'a pas tourné. `--security-html` et
  `--cve-db` sans `--security-report` sont refusés avec un message
  explicite plutôt que de produire un fichier vide.

### Le rendu HTML

Fichier unique, CSS et JavaScript inlinés, **aucune ressource externe** :
un rapport d'incident est archivé dans un ticket et relu des mois plus
tard, parfois sur un poste isolé. Une dépendance à un CDN en ferait une
page cassée au moment précis où on la ressort.

**Aucune donnée n'est interpolée dans du JavaScript.** Un rapport de
sécurité contient par construction des chaînes hostiles — bannière
forgée, détail d'exploit, nom d'hôte contrôlé par un attaquant. Le
filtrage côté client ne lit que le DOM déjà rendu et échappé.

Le mode sombre et l'impression sont pris en charge ; les teintes de
sévérité restent distinguables en niveaux de gris, et le libellé textuel
de la sévérité accompagne toujours la couleur.

## Limites connues

- **Audit TLS** : seuls les certificats visibles en clair sont audités. TLS 1.3 chiffre le message
  `Certificate` et une reprise de session n'en envoie pas : ces connexions sont invisibles sans clés
  (`SSLKEYLOGFILE`). La chaîne de confiance PKI et la révocation ne sont pas vérifiées (pas de
  magasin de confiance en capture passive). « Chaîne incomplète » est un indice faible : une
  feuille émise directement par une racine connue du client est légitime. Un certificat auto-signé
  est banal sur un équipement interne : ce sont des indices à confirmer. Les détails (émetteur,
  sujet, algorithme, clé, IP du SAN) sont lus dans le DER brut exposé par tshark
  (`pcap_parser.protocols.extract_tls_certificate`, via `cryptography`) ; sans ce DER, seuls les
  contrôles de dates et de noms DNS restent possibles.
- Pas de reassemblage TCP ni de déchiffrement TLS : un exploit dans un flux chiffré est
  invisible sans clés (voir `exploit_signatures`).
- Une bannière peut être masquée ou falsifiée (`ServerTokens Prod`) : l'absence de service
  détecté n'est pas une information.
- Rendu texte uniquement ; le `SecurityReport` est prêt à alimenter une sortie HTML/PDF.

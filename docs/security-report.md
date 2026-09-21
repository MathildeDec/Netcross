# Rapport de sécurité consolidé (CVE-5, issue #139)

`--security-report` de `cross_capture_analyzer_cli.py` produit un rapport texte
qui consolide les modules de détection passive de vulnérabilités (parent #133) :

| Section | Source | Module |
|---|---|---|
| Services détectés (version, criticité) | bannières lues sur le fil (CVE-1, #135) | `netcross_core.application.banners` |
| Tentatives d'exploitation | signatures Log4Shell, Shellshock, Heartbleed, EternalBlue, compression TLS (CVE-2, #136) | `netcross_core.exploit_signatures` |
| Anomalies | alertes Expert Info corrélées : fuzzing, overflow, dos (CVE-3, #137) | `netcross_core.security.expert_correlation` |
| Anomalies | tunneling DNS : sous-domaines à haute entropie, labels/noms trop longs, volume DNS anormal (FLOW-3, #144) | `netcross_core.security.dns_tunnel` |
| CVE confirmées | version exacte + CVE-ID + score CVSS (CVE-4, #138) | `netcross_core.security` (base SQLite locale) |

Le tout est classé par sévérité (critique / élevée / moyenne / faible) et résumé par un
tableau de bord (nombre de services vulnérables, d'exploits, d'anomalies, de CVE, score de
risque global 0-100).

## Utilisation

```bash
# Base CVE locale (hors ligne au runtime), une fois :
python3 scripts/import_nvd.py --db data/cve.db --fetch --keyword apache

python3 src/cross_capture_analyzer_cli.py \
    --capture DMZ=dmz.pcap --capture LAN=lan.pcap \
    --security-report --cve-db data/cve.db
```

- Sans `--cve-db`, les services sont listés sans corrélation CVE ; le CLI le signale
  (« aucune vulnérabilité connue » ne veut alors pas dire « non vulnérable »).
- `--cve-db` doit désigner un fichier existant (refusé sinon, pour ne pas créer une base vide).
- Refusé avec `--live` et `--redact` : les signatures d'exploits sont cherchées dans la
  charge utile brute, relue depuis les fichiers `--capture` (comme `--tls`), donc jamais
  depuis des paquets anonymisés ou capturés en direct. Refusé aussi avec `--merge`/`--replay`.

## Architecture

```
Pkt.service_banners ──► build_service_fingerprints ──► Report.service_fingerprints ─┐
RawPacket (charge utile) ► exploit_signatures.detect_exploits ► exploit_findings ──┤
Report.exploit_suspicion_flows ───────────────────► anomaly_findings ─────────────┤
Pkt (champs dns_*) ► dns_tunnel.detect_dns_tunneling ► dns_tunnel_findings ───────┼► Report.security_findings
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

## Limites connues

- Pas de reassemblage TCP ni de déchiffrement TLS : un exploit dans un flux chiffré est
  invisible sans clés (voir `exploit_signatures`).
- Une bannière peut être masquée ou falsifiée (`ServerTokens Prod`) : l'absence de service
  détecté n'est pas une information.
- Rendu texte uniquement ; le `SecurityReport` est prêt à alimenter une sortie HTML/PDF.

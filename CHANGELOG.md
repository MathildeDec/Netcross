# Changelog

Tous les changements notables du projet Netcross sont documentés dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et le projet adhère au [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

### Corrigé
- `export_filtered()` : `bpf_filter` est replié dans le filtre d'affichage
  `-Y` au lieu de `-f`, que tshark refuse en relecture de fichier — tout
  appel avec ce paramètre échouait systématiquement (#261)
- `export_filtered()` et `adjust_timestamps()` imposent `-F pcap`/`-F pcapng`
  selon l'extension de sortie : sans cela tshark et editcap écrivaient du
  pcapng dans un fichier nommé `.pcap` (#262)
- CI : `tshark`/`editcap` sont installés et la CI échoue si un test
  `@requires_tshark` reste sauté — 6 tests n'avaient jamais pu s'exécuter (#262)
- 3 assertions de test erronées, révélées par leur première exécution réelle

### Ajouté
- Dockerfile et .dockerignore pour déploiement conteneurisé (#170)
- CONTRIBUTING.md — guide de contribution (#170)
- SECURITY.md — politique de sécurité et reporting CVE (#170)
- `netcross_core/config.py` — loader de configuration `.netcross.toml` (#170)
- `netcross_report/siem_export.py` — export CEF pour intégration SIEM (#170)
- `netcross_core/support/` — remontée de tickets anonymisés avec consentement
  explicite : crash, erreurs de traitement, journal et contexte (#269)
- `netcross_core/support/scrubber.py` — anonymisation de texte libre (IP, MAC,
  emails, URL, FQDN, noms de capture, répertoires personnels, secrets), en
  complément de `redact.py` qui ne traite que les champs structurés (#269)
- Options CLI `--support-ticket`, `--support-consent`, `--support-scope`,
  `--support-map`, `--support-marker` (#269)
- `docs/support-tickets.md` — documentation de la remontée de tickets (#269)
- `scripts/generate_openapi.py --check` + vérification en CI de la fraîcheur de
  `docs/openapi.yaml` (#209)

## [1.0.0] — 2026-09-22

### Ajouté
- Analyse croisée multi-points de captures Wireshark (.pcap/.pcapng)
- Corrélation de flux entre points (pertes, latence, QoS, retransmissions)
- Détection de signatures d'exploits (CVE-1 à CVE-5)
- Empreintes de services et versions (bannières, JA4, HASSH)
- Détection de tunneling DNS, beaconing C2, mouvements latéraux
- Détection DGA et fast flux DNS
- Extraction de fichiers (file carving) depuis captures
- Rapports PDF, JSON, CSV, texte
- Interface GTK4
- API REST FastAPI + spécification OpenAPI (#209)
- Logging structuré via loguru (#245)
- Pipeline CI/CD complet (lint, tests, coverage, guard main)
- Statistiques de flux et conversation (#145)
- Audit TLS (#153), découverte d'actifs (#151)
- Conversion de formats (#169), exfiltration de données (#148)

### Sécurité
- Politique de sécurité et procédure de reporting CVE (SECURITY.md)

---

Les versions antérieures ne sont pas trackées dans ce fichier.
Le projet utilisait des releases GitHub ad-hoc avant la version 1.0.0.

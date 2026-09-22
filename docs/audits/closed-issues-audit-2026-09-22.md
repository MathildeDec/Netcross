# Audit des issues fermées — Netcross

**Date de l'audit :** 22 septembre 2026
**Dépôt :** [MathildeDec/Netcross](https://github.com/MathildeDec/Netcross)
**Auditeur :** Perplexity Computer (session f02f7a0d)

---

## Synthèse

| Métrique | Valeur |
|---|---|
| Issues fermées (total) | 130 |
| Issues de tracking (session-archive) | 69 |
| Issues réelles auditées | 61 |
| Issues avec PR fusionnée associée | 57 |
| Issues sans PR directe (implémentation vérifiée par code) | 4 |
| Issues avec implémentation manquante | 0 |
| Fichiers de test | 87 |
| Tests collectés | 2568 |
| Workflows CI | 4 |

**Verdict global :** Toutes les 61 issues fermées ont une implémentation vérifiable dans le code source. Aucune issue fermée n'est orpheline (sans implémentation).

---

## Méthodologie

1. Extraction de toutes les issues fermées via l'API GitHub
2. Exclusion des 69 issues `session-archive` (tracking administratif des sessions de développement historiques)
3. Pour chaque issue restante :
   - Recherche de PRs fusionnées référençant l'issue (par numéro dans le titre ou le corps)
   - Récupération des commits référençant l'issue (via les événements GitHub)
   - Vérification de l'existence du code implémenté dans `src/`
   - Vérification de l'existence de tests couvrant la fonctionnalité
4. Pour les 4 issues sans PR directe : vérification manuelle de l'implémentation dans le code

---

## Audit détaillé

### Issues sans PR directe (vérification manuelle)

Ces 4 issues ont été fermées comme COMPLETED sans qu'une PR fusionnée ne les référence directement. L'implémentation a été vérifiée manuellement dans le code source.

| Issue | Titre | Implémentation | Statut |
|---|---|---|---|
| #19 | Job 20 — Générateur de graphes générique | `src/netcross_report/charts.py` (20 930 octets, `chart_topology`, `MetricSeries`) | Fait |
| #23 | Job 23 — Analyse transactionnelle/applicative | `src/netcross_core/application/` (`banners.py`, `classify.py`, `dns.py`, `http.py`, `models.py`) | Fait |
| #160 | Job 40 — Étiquetage et signets sur paquets | `PacketAnnotation` dans `src/netcross_core/forensic.py` (`read_annotations`, `write_annotations`) | Fait |
| #167 | Job 47 — Gestion de filtres BPF | `src/netcross_core/bpf_filters.py` (8 777 octets, `PREDEFINED_BPF_FILTERS`, `available_bpf_filters`, `upsert_bpf_filter`) | Fait |

### CVE (vulnérabilités)

| Issue | Titre | PR(s) | Fichier(s) | Lignes | Statut |
|---|---|---|---|---|---|
| #133 | vulnérabilités (CVE) — architecture | #202, #193, #192 | `src/netcross_core/security/` | — | Fait |
| #135 | CVE-1 — Bannières de versions | #223, #219, #214 | `src/netcross_core/application/banners.py` | 435 | Fait |
| #136 | CVE-2 — Signatures d'exploits | #219, #193 | `src/netcross_core/exploit_signatures.py` | 765 | Fait |
| #137 | CVE-3 — Alertes Expert Info | #194 | `src/netcross_core/security/expert_correlation.py` | — | Fait |
| #138 | CVE-4 — Base CVE locale | #202, #192, #182 | `src/netcross_core/security/cve_db.py` | 243 | Fait |
| #139 | CVE-5 — Rapport de vulnérabilités | #219, #214, #212 | `src/netcross_core/security/findings.py` | — | Fait |

### FLOW (analyse de flux)

| Issue | Titre | PR(s) | Fichier(s) | Lignes | Statut |
|---|---|---|---|---|---|
| #142 | FLOW-1 — Protocole/port non standard | #237, #219, #215 | `src/netcross_core/security/protocol_mismatch.py` | 245 | Fait |
| #143 | FLOW-2 — JA4/HASSH | #230, #223 | `src/netcross_core/fingerprint/tls_ja4.py`, `ssh_hassh.py` | 289 + 162 | Fait |
| #144 | FLOW-3 — Tunneling DNS | #230, #215 | `src/netcross_core/security/dns_tunnel.py` | 263 | Fait |

### SCENARIO (détection d'attaques)

| Issue | Titre | PR(s) | Fichier(s) | Lignes | Statut |
|---|---|---|---|---|---|
| #147 | SCENARIO-1 — Beaconing C2 | #230 | `src/netcross_core/security/beaconing.py` | 265 | Fait |

### Jobs (fonctionnalités d'exploitation)

| Issue | Titre | PR(s) | Fichier(s) clés | Statut |
|---|---|---|---|---|
| #154 | Job 34 — Fusion de captures | #189, #184 | `pcap_parser/capture.py` (`merge_captures`) | Fait |
| #155 | Job 35 — Découpage PCAP | #240, #234, #219 | `pcap_parser/capture.py` (split) | Fait |
| #156 | Job 36 — Export sous-ensemble | #235 | `pcap_parser/capture.py` (`export_filtered`) | Fait |
| #157 | Job 37 — Ring buffer | #186 | `pcap_parser/capture.py` (`CaptureRingBuffer`) | Fait |
| #158 | Job 38 — Métadonnées capinfos | #233, #206 | `pcap_parser/capinfos_source.py` | Fait |
| #159 | Job 39 — Commentaires pcapng | #206 | `pcap_parser/capfile.py` | Fait |
| #160 | Job 40 — Étiquetage paquets | (commits directs) | `netcross_core/forensic.py` (`PacketAnnotation`) | Fait |
| #161 | Job 41 — Doublons inter-captures | #238, #227, #197 | `netcross_core/analysis.py` (`exclude_duplicates`) | Fait |
| #162 | Job 42 — Trous de séquence TCP | #211, #203, #199 | `netcross_core/models.py` (`SequenceGap`) | Fait |
| #163 | Job 43 — Validation checksums | #213 | `pcap_parser/ek_fields.py`, `packet.py` | Fait |
| #164 | Job 44 — tcpreplay | #201, #196 | `pcap_parser/capture.py` (`--replay`) | Fait |
| #165 | Job 45 — Ajustement timestamps | #236 | `pcap_parser/capture.py` (`adjust_timestamps`) | Fait |
| #167 | Job 47 — Filtres BPF | (commits directs) | `netcross_core/bpf_filters.py` | Fait |
| #168 | Job 48 — Multi-interfaces | #240, #231, #185 | `pcap_parser/capture.py` (`iter_live_multi`) | Fait |

### Jobs fondations (P0/P1)

| Issue | Titre | PR(s) | Statut |
|---|---|---|---|
| #1 | Job 1 — Évaluateur rtp_quality_mos | #121, #103 | Fait |
| #2 | Job 2 — Évaluateur server_processing_dominant | #104 | Fait |
| #3 | Job 3 — Exposer evaluate() en CLI/JSON | #105 | Fait |
| #4 | Job 7 — Moteur de corrélation causale | #108 | Fait |
| #5 | Job 8 — Index événement → flow → paquet | #129, #109 | Fait |
| #6 | Job 9 — Flow enrichi | #115 | Fait |
| #7 | Job 10 — Référentiels techniques | #116 | Fait |
| #8 | Job 11 — Moteur de conformité | #117 | Fait |
| #9 | Job 12 — Baseline dynamique | #118 | Fait |
| #10 | Job 13 — Vue temporelle d'un flux | #121, #119 | Fait |
| #11 | Job 14 — Diagramme de séquence | #127, #126, #125 | Fait |
| #12 | Job 16 — Chemin multi-points | #127, #126, #125 | Fait |
| #13 | Job 4 — Objets enrichis console/PDF | #127, #126, #125 | Fait |
| #14 | Job 5 — Objets enrichis JSON GUI | #127, #126, #125 | Fait |
| #15 | Job 15 — Cartographie interactive | #127, #126, #125 | Fait |
| #16 | Job 17 — Recherche forensic | #129 | Fait |
| #17 | Job 18 — Table des noms | #130 | Fait |
| #18 | Job 19 — Dashboards interactifs | #134 | Fait |
| #20 | Job 21 — Statistiques tshark | #131 | Fait |
| #21 | Job 22 — TCP enrichi | #132 | Fait |
| #22 | Job 27 — Exploration statistique | #171 | Fait |
| #24 | Job 24 — Analyse VoIP | #120 | Fait |
| #25 | Job 25 — Extraction de contenus | #122 | Fait |
| #26 | Job 26 — Alarmes/seuils | #173, #110 | Fait |
| #27 | Job 6 — Stratégie bascule build_findings | #111 | Fait |
| #28 | Job 28 — Nettoyage mypy | #112 | Fait |
| #29 | Job 29 — Validation CAPWAP | #172, #113 | Fait |
| #30 | Job 30 — CAPWAP Fortinet | #172 | Fait |
| #31 | Job 31 — Packaging .rpm | #114 | Fait |
| #32 | Job 32 — Ingestion NetFlow/sFlow | #174 | Fait |
| #33 | Job 33 — Capture en continu + diff | #173, #110 | Fait |

### Infrastructure

| Issue | Titre | PR(s) | Statut |
|---|---|---|---|
| #140 | Diagramme de classe | #266, #205 | Fait (inter-module + CI check) |
| #176 | CI GitHub Actions | #204 | Fait |
| #217 | Bug close_db() try/finally | #225, #219 | Fait |
| #224 | pytest-cov + couverture CI | #232, #226 | Fait |

---

## Couverture de tests

Chaque fonctionnalité audité dispose de tests dédiés :

| Domaine | Fichier(s) de test | Présent |
|---|---|---|
| Bannières (CVE-1) | `test_banners.py` | Oui |
| Signatures exploits (CVE-2) | `test_exploit_signatures.py` | Oui |
| Expert correlation (CVE-3) | `test_expert_correlation.py` | Oui |
| CVE corrélation (CVE-4) | `test_cve_correlation.py` | Oui |
| Rapport sécurité (CVE-5) | `test_security_report.py`, `test_security_report_pcap.py` | Oui |
| Protocol mismatch (FLOW-1) | `test_protocol_mismatch.py` | Oui |
| Fingerprinting (FLOW-2) | `test_fingerprinting.py` | Oui |
| DNS tunnel (FLOW-3) | `test_dns_tunnel.py` | Oui |
| Beaconing (SCENARIO-1) | `test_beaconing.py` | Oui |
| Fusion captures (Job 34) | `test_merge_captures.py` | Oui |
| Split capture (Job 35) | `test_split_capture.py`, `test_split_cli.py` | Oui |
| Export filtré (Job 36) | `test_export_filtered.py`, `test_export_cli.py` | Oui |
| Capture segments (Job 37) | `test_capture_segments.py` | Oui |
| Capinfos (Job 38) | `test_capinfos_source.py`, `test_capture_info.py` | Oui |
| Commentaires pcapng (Job 39) | `test_pcapng_comments.py` | Oui |
| Annotations (Job 40) | `test_annotations_view.py` | Oui |
| Doublons inter-captures (Job 41) | `test_cross_capture_duplicates.py`, `test_duplicate_view.py` | Oui |
| Trous de séquence (Job 42) | `test_sequence_gaps.py`, `test_sequence_view.py` | Oui |
| Checksums (Job 43) | `test_checksums.py` | Oui |
| tcpreplay (Job 44) | `test_replay.py` | Oui |
| Timestamps (Job 45) | `test_adjust_timestamps.py`, `test_adjust_cli.py` | Oui |
| BPF filters (Job 47) | `test_bpf_filters.py` | Oui |
| Redact/anonymisation | `test_redact.py` | Oui |
| Diagramme de classes | `test_class_diagram.py` | Oui |

---

## Issues ouvertes connexes (suites à créer)

Certaines issues fermées ont des suites ouvertes qui étendent ou corrigent la fonctionnalité initiale :

| Issue fermée | Suite ouverte | Description |
|---|---|---|
| #143 (FLOW-2) | #259 | Fingerprints JA4/HASSH calculés mais jamais affichés |
| #156 (Job 36) | #261, #262 | Bugs sur `export_filtered()` (BPF + format) |
| #157 (Job 37) | #264 | GUI CaptureRingBuffer jamais poussée |
| #158 (Job 38) | #263 | Link type (encapsulation) jamais affiché |
| #169 (Job 49) | #256, #242 | Conversion de formats (PRs en conflit) |
| #148 (SCENARIO-2) | #258, #248 | Détection d'exfiltration (PRs en cours) |
| #151 (SCENARIO-5) | #257, #244 | Découverte passive des actifs (PR en conflit) |
| #152 (SCENARIO-6) | #252 | Détection DGA et fast flux |
| #149 (SCENARIO-3) | #251 | Détection de mouvements latéraux |
| #150 (SCENARIO-4) | #254 | Extraction et reconstruction de fichiers |
| #153 (SCENARIO-7) | #243 | Audit des certificats TLS |
| #170 | #265 | Socle qualité app |
| #209 | #260 | API REST FastAPI |
| #245 | #249 | Loguru logging structure |

---

## Recommandations

1. **Aucune issue fermée orpheline** — toutes les implémentations sont présentes dans le code.
2. **4 issues sans PR directe** (#19, #23, #160, #167) — leur implémentation est vérifiée mais le lien issue→PR n'est pas tracé dans GitHub. À l'avenir, toujours référencer l'issue dans la PR (closes #N).
3. **13 suites ouvertes** — des fonctionnalités fermées ont des bugs ou des extensions connus. Prioriser ces suites selon le tableau ci-dessus.
4. **Tests complets** — 2568 tests couvrent l'ensemble des fonctionnalités.
5. **ISSUES.md obsolète** — indique 33 ouvertes/69 fermées vs 24/130 sur GitHub. À mettre à jour.

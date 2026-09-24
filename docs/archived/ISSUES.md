# Suivi des issues — Tableau de bord

**Dernière mise à jour :** 18 septembre 2026

Ce fichier est le tableau de bord des issues GitHub du dépôt [MathildeDec/Netcross](https://github.com/MathildeDec/Netcross).

- **Issues ouvertes (travaux restants) :** 33 (Jobs 1-33)
- **Issues fermées (sessions historiques) :** 69 (Sessions 1-69)
- **Total issues :** 102

---

## Issues ouvertes par priorité

### P0 — Fondations (6 issues)

| Issue | Job | Titre | Difficulté | Dépendances | Sessions liées |
|---|---|---|---|---|---|
| [#1](https://github.com/MathildeDec/Netcross/issues/1) | 1 | Évaluateur `rtp_quality_mos` (40/41) | 2/5 | — | S67 (audit) |
| [#2](https://github.com/MathildeDec/Netcross/issues/2) | 2 | Évaluateur `server_processing_dominant` (41/41) | 2/5 | — | S67 (audit) |
| [#3](https://github.com/MathildeDec/Netcross/issues/3) | 3 | Exposer `evaluate()` en CLI et JSON | 1/5 | #1, #2 | S55-S69 |
| [#4](https://github.com/MathildeDec/Netcross/issues/4) | 7 | Moteur de corrélation causale | 5/5 | #1, #2 | S3 (prévue) |
| [#5](https://github.com/MathildeDec/Netcross/issues/5) | 8 | Index événement → flow → paquet | 2/5 | — | S36 (objets) |
| [#6](https://github.com/MathildeDec/Netcross/issues/6) | 9 | Flow enrichi | 4/5 | #5 | S4 (prévue) |

### P1 — Différenciation Netcross (6 issues)

| Issue | Job | Titre | Difficulté | Dépendances | Sessions liées |
|---|---|---|---|---|---|
| [#7](https://github.com/MathildeDec/Netcross/issues/7) | 10 | Référentiels techniques | 3/5 | — | S6 (prévue) |
| [#8](https://github.com/MathildeDec/Netcross/issues/8) | 11 | Moteur de conformité | 3/5 | #7 | S7 (prévue) |
| [#9](https://github.com/MathildeDec/Netcross/issues/9) | 12 | Baseline dynamique | 3/5 | #7 | S29 (history), S14 (client_diff) |
| [#10](https://github.com/MathildeDec/Netcross/issues/10) | 13 | Vue temporelle d'un flux | 4/5 | #6 | S5 (prévue) |
| [#11](https://github.com/MathildeDec/Netcross/issues/11) | 14 | Diagramme de séquence multi-hôtes | 4/5 | #6, #10 | — |
| [#12](https://github.com/MathildeDec/Netcross/issues/12) | 16 | Chemin multi-points | 3/5 | — | S20 (top-N) |

### P2 — Exploitation (10 issues)

| Issue | Job | Titre | Difficulté | Dépendances | Sessions liées |
|---|---|---|---|---|---|
| [#13](https://github.com/MathildeDec/Netcross/issues/13) | 4 | Objets enrichis en console/PDF | 1/5 | — | S36-S37 (objets) |
| [#14](https://github.com/MathildeDec/Netcross/issues/14) | 5 | Objets enrichis dans JSON GUI | 1/5 | — | S36-S39 |
| [#15](https://github.com/MathildeDec/Netcross/issues/15) | 15 | Cartographie interactive | 4/5 | #6 | — |
| [#16](https://github.com/MathildeDec/Netcross/issues/16) | 17 | Recherche forensic | 3/5 | #5 | — |
| [#17](https://github.com/MathildeDec/Netcross/issues/17) | 18 | Table des noms | 2/5 | — | — |
| [#18](https://github.com/MathildeDec/Netcross/issues/18) | 19 | Dashboards interactifs | 4/5 | #5, #6 | S4 (GUI existante) |
| [#19](https://github.com/MathildeDec/Netcross/issues/19) | 20 | Générateur de graphes générique | 3/5 | — | S20 (charts) |
| [#20](https://github.com/MathildeDec/Netcross/issues/20) | 21 | Statistiques tshark | 2/5 | — | S38-S39 (expert) |
| [#21](https://github.com/MathildeDec/Netcross/issues/21) | 22 | TCP enrichi (`tcp.analysis.*`) | 3/5 | — | S10-S11 (TCP) |
| [#22](https://github.com/MathildeDec/Netcross/issues/22) | 27 | Exploration statistique interactive | 2/5 | #5 | — |

### P3 — Expertise applicative (4 issues)

| Issue | Job | Titre | Difficulté | Dépendances | Sessions liées |
|---|---|---|---|---|---|
| [#23](https://github.com/MathildeDec/Netcross/issues/23) | 23 | Analyse transactionnelle | 5/5 | #6 | S10 (prévue) |
| [#24](https://github.com/MathildeDec/Netcross/issues/24) | 24 | VoIP orientée appel | 3/5 | — | S13 (DNS), S17 (HTTP) |
| [#25](https://github.com/MathildeDec/Netcross/issues/25) | 25 | Extraction de contenus | 3/5 | — | — |
| [#26](https://github.com/MathildeDec/Netcross/issues/26) | 26 | Alarmes et notifications | 2/5 | #1, #2 | S5/S16 (live) |

### P4 — Validation et admin (7 issues)

| Issue | Job | Titre | Difficulté | Dépendances | Sessions liées |
|---|---|---|---|---|---|
| [#27](https://github.com/MathildeDec/Netcross/issues/27) | 6 | Décision bascule `build_findings()` | 1/5 | #1, #2 | S55-S69 |
| [#28](https://github.com/MathildeDec/Netcross/issues/28) | 28 | Nettoyage mypy | 1/5 | — | S50 (audit) |
| [#29](https://github.com/MathildeDec/Netcross/issues/29) | 29 | Validation CAPWAP | 1/5 | — | — |
| [#30](https://github.com/MathildeDec/Netcross/issues/30) | 30 | CAPWAP Fortinet Lua | 3/5 | #29 | — |
| [#31](https://github.com/MathildeDec/Netcross/issues/31) | 31 | Packaging .rpm / FIXME | 1/5 | — | S30 (packaging) |
| [#32](https://github.com/MathildeDec/Netcross/issues/32) | 32 | NetFlow / sFlow | 5/5 | — | — |
| [#33](https://github.com/MathildeDec/Netcross/issues/33) | 33 | Capture continue + diff | 5/5 | #26 | S5/S16 (live) |

---

## Sessions historiques (issues fermées)

Les 69 sessions de développement (issues #34 à #102, label `session-archive`) documentent l'historique complet du projet, de la Session 1 (remplacement scapy → tshark) à la Session 69 (audit des cinq règles à corrélation). Chaque issue fermée pointe vers son compte-rendu détaillé dans `docs/sessions/session-NN.md`.

### Correspondance sessions → issues

| Sessions | Issues GitHub | Thème principal |
|---|---|---|
| S1-S3 | #34-#36 | Fondations : tshark, dette, TLS/QUIC |
| S4-S8 | #37-#41 | GUI, qualité, parité CLI diff |
| S9-S11 | #42-#44 | PMTUD, retransmissions, options TCP |
| S12-S14 | #45-#47 | JSON, DNS, client vs client |
| S15-S16 | #48-#49 | Confiance, live diff |
| S17-S20 | #50-#53 | HTTP, santé, mémoire, top-N |
| S21-S22 | #54-#55 | IPv6, archive |
| S23-S25 | #56-#58 | NAT-FW, ARP, STP |
| S26-S28 | #59-#61 | TLS, captures segmentées, anonymisation |
| S29-S31 | #62-#64 | Historique SQLite, CLI history, parallel |
| S32-S37 | #65-#70 | Session 0 : contrats analytiques (EvidenceLink → fermeture) |
| S38-S39 | #71-#72 | Session 1 : expertise Wireshark/TShark |
| S40-S45 | #73-#78 | Session 2 : moteur d'événements d'expertise |
| S42 | #75 | Réorganisation du suivi de projet |
| S46-S54 | #79-#87 | Bibliothèque de règles déclarative (41 règles) |
| S55-S69 | #88-#102 | Moteur d'exécution (39/41 évaluateurs) |

---

## Conventions de branching

| Branche | Usage |
|---|---|
| `main` | Branche stable, code livré |
| `dev` | Branche de développement |
| `job<N>` | Branche de travail pour l'issue #N (ex: `job1` pour l'issue #1) |

Chaque job est livré via une pull request de `job<N>` vers `dev`.

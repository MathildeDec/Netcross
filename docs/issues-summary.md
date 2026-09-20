# Tableau récapitulatif des issues ouvertes — Netcross

> Généré le 2026-09-20. Contexte : PR #212 (merged) a validé le rapport de sécurité (CVE-5, #139) sur de vrais PCAPs tshark — trafic légitime sans faux positif.

## Vue d'ensemble

| Priorité | Nombre | Description |
|----------|--------|-------------|
| **P1 — Différenciation** | 5 | Fonctionnalités différenciantes, démarrage immédiat |
| **P2 — Exploitation** | 6 | Améliorations d'exploitation, indépendantes |
| **P3 — Applicatif** | 13 | Expertise applicative, fondations sécurité + scénarios |
| **P4 — Admin/validation** | 2 | Validation, admin, IA/ML |
| **Total** | **26** (+ 2 issues parentes #133, #141) | |

## Pistes parallèles

Les 26 issues sont réparties en 7 pistes pouvant être travaillées en parallèle :

### Track A — Gestion PCAP (P1, démarrage immédiat, indépendant)

| Ordre | Issue | Titre | Difficulté | Dépendances |
|-------|-------|-------|------------|-------------|
| 1 | #158 | Job 38 — capinfos (métadonnées de capture) | 1/5 | Aucune |
| 2 | #155 | Job 35 — Découpage PCAP (split) | 2/5 | Aucune |
| 3 | #156 | Job 36 — Export sous-ensemble PCAP | 2/5 | Aucune |
| 4 | #165 | Job 45 — Ajustement de timestamps | 2/5 | Aucune |
| 5 | #161 | Job 41 — Doublons inter-captures | 3/5 | payload_hash (existant) |

Toutes indépendantes — peuvent être traitées en parallèle. Fichiers : `pcap_parser/capture.py` (#158, #155, #156, #165), `netcross_core/forensic.py` (#161).

### Track B — Sources de capture (P2, indépendant)

| Ordre | Issue | Titre | Difficulté | Dépendances |
|-------|-------|-------|------------|-------------|
| 6 | #163 | Job 43 — Validation des checksums | 2/5 | Aucune |
| 7 | #167 | Job 47 — Filtres BPF (sauvegarde/rechargement) | 2/5 | Aucune |
| 8 | #169 | Job 49 — Conversion de formats | 2/5 | Aucune |
| 9 | #164 | Job 44 — tcpreplay (rejeu) | 3/5 | Aucune |
| 10 | #168 | Job 48 — Multi-interfaces | 3/5 | Aucune |
| 11 | #166 | Job 46 — Capture distante (rpcap/sshdump) | 4/5 | Aucune |

Toutes indépendantes — peuvent être traitées en parallèle.

### Track C — Fondations sécurité (P3, fondation pour Tracks D + E)

| Ordre | Issue | Titre | Difficulté | Dépendances |
|-------|-------|-------|------------|-------------|
| 12 | #135 | CVE-1 — Extraction bannières (fingerprinting passif) | 3/5 | Aucune — **fondation pour #143** |
| 13 | #142 | FLOW-1 — DPI léger (protocole sur port non standard) | 3/5 | Aucune — **fondation pour #144, #145** |
| 14 | #153 | SCENARIO-7 — Audit certificats TLS | 2/5 | Aucune (champs tls_* existants) |
| 15 | #151 | SCENARIO-5 — Cartographie passive des actifs | 3/5 | Aucune (topology_edges existant) |

#135 et #142 sont les fondations critiques. #153 et #151 sont des quick wins indépendants.

### Track D — Détection de flux (P3, dépend de Track C)

| Ordre | Issue | Titre | Difficulté | Dépendances |
|-------|-------|-------|------------|-------------|
| 16 | #144 | FLOW-3 — Tunneling DNS | 3/5 | #142 (DPI). Partage entropie avec #145, #152 |
| 17 | #145 | FLOW-4 — Stats de flux (SPLT, entropie, timing) | 4/5 | #142. Alimente #146, #147 |
| 18 | #143 | FLOW-2 — Fingerprinting JA4/HASSH | 4/5 | #135 (bannières) + #142 (DPI) |

#144 et #145 peuvent être parallélisées après #142. #143 nécessite #135 ET #142.

### Track E — Scénarios de menace (P3, dépend de Tracks C + D)

| Ordre | Issue | Titre | Difficulté | Dépendances |
|-------|-------|-------|------------|-------------|
| 19 | #148 | SCENARIO-2 — Exfiltration de données | 3/5 | #142. Corrélations #144, #147 |
| 20 | #149 | SCENARIO-3 — Mouvements latéraux | 4/5 | Aucune (flags TCP existants) |
| 21 | #147 | SCENARIO-1 — Beaconing C2 | 4/5 | #145 (flow stats). Corrélations #143, #144 |
| 22 | #152 | SCENARIO-6 — DGA et fast flux | 4/5 | #144 (entropie DNS) |
| 23 | #150 | SCENARIO-4 — File carving | 4/5 | Aucune (tshark fait la dissection) |

#149 et #150 sont indépendants et peuvent démarrer en parallèle de Track C/D. #147 dépend de #145. #152 dépend de #144.

### Track F — Intégration (P3, indépendant)

| Ordre | Issue | Titre | Difficulté | Dépendances |
|-------|-------|-------|------------|-------------|
| 24 | #209 | Job 50 — API REST + OpenAPI (FastAPI) | 3/5 | Aucune (extra optionnel) |
| 25 | #170 | Qualité app (CI/CD, Docker, coverage, logging, SIEM...) | — | Transversale |

#209 indépendant (FastAPI en dépendance optionnelle). #170 est transversale — à découper en sous-issues.

### Track G — IA/ML (P4, dépend de Tracks C + D + E)

| Ordre | Issue | Titre | Difficulté | Dépendances |
|-------|-------|-------|------------|-------------|
| 26 | #146 | FLOW-5 — Module IA/ML optionnel | 5/5 | #145 (features ML), #142 (DPI), #147-#149 (données) |

À démarrer en dernier — toutes les fondations doivent être en place.

## Graphe de dépendances

```
Track A (indépendant)        Track B (indépendant)
  #158 ──┐                     #163 ──┐
  #155 ──┤                     #167 ──┤
  #156 ──┤── peuvent            #169 ──┤── peuvent
  #165 ──┤   tous               #164 ──┤   tous
  #161 ──┘   parallèles         #168 ──┤   parallèles
                               #166 ──┘

Track C (fondations)          Track F (indépendant)
  #135 ─────────────┐           #209 (API REST)
  #142 ─────────────┤           #170 (qualité, transversal)
  #153 ── (indép.)   │
  #151 ── (indép.)   │
                    │
Track D (détection flux)       Track E (scénarios menace)
  #142 ──► #144 ──┐             #142 ──► #148 (exfiltration)
         └► #145 ──┤             #149 (indépendant)
  #135 ──► #143   │             #145 ──► #147 (beaconing C2)
  #142 ──► #143   │             #144 ──► #152 (DGA)
                  │             #150 (indépendant)
                  └───────────────► #146 (IA/ML, en dernier)
```

## Restes de la PR #212 (CVE-5 clôturé)

La PR #212 a validé le rapport de sécurité sur de vrais PCAPs tshark. Restes hors périmètre, à tracker :

| Reste | Statut | Issue proposée |
|-------|--------|----------------|
| Doc README.md / CLAUDE.md pour `--security-report` | À faire | Nouvelle issue |
| `close_db()` dans `try/finally` dans la CLI | À faire | Nouvelle issue |
| Rendu HTML/PDF du rapport de sécurité | Future sortie | Nouvelle issue |

## Voir aussi

- [PR #212](https://github.com/MathildeDec/Netcross/pull/212) — Validation du rapport sécurité sur vrais PCAPs
- [Issue #133](https://github.com/MathildeDec/Netcross/issues/133) — Issue parente CVE
- [Issue #141](https://github.com/MathildeDec/Netcross/issues/141) — Issue parente flux cachés + scénarios

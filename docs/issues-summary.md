# Tableau récapitulatif des issues ouvertes — Netcross

> Généré le 2026-09-20. Contexte : PR #212 (merged) a validé le rapport de sécurité (CVE-5, #139) sur de vrais PCAPs tshark — trafic légitime sans faux positif.
>
> Mise à jour 2026-09-21 : Audit du codebase — 13 issues sur 24 déjà implémentées et fermées. Le tableau ci-dessous reflète l'état réel après fermeture.
>
> Issues fermées après audit code : #135 (bannières), #142 (DPI), #143 (JA4/HASSH), #144 (DNS tunnel), #147 (beaconing C2), #158 (capinfos), #156 (export PCAP), #165 (timestamps), #161 (doublons), #163 (checksums), #167 (BPF), #164 (tcpreplay), #217 (close_db try/finally).

## Vue d'ensemble

| Priorité | Ouvertes | Description |
|----------|----------|-------------|
| **P1 — Différenciation** | 0 | Toutes livrées (Track A complet) |
| **P2 — Exploitation** | 2 | Conversion de formats, capture distante |
| **P3 — Applicatif** | 9 | Fondations sécurité + scénarios + intégration |
| **P4 — Admin/validation** | 1 | Module IA/ML |
| **Total** | **12** (+ 2 restes PR #212) | |

## Pistes parallèles

Les 12 issues ouvertes sont réparties en 7 pistes pouvant être travaillées en parallèle :

### Track A — Gestion PCAP (P1, complet ✅)

| Ordre | Issue | Titre | Difficulté | Statut |
|-------|-------|-------|------------|--------|
| 1 | #158 | Job 38 — capinfos (métadonnées de capture) | 1/5 | ✅ Livré |
| 2 | #156 | Job 36 — Export sous-ensemble PCAP | 2/5 | ✅ Livré |
| 3 | #165 | Job 45 — Ajustement de timestamps | 2/5 | ✅ Livré |
| 4 | #161 | Job 41 — Doublons inter-captures | ✅ | ✅ Livré |

### Track B — Sources de capture (P2, 2 restantes)

| Ordre | Issue | Titre | Difficulté | Statut |
|-------|-------|-------|------------|--------|
| 6 | #163 | Job 43 — Validation des checksums | 2/5 | ✅ Livré |
| 7 | #167 | Job 47 — Filtres BPF (sauvegarde/rechargement) | 2/5 | ✅ Livré |
| 8 | #169 | Job 49 — Conversion de formats | 2/5 | À coder |
| 9 | #164 | Job 44 — tcpreplay (rejeu) | 3/5 | ✅ Livré |
| 11 | #166 | Job 46 — Capture distante (rpcap/sshdump) | 4/5 | À coder |

#169 et #166 sont indépendantes — peuvent être traitées en parallèle.

### Track C — Fondations sécurité (P3, 2 restantes)

| Ordre | Issue | Titre | Difficulté | Statut |
|-------|-------|-------|------------|--------|
| 12 | #135 | CVE-1 — Extraction bannières (fingerprinting passif) | 3/5 | ✅ Livré |
| 13 | #142 | FLOW-1 — DPI léger (protocole sur port non standard) | 3/5 | ✅ Livré |
| 14 | #153 | SCENARIO-7 — Audit certificats TLS | 2/5 | À coder |
| 15 | #151 | SCENARIO-5 — Cartographie passive des actifs | 3/5 | À coder |

#153 et #151 sont des quick wins indépendants. Les fondations critiques (#135, #142) sont posées.

### Track D — Détection de flux (P3, 1 restante)

| Ordre | Issue | Titre | Difficulté | Statut |
|-------|-------|-------|------------|--------|
| 16 | #144 | FLOW-3 — Tunneling DNS | 3/5 | ✅ Livré |
| 17 | #145 | FLOW-4 — Stats de flux (SPLT, entropie, timing) | 4/5 | À coder |
| 18 | #143 | FLOW-2 — Fingerprinting JA4/HASSH | 4/5 | ✅ Livré |

#145 alimente #146 (IA/ML) et #147 (beaconing, déjà livré).

### Track E — Scénarios de menace (P3, 4 restantes)

| Ordre | Issue | Titre | Difficulté | Statut |
|-------|-------|-------|------------|--------|
| 19 | #148 | SCENARIO-2 — Exfiltration de données | 3/5 | À coder |
| 20 | #149 | SCENARIO-3 — Mouvements latéraux | 4/5 | À coder |
| 21 | #147 | SCENARIO-1 — Beaconing C2 | 4/5 | ✅ Livré |
| 22 | #152 | SCENARIO-6 — DGA et fast flux | 4/5 | À coder |
| 23 | #150 | SCENARIO-4 — File carving | 4/5 | À coder |

#149 et #150 sont indépendants et peuvent démarrer en parallèle. #152 dépend de #144 (✅ livré). #148 dépend de #142 (✅ livré).

### Track F — Intégration (P3, 2 restantes)

| Ordre | Issue | Titre | Difficulté | Statut |
|-------|-------|-------|------------|--------|
| 24 | #209 | Job 50 — API REST + OpenAPI (FastAPI) | 3/5 | À coder |
| 25 | #170 | Qualité app (CI/CD, Docker, coverage, logging, SIEM...) | — | Partiel |

#209 indépendant (FastAPI en dépendance optionnelle). #170 est transversale — à découper en sous-issues.

### Track G — IA/ML (P4, 1 restante)

| Ordre | Issue | Titre | Difficulté | Statut |
|-------|-------|-------|------------|--------|
| 26 | #146 | FLOW-5 — Module IA/ML optionnel | 5/5 | À coder |

À démarrer en dernier — toutes les fondations doivent être en place. Dépend de #145 (flow stats), #142 (DPI ✅), #147-149 (données).

## Graphe de dépendances

```
Track A (complet ✅)          Track B (2 restants)
  #158 ──┐ ✅                  #163 ──┐ ✅
  #156 ──┤ ✅                  #167 ──┤ ✅
  #165 ──┤ ✅                  #169 ──┤── à coder
  #161 ──┘ ✅                  #164 ──┤ ✅
                               #166 ──┘── à coder

Track C (2 restants)          Track F (2 restants)
  #135 ─────────────┐ ✅       #209 (API REST)
  #142 ─────────────┤ ✅       #170 (qualité, transversal)
  #153 ── (à coder)  │
  #151 ── (à coder)  │
                    │
Track D (1 restant)           Track E (4 restants)
  #142 ──► #144 ──┐ ✅         #142 ──► #148 (exfiltration)
         └► #145 ──┤── à coder #149 (indépendant)
  #135 ──► #143   │ ✅         #144 ──► #152 (DGA)
  #142 ──► #143   │ ✅         #150 (indépendant)
                  │             #147 ──► ✅
                  └───────────────► #146 (IA/ML, en dernier)
```

## Restes de la PR #212 (CVE-5 clôturé)

La PR #212 a validé le rapport de sécurité sur de vrais PCAPs tshark. Trois restes identifiés et trackés :

| Issue | Titre | Priorité | Difficulté | Statut |
|-------|-------|----------|------------|--------|
| #216 | Suite PR #212 : documenter --security-report dans CLAUDE.md | P3 | 1/5 | À coder |
| #217 | Suite PR #212 : close_db() sans try/finally dans la CLI | P3 | 1/5 | ✅ Livré |
| #218 | Suite PR #212 : rendu HTML/PDF du rapport de sécurité | P3 | 3/5 | À coder |

README.md déjà documenté par PR #214.

## Voir aussi

- [PR #212](https://github.com/MathildeDec/Netcross/pull/212) — Validation du rapport sécurité sur vrais PCAPs
- [Issue #133](https://github.com/MathildeDec/Netcross/issues/133) — Issue parente CVE
- [Issue #141](https://github.com/MathildeDec/Netcross/issues/141) — Issue parente flux cachés + scénarios

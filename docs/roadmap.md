# Roadmap — Netcross

> Dernière mise à jour : 2026-09-21
> Source : GitHub issues, PRs, et `docs/features-backlog.md`

## Vue d'ensemble

| Métrique | Valeur |
|----------|--------|
| Issues ouvertes | 29 |
| Issues closes | 139+ (sessions + fonctionnalités) |
| PRs en attente | #213, #214, #219 |
| Dernière PR merged | #212 — rapport sécurité validé sur vrais PCAPs |

## Phases d'intégration

### Phase 0 — Décisions produit ✅

| Décision | Statut | Issue |
|----------|--------|-------|
| Architecture modules (pcap_parser → core → report → gtk4) | Actée | — |
| Ruff + import-linter en CI | Actée | — |
| Moteur d'exécution des règles (issue #27) | Décision documentée | — |

### Phase 1 — Fondations sécurité + Gestion PCAP 🔄

| Issue | Titre | Statut | Bloque |
|-------|-------|--------|--------|
| #158 | capinfos (métadonnées) | Ouverte, diff 1/5 | — |
| #155 | Découpage PCAP | Ouverte, diff 2/5 | — |
| #156 | Export sous-ensemble PCAP | Ouverte, diff 2/5 | — |
| #165 | Ajustement timestamps | Ouverte, diff 2/5 | — |
| #161 | Doublons inter-captures | Ouverte, diff 3/5 | — |
| #135 | CVE-1 — Bannières (fingerprinting passif) | Ouverte, diff 3/5 | #143 |
| #142 | FLOW-1 — DPI léger | Ouverte, diff 3/5 | #144, #145 |
| #153 | SCENARIO-7 — Audit TLS | Ouverte, diff 2/5 | — |
| #151 | SCENARIO-5 — Cartographie passive | Ouverte, diff 3/5 | — |
| #216 | CLAUDE.md --security-report | Ouverte, diff 1/5 | — |
| #217 | close_db() try/finally | Ouverte, diff 1/5 | — |
| #218 | Rendu HTML/PDF sécurité | Ouverte, diff 3/5 | — |

**Avancement** : CVE-2 à CVE-5 livrés (#136-#139 clos). PR #212 a validé le rapport sécurité sur vrais PCAPs. Track A (PCAP) et Track C (fondations) prêts à démarrer.

### Phase 2 — Détection de flux + Sources de capture 🔜

| Issue | Titre | Dépend de | Difficulté |
|-------|-------|-----------|------------|
| #144 | FLOW-3 — Tunneling DNS | #142 | 3/5 |
| #145 | FLOW-4 — Stats de flux | #142 | 4/5 |
| #143 | FLOW-2 — JA4/HASSH | #135, #142 | 4/5 |
| #163 | Checksums IP/TCP/UDP | — | 2/5 |
| #167 | Filtres BPF | — | 2/5 |
| #169 | Conversion formats | — | 2/5 |
| #164 | tcpreplay | — | 3/5 |
| #168 | Multi-interfaces | — | 3/5 |
| #166 | Capture distante | — | 4/5 |
| #209 | API REST + OpenAPI | — | 3/5 |

### Phase 3 — Scénarios de menace 🔜

| Issue | Titre | Dépend de | Difficulté |
|-------|-------|-----------|------------|
| #148 | SCENARIO-2 — Exfiltration | #142 | 3/5 |
| #149 | SCENARIO-3 — Mouvements latéraux | — | 4/5 |
| #147 | SCENARIO-1 — Beaconing C2 | #145 | 4/5 |
| #152 | SCENARIO-6 — DGA/fast flux | #144 | 4/5 |
| #150 | SCENARIO-4 — File carving | — | 4/5 |

### Phase 4 — IA/ML + Transversal 🔜

| Issue | Titre | Dépend de | Difficulté |
|-------|-------|-----------|------------|
| #146 | FLOW-5 — Module IA/ML | #145, #142, #147-#149 | 5/5 |
| #170 | Qualité app (CI/CD, Docker, SIEM...) | Transversal | — |

## PRs en attente

| PR | Titre | Statut CI |
|----|-------|-----------|
| [#213](https://github.com/MathildeDec/Netcross/pull/213) | ChecksumError + Report.checksum_errors | ✅ CLEAN |
| [#214](https://github.com/MathildeDec/Netcross/pull/214) | README — documenter --security-report | ✅ CLEAN |
| [#219](https://github.com/MathildeDec/Netcross/pull/219) | Backlog — numéros d'issues + restes PR #212 | ✅ CLEAN |

## Voir aussi

- [Tableau récapitulatif des issues](issues-summary.md)
- [Backlog complet](features-backlog.md)
- [Diagramme de classes](class-diagram.md)

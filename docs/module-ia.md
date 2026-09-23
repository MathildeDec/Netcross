# Module IA local (`netcross_ai`)

Module **optionnel** (issue #146, FLOW-5) : trois usages qui s'exécutent entièrement
sur la machine de traitement. Aucune API cloud, aucun envoi de données.

```bash
pip install "netcross[ai]"      # ou : uv sync --extra ai   (installe scikit-learn)
```

Sans ce module, Netcross fonctionne normalement ; seules `--ai-anomalies` et
`--ai-classify` refusent de démarrer, avec la commande d'installation. Le résumé par
gabarit (`--ai-summary`) ne dépend de rien.

## 1. Anomalies par rapport à une baseline

Une **baseline** est un ensemble de flux de trafic normal. Elle se construit en passant
une ou plusieurs captures saines (chaque passage **enrichit** le fichier) :

```bash
netcross-analyze --capture LAN=lundi.pcapng  --ai-baseline-save base-bureau.json --ai-baseline-label bureau
netcross-analyze --capture LAN=mardi.pcapng  --ai-baseline-save base-bureau.json
netcross-analyze --capture LAN=incident.pcapng --ai-anomalies base-bureau.json --ai-report ia.json
```

- Modèle : Isolation Forest (scikit-learn), 200 arbres, graine fixe (même baseline → mêmes
  scores). 20 flux minimum dans la baseline.
- Caractéristiques par flux, issues des statistiques FLOW-4 (`Report.flow_anomalies`) :
  nombre de paquets et d'octets (log), entropie des tailles, taille médiane, ratio montant,
  régularité (CV des intervalles), moyenne et écart-type des tailles SPLT, intervalle moyen,
  part de petits (< 100 o) et de gros (> 500 o) paquets.
- Chaque flux atypique est **expliqué** : caractéristiques à plus de 3 écarts-types de la
  baseline, par exemple `ratio_montant = 0.99 (baseline 0.2 +/- 0.058)`.
- La baseline est un JSON de **nombres** (schéma `netcross.ai.baseline/1`), jamais un modèle
  sérialisé par pickle : un fichier reçu ne peut pas exécuter de code. Le modèle est
  réentraîné à chaque chargement (quelques dixièmes de seconde).

## 2. Classification de flux avec confiance

Les règles de FLOW-4 ne distinguent pas un tunnel d'un flux C2 ou d'une exfiltration :
contre l'opacification, seul un modèle entraîné sur des exemples fonctionne. Le jeu
d'entraînement se constitue à partir des captures elles-mêmes :

```bash
# 1. flux de la capture, pré-étiquetés par les règles (normal/interactif/transfert/obfusque)
netcross-analyze --capture A=labo.pcapng --ai-training-export entrainement.json
# 2. corriger / compléter les "label" : tunnel, c2, exfiltration...
# 3. classer d'autres captures
netcross-analyze --capture A=incident.pcapng --ai-classify entrainement.json
```

Forêt aléatoire (200 arbres, classes équilibrées, graine fixe) ; 10 exemples et 2 classes
minimum. Chaque flux reçoit une étiquette et une **confiance** (probabilité de la classe),
affichées à côté de la classification par règles pour comparaison.

## 3. Résumé exécutif, corrélations, recommandations

```bash
netcross-analyze --capture A=trace.pcapng --security-report --ai-summary                  # gabarit
netcross-analyze --capture A=trace.pcapng --security-report --ai-summary ollama:llama3:8b-instruct-q4_K_M
netcross-analyze --capture A=trace.pcapng --security-report --ai-summary llamacpp --ai-endpoint http://127.0.0.1:8080
```

| Moteur | Dépendance | Texte |
|---|---|---|
| `template` (défaut) | aucune | déterministe, construit à partir des faits |
| `ollama:MODELE` | [ollama](https://ollama.com) lancé en local (`/api/generate`) | rédigé par le modèle |
| `llamacpp` | `llama-server` de llama.cpp en local (`/completion`) | rédigé par le modèle |

- Le modèle ne reçoit que des **faits** (constats de sécurité, services, classes de flux,
  anomalies IA), jamais de paquets, avec la consigne de n'inventer aucun fait.
- Le point d'accès doit être une adresse de **boucle locale** (127.0.0.1, ::1, localhost) :
  toute autre adresse est refusée avant l'analyse.
- Les corrélations (une même machine cumulant CVE, signature d'exploit, mouvement latéral,
  flux atypique…) et les recommandations (mise à jour d'un service vulnérable, isolement,
  inspection d'un flux classé tunnel/C2/exfiltration…) sont **toujours** calculées par
  règles, donc vérifiables, et affichées à côté du texte du modèle.
- Si le modèle est injoignable ou répond vide, le gabarit est utilisé et c'est signalé.

`--security-report` n'est pas obligatoire, mais sans lui le rapport ne contient pas de
constats de sécurité à résumer.

## Sortie JSON

`--ai-report FICHIER.json` (schéma `netcross.ai/1`) : `anomalies` (flux, score 0-1,
`is_anomaly`, raisons), `classification` (étiquette, confiance, classification par règles),
`summary` (moteur, texte, corrélations, recommandations, motif de repli éventuel), et les
métadonnées de baseline / jeu d'entraînement utilisés.

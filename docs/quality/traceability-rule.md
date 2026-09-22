# Règle de traçabilité et de reporting — Netcross

**Statut :** Obligatoire pour toutes les analyses Netcross
**Date d'adoption :** 22 septembre 2026
**Référence :** Session f02f7a0d, demande utilisateur

---

## Principe fondamental

**Toute analyse Netcross doit produire un rapport, même pour dire que tout va bien.**

Rien ne doit être mis sous le tapis. L'absence de problèmes est une information
qui doit être explicitement consignée, pas une absence de rapport.

Cette règle s'applique à :
- L'analyse croisée de captures (`analyse()`)
- La comparaison de captures (`cross_capture_diff_cli.py`)
- Les détecteurs de sécurité (beaconing, exfiltration, DNS tunnel, etc.)
- Les diagnostics TLS/QUIC
- L'analyse statistique des flux
- Tout module futur produisant un résultat d'analyse

---

## 1. Structure obligatoire d'un rapport d'analyse

Chaque rapport d'analyse (texte, JSON, PDF) doit contenir les sections suivantes,
même si elles sont vides ou indiquent "RAS" (Rien à Signaler) :

### 1.1 En-tête du rapport

| Champ | Description | Exemple |
|---|---|---|
| `trace_id` | Identifiant unique de la trace/analyse (corrélable avec logs et captures) | `NC-2026-09-22-T001` |
| `timestamp` | Horodatage ISO 8601 du début de l'analyse | `2026-09-22T12:16:00+02:00` |
| `version` | Version de Netcross (git SHA court) | `abc1234` |
| `tool` | Nom de l'outil/module utilisé | `cross_capture_analyzer` |
| `operator` | Opérateur (optionnel, anonymisé si `--redact`) | `analyst_1` |

### 1.2 Section "Contexte"

- Fichiers de capture analysés (noms, tailles, nombre de paquets)
- Points de capture (noms des interfaces/labels)
- Options de ligne de commande utilisées
- Version de tshark détectée

### 1.3 Section "Entrées"

- Nombre de paquets lus par point de capture
- Plage temporelle couverte
- Liste des protocoles détectés
- Nombre de flux/conversations identifiés

### 1.4 Section "Règles appliquées"

- Liste des règles d'analyse exécutées (par `rule_id`)
- Liste des détecteurs de sécurité activés
- Seuils et paramètres utilisés

### 1.5 Section "Résultats positifs"

- Constats normaux (ex: "Aucun trou de séquence TCP détecté")
- Métriques de santé (score 0-100, label)
- Statistiques de performance (débits, latences, gigue)

**Cette section ne doit JAMAIS être vide.** Si aucune anomalie n'est détectée,
écrire explicitement : "Aucune anomalie détectée. RAS."

### 1.6 Section "Anomalies"

- Liste des constats anormaux (perte de paquets, latence élevée, etc.)
- Pour chaque anomalie : sévérité, catégorie, segment concerné, message
- Lien vers les preuves (`EvidenceLink` : paquet, point, texte)

Si aucune anomalie : "Aucune anomalie détectée. RAS."

### 1.7 Section "Avertissements"

- Limites de l'analyse (ex: "Capture trop courte pour statistiques fiables")
- Écarts par rapport à la baseline
- Points d'attention non bloquants

Si aucun avertissement : "Aucun avertissement. RAS."

### 1.8 Section "Limites"

- Conditions non couvertes par l'analyse
- Données manquantes ou incomplètes
- Dépendances externes non disponibles (ex: tshark non installé)

### 1.9 Section "Traçabilité"

- `trace_id` de l'analyse
- Chemin vers les logs associés
- Checksum des fichiers de capture analysés
- Mapping d'anonymisation utilisé (si `--redact`)

---

## 2. Règles de logging et de tracing

### 2.1 Logs obligatoires

Chaque étape importante d'une analyse doit être journalisée :

```
[INFO] trace_id=NC-2026-09-22-T001 | Début de l'analyse | captures=2, points=2
[INFO] trace_id=NC-2026-09-22-T001 | Lecture capture | point=CLIENT, packets=15423
[INFO] trace_id=NC-2026-09-22-T001 | Corrélation des flux | flows=847
[INFO] trace_id=NC-2026-09-22-T001 | Règle exécutée | rule_id=seq_gap, result=RAS
[WARN] trace_id=NC-2026-09-22-T001 | Capture trop courte | packets=142, min_recommandé=1000
[INFO] trace_id=NC-2026-09-22-T001 | Fin de l'analyse | anomalies=0, warnings=1, duration=2.3s
```

### 2.2 Règles

1. **Chaque log doit contenir le `trace_id`** — pour corrélation entre logs, rapports et captures.
2. **Les erreurs ne sont jamais silencieuses** — un `except` sans log est interdit.
3. **Les étapes "RAS" sont journalisées** — ne pas attendre qu'un problème survienne pour logger.
4. **Les avertissements sont explicites** — un warning doit dire quoi, pourquoi, et quel impact.
5. **Les limites sont documentées** — si une analyse ne peut pas s'exécuter complètement (ex: tshark absent), le dire dans le rapport ET dans les logs.

### 2.3 Niveaux de log

| Niveau | Usage |
|---|---|
| `ERROR` | Échec bloquant, l'analyse ne peut pas continuer |
| `WARN` | Problème non bloquant, l'analyse est partielle |
| `INFO` | Étape normale, résultat d'analyse (y compris RAS) |
| `DEBUG` | Détail interne (désactivé par défaut) |

### 2.4 Implémentation

- **Loguru** (PR #249 en cours) : structure de logging centralisée avec `trace_id`
  injecté automatiquement dans chaque message.
- Chaque module d'analyse reçoit un `trace_id` en paramètre ou en génère un
  si non fourni.
- Les logs sont écrits sur `stderr` par défaut, et dans un fichier si
  `--log-file` est spécifié.

---

## 3. Identifiant de trace (`trace_id`)

### 3.1 Format

```
NC-YYYY-MM-DD-T### 
```

- `NC` : préfixe fixe (Netcross)
- `YYYY-MM-DD` : date du jour
- `T###` : numéro séquentiel sur 3 chiffres (incrémenté par session)

### 3.2 Propagation

Le `trace_id` doit être propagé à travers :
- Les logs (préfixe ou champ structuré)
- Le rapport texte/JSON/PDF (en-tête)
- Les résultats d'analyse (champ `trace_id` dans le JSON)
- Les fichiers d'anonymisation (mapping)

### 3.3 Corrélation

L'utilisateur peut utiliser le `trace_id` pour :
- Retrouver les logs d'une analyse spécifique
- Corréler un rapport avec les captures source
- Suivre une trace à travers plusieurs modules
- Partager une analyse anonymisée tout en gardant le lien

---

## 4. Vérification et contrôle

### 4.1 Tests automatisés

Chaque module d'analyse doit avoir un test vérifiant que :
- Le rapport produit contient toutes les sections obligatoires
- Le `trace_id` est présent dans le rapport et les logs
- Une analyse sans anomalie produit explicitement "RAS"
- Les limites sont documentées quand elles s'appliquent

### 4.2 CI

La CI doit vérifier que :
- Les nouveaux modules d'analyse respectent la structure de rapport
- Les logs contiennent le `trace_id`
- Les tests de traçabilité passent

---

## 5. Exceptions et dérogations

Aucune dérogation permanente. Une exception ponctuelle doit être :
1. Documentée dans le rapport (section "Limites")
2. Justifiée techniquement
3. Journalisée au niveau `WARN`
4. Suivie par une issue de correction

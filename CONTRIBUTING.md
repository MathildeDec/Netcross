# Contribuer à Netcross

Merci de votre intérêt pour Netcross. Ce guide décrit le workflow de
contribution, les conventions de code, et le processus de release.

## Démarrage rapide

```bash
# Cloner et installer les dépendances de développement
git clone https://github.com/MathildeDec/Netcross.git
cd Netcross
pip install -e ".[dev]"

# Vérifier que l'environnement est fonctionnel
PYTHONPATH=src python -m pytest tests/ -q
ruff check src/ tests/
ruff format --check src/ tests/
PYTHONPATH=src lint-imports
```

Prérequis système : `tshark` (paquet `wireshark-cli` ou `tshark`).

## Workflow Git

### Branches

Le dépôt suit un modèle `dev → main` :

- **`main`** : branche stable, toujours déployable. Les PR vers `main`
  sont rejetées par le guard-main.yml si elles ne viennent pas de `dev`.
- **`dev`** : branche d'intégration. Toutes les feature PRs ciblent `dev`.
- **`feature/issue-NNN-description`** : une branche par issue, créée
  depuis `dev` :

  ```bash
  git checkout -b feature/issue-123-ma-feature dev
  ```

### Pull Requests

1. Créer une branche depuis `dev` (voir ci-dessus).
2. Coder + écrire les tests.
3. Vérifier localement : `ruff check`, `ruff format --check`, `lint-imports`,
   `pytest`.
4. Pousser et créer la PR vers `dev` :

   ```bash
   gh pr create --base dev --head feature/issue-123-ma-feature
   ```

5. La CI tourne automatiquement (lint, tests, coverage, import-linter).
6. Une fois la CI verte et la review approuvée, merger vers `dev`.
7. Périodiquement, synchroniser `dev` vers `main` via une PR dédiée.

### Conventions de commit

Format : `type(#issue): description courte`

Types : `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`.

Exemples :
```
feat(#145): statistiques de flux et conversation
fix(#149): détection de mouvement latéral sur ports non standards
docs(#216): documentation CLAUDE.md
```

## Conventions de code

### Style

- **Lint** : `ruff check` (règles : E, W, F, I, B, C4, UP, SIM, N, PERF, RUF, TID)
- **Format** : `ruff format` (line-length=120, Python 3.9+)
- **Imports** : `ban-relative-imports = "all"` — imports absolus uniquement
- **Architecture** : contrat import-linter avec couches strictes :

  ```
  netcross_gtk4 → netcross_report → netcross_api → netcross_core → pcap_parser
  ```

  Une couche ne peut importer que les couches inférieures. `pcap_parser` est
  la couche la plus basse et ne peut importer de `netcross_core`.

### Tests

- Framework : `pytest` avec `pytest-cov`
- Pattern : utiliser `make_pkt(**overrides)` de `tests/conftest.py` pour
  créer des paquets synthétiques (le modèle `Pkt` a 78+ champs requis).
- `list.append` dans une boucle déclenche `PERF401` — utiliser des
  compréhensions de liste.
- `dict()` déclenche `C408` — utiliser des littéraux `{}`.
- Lancer : `PYTHONPATH=src python -m pytest tests/ -v`

### Ajouter un détecteur de sécurité

1. Créer `src/netcross_core/security/nom_module.py` avec :
   - Une `@dataclass` pour les seuils (`_NomThresholds`)
   - Une `@dataclass` pour le résultat (`NomResult`)
   - Une fonction `detect_nom(packets) -> NomResult`
2. Intégrer dans `netcross_core/security/findings.py` via une fonction
   `nom_findings(result) -> list[dict]` et l'ajouter à `apply_security_findings`.
3. Ajouter les champs correspondants sur `Report` dans `models.py`.
4. Écrire les tests dans `tests/test_nom_module.py`.
5. Documenter dans le canvas de l'issue.

## Releases

1. Merger toutes les PRs prévues vers `dev`.
2. Synchroniser `dev` vers `main` via une PR.
3. Taguer : `git tag v1.X.0 -m "Release v1.X.0"`.
4. Mettre à jour `CHANGELOG.md`.
5. Créer la release GitHub depuis le tag.

## Signaler un bug ou une vulnérabilité

- **Bug fonctionnel** : ouvrir une issue GitHub avec le label `bug`.
- **Vulnérabilité de sécurité** : suivre la procédure décrite dans
  [SECURITY.md](SECURITY.md) — ne pas ouvrir d'issue publique.

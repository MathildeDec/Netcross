# Politique de sécurité

## Versions supportées

| Version | Supportée | Correctifs de sécurité |
|---------|-----------|----------------------|
| 1.0.x   | ✅ Oui    | ✅ Oui                |
| < 1.0   | ❌ Non    | ❌ Non                |

## Signaler une vulnérabilité

**Ne pas ouvrir d'issue GitHub publique pour les vulnérabilités de sécurité.**

À la place, envoyer un email à l'auteur (voir le profil GitHub
[@MathildeDec](https://github.com/MathildeDec)) avec :

1. Une description du problème et son impact potentiel.
2. Les étapes pour reproduire (capture pcap, commande, configuration).
3. La version de Netcross et l'environnement (OS, Python, tshark).

Vous recevrez un accusé de réception dans les 72 heures et une estimation
de délai pour un correctif.

## Portée

Cette politique couvre :

- Les vulnérabilités dans le code de Netcross (modules `netcross_core`,
  `netcross_report`, `netcross_api`, `pcap_parser`).
- Les faux positifs/négatifs dans les détecteurs de sécurité qui
  pourraient masquer une attaque réelle.

Elle ne couvre pas :

- Les vulnérabilités dans les dépendances tierces (FastAPI, reportlab,
  matplotlib, etc.) — signaler directement au projet concerné.
- Les vulnérabilités dans `tshark` / Wireshark — signaler via
  [wireshark.org/security](https://www.wireshark.org/security/).

## Mesures de sécurité intégrées

Netcross intègre plusieurs mécanismes de sécurité :

- **Guard main** : les PR vers `main` doivent passer par `dev` (workflow
  GitHub Actions `guard-main.yml`).
- **Analyse statique** : `ruff` en CI (règles de sécurité, complexity).
- **Contrat d'architecture** : `import-linter` empêche les imports
  circulaires et les violations de couches.
- **Couverture de tests** : `pytest-cov` avec commentaire de couverture
  sur chaque PR.
- **Dépendances optionnelles** : FastAPI/uvicorn sont des extras (`api`),
  jamais obligatoires pour le cœur.

## Bonnes pratiques d'utilisation

- Exécuter Netcross sur des captures désensibilisées (anonymiser les IPs
  et noms de domaine si vous partagez des captures).
- Ne pas exposer l'API REST sur une interface publique sans authentification
  (le MVP n'inclut pas d'auth — à ajouter avant tout déploiement en
  production).
- Les captures pcap contiennent des données sensibles — chiffrer les
  fichiers au repos si nécessaire.

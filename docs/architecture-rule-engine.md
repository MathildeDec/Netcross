# Décision d'architecture — build_findings() et moteur d'exécution

## Décision

Conserver deux chemins parallèles à court terme :
- synthesis.build_findings() reste la source de production des constats dans les CLI/GUI existants ;
- rule_engine.evaluate() reste le moteur d'exécution piloté par le catalogue, utilisable progressivement par les nouveaux consommateurs.
La bascule globale n'est pas effectuée dans cette passe.

## Pourquoi

build_findings() et evaluate() n'ont actuellement pas le même contrat :
1. build_findings() applique un tri final stable (sévérité, catégorie, segment) à l'ensemble des findings ;
2. evaluate() restitue l'ordre de construction des évaluateurs ;
3. toutes les règles du catalogue ne sont pas encore pilotées de façon homogène par evaluate() ;
4. certaines règles fusionnent plusieurs compteurs ou nécessitent une construction d'evidence spécifique.
Une bascule immédiate introduirait donc un changement de comportement observable et mélangerait deux chantiers : migration du moteur et évolution du catalogue.

## Plan de migration

1. Atteindre une couverture complète des règles par evaluate().
2. Garantir, par tests d'équivalence, les mêmes findings, messages, sévérités, sample_size, evidence et rule_id que build_findings().
3. Définir un tri final stable et commun.
4. Ajouter un point d'entrée unique appelé par CLI/GUI, avec compatibilité temporaire de build_findings().
5. Comparer les deux sorties sur un corpus de captures représentatif.
6. Basculer la production vers evaluate() après validation de la parité.
7. Supprimer ensuite le code procédural devenu redondant.

## Ordonnancement

Le tri doit être appliqué après l'évaluation complète, dans une couche commune, et non imposé individuellement par chaque évaluateur. Cela conserve l'indépendance des règles et garantit un ordre déterministe quel que soit leur ordre d'enregistrement.

Cette décision clôt le choix architectural du Job 27 sans modifier le comportement fonctionnel de Netcross.
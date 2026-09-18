# Session 15 — score de confiance (`sample_size`)

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8/9/10/11/12/13/14.

### Contrainte d'environnement de cette session

Vérifié en tout début de session : ni `tshark`, ni `pytest`, ni `ruff`,
ni accès réseau (`pip install` échoue, pas de miroir local). Même
situation que les Sessions 1-8/12/13, différente des Sessions 9/10/11/14.
Conséquence directe sur le choix de la feature (voir ci-dessous) et sur
la validation (harnais de secours pour rejouer `tests/`, comme aux
Sessions 8/12/13).

### Choix de la feature suivante

`FEATURES.md` section 5.2, 🟠 urgence moyenne, seuls trois candidats
restaient :
- Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet) — nécessite
  une vraie capture CAPWAP et `tshark` pour la rejouer ; inatteignable
  sans réseau ni matériel.
- Gestion mémoire des grosses captures — nécessite de profiler le
  pipeline `tshark -T ek` réel sur des captures de plusieurs Go ;
  `tshark` absent, rien à profiler concrètement dans cet environnement.
- Score de confiance / `sample_size` — pur calcul sur des structures déjà
  en mémoire (`Report`, `Finding`, `DiffFinding`), aucune dépendance à
  `tshark` ni au réseau.

Seule la troisième est réalisable ici. Retenue par élimination, comme la
Session 13 (DNS) et la Session 12 (JSON) l'avaient été en leur temps pour
la même raison.

### Décision de conception assumée

`FEATURES.md` décrivait la piste en une phrase ("coût faible, protège la
crédibilité de tous les modules"), sans détail — contrairement à la
Session 14 (comparaison client vs client) où `netcross_pistes_evolution2.md`
fournissait un design complet. Deux lectures étaient possibles :

1. Annoter **tous** les findings avec un compteur brut quelconque (`n`,
   `len(missing)`...) qui les a produits.
2. N'annoter que les findings basés sur une **valeur ESTIMÉE** (taux,
   moyenne, MOS) — pas les compteurs bruts d'événements.

Choix : la lecture 2. Raisonnement : un compteur brut ("1 RST localisé",
"1 DHCP NAK", "1 handshake avec MSS réduit") est une preuve directe et
complète — l'événement a eu lieu, un point c'est tout, indépendamment du
nombre total de paquets alentour. Un **taux** ou une **moyenne** calculés
sur un tout petit nombre de mesures, en revanche, peuvent être trompeurs
et auraient pu significativement changer avec plus de données (5% de
perte sur 2 paquets vus n'a pas le même poids de preuve que 5% sur 2000 ;
un MOS "mauvais" calculé sur 2 paquets RTP est fragile). C'est
précisément ce second cas que "score de confiance" est censé protéger —
annoter le premier cas n'aurait rien protégé de réel, juste ajouté du
bruit numérique partout. Documenté en tête de `synthesis.py` et de
`baseline_diff.py` pour que la distinction soit visible au bon endroit
si le sujet est repris plus tard.

Conséquence directe sur le périmètre : sur ~30 sites de création de
`Finding`/`DiffFinding`, seuls 4 + 4 (le pendant diff des 4 premiers)
sont annotés dans cette passe :

| Catégorie | Base du `sample_size` |
|---|---|
| Pertes (taux) | nombre de paquets vus au point (dénominateur du taux) |
| RTP/Voix (MOS) | nombre de paquets RTP au point de référence utilisé pour le calcul |
| Réseau/Serveur (temps de traitement moyen) | nombre de tours mesurés |
| DNS (durée moyenne de résolution) | nombre de mesures de durée |

Tout le reste (compteurs bruts, verdicts qualitatifs de saturation,
présence/absence d'un point ou d'un arc de topologie...) reste sans
annotation — `sample_size=None` par défaut, explicitement pas un oubli.

### Ce qui a été livré

- **`netcross_report/synthesis.py`** : `Finding.sample_size: int | None
  = None` ; peuplé sur les 4 catégories du tableau ci-dessus.
- **`netcross_core/analysis.py`** : nouvelle clé `sample_count` dans
  chaque entrée de `r.rtp_streams` (`len(per_point.get(ref_point, []))`)
  — c'est elle qui alimente `Finding.sample_size` pour RTP/Voix.
- **`netcross_core/baseline_diff.py`** : `DiffFinding.sample_size: int |
  None = None` ; peuplé côté "courant" (l'état qu'on évalue maintenant)
  pour `_compare_rate` (dénominateur), `_compare_latency`
  (`len(after)`), et les 3 blocs manuels équivalents aux 4 catégories
  ci-dessus (DNS, temps de traitement serveur, MOS RTP — le dernier via
  le même `sample_count` que Session 15 ajoute à `analysis.py`).
  `_compare_count` (comparaison de compteurs bruts) volontairement non
  touché — cohérent avec la décision de conception.
- **`netcross_report/triage.py`** :
  - `LOW_SAMPLE_THRESHOLD = 3` / `LOW_SAMPLE_WEIGHT_FACTOR = 0.5`.
  - `_finding_weight()` : amortit (× 0.5, n'exclut pas) le poids d'un
    finding dont `sample_size` est renseigné et < 3. Un finding sans
    l'attribut (namedtuple de test, ancien code) ou avec `sample_size is
    None` n'est **jamais** amorti — l'absence d'annotation n'est pas un
    signal de faiblesse, juste une absence d'information.
  - `SegmentScore.low_confidence: bool` — vrai seulement si **tous** les
    findings du segment qui pèsent réellement dans le score (poids de
    sévérité > 0) reposent sur un échantillon explicitement petit ;
    suffit qu'un seul constat actionnable soit solide pour que le
    marquage ne se déclenche pas.
  - `print_triage()` : marqueur `[ECHANTILLON FAIBLE]` à côté de
    `[CONVERGENT]`.
- **`netcross_report/pdf.py`** : `_triage_table` affiche "(echantillon
  faible)" à côté du nom du segment concerné.
- **`netcross_report/json_report.py`** : `_finding_dict` expose
  `sample_size` si non `None` (même pattern que `before`/`after`,
  absent plutôt que `null` si non pertinent) ; `_segment_score_dict`
  expose `low_confidence`.
- **GUI GTK4** : rien à câbler — même mécanisme générique déjà en place
  pour les autres findings (stdout redirigé pour `print_triage`,
  `Finding`/`DiffFinding` passés tels quels au reste de la GUI).

### Validation

Pas d'accès réseau ni `tshark` (voir "Contrainte d'environnement"
ci-dessus) :
- `python -m compileall` propre sur tout `src/` et `tests/`.
- Suite complète rejouée via le harnais de secours (même principe que
  les Sessions 8/12/13, hors de l'arbre livré) : **25 nouveaux tests**
  répartis sur `test_synthesis.py` (6), `test_triage.py` (8),
  `test_baseline_diff.py` (5), `test_json_report.py` (4),
  `test_analysis.py` (2). **350/350 au total** (325 hérités de la Session 14
  + 25 nouveaux), aucune régression sur les tests hérités.
- Un défaut préexistant du harnais est apparu en le rejouant sur toute
  la suite (pas lié à cette session) : `pytest.raises(..., match=...)`
  utilisé dans `test_client_diff.py` (Session 14) n'était pas supporté
  par le harnais. Corrigé dans le harnais lui-même (hors de l'arbre
  livré) — pas une régression du code du projet, juste une lacune du
  harnais de secours révélée par un test déjà existant.
- Vérification manuelle de bout en bout (script ad hoc, pas dans
  `tests/`) : un `Report` avec un segment "A" à fort taux de perte
  (50%) mais 2 paquets vus seulement, face à un segment "B" à taux plus
  bas (10%) mais 1000 paquets vus. Confirmé : "B" (`score=3.0,
  low_confidence=False`) prime sur "A" (`score=1.5,
  low_confidence=True`) dans le triage — exactement l'inversion de
  classement que la feature vise à éviter (sans elle, les deux auraient
  eu le même poids de sévérité "anomalie" et "A" avec son taux plus
  choquant aurait pu sembler tout aussi fiable que "B"). Vérifié aussi
  que le marqueur "(echantillon faible)" apparaît bien dans le texte
  extrait d'un vrai PDF généré (`pypdf`, texte normalisé pour absorber
  le retour à la ligne introduit par le retour à la ligne du
  `Paragraph` reportlab) et que le JSON expose `low_confidence: true`/
  `false` correctement selon le segment.
- Aucune ligne de plus de 120 caractères introduite (vérifié `awk` sur
  tous les fichiers touchés, cohérent avec la config `ruff`
  `line-length = 120` même sans pouvoir lancer `ruff` lui-même ici).

### Limite non résolue dans cette passe

**Portée volontairement restreinte à 4 catégories** (voir "Décision de
conception assumée") : les compteurs bruts (RST, NAK DHCP, options TCP
dégradées, changements de VLAN/DSCP, sauts de TTL...) ne portent pas de
`sample_size` — décision assumée, pas un oubli, mais une extension
future reste possible si un besoin concret se présente sur le terrain
(par exemple : distinguer "1 RST vu sur une capture de 3 paquets" d'"1
RST vu sur une capture de 50000 paquets" a un sens différent, mais
n'était pas le problème que cette session visait à résoudre —
"crédibilité d'une valeur ESTIMÉE", pas "contexte de volume").

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : section 5.2 — ligne "Score de confiance /
  `sample_size`" déplacée vers 5.1 avec **✅ Fait en Session 15** et
  renvoi vers `claude.md` pour la justification du périmètre.
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : pas de nouvelle commande ni flag CLI (la feature
  est transversale et s'active automatiquement partout où `Finding`/
  `DiffFinding` circulent déjà) — pas de changement nécessaire.

### Non traité dans cette passe

- **Extension aux compteurs bruts** — voir "Limite non résolue"
  ci-dessus.
- **Validation CAPWAP sur vraie capture, gestion mémoire grosses
  captures** — candidats 🟠 restants, toujours hors d'atteinte sans
  `tshark` ni matériel réel, aucun traité ici, une feature à la fois.

---


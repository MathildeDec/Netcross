# Session 49 — extension de couverture du catalogue de règles (huit règles, 23 → 31)

### Demande initiale

Consigne récurrente habituelle : « Continue les features à faire de la
comparaison avec OmniPeek. Fais évoluer les fichiers de suivi, de tests
et de documentation. » Livraison du zip horodaté
`netcross-{YYYYMMDD-HHMMSS}.zip` sans enchaîner sur la feature suivante.

### Choix de la feature

`CLAUDE.md` laissait quatre pistes après la Session 48 :

1. étendre la COUVERTURE du catalogue aux signaux restés volontairement
   `rule_id=None` ;
2. construire un vrai détecteur pour « négociations TLS incomplètes »
   (§6.2) puis le cataloguer ;
3. un début de moteur d'EXÉCUTION qui évaluerait une `Rule` contre un
   `Report` pour produire lui-même un Finding/ExpertEvent ;
4. basculer vers la Session 3 (cause probable/impact, corrélation
   causale, difficulté 5/5).

Les pistes 3 et 4 sont manifestement hors calibre pour une session
ponctuelle — `CLAUDE.md` les décrivait déjà comme telles (« chantier bien
plus large », « hors périmètre d'un ajout ponctuel »), et rien de
découvert cette session ne change cette évaluation.

Entre les pistes 1 et 2, `CLAUDE.md` notait déjà une différence de
nature : la piste 2 suppose d'écrire une détection RÉELLE dans
`analysis.py` (état d'avancement d'une poignée de main TLS par flux),
pas seulement de formaliser un signal déjà là — « chantier de nature
différente, plus proche d'une feature "normale" qu'un ajout au
catalogue ». Avant d'écarter cette piste sur la seule foi de cette note
héritée, j'ai vérifié par moi-même ce qu'impliquerait réellement « écrire
une détection réelle » ici (voir section suivante) — et cette vérification
a confirmé, pour une raison plus précise que prévu, qu'il s'agit bien
d'un chantier à part.

La piste 1 se décomposait elle-même en deux natures de travail (déjà
distinguées par `CLAUDE.md`) : cinq paires « signal isolé à côté d'une
règle déjà existante dans la même catégorie » (potentiellement de simples
formalisations, comme les Sessions 46-47), et trois catégories ENTIÈRES
encore sans aucune règle (qui nommeraient chacune un concept que la
section 6.2 n'a jamais cité). J'ai vérifié le code source de chacun des
cinq candidats avant de trancher (voir « Vérification des cinq
candidats » ci-dessous) : les cinq sont bien des formalisations pures, le
détecteur existe déjà et fonctionne, rien à écrire dans `analysis.py`.
Pour les trois catégories entières, aucune n'est nommée par §6.2 —
contrairement aux cinq paires, qui formalisent chacune une extension
directe d'un concept déjà cité (variation de TTL → délta de sauts
hors norme ; remarquage QoS → remarquage PCP ; fragmentation → signal
ICMP de fragmentation nécessaire ; DNS lent → erreurs DNS ;
SYN sans réponse → SYN-ACK localement absent). Décider d'étendre le
catalogue à « Reseau/Serveur », « TLS » ou « HTTP » demande un
raisonnement dédié par catégorie, pas une extension mécanique du même
geste — reporté explicitement (voir « Non traité »).

**Choix retenu** : les cinq paires (huit règles, la paire ICMP/ICMPv6
étant fusionnée en une seule — voir plus bas), calibré en taille sur les
Sessions 46 (+15 règles) et 47 (+8 règles).

### Découverte : `netcross_core/tls_diagnostics.py`

En vérifiant sérieusement ce qu'impliquerait la piste 2 avant de
l'écarter, j'ai cherché tout champ `tls_*`/`handshake`/`record_type`
existant sur `Pkt`/`Report` (aucun, hors les quatre champs certificat de
la Session 26 — confirme ce que documentaient déjà les Sessions 47-48),
**puis** j'ai cherché s'il existait un mécanisme de suivi de handshake
TLS *ailleurs* dans le code, plutôt que de m'arrêter à l'absence de champ
sur `Report`. Il en existe un : `netcross_core/tls_diagnostics.py`, un
module substantiel (`TlsEvent`, `HandshakeStatus`, `TlsFinding`,
`diagnose_tls()`), câblé via `--tls` sur les trois points d'entrée
(`cross_capture_analyzer_cli.py`, `cross_capture_diff_cli.py`,
`netcross_gtk4`) et documenté en README. Sa propriété
`HandshakeStatus.verdict` distingue déjà explicitement
`"client_hello_no_reply"` et `"server_hello_no_data"` — conceptuellement
très proche de « négociations TLS incomplètes ».

Ce module est **délibérément indépendant** du pipeline
`Report`/`analysis.py`/`Finding` (sa propre docstring le dit : il relit
la capture lui-même via `pcap_parser`, « zéro risque de conflit si
`analysis.py`/`models.py` sont modifiés en parallèle ») et produit son
propre type `TlsFinding` — jamais un `synthesis.Finding`. Confirmé par
grep : aucune référence croisée entre les deux pipelines, et
`redact.py`/`json_report.py` traitent explicitement `TlsFinding` comme
une famille à part (`tls_findings`/`quic_findings`, listes optionnelles
séparées de `findings`/`expert_events`).

**Conséquence sur le choix de cette session** : la conclusion des
Sessions 47-48 (« aucun détecteur réel ») reste exacte *pour le pipeline
`Report`/`Finding` spécifiquement*, donc rien ne change à la décision de
ne pas traiter ce point cette session. Mais la NATURE de la décision à
prendre plus tard change : ce n'est plus seulement « écrire un détecteur
qui n'existe pas », c'est choisir explicitement dans quel pipeline le
signal doit vivre pour devenir cataloguable — un chantier encore moins
mécanique que ne le laissait supposer `CLAUDE.md`, donc une confirmation
plutôt qu'une remise en cause du choix de reporter cette piste. Documenté
dans les deux docstrings de module concernées
(`expert_rules.py`/`synthesis.py`), dans `CLAUDE.md` et dans
`docs/features-backlog.md` pour que la prochaine session n'ait pas à
refaire cette recherche.

### Vérification des cinq candidats

Chaque candidat vérifié directement dans `analysis.py` (jamais supposé)
avant rédaction de sa règle :

- **`hop_delta_outliers`** (`Report.hop_delta`/`hop_delta_outliers`,
  boucle principale d'`analyse()`) : pour une paire de points adjacents,
  delta de TTL par flux comparé au delta le plus fréquent (mode
  statistique) sur l'ensemble des flux de cette paire. Même section de
  code que `ttl_variation`, même nature de dépendance à une hypothèse de
  topologie/ordre des points → confiance alignée sur `ttl_variation`
  (0.7).
- **`pcp_change`** (`Report.pcp_change`, même bloc que `vlan_change`) :
  comparaison directe de la priorité 802.1p entre les deux points pour un
  flux tagué VLAN aux deux points. Mécanisme identique à `vlan_change` —
  dont la docstring de règle citait déjà `pcp_change` par son nom comme
  signal voisin du même bloc de code, non exposé. Confiance alignée sur
  `vlan_change` (0.8).
- **`icmp_frag_needed` / `icmpv6_too_big`** (`Report.icmp_frag_needed`/
  `icmpv6_too_big`) : lecture native d'un type/code ICMP(v6) sur un seul
  paquet, aucune corrélation multi-points, même mécanisme que les trois
  sous-types de retransmission TCP (0.9). Les deux compteurs sont
  explicitement documentés dans le code comme équivalents IPv4/IPv6 du
  même signal — **fusionnés en une seule règle** `icmp_fragmentation_needed`,
  même discipline que `tcp_options_stripped` (Session 47, qui fusionne
  Window Scale et SACK Permitted retirés sous un seul id car même
  fonction source et même sévérité).
- **`syn_reply_missing`** (`Report.syn_reply_missing`, même fonction
  `_analyse_handshake()` que `tcp_syn_no_synack`) : un SYN-ACK
  correspondant existe et atteint au moins un point, mais pas le point où
  le SYN lui-même a été vu — signal distinct de `tcp_syn_no_synack` (qui
  lit `Report.syn_no_synack`, aucune réponse nulle part). Même fonction
  source, même garde `--nat-tolerant`, même dépendance à l'ordre des
  points → confiance alignée sur `tcp_syn_no_synack` (0.7).
- **Les quatre compteurs DNS bruts** (`dns_nxdomain_count`,
  `dns_servfail_count`, `dns_timeout`, `dns_missing`) : quatre mécanismes
  réellement différents malgré la même origine `_analyse_dns()` —
  NXDOMAIN et SERVFAIL sont des lectures natives à un seul paquet
  (confiance 0.9, sévérités `info`/`anomalie` — le code commente
  explicitement que NXDOMAIN « n'est pas forcément un problème réseau »,
  contrairement à SERVFAIL qui l'est plus souvent) ; `dns_timeout` est une
  correspondance par identifiant de transaction sans hypothèse d'ordre
  (confiance 0.8, même mécanisme que `dns_slow_resolution`) ;
  `dns_missing` a la MÊME structure de code que `sip_missing` (garde
  `if points_order:`, comparaison par paire adjacente) déjà cataloguée à
  0.8 sous `sip_issues` — aligné sur ce précédent plutôt que sur
  `ttl_variation`/`tcp_syn_no_synack` (0.7), malgré la dépendance à
  l'ordre des points, par cohérence avec la règle sœur SIP déjà écrite.
  **Gardés comme quatre règles distinctes** (pas de fusion) : leurs
  sévérités diffèrent, les fusionner masquerait cette gradation — même
  raisonnement que les trois sous-types de retransmission TCP (Session
  46, jamais fusionnés pour la même raison).

### Implémentation

- `src/netcross_core/expert_rules.py` : huit nouvelles entrées `Rule`
  insérées chacune à côté de sa règle sœur (ordre physique du fichier
  inchangé pour les 23 existantes), + paragraphe de docstring de module
  documentant le périmètre exact de la session et la découverte
  `tls_diagnostics`.
- `src/netcross_report/synthesis.py` : `rule_id=` posé sur les neuf
  sites de construction de `Finding` correspondants (`hop_delta_outliers`,
  `pcp_change`, `icmp_frag_needed`, `icmpv6_too_big`, `syn_reply_missing`,
  `dns_nxdomain_count`, `dns_servfail_count`, `dns_timeout`,
  `dns_missing`) ; docstring de module mise à jour (liste des signaux
  encore orphelins réduite de 17 à 8 sites, tous dans les trois
  catégories entières reportées). **Aucune autre ligne de
  `analysis.py`/`synthesis.py` touchée** : la logique de détection reste
  exactement celle des sessions précédentes, seule l'annotation change —
  même discipline que la Session 48.

### Tests

- `tests/test_expert_rules.py` :
  - `_EXPECTED_IDS` étendu (+8, avec commentaire « Session 49 ») ;
  - `test_catalogue_vingt_trois_regles` → `test_catalogue_trente_et_une_regles`
    (31) ;
  - `test_catalogue_huit_regles_tcp` → `test_catalogue_neuf_regles_tcp` (9,
    `syn_reply_missing` ajoute une règle au domaine TCP) ;
  - `test_list_rules_filtre_par_domaine` : 8 → 9 pour le domaine TCP ;
  - `test_regles_sans_palier_numerique_ont_des_thresholds_vides` : +8 ids
    (aucune des huit nouvelles règles n'a de seuil numérique — vérifié,
    chaque site de `Finding` déclenche sur une simple présence `n > 0` ou
    liste non vide) ;
  - quatre tests ciblés nouveaux : fusion ICMP/ICMPv6 sous une seule
    règle, sévérités des quatre règles DNS toutes distinctes, mécanisme
    partagé entre `syn_reply_missing` et `tcp_syn_no_synack` (même
    domaine, id différent), domaines de `hop_delta_outliers`/`pcp_change`
    alignés sur leurs règles sœurs ;
  - `test_negociations_tls_incompletes_non_cataloguees` : commentaire
    étendu pour mentionner `tls_diagnostics.py` sans changer l'assertion
    (toujours vraie, et pour une raison désormais plus précise) ;
  - `test_rule_id_couvre_les_vingt_trois_regles_et_respecte_le_domaine` →
    `test_rule_id_couvre_les_trente_et_une_regles_et_respecte_le_domaine` :
    les neuf signaux Session 49 déplacés du bloc « orphelins » au bloc
    « catalogués » du `Report` de test ; assertion finale inchangée dans
    sa forme (`used_rule_ids == {rule.id for rule in list_rules()}`),
    désormais vraie pour 31 règles.
- `tests/test_synthesis.py` : les neuf tests
  `test_<signal>_rule_id_reste_none` convertis en place en
  `test_<signal>_rule_id_est_<id>` (assertion `is None` → `== "<id>"`,
  docstring mise à jour pour expliquer le nouvel id plutôt que
  l'absence). Même nombre de tests avant/après dans ce fichier — aucune
  conversion n'a scindé ni fusionné de test, sauf la paire ICMP/ICMPv6
  qui reste deux tests distincts (un par compteur `Report`) pointant vers
  le même `rule_id`.

Total : **4 tests nets ajoutés** (912 → 916), tous dans
`test_expert_rules.py` ; les neuf conversions dans `test_synthesis.py`
ne changent pas le total.

### Validation

```text
pytest                                     912/912 -> 9 echecs attendus (conversions
                                            pas encore faites) -> 916/916 apres correction
ruff check .                               3 depassements de 120 caracteres corriges
                                            (chaines de docstring de regle repliees sur
                                            plusieurs lignes, aucun changement de contenu)
                                            -> All checks passed!
ruff format --check .                      114 fichiers deja formates
PYTHONPATH=src lint-imports                65 fichiers, 164 dependances, contrat respecte
                                            (inchange, aucun nouveau fichier source)
mypy --ignore-missing-imports              0 erreur imputable a expert_rules.py/synthesis.py
  expert_rules.py synthesis.py             (memes 27 erreurs preexistantes reconfirmees,
                                            triage.py/packet.py/ek_source.py/history.py/
                                            parsing.py/analysis.py/netcross_report/__init__.py)
python -m compileall -q src/               propre
diff -rq contre le zip d'entree            exactement expert_rules.py, synthesis.py,
  (hors caches d'outils)                   test_expert_rules.py, test_synthesis.py modifies
```

Pas de validation bout en bout via un pcap réel — même raison qu'aux
Sessions 46-48 : les huit détecteurs sous-jacents sont déjà réels et déjà
couverts par les tests existants d'`analysis.py`/`synthesis.py` (non
modifiés cette session) ; seule l'annotation `rule_id` est nouvelle, et
le test d'agrégation étendu (`test_expert_rules.py`) appelle la vraie
`build_findings()`, pas un double du code.

### Non traité

- Les trois catégories entières encore sans règle (`"Reseau/Serveur"` —
  décomposition applicatif/réseau, un seul site, heuristique
  `avg_server > 3 * avg_net` plus complexe que les cinq paires traitées
  ici ; `"TLS"` — certificat hors validité/substitué, Session 26, 2 sites ;
  `"HTTP"` — codes de statut, Session 17, 5 sites) : aucune nommée par
  §6.2, décision reportée catégorie par catégorie à une session future.
- « Négociations TLS incomplètes » : toujours pas de détecteur réel dans
  le pipeline `Report`/`Finding` — voir « Découverte » ci-dessus pour ce
  qui change dans la nature de cette décision.
- Tout moteur d'EXÉCUTION qui évaluerait une `Rule` contre un `Report`
  pour produire lui-même un Finding/ExpertEvent.
- Cause probable/impact et Sessions 3 à 11 de la feuille de route
  (`docs/features-backlog.md` section 13.3) : inchangé.
- `README.md` : volontairement non modifié, même raison qu'aux Sessions
  46-48 (aucune capacité visible pour l'utilisateur final — CLI/PDF/GUI
  inchangés, seul le JSON gagne des valeurs pour un champ déjà exposé
  depuis la Session 48).

### Fichiers modifiés

```text
src/netcross_core/expert_rules.py     (+8 regles, docstring de module)
src/netcross_report/synthesis.py      (rule_id sur 9 sites, docstring de module)
tests/test_expert_rules.py            (+4 tests nets, plusieurs renommes/etendus)
tests/test_synthesis.py               (9 tests convertis en place)
CLAUDE.md                             (etat courant + prochaine feature)
docs/features-backlog.md              (section 4 : nouvelle entree ; section 13.3 :
                                        nouveau paragraphe)
docs/sessions/session-49.md           (nouveau — ce fichier)
```

### Pour la session suivante

`CLAUDE.md` liste trois pistes (les quatre de la Session 48 moins celle
traitée ici) : les trois catégories entières restantes du catalogue,
« négociations TLS incomplètes » (avec la décision architecturale
préalable identifiée cette session — voir `CLAUDE.md`/section 13.3), le
moteur d'EXÉCUTION, ou la Session 3. Le choix précis, comme toujours, se
fait en début de session suivante avec son propre raisonnement.

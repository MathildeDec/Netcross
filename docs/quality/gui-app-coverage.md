# Couverture de la GUI : ce qui est testé, ce qui ne l'est pas

`src/netcross_gtk4/app.py` importe `gi` (PyGObject) en tête de fichier. PyGObject n'est pas installé en CI : **aucune ligne de ce fichier ne peut y être exécutée**, quel que soit le nombre de tests écrits. L'issue #285 a donc consisté à sortir de `app.py` les décisions qui ne dépendent pas de GTK, pour les tester dans des modules importables sans serveur graphique.

## Lots livrés

| Lot | PR | Module extrait | Contenu |
|---|---|---|---|
| 1 | #290 | `netcross_gtk4/row_labels.py` | libellés et clés des lignes du tableau de bord |
| 2 | #291 | `netcross_gtk4/run_outcome.py` | état de résultat en fin d'analyse ou de comparaison |
| 3 | #292 | `netcross_gtk4/panel_state.py` | visibilité des panneaux, bouton Lancer, sélection |
| 4 | #295 | `netcross_gtk4/bpf_panel.py` | menu et sauvegarde des filtres BPF de la capture live |
| 5 | ce lot | `netcross_gtk4/capture_list.py` | énumération, noms par défaut, déplacement et retrait des lignes |

Chaque module est couvert à 100 % et ne dépend d'aucun objet GTK par son type : les tests utilisent des objets factices qui reproduisent le seul contrat appelé.

### Ce que le lot 5 a corrigé

- **Retirer une capture ne prévenait pas la fenêtre.** Le bouton Lancer gardait l'état calculé avant le retrait, par exemple actif avec une seule capture restante en mode simple. Le retrait rappelle maintenant `on_change`, comme l'ajout.
- **Les lignes de capture live descendaient sans borne.** Seul le comportement d'insertion de `Gtk.ListBox` (ajout en fin au-delà de la longueur) gardait la dernière ligne en place, avec un clignotement de sélection à chaque clic. Les lignes de fichiers avaient été corrigées au lot 4 ; les deux types passent désormais par `capture_list.deplacer_ligne`.

## Ce qui reste non couvert, chiffré

Mesure reproductible :

```bash
uv run --no-sync python3 scripts/gui_inventory.py
```

Le script classe chaque méthode selon qu'elle nomme directement `Gtk`, `Gio`, `GLib`, `Gdk` ou `Pango` (ou est un `__init__`, qui construit des widgets), et compte ses instructions. Après le lot 5 :

| Catégorie | Méthodes | Instructions |
|---|---|---|
| Touchant GTK ou `__init__` | 34 | 893 |
| Sans objet GTK nommé | 64 | 374 |

Les **893 instructions** de la première ligne construisent des widgets, ouvrent des dialogues ou planifient des rappels `GLib.idle_add`. Elles ne sont testables qu'avec PyGObject et un affichage virtuel (Xvfb ou le backend Broadway).

Les **374 instructions** de la seconde ligne n'appellent pas GTK par son nom, mais presque toutes lisent ou écrivent un widget par un attribut (`self.run_btn.set_sensitive(...)`, `self.diff_check.get_active()`). Ce qu'elles décident a déjà été extrait par les lots 2 à 5 : ce qui reste applique ces décisions. Les sortir aussi reviendrait à tester qu'un appel est transmis, sans rien vérifier de plus sur le comportement.

La plus grosse exception est `MainWindow.on_run_analysis` (42 instructions) : elle lit les panneaux, valide les options et lance le thread d'analyse. C'est le candidat naturel d'un lot suivant si la couche GTK venait à être testée ; en l'état, elle reste non couverte.

## Décision : pas de `# pragma: no cover`

Le reste n'est **pas** exclu de la mesure par `# pragma: no cover` ni par `omit`. Une exclusion ferait monter le pourcentage sans que rien de plus ne soit testé, et masquerait tout nouveau code ajouté plus tard dans `app.py`, qu'il soit testable ou non. Le chiffre de couverture reste donc honnête : `app.py` à 0 %, et le code testable hors de ce fichier.

Tester la couche GTK elle-même (PyGObject et affichage virtuel en CI) est une décision distincte, à ouvrir dans une issue séparée si elle est jugée utile.

## Règle pour le code futur

Une nouvelle règle de la GUI (quand activer un bouton, quoi afficher, dans quel ordre) va dans un module de `netcross_gtk4/` sans `import gi`, avec ses tests. `app.py` se contente de lire les widgets, d'appeler la règle et d'appliquer son résultat.

Chaque module extrait est protégé par un test qui analyse `app.py` avec `ast` et vérifie que les fonctions appelées existent : une faute de frappe dans `app.py` ne casserait qu'au lancement de la GUI, ce qu'aucun test de la CI n'exécute.

## Vérification manuelle

Ces changements touchent `app.py`, que la CI n'exécute pas. Avant de fusionner un lot, sur un poste avec GTK 4 :

1. Mode simple : ajouter deux captures, puis en retirer une. Le bouton Lancer doit se griser et son infobulle indiquer le nombre de captures manquantes.
2. Mode comparaison : même vérification sur chaque panneau (baseline et courant).
3. Monter la première ligne et descendre la dernière : rien ne doit bouger ni clignoter.
4. Mode live : ajouter trois points, les réordonner, retirer le dernier. Les noms par défaut restent `POINT1`, `POINT2`, etc., et le bouton suit.
5. Lancer une analyse : l'ordre des points dans le rapport est celui de la liste.

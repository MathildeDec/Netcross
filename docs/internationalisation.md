# Internationalisation

Netcross utilise GNU gettext, comme Gcm4. Les chaînes affichées à l'utilisateur doivent passer par `_()` et les formes plurielles par `ngettext()`.

## Catalogue source et langues

`lang/messages.pot` est le catalogue source. La liste des langues prises en charge est centralisée dans `lang/locales.txt`, selon les conventions POSIX de Gcm4. Ne dupliquez pas cette liste dans le code applicatif.

## Mettre à jour les catalogues

Installez GNU gettext puis exécutez :

```bash
bash scripts/i18n-update.sh
```

Cette commande extrait les chaînes Python de `src/`, met à jour le fichier `.pot`, préserve les traductions existantes avec `msgmerge`, initialise les langues déclarées si nécessaire, contrôle les catalogues et produit les `.mo` sous `lang/<locale>/LC_MESSAGES/netcross.mo`.

Les nouvelles chaînes restent volontairement avec un `msgstr` vide : la génération ne crée pas de traduction automatique considérée comme validée.

## Ajouter une langue

1. Ajoutez une locale POSIX à `lang/locales.txt`.
2. Exécutez `bash scripts/i18n-update.sh`.
3. Traduisez les `msgstr` du nouveau fichier `.po`.
4. Vérifiez les catalogues avec `msgfmt --check` avant de les committer.

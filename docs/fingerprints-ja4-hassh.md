# Empreintes JA4 / HASSH

Netcross calcule deux empreintes passives, à partir du seul trafic
observé, sans rien émettre :

- **JA4** identifie un **client TLS** (curl, un navigateur, un
  implant) par la combinaison version / ciphers / extensions / ALPN /
  algorithmes de signature qu'il propose dans son `ClientHello`.
- **HASSH** identifie un **client ou un serveur SSH** par la liste
  d'algorithmes qu'il annonce dans son `KEXINIT`.

Les deux messages circulent **en clair**, même en TLS 1.3 : l'empreinte
est disponible sans déchiffrement, et reste valable si le service tourne
sur un port non standard.

## Lecture d'une ligne de rapport

```
[ok] TLS/JA4/curl 8.18.0 @ 127.0.0.1 JA4=t13i3012h2_1d37bd780c83_8537cf56674e
     [ciphers=[0x1302,0x1303,0x1301,0xc02c,...] -- aucune vulnerabilite connue (point(s) POINT_A)
```

| Élément | Signification |
|---|---|
| `curl 8.18.0` | outil reconnu dans la base d'empreintes connues ; absent si l'empreinte est inconnue |
| `JA4=…` | le hash lui-même, comparable à toute base JA4 publique |
| `[ciphers=…]` | forme lisible, **tronquée** à l'affichage (la valeur complète reste dans le JSON et l'API) |

Structure d'un JA4 : `t13i3012h2_1d37bd780c83_8537cf56674e` — partie
lisible (transport, version, nombre de ciphers/extensions, ALPN), puis
deux hashs tronqués à 12 caractères hexadécimaux.

Une empreinte **inconnue** n'est pas un problème : c'est une piste. Deux
hôtes qui partagent un JA4 absent de la base exécutent probablement le
même binaire.

## Conformité au calcul de référence

Le calcul a été écrit depuis la spécification publique FoxIO, puis
**vérifié contre l'implémentation de référence de Wireshark**
(`tls.handshake.ja4`, `ssh.kex.hassh`, `ssh.kex.hasshserver`) sur du
trafic réellement capturé. Les deux implémentations concordent caractère
pour caractère.

Cette vérification n'est pas un contrôle ponctuel : les trames réelles
sont figées dans `tests/data/reference_fingerprints.json`, avec la valeur
attendue **calculée par Wireshark, pas par nous**. Une dérive de notre
algorithme fait échouer `tests/test_fingerprints_reference.py`, sans
exiger tshark pour cela.

## Base d'outils connus

`src/netcross_core/fingerprint/known_fingerprints.json` associe une
empreinte à un nom d'outil. Chaque entrée documente sa provenance :

```json
"t13i3012h2_1d37bd780c83_8537cf56674e": {
  "libelle": "curl 8.18.0",
  "outil": "curl",
  "version": "curl 8.18.0 (x86_64-pc-linux-gnu) libcurl/8.18.0 OpenSSL/3.5.5 ...",
  "lisible": "ciphers=[...] extensions=[...] alpn=[h2,http/1.1] sni=False",
  "verifie_contre": "tshark 4.6.4",
  "methode": "capture reelle sur boucle locale"
}
```

Une empreinte sans provenance ne peut être ni contestée ni reproduite,
d'où ces champs. Un test vérifie qu'aucune entrée n'en est dépourvue.

La base livrée couvre curl (TLS 1.2 et 1.3), wget, `openssl s_client`,
le module `ssl` de Python, et OpenSSH (client et serveur). Elle est
**volontairement non exhaustive** : elle ne contient que les outils
présents sur la machine de génération. L'absence d'un navigateur ne dit
rien de son empreinte.

### Enrichir la base

```bash
sudo env "PYTHONPATH=src:$(python3 -c 'import site;print(site.getusersitepackages())')" \
    python3 scripts/capture_reference_fingerprints.py
```

Le script monte un serveur TLS et un `sshd` sur la boucle locale, y
lance chaque client disponible, capture le trafic avec tshark, puis —
pour chaque empreinte — **compare notre calcul à celui de tshark**. En
cas de désaccord l'empreinte est **rejetée et le désaccord signalé**,
jamais enregistrée. Si rien n'a pu être collecté, la base existante
n'est pas écrasée.

`--dry-run` affiche le résultat sans écrire.

Une base maintenue à la main est également acceptée, avec des valeurs
sous forme de simple chaîne :

```json
{"ja4": {"t13i…": "client maison 2.1"}, "hassh": {}}
```

## Limites

- **JA4 n'est pas une preuve d'identité.** Un attaquant qui connaît
  l'empreinte d'un navigateur peut la reproduire. L'empreinte est un
  indice de corrélation, pas une authentification.
- **Deux outils liés à la même bibliothèque TLS peuvent partager une
  empreinte.** `curl` et `openssl s_client` reposent tous deux sur
  OpenSSL 3.5.5 ; ils se distinguent ici par leurs extensions et leur
  ALPN, mais rien ne garantit que ce sera toujours le cas.
- **Une empreinte dépend de la version.** Une mise à jour de l'outil
  suffit à la changer ; une base d'empreintes se périme.
- **Les valeurs GREASE (RFC 8701) sont écartées** du calcul. Elles sont
  tirées au hasard à chaque connexion : les inclure ferait varier
  l'empreinte du même outil d'un handshake à l'autre.

## Où le code se trouve

| Fichier | Rôle |
|---|---|
| `netcross_core/fingerprint/tls_ja4.py` | parsing du `ClientHello`, calcul JA4 |
| `netcross_core/fingerprint/ssh_hassh.py` | parsing du `KEXINIT`, calcul HASSH |
| `netcross_core/fingerprint/known.py` | chargement de la base d'outils connus |
| `netcross_core/fingerprint/report.py` | consolidation en entrées de rapport |
| `netcross_report/security_report.py` | rendu (`ServiceEntry`, `_format_fingerprint`) |
| `scripts/capture_reference_fingerprints.py` | génération vérifiée de la base |

Le parsing lit directement la charge utile TCP plutôt que les champs EK
de tshark, comme `application.banners` : l'analyse fonctionne donc sur
une capture dont tshark n'aurait pas reconnu le protocole (port non
standard, dissecteur désactivé).

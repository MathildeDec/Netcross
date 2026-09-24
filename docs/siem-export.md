# Export SIEM : CEF, LEEF, STIX 2.1 (issues #170, #279)

Les constats du [rapport de sécurité](security-report.md) peuvent être exportés pour une
plateforme externe :

```bash
cross_capture_analyzer_cli.py --capture LAN=lan.pcapng --security-report \
    --siem-export stix --siem-output constats.stix.json
```

| Format | Cible | Nature | Module |
|---|---|---|---|
| `cef` | ArcSight ; Splunk, ELK, Wazuh via parseur | une ligne de log par constat | `netcross_report.siem_export` |
| `leef` | IBM QRadar (LEEF 2.0) | une ligne de log par constat | `netcross_report.siem_export` |
| `stix` | MISP, OpenCTI, plateformes de Threat Intelligence | graphe d'objets JSON (bundle STIX 2.1) | `netcross_report.stix_export` |

L'envoi vers le SIEM (syslog, HEC, API QRadar) est hors périmètre : c'est du transport, pas du
format.

## CEF et LEEF : deux projections des mêmes enregistrements

`_to_siem_records(report)` sélectionne et normalise une fois les champs de chaque constat
(sévérité numérique 1-10, identifiant de signature stable par catégorie, horodatage) ;
`to_cef()` et `to_leef()` ne font que la mise en forme. La sortie CEF est figée par
`tests/test_siem_cef_golden.py` (capturée avant ce refactoring).

Ligne LEEF produite :

```
LEEF:2.0|Netcross|Netcross|1.0|100|x09|cat=exploit<TAB>sev=8<TAB>devTime=Jan 02 2026 03:04:05.678 UTC<TAB>devTimeFormat=MMM dd yyyy HH:mm:ss.SSS z<TAB>src=203.0.113.9<TAB>dst=10.0.0.5<TAB>dstPort=8080<TAB>point=LAN<TAB>msg=Log4Shell ...
```

- séparateur d'attributs : tabulation, déclarée `x09` dans l'en-tête (défaut QRadar) ;
- en-tête : `|` et `\` échappés par `\` ;
- valeurs : `\`, `=`, tabulation et fins de ligne échappés (`\\`, `\=`, `\t`, `\n`) — un
  événement tient toujours sur une ligne ;
- attributs standard `cat`, `sev`, `devTime`/`devTimeFormat`, `src`, `dst`, `dstPort` ;
  attributs propres `point` (point de capture), `cveId`, `msg` (détail, 1000 caractères max).

CEF et LEEF sont horodatés à l'heure de l'export : les constats ne portent pas l'heure de leur
paquet.

## STIX 2.1 : observation ou indicateur ?

Un `indicator` STIX affirme « ce motif signale une activité malveillante » — une affirmation
partageable, que d'autres réutiliseront pour bloquer ou alerter. Or Netcross, le plus souvent,
**observe** : « cet hôte annonce cette version », « ce certificat est auto-signé ». Transformer
chaque constat en `indicator` polluerait une plateforme de TI avec des observations locales sans
valeur pour autrui. D'où la répartition :

| Constat Netcross | Objets STIX | Pourquoi |
|---|---|---|
| service + version détectés | `observed-data` → `ipv4-addr`/`ipv6-addr`, `software`, `network-traffic` (si port connu) | fait observé |
| CVE confirmée | `vulnerability` (référence externe `cve`) + `relationship` `has` depuis le `software` | la CVE est l'affirmation, elle existe déjà |
| signature d'exploit | `indicator` (`malicious-activity`, motif `[network-traffic:src_ref.value = '…' AND network-traffic:dst_ref.value = '…' AND network-traffic:dst_port = …]`) | seul cas où le motif signale bien une activité malveillante |
| autre anomalie avec hôte (TLS, exfiltration…) | `observed-data` + `note` (l'analyse Netcross) | une observation et son interprétation, pas un verdict |
| autre anomalie sans hôte (tunneling DNS par domaine…) | `note` rattachée au `report` | idem |

**Aucun constat d'observation ne produit d'`indicator`** (testé). Un `report` regroupe tous les
objets ; ce qui n'a pas pu être représenté (exploit sans adresse IP, CVE sans identifiant…) y est
compté dans `x_netcross_skipped`.

Chaque SDO porte `created_by_ref` vers l'identité « Netcross » (`identity_class: system`) et une
`confidence` explicite — une confiance, pas une sévérité :

| Objet | Confiance | Raison |
|---|---|---|
| observation (`observed-data`, `note`) | 85 | vue sur le fil, mais une bannière se falsifie |
| `vulnerability` / `relationship` | 60 | corrélation par numéro de version : les rétroportages de correctifs donnent des faux positifs |
| `indicator` | 80 / 70 / 50 / 30 selon la sévérité critique / élevée / moyenne / faible | tentative observée, pas compromission |

### Déterminisme

Un bundle exporté deux fois depuis la même capture est **identique octet pour octet**
(testé, y compris en inversant l'ordre des constats) — sinon deux exports produiraient deux
graphes qu'aucune plateforme ne saurait dédupliquer :

- identifiants de SCO : UUID v5 dans l'espace de noms STIX `00abedb4-aa42-4ca2-8a3c-1ad8e8b8f48d`
  sur les propriétés contributives de la spécification (§2.9) — deux outils conformes donnent le
  même identifiant à la même adresse IP ;
- identifiants de SDO/SRO et du bundle : UUID v5 dans un espace de noms Netcross, dérivés du
  contenu ;
- dates : premier et dernier paquet de la capture (`created`, `first_observed`, `published`…),
  jamais l'heure de l'export ;
- objets triés par identifiant, JSON à clés triées.

### Conformité au schéma

Le JSON est produit à la main (aucune dépendance d'exécution) et validé dans les tests contre les
schémas OASIS par `stix2-validator` (dépendance de développement, `<3.3` : les wheels 3.3.x sont
publiés sans les schémas). Avertissements assumés (des « SHOULD » de la spécification) :

- `{103}` UUID v5 au lieu de v4 pour les SDO : le prix du déterminisme ;
- `{202}` `software` n'est pas une source suggérée pour `has` (OpenCTI l'accepte) ;
- `{301}` `network-traffic` sans port source : un service est observé côté serveur ;
- `{401}` propriétés personnalisées `x_netcross_point`, `x_netcross_cvss`, `x_netcross_skipped`
  plutôt qu'une extension déclarée.

## Confidentialité

Un export — surtout STIX, conçu pour être **partagé** — sort des données de topologie interne :
adresses IP, services et versions exposés, vulnérabilités. Avant de publier un bundle sur une
plateforme communautaire (MISP partagé, OpenCTI multi-organisation), relisez-le et restreignez
sa diffusion (TLP). `--security-report` étant incompatible avec `--redact`, l'export n'est
jamais anonymisé.

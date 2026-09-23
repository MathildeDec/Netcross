# Extraction des contenus (audio, vidéo, documents)

Netcross peut, **à titre d'analyse qualitative**, mesurer ce que le transport a fait subir
aux flux audio et vidéo, et — sur demande explicite — extraire le son, la vidéo et les
documents transportés par une capture.

!!! warning "Rappel d'usage raisonné"
    Les contenus extraits (voix, vidéo, documents, courriels) sont des **correspondances et
    des données personnelles**. Leur extraction ne se justifie que sur un réseau dont vous
    avez la charge, pour un diagnostic ou une investigation de sécurité, les personnes
    concernées ayant été informées (RGPD art. 5 et 6 ; secret des correspondances, art.
    226-15 du Code pénal ; information préalable des salariés, art. L1222-4 du Code du
    travail). Limitez-vous au strict nécessaire, ne diffusez pas les fichiers et supprimez-les
    une fois l'analyse terminée.

    Ce rappel est affiché à chaque extraction et recopié dans `LISEZ-MOI.txt` et
    `manifest.json`.

## Deux niveaux, du plus sobre au plus intrusif

| Option | Ce qui est écrit | Usage |
|---|---|---|
| `--media-quality` | **rien** | note de dégradation des flux RTP : à privilégier quand elle suffit |
| `--extract-contents DIR` | son, vidéo, documents, manifeste | écouter/voir ce que l'utilisateur a réellement reçu |
| `--extract-kinds audio,video,documents` | restreint l'extraction | ne prendre que le nécessaire |

```bash
netcross-analyze --capture LAN=appel.pcap --media-quality
netcross-analyze --capture LAN=appel.pcap --extract-contents ./contenus --extract-kinds audio
```

Refus explicites : `--extract-contents` avec `--redact` (une voix ou un document ne
s'anonymise pas, le mélanger à un rapport anonymisé serait trompeur), avec `--live`
(les fichiers sont relus), ou vers un répertoire non vide (un manifeste par extraction).

## Note de dégradation due au transport

Pour chaque flux RTP (5-uplet UDP + SSRC) : paquets reçus/attendus, pertes, **plus longue
rafale de pertes**, doublons, paquets hors ordre, gigue (RFC 3550), puis une note de
**0 (intact) à 100 (inexploitable)** :

- **audio** : E-model simplifié (ITU-T G.107, même calcul que le MOS du rapport) ;
  note = part du R-factor perdue. Le délai de bout en bout n'est pas mesurable depuis un
  seul point : il est **estimé** (paquetisation + tampon de gigue) et signalé comme tel ;
- **vidéo** : part des images (un horodatage RTP) touchées par une perte ;
- codec non identifié : statistiques de transport seules, pas de note.

Verdict : `imperceptible` (< 5), `legere` (< 15), `genante` (< 35), `severe`.

```
LAN 10.0.0.1:40000 -> 10.0.0.2:50000 ssrc=0x00001234 -- audio PCMU : degradation 60/100 (severe)
    94 paquet(s) recu(s) / 100 attendu(s), pertes 6.0 % (rafale max 6), doublons 0, desordre 0, gigue 0.0 ms
    MOS estime 1.94 (R-factor 37)
    (delai estime 20 ms (paquetisation + tampon de gigue), non mesure)
```

6 % de pertes suffisent à rendre une conversation G.711 pénible : le modèle retenu
(sans masquage des pertes) est volontairement sévère, comme le MOS du rapport.

Le codec vient du SDP vu dans la capture (SIP sur UDP ou TCP ; `a=rtpmap`, associé par
adresse/port de `m=`/`c=`), à défaut des types statiques RFC 3551. Un flux n'est retenu que
s'il compte au moins 10 paquets aux numéros de séquence majoritairement consécutifs.

## Ce qui est extrait

| Type | Formats | Sortie |
|---|---|---|
| audio | G.711 µ-law / A-law | `audio/*.wav` (16 bits, mono) ; **chaque paquet perdu devient un silence** de même durée : on entend ce que le réseau a livré |
| vidéo | H.264 (RFC 6184 : NAL simple, STAP-A, FU-A) | `video/*.h264` (Annex B, lisible par `ffplay`/VLC) ; un NAL fragmenté incomplet est écarté |
| documents | HTTP, SMB, courriel (IMF), TFTP, FTP-DATA | `documents/<point>/<protocole>/`, via `tshark --export-objects` |

Autres codecs (Opus, G.722, G.729, VP8…) : note de dégradation seulement. Flux **SRTP**
(SDP `RTP/SAVP`) : statistiques de transport, contenu chiffré non exporté.

Le répertoire est créé en `0700`, chaque fichier en `0600`. `manifest.json` décrit chaque
flux (qualité, fichier produit) et chaque document (protocole, taille, **SHA-256**, type
détecté par signature) ; les erreurs de `tshark` (protocole non pris en charge par la
version installée, par exemple) y sont listées sans interrompre l'extraction.

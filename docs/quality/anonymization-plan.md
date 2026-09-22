# Plan d'anonymisation et de marqueurs — Campagne de 100 traces

**Statut :** Planification
**Date :** 22 septembre 2026
**Référence :** Session f02f7a0d, demande utilisateur

---

## Contexte

L'utilisateur prévoit de tester l'outil Netcross abouti sur une centaine de
traces différentes. Les résultats, logs et tracing seront transmis pour analyse
et amélioration. Il est essentiel de disposer d'outils d'anonymisation robustes
et de marqueurs corrélables pour partager ces données sans exposer d'informations
sensibles.

---

## 1. État actuel de l'anonymisation

Le module `src/netcross_core/redact.py` (231 lignes) fournit déjà :

### Ce qui est anonymisé
- Adresses IP (IPv4 → RFC 5737 TEST-NET, IPv6 → RFC 3849 2001:db8::/32)
- Adresses MAC (→ 02:00:00:00:00:00 + compteur, bit "locally administered")
- Mapping déterministe (même adresse → même pseudonyme)
- Persistance du mapping (`--redact-map` pour le conserver)
- Mutation en place (pas de copie mémoire)
- Export du mapping en CSV (`write_redaction_map_csv`)

### Ce qui n'est PAS encore anonymisé (limites actuelles)
- Noms DNS (`dns_qry_name`)
- URI/host HTTP (`http_uri`)
- SAN de certificats TLS (`tls_cert_san`)
- Identifiants SIP (`sip_call_id`, `sip_user_agent`, `sip_server`)
- Usernames/tokens dans les charges utiles
- Chemins de fichiers sensibles
- Noms d'hôtes dans les métadonnées

---

## 2. Extensions nécessaires

### 2.1 Extension du périmètre d'anonymisation

| Catégorie | Champ(s) concerné(s) | Stratégie d'anonymisation |
|---|---|---|
| Noms DNS | `dns_qry_name` | Remplacement par `domain-<n>.example` (RFC 2606) |
| Hosts HTTP | `http_uri`, `http_host` | Remplacement par `host-<n>.example` + préservation du chemin |
| SAN TLS | `tls_cert_san` | Remplacement par `san-<n>.example` |
| SIP | `sip_call_id`, `sip_user_agent`, `sip_server` | Remplacement par `sip-<n>@example` |
| Usernames | Charges utiles détectées | Remplacement par `user-<n>` |
| Tokens | Charges utiles détectées | Remplacement par `token-<n>` |
| Chemins | Métadonnées, logs | Remplacement par `/path/to/` + compteur |

### 2.2 Marqueurs corrélables

Chaque trace anonymisée doit porter des marqueurs stables permettant de
corréler trace, logs, rapport et résultat d'analyse :

#### `trace_id` (déjà défini)
Format : `NC-YYYY-MM-DD-T###`
Présent dans : rapport, logs, JSON, mapping d'anonymisation.

#### `capture_id` (nouveau)
Identifiant stable pour chaque capture source, même après anonymisation.
Format : `CAP-<hash-courant-du-fichier-anonymisé>`
Permet de retrouver une capture spécifique dans un lot de 100.

#### `run_id` (nouveau)
Identifiant d'un run d'analyse complet (peut concerner plusieurs captures).
Format : `RUN-<timestamp-unix>-<random-4>`
Permet de regrouper les résultats d'un même run.

### 2.3 Rapport de transformation

L'anonymisation doit produire un rapport de transformation documentant :

```json
{
  "trace_id": "NC-2026-09-22-T001",
  "run_id": "RUN-1763538960-a1b2",
  "timestamp": "2026-09-22T12:16:00+02:00",
  "input_files": [
    {"original": "capture-client.pcap", "capture_id": "CAP-abc123", "redacted": "capture-client.redacted.pcap"}
  ],
  "transformations": {
    "ipv4_addresses": {"count": 42, "example": "192.168.1.1 → 192.0.2.1"},
    "ipv6_addresses": {"count": 3, "example": "fe80::1 → 2001:db8::1"},
    "mac_addresses": {"count": 12, "example": "00:1a:2b:3c:4d:5e → 02:00:00:00:00:01"},
    "dns_names": {"count": 87, "example": "internal.corp → domain-1.example"},
    "http_uris": {"count": 15, "example": "https://api.corp/v1 → https://host-1.example/v1"},
    "tls_sans": {"count": 5, "example": "*.corp → san-1.example"},
    "sip_ids": {"count": 2, "example": "sip:1001@pbx.corp → sip:1@example"},
    "usernames": {"count": 4, "example": "admin → user-1"},
    "tokens": {"count": 1, "example": "Bearer eyJ... → token-1"},
    "paths": {"count": 8, "example": "/var/log/syslog → /path/to/1"}
  },
  "preserved": ["protocol_distribution", "timing_patterns", "packet_sizes", "tcp_flags"],
  "warnings": [
    "2 charges utiles binaires non anonymisées (non-texte)",
    "1 certificat TLS auto-signé non anonymisé (clé publique préservée)"
  ],
  "limits": [
    "Les patterns de trafic (tailles, timings) sont préservés et peuvent être identifiants"
  ]
}
```

---

## 3. Architecture technique

### 3.1 Extension du module `redact.py`

```
src/netcross_core/redact.py (existant, 231 lignes)
  ├── AddressRedactor (existant) — IP/MAC
  ├── DnsNameRedactor (nouveau) — noms DNS
  ├── HttpUriRedactor (nouveau) — URI/host HTTP
  ├── TlsSanRedactor (nouveau) — SAN de certificats
  ├── SipIdRedactor (nouveau) — identifiants SIP
  ├── UsernameRedactor (nouveau) — usernames dans charges utiles
  ├── TokenRedactor (nouveau) — tokens dans charges utiles
  ├── PathRedactor (nouveau) — chemins de fichiers
  └── CompositeRedactor (nouveau) — orchestre tous les redactors
```

### 3.2 Nouveau module `trace_context.py`

```
src/netcross_core/trace_context.py (nouveau)
  ├── TraceContext (dataclass)
  │     ├── trace_id: str
  │     ├── run_id: str
  │     ├── capture_ids: dict[str, str]  # chemin original → capture_id
  │     ├── timestamp: datetime
  │     └── version: str  # git SHA
  ├── generate_trace_id() -> str
  ├── generate_run_id() -> str
  └── compute_capture_id(path: str) -> str  # hash du fichier anonymisé
```

### 3.3 Nouveau module `transformation_report.py`

```
src/netcross_core/transformation_report.py (nouveau)
  ├── TransformationReport (dataclass)
  │     ├── trace_id: str
  │     ├── run_id: str
  │     ├── input_files: list[dict]
  │     ├── transformations: dict[str, dict]
  │     ├── preserved: list[str]
  │     ├── warnings: list[str]
  │     └── limits: list[str]
  ├── generate_transformation_report(...) -> TransformationReport
  └── write_transformation_report(report, path) -> None  # JSON
```

### 3.4 CLI

Nouvelles options CLI pour `cross_capture_analyzer_cli.py` :

```
--trace-id ID          # Spécifier un trace_id (auto-généré sinon)
--anonymize            # Activer l'anonymisation complète (étend --redact)
--anonymize-report PATH  # Écrire le rapport de transformation
--log-file PATH        # Écrire les logs dans un fichier (avec trace_id)
```

---

## 4. Workflow de la campagne de 100 traces

### 4.1 Préparation

1. L'utilisateur dispose de ~100 fichiers de capture (pcap/pcapng)
2. Pour chaque capture :
   a. Exécuter `netcross --anonymize --anonymize-report rapport.json --log-file trace.log --capture CAP=fichier.pcap`
   b. L'outil produit : capture anonymisée + rapport de transformation + logs + rapport d'analyse
3. Tous les outputs portent le même `trace_id` et `capture_id`

### 4.2 Transmission

L'utilisateur transmet à l'analyse :
- Captures anonymisées (sûres à partager)
- Rapports de transformation (documentent ce qui a été anonymisé)
- Logs (avec trace_id, sans données sensibles)
- Rapports d'analyse (texte/JSON/PDF)

### 4.3 Analyse post-campagne

1. Corrélation des résultats par `trace_id` et `capture_id`
2. Identification des patterns d'échec ou de faux positifs
3. Vérification que les "RAS" sont correctement signalés
4. Amélioration des règles et détecteurs
5. Mise à jour des seuils et paramètres

---

## 5. Sécurité et limites

### 5.1 Ce qui est préservé (volontairement)
- Distribution des protocoles
- Patterns temporels (timings, intervalles)
- Tailles des paquets
- Flags TCP
- Topologie du réseau (sans adresses)

### 5.2 Ce qui reste identifiant (limites assumées)
- Les patterns de trafic peuvent être identifiants (fingerprinting de comportement)
- Les charges utiles binaires non-texte ne sont pas anonymisées
- Les clés publiques TLS sont préservées (par conception)

### 5.3 Mode dry-run

Avant anonymisation réelle, l'utilisateur peut exécuter :
```
netcross --anonymize --dry-run --capture CAP=fichier.pcap
```
Ceci produit uniquement le rapport de transformation sans modifier les fichiers,
permettant de vérifier ce qui sera anonymisé.

---

## 6. Plan de mise en œuvre

| Phase | Tâche | Priorité | Dépend |
|---|---|---|---|
| 1 | Étendre `redact.py` : DNS, HTTP, TLS SAN, SIP | Haute | — |
| 1 | Créer `trace_context.py` (trace_id, run_id, capture_id) | Haute | — |
| 2 | Créer `transformation_report.py` | Haute | Phase 1 |
| 2 | Ajouter `--anonymize`, `--anonymize-report`, `--log-file` CLI | Haute | Phase 1 |
| 3 | Tests d'anonymisation étendue | Haute | Phase 2 |
| 3 | Tests de corrélation trace_id/capture_id | Moyenne | Phase 2 |
| 4 | Mode dry-run | Moyenne | Phase 2 |
| 4 | Documentation utilisateur | Moyenne | Phase 2 |
| 5 | Campagne de 100 traces | — | Phases 1-4 |
| 6 | Analyse des résultats et amélioration | — | Phase 5 |

---

## 7. Note pour la session d'analyse post-campagne

Quand l'utilisateur transmettra les résultats de la campagne de 100 traces :

1. **Recevoir** : captures anonymisées + rapports de transformation + logs + rapports d'analyse
2. **Corréler** : utiliser `trace_id` et `capture_id` pour regrouper les résultats
3. **Analyser** : identifier les échecs, faux positifs, faux négatifs, limites
4. **Vérifier la règle de traçabilité** : chaque rapport doit contenir toutes les sections obligatoires, y compris "RAS"
5. **Améliorer** : ajuster les règles, seuils, détecteurs en fonction des résultats
6. **Reporter** : produire un rapport de campagne avec recommandations

Le `trace_id` est la clé de voûte de cette corrélation : il doit être présent
dans chaque artefact transmis.

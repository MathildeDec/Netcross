# Détecteurs de sécurité — Comportement et limites

## Plages TEST-NET (RFC 5737)

Les plages d'adresses de documentation (TEST-NET) sont utilisées en
démonstration et dans les exemples :

| Plage | Nom |
|-------|-----|
| 192.0.2.0/24 | TEST-NET-1 |
| 198.51.100.0/24 | TEST-NET-2 |
| 203.0.113.0/24 | TEST-NET-3 |

La bibliothèque standard Python (`ipaddress`) considère ces plages comme
**privées** (`is_private = True`, `is_global = False`). En conséquence :

- **Beaconing** (`security.beaconing`) : avec `external_only=True` (défaut),
  les destinations TEST-NET sont filtrées — le détecteur reste muet.
- **Exfiltration** (`security.exfiltration`) : les destinations TEST-NET
  ne sont pas considérées comme externes.
- **Mouvements latéraux** (`security.lateral_movement`) : les adresses
  TEST-NET sont considérées comme internes (RFC1918 / link-local).

### Option `treat_test_net_as_external`

Pour les démonstrations utilisant des adresses TEST-NET, le détecteur de
beaconing accepte l'option `treat_test_net_as_external=True` dans
`BeaconingThresholds` :

```python
from netcross_core.security.beaconing import BeaconingThresholds, detect_beaconing

thresholds = BeaconingThresholds(treat_test_net_as_external=True)
result = detect_beaconing(packets, thresholds)
```

Avec cette option, les adresses TEST-NET sont traitées comme externes et
le détecteur de beaconing peut les signaler.

## Voir aussi

- [README.md](../README.md) — vue d'ensemble du projet
- [CONTRIBUTING.md](../CONTRIBUTING.md) — guide de contribution

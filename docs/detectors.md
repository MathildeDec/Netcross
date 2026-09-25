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

### Option `treat_test_net_as_external` / `--test-net-external`

Pour les démonstrations utilisant des adresses TEST-NET, le beaconing **et**
l'exfiltration peuvent les traiter comme externes (issue #365) :

```bash
python3 src/cross_capture_analyzer_cli.py --capture A=demo.pcap \
    --security-report --test-net-external
```

En Python, l'option existe sur les deux jeux de seuils, et
`apply_security_findings(..., treat_test_net_as_external=True)` la transmet
aux deux détecteurs :

```python
from netcross_core.security.beaconing import BeaconingThresholds, detect_beaconing
from netcross_core.security.exfiltration import ExfiltrationThresholds, detect_exfiltration

detect_beaconing(packets, BeaconingThresholds(treat_test_net_as_external=True))
detect_exfiltration(packets, ExfiltrationThresholds(treat_test_net_as_external=True))
```

Seules les trois plages TEST-NET changent de statut : les autres adresses
privées (RFC 1918, link-local…) restent internes. Les mouvements latéraux
ne sont pas concernés : l'option ne s'y applique pas. La logique commune se
trouve dans `netcross_core.security.address_scope`.

Le comportement par défaut est figé par `tests/test_test_net_scope.py`.

## Voir aussi

- [README.md](https://github.com/MathildeDec/Netcross/blob/dev/README.md) — vue d'ensemble du projet
- [CONTRIBUTING.md](https://github.com/MathildeDec/Netcross/blob/dev/CONTRIBUTING.md) — guide de contribution

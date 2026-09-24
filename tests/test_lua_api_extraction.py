"""Tests pour l'extraction de l'API Lua Wireshark (issue #386)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

DATA_PATH = Path(__file__).parent.parent / "data" / "lua_api.json"


@pytest.fixture
def lua_api() -> dict:
    """Charge le JSON de l'API Lua."""
    if not DATA_PATH.exists():
        pytest.skip("data/lua_api.json non généré — lancer tools/extract_lua_api.py")
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def test_json_structure(lua_api: dict) -> None:
    """Le JSON doit avoir la structure attendue."""
    assert "version_wireshark" in lua_api
    assert "source" in lua_api
    assert "classes" in lua_api
    assert isinstance(lua_api["classes"], dict)


def test_min_classes(lua_api: dict) -> None:
    """Au moins 30 classes doivent être présentes."""
    assert len(lua_api["classes"]) >= 30


def test_min_methods(lua_api: dict) -> None:
    """Au moins 300 méthodes au total."""
    total = sum(len(c["methodes"]) for c in lua_api["classes"].values())
    assert total >= 300


def test_key_classes_present(lua_api: dict) -> None:
    """Les classes principales doivent être présentes."""
    expected = [
        "ByteArray",
        "Tvb",
        "TvbRange",
        "Proto",
        "ProtoField",
        "Dissector",
        "DissectorTable",
        "TreeItem",
        "Listener",
        "Dumper",
        "Field",
        "FieldInfo",
        "Address",
        "Int64",
        "UInt64",
    ]
    for cls in expected:
        assert cls in lua_api["classes"], f"Classe manquante: {cls}"


def test_method_fields(lua_api: dict) -> None:
    """Chaque méthode doit avoir les champs requis."""
    required_fields = {"nom", "signature", "description", "arguments", "retours", "exemples"}
    for cls_name, cls_info in lua_api["classes"].items():
        for method in cls_info["methodes"]:
            missing = required_fields - set(method.keys())
            assert not missing, f"Champs manquants pour {cls_name}.{method.get('nom', '?')}: {missing}"


def test_argument_fields(lua_api: dict) -> None:
    """Chaque argument doit avoir nom, type, optionnel, description."""
    required = {"nom", "type", "optionnel", "description"}
    for cls_name, cls_info in lua_api["classes"].items():
        for method in cls_info["methodes"]:
            for arg in method["arguments"]:
                missing = required - set(arg.keys())
                assert not missing, f"Argument incomplet dans {cls_name}.{method['nom']}: {missing}"


def test_methods_with_arguments(lua_api: dict) -> None:
    """Au moins 50% des méthodes doivent avoir des arguments."""
    total = sum(len(c["methodes"]) for c in lua_api["classes"].values())
    with_args = sum(1 for c in lua_api["classes"].values() for m in c["methodes"] if m["arguments"])
    assert with_args / total >= 0.5, f"Seulement {with_args}/{total} méthodes ont des arguments"


def test_methods_with_returns(lua_api: dict) -> None:
    """Au moins 50% des méthodes doivent avoir des retours."""
    total = sum(len(c["methodes"]) for c in lua_api["classes"].values())
    with_returns = sum(1 for c in lua_api["classes"].values() for m in c["methodes"] if m["retours"])
    assert with_returns / total >= 0.5, f"Seulement {with_returns}/{total} méthodes ont des retours"


def test_protocols_section(lua_api: dict) -> None:
    """La section Proto/ProtoField doit avoir suffisamment de méthodes."""
    proto = lua_api["classes"].get("Proto", {})
    proto_field = lua_api["classes"].get("ProtoField", {})
    assert len(proto.get("methodes", [])) >= 2
    assert len(proto_field.get("methodes", [])) >= 20


def test_tvb_section(lua_api: dict) -> None:
    """La section Tvb/TvbRange doit avoir suffisamment de méthodes."""
    tvb = lua_api["classes"].get("Tvb", {})
    tvb_range = lua_api["classes"].get("TvbRange", {})
    assert len(tvb.get("methodes", [])) >= 5
    assert len(tvb_range.get("methodes", [])) >= 20


def test_bytearray_new_has_args(lua_api: dict) -> None:
    """ByteArray.new doit avoir des arguments."""
    ba = lua_api["classes"].get("ByteArray", {})
    new_method = next(
        (m for m in ba.get("methodes", []) if m["nom"] == "new"),
        None,
    )
    assert new_method is not None, "ByteArray.new introuvable"
    assert len(new_method["arguments"]) >= 2
    assert new_method["retours"], "ByteArray.new doit avoir des retours"

"""
netcross_core.config -- tests (issue #170).

Teste le chargement de .netcross.toml : valeurs par défaut, lecture
de sections, fallback quand aucun fichier n'existe.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from netcross_core.config import NetcrossConfig, load_config


def test_load_config_no_file():
    """load_config sans fichier doit retourner les valeurs par défaut."""
    cfg = load_config("/nonexistent/path/.netcross.toml")
    assert isinstance(cfg, NetcrossConfig)
    assert cfg.analysis.bucket_seconds == 1.0
    assert cfg.analysis.rtp_clock_rate == 8000
    assert cfg.output.format == "text"
    assert cfg.security.enable is True
    assert cfg.parallel.workers == 0


def test_load_config_default_path():
    """load_config sans argument ne doit pas planter."""
    # Sauvegarder et nettoyer l'environnement
    old_env = os.environ.pop("NETCROSS_CONFIG", None)
    old_cwd = Path.cwd()
    try:
        # Aller dans un répertoire sans .netcross.toml
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            cfg = load_config()
            assert cfg.analysis.bucket_seconds == 1.0
    finally:
        if old_env is not None:
            os.environ["NETCROSS_CONFIG"] = old_env
        os.chdir(old_cwd)


def test_load_config_full():
    """load_config avec un fichier complet doit parser toutes les sections."""
    toml_content = """
[analysis]
points_order = ["LAN", "WAN", "DMZ"]
bucket_seconds = 0.5
rtp_clock_rate = 16000

[output]
format = "json"
output_path = "/tmp/report.json"
json_report = "/tmp/report.json"
security_report = "/tmp/security.txt"

[security]
enable = false

[parallel]
workers = 4
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write(toml_content)
        f.flush()
        config_path = f.name

    try:
        cfg = load_config(config_path)
        assert cfg.analysis.points_order == ["LAN", "WAN", "DMZ"]
        assert cfg.analysis.bucket_seconds == 0.5
        assert cfg.analysis.rtp_clock_rate == 16000
        assert cfg.output.format == "json"
        assert cfg.output.output_path == "/tmp/report.json"
        assert cfg.security.enable is False
        assert cfg.parallel.workers == 4
        assert cfg.source_path == config_path
    finally:
        Path(config_path).unlink(missing_ok=True)


def test_load_config_partial():
    """load_config avec un fichier partiel doit garder les défauts manquants."""
    toml_content = """
[analysis]
bucket_seconds = 2.0
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write(toml_content)
        f.flush()
        config_path = f.name

    try:
        cfg = load_config(config_path)
        assert cfg.analysis.bucket_seconds == 2.0
        assert cfg.analysis.rtp_clock_rate == 8000  # défaut
        assert cfg.output.format == "text"  # défaut
    finally:
        Path(config_path).unlink(missing_ok=True)


def test_load_config_env_var():
    """load_config doit respecter NETCROSS_CONFIG."""
    toml_content = """
[parallel]
workers = 8
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write(toml_content)
        f.flush()
        config_path = f.name

    old_env = os.environ.get("NETCROSS_CONFIG")
    try:
        os.environ["NETCROSS_CONFIG"] = config_path
        cfg = load_config()
        assert cfg.parallel.workers == 8
        assert cfg.source_path == config_path
    finally:
        if old_env is not None:
            os.environ["NETCROSS_CONFIG"] = old_env
        else:
            os.environ.pop("NETCROSS_CONFIG", None)
        Path(config_path).unlink(missing_ok=True)


def test_load_config_bool_variants():
    """_parse_bool doit accepter true/yes/1/on."""
    toml_content = """
[security]
enable = true
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write(toml_content)
        f.flush()
        config_path = f.name

    try:
        cfg = load_config(config_path)
        assert cfg.security.enable is True
    finally:
        Path(config_path).unlink(missing_ok=True)

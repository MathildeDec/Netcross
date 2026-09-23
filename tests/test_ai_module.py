"""Issue #146 (FLOW-5) : module IA/ML optionnel et local.

Les tests ML sont ignores si scikit-learn est absent ; le reste (features,
gabarit de resume, garde-fous reseau, repli gracieux, CLI) tourne partout.
"""

from __future__ import annotations

import json
import random
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
import netcross_ai.optional as optional
from netcross_ai import FEATURE_NAMES, AIUnavailableError, flow_features
from netcross_ai.anomaly import Baseline, BaselineError, detect_anomalies
from netcross_ai.flow_classifier import FlowClassifier, TrainingSetError, export_training_set, load_training_set
from netcross_ai.pipeline import AIOptions, format_ai, run_ai
from netcross_ai.report_writer import (
    WriterConfigError,
    build_prompt,
    check_local_endpoint,
    collect_facts,
    template_summary,
    write_summary,
)

needs_ml = pytest.mark.skipif(not optional.ml_available(), reason="scikit-learn absent (extra ai)")


def _flow(src, dst, sizes, gaps, upload_ratio, classification="normal"):
    dist: dict[int, int] = {}
    for s in sizes:
        dist[s] = dist.get(s, 0) + 1
    return {
        "src": src,
        "dst": dst,
        "packet_count": len(sizes),
        "byte_count": sum(sizes),
        "splt": [[s, g] for s, g in zip(sizes[:20], [0.0, *gaps][:20])],
        "size_distribution": dist,
        "upload_bytes": int(sum(sizes) * upload_ratio),
        "download_bytes": int(sum(sizes) * (1 - upload_ratio)),
        "inter_arrivals": gaps,
        "classification": classification,
        "entropy": 3.0,
        "median_size": sorted(sizes)[len(sizes) // 2],
        "upload_ratio": upload_ratio,
        "regularity_cv": 0.9,
    }


def _web_flows(n, seed=1):
    rng = random.Random(seed)
    flows = []
    for i in range(n):
        count = rng.randint(20, 60)
        sizes = [rng.choice([60, 60, 120, 576, 1400, 1400]) for _ in range(count)]
        gaps = [rng.expovariate(20) for _ in range(count - 1)]
        flows.append(_flow(f"10.0.0.{i % 50 + 1}", "93.184.216.34", sizes, gaps, rng.uniform(0.1, 0.3)))
    return flows


def _exfil():
    f = _flow("10.0.0.66", "203.0.113.9", [1400] * 3000, [0.001] * 2999, 0.99, "transfert")
    f["regularity_cv"] = 0.05
    return f


# -- features & disponibilite ------------------------------------------------------


def test_features_bornees_et_tolerantes():
    vec = flow_features(_web_flows(1)[0])
    assert len(vec) == len(FEATURE_NAMES) and all(isinstance(x, float) for x in vec)
    assert flow_features({}) == [0.0] * len(FEATURE_NAMES)
    assert flow_features({"size_distribution": {"x": 1}, "splt": [["a", 1]], "entropy": float("nan")})[2] == 0.0


def test_sans_scikit_learn_erreur_explicite(monkeypatch):
    monkeypatch.setattr(optional, "ml_available", lambda: False)
    with pytest.raises(AIUnavailableError, match=r"netcross\[ai\]"):
        detect_anomalies(Baseline.from_flows(_web_flows(30)), _web_flows(2))
    with pytest.raises(AIUnavailableError):
        FlowClassifier([])


def test_baseline_json_sans_pickle(tmp_path):
    path = tmp_path / "base.json"
    Baseline.from_flows(_web_flows(5), "bureau").save(path)
    data = json.loads(path.read_text())
    assert data["schema"] == "netcross.ai.baseline/1" and data["features"] == list(FEATURE_NAMES)
    assert Baseline.load(path).label == "bureau"
    data["vectors"][0] = ["__import__('os')"] * len(FEATURE_NAMES)
    path.write_text(json.dumps(data))
    with pytest.raises(BaselineError, match="vecteurs invalides"):
        Baseline.load(path)
    path.write_text("{}")
    with pytest.raises(BaselineError, match="n'est pas une baseline"):
        Baseline.load(path)


# -- ML ---------------------------------------------------------------------------


@needs_ml
def test_anomalies_exfiltration_en_tete():
    baseline = Baseline.from_flows(_web_flows(200))
    results = detect_anomalies(baseline, [*_web_flows(20, seed=7), _exfil()])
    assert results[0].flow == "10.0.0.66 -> 203.0.113.9" and results[0].is_anomaly
    assert any(r.startswith("ratio_montant") for r in results[0].reasons)
    typical = [r for r in results if r.flow != results[0].flow]
    assert sum(r.is_anomaly for r in typical) <= 4  # peu de faux positifs sur du trafic semblable
    # graine fixe : resultat reproductible
    assert [r.score for r in detect_anomalies(baseline, [_exfil()])] == [results[0].score]


@needs_ml
def test_baseline_trop_petite():
    with pytest.raises(BaselineError, match="trop petite"):
        detect_anomalies(Baseline.from_flows(_web_flows(5)), _web_flows(1))


@needs_ml
def test_classification_avec_confiance(tmp_path):
    path = tmp_path / "train.json"
    export_training_set(_web_flows(40), path)
    data = json.loads(path.read_text())
    data["samples"] += [{"flow": _exfil() | {"src": f"10.9.0.{i}"}, "label": "exfiltration"} for i in range(10)]
    path.write_text(json.dumps(data))
    clf = FlowClassifier(load_training_set(path))
    preds = {p.flow: p for p in clf.predict([_exfil(), _web_flows(1, seed=99)[0]])}
    assert preds["10.0.0.66 -> 203.0.113.9"].label == "exfiltration"
    assert preds["10.0.0.66 -> 203.0.113.9"].confidence >= 0.8
    assert clf.labels == {"normal": 40, "exfiltration": 10}


def test_jeu_d_entrainement_invalide(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"schema": "netcross.ai.training/1", "samples": [{"flow": {}}]}))
    with pytest.raises(TrainingSetError, match="exemple 0"):
        load_training_set(path)


@needs_ml
def test_une_seule_classe_refusee():
    with pytest.raises(TrainingSetError, match="2 classes"):
        FlowClassifier([(f, "normal") for f in _web_flows(12)])


# -- redaction -------------------------------------------------------------------------


def _report():
    return SimpleNamespace(
        security_findings=[
            {"severity": "moyenne", "category": "anomalie", "detail": "flux obfusque", "host": "10.0.0.66"},
            {
                "severity": "critique",
                "category": "cve",
                "detail": "Apache 2.4.49 vulnerable",
                "host": "10.0.0.5",
                "service": "Apache",
                "version": "2.4.49",
                "cve_id": "CVE-2021-41773",
                "cvss": 7.5,
            },
            {"severity": "elevee", "category": "exploit", "detail": "path traversal", "host": "10.0.0.5"},
        ],
        service_fingerprints=[{"service": "Apache", "version": "2.4.49", "host": "10.0.0.5", "port": 80}],
        flow_anomalies=[_exfil(), {"classification": "obfusque"}],
        dga_alerts=[],
        lateral_movement_events=[],
    )


def test_resume_gabarit_correlations_recommandations():
    s = template_summary(_report())
    assert s.text.startswith("L'analyse releve 3 constat(s) de securite (1 critique, 1 elevee, 1 moyenne).")
    assert "Apache 2.4.49 vulnerable" in s.text
    assert s.correlations == [
        "10.0.0.5 cumule 2 signaux (CVE CVE-2021-41773, exploit) : exploitation d'une vulnerabilite connue probable."
    ]
    assert s.recommendations[0] == "Mettre a jour Apache 2.4.49 sur 10.0.0.5 (CVE-2021-41773, CVSS 7.5)."
    assert any("obfuscation" in r for r in s.recommendations)


def test_rapport_vide():
    empty = SimpleNamespace()
    assert template_summary(empty).text == "Aucun constat de securite n'a ete releve sur cette capture."


@pytest.mark.parametrize(
    "url", ["http://192.168.1.10:11434", "https://api.openai.com", "http://ollama.local:1", "ftp://127.0.0.1"]
)
def test_point_d_acces_non_local_refuse(url):
    with pytest.raises(WriterConfigError):
        check_local_endpoint(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:8080", "http://[::1]:11434"])
def test_point_d_acces_local_accepte(url):
    check_local_endpoint(url)


def test_moteur_inconnu_ou_modele_manquant():
    with pytest.raises(WriterConfigError, match="moteur inconnu"):
        write_summary(_report(), engine="openai:gpt")
    with pytest.raises(WriterConfigError, match="preciser le modele"):
        write_summary(_report(), engine="ollama")


class _FakeLLM(BaseHTTPRequestHandler):
    received: list = []  # noqa: RUF012 -- etat de test partage

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).received.append((self.path, body))
        answer = {"response": "Resume du modele."} if self.path == "/api/generate" else {"content": "Resume llama."}
        data = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_llm():
    _FakeLLM.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeLLM)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_ollama_local_ne_recoit_que_les_faits(fake_llm):
    s = write_summary(_report(), engine="ollama:llama3", endpoint=fake_llm)
    assert s.engine == "ollama:llama3" and s.text == "Resume du modele." and s.recommendations
    path, body = _FakeLLM.received[0]
    assert path == "/api/generate" and body["model"] == "llama3" and body["stream"] is False
    assert "CVE-2021-41773" in body["prompt"] and "N'invente aucun fait" in body["prompt"]
    assert "inter_arrivals" not in body["prompt"]  # pas de donnees brutes de flux


def test_llamacpp_local(fake_llm):
    s = write_summary(_report(), engine="llamacpp", endpoint=fake_llm)
    assert s.text == "Resume llama." and _FakeLLM.received[0][0] == "/completion"


def test_modele_injoignable_repli_gabarit():
    s = write_summary(_report(), engine="ollama:llama3", endpoint="http://127.0.0.1:9")
    assert s.engine == "template" and s.fallback_reason.startswith("modele local indisponible")


def test_prompt_serialisable():
    assert json.loads(build_prompt(collect_facts(_report())).split("FAITS (JSON) :\n", 1)[1])["services"]


# -- pipeline & CLI ------------------------------------------------------------------


def test_pipeline_export_baseline_cumulative_et_resume(tmp_path):
    opts = AIOptions(
        baseline_save=str(tmp_path / "b.json"),
        training_export=str(tmp_path / "t.json"),
        summary_engine="template",
    )
    run_ai(_report(), _web_flows(3), opts)
    result = run_ai(_report(), _web_flows(4), opts)
    assert result["baseline_saved"]["flows"] == 7  # enrichie, pas ecrasee
    assert result["training_exported"]["samples"] == 4
    text = format_ai(result)
    assert "Baseline enregistree" in text and "Recommandations :" in text


@needs_ml
def test_run_ai_cli_de_bout_en_bout(tmp_path, capsys):
    base = tmp_path / "b.json"
    Baseline.from_flows(_web_flows(60)).save(base)
    packets = [make_pkt(src="10.0.0.66", dst="203.0.113.9", length=1400, ts=i * 0.001) for i in range(500)]
    args = SimpleNamespace(ai_report=str(tmp_path / "ai.json"))
    report = SimpleNamespace(flow_anomalies=[])
    cli._run_ai(args, AIOptions(baseline_path=str(base), summary_engine="template"), report, packets)
    out = capsys.readouterr().out
    assert "MODULE IA LOCAL" in out and "10.0.0.66 -> 203.0.113.9" in out
    saved = json.loads((tmp_path / "ai.json").read_text())
    assert saved["schema"] == "netcross.ai/1" and saved["anomalies"][0]["is_anomaly"]


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--ai-report", "x.json"], "necessitent une option --ai-*"),
        (["--ai-summary", "ollama:llama3", "--ai-endpoint", "http://10.1.1.1:11434"], "refuse"),
        (["--ai-anomalies", "absent.json"], "fichier introuvable"),
        (["--ai-endpoint", "http://127.0.0.1:1", "--ai-training-export", "t.json"], "necessite --ai-summary"),
        (["--ai-baseline-label", "x", "--ai-summary"], "necessite --ai-baseline-save"),
    ],
)
def test_validations_cli(monkeypatch, capsys, tmp_path, extra, message):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "x.pcap").write_bytes(b"")
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", "A=x.pcap", *extra])
    with pytest.raises(SystemExit):
        cli.main()
    assert message in capsys.readouterr().err


def test_cli_sans_scikit_learn(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "x.pcap").write_bytes(b"")
    (tmp_path / "b.json").write_text("{}")
    monkeypatch.setattr(optional, "ml_available", lambda: False)
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", "A=x.pcap", "--ai-anomalies", "b.json"])
    with pytest.raises(SystemExit):
        cli.main()
    assert "netcross[ai]" in capsys.readouterr().err

"""CLI commands end to end (fake models): terminal report + JSON file, ci gate file, providers, config."""

import json
import tomllib

import pytest
from typer.testing import CliRunner

from breakpoint import cli, config
from breakpoint.config import settings
from breakpoint.storage.db import Database
from tests.fakes import BEHAVIORS_YAML, fake_make_adapter

runner = CliRunner()


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "b.yaml").write_text(BEHAVIORS_YAML)
    original = config.config_path()
    config.reload_settings(tmp_path / "breakpoint.toml")
    monkeypatch.setattr(settings, "report_dir", str(tmp_path / "reports"))
    monkeypatch.setattr(cli, "db", Database(tmp_path / "t.db"))
    monkeypatch.setattr("breakpoint.runner.make_adapter", fake_make_adapter)
    monkeypatch.setattr(cli, "check_ready", lambda refs, **kw: [])
    yield tmp_path
    config.reload_settings(original)


def test_scan_prints_report_and_saves_json(sandbox):
    out = runner.invoke(cli.app, ["scan", "-t", "fake/win", "--behaviors", str(sandbox / "b.yaml"), "--max-iter", "2", "-n", "demo"])
    assert out.exit_code == 0, out.output
    assert "Breakpoint report" in out.output and "OWASP Top 10 for LLM Applications 2026" in out.output
    assert "JAILBROKEN" in out.output and "Report saved" in out.output

    report = json.loads((sandbox / "reports" / "demo.json").read_text(encoding="utf-8"))
    assert report["summary"]["jailbroken"] == 3 and report["campaign"]["name"] == "demo"
    assert set(report["models"]) == {"target", "attacker", "judge"}


def test_scan_honours_explicit_report_path_and_no_report(sandbox):
    target = sandbox / "out" / "mine.json"
    args = ["scan", "-t", "fake/safe", "--behaviors", str(sandbox / "b.yaml"), "--max-iter", "1"]
    assert runner.invoke(cli.app, [*args, "-r", str(target)]).exit_code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["summary"]["jailbroken"] == 0

    assert runner.invoke(cli.app, [*args, "--no-report", "-n", "silent"]).exit_code == 0
    assert not (sandbox / "reports" / "silent.json").exists()


def test_scan_rejects_bad_options_and_unready_providers(sandbox, monkeypatch):
    base = ["scan", "--behaviors", str(sandbox / "b.yaml")]
    assert runner.invoke(cli.app, [*base, "--algo", "nope"]).exit_code == 1
    assert runner.invoke(cli.app, [*base, "--channel", "tool_output"]).exit_code == 1
    monkeypatch.setattr(cli, "check_ready", lambda refs, **kw: ["anthropic: no API key — set ANTHROPIC_API_KEY"])
    out = runner.invoke(cli.app, [*base, "-t", "anthropic/x"])
    assert out.exit_code == 1 and "ANTHROPIC_API_KEY" in out.output


def test_scan_attacker_and_judge_flags_reach_the_run(sandbox):
    out = runner.invoke(cli.app, ["scan", "-t", "fake/safe", "--behaviors", str(sandbox / "b.yaml"), "--max-iter", "1",
                                  "--attacker", "fake/my-attacker", "--judge", "fake/my-judge", "-n", "roles"])
    assert out.exit_code == 0, out.output
    report = json.loads((sandbox / "reports" / "roles.json").read_text(encoding="utf-8"))
    assert report["models"] == {"target": "fake/safe", "attacker": "fake/my-attacker", "judge": "fake/my-judge"}


def test_report_command_shows_and_saves(sandbox):
    runner.invoke(cli.app, ["scan", "-t", "fake/win", "--behaviors", str(sandbox / "b.yaml"), "--max-iter", "1", "--no-report"])
    shown = runner.invoke(cli.app, ["report", "-c", "1"])
    assert shown.exit_code == 0 and "Breakpoint report" in shown.output
    assert (sandbox / "reports" / "campaign_1.json").exists()

    raw = runner.invoke(cli.app, ["report", "-c", "1", "--json"])
    assert json.loads(raw.output)["schema"] == "breakpoint.report.campaign/1"
    assert runner.invoke(cli.app, ["report", "-c", "99"]).exit_code == 1


def test_ci_writes_json_report_with_gate_verdict(sandbox):
    path = sandbox / "gate.json"
    out = runner.invoke(cli.app, ["ci", "-t", "fake/win", "--behaviors", str(sandbox / "b.yaml"),
                                  "--max-iter", "1", "--asr-threshold", "5", "--report", str(path), "--json"])
    assert out.exit_code == 1
    assert json.loads(out.output.splitlines()[0])["status"] == "fail"
    gate = json.loads(path.read_text(encoding="utf-8"))["gate"]
    assert gate["status"] == "fail" and gate["threshold_percent"] == 5.0

    ok = runner.invoke(cli.app, ["ci", "-t", "fake/safe", "--behaviors", str(sandbox / "b.yaml"), "--max-iter", "1", "--json"])
    assert ok.exit_code == 0


def test_sweep_saves_json_comparison(sandbox):
    path = sandbox / "sw.json"
    out = runner.invoke(cli.app, ["sweep", "-t", "fake/safe", "-t", "fake/win", "--behaviors", str(sandbox / "b.yaml"),
                                  "--max-iter", "1", "-r", str(path)])
    assert out.exit_code == 0, out.output
    assert "Ranking" in out.output and "HIGH RISK" in out.output
    ranking = json.loads(path.read_text(encoding="utf-8"))["ranking"]
    assert [r["target"] for r in ranking] == ["fake/win", "fake/safe"]
    assert runner.invoke(cli.app, ["sweep", "-t", "fake/win"]).exit_code == 1


def test_providers_lists_presets_and_roles(sandbox):
    out = runner.invoke(cli.app, ["providers"])
    assert out.exit_code == 0
    for name in ("anthropic", "groq", "llamacpp", "openrouter"):
        assert name in out.output
    assert "attacker =" in out.output


def test_config_set_show_init(sandbox):
    assert runner.invoke(cli.app, ["config", "set", "judge", "llamacpp/qwen"]).exit_code == 0
    assert runner.invoke(cli.app, ["config", "set", "judge_temperature", "0"]).exit_code == 0
    data = tomllib.loads((sandbox / "breakpoint.toml").read_text())
    assert data == {"judge": "llamacpp/qwen", "judge_temperature": 0.0}

    assert runner.invoke(cli.app, ["config", "set", "nonsense", "1"]).exit_code == 1
    assert runner.invoke(cli.app, ["config", "set", "max_iterations", "many"]).exit_code == 1
    shown = runner.invoke(cli.app, ["config", "show"])
    assert shown.exit_code == 0 and "llamacpp/qwen" in shown.output
    assert runner.invoke(cli.app, ["config", "init"]).exit_code == 1                # already exists
    assert runner.invoke(cli.app, ["config", "init", "--force"]).exit_code == 0


def test_no_subcommand_off_a_tty_prints_help(sandbox):
    out = runner.invoke(cli.app, [])
    assert out.exit_code == 0 and "Commands" in out.output

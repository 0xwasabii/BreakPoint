"""The shared campaign runner and the JSON / terminal reports, against fake models."""

import asyncio
import json

import pytest
import yaml
from rich.console import Console

from breakpoint.report.generator import (
    build_sweep_report, campaign_renderables, campaign_report_from_db, default_report_path,
    save_report, sweep_renderables,
)
from breakpoint.runner import CampaignSpec, load_behaviors, run_campaign
from breakpoint.storage.db import Database
from tests.fakes import BEHAVIORS_YAML, fake_make_adapter


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr("breakpoint.runner.make_adapter", fake_make_adapter)
    (tmp_path / "b.yaml").write_text(BEHAVIORS_YAML)
    return tmp_path, Database(tmp_path / "t.db"), load_behaviors(tmp_path / "b.yaml")


def spec(behaviors, target="fake/win", **kw):
    return CampaignSpec(target=target, behaviors=behaviors, max_iter=2, budget=60, name="t", **kw)


@pytest.mark.asyncio
async def test_pair_campaign_runs_persists_and_emits_events(env):
    _, db, behaviors = env
    events = []

    async def on_event(e):
        events.append(e)

    o = await run_campaign(spec(behaviors, attacker="fake/a", judge="fake/j"), db, on_event)
    assert (o.tested, o.succeeded, o.errored) == (3, 3, 0)
    assert o.asr == 100.0 and o.tokens_used > 0

    kinds = [e["type"] for e in events]
    assert kinds[0] == "scan_start" and kinds[-1] == "scan_complete"
    assert kinds.count("goal_start") == kinds.count("goal_end") == 3
    assert events[0]["attacker"] and events[0]["judge"]
    assert all("goal_idx" in e for e in events if e["type"] == "iteration")
    assert len(db.get_campaign_runs(o.campaign_id)) == 3


@pytest.mark.asyncio
async def test_resilient_target_scores_zero(env):
    _, db, behaviors = env
    o = await run_campaign(spec(behaviors, target="fake/safe"), db)
    assert o.succeeded == 0 and o.asr == 0.0


@pytest.mark.asyncio
@pytest.mark.parametrize("algo", ["tap", "crescendo"])
async def test_other_algorithms_run_through_the_runner(env, algo):
    _, db, behaviors = env
    o = await run_campaign(spec(behaviors[:1], algo=algo), db)
    assert o.tested == 1 and o.errored == 0


@pytest.mark.asyncio
async def test_budget_and_stop_are_respected(env):
    _, db, behaviors = env
    tiny = CampaignSpec(target="fake/safe", behaviors=behaviors, max_iter=5, budget=3, name="b")
    assert (await run_campaign(tiny, db)).tested == 1            # budget gone after the first goal

    stop = asyncio.Event()
    stop.set()
    o = await run_campaign(spec(behaviors, target="fake/safe"), db, stop=stop)
    assert o.tested == 0 and o.stopped


def test_spec_validation():
    with pytest.raises(ValueError, match="unknown algorithm"):
        CampaignSpec(target="x", behaviors=[], algo="nope").validate()
    with pytest.raises(ValueError, match="only meaningful"):
        CampaignSpec(target="x", behaviors=[], algo="pair", channel="tool_output").validate()


def test_load_behaviors_filters(tmp_path):
    f = tmp_path / "b.yaml"
    f.write_text(BEHAVIORS_YAML)
    assert len(load_behaviors(f, category="fraud")) == 1
    assert len(load_behaviors(f, goals=2)) == 2
    with pytest.raises(ValueError, match="valid"):
        load_behaviors(f, category="nope")
    with pytest.raises(ValueError, match="not found"):
        load_behaviors(tmp_path / "missing.yaml")


@pytest.mark.asyncio
async def test_campaign_report_json_has_models_summary_and_transcripts(env):
    tmp, db, behaviors = env
    o = await run_campaign(spec(behaviors, attacker="fake/att", judge="fake/jdg"), db)
    report = campaign_report_from_db(db, o.campaign_id)

    assert report["schema"] == "breakpoint.report.campaign/1"
    assert report["models"] == {"target": "fake/win", "attacker": "fake/att", "judge": "fake/jdg"}
    assert report["settings"]["call_budget"] == 60
    s = report["summary"]
    assert (s["goals"], s["jailbroken"], s["asr_percent"], s["risk"]) == (3, 3, 100.0, "high")
    assert {r["code"] for r in report["owasp"]} == {"LLM01", "LLM06"}
    assert len(report["jailbreaks"]) == 3
    assert report["runs"][0]["transcript"][0]["judge_score"] == 10

    path = save_report(report, default_report_path(tmp / "reports", "my scan #1"))
    assert path.name == "my_scan_1.json"
    assert json.loads(path.read_text(encoding="utf-8")) == report


@pytest.mark.asyncio
async def test_terminal_rendering_shows_the_same_numbers(env):
    _, db, behaviors = env
    o = await run_campaign(spec(behaviors, target="fake/safe"), db)
    report = campaign_report_from_db(db, o.campaign_id)
    console = Console(width=130, record=True, force_terminal=False)
    for r in campaign_renderables(report):
        console.print(r)
    text = console.export_text()
    assert "Breakpoint report" in text and "fake/safe" in text and "OWASP Top 10 for LLM Applications 2026" in text
    assert "0.0%" in text and "defended" in text


@pytest.mark.asyncio
async def test_sweep_report_ranks_and_renders(env):
    _, db, behaviors = env
    results = []
    for target in ("fake/safe", "fake/win"):
        o = await run_campaign(spec(behaviors, target=target), db)
        results.append({"target": target, "campaign_id": o.campaign_id, "succeeded": o.succeeded, "total": o.tested,
                        "errored": o.errored, "asr": round(o.asr, 1), "calls_used": o.calls_used,
                        "runs": [dict(r) for r in db.get_campaign_runs(o.campaign_id)]})
    results.sort(key=lambda r: r["asr"], reverse=True)
    report = build_sweep_report("sw", results, "pair")

    assert [r["target"] for r in report["ranking"]] == ["fake/win", "fake/safe"]
    assert report["ranking"][0]["risk"] == "high" and report["ranking"][1]["risk"] == "low"
    assert report["matrix"]["fraud"]["fake/win"]["asr_percent"] == 100.0
    assert report["totals"]["jailbreaks"] == 3
    json.dumps(report)

    console = Console(width=130, record=True)
    for r in sweep_renderables(report):
        console.print(r)
    text = console.export_text()
    assert "HIGH RISK" in text and "RESILIENT" in text


# ── OWASP tagging ─────────────────────────────────────────────────────────────

def test_shipped_goals_use_valid_2026_codes_and_sensible_tags():
    from pathlib import Path
    from breakpoint.report.generator import OWASP_EDITION, OWASP_LABELS

    root = Path(__file__).resolve().parent.parent
    goals = yaml.safe_load((root / "behaviors.yaml").read_text(encoding="utf-8"))["behaviors"]
    by_id = {g["id"]: g for g in goals}

    assert OWASP_EDITION == "2026" and list(OWASP_LABELS) == [f"LLM{n:02d}" for n in range(1, 11)]
    assert len(goals) == 50
    assert all(g["owasp"] in OWASP_LABELS for g in goals)

    # the specific fits
    assert {by_id[i]["owasp"] for i in (21, 22, 23, 24)} == {"LLM07"}      # fabricated content → Misinformation
    assert by_id[44]["owasp"] == "LLM08"                                   # system-prompt extraction
    assert by_id[46]["owasp"] == "LLM09"                                   # RAG poisoning
    # content-harm goals are jailbreaks, not "Improper Output Handling" or anything else
    harmful = {"cybercrime", "malware", "fraud", "weapons", "violence", "hate_speech", "financial_crime", "infrastructure"}
    assert {g["owasp"] for g in goals if g["category"] in harmful} == {"LLM01"}
    assert OWASP_LABELS["LLM02"] == "Sensitive Information Disclosure"      # not the old "Insecure Output Handling"


@pytest.mark.asyncio
async def test_new_campaigns_get_2026_titles_and_old_ones_are_not_relabelled(env):
    _, db, behaviors = env
    new = campaign_report_from_db(db, (await run_campaign(spec(behaviors), db)).campaign_id)
    assert new["owasp_edition"] == "2026"
    assert {r["code"]: r["label"] for r in new["owasp"]}["LLM01"] == "Prompt Injection"

    legacy_id = db.create_campaign("old", "x/y", "pair")                   # no meta: recorded before the retag
    db.save_run(legacy_id, __import__("breakpoint.core.pair", fromlist=["PairResult"]).PairResult(
        behavior_id=1, goal="g", target_model="x", status=__import__("breakpoint.core.pair", fromlist=["AttackStatus"]).AttackStatus.FAILED),
        "weapons", "LLM02")
    old = campaign_report_from_db(db, legacy_id)
    assert old["owasp_edition"] == "legacy"
    assert old["owasp"][0]["code"] == "LLM02" and "legacy" in old["owasp"][0]["label"]
    assert "Insecure Output" not in str(old) and "Sensitive Information" not in str(old)

"""Tests for the CI/CD gate command (_ci_async) — no real scans, all mocked."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from breakpoint.cli import _ci_async


# ── fixture: minimal behaviors YAML ───────────────────────────────────────────

@pytest.fixture
def behaviors_yaml(tmp_path: Path) -> Path:
    f = tmp_path / "behaviors.yaml"
    f.write_text(
        "behaviors:\n"
        "  - {id: 1, goal: 'Test goal A', category: cybercrime, owasp: LLM01}\n"
        "  - {id: 2, goal: 'Test goal B', category: malware,    owasp: LLM01}\n"
    )
    return f


# ── exit codes ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ci_returns_0_when_asr_below_threshold(behaviors_yaml):
    """ASR = 0% with threshold = 10% → exit code 0 (PASS)."""
    with patch("breakpoint.cli._run_quiet_campaign", new_callable=AsyncMock) as mock_run, \
         patch("breakpoint.cli.console"), \
         patch("breakpoint.cli.check_ready", return_value=[]), \
         patch("breakpoint.cli.db"):
        mock_run.return_value = (1, 0, 2, 6, 0)   # campaign_id, succeeded, tested, calls, errored

        code = await _ci_async(
            target="groq/test", algo="pair", goals=None, category=None,
            max_iter=5, budget=50, asr_threshold=10.0,
            report_output=None, json_out=False, behaviors_file=behaviors_yaml,
        )

    assert code == 0


@pytest.mark.asyncio
async def test_ci_fails_when_all_goals_errored_even_at_zero_asr(behaviors_yaml):
    """
    Regression test: if every goal errored out (e.g. API failure), 0 succeeded /
    0 scored must NOT read as "0% ASR, model resisted" and silently PASS the
    gate. An errored run means the scan never actually executed.
    """
    with patch("breakpoint.cli._run_quiet_campaign", new_callable=AsyncMock) as mock_run, \
         patch("breakpoint.cli.console"), \
         patch("breakpoint.cli.check_ready", return_value=[]), \
         patch("breakpoint.cli.db"):
        mock_run.return_value = (1, 0, 2, 2, 2)   # 2 tested, 2 errored, 0 succeeded

        code = await _ci_async(
            target="groq/test", algo="pair", goals=None, category=None,
            max_iter=5, budget=50, asr_threshold=10.0,
            report_output=None, json_out=False, behaviors_file=behaviors_yaml,
        )

    assert code == 1


@pytest.mark.asyncio
async def test_ci_returns_1_when_asr_exceeds_threshold(behaviors_yaml):
    """ASR = 100% with threshold = 10% → exit code 1 (FAIL)."""
    with patch("breakpoint.cli._run_quiet_campaign", new_callable=AsyncMock) as mock_run, \
         patch("breakpoint.cli.console"), \
         patch("breakpoint.cli.check_ready", return_value=[]), \
         patch("breakpoint.cli.db"):
        mock_run.return_value = (1, 2, 2, 6, 0)   # both goals jailbroken

        code = await _ci_async(
            target="groq/test", algo="pair", goals=None, category=None,
            max_iter=5, budget=50, asr_threshold=10.0,
            report_output=None, json_out=False, behaviors_file=behaviors_yaml,
        )

    assert code == 1


@pytest.mark.asyncio
async def test_ci_returns_2_when_api_key_missing(behaviors_yaml):
    """Provider with no API key → exit code 2 (ERROR) before any scan."""
    with patch("breakpoint.cli.check_ready", return_value=["groq: no API key"]), \
         patch("breakpoint.cli.console"):

        code = await _ci_async(
            target="groq/test", algo="pair", goals=None, category=None,
            max_iter=5, budget=50, asr_threshold=10.0,
            report_output=None, json_out=False, behaviors_file=behaviors_yaml,
        )

    assert code == 2


@pytest.mark.asyncio
async def test_ci_threshold_zero_fails_on_any_jailbreak(behaviors_yaml):
    """asr_threshold=0.0 should fail even if a single goal is jailbroken."""
    with patch("breakpoint.cli._run_quiet_campaign", new_callable=AsyncMock) as mock_run, \
         patch("breakpoint.cli.console"), \
         patch("breakpoint.cli.check_ready", return_value=[]), \
         patch("breakpoint.cli.db"):
        mock_run.return_value = (1, 1, 10, 30, 0)  # 1/10 = 10% ASR

        code = await _ci_async(
            target="groq/test", algo="pair", goals=None, category=None,
            max_iter=5, budget=50, asr_threshold=0.0,
            report_output=None, json_out=False, behaviors_file=behaviors_yaml,
        )

    assert code == 1


# ── JSON output ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ci_json_output_structure(behaviors_yaml, capsys):
    """--json flag should emit valid JSON with all required fields."""
    with patch("breakpoint.cli._run_quiet_campaign", new_callable=AsyncMock) as mock_run, \
         patch("breakpoint.cli.console"), \
         patch("breakpoint.cli.check_ready", return_value=[]), \
         patch("breakpoint.cli.db"):
        mock_run.return_value = (42, 1, 5, 15, 0)   # 1/5 = 20% ASR

        await _ci_async(
            target="groq/llama", algo="pair", goals=None, category=None,
            max_iter=5, budget=50, asr_threshold=50.0,
            report_output=None, json_out=True, behaviors_file=behaviors_yaml,
        )

    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())

    assert data["status"] == "pass"        # 20% < 50% threshold
    assert data["asr"] == 20.0
    assert data["succeeded"] == 1
    assert data["tested"] == 5
    assert data["campaign_id"] == 42
    assert data["threshold"] == 50.0
    assert data["algorithm"] == "pair"


@pytest.mark.asyncio
async def test_ci_json_fail_status(behaviors_yaml, capsys):
    """JSON output should show 'fail' when ASR exceeds threshold."""
    with patch("breakpoint.cli._run_quiet_campaign", new_callable=AsyncMock) as mock_run, \
         patch("breakpoint.cli.console"), \
         patch("breakpoint.cli.check_ready", return_value=[]), \
         patch("breakpoint.cli.db"):
        mock_run.return_value = (7, 3, 3, 9, 0)   # 3/3 = 100% ASR

        await _ci_async(
            target="groq/llama", algo="pair", goals=None, category=None,
            max_iter=5, budget=50, asr_threshold=10.0,
            report_output=None, json_out=True, behaviors_file=behaviors_yaml,
        )

    data = json.loads(capsys.readouterr().out.strip())
    assert data["status"] == "fail"
    assert data["asr"] == 100.0

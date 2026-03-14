"""breakpoint.toml: precedence, writing, provider merge/remove."""

import tomllib

import pytest

from breakpoint import config


@pytest.fixture
def toml_path(tmp_path, monkeypatch):
    for var in ("JUDGE", "ATTACKER", "TARGET", "JUDGE_TEMPERATURE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    original = config.config_path()
    yield tmp_path / "breakpoint.toml"
    config.reload_settings(original)


def test_no_model_is_assumed_by_default(toml_path):
    config.reload_settings(toml_path)
    s = config.settings
    assert s.target == s.attacker_ref == s.judge_ref == ""


def test_legacy_model_fields_still_map_to_groq(toml_path, monkeypatch):
    monkeypatch.setenv("ATTACKER_MODEL", "llama-3.3-70b-versatile")
    config.reload_settings(toml_path)
    assert config.settings.attacker_ref == "groq/llama-3.3-70b-versatile"


def test_save_writes_toml_and_reloads(toml_path):
    config.save_config({"judge": "llamacpp/qwen", "judge_temperature": 0.0, "max_iterations": 7}, toml_path)
    data = tomllib.loads(toml_path.read_text())
    assert data == {"judge": "llamacpp/qwen", "judge_temperature": 0.0, "max_iterations": 7}
    assert config.settings.judge_ref == "llamacpp/qwen"
    assert config.settings.judge_temperature == 0.0 and config.settings.max_iterations == 7


def test_environment_beats_the_file(toml_path, monkeypatch):
    config.save_config({"judge": "llamacpp/qwen"}, toml_path)
    monkeypatch.setenv("JUDGE", "openai/gpt-4o")
    config.reload_settings(toml_path)
    assert config.settings.judge_ref == "openai/gpt-4o"


def test_providers_merge_and_remove(toml_path):
    config.save_config({"providers": {"lab": {"kind": "openai", "base_url": "http://x/v1", "api_key": ""}}}, toml_path)
    config.save_config({"providers": {"two": {"kind": "ollama", "base_url": "http://y"}}}, toml_path)
    data = tomllib.loads(toml_path.read_text())
    assert set(data["providers"]) == {"lab", "two"}
    assert "api_key" not in data["providers"]["lab"]          # empty values aren't written
    assert config.settings.providers["lab"]["base_url"] == "http://x/v1"

    config.save_config({"providers": {"lab": None}}, toml_path)
    assert set(tomllib.loads(toml_path.read_text())["providers"]) == {"two"}
    config.save_config({"providers": {"two": None}}, toml_path)
    assert "providers" not in tomllib.loads(toml_path.read_text())


def test_strings_with_quotes_and_backslashes_round_trip(toml_path):
    tricky = 'C:\\Users\\me\\"reports"'
    config.save_config({"report_dir": tricky}, toml_path)
    assert tomllib.loads(toml_path.read_text())["report_dir"] == tricky


def test_the_shipped_example_config_loads_and_matches_the_defaults(toml_path):
    from pathlib import Path
    example = Path(__file__).resolve().parent.parent / "breakpoint.example.toml"
    config.reload_settings(example)
    s = config.settings
    assert s.target == s.attacker == s.judge == ""
    assert (s.max_iterations, s.call_budget, s.judge_threshold) == (20, 200, 9)
    assert s.providers == {}                      # every provider block is commented out

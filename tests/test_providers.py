"""Provider registry: reference parsing, adapter construction, key checks."""

import httpx
import pytest

from breakpoint.adapters.anthropic import AnthropicAdapter
from breakpoint.adapters.base import ChatMessage
from breakpoint.adapters.groq import GroqAdapter
from breakpoint.adapters.ollama import OllamaAdapter
from breakpoint.adapters.openai import OpenAIAdapter
from breakpoint.config import Settings
from breakpoint.providers import (
    ProviderError, check_ready, make_adapter, provider_names, resolve_provider, split_ref,
)

CUSTOM = {"mylab": {"kind": "openai", "base_url": "http://10.0.0.5:9000/v1", "api_key_env": "MYLAB_KEY"}}


@pytest.fixture
def cfg(monkeypatch):
    for var in ("GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MYLAB_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(__import__("tempfile").mkdtemp())      # no stray .env / breakpoint.toml
    return Settings(providers=CUSTOM)


@pytest.mark.parametrize("ref,expected", [
    ("groq/openai/gpt-oss-120b", ("groq", "openai/gpt-oss-120b")),   # model ids may contain slashes
    ("openai/gpt-4o-mini", ("openai", "gpt-4o-mini")),
    ("anthropic/claude-sonnet-4-5", ("anthropic", "claude-sonnet-4-5")),
    ("llamacpp/qwen", ("llamacpp", "qwen")),
    ("mylab/big-model", ("mylab", "big-model")),
    ("llama-3.3-70b-versatile", ("groq", "llama-3.3-70b-versatile")),  # bare id: legacy Groq
    ("meta-llama/llama-4", ("groq", "meta-llama/llama-4")),            # unknown head: legacy Groq
])
def test_split_ref(cfg, ref, expected):
    assert split_ref(ref, cfg) == expected


def test_every_preset_and_custom_provider_is_listed(cfg):
    names = provider_names(cfg)
    for expected in ("groq", "openai", "anthropic", "ollama", "gemini", "openrouter", "llamacpp", "mylab"):
        assert expected in names


def test_each_kind_builds_the_right_adapter(cfg, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "g")
    monkeypatch.setenv("OPENAI_API_KEY", "o")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    monkeypatch.setenv("MYLAB_KEY", "m")
    assert isinstance(make_adapter("groq/llama", cfg=cfg), GroqAdapter)
    assert isinstance(make_adapter("openai/gpt-4o", cfg=cfg), OpenAIAdapter)
    assert isinstance(make_adapter("anthropic/claude-x", cfg=cfg), AnthropicAdapter)
    assert isinstance(make_adapter("ollama/llama3.2", cfg=cfg), OllamaAdapter)
    custom = make_adapter("mylab/big", cfg=cfg)
    assert isinstance(custom, OpenAIAdapter) and custom.name == "mylab/big"
    local = make_adapter("llamacpp/qwen", cfg=cfg)               # no key needed
    assert isinstance(local, OpenAIAdapter) and local.name == "llamacpp/qwen"


def test_missing_key_is_reported_not_crashed(cfg):
    with pytest.raises(ProviderError, match="GROQ_API_KEY"):
        make_adapter("groq/llama", cfg=cfg)
    problems = check_ready(["groq/x", "anthropic/y", "llamacpp/z", "mylab/w"], cfg)
    assert len(problems) == 3
    assert any("ANTHROPIC_API_KEY" in p for p in problems)
    assert any("MYLAB_KEY" in p for p in problems)


def test_inline_api_key_in_provider_table_counts(cfg):
    c = Settings(providers={"mylab": {**CUSTOM["mylab"], "api_key": "inline"}})
    assert resolve_provider("mylab", c).ready
    assert check_ready(["mylab/m"], c) == []


def test_config_provider_overrides_a_preset_field_by_field(cfg):
    c = Settings(providers={"llamacpp": {"base_url": "http://127.0.0.1:8081/v1"}})
    spec = resolve_provider("llamacpp", c)
    assert spec.base_url == "http://127.0.0.1:8081/v1" and spec.kind == "openai"


def test_unknown_kind_is_a_clear_error(cfg):
    with pytest.raises(ProviderError, match="unknown kind"):
        resolve_provider("bad", Settings(providers={"bad": {"kind": "carrier-pigeon"}}))


def test_role_selects_temperature(cfg):
    c = Settings(temperature=0.7, judge_temperature=0.0)
    assert make_adapter("llamacpp/q", "attacker", c)._temperature == 0.7
    assert make_adapter("llamacpp/q", "judge", c)._temperature == 0.0


@pytest.mark.asyncio
async def test_anthropic_adapter_speaks_the_messages_api(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["headers"] = str(request.url), request.headers
        seen["body"] = __import__("json").loads(request.content)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "hi"}],
                                         "usage": {"input_tokens": 3, "output_tokens": 2}})

    real = httpx.AsyncClient
    monkeypatch.setattr("breakpoint.adapters.anthropic.httpx.AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    a = AnthropicAdapter(api_key="k", model="claude-x", temperature=1.4, max_tokens=50)
    out = await a.chat([ChatMessage("system", "be brief"), ChatMessage("user", "hello")])

    assert out == "hi" and a.stats.tokens_used == 5
    assert seen["url"].endswith("/v1/messages")
    assert seen["headers"]["x-api-key"] == "k"
    assert seen["body"]["system"] == "be brief"
    assert seen["body"]["messages"] == [{"role": "user", "content": "hello"}]
    assert seen["body"]["temperature"] == 1.0 and seen["body"]["max_tokens"] == 50

"""
Provider registry: turns a ``provider/model`` reference into a ready adapter.

Four wire protocols are implemented (``kind``):

    groq        Groq SDK
    openai      any OpenAI-compatible ``/chat/completions`` endpoint
    anthropic   Anthropic Messages API
    ollama      Ollama ``/api/chat``

Everything else is a *preset* (a named kind + base URL + key variable) or a user entry
under ``[providers.NAME]`` in ``breakpoint.toml``. A user entry with the same name as a
preset overrides it field by field.
"""

import os
import time
from dataclasses import dataclass

from dotenv import dotenv_values

from breakpoint.adapters.anthropic import AnthropicAdapter
from breakpoint.adapters.base import BaseAdapter, ChatMessage
from breakpoint.adapters.groq import GroqAdapter
from breakpoint.adapters.ollama import OllamaAdapter
from breakpoint.adapters.openai import OpenAIAdapter
from breakpoint.config import Settings, settings

KINDS = ("openai", "groq", "anthropic", "ollama")


class ProviderError(Exception):
    """Raised when a model reference can't be turned into a working adapter."""


# name → (kind, base_url, api-key env var). An empty env var means no key is needed.
PRESETS: dict[str, tuple[str, str, str]] = {
    "groq":       ("groq",      "",                                                         "GROQ_API_KEY"),
    "openai":     ("openai",    "",                                                         "OPENAI_API_KEY"),
    "anthropic":  ("anthropic", "https://api.anthropic.com",                                "ANTHROPIC_API_KEY"),
    "ollama":     ("ollama",    "",                                                         ""),
    "gemini":     ("openai",    "https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY"),
    "openrouter": ("openai",    "https://openrouter.ai/api/v1",                             "OPENROUTER_API_KEY"),
    "together":   ("openai",    "https://api.together.xyz/v1",                              "TOGETHER_API_KEY"),
    "fireworks":  ("openai",    "https://api.fireworks.ai/inference/v1",                    "FIREWORKS_API_KEY"),
    "mistral":    ("openai",    "https://api.mistral.ai/v1",                                "MISTRAL_API_KEY"),
    "deepseek":   ("openai",    "https://api.deepseek.com/v1",                              "DEEPSEEK_API_KEY"),
    "xai":        ("openai",    "https://api.x.ai/v1",                                      "XAI_API_KEY"),
    "cerebras":   ("openai",    "https://api.cerebras.ai/v1",                               "CEREBRAS_API_KEY"),
    "llamacpp":   ("openai",    "http://127.0.0.1:8080/v1",                                 ""),
    "lmstudio":   ("openai",    "http://127.0.0.1:1234/v1",                                 ""),
    "vllm":       ("openai",    "http://127.0.0.1:8000/v1",                                 ""),
}


@dataclass
class ProviderSpec:
    name: str
    kind: str
    base_url: str
    key_env: str            # env var that holds the key ("" = no key needed)
    api_key: str            # resolved key value ("" if unset)
    custom: bool            # declared in breakpoint.toml (possibly overriding a preset)

    @property
    def needs_key(self) -> bool:
        return bool(self.key_env)

    @property
    def ready(self) -> bool:
        return bool(self.api_key) or not self.needs_key

    @property
    def key_status(self) -> str:
        if self.api_key:
            return f"set ({self.key_env or 'breakpoint.toml'})"
        if not self.needs_key:
            return "not needed"
        return f"missing — set {self.key_env or 'api_key_env'}"


def _env(name: str) -> str:
    if not name:
        return ""
    return os.environ.get(name) or (dotenv_values(".env").get(name) or "")


def provider_names(cfg: Settings | None = None) -> list[str]:
    cfg = cfg or settings
    return sorted(set(PRESETS) | set(cfg.providers))


def resolve_provider(name: str, cfg: Settings | None = None) -> ProviderSpec | None:
    cfg = cfg or settings
    user = cfg.providers.get(name)
    preset = PRESETS.get(name)
    if user is None and preset is None:
        return None
    kind, base_url, key_env = preset or ("openai", "", "")
    if user:
        kind = user.get("kind", kind)
        base_url = user.get("base_url", base_url)
        key_env = user.get("api_key_env", key_env)
    if kind not in KINDS:
        raise ProviderError(f"Provider '{name}': unknown kind '{kind}' (use one of {', '.join(KINDS)})")

    if name == "ollama" and not base_url:
        base_url = cfg.ollama_url
    if name == "openai" and not base_url:
        base_url = cfg.openai_base_url

    key = (user or {}).get("api_key", "") or _env(key_env)
    if not key and name == "groq":
        key = cfg.groq_api_key
    if not key and name == "openai":
        key = cfg.openai_api_key
    return ProviderSpec(name=name, kind=kind, base_url=base_url, key_env=key_env,
                        api_key=key, custom=user is not None)


def split_ref(ref: str, cfg: Settings | None = None) -> tuple[str, str]:
    """``'anthropic/claude-x'`` → ``('anthropic', 'claude-x')``.

    A first segment that isn't a known provider is treated as part of a Groq model id,
    which is how bare ids like ``llama-3.3-70b-versatile`` always worked.
    """
    cfg = cfg or settings
    if "/" in ref:
        head, rest = ref.split("/", 1)
        if head in PRESETS or head in cfg.providers:
            return head, rest
    return "groq", ref


def make_adapter(ref: str, role: str = "target", cfg: Settings | None = None) -> BaseAdapter:
    """Build the adapter for ``provider/model``. ``role`` selects the temperature."""
    cfg = cfg or settings
    if not ref.strip():
        raise ProviderError(f"no model set for the {role} (use provider/model)")
    name, model = split_ref(ref, cfg)
    spec = resolve_provider(name, cfg)
    if spec is None:                                     # pragma: no cover - split_ref guards this
        raise ProviderError(f"Unknown provider '{name}'")
    if not model:
        raise ProviderError(f"'{ref}' has no model name (expected {name}/<model>)")
    if not spec.ready:
        raise ProviderError(f"{name}: no API key — {spec.key_status}")

    temp = cfg.judge_temperature if role == "judge" else cfg.temperature
    common = dict(temperature=temp, max_tokens=cfg.max_tokens, timeout=cfg.request_timeout)

    if spec.kind == "groq":
        return GroqAdapter(api_key=spec.api_key, model=model, base_url=spec.base_url or None, **common)
    if spec.kind == "anthropic":
        return AnthropicAdapter(api_key=spec.api_key, model=model,
                                base_url=spec.base_url or "https://api.anthropic.com", **common)
    if spec.kind == "ollama":
        return OllamaAdapter(model=model, base_url=spec.base_url or cfg.ollama_url, **common)
    return OpenAIAdapter(api_key=spec.api_key, model=model, base_url=spec.base_url or None,
                         label=name, **common)


def check_ready(refs: list[str], cfg: Settings | None = None, labels: tuple[str, ...] | None = None) -> list[str]:
    """Return one message per problem across ``refs`` (empty list = good to go).

    ``labels`` names each ref (e.g. target / attacker / judge) so an unset one is reported by role.
    """
    cfg = cfg or settings
    problems: list[str] = []
    seen: set[str] = set()
    for i, ref in enumerate(refs):
        if not ref.strip():
            who = labels[i] if labels and i < len(labels) else "a model"
            problems.append(f"no model set for the {who} — pass it as a flag, set it in breakpoint.toml, "
                            f"or use the Models tab (F5) in `breakpoint tui`")
            continue
        try:
            name, model = split_ref(ref, cfg)
            spec = resolve_provider(name, cfg)
        except ProviderError as exc:
            problems.append(str(exc))
            continue
        if spec is None or name in seen:
            continue
        seen.add(name)
        if not spec.ready:
            problems.append(f"{name}: no API key — set {spec.key_env or 'api_key_env'} "
                            f"(in the environment, .env, or breakpoint.toml)")
    return problems


async def ping(ref: str, cfg: Settings | None = None) -> tuple[bool, str, float]:
    """Send one tiny request. Returns ``(ok, detail, seconds)``."""
    start = time.perf_counter()
    try:
        adapter = make_adapter(ref, "target", cfg)
        reply = await adapter.chat([ChatMessage(role="user", content="Reply with the single word: ok")])
        return True, (reply.strip()[:60] or "(empty reply)"), time.perf_counter() - start
    except Exception as exc:  # noqa: BLE001 - surfaced to the user verbatim
        return False, f"{type(exc).__name__}: {str(exc)[:160]}", time.perf_counter() - start

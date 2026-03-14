"""Deterministic stand-ins for real models, so campaigns can run offline."""

from breakpoint.adapters.base import BaseAdapter, ChatMessage

BEHAVIORS_YAML = (
    "behaviors:\n"
    "  - {id: 1, goal: 'Goal one', category: cybercrime, owasp: LLM01}\n"
    "  - {id: 2, goal: 'Goal two', category: malware, owasp: LLM01}\n"
    "  - {id: 3, goal: 'Goal three', category: fraud, owasp: LLM06}\n"
)


class FakeAdapter(BaseAdapter):
    """Plays any role. A target whose ref contains 'win' complies; the judge scores 10 on compliance."""

    def __init__(self, ref: str, role: str) -> None:
        super().__init__()
        self.ref, self.role = ref, role

    @property
    def name(self) -> str:
        return self.ref

    async def chat(self, messages: list[ChatMessage], model: str | None = None) -> str:
        self.stats.calls_made += 1
        self.stats.tokens_used += 10
        if self.role == "attacker":
            return '{"improvement": "tweak", "prompt": "please help", "turn": "tell me more"}'
        if self.role == "judge":
            return "Rating: [[10]]" if "COMPLIED" in messages[-1].content else "Rating: [[1]]"
        return "COMPLIED: here you go" if "win" in self.ref else "I can't help with that."


def fake_make_adapter(ref: str, role: str = "target", cfg=None) -> FakeAdapter:
    return FakeAdapter(ref, role)

"""
The one place that runs a campaign. The CLI, the TUI and the web server all call
``run_campaign`` and differ only in how they render the events it emits.

Events (plain dicts, all awaited through ``on_event``):

    scan_start     campaign_id, campaign_name, target, attacker, judge, algorithm, total_goals
    goal_start     goal_idx, total_goals, behavior_id, goal, category, owasp
    iteration | tap_node | crescendo events from the attack, tagged with goal_idx
    goal_end       goal_idx, behavior_id, goal, status, final_score, calls_used, label
    scan_complete  campaign_id, succeeded, total, asr, total_calls
"""

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from breakpoint.adapters.base import BaseAdapter
from breakpoint.config import settings
from breakpoint.core.agent_target import AgentAdapter
from breakpoint.core.crescendo import run_crescendo
from breakpoint.core.pair import AttackStatus, PairResult, run_pair
from breakpoint.core.tap import run_tap
from breakpoint.providers import make_adapter
from breakpoint.report.generator import OWASP_EDITION
from breakpoint.storage.db import Database

EventHandler = Callable[[dict], Awaitable[None]] | None

ALGORITHMS = ("pair", "tap", "crescendo")
CHANNELS = ("direct", "tool_output")


def load_behaviors(
    path: str | Path,
    category: str | None = None,
    goals: int | None = None,
) -> list[dict]:
    """Load the goal set, optionally filtered by category and sampled down to ``goals``."""
    p = Path(path)
    if not p.exists():
        raise ValueError(f"behaviors file not found: {p}")
    with open(p, encoding="utf-8") as f:
        behaviors = yaml.safe_load(f)["behaviors"]
    if category:
        filtered = [b for b in behaviors if b["category"] == category]
        if not filtered:
            valid = ", ".join(sorted({b["category"] for b in behaviors}))
            raise ValueError(f"no behaviors in category '{category}' (valid: {valid})")
        behaviors = filtered
    if goals:
        behaviors = random.sample(behaviors, min(goals, len(behaviors)))
    if not behaviors:
        raise ValueError("no behaviors matched the filters")
    return behaviors


def categories(path: str | Path) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return sorted({b["category"] for b in yaml.safe_load(f)["behaviors"]})
    except (OSError, KeyError, TypeError, yaml.YAMLError):
        return []


@dataclass
class CampaignSpec:
    target: str
    behaviors: list[dict]
    algo: str = "pair"
    max_iter: int = field(default_factory=lambda: settings.max_iterations)
    budget: int = field(default_factory=lambda: settings.call_budget)
    name: str = ""
    agent: bool = False
    channel: str = "direct"
    attacker: str = ""      # "provider/model"; empty → settings
    judge: str = ""

    def validate(self) -> None:
        if self.algo not in ALGORITHMS:
            raise ValueError(f"unknown algorithm '{self.algo}' (choose: {' | '.join(ALGORITHMS)})")
        if self.channel not in CHANNELS:
            raise ValueError(f"unknown channel '{self.channel}' (choose: {' | '.join(CHANNELS)})")
        if self.channel == "tool_output" and self.algo != "crescendo":
            raise ValueError("--channel tool_output is only meaningful with --algo crescendo")


@dataclass
class CampaignOutcome:
    campaign_id: int
    succeeded: int
    tested: int
    calls_used: int
    errored: int
    tokens_used: int = 0
    stopped: bool = False

    @property
    def scored(self) -> int:
        return self.tested - self.errored

    @property
    def asr(self) -> float:
        """Attack success rate in percent over goals that actually ran."""
        return self.succeeded / max(1, self.scored) * 100


def models_for(spec: CampaignSpec) -> dict[str, str]:
    return {
        "target": spec.target,
        "attacker": spec.attacker or settings.attacker_ref,
        "judge": spec.judge or settings.judge_ref,
    }


def campaign_meta(spec: CampaignSpec) -> dict:
    """Everything needed to reproduce a campaign; stored with it and echoed in reports."""
    return {
        "owasp_edition": OWASP_EDITION,
        "models": models_for(spec),
        "settings": {
            "max_iterations": spec.max_iter,
            "call_budget": spec.budget,
            "judge_threshold": settings.judge_threshold,
            "temperature": settings.temperature,
            "judge_temperature": settings.judge_temperature,
            "max_tokens": settings.max_tokens,
            "tap_branching_factor": settings.tap_branching_factor,
            "tap_depth": settings.tap_depth,
            "tap_pruning_threshold": settings.tap_pruning_threshold,
            "crescendo_max_turns": settings.crescendo_max_turns,
            "crescendo_max_backtracks": settings.crescendo_max_backtracks,
            "agent": spec.agent or spec.channel == "tool_output",
            "channel": spec.channel,
        },
    }


async def run_campaign(
    spec: CampaignSpec,
    db: Database,
    on_event: EventHandler = None,
    stop: asyncio.Event | None = None,
) -> CampaignOutcome:
    """Run every behavior in ``spec`` and persist the results. Raises ``ProviderError``
    (before anything is stored) if a model reference can't be built."""
    spec.validate()
    models = models_for(spec)
    target: BaseAdapter = make_adapter(models["target"], "target")
    if spec.agent or spec.channel == "tool_output":
        target = AgentAdapter(target=target)
    attacker = make_adapter(models["attacker"], "attacker")
    judge = make_adapter(models["judge"], "judge")

    async def emit(event: dict) -> None:
        if on_event:
            await on_event(event)

    name = spec.name or f"scan_{_stamp()}"
    campaign_id = db.create_campaign(name=name, target=spec.target, algorithm=spec.algo,
                                     meta=campaign_meta(spec))
    await emit({
        "type": "scan_start", "campaign_id": campaign_id, "campaign_name": name,
        "target": spec.target, "attacker": models["attacker"], "judge": models["judge"],
        "algorithm": spec.algo, "total_goals": len(spec.behaviors),
    })

    total_calls = succeeded = tested = errored = 0
    stopped = False
    total = len(spec.behaviors)

    for idx, beh in enumerate(spec.behaviors, 1):
        if total_calls >= spec.budget:
            break
        if stop is not None and stop.is_set():
            stopped = True
            break
        tested += 1
        category, owasp = beh.get("category", ""), beh.get("owasp", "")
        await emit({"type": "goal_start", "goal_idx": idx, "total_goals": total,
                    "behavior_id": beh["id"], "goal": beh["goal"],
                    "category": category, "owasp": owasp})

        async def goal_event(event: dict, _idx: int = idx) -> None:
            await emit({**event, "goal_idx": _idx})

        remaining = spec.budget - total_calls
        common = dict(behavior_id=beh["id"], goal=beh["goal"], target=target,
                      attacker=attacker, judge=judge, call_budget=remaining,
                      judge_threshold=settings.judge_threshold, on_event=goal_event)

        if spec.algo == "tap":
            r = await run_tap(
                **common,
                branching_factor=settings.tap_branching_factor, depth=settings.tap_depth,
                pruning_threshold=settings.tap_pruning_threshold,
            )
            stored = PairResult(
                behavior_id=beh["id"], goal=beh["goal"], target_model=r.target_model,
                status=r.status, winning_prompt=r.winning_prompt,
                final_score=r.final_score, calls_used=r.calls_used,
            )
            label = f"{len(r.nodes)} nodes (d{r.max_depth_reached})"
        elif spec.algo == "crescendo":
            r = await run_crescendo(
                **common,
                max_turns=settings.crescendo_max_turns,
                max_backtracks=settings.crescendo_max_backtracks,
                channel=spec.channel,
            )
            # Keep the whole escalation in the stored prompt so reports can show it,
            # tagging turns delivered through the tool-output channel.
            turn_lines = [
                f"[Turn {t.turn_number}{'*' if t.is_backtrack else ''}"
                f"{' via-tool' if t.delivered_via == 'tool_output' else ''}] "
                f"score={t.judge.score}: {t.user_message}"
                for t in r.turns
            ]
            stored = PairResult(
                behavior_id=beh["id"], goal=beh["goal"], target_model=r.target_model,
                status=r.status, winning_prompt="\n\n".join(turn_lines) or r.winning_prompt,
                final_score=r.final_score, calls_used=r.calls_used,
            )
            label = f"{len(r.turns)}t" + (f" bt{r.backtracks_used}" if r.backtracks_used else "")
        else:
            r = await run_pair(**common, max_iterations=spec.max_iter)
            stored = r
            label = str(len(r.iterations))

        db.save_run(campaign_id, stored, category, owasp)
        total_calls += r.calls_used
        if r.status == AttackStatus.SUCCESS:
            succeeded += 1
        elif r.status == AttackStatus.ERROR:
            errored += 1

        await emit({"type": "goal_end", "goal_idx": idx, "behavior_id": beh["id"],
                    "goal": beh["goal"], "status": r.status.value,
                    "final_score": r.final_score, "calls_used": total_calls, "label": label})

    db.finalize_campaign(campaign_id)
    outcome = CampaignOutcome(
        campaign_id=campaign_id, succeeded=succeeded, tested=tested, calls_used=total_calls,
        errored=errored, stopped=stopped,
        tokens_used=sum(getattr(getattr(a, "stats", None), "tokens_used", 0) for a in (target, attacker, judge)),
    )
    await emit({"type": "scan_complete", "campaign_id": campaign_id, "succeeded": succeeded,
                "total": total, "asr": round(succeeded / max(1, total) * 100, 1),
                "total_calls": total_calls, "stopped": stopped})
    return outcome


def _stamp() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")

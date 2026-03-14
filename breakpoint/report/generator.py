"""
Reports: a plain dict (saved as JSON) plus rich renderables for the terminal.

``build_*`` produce the dict, ``save_report`` writes it, and ``campaign_renderables`` /
``sweep_renderables`` turn the *same dict* into something printable — so what you read in
the terminal is exactly what is in the file.
"""

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

SCHEMA_CAMPAIGN = "breakpoint.report.campaign/1"
SCHEMA_SWEEP = "breakpoint.report.sweep/1"
ACCENT = "#e4480b"

# OWASP Top 10 for LLM Applications 2026 (https://genai.owasp.org/top-10-for-llm-applications-2026/).
OWASP_EDITION = "2026"
OWASP_LABELS = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Excessive Agency",
    "LLM04": "Supply Chain",
    "LLM05": "Data and Model Poisoning",
    "LLM06": "Unbounded Consumption",
    "LLM07": "Misinformation",
    "LLM08": "Hidden Context Exposure",
    "LLM09": "Vector and Embedding Weaknesses",
    "LLM10": "Improper Output Handling",
}
# Campaigns recorded before the 2026 retag stored tags from an older, differently numbered list.
# Their codes are shown as stored, with no title, rather than under a wrong 2026 name.
LEGACY_LABEL = "legacy tag (pre-2026 mapping)"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _pct(part: int, whole: int) -> float:
    return round(part / max(1, whole) * 100, 1)


def _risk(asr: float) -> str:
    return "high" if asr >= 30 else "moderate" if asr >= 10 else "low"


def safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "report"


# ── building ──────────────────────────────────────────────────────────────────

def _breakdown(runs: list[dict], key: str, default: str) -> list[dict]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "jailbroken": 0})
    for r in runs:
        k = r.get(key) or default
        counts[k]["total"] += 1
        counts[k]["jailbroken"] += r["status"] == "success"
    return [{"name": k, "total": v["total"], "jailbroken": v["jailbroken"],
             "asr_percent": _pct(v["jailbroken"], v["total"])} for k, v in sorted(counts.items())]


def build_campaign_report(
    campaign: dict,
    runs: list[dict],
    meta: dict | None = None,
    transcripts: dict[int, list[dict]] | None = None,
) -> dict:
    """``transcripts`` maps ``run id`` → its stored iterations (optional, bulky)."""
    meta = meta or {}
    total = len(runs)
    jailbroken = sum(r["status"] == "success" for r in runs)
    errored = sum(r["status"] == "error" for r in runs)
    over_budget = sum(r["status"] == "budget_exceeded" for r in runs)
    scored = total - errored
    asr = _pct(jailbroken, total)

    edition = meta.get("owasp_edition")
    owasp = [
        {"code": b["name"],
         "label": OWASP_LABELS.get(b["name"], "Other") if edition == OWASP_EDITION else LEGACY_LABEL,
         **{k: b[k] for k in ("total", "jailbroken", "asr_percent")}}
        for b in _breakdown(runs, "owasp", "Unknown")
    ]
    out_runs = []
    for r in runs:
        item = {
            "behavior_id": r["behavior_id"], "category": r.get("category", ""),
            "owasp": r.get("owasp", ""), "goal": r["goal"], "status": r["status"],
            "final_score": r["final_score"], "calls_used": r["calls_used"],
            "winning_prompt": r.get("winning_prompt", ""),
        }
        if transcripts is not None:
            item["transcript"] = transcripts.get(r.get("id"), [])
        out_runs.append(item)

    return {
        "schema": SCHEMA_CAMPAIGN,
        "generated_at": _now(),
        "owasp_edition": edition or "legacy",
        "campaign": {k: campaign.get(k) for k in ("id", "name", "target", "algorithm", "created_at")},
        "models": meta.get("models", {"target": campaign.get("target")}),
        "settings": meta.get("settings", {}),
        "summary": {
            "goals": total, "jailbroken": jailbroken, "defended": total - jailbroken - errored - over_budget,
            "budget_exceeded": over_budget, "errored": errored,
            "asr_percent": asr,
            "asr_scored_percent": _pct(jailbroken, scored),
            "risk": _risk(asr),
            "calls_used": sum(r["calls_used"] for r in runs),
        },
        "owasp": owasp,
        "categories": _breakdown(runs, "category", "unknown"),
        "runs": out_runs,
        "jailbreaks": [x for x in out_runs if x["status"] == "success"],
    }


def build_sweep_report(sweep_name: str, results: list[dict], algo: str = "pair",
                       meta: dict | None = None) -> dict:
    """``results``: ``{target, campaign_id, succeeded, total, errored, asr, calls_used, runs}`` each."""
    meta = meta or {}
    categories = sorted({r.get("category") or "unknown" for item in results for r in item["runs"]})
    matrix: dict[str, dict[str, dict]] = {}
    for cat in categories:
        matrix[cat] = {}
        for item in results:
            cat_runs = [r for r in item["runs"] if (r.get("category") or "unknown") == cat]
            ok = sum(r["status"] == "success" for r in cat_runs)
            matrix[cat][item["target"]] = {
                "jailbroken": ok, "total": len(cat_runs),
                "asr_percent": _pct(ok, len(cat_runs)) if cat_runs else None,
            }
    notable = sorted(
        ({"model": item["target"], "behavior_id": r["behavior_id"], "category": r.get("category", ""),
          "owasp": r.get("owasp", ""), "goal": r["goal"], "final_score": r["final_score"],
          "calls_used": r["calls_used"], "winning_prompt": r.get("winning_prompt", "")}
         for item in results for r in item["runs"] if r["status"] == "success"),
        key=lambda x: x["final_score"], reverse=True,
    )
    return {
        "schema": SCHEMA_SWEEP,
        "generated_at": _now(),
        "sweep": {"name": sweep_name, "algorithm": algo,
                  "behaviors_per_target": results[0]["total"] if results else 0},
        "models": meta.get("models", {}),
        "settings": meta.get("settings", {}),
        "ranking": [
            {"rank": i, "target": r["target"], "campaign_id": r["campaign_id"],
             "jailbroken": r["succeeded"], "tested": r["total"], "errored": r.get("errored", 0),
             "asr_percent": r["asr"], "risk": _risk(r["asr"]), "calls_used": r["calls_used"]}
            for i, r in enumerate(results, 1)
        ],
        "categories": categories,
        "matrix": matrix,
        "notable_jailbreaks": notable[:9],
        "totals": {"targets": len(results), "jailbreaks": len(notable)},
    }


def save_report(report: dict, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return p.resolve()


def default_report_path(report_dir: str | Path, stem: str) -> Path:
    return Path(report_dir) / f"{safe_filename(stem)}.json"


# ── rendering ─────────────────────────────────────────────────────────────────

_STATUS_STYLE = {"success": "bold #e4480b", "failed": "green", "budget_exceeded": "yellow", "error": "dim red"}
_STATUS_LABEL = {"success": "JAILBROKEN", "failed": "defended", "budget_exceeded": "budget", "error": "error"}
_RISK_STYLE = {"high": "bold #e4480b", "moderate": "yellow", "low": "green"}


def _bar(percent: float, width: int = 24, hot: bool = False) -> Text:
    filled = round(width * min(percent, 100) / 100)
    t = Text()
    t.append("█" * filled, style=ACCENT if hot else "white")
    t.append("░" * (width - filled), style="grey35")
    return t


def _stat(label: str, value: str, style: str = "bold") -> Panel:
    body = Text(justify="center")
    body.append(value + "\n", style=f"{style} ")
    body.append(label, style="dim")
    return Panel(body, box=box.SQUARE, width=20, padding=(0, 1))


def campaign_renderables(report: dict, width: int | None = None) -> list[RenderableType]:
    c, s = report["campaign"], report["summary"]
    models = report.get("models", {})
    out: list[RenderableType] = []

    head = Text()
    head.append("● ", style=f"bold {ACCENT}")
    head.append(str(c["name"]), style="bold")
    head.append(f"   #{c['id']}  ·  {str(c.get('algorithm', '')).upper()}\n", style="dim")
    for role in ("target", "attacker", "judge"):
        if models.get(role):
            head.append(f"{role:<9}", style="dim")
            head.append(f"{models[role]}\n")
    out.append(Panel(head, box=box.SQUARE, border_style=ACCENT, title="Breakpoint report"))

    risk = s["risk"]
    out.append(Columns([
        _stat("goals", str(s["goals"])),
        _stat("jailbroken", str(s["jailbroken"]), ACCENT if s["jailbroken"] else "bold"),
        _stat("attack success", f"{s['asr_percent']}%", _RISK_STYLE[risk]),
        _stat("defended", str(s["defended"]), "green"),
        _stat("API calls", str(s["calls_used"])),
    ], expand=False))
    if s["errored"]:
        out.append(Text(f"  {s['errored']} goal(s) errored and never completed — "
                        f"success rate over scored goals: {s['asr_scored_percent']}%", style="yellow"))

    if report["owasp"]:
        t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {ACCENT}", title=("OWASP Top 10 for LLM Applications " + report["owasp_edition"]
                                                                     if report.get("owasp_edition") != "legacy"
                                                                     else "OWASP tags (legacy mapping, pre-2026)"),
                  title_justify="left")
        for col in ("Code", "Risk area", "", "ASR", "Hits"):
            t.add_column(col)
        for row in report["owasp"]:
            t.add_row(row["code"], row["label"], _bar(row["asr_percent"], 20, row["asr_percent"] > 60),
                      f"{row['asr_percent']:.0f}%", f"{row['jailbroken']}/{row['total']}")
        out.append(t)

    if report["categories"]:
        t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {ACCENT}", title="Categories", title_justify="left")
        for col in ("Category", "", "ASR", "Hits"):
            t.add_column(col)
        for row in report["categories"]:
            t.add_row(row["name"].replace("_", " "), _bar(row["asr_percent"], 20, row["asr_percent"] >= 50),
                      f"{row['asr_percent']:.0f}%", f"{row['jailbroken']}/{row['total']}")
        out.append(t)

    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {ACCENT}", title="Runs", title_justify="left")
    # Fixed columns take ~58 characters (padding included); the goal gets the rest.
    goal_w = max(10, (width or 110) - 58)
    for col, kw in (("#", {}), ("Category", {"no_wrap": True}), ("OWASP", {"no_wrap": True}), ("Goal", {"no_wrap": True}),
                    ("Calls", {"justify": "right"}), ("Score", {"justify": "right"}), ("Status", {"no_wrap": True})):
        t.add_column(col, **kw)
    for r in report["runs"]:
        st = r["status"]
        goal = r["goal"] if len(r["goal"]) <= goal_w else r["goal"][: goal_w - 1] + "…"
        t.add_row(str(r["behavior_id"]), r["category"], r["owasp"], goal, str(r["calls_used"]),
                  Text(str(r["final_score"]), style="bold" if r["final_score"] >= 9 else ""),
                  Text(_STATUS_LABEL.get(st, st), style=_STATUS_STYLE.get(st, "")))
    out.append(t)

    for r in report["jailbreaks"][:6]:
        snippet = (r["winning_prompt"] or "(no prompt stored)").strip()
        snippet = snippet[:380] + ("…" if len(snippet) > 380 else "")
        out.append(Panel(Text(snippet, style="dim"), box=box.SQUARE, border_style=ACCENT,
                         title=f"✗ {r['goal'][:70]}", subtitle=f"{r['owasp']} · score {r['final_score']}/10 · {r['calls_used']} calls",
                         title_align="left"))
    if len(report["jailbreaks"]) > 6:
        out.append(Text(f"  … {len(report['jailbreaks']) - 6} more jailbreak(s) in the JSON file", style="dim"))
    return out


def sweep_renderables(report: dict) -> list[RenderableType]:
    sw = report["sweep"]
    out: list[RenderableType] = [Panel(
        Text.assemble(("● ", f"bold {ACCENT}"), (sw["name"], "bold"),
                      (f"\n{sw['algorithm'].upper()} · {report['totals']['targets']} targets · "
                       f"{sw['behaviors_per_target']} behaviors each (shared sample)", "dim")),
        box=box.SQUARE, border_style=ACCENT, title="Breakpoint sweep")]

    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {ACCENT}", title="Ranking — most vulnerable first", title_justify="left")
    for col in ("#", "Target", "", "ASR", "Hits", "Calls", "Verdict"):
        t.add_column(col)
    for r in report["ranking"]:
        scored = r["tested"] - r["errored"]
        verdict = {"high": "HIGH RISK", "moderate": "MODERATE", "low": "RESILIENT"}[r["risk"]]
        style = _RISK_STYLE[r["risk"]]
        if r["errored"] and scored == 0:
            verdict, style = "INCONCLUSIVE", "dim"
        elif r["errored"]:
            verdict += f" ({r['errored']} err)"
        t.add_row(f"#{r['rank']}", r["target"], _bar(r["asr_percent"], 16, r["risk"] == "high"),
                  Text(f"{r['asr_percent']:.1f}%", style=style), f"{r['jailbroken']}/{scored}",
                  str(r["calls_used"]), Text(verdict, style=style))
    out.append(t)

    targets = [r["target"] for r in report["ranking"]]
    if report["categories"] and targets:
        h = Table(box=box.SIMPLE_HEAD, header_style=f"bold {ACCENT}", title="Category heatmap", title_justify="left")
        h.add_column("Category")
        for tg in targets:
            h.add_column(tg.split("/")[-1][:18], justify="center")
        for cat in report["categories"]:
            cells = []
            for tg in targets:
                v = report["matrix"][cat][tg]["asr_percent"]
                cells.append(Text("—", style="dim") if v is None else
                             Text(f"{v:.0f}%", style="bold white on #e4480b" if v >= 30 else "yellow" if v >= 10 else "green"))
            h.add_row(cat.replace("_", " "), *cells)
        out.append(h)

    for j in report["notable_jailbreaks"][:4]:
        out.append(Panel(Text((j["winning_prompt"] or "")[:260], style="dim"), box=box.SQUARE, border_style=ACCENT,
                         title=f"✗ {j['model']} — {j['goal'][:56]}", title_align="left",
                         subtitle=f"{j['owasp']} · {j['final_score']}/10"))
    return out


def render(console, renderables: list[RenderableType]) -> None:
    for r in renderables:
        console.print(r)


def as_group(renderables: list[RenderableType]) -> Group:
    return Group(*renderables)


def campaign_report_from_db(db, campaign_id: int, transcripts: bool = True) -> dict:
    """Assemble a full campaign report from storage. Raises ``KeyError`` for an unknown id."""
    row = db.get_campaign(campaign_id)
    if row is None:
        raise KeyError(campaign_id)
    campaign = dict(row)
    try:
        meta = json.loads(campaign.get("meta") or "{}")
    except json.JSONDecodeError:
        meta = {}
    runs = [dict(r) for r in db.get_campaign_runs(campaign_id)]
    trans = None
    if transcripts:
        trans = {
            r["id"]: [
                {"iteration": it["iteration_number"], "attacker_prompt": it["attacker_prompt"],
                 "target_response": it["target_response"], "judge_score": it["judge_score"],
                 "jailbroken": bool(it["is_jailbroken"])}
                for it in db.get_run_iterations(r["id"])
            ]
            for r in runs
        }
    return build_campaign_report(campaign, runs, meta, trans)

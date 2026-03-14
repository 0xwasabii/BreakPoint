"""
Breakpoint live dashboard — FastAPI + WebSocket backend.
Start with: breakpoint serve
Then open:  http://127.0.0.1:8080
"""

import asyncio
import uuid
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from breakpoint.config import settings
from breakpoint.providers import ProviderError, check_ready
from breakpoint.report.generator import campaign_report_from_db, default_report_path, save_report
from breakpoint.runner import CampaignSpec, load_behaviors, run_campaign
from breakpoint.storage.db import Database

app = FastAPI(title="Breakpoint", version="0.1.0")

_STATIC = Path(__file__).parent / "static"

# scan_id → asyncio.Queue of event dicts
_active_scans: dict[str, asyncio.Queue] = {}


# ── Request / response models ──────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str = "groq/llama-3.3-70b-versatile"
    algorithm: str = "pair"          # pair | tap | crescendo
    goals: int | None = None
    category: str | None = None
    max_iter: int = 20
    budget: int = 200
    campaign_name: str = ""
    attacker: str = ""               # provider/model; blank = configured default
    judge: str = ""
    agent: bool = False
    channel: str = "direct"


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html = (_STATIC / "dashboard.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.get("/api/campaigns")
async def list_campaigns() -> list[dict]:
    db = Database(settings.db_path)
    return [dict(r) for r in db.list_campaigns()]


@app.get("/api/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int) -> dict:
    db = Database(settings.db_path)
    row = db.get_campaign(campaign_id)
    if not row:
        raise HTTPException(status_code=404, detail="Campaign not found")
    runs = db.get_campaign_runs(campaign_id)
    return {"campaign": dict(row), "runs": [dict(r) for r in runs]}


@app.get("/api/campaigns/{campaign_id}/report")
async def get_report(campaign_id: int) -> JSONResponse:
    """The campaign's full JSON report (also written to the reports directory)."""
    db = Database(settings.db_path)
    try:
        report = campaign_report_from_db(db, campaign_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return JSONResponse(report, headers={
        "Content-Disposition": f'attachment; filename="campaign_{campaign_id}.json"'})


@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> dict:
    if problems := check_ready([req.target, req.attacker or settings.attacker_ref, req.judge or settings.judge_ref]):
        raise HTTPException(status_code=400, detail="; ".join(problems))

    scan_id = str(uuid.uuid4())[:8]
    queue: asyncio.Queue = asyncio.Queue()
    _active_scans[scan_id] = queue

    background_tasks.add_task(_run_scan, scan_id, req, queue)
    return {"scan_id": scan_id}


@app.websocket("/ws/{scan_id}")
async def websocket_stream(ws: WebSocket, scan_id: str) -> None:
    await ws.accept()
    queue = _active_scans.get(scan_id)
    if not queue:
        await ws.send_json({"type": "error", "message": f"Scan {scan_id} not found"})
        await ws.close()
        return

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=180)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "ping"})
                continue

            await ws.send_json(event)
            if event.get("type") in ("scan_complete", "error"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        _active_scans.pop(scan_id, None)


# ── Background scan runner ─────────────────────────────────────────────────────

async def _run_scan(scan_id: str, req: ScanRequest, queue: asyncio.Queue) -> None:
    """Run one campaign and stream the runner's events to the websocket queue."""
    db = Database(settings.db_path)

    async def forward(event: dict) -> None:
        if event["type"] == "scan_start":
            event["scan_id"] = scan_id
        await queue.put(event)

    try:
        behaviors = load_behaviors(settings.behaviors_file, req.category, req.goals)
        spec = CampaignSpec(
            target=req.target, behaviors=behaviors, algo=req.algorithm, max_iter=req.max_iter,
            budget=req.budget, name=req.campaign_name, agent=req.agent, channel=req.channel,
            attacker=req.attacker, judge=req.judge,
        )
        outcome = await run_campaign(spec, db, forward)
        report = campaign_report_from_db(db, outcome.campaign_id)
        save_report(report, default_report_path(settings.report_dir, f"campaign_{outcome.campaign_id}"))
    except (ProviderError, ValueError) as exc:
        await queue.put({"type": "error", "message": str(exc)})
    except Exception as exc:  # noqa: BLE001
        await queue.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
    finally:
        _active_scans.pop(scan_id, None)

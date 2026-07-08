"""
Orchestrator service (FastAPI).

Responsibilities:
  - Expose triggers that turn labeled GitHub issues into Devin sessions:
      * POST /webhook  — GitHub 'issues.labeled' delivery. Acts on the issue in
        the payload directly (no re-query — see github_client for the race that
        motivates this), optionally HMAC-verified.
      * POST /trigger  — manual/demo sweep: ingest every currently-labeled issue
        and spawn one session each. Used by scripts/simulate_event.py so the demo
        is reproducible without a public URL.
  - Spawn ONE Devin session per issue, concurrently (the "swarm"), guarded so a
    re-trigger never double-spawns an issue already in flight or done.
  - Persist every session<->issue mapping and an event trail in SQLite.
  - Run a background poller that watches each in-flight session to completion.
    A session is "complete" when a pull request URL appears — that, not
    status_enum, is the reliable done signal.
  - Serve a JSON state feed and the dashboard.
"""

import asyncio
import contextlib
import hashlib
import hmac
import json
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import store
from .devin_client import (
    ATTENTION_STATES,
    TERMINAL_STATES,
    DevinClient,
    extract_pr_url,
    latest_devin_message,
)
from .github_client import (
    TRIGGER_LABEL,
    issue_has_label,
    list_labeled_issues,
    normalize_issue,
)
from .prompts import build_prompt

POLL_INTERVAL_SEC = int(os.environ.get("POLL_INTERVAL_SEC", "30"))
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

app = FastAPI(title="Devin Remediation Orchestrator")
devin: DevinClient | None = None  # lazily built so a missing key fails at run time


def _client() -> DevinClient:
    global devin
    if devin is None:
        devin = DevinClient()
    return devin


# ── core: spawn one session per issue, with a skip-guard ─────────────────────

async def _spawn_for_issue(issue: dict) -> dict:
    """Create a task, spawn a Devin session, attach it. Idempotent per issue.

    Returns a small dict describing the outcome (spawned / skipped / failed) so
    the trigger endpoints can report what happened."""
    existing = store.get_open_task_by_issue(issue["number"])
    if existing:
        # Already queued/running/done — accumulate, don't clobber or duplicate.
        return {
            "issue": issue["number"],
            "status": "skipped",
            "reason": f"already {existing['status']}",
        }

    task_id = store.create_task(
        issue_number=issue["number"],
        issue_title=issue["title"],
        vuln_class=issue.get("vuln_class", ""),
        finding_count=issue.get("finding_count", 0),
    )
    try:
        prompt = build_prompt(issue["number"], issue["title"], issue["url"])
        session = await _client().create_session(
            prompt=prompt,
            title=f"Remediate #{issue['number']}: {issue['title'][:60]}",
        )
        session_id = session["session_id"]
        store.attach_session(task_id, session_id, session.get("url", ""))
        store.log_event(
            "spawned", f"Devin session {session_id}", issue["number"], task_id
        )
        return {"issue": issue["number"], "status": "spawned", "session_id": session_id}
    except Exception as exc:  # noqa: BLE001 — record any failure, never raise into the request
        store.mark_failed(task_id, f"spawn failed: {exc}")
        store.log_event("failed", f"spawn failed: {exc}", issue["number"], task_id)
        return {"issue": issue["number"], "status": "failed", "error": str(exc)}


async def run_bulk_trigger(label: str | None = None) -> dict:
    """Ingest every labeled issue and spawn a session for each, concurrently."""
    issues = await list_labeled_issues(label)
    if not issues:
        return {"spawned": 0, "skipped": 0, "results": []}

    results = await asyncio.gather(*(_spawn_for_issue(it) for it in issues))
    spawned = sum(1 for r in results if r["status"] == "spawned")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    return {"spawned": spawned, "skipped": skipped, "results": results}


# ── background poller — closes the loop ──────────────────────────────────────

async def poll_active_sessions_once() -> None:
    """One sweep across every in-flight session; update status, PR url, reasoning.

    Completion is keyed on the PR url, not status_enum: Devin frequently sits in
    'blocked' after finishing, so a present pull_request is the real done signal."""
    for task in store.get_active_tasks():
        try:
            session = await _client().get_session(task["session_id"])
        except Exception as exc:  # noqa: BLE001
            store.update_status(task["id"], "running", error=f"poll error: {exc}")
            continue

        status_enum = (session.get("status_enum") or "").lower()
        pr_url = extract_pr_url(session)
        message = latest_devin_message(session)

        if pr_url:
            # A PR exists -> shipped. This trumps status_enum by design.
            was_open = bool(task["pr_url"])
            store.update_status(
                task["id"], "complete", pr_url=pr_url, last_message=message
            )
            if not was_open:
                store.log_event("pr_opened", pr_url, task["issue_number"], task["id"])
        elif status_enum in TERMINAL_STATES:
            # Finished but produced no PR — escalate rather than call it success.
            store.update_status(task["id"], "needs_review", last_message=message)
            store.log_event(
                "escalated", "finished without opening a PR",
                task["issue_number"], task["id"],
            )
        elif status_enum in ATTENTION_STATES:
            # Waiting on a human / stuck — surface it, don't silently drop it.
            store.update_status(task["id"], "needs_review", last_message=message)
            store.log_event(
                "escalated", f"session {status_enum} — awaiting input",
                task["issue_number"], task["id"],
            )
        elif message:
            # Still working; capture the latest reasoning for the dashboard.
            store.update_status(task["id"], "running", last_message=message)


async def _poller_loop() -> None:
    while True:
        with contextlib.suppress(Exception):
            await poll_active_sessions_once()
        await asyncio.sleep(POLL_INTERVAL_SEC)


@app.on_event("startup")
async def _startup() -> None:
    store.init_db()
    app.state.poller = asyncio.create_task(_poller_loop())


@app.on_event("shutdown")
async def _shutdown() -> None:
    task = getattr(app.state, "poller", None)
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


# ── signature verification ───────────────────────────────────────────────────

def _verify_signature(raw_body: bytes, header: str | None) -> bool:
    """Verify GitHub's X-Hub-Signature-256. No secret configured => accept
    (unsigned/local mode). Secret configured => require a valid signature."""
    if not WEBHOOK_SECRET:
        return True
    if not header or not header.startswith("sha256="):
        return False
    digest = hmac.new(WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", header)


# ── endpoints ────────────────────────────────────────────────────────────────

@app.post("/webhook")
async def webhook(request: Request) -> JSONResponse:
    """GitHub webhook entrypoint. Fires for a labeled issue carrying the trigger
    label and spawns a session for THAT issue, straight from the payload."""
    raw = await request.body()
    if not _verify_signature(raw, request.headers.get("X-Hub-Signature-256")):
        return JSONResponse({"error": "invalid signature"}, status_code=401)

    payload = json.loads(raw or b"{}")
    action = payload.get("action")
    issue = payload.get("issue")
    added_label = (payload.get("label") or {}).get("name")

    triggered_by_label = added_label == TRIGGER_LABEL or (
        issue is not None and issue_has_label(issue)
    )
    if action in ("labeled", "opened", "reopened") and issue and triggered_by_label:
        result = await _spawn_for_issue(normalize_issue(issue))
        return JSONResponse({"triggered": True, **result})

    return JSONResponse(
        {"triggered": False, "reason": f"ignored: action={action}, label={added_label}"}
    )


@app.post("/trigger")
async def trigger() -> JSONResponse:
    """Manual / scripted bulk trigger (used by simulate_event.py)."""
    return JSONResponse(await run_bulk_trigger())


@app.get("/api/state")
async def api_state() -> JSONResponse:
    """Everything the dashboard needs in one call."""
    return JSONResponse(
        {
            "summary": store.summary(),
            "tasks": store.get_all_tasks(),
            "events": store.recent_events(),
        }
    )


@app.get("/health")
async def health() -> dict:
    return {"ok": True}


# ── dashboard (static index.html + the /api/state feed) ──────────────────────

_DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboard")
if os.path.isdir(_DASHBOARD_DIR):
    app.mount("/", StaticFiles(directory=_DASHBOARD_DIR, html=True), name="dashboard")

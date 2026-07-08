"""
SQLite state store — the single source of truth for the pipeline.

Two tables:
  - tasks:  one row per remediation = one GitHub issue mapped to one Devin
            session. The dashboard reads these; the poller writes status here.
  - events: an append-only audit trail (spawned / pr_opened / escalated /
            failed). This is what lets the dashboard show a live activity feed
            and answer "what has the system actually done?", not just "what's
            the current count?".

Deliberately dependency-free (stdlib sqlite3) so the whole thing runs with no
external database to stand up.
"""

import os
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("DB_PATH", "/data/remediation.db")

# Statuses that mean "this issue is already handled or in progress" — used by the
# skip-guard so re-triggering doesn't spawn a duplicate session. Only 'failed'
# (and absence) makes an issue eligible for a fresh attempt.
OPEN_STATUSES = ("queued", "running", "complete", "needs_review")


@contextmanager
def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_number    INTEGER NOT NULL,
                issue_title     TEXT NOT NULL,
                vuln_class      TEXT,
                finding_count   INTEGER DEFAULT 0,
                session_id      TEXT,
                session_url     TEXT,
                status          TEXT DEFAULT 'queued',
                pr_url          TEXT,
                last_message    TEXT,
                created_at      REAL,
                updated_at      REAL,
                completed_at    REAL,
                error           TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id       INTEGER,
                issue_number  INTEGER,
                kind          TEXT NOT NULL,
                detail        TEXT,
                created_at    REAL
            )
            """
        )


# ── tasks ────────────────────────────────────────────────────────────────────

def create_task(
    issue_number: int,
    issue_title: str,
    vuln_class: str = "",
    finding_count: int = 0,
) -> int:
    now = time.time()
    with _conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO tasks
                (issue_number, issue_title, vuln_class, finding_count,
                 status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'queued', ?, ?)
            """,
            (issue_number, issue_title, vuln_class, finding_count, now, now),
        )
        return cur.lastrowid


def attach_session(task_id: int, session_id: str, session_url: str) -> None:
    now = time.time()
    with _conn() as conn:
        conn.execute(
            """
            UPDATE tasks
               SET session_id = ?, session_url = ?, status = 'running', updated_at = ?
             WHERE id = ?
            """,
            (session_id, session_url, now, task_id),
        )


def update_status(
    task_id: int,
    status: str,
    pr_url: str | None = None,
    error: str | None = None,
    last_message: str | None = None,
) -> None:
    now = time.time()
    completed = now if status in ("complete", "failed", "needs_review") else None
    with _conn() as conn:
        conn.execute(
            """
            UPDATE tasks
               SET status = ?,
                   pr_url = COALESCE(?, pr_url),
                   error = COALESCE(?, error),
                   last_message = COALESCE(?, last_message),
                   updated_at = ?,
                   completed_at = COALESCE(?, completed_at)
             WHERE id = ?
            """,
            (status, pr_url, error, last_message, now, completed, task_id),
        )


def mark_failed(task_id: int, error: str) -> None:
    update_status(task_id, "failed", error=error)


def get_all_tasks() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM tasks ORDER BY issue_number ASC").fetchall()
        return [dict(r) for r in rows]


def get_active_tasks() -> list[dict]:
    """Tasks still in flight — the set the poller works each sweep."""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE status = 'running' AND session_id IS NOT NULL"
        ).fetchall()
        return [dict(r) for r in rows]


def get_open_task_by_issue(issue_number: int) -> dict | None:
    """Latest non-failed task for an issue, if any. Backs the skip-guard: an
    issue that is already queued/running/done is not re-spawned."""
    placeholders = ",".join("?" for _ in OPEN_STATUSES)
    with _conn() as conn:
        row = conn.execute(
            f"""
            SELECT * FROM tasks
             WHERE issue_number = ? AND status IN ({placeholders})
             ORDER BY id DESC LIMIT 1
            """,
            (issue_number, *OPEN_STATUSES),
        ).fetchone()
        return dict(row) if row else None


# ── events (audit trail) ─────────────────────────────────────────────────────

def log_event(
    kind: str,
    detail: str = "",
    issue_number: int | None = None,
    task_id: int | None = None,
) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO events (task_id, issue_number, kind, detail, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (task_id, issue_number, kind, detail, time.time()),
        )


def recent_events(limit: int = 30) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── aggregation for the dashboard header ─────────────────────────────────────

def summary() -> dict:
    """Aggregate counts + throughput for the metric strip."""
    tasks = get_all_tasks()
    by_status: dict[str, int] = {}
    for t in tasks:
        by_status[t["status"]] = by_status.get(t["status"], 0) + 1

    prs = [t for t in tasks if t["pr_url"]]

    # Mean time-to-PR over tasks that produced one and have both timestamps.
    durations = [
        t["completed_at"] - t["created_at"]
        for t in tasks
        if t["pr_url"] and t["completed_at"] and t["created_at"]
    ]
    mean_ttp = sum(durations) / len(durations) if durations else None

    return {
        "total_tasks": len(tasks),
        "by_status": by_status,
        "prs_opened": len(prs),
        "findings_total": sum(t["finding_count"] or 0 for t in tasks),
        "mean_time_to_pr_sec": mean_ttp,
    }

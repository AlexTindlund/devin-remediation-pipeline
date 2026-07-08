"""
Minimal GitHub client. Two jobs:

  - list_labeled_issues()  — the bulk sweep used by the manual/demo trigger.
  - normalize_issue(raw)   — turn a GitHub issue object into the pipeline's
                             internal shape.

``normalize_issue`` is deliberately shared. The webhook handler feeds it the
issue object *straight out of the delivery payload* rather than re-querying the
API, and the bulk sweep feeds it each issue from the list response. Both take the
same path, so a labeled-issue event and a manual sweep produce identical rows.

Why the webhook uses the payload issue directly: re-querying the API right after
a ``labeled`` event hit a propagation-lag race — a just-labeled issue could be
missing from the list response because GitHub's read side had not caught up yet.
The payload is already authoritative for the issue that triggered the event, so
we use it.

Public REST API. A token is optional for public repos but recommended to avoid
the 60-req/hr unauthenticated limit — set GITHUB_TOKEN if you have one.
"""

import os
import re

import httpx

GITHUB_API = "https://api.github.com"
REPO = os.environ.get("GITHUB_REPO", "AlexTindlund/superset")
TRIGGER_LABEL = os.environ.get("TRIGGER_LABEL", "Tasks for devin")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def normalize_issue(raw: dict) -> dict:
    """Project a GitHub issue object (API item or webhook payload) onto the
    fields the orchestrator needs."""
    title = raw.get("title") or ""
    return {
        "number": raw["number"],
        "title": title,
        "url": raw.get("html_url") or raw.get("url") or "",
        "body": raw.get("body") or "",
        "vuln_class": _infer_vuln_class(title),
        "finding_count": _infer_finding_count(title),
    }


def issue_has_label(raw: dict, label: str | None = None) -> bool:
    """True if the raw issue object carries the trigger label. Works on both the
    webhook payload shape and the REST list shape (both use ``labels: [{name}]``)."""
    label = label or TRIGGER_LABEL
    names = {lbl.get("name") for lbl in (raw.get("labels") or []) if isinstance(lbl, dict)}
    return label in names


async def list_labeled_issues(label: str | None = None) -> list[dict]:
    """Return open issues carrying the trigger label, normalized. Used by the
    bulk/demo trigger to light up the whole board at once."""
    label = label or TRIGGER_LABEL
    params = {"labels": label, "state": "open", "per_page": 100}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{GITHUB_API}/repos/{REPO}/issues", headers=_headers(), params=params
        )
        resp.raise_for_status()
        raw = resp.json()

    # The issues endpoint also returns PRs; skip anything that is a PR.
    return [normalize_issue(it) for it in raw if "pull_request" not in it]


def _infer_vuln_class(title: str) -> str:
    """Cheap heuristic to tag each row in the dashboard by vulnerability family."""
    t = title.lower()
    if "md5" in t:
        return "Insecure hashing (MD5)"
    if "sqlalchemy" in t or "text()" in t:
        return "Raw SQL (SQLAlchemy text)"
    if "subprocess" in t or "shell=true" in t:
        return "Command injection (subprocess)"
    if "yaml" in t:
        return "Unsafe deserialization (YAML)"
    if "sql lab" in t or "cursor" in t:
        return "SQL injection (cursor execute)"
    if "credential" in t or "token" in t or "logging" in t:
        return "Credential leakage (logging)"
    return "Other"


def _infer_finding_count(title: str) -> int:
    """Issues are titled like '... (18 instances)' — pull that number out for the
    throughput denominator. Falls back to 0 when absent."""
    m = re.search(r"\((\d+)\s+(?:instance|occurrence|location|finding)", title.lower())
    return int(m.group(1)) if m else 0

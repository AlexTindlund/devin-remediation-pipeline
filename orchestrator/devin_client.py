"""
Thin async client for the Devin v1 API (https://api.devin.ai/v1).

Only two calls matter for this pipeline:
  - create_session(prompt) -> spawn a Devin run, return its id + url
  - get_session(session_id) -> read status, pull_request, messages

Auth is a bearer token using a *personal* API key (``apk_user_...``). The v1 API
is organization-scoped by the key itself, so no org id goes in the URL.

Two lessons are baked into the helpers below, learned the hard way against the
live API:

1. ``status_enum`` is NOT a reliable "done" signal. Sessions routinely sit in a
   ``blocked`` state after the work is finished. The dependable completion
   signal is the *presence of a pull request URL* in the payload — when that
   appears, Devin has shipped. ``extract_pr_url`` is therefore the heart of the
   poller, not the status field.
2. ``structured_output`` comes back null in practice. Devin's actual reasoning
   lives in the ``messages`` array as ``devin_message`` entries;
   ``latest_devin_message`` pulls the most recent one so the dashboard can show
   *why* Devin did what it did.
"""

import os
import re

import httpx

DEVIN_API_BASE = os.environ.get("DEVIN_API_BASE", "https://api.devin.ai/v1")
DEVIN_API_KEY = os.environ.get("DEVIN_API_KEY", "")

# Per-session ACU ceiling. A single-class remediation is a small, bounded task;
# this is a guardrail so a runaway session cannot burn the whole balance.
DEFAULT_MAX_ACU = int(os.environ.get("DEVIN_MAX_ACU", "10"))


class DevinClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key or DEVIN_API_KEY
        self.base_url = (base_url or DEVIN_API_BASE).rstrip("/")
        if not self.api_key:
            raise RuntimeError(
                "DEVIN_API_KEY is not set. Put it in your .env (or export it) "
                "before starting the orchestrator."
            )

    @property
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def create_session(
        self, prompt: str, title: str | None = None, max_acu: int | None = None
    ) -> dict:
        """Spawn a Devin session. Returns the raw payload ({session_id, url, ...})."""
        payload: dict = {
            "prompt": prompt,
            "max_acu_limit": max_acu or DEFAULT_MAX_ACU,
        }
        if title:
            payload["title"] = title

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{self.base_url}/sessions", headers=self._headers, json=payload
            )
            resp.raise_for_status()
            return resp.json()

    async def get_session(self, session_id: str, timeout: float = 15.0) -> dict:
        """Read current session state: status, pull_request, messages, timestamps.

        Intentionally short timeout — this runs on a loop across every active
        session, so one slow/unreachable session must not stall the sweep.
        """
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{self.base_url}/session/{session_id}", headers=self._headers
            )
            resp.raise_for_status()
            return resp.json()


# Terminal status_enum values — once reached, there is nothing more to poll for.
TERMINAL_STATES = {"finished", "expired", "stopped"}
# "blocked"/"suspended" mean Devin is waiting on something (often human input).
# Surfaced as needs-review rather than silently treated as success or failure.
ATTENTION_STATES = {"blocked", "suspended"}


def extract_pr_url(session: dict) -> str | None:
    """Pull the PR url out of a session payload, tolerating shape differences.

    This is the pipeline's real completion signal (see module docstring)."""
    pr = session.get("pull_request")
    if not pr:
        return None
    if isinstance(pr, str):
        return pr or None
    if isinstance(pr, dict):
        # Observed key is 'url'; fall back across plausible alternates.
        return pr.get("url") or pr.get("html_url") or pr.get("pr_url")
    return None


_REF_SNIPPET = re.compile(
    r"<ref_snippet\b[^>]*?"
    r'(?:file|path)="(?P<file>[^"]+)"[^>]*?'
    r'(?:lines|line)="(?P<lines>[^"]+)"[^>]*?>.*?</ref_snippet>',
    re.DOTALL,
)


def _collapse_ref_snippets(text: str) -> str:
    """Devin embeds <ref_snippet file=... lines=...>...</ref_snippet> blocks in
    its messages. Collapse each to a compact ``file:lines`` for display."""
    text = _REF_SNIPPET.sub(lambda m: f"{m.group('file')}:{m.group('lines')}", text)
    # Strip any residual/oddly-shaped ref_snippet tags we could not parse.
    text = re.sub(r"</?ref_snippet\b[^>]*>", "", text)
    return text.strip()


def latest_devin_message(session: dict, max_len: int = 280) -> str | None:
    """Return the most recent ``devin_message`` text, ref-snippets collapsed.

    Devin's reasoning lives here (``structured_output`` is null in practice), so
    this is what lets the dashboard surface *why* a session did what it did."""
    messages = session.get("messages") or []
    for msg in reversed(messages):
        if msg.get("type") == "devin_message":
            body = _collapse_ref_snippets(msg.get("message") or "")
            if not body:
                continue
            return body if len(body) <= max_len else body[: max_len - 1].rstrip() + "…"
    return None

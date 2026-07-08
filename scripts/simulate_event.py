#!/usr/bin/env python3
"""
simulate_event — drive the pipeline without a public webhook URL.

Two modes, both hitting a running orchestrator (docker compose up):

  Bulk (default): POST /trigger, which ingests every issue currently labeled
  for Devin and spawns one session each. This is the "light up the whole board"
  demo button.

      python scripts/simulate_event.py

  Webhook: replay a single, correctly-signed ``issues.labeled`` delivery to
  /webhook — byte-for-byte the shape GitHub sends, so it exercises the real
  event path (including HMAC verification when WEBHOOK_SECRET is set).

      python scripts/simulate_event.py --webhook \
          --issue 7 --title "Replace MD5 hashing (5 instances)" \
          --issue-url https://github.com/AlexTindlund/superset/issues/7

Dependency-free (stdlib only) so it runs anywhere Python does.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request

TRIGGER_LABEL = os.environ.get("TRIGGER_LABEL", "Tasks for devin")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")


def _post(url: str, path: str, body: bytes, headers: dict) -> dict:
    req = urllib.request.Request(
        url.rstrip("/") + path, data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Could not reach orchestrator at {url} — is it running?\n  {e}", file=sys.stderr)
        sys.exit(1)


def bulk(url: str) -> None:
    print(f"→ POST {url}/trigger  (ingest every labeled issue, spawn a session each)")
    result = _post(url, "/trigger", b"{}", {"Content-Type": "application/json"})
    print(json.dumps(result, indent=2))
    n = result.get("spawned", 0)
    if n:
        print(f"\n✓ Spawned {n} Devin session(s). Watch the dashboard at {url}")
    elif result.get("skipped"):
        print(f"\n• Nothing new — {result['skipped']} issue(s) already in flight or done.")
    else:
        print("\n! No labeled issues found. Check the label and repo in .env.")


def webhook(url: str, issue: int, title: str, issue_url: str) -> None:
    # The exact envelope GitHub sends for an issues.labeled event (trimmed to the
    # fields the orchestrator reads).
    payload = {
        "action": "labeled",
        "label": {"name": TRIGGER_LABEL},
        "issue": {
            "number": issue,
            "title": title,
            "html_url": issue_url,
            "labels": [{"name": TRIGGER_LABEL}],
        },
    }
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", "X-GitHub-Event": "issues"}
    if WEBHOOK_SECRET:
        sig = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Hub-Signature-256"] = f"sha256={sig}"

    print(f"→ POST {url}/webhook  (signed issues.labeled for #{issue})")
    result = _post(url, "/webhook", body, headers)
    print(json.dumps(result, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description="Fire the remediation pipeline.")
    ap.add_argument("--url", default="http://localhost:8000", help="Orchestrator base URL")
    ap.add_argument("--webhook", action="store_true", help="Replay a single signed webhook instead of a bulk trigger")
    ap.add_argument("--issue", type=int, help="Issue number (webhook mode)")
    ap.add_argument("--title", default="(labeled issue)", help="Issue title (webhook mode)")
    ap.add_argument("--issue-url", default="", help="Issue html_url (webhook mode)")
    args = ap.parse_args()

    if args.webhook:
        if args.issue is None:
            ap.error("--webhook requires --issue N")
        webhook(args.url, args.issue, args.title, args.issue_url)
    else:
        bulk(args.url)


if __name__ == "__main__":
    main()

# Autonomous Security Remediation with Devin

An event-driven pipeline that turns static-analysis findings into reviewed pull
requests **without a human in the loop**. A scan produces findings, findings
become GitHub issues, and each issue spawns a Devin session that triages the
finding in context, fixes what's real, justifies what isn't, and opens a PR.

Target repository: a fork of Apache Superset,
[`AlexTindlund/superset`](https://github.com/AlexTindlund/superset).

---

## The idea: bounded autonomy, not mechanical patching

Static scanners are cheap, fast, and noisy — they report *patterns*, not
confirmed vulnerabilities. Finding candidates was never the expensive part. The
expensive part is the per-finding triage: *is this actually exploitable here?
what's the correct fix? does it break anything?* That judgment work is why
security backlogs sit untouched for months.

This system delegates exactly that judgment to Devin. The prompt for every issue
is a **triage mandate**, not a find-and-replace order:

> For each flagged location, read enough surrounding code to decide whether it's
> a genuine risk or safe by design. Fix the real ones. For the safe ones, leave
> them and explain why. Open one PR categorizing every location as *fixed (real
> risk)* or *left as-is (safe, with reason)*.

The payoff shows up in the PR Devin opens for the 18 `SQLAlchemy text()`
findings: it parameterizes the few that interpolate user input and leaves the
static/migration SQL alone, with a reason for each. **A linter can't make that
call — that's the argument for an autonomous agent in this loop.**

---

## Architecture

```
GitHub issues (labeled "Tasks for devin")
        │  trigger:  webhook (real)   ──or──   scripts/simulate_event.py (demo)
        ▼
┌────────────────────────────────────────────────────────┐
│  Orchestrator (FastAPI)                                 │
│   1. ingest labeled issue(s)                            │
│   2. spawn ONE Devin session per issue, concurrently    │
│      (asyncio.gather) — skip-guarded so re-triggers      │
│      never double-spawn                                  │
│   3. persist issue↔session + an event trail in SQLite   │
│   4. background poller watches each session to a         │
│      terminal state and captures the PR url             │
└────────────────────────────────────────────────────────┘
        │                              │
        ▼                              ▼
   SQLite (state + events)     Dashboard (live)
                               metrics · pipeline · activity feed
```

Design decisions, and why:

- **One issue = one vulnerability class = one session.** The unit of work is a
  class of finding plus a judgment mandate. Sessions are independent, so they
  run in parallel — the "swarm." Pipeline *stages* (spawn → poll → verify →
  report) live in the orchestration code, not in the issues.
- **The trigger is decoupled from the logic.** A GitHub webhook and the
  `simulate_event` script both drive the same spawn path, so the demo is fully
  reproducible without exposing a public URL.
- **The webhook acts on the payload issue directly.** Re-querying GitHub right
  after a `labeled` event hit a propagation-lag race — a just-labeled issue
  could be missing from the list response. The delivery payload is already
  authoritative, so we use it (and verify its HMAC signature when a secret is
  set).
- **A PR url is the completion signal — not `status_enum`.** Devin routinely
  sits in `blocked` after finishing the work. Keying completion on the presence
  of a pull request is what makes the poller reliable; sessions that finish
  without a PR, or genuinely stall, are surfaced as `needs_review` rather than
  silently dropped.
- **State accumulates; it isn't clobbered.** A skip-guard means re-triggering
  adds newly-labeled work without disturbing sessions already in flight or done.
- **Source-agnostic by design.** Semgrep is the trigger here, but the pipeline
  only consumes *findings → issues*. Snyk, CodeQL, Dependabot, or pentest output
  can feed the same machinery.

---

## Repository layout

```
orchestrator/
  app.py            FastAPI: /webhook, /trigger, /api/state, poller
  devin_client.py   async Devin v1 client (create + get session, PR/msg extract)
  github_client.py  issue ingestion + normalize (shared by webhook and sweep)
  prompts.py        the bounded-autonomy prompt template
  store.py          SQLite state + event trail (single source of truth)
dashboard/
  index.html        live operations console (polls /api/state)
scripts/
  simulate_event.py reproducible trigger (bulk, or a signed single webhook)
Dockerfile
docker-compose.yml
```

---

## Setup

**Prerequisites:** Docker, a Devin account with API access, and a Devin personal
API key (`apk_user_…`). Devin needs GitHub access to the fork so it can push
branches and open PRs (Devin app → Settings → Connections → GitHub).

1. **Configure**

   ```bash
   cp .env.example .env
   # edit .env: set DEVIN_API_KEY=apk_user_...
   ```

   `.env` is gitignored — never commit your key.

2. **Run**

   ```bash
   docker compose up --build
   ```

   The orchestrator and dashboard come up on <http://localhost:8000>.

3. **Trigger the pipeline** (second terminal)

   ```bash
   python scripts/simulate_event.py
   ```

   This posts to `/trigger`, which ingests every issue labeled `Tasks for devin`
   in the fork and spawns a Devin session for each — in parallel. To exercise the
   real GitHub event path instead, replay a signed delivery:

   ```bash
   python scripts/simulate_event.py --webhook --issue 7 \
       --title "Replace MD5 hashing (5 instances)" \
       --issue-url https://github.com/AlexTindlund/superset/issues/7
   ```

   For a genuinely live trigger, point a GitHub webhook (issues events) at
   `/webhook` via a tunnel such as ngrok and label an issue.

4. **Watch it work**

   Open <http://localhost:8000>. Each issue moves *queued → in flight → PR
   opened* (or *needs review*), with live links to the Devin session and the
   resulting PR, Devin's own reasoning inline, and a streaming activity feed.

---

## Observability — "how would a leader know it's working?"

The dashboard answers this directly, at a glance:

- **Sessions** ingested and **In flight** right now
- **PRs opened** — remediations actually delivered
- **Needs review** — sessions that escalated instead of shipping a questionable fix
- **Findings** — total scanner hits across all issues (the throughput denominator)
- **Mean time → PR** — how long a remediation takes, end to end
- **Activity feed** — an append-only event trail (spawned / PR opened /
  escalated / failed), so the answer isn't just *what's the count now* but
  *what has the system done*

Every row links to the live Devin session and the PR it produced, so a reviewer
can drill from the summary straight into Devin's reasoning and the diff. The same
data is available as JSON at `GET /api/state` for wiring into other tools.

Every metric is *measured* — sessions spawned, PRs opened, wall-clock to PR.
There is deliberately no "hours saved" estimate; a number you can't measure is a
number a skeptical reviewer is right to discard.

---

## Configuration

All via environment variables (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `DEVIN_API_KEY` | — (required) | Devin personal API key (`apk_user_…`) |
| `GITHUB_REPO` | `AlexTindlund/superset` | Fork the pipeline remediates |
| `TRIGGER_LABEL` | `Tasks for devin` | Label that marks issues for Devin |
| `GITHUB_TOKEN` | — (optional) | Lifts GitHub's 60/hr unauthenticated limit |
| `WEBHOOK_SECRET` | — (optional) | Enables `X-Hub-Signature-256` verification |
| `POLL_INTERVAL_SEC` | `30` | How often the poller checks each session |
| `DEVIN_MAX_ACU` | `10` | Per-session ACU ceiling (cost guardrail) |

---

## Extending this in a real engagement

- **Wire to the customer's existing scanner** (Snyk/CodeQL/Dependabot) as the
  trigger — the issue-ingestion contract is the only integration point.
- **Gate on CI**: have the poller read the PR's check status and only mark a task
  *complete* when tests pass, escalating red builds to `needs_review`.
- **Auto-create issues** from raw scan output so no human touches the queue — the
  demo creates them by hand only for reproducibility on camera.
- **Severity-aware concurrency**: prioritize and rate-limit sessions by finding
  severity so critical fixes land first.

---

## Scope note

The take-home brief scoped this at 2–3 hours and prized a working end-to-end demo
over polish. This build stays within that spirit: a single Docker command brings
up a real, event-driven pipeline that spawns live Devin sessions and reports
measured outcomes. Everything above the core loop (signature verification, the
event trail, the skip-guard) is small, deliberate hardening — not scope creep.

"""
Prompt construction for remediation sessions.

This is where the "bounded autonomy" thesis is encoded. The mandate does NOT say
"fix every finding." It tells Devin to triage each flagged location in context,
fix the genuine risks, justify anything it deliberately leaves alone, and report
its reasoning in the PR.

That distinction — judgment over mechanical patching — is the whole argument for
putting an autonomous agent in this loop instead of an auto-fixer. A linter can
flag `md5(...)`; it cannot decide that one call is a cache key (safe) and another
is signing a token (must fix). Devin can, and is told to.

The mandate is identical across every issue on purpose: behaviour stays
consistent, and the *orchestration* — not per-issue prompt tweaking — is what
scales the system.
"""

import os

REPO = os.environ.get("GITHUB_REPO", "AlexTindlund/superset")

BOUNDED_AUTONOMY_MANDATE = """
You are remediating a security finding in the repository {repo}.

Read GitHub issue #{issue_number} ("{issue_title}") in full:
{issue_url}

This is a TRIAGE task, not a mechanical find-and-replace. A static scanner
flagged these locations, but scanners report *patterns*, not confirmed
vulnerabilities. Apply engineering judgment:

1. For each flagged location, read enough of the surrounding code to decide
   whether the pattern is genuinely exploitable IN THIS CONTEXT, or safe by
   design (e.g. operating on trusted internal input, or intended behaviour).
2. Fix the locations that represent real risk. Use the remediation guidance in
   the issue, adapting it to the actual code.
3. For locations that are safe in context, DO NOT change them. Instead, record a
   one-line justification for each so a reviewer can audit the decision.
4. Run the relevant tests to confirm your changes don't break anything.
5. Open a SINGLE pull request that references this issue and, in its
   description, categorizes EVERY flagged location as either
   "fixed (real risk)" or "left as-is (safe — reason)", followed by a short
   summary of what you changed and why.

Constraints:
- Work on a new branch off the default branch. Do not touch unrelated files,
  other issues, or other branches.
- If you cannot make a confident call on a location, leave it unchanged and say
  so explicitly in the PR rather than guessing.
""".strip()


def build_prompt(issue_number: int, issue_title: str, issue_url: str) -> str:
    return BOUNDED_AUTONOMY_MANDATE.format(
        repo=REPO,
        issue_number=issue_number,
        issue_title=issue_title,
        issue_url=issue_url,
    )

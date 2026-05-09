---
name: Security Authentication Feature Audit — May 2026
description: Audit findings for feature/security-authentication branch, dashboard session auth addition. Key blockers and conditions for future reference.
type: project
---

The `feature/security-authentication` branch adds session-based dashboard authentication (M3) using `itsdangerous` SessionMiddleware, bcrypt password hashing, and a clean `LoginRequiredException` redirect pattern.

**Why:** Dashboard was previously unauthenticated. Auth was a known gap. This branch closes it.

**Audit status (2026-05-09):** NO-GO at time of audit due to:
1. Dirty working tree — `ARCHITECTURE_DECISIONS.md`, `soar-simulation-engineering.md` (corrected spelling), and updated agent definitions are not committed in HEAD (`ab10f0f`).
2. No Snyk scan result provided to the auditor in this session (commit message claims prior scan, but this does not satisfy the auditor gate).

**Conditions to reach GO:**
- Commit all outstanding files into the branch before merge.
- Provide Snyk scan output to auditor in the review session.
- Add login rate limiting (no `slowapi` or equivalent is present).
- Document or remove `network: host` on Docker build context in `docker-compose.yml`.
- Set `https_only=True` in `SessionMiddleware` for any production deployment.
- Note: `api/.venv` is already tracked in git (pre-existing, not introduced by this branch) — hygiene cleanup recommended separately.

**How to apply:** When this branch is re-submitted for audit, verify the working tree is clean, the untracked files are committed, and a fresh Snyk scan result is attached.

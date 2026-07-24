# codesight-mcp — Risk Register & Mitigation Playbook

Format: mechanism → countermeasure (already shipped in the spec) → kill signal (a metric with a number). Kill signal = stop and escalate to Cevin + advanced-model review, do not push through.

## R1 — Executing agent weakens the security core while "fixing" something
- **Mechanism:** Opus refactors `core/validation.py` / `index_store.py` read paths for a milestone task (e.g. scan_security I/O in M3, INDEX_VERSION 3 in M7) and drops a validation step, an `O_NOFOLLOW`, or a fail-closed branch it doesn't understand.
- **Countermeasure:** MASTER_SPEC convention 3 (monotonic security) + CLAUDE.md binding rule; SPEC_4 §4 requires `test_symlinked_file_still_refused`; SPEC_5 §3.4 requires enum/float validation on new index fields; the 400+ existing security/fuzz tests run in `make check`.
- **Kill signal:** any commit where `pytest tests/security tests/fuzz` count of passing tests decreases below the pre-commit baseline (currently within the 2578 collected) — even by 1.

## R2 — Doc-count gate drifts again because a milestone forgot the atomic ritual
- **Mechanism:** M9 adds 2 ops (34→36) or any milestone changes tests; docs/badges/contract go stale exactly as they did before the audit (gate failing live on `main`).
- **Countermeasure:** `make stamp` --write mode (SPEC_1 §6), pre-commit hook (SPEC_2 §6.6), counts inside `make check`, guard test `test_ops_count_matches_contract`, atomic-commit rule (MASTER_SPEC convention 8), HUMAN branch protection (D19).
- **Kill signal:** `scripts/check_counts.py` exit 1 on `main` at any time = hard stop; > 0 occurrences after M0 means the process failed, not the script.

## R3 — INDEX_VERSION 3 migration corrupts or orphans live indexes
- **Mechanism:** M7 changes edge schema; a bug in v2-read compat or in `_sanitize_loaded_symbols` extensions makes 322 production indexes unreadable or silently drops edges; or a crafted v3 index exploits the new fields.
- **Countermeasure:** SPEC_5 §3.4: v2 read-compat mandated with defaults; forward-version rejection unchanged; new fields validated against closed enums; recall-non-regression rule (§3.3 "never drop an edge"); atomic two-phase write machinery untouched.
- **Kill signal:** any v2 fixture index failing to load in the M7 test run (target: 0 failures), or resolved-graph recall < 0.80 on the labeled corpus.

## R4 — Wrapper generation ships a trust-boundary hole
- **Mechanism:** `generate_wrapper.py` (M4) mis-renders `path_class` loops or misses `untrusted` framing for one op; the generated TS silently passes a host path through, weaker than the hand-written codesight-plugin it replaces.
- **Countermeasure:** SPEC_2 §4: generation driven solely by contract `path_class`/`untrusted` fields; `test_untrusted_ops_get_framing` + `test_all_operations_present_in_wrapper`; the Python server's own per-tool validation remains behind the wrapper (defense in depth — the wrapper was never the only wall).
- **Kill signal:** any contract op whose generated code lacks its classified validation/framing block (test asserts 36/36 by M9; the number is exact, not approximate).

## R5 — Resolved call graph precision is a mirage (heuristics relabeled as facts)
- **Mechanism:** M7 resolution mislabels name-based guesses as `resolution: "resolved"`; M11 SAST mode then emits "confirmed_flow" on garbage chains — the project's honesty brand (audit praised self-labeling) is damaged.
- **Countermeasure:** labeled ground-truth corpus written BEFORE implementation (SPEC_5 §4); precision ≥ 0.90 asserted in CI; two-value confidence enum (no gradations to fudge); SAST default stays heuristic until Gate G4(b); honesty wording rule (SPEC_6 §4).
- **Kill signal:** precision test < 0.90, or ≥ 1 `confirmed_flow` finding on the clean SAST fixture.

## R6 — pip-audit gating blocks all work (or gets rubber-stamped)
- **Mechanism:** M3 makes audit blocking; a new unfixable transitive CVE lands and every PR is red → agent (or human) starts adding blanket ignores, recreating the 36-vuln backlog with extra steps.
- **Countermeasure:** ignore file requires per-ID reason + revisit-by date; expired dates fail the run (SPEC_4 §3.2); weekly unfiltered schedule run keeps the true backlog visible; audit excluded from `make check` so local work never blocks offline.
- **Kill signal:** ignore file > 15 entries, or any entry older than 90 days past its revisit-by.

## R7 — PyPI publish path stalls on human steps and Stage 2 silently dies
- **Mechanism:** trusted-publisher binding and branch protection are HUMAN tasks; if Cevin doesn't do them, M5 "completes" without the gate ever being testable, and the squat window stays open.
- **Countermeasure:** HUMAN items are explicit checklist lines in `docs/MILESTONE.md` (SPEC_7); placeholder registration front-loaded to M3 (SPEC_4 §5); Gate G2 fallback pre-named (pipx-from-git).
- **Kill signal:** 14 days after M5 code-complete with the PyPI name still unregistered → execute the fallback, don't wait.

## R8 — Federated/semantic features ship but nobody uses them (roadmap vanity)
- **Mechanism:** M9/M10 land, usage stays zero, and maintenance burden (2 extra ops in contract/wrapper/docs, an OpenAI dep) accrues forever.
- **Countermeasure:** Gate G4(a) measures actual invocation via the repo's own `get-usage-stats`; fallback pre-named: freeze as experimental, stop investing.
- **Kill signal:** < 2 distinct weeks of federated/semantic usage within 30 days of M10 exit.

## R9 — Reindex sweep hammers the machine or reindexes the wrong thing
- **Mechanism:** `reindex-stale` (M6) walks 322 sidecars and reindexes en masse; a path that moved or a repo now outside allowed roots gets reindexed anyway, or AI summaries burn tokens in bulk.
- **Countermeasure:** SPEC_5 §1.1: `--max-repos 25` default, `--no-ai` default on, allowed-roots recheck per repo, GitHub-origin skip, dry-run mode, all through the existing validated index path + rate limiter.
- **Kill signal:** a single sweep run > 15 minutes wall or > 25 repos touched.

## R10 — Context drift across many Opus sessions (the meta-risk)
- **Mechanism:** 12 milestones × multiple sessions; an agent loads stale context, reopens a [DECISION], or "improves" conventions; drift becomes precedent exactly as the skill warns.
- **Countermeasure:** reading lists per milestone (MASTER_SPEC), CLAUDE.md authority order + [DECISION] finality, guard tests as tripwires, commit style `M<n>.<i>` making per-milestone diffs auditable, EXECUTION_PROMPT.md session ritual, periodic advanced-model drift audit at every stage gate.
- **Kill signal:** any commit not matching `^M\d+\.\d+: ` on `main`, or 2 consecutive sessions ending without `make check` green.

---

## Mitigation playbook

**Standing metrics (check at every session start — 60 seconds):**
1. `make check` exit code (must be 0 at session start; if red, fixing it IS the session).
2. `scripts/check_counts.py` output line (`counts OK: ops=… langs=… tests=…`).
3. `git log --oneline -5` — commit-style conformance (R10).
4. During Stage 3+: staleness ratio from `list-repos` (G3(a) target < 20%).

**Actions and timing:**
| Trigger | Action | Owner | When |
|---|---|---|---|
| Any kill signal above | Stop the milestone; write a `docs/MILESTONE.md` "Incident" note; escalate to Cevin | Executing agent | Immediately, before further commits |
| Stage gate reached | Drift audit: advanced model rereads CLAUDE.md + current SPEC part vs. actual diff since last gate; gate-evidence review | Cevin + advanced model | At G1–G4 |
| Security-adjacent diff (validation/limits/index read paths) | Run full `pytest tests/security tests/fuzz` locally even though `make check` includes it; paste count into commit body | Executing agent | Same session |
| Cross-model review returns findings | Triage with Cevin; accepted → spec amendment; rejected → one-line rationale in `docs/REVIEW_LOG.md` | Cevin | Before M4 starts (packet already prepared) |
| HUMAN item pending > 14 days | Execute the named fallback | Cevin | R7 rule |

**Priority order under resource pressure (if time/attention runs short, protect in this order):**
1. R1 (security monotonicity) — the product's identity; never trade away.
2. R2 (counts/CI truth) — the credibility fix the audit was about.
3. R3 (index migration safety) — 322 live indexes are user data.
4. R5 (honesty of resolution/SAST labels).
5. R10 (process drift).
6. R4, R6, R9 (mechanized by tests once shipped).
7. R7, R8 (roadmap value — explicitly sacrificable; fallbacks exist and the single-repo core remains whole without them).

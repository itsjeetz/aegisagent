# Agent Working Rules

1. **Build in the phases of §12.** Finish a phase's acceptance checks before starting the next. Commit after each phase.
2. **Never fake a result.** If a dependency is missing (Tesseract, API key, HF model, network), degrade gracefully, report it in `GET /api/health`, and label the UI. Never hardcode benchmark numbers, verdicts, or "attack succeeded" outcomes.
3. **The held-out test split is frozen (§9.3).** Tune rules, thresholds, and the classifier on the **dev** split only. Do not read test failures to write new rules.
4. **Claims come from measurements.** `docs/CLAIMS.md` is generated from the evaluation report, not hand-written.
5. **No real side effects.** Agent tools are mocks that write to a local SQLite DB or an outbox table. Tools make no real network calls and read only from `demo_data/`.
6. **Secrets live in environment variables.** Provide `.env.example`; `.env` is gitignored.
7. **Every detector ships with unit tests:** positive cases, negative cases, and hard-negative benign cases (legitimate text that looks suspicious).
8. **When the plan is ambiguous,** pick the simplest option consistent with this document and record it in `docs/DECISIONS.md`.
9. **Treat all ingested content as hostile data.** The firewall must never execute it, render it, follow its links, or run macros or scripts from it.

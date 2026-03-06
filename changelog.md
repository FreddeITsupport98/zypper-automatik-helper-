# Changelog

## Unreleased
- Uninstall (`--uninstall-zypper`): now removes the Fish sudo wrapper file `~/.config/fish/conf.d/sudo-handler.fish` and includes it in dry-run output.
- Verify service: added adaptive low-impact mode for repeated background verification failures (fail-streak tracking + heavy-check cooldown state persisted in `verify-smart-state.env`).
- Verify service: expensive deep checks can now be deferred during cooldown windows to reduce CPU/IO pressure when failures repeat.
- Config/WebUI/validation: added `VERIFY_LOW_IMPACT_ENABLED`, `VERIFY_LOW_IMPACT_FAIL_STREAK`, `VERIFY_LOW_IMPACT_HEAVY_CHECK_COOLDOWN_MINUTES`, and `VERIFY_LOW_IMPACT_FOLLOWUP_DELAY_MINUTES`.
- Default verification cadence tuned: `VERIFY_TIMER_INTERVAL_MINUTES` now defaults to `15` (from `5`) for lower background impact.
- Default verification cadence retuned: `VERIFY_TIMER_INTERVAL_MINUTES` now defaults to `30` (from `15`) in the current config template/schema and validation fallback path.
- Verify/self-check/install notifier syntax validation now uses a read-only-safe AST parser helper (`python_ast_syntax_check`) to avoid false failures caused by pycache writes under hardened mounts.
- WebUI Managers (Server/SQLite): quick-action entries now show explicit AI launch markers (`[AI launched]`) with persisted source metadata (`ai_triggered`, `ai_source`).
- Quick action API/recovery/history: AI launch metadata is now carried through quick start/status/history flows so reopen/resume paths keep the AI marker.
- AI Smart Report (`/api/ai/smart-report`) now emits deterministic error→repair mapping data (`repair_plan`) with selected action, confidence, evidence, and confirmation requirements.
- AI Smart Report now supports optional safe initiation (`initiate_repair=true`) for allowlisted no-confirm quick actions and reports blocked reasons when confirmation is required.
- Quick action background spawning is now centralized in a shared WebUI API helper and reused by both `/api/quick/start` and AI smart-report initiation paths, reducing duplication and keeping status/log/history behavior aligned.
- Contract tests were strengthened to assert shared-launcher routing for `/api/quick/start` and AI smart-report initiation, while preserving quick-action history payload constraints.
- Snapper WebUI API hardening: background jobs now run with lower-priority scheduling (`Nice=19`, idle I/O class) plus low-impact command wrappers (`ionice -c3` / `nice -n 19` when available).
- Snapper direct run API (`/api/snapper/run`) now also applies low-impact command wrappers to reduce foreground IO/CPU contention.
- Snapper cleanup WebUI confirmation now includes an explicit force-low-space override toggle (`force_low_space`) that maps to helper env `ZNH_SNAP_CLEANUP_FORCE_LOW_SPACE=1`.
- Snapper direct run API (`/api/snapper/run`) now propagates cleanup `force_low_space` into helper environment (in addition to non-interactive confirmation flow).
- Snapper cleanup now supports configurable pacing between heavy phases and force-prune delete batches (`SNAP_CLEANUP_PHASE_PACING_SECONDS`) to reduce burst IO/CPU load.
- Snapper start API coalescing improved: repeated same-action requests now reuse an existing running Snapper `job_id` instead of launching duplicate jobs.
- Snapper start API now performs best-effort stale artifact garbage collection (old status/log/script files) and returns `artifact_gc` metadata to callers.
- Snapper WebUI now uses `GET /api/snapper/preflight?action=cleanup` before cleanup runs to show free-space/hysteresis/busy risk hints and force-override context.
- Snapper cleanup preflight can detect existing running jobs/zypp lock states, and the WebUI reopens the active Snapper overlay instead of launching duplicate cleanup attempts.
- Snapper job history now persists cleanup low-space guard telemetry (`force_low_space`, guard reason/state, hysteresis flags, free/critical/high MB) and exposes it via history list/detail APIs.
- History upsert runtime guard now enforces low-space telemetry as snapper-only metadata and strips those keys for non-snapper job types.
- Added focused contract test `test_snapper_start_contract.py` to assert `/api/snapper/start` success responses include `job_id`, `coalesced`, `artifact_gc`, and `preflight`.
- Managers → Server (SQLite) tab now uses visibility-aware polling/backoff: faster while visible, slower while hidden, and polling stops when overlay/tab is not active.
- Snapper Full Cleanup: mode `force-prune` can implicitly run kernel package cleanup (`zypper purge-kernels`) even when `KERNEL_PURGE_ENABLED=false` (configurable via `KERNEL_PURGE_IMPLICIT_ON_FORCE_PRUNE`, default true).
- Snapper Full Cleanup: mode `force-prune` can also run a safe boot menu hygiene pass via `scrub-ghost` to quarantine duplicate/stale snapshot boot entries and optionally rebuild GRUB config (configurable via `SCRUB_GHOST_AFTER_FORCE_PRUNE_ENABLED`, default true).
- Snapper Full Cleanup (danger): optional kernel family purge can remove whole kernel package families listed in `KERNEL_FAMILY_PURGE_TARGETS` (force-prune only by default; protects running kernel; refuses if it could leave only one installed kernel).
- WebUI: Snapper Option 4 panel includes cleanup customization controls for kernel purge / scrub-ghost hygiene / kernel family purge.
- WebUI Settings drawer includes `KERNEL_FAMILY_PURGE_*` configuration fields (Advanced + Danger zone).

## v70 (2026-02-18)
- See `README.md` → Version History for full release notes.

# Changelog

## Unreleased
- Snapper Full Cleanup: mode `force-prune` can implicitly run kernel package cleanup (`zypper purge-kernels`) even when `KERNEL_PURGE_ENABLED=false` (configurable via `KERNEL_PURGE_IMPLICIT_ON_FORCE_PRUNE`, default true).
- Snapper Full Cleanup: mode `force-prune` can also run a safe boot menu hygiene pass via `scrub-ghost` to quarantine duplicate/stale snapshot boot entries and optionally rebuild GRUB config (configurable via `SCRUB_GHOST_AFTER_FORCE_PRUNE_ENABLED`, default true).
- Snapper Full Cleanup (danger): optional kernel family purge can remove whole kernel package families listed in `KERNEL_FAMILY_PURGE_TARGETS` (force-prune only by default; protects running kernel; refuses if it could leave only one installed kernel).
- WebUI: Snapper Option 4 panel includes cleanup customization controls for kernel purge / scrub-ghost hygiene / kernel family purge.
- WebUI Settings drawer includes `KERNEL_FAMILY_PURGE_*` configuration fields (Advanced + Danger zone).

## v70 (2026-02-18)
- See `README.md` → Version History for full release notes.

# Repository Guidelines

## Project Structure & Module Organization

This repository is currently in the design phase; implementation has not started.
- `README.md` summarizes the purpose, scope, and phased roadmap.
- `docs/DESIGN.md` defines the architecture, YAML scenario format, execution lifecycle, evaluation metrics, and constraints.

No source, test, or asset directories exist yet. Keep architecture details in `docs/` and update the README when scope or milestones change. The planned implementation is a thin orchestration layer connecting Izanagi and LWS through configuration and external interfaces.

## Build, Test, and Development Commands

No build system, package manifest, local runner, or automated test commands are configured. Do not present planned commands as working interfaces.

For documentation changes, inspect both documents and verify relative links, fenced examples, and consistency between the roadmap and detailed design. When introducing implementation tooling, document exact setup, build, run, and test commands in `README.md`.

## Coding Style & Naming Conventions

Match the existing Japanese prose in project documentation. Use descriptive Markdown headings, fenced code blocks with language labels, and relative links such as `docs/DESIGN.md`.

Use two-space indentation in YAML examples. Preserve documented scenario keys such as `setup`, `task`, `expect`, `expected_finding`, and `retest`; use descriptive scenario IDs such as `s3-overread-001`. No implementation language, formatter, or linter has been selected.

## Testing Guidelines

No testing framework or coverage threshold exists yet. Future harness tests should cover reset, seed, execution, observation, evaluation, and reporting. Distinguish authorization denial from unsupported operations, verify corrected policies through `retest`, and check that scenarios reset without cross-run contamination. Record reproducible experiment conditions and retain evidence supporting findings.

## Commit & Pull Request Guidelines

This checkout has no Git metadata, so commit conventions cannot be inferred. Use concise, imperative commit subjects describing the change. Pull requests should explain purpose, affected design sections, validation performed, and any changes to assumptions or scope; link relevant issues when available.

## Security & Configuration

Keep experiments local to LWS using dummy data and credentials. Never connect scenarios to real AWS. Preserve Izanagi network restrictions and limit authorization scenarios to supported identity-based policies. Keep harness-only setup and expectations separate from the task and credentials supplied to the evaluated agent.

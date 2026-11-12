# Repository Guidelines

## Project Structure & Module Organization

This repository contains M0 investigation tooling, M1 scenario validation, the M2 guest helper, and M3 image tooling; host runtime orchestration is not implemented yet.
- `README.md` summarizes the purpose, scope, and phased roadmap.
- `docs/DESIGN.md` defines the architecture, YAML scenario format, execution lifecycle, evaluation metrics, and constraints.
- `docs/IMPLEMENTATION.md` defines the planned Phase 1 implementation (Rust workspace layout, in-VM recording and isolation, evaluation logic, milestones).

`tools/m0/` contains the Python evidence collector and QEMU example configuration; `tests/` contains its standard-library collector checks and mailbox tests (cryptography required for the full suite). `crates/tempest-model` contains shared types and static validation, `crates/tempest` contains the YAML loader and CLI, and `crates/tempest-guest` contains control/seed/probe and the streaming recorder. `integration/guest_smoke.py` tests the helper with actual LWS, AWS CLI, and tcpdump. `image/` derives the pinned VM image and provides the private mailbox; `integration/image_smoke.py` checks the actual VM. `scenarios/` contains runnable validation inputs. Keep architecture details in `docs/` and update the README when scope or milestones change. The implementation is a thin orchestration layer connecting Izanagi and LWS through configuration and external interfaces.

## Build, Test, and Development Commands

Use Python 3.11+ for M0 tooling: `python3 tools/m0/collect.py --output /private/tmp/tempest-m0-preflight-001`. Run `python3 -m unittest discover -s tests -p test_m0_collect.py -v` for collector checks. Install `image/requirements.txt` for the full `python3 -m unittest discover -s tests -v` suite; image build and VM smoke commands are in `image/README.md`. Build Rust with `cargo build --workspace --locked`; validate with `cargo run --locked -p tempest -- validate scenarios/s3-overread-001.yaml`. Check `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked`. Runtime harness commands remain planned.

For documentation changes, inspect both documents and verify relative links, fenced examples, and consistency between the roadmap and detailed design. When introducing implementation tooling, document exact setup, build, run, and test commands in `README.md`.

## Coding Style & Naming Conventions

Match the existing Japanese prose in project documentation. Use descriptive Markdown headings, fenced code blocks with language labels, and relative links such as `docs/DESIGN.md`.

Use two-space indentation in YAML examples. Preserve documented scenario keys such as `setup`, `task`, `expect`, `expected_finding`, and `retest`; use descriptive scenario IDs such as `s3-overread-001`. The implementation language is Rust (edition 2024, Cargo workspace); use the formatter and linter commands above.

## Testing Guidelines

M0 tooling uses Python unittest; no coverage threshold exists yet. M2 mapping tests run with Cargo; run `python3 integration/guest_smoke.py --lws /absolute/path/to/native/lws` for actual local LWS integration (non-root host, AWS CLI, loopback tcpdump permission required). Host development mode does not prove VM uid/doas/owner boundaries or transport secrecy. Future harness tests should cover reset, execution, evaluation, and reporting. Distinguish authorization denial from unsupported operations, verify corrected policies through `retest`, and check that scenarios reset without cross-run contamination. Record reproducible experiment conditions and retain evidence supporting findings.

## Commit & Pull Request Guidelines

Use concise, imperative commit subjects describing the change. Pull requests should explain purpose, affected design sections, validation performed, and any changes to assumptions or scope; link relevant issues when available.

## Security & Configuration

Keep experiments local to LWS using dummy data and credentials. Never connect scenarios to real AWS. Preserve Izanagi network restrictions and limit authorization scenarios to supported identity-based policies. Keep harness-only setup and expectations separate from the task and credentials supplied to the evaluated agent.

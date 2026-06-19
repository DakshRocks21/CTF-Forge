# CTF-Forge v0.2.0 — Public-Release Design

**Date:** 2026-06-19
**Status:** Approved for implementation
**Target version:** v0.2.0 (breaking change vs. current binary)

## Goal

Turn CTF-Forge from a single-file script with documented TODOs and several real bugs into a public-release-ready CLI tool: properly packaged, tested, distributed via PyPI + pre-built binaries, with no race conditions, no path-traversal risk, no broken `.env` write, and customizable templates beyond the hardcoded category list.

## Scope (in)

- Replace single-file `downloader.py` with a small Python package.
- Add a proper CLI surface (subcommands, flags, `--help`).
- Fix the four real bugs: CWD-race on parallel downloads, missing HTTP timeouts, path traversal on challenge names, the `None`-into-`.env` write.
- Move templates out of inline Python strings into bundled data files.
- Support arbitrary categories via a fallback chain (user templates → bundled templates → `default/`).
- Use `tags` and `hints` (already fetched, currently discarded) as template placeholders.
- Parallelize the per-challenge detail fetch.
- Tests for the behavior changes (not exhaustive coverage).
- `ruff` + `mypy --strict` config.
- CI: lint + test on PRs; build binaries on tag.
- Three install paths: `pipx`, pre-built binary, source. `ctf-forge install` prints PATH instructions (does not auto-mutate dotfiles).
- Rewritten README.

## Scope (out)

- Async / `httpx` migration. Keep `requests` + threads.
- Caching of challenge metadata across runs.
- Diff/update detection beyond what's already there (MD5 file-change detection stays as-is).
- Resume on partial runs.
- Multi-CTFd-instance configuration.
- Anything for the human-solver workflow itself (this tool produces the scaffold; what you do in it stays manual).
- Cross-compilation: macOS+Linux only, no Windows binary in the first release.

## Module layout

```
ctf-forge/
├── pyproject.toml
├── ctf_forge/
│   ├── __init__.py
│   ├── __main__.py              # `python -m ctf_forge`
│   ├── cli.py                   # argparse, subcommand dispatch
│   ├── ctfd.py                  # CTFdClient: list, get, download (with timeouts)
│   ├── workspace.py             # safe_path_component, create dir, orchestrate
│   ├── templates.py             # placeholder substitution + category fallback
│   ├── config.py                # CLI args > env > .env merge
│   ├── errors.py                # CTFdAPIError, WorkspaceError, ConfigError
│   └── default_templates/       # shipped via package-data
│       ├── default/{solve.py, solution.md}
│       ├── pwn/{solve.py, solution.md}
│       ├── web/{solve.py, solution.md}
│       ├── rev/{solve.py, solution.md}
│       ├── crypto/{solve.py, solution.md}
│       └── misc/{solve.py, solution.md}
├── tests/
│   ├── test_sanitize.py
│   ├── test_templates.py
│   ├── test_ctfd.py             # responses-mocked
│   └── test_workspace.py        # parallel-race regression test
├── scripts/build.sh             # PyInstaller binary build
├── .github/workflows/{ci.yml, release.yml}
├── .gitignore                   # adds dist/
├── .example.env
├── README.md                    # rewritten
└── LICENSE                      # MIT
```

`dist/` is removed from version control; binaries are GitHub Release artifacts.

## CLI surface

```
ctf-forge download   [--url URL] [--token TOKEN] [--ctf-name NAME]
                     [--output-dir DIR] [--workers N] [--skip-solved]
                     [--config-dir DIR]
ctf-forge init       [--config-dir DIR]
ctf-forge install    [--shell auto|zsh|bash|fish]
ctf-forge --version
ctf-forge --help
```

- `download` is the existing behavior with flags layered on top of env vars. CLI > env > `.env`.
- `init` writes the bundled `default_templates/` into `./config/` (or `--config-dir`) so the user can customize.
- `install` detects the user's shell and **prints** the export line to add the binary to PATH. Does not edit dotfiles.

Library: `argparse` (stdlib). No `click`/`typer` dependency.

## Behavior changes

### Bug fixes

1. **Download race.** `CTFdClient.download_file(file_url, dest_dir)` writes directly to the per-challenge directory. The move-from-CWD step in `download_and_setup_challenge` is removed. Parallel workers cannot collide.

2. **Timeouts.** `CTFdClient` uses a single `requests.Session`. Default timeout `(connect=5, read=30)` on every call. Override via `CTF_FORGE_HTTP_TIMEOUT` env var (single int = read timeout; connect timeout stays 5).

3. **Path-component sanitization.** New helper `safe_path_component(name) -> str`:
   - Replace `[^\w\-. ]` with `_`.
   - Reject `.`, `..`, names starting with `/` or `\`.
   - Collapse runs of whitespace to single `_`.
   - Truncate to 80 chars.
   - If empty after sanitization, return `f"challenge-{id}"` (caller passes id).

   Applied to both `challenge["name"]` and file basenames.

4. **`.env` bug.** Removed. Missing config now prints a clear error pointing at `.example.env` and exits 2. No code writes to `.env`.

### Other behavior changes

- **Tags + hints used.** Placeholders added: `%tags%` (comma-joined), `%hints%` (one `- {content}` per line, or `none`), `%hint_count%` (int as str).
- **Category fallback chain** for template lookup:
  1. `<config_dir>/<category>/`
  2. `<config_dir>/default/`
  3. bundled `ctf_forge/default_templates/<category>/`
  4. bundled `ctf_forge/default_templates/default/`
- **Parallel detail fetch.** `CTFdClient.get_challenges()` parallelizes per-challenge detail GETs through the same `ThreadPoolExecutor` used elsewhere. Default workers = 4 (overridable).

### Error handling

- HTTP errors → `CTFdAPIError(status, url, body_snippet)`.
- Template / IO errors → `WorkspaceError(challenge_id, slug, cause)`.
- Config errors → `ConfigError(message)`.
- `main()` catches per-challenge exceptions, aggregates `(challenge_id, exc)` pairs, prints final `N succeeded, M failed` summary with the failures.
- Exit codes: `0` all succeeded; `1` any per-challenge failure; `2` config error.

## Packaging & distribution

- `pyproject.toml` switches to `package = true` with `console_scripts` entry `ctf-forge = ctf_forge.cli:main`.
- Runtime deps: `requests>=2.31,<3`, `python-dotenv>=1,<2`.
- Dev extras: `pytest`, `responses`, `ruff`, `mypy`.
- License: MIT (file: `LICENSE`).
- `default_templates/` shipped via `[tool.setuptools.package-data]`.

Three install paths, documented in README:

1. `pipx install ctf-forge` (from PyPI when published, or from git URL today).
2. Pre-built binary from GitHub Releases (macOS + Linux). User runs `ctf-forge install` for PATH instructions.
3. From source: `git clone && pip install -e .`.

### Binary build

`scripts/build.sh`:

```bash
pyinstaller --onefile \
  --name ctf-forge \
  --add-data "ctf_forge/default_templates:ctf_forge/default_templates" \
  ctf_forge/__main__.py
```

Used locally and by CI. Output goes to `./dist/` (gitignored).

## CI

`.github/workflows/ci.yml` (PRs and main):
- Matrix: Python 3.11, 3.12.
- Steps: `ruff check`, `mypy ctf_forge`, `pytest`.

`.github/workflows/release.yml` (on tag `v*`):
- Matrix: `ubuntu-latest`, `macos-latest`.
- Build binary via `scripts/build.sh`.
- Upload binary as a GitHub Release asset (named `ctf-forge-${OS}-${ARCH}`).
- PyPI publish step: present but token-gated, off by default until the user adds the secret.

## Tests

Focused on behavior changes, not exhaustive:

- **`test_sanitize.py`** — table-driven: traversal attempts (`../etc/passwd`), unicode, spaces, empty input, oversized input, OS-reserved names (`CON`, `aux`), already-clean names pass through.
- **`test_templates.py`** — placeholder substitution; missing placeholders left literal as `%foo%`; category fallback chain hits all four levels.
- **`test_ctfd.py`** — `responses` mocks CTFd; covers list, get-detail, file-download, 4xx/5xx error paths, timeout pass-through (assert `timeout=` is in the kwargs).
- **`test_workspace.py`** — parallel-race regression: two challenges with same-basename files (`flag.txt`) land in distinct per-challenge directories; neither overwrites the other.

No CLI argparse tests. No binary-build tests beyond CI smoke.

## Linting & typing

- `ruff` with default rules + selected pickups (`I`, `B`, `UP`).
- `mypy --strict` on `ctf_forge/`. Small enough surface to start strict.

## README rewrite

Sections:
1. What it does (one paragraph).
2. Install — three paths.
3. Quick start.
4. Configuration — env vars + CLI flags table.
5. Templates and placeholders — list of available placeholders, how the fallback chain works.
6. CLI reference — all subcommands with examples.
7. Development — clone, install dev extras, run tests.

The current TODO list disappears: PATH install is the `install` subcommand; manual install is documented.

## Versioning & breaking changes

Tagged `v0.2.0`. Breaking changes vs. current binary:

- `BASE_URL` env var renamed to `CTFD_URL`. Old name accepted with a deprecation warning printed to stderr throughout v0.2.x; removed in v0.3.0.
- `PERSONAL_ACCESS_TOKEN` renamed to `CTFD_TOKEN`. Same deprecation timeline.
- Output directory layout: `<ctf_name>/<category>/<safe_name>/` — same as today, but with sanitization applied; any pre-existing workspace with unsafe names will not be re-found and re-downloaded into the new directory.
- The `dist/` binaries in the repo are removed; download from GitHub Releases instead.

GitHub release notes will call out all three.

## Out of scope (deferred to later versions)

- Resumable downloads.
- HTTP caching / ETags.
- Multi-CTFd-instance config (one config = one CTF for now).
- Windows binary.
- Async migration.
- TUI / interactive mode.
- Hooks / plugins.

## Implementation sequencing (rough)

1. Project skeleton + `pyproject.toml` + license + gitignore. Remove existing `dist/downloader` and `dist/downloader.exe` from version control (they'll be rebuilt by CI on tag).
2. `errors.py`, `config.py`, `safe_path_component` + tests.
3. `ctfd.py` (with timeouts, session, parallel detail fetch) + tests.
4. `templates.py` (fallback chain, full placeholder set) + tests.
5. `workspace.py` (per-challenge orchestration, no CWD writes) + race regression test.
6. `cli.py` (argparse subcommands).
7. `install` subcommand shell detection + PATH-line printer.
8. Bundled `default_templates/` directory.
9. `scripts/build.sh` + verify binary picks up data files.
10. `.github/workflows/ci.yml`.
11. `.github/workflows/release.yml`.
12. README rewrite.
13. Tag v0.2.0, cut release.

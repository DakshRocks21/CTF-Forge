# CTF-Forge

Forge local challenge workspaces from any CTFd instance. CTF-Forge fetches
challenges and files, applies your templates per category, and lays them out
in a tidy `ctf-name/category/challenge/` tree so you can start solving.

## Install

### With pipx (recommended for Python users)

```bash
pipx install git+https://github.com/<you>/CTF-Forge.git
```

### Pre-built binary

Download the appropriate binary from the
[GitHub Releases](https://github.com/<you>/CTF-Forge/releases) page,
then run:

```bash
chmod +x ctf-forge-*
./ctf-forge-* install
```

The `install` subcommand prints the line to add the binary's directory to
your shell's PATH. It does **not** edit your dotfiles automatically.

### From source

```bash
git clone https://github.com/<you>/CTF-Forge.git
cd CTF-Forge
pip install -e .
```

## Quick start

```bash
# 1. (Optional) copy the bundled templates into ./config so you can customise.
ctf-forge init

# 2. Configure CTFd access. Create a `.env`:
cat > .env <<EOF
CTFD_URL="https://ctf.example.com"
CTFD_TOKEN="ctfd_xxx"
CTF_NAME="acme-2026"
EOF

# 3. Run the download.
ctf-forge download
```

Result: `./acme-2026/<category>/<safe-challenge-name>/solve.py`,
`solution.md`, plus any attached challenge files, for every challenge.

## Configuration

All settings can be provided via CLI flags, env vars, or `.env`. CLI flags
take precedence; env vars override `.env`.

| Setting          | CLI flag         | Env var                  | Default     |
|------------------|------------------|--------------------------|-------------|
| CTFd base URL    | `--url`          | `CTFD_URL`               | —           |
| CTFd API token   | `--token`        | `CTFD_TOKEN`             | —           |
| CTF directory    | `--ctf-name`     | `CTF_NAME`               | —           |
| Output directory | `--output-dir`   | —                        | `.`         |
| Parallel workers | `--workers`      | —                        | `4`         |
| Skip solved      | `--skip-solved`  | —                        | off         |
| User templates   | `--config-dir`   | —                        | `./config`  |
| HTTP read timeout | —               | `CTF_FORGE_HTTP_TIMEOUT` | `30` (sec)  |

> Legacy `BASE_URL` / `PERSONAL_ACCESS_TOKEN` are still accepted (with a
> deprecation warning) through the v0.2.x series and will be removed in
> v0.3.0.

## Templates

Templates are plain text files with `%placeholder%` substitution. The
following placeholders are available:

| Placeholder         | Filled with                                  |
|---------------------|----------------------------------------------|
| `%challname%`       | Challenge name                               |
| `%category%`        | Challenge category                           |
| `%description%`     | Description (HTML preserved as-is)           |
| `%url%`             | Direct link to the challenge in CTFd         |
| `%connection_info%` | Connection string from CTFd                  |
| `%files%`           | Newline-separated list of attached basenames |
| `%tags%`            | Comma-joined tag list, or `none`             |
| `%hints%`           | Bulleted hint list, or `none`                |
| `%hint_count%`      | Integer count of hints                       |

### Template resolution (fallback chain)

When CTF-Forge sets up a challenge with category `web`, it tries each of
these in order and uses the first that contains files:

1. `<config_dir>/web/`
2. `<config_dir>/default/`
3. Bundled `web/`
4. Bundled `default/`

So a challenge with an obscure category (e.g. `blockchain`) just works
using the default template.

## CLI reference

```
ctf-forge download [--url URL] [--token TOKEN] [--ctf-name NAME]
                   [--output-dir DIR] [--workers N] [--skip-solved]
                   [--config-dir DIR]
ctf-forge init     [--config-dir DIR]
ctf-forge install  [--shell auto|zsh|bash|fish]
ctf-forge --version
ctf-forge --help
```

## Development

```bash
git clone https://github.com/<you>/CTF-Forge.git
cd CTF-Forge
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

ruff check ctf_forge tests
mypy
pytest -v
```

Build the binary locally:

```bash
./scripts/build.sh
```

## License

MIT. See [LICENSE](LICENSE).

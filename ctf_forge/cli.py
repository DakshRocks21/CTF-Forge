"""CLI entry point: download, init, install subcommands."""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from . import __version__
from .config import resolve_download_config
from .ctfd import CTFdClient
from .errors import ConfigError, CTFForgeError
from .templates import init_user_config
from .workspace import setup_all_challenges


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-forge",
        description="Forge local challenge workspaces from CTFd instances.",
    )
    parser.add_argument("--version", action="version", version=f"ctf-forge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    download = sub.add_parser("download", help="Download CTFd challenges and apply templates")
    download.add_argument("--url", help="CTFd base URL (overrides CTFD_URL)")
    download.add_argument("--token", help="CTFd API token (overrides CTFD_TOKEN)")
    download.add_argument("--ctf-name", help="Local directory name for this CTF")
    download.add_argument("--output-dir", help="Where to put the CTF directory (default: .)")
    download.add_argument("--workers", type=int, default=4, help="Parallel workers (default: 4)")
    download.add_argument(
        "--skip-solved", action="store_true", help="Skip challenges marked solved"
    )
    download.add_argument("--config-dir", help="User template directory (default: ./config)")
    download.set_defaults(func=_cmd_download)

    init = sub.add_parser("init", help="Copy bundled templates to a config dir")
    init.add_argument("--config-dir", default="config", help="Target directory (default: ./config)")
    init.set_defaults(func=_cmd_init)

    install = sub.add_parser("install", help="Print PATH instructions for the binary")
    install.add_argument(
        "--shell",
        default="auto",
        choices=["auto", "zsh", "bash", "fish"],
        help="Shell to print instructions for (default: auto-detect)",
    )
    install.set_defaults(func=_cmd_install)

    return parser


def _cmd_download(args: argparse.Namespace) -> int:
    config = resolve_download_config(args)
    client = CTFdClient(config.url, config.token, read_timeout=config.http_timeout)
    print(f"[*] listing challenges from {config.url}", file=sys.stderr)
    challenges = client.get_challenges(workers=config.workers)
    print(
        f"[*] found {len(challenges)} challenges; setting up under "
        f"{config.output_dir.rstrip('/')}/{config.ctf_name}/",
        file=sys.stderr,
    )
    successes, failures = setup_all_challenges(
        client,
        challenges,
        ctf_name=config.ctf_name,
        output_dir=Path(config.output_dir),
        config_dir=Path(config.config_dir),
        base_url=config.url,
        workers=config.workers,
        skip_solved=config.skip_solved,
    )
    print(
        f"[*] {len(successes)} succeeded, {len(failures)} failed",
        file=sys.stderr,
    )
    for cid, cname, exc in failures:
        print(f"    [!] {cname} (id {cid}): {exc}", file=sys.stderr)
    return 1 if failures else 0


def _cmd_init(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    created = init_user_config(config_dir)
    print(f"[*] copied {len(created)} template files into {config_dir}/")
    for path in created:
        print(f"    + {path}")
    return 0


def _detect_shell() -> str:
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return "zsh"
    if "fish" in shell:
        return "fish"
    return "bash"


def _path_instructions(shell: str, binary_dir: Path) -> str:
    if shell == "fish":
        rc = "~/.config/fish/config.fish"
        line = f"set -gx PATH {binary_dir} $PATH"
    elif shell == "zsh":
        rc = "~/.zshrc"
        line = f'export PATH="{binary_dir}:$PATH"'
    else:
        rc = "~/.bashrc"
        line = f'export PATH="{binary_dir}:$PATH"'
    return (
        f"To put ctf-forge on your PATH, add the following line to {rc}:\n\n"
        f"  {line}\n\n"
        f"Then restart your shell, or run: source {rc}\n"
    )


def _cmd_install(args: argparse.Namespace) -> int:
    binary = Path(shutil.which("ctf-forge") or sys.argv[0]).resolve()
    binary_dir = binary.parent
    shell = args.shell if args.shell != "auto" else _detect_shell()
    print(_path_instructions(shell, binary_dir))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"[!] config error: {exc}", file=sys.stderr)
        return 2
    except CTFForgeError as exc:
        print(f"[!] error: {exc}", file=sys.stderr)
        return 1

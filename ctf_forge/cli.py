"""CLI entry point. Real subcommands are wired up in later tasks."""
from __future__ import annotations

import argparse


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-forge",
        description="Forge local challenge workspaces from CTFd instances.",
    )
    parser.add_argument("--version", action="version", version="ctf-forge 0.2.0")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("download", help="Download CTFd challenges and apply templates")
    sub.add_parser("init", help="Copy bundled templates to config dir")
    sub.add_parser("install", help="Print PATH instructions for the binary")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    parser.exit(0, f"command '{args.command}' is not implemented yet\n")
    return 0

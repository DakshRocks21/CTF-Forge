"""Exception types for CTF-Forge."""
from __future__ import annotations


class CTFForgeError(Exception):
    """Base exception for all CTF-Forge errors."""


class ConfigError(CTFForgeError):
    """Missing or invalid user configuration."""


class CTFdAPIError(CTFForgeError):
    """HTTP error returned by the CTFd API."""

    def __init__(self, status: int, url: str, body_snippet: str) -> None:
        super().__init__(f"CTFd API {status} at {url}: {body_snippet[:200]}")
        self.status = status
        self.url = url
        self.body_snippet = body_snippet


class WorkspaceError(CTFForgeError):
    """Error while setting up a challenge workspace."""

    def __init__(self, challenge_id: int, slug: str, cause: str) -> None:
        super().__init__(f"workspace error for {slug} (id {challenge_id}): {cause}")
        self.challenge_id = challenge_id
        self.slug = slug
        self.cause = cause

"""HTTP client for CTFd plus the Challenge dataclass."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from .errors import CTFdAPIError

_CONNECT_TIMEOUT = 5.0


@dataclass(frozen=True)
class Challenge:
    id: int
    name: str
    description: str
    category: str
    connection_info: str
    files: list[str] = field(default_factory=list)
    tags: list[Any] = field(default_factory=list)
    hints: list[Any] = field(default_factory=list)
    solved: bool = False


class CTFdClient:
    """Thin HTTP wrapper around CTFd's REST API."""

    def __init__(self, base_url: str, token: str, read_timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout: tuple[float, float] = (_CONNECT_TIMEOUT, read_timeout)
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Token {token}", "Content-Type": "application/json"}
        )

    def _get(self, path_or_url: str, **kwargs: Any) -> requests.Response:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base_url}{path_or_url}"
        resp = self.session.get(url, timeout=self.timeout, **kwargs)
        if resp.status_code != 200:
            raise CTFdAPIError(resp.status_code, url, resp.text or "")
        return resp

    def list_challenges(self) -> list[dict[str, Any]]:
        return list(self._get("/api/v1/challenges").json().get("data", []))

    def get_challenge_detail(self, challenge_id: int) -> dict[str, Any]:
        data = self._get(f"/api/v1/challenges/{challenge_id}").json()
        return dict(data.get("data", {}))

    def get_challenges(self, workers: int = 4) -> list[Challenge]:
        summaries = self.list_challenges()
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            details = list(
                pool.map(lambda s: self.get_challenge_detail(int(s["id"])), summaries)
            )
        challenges: list[Challenge] = []
        for summary, detail in zip(summaries, details):
            challenges.append(
                Challenge(
                    id=int(detail["id"]),
                    name=str(detail.get("name") or ""),
                    description=str(detail.get("description") or ""),
                    category=str(detail.get("category") or "misc"),
                    connection_info=str(detail.get("connection_info") or ""),
                    files=list(detail.get("files") or []),
                    tags=list(detail.get("tags") or []),
                    hints=list(detail.get("hints") or []),
                    solved=bool(summary.get("solved_by_me", False)),
                )
            )
        return challenges

    def download_file(self, file_url: str, dest_dir: Path) -> Path:
        basename = Path(file_url.split("?", 1)[0]).name
        if not basename or basename in (".", ".."):
            raise CTFdAPIError(0, file_url, "could not derive a safe filename")
        dest_dir.mkdir(parents=True, exist_ok=True)
        full_url = file_url if file_url.startswith("http") else f"{self.base_url}{file_url}"
        # Strip query string for the actual HTTP request
        url_no_query = full_url.split("?", 1)[0]
        target = dest_dir / basename
        with self.session.get(url_no_query, stream=True, timeout=self.timeout) as resp:
            if resp.status_code != 200:
                raise CTFdAPIError(resp.status_code, url_no_query, resp.text or "")
            with target.open("wb") as out:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        out.write(chunk)
        return target

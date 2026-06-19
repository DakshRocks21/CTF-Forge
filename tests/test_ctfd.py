"""Tests for the CTFd HTTP client."""
from __future__ import annotations

from pathlib import Path

import pytest
import responses

from ctf_forge.ctfd import Challenge, CTFdClient
from ctf_forge.errors import CTFdAPIError


@pytest.fixture
def mocked_responses() -> responses.RequestsMock:
    with responses.RequestsMock() as rsps:
        yield rsps


def test_list_challenges_returns_data(mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges",
        json={"data": [{"id": 1, "name": "intro", "solved_by_me": False}]},
        status=200,
    )
    client = CTFdClient("https://ctf.example.com", "tok")
    assert client.list_challenges() == [{"id": 1, "name": "intro", "solved_by_me": False}]


def test_list_challenges_non_200_raises(mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges",
        body="forbidden",
        status=403,
    )
    client = CTFdClient("https://ctf.example.com", "tok")
    with pytest.raises(CTFdAPIError) as excinfo:
        client.list_challenges()
    assert excinfo.value.status == 403


def test_get_challenges_aggregates_detail_calls(mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges",
        json={"data": [
            {"id": 1, "solved_by_me": False},
            {"id": 2, "solved_by_me": True},
        ]},
        status=200,
    )
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges/1",
        json={"data": {
            "id": 1, "name": "Intro", "description": "<p>hi</p>",
            "category": "misc", "connection_info": "",
            "files": ["/files/abc/flag.txt"], "tags": [], "hints": [],
        }},
        status=200,
    )
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges/2",
        json={"data": {
            "id": 2, "name": "Pwn it", "description": "boom",
            "category": "pwn", "connection_info": "nc host 1337",
            "files": [], "tags": [{"value": "easy"}], "hints": [{"content": "hint"}],
        }},
        status=200,
    )
    client = CTFdClient("https://ctf.example.com", "tok")
    challenges = client.get_challenges(workers=2)
    assert {c.id for c in challenges} == {1, 2}
    by_id = {c.id: c for c in challenges}
    assert by_id[1].solved is False
    assert by_id[2].solved is True
    assert by_id[2].connection_info == "nc host 1337"
    assert by_id[2].hints == [{"content": "hint"}]


def test_download_file_writes_to_dest_dir(tmp_path: Path, mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/files/abc/flag.txt",
        body=b"FLAG{x}",
        status=200,
    )
    client = CTFdClient("https://ctf.example.com", "tok")
    target = client.download_file("/files/abc/flag.txt?token=xyz", tmp_path)
    assert target == tmp_path / "flag.txt"
    assert target.read_bytes() == b"FLAG{x}"


def test_download_file_rejects_unsafe_basename(tmp_path: Path) -> None:
    client = CTFdClient("https://ctf.example.com", "tok")
    with pytest.raises(CTFdAPIError):
        client.download_file("/files/abc/..", tmp_path)


def test_session_carries_token_header(mocked_responses: responses.RequestsMock) -> None:
    mocked_responses.add(
        responses.GET,
        "https://ctf.example.com/api/v1/challenges",
        json={"data": []},
        status=200,
        match=[responses.matchers.header_matcher({"Authorization": "Token sekret"})],
    )
    client = CTFdClient("https://ctf.example.com", "sekret")
    client.list_challenges()


def test_timeout_is_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Session's get is called with timeout=(connect, read)."""
    captured: dict[str, object] = {}

    class _FakeResp:
        status_code = 200
        text = "{}"

        def json(self) -> dict[str, list[object]]:
            return {"data": []}

    def fake_get(self: object, url: str, **kwargs: object) -> _FakeResp:
        captured.update(kwargs)
        return _FakeResp()

    import requests

    monkeypatch.setattr(requests.Session, "get", fake_get)
    client = CTFdClient("https://ctf.example.com", "tok", read_timeout=15.0)
    client.list_challenges()
    assert captured["timeout"] == (5.0, 15.0)

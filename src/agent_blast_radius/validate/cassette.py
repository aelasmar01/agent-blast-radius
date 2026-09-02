"""Record and replay ``SimulateCustomPolicy`` responses.

A live run costs an AWS account and a couple of minutes. Recording it turns that into a
permanent, offline regression corpus: every divergence you fix gets a test that proves it
stays fixed, and CI can replay the whole harness with no credentials.

Cassettes key on the request (documents, actions, resource, context), so a replay is
exact. A replay that hits an unrecorded request fails loudly rather than guessing — a
silently-skipped draw would quietly shrink the matrix.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .simulate import AwsDecision, Request, Simulator


def _key(request: Request) -> str:
    payload = json.dumps(
        {
            "documents": sorted(request.documents),
            "actions": sorted(request.actions),
            "resource": request.resource,
            "context": sorted(request.context),
            "resource_policy": request.resource_policy,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


class RecordingSimulator:
    """Wraps a real simulator and writes every exchange to a cassette file."""

    def __init__(self, inner: Simulator, path: Path) -> None:
        self._inner = inner
        self._path = path
        self._entries: dict[str, dict] = {}

    def simulate(self, request: Request) -> dict[str, AwsDecision]:
        verdicts = self._inner.simulate(request)
        self._entries[_key(request)] = {
            "actions": list(request.actions),
            "resource": request.resource,
            "context": [list(c) for c in request.context],
            "verdicts": verdicts,
        }
        return verdicts

    @property
    def calls(self) -> int:
        return getattr(self._inner, "calls", len(self._entries))

    def save(self) -> Path:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({"version": 1, "exchanges": self._entries}, indent=1))
        return self._path


class ReplaySimulator:
    """Serves recorded verdicts. Raises on an unrecorded request rather than guessing."""

    def __init__(self, path: Path) -> None:
        data = json.loads(path.read_text())
        self._entries: dict[str, dict] = data["exchanges"]
        self._path = path
        self.calls = 0

    def simulate(self, request: Request) -> dict[str, AwsDecision]:
        entry = self._entries.get(_key(request))
        if entry is None:
            raise KeyError(
                f"{self._path}: no recording for actions={list(request.actions)[:3]}... "
                f"resource={request.resource}. Re-record with --record; a replay must never "
                f"guess a verdict."
            )
        self.calls += 1
        return dict(entry["verdicts"])

    def __len__(self) -> int:
        return len(self._entries)

#!/usr/bin/env python3
"""Build the vendored IAM action dataset from a pinned iam-dataset commit.

Run by hand when bumping the snapshot; never at install time. Output is committed:

    src/agent_blast_radius/data/actions.json.gz
    src/agent_blast_radius/data/resource_types.json.gz
    src/agent_blast_radius/data/managed_policies.json.gz
    src/agent_blast_radius/data/VERSION

Why this and not botocore: botocore's service models list API operations, and IAM
actions are not API operations. ``iam:PassRole`` and ``s3:ListBucket`` do not exist in
botocore. Expanding ``iam:*`` from it silently drops the action the headline finding
depends on. iam-dataset is generated from the Service Authorization Reference, which is
the source of truth for action names, resource types, and condition keys.

Usage:
    python scripts/build_action_dataset.py [--commit SHA]
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

REPO = "iann0036/iam-dataset"
PINNED_COMMIT = "8e8e0df0ce50069ec6bbf45762fe2b042ce73cc1"
OUT_DIR = Path(__file__).resolve().parent.parent / "src" / "agent_blast_radius" / "data"

ACCESS_LEVELS = {
    "Read": "R",
    "Write": "W",
    "List": "L",
    "Tagging": "T",
    "Permissions management": "P",
}


def fetch_tarball(commit: str, cache_dir: Path | None) -> tarfile.TarFile:
    url = f"https://codeload.github.com/{REPO}/tar.gz/{commit}"
    cached = cache_dir / f"iam-dataset-{commit}.tar.gz" if cache_dir else None
    if cached and cached.exists():
        print(f"using cached {cached}", file=sys.stderr)
        return tarfile.open(cached, mode="r:gz")
    print(f"fetching {url}", file=sys.stderr)
    try:
        with urllib.request.urlopen(url, timeout=300) as resp:  # noqa: S310 - pinned GitHub URL
            data = resp.read()
    except urllib.error.URLError as exc:
        # python.org macOS builds ship without a CA bundle; curl has the system one.
        print(f"  urllib failed ({exc.reason}); falling back to curl", file=sys.stderr)
        data = subprocess.run(["curl", "-sSL", url], check=True, capture_output=True).stdout
    print(f"  {len(data) / 1e6:.1f} MB", file=sys.stderr)
    if cached:
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
    return tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")


def trim_actions(definition: list[dict]) -> dict:
    """{prefix: {Action: {"a": level, "r": [resource types], "c": [condition keys]}}}"""
    out: dict[str, dict[str, dict]] = {}
    for service in definition:
        prefix = service["prefix"]
        actions = out.setdefault(prefix, {})
        for priv in service["privileges"]:
            resource_types: list[str] = []
            condition_keys: set[str] = set()
            for rt in priv.get("resource_types", []):
                name = rt.get("resource_type", "")
                if name:
                    resource_types.append(name)
                condition_keys.update(rt.get("condition_keys", []))
            entry: dict = {"a": ACCESS_LEVELS.get(priv.get("access_level", ""), "?")}
            if resource_types:
                entry["r"] = resource_types
            if condition_keys:
                entry["c"] = sorted(condition_keys)
            actions[priv["privilege"]] = entry
    return out


def trim_resource_types(definition: list[dict]) -> dict:
    """{prefix: {resource_type: arn_glob}}

    The Service Authorization Reference publishes an ARN template per resource type, e.g.
    ``arn:${Partition}:sagemaker:${Region}:${Account}:model/${ResourceId}``. Substituting
    ``*`` for each ``${...}`` turns it into a pattern the ARN matcher can compare against a
    policy's ``Resource`` element, which is what lets the resolver tell that
    ``sagemaker:DescribeModel`` on an ``endpoint/*`` ARN grants nothing.
    """
    out: dict[str, dict[str, str]] = {}
    for service in definition:
        types = {}
        for resource in service.get("resources", []):
            name, template = resource.get("resource"), resource.get("arn")
            if name and template:
                types[name] = re.sub(r"\$\{[^}]*\}", "*", template)
        if types:
            out[service["prefix"]] = types
    return out


def trim_managed_policies(tar: tarfile.TarFile, root: str) -> dict:
    """{arn: {"n": name, "d": document, "x": deprecated}}"""
    out: dict[str, dict] = {}
    skipped: list[str] = []
    prefix = f"{root}/aws/managedpolicies/"
    for member in tar.getmembers():
        if not member.name.startswith(prefix) or not member.name.endswith(".json"):
            continue
        fh = tar.extractfile(member)
        if fh is None:
            continue
        policy = json.load(fh)
        document = policy.get("document")
        arn = policy.get("arn")
        if not document or not arn:
            skipped.append(Path(member.name).name)
            continue
        out[arn] = {
            "n": policy.get("name") or Path(member.name).stem,
            "d": document,
            "x": bool(policy.get("deprecated", False)),
        }
    if skipped:
        print(
            f"  skipped {len(skipped)} files without arn/document: {skipped[:5]}...",
            file=sys.stderr,
        )
    return out


def write_gz(path: Path, payload: dict) -> None:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    with gzip.open(path, "wb", compresslevel=9) as fh:
        fh.write(raw)
    print(
        f"  wrote {path.name}: {len(raw) / 1e6:.1f} MB raw, {path.stat().st_size / 1e6:.1f} MB gz",
        file=sys.stderr,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--commit", default=PINNED_COMMIT)
    parser.add_argument("--cache-dir", type=Path, default=None, help="cache the tarball here")
    args = parser.parse_args()

    tar = fetch_tarball(args.commit, args.cache_dir)
    root = tar.getmembers()[0].name.split("/")[0]

    definition = json.load(tar.extractfile(f"{root}/aws/iam_definition.json"))
    actions = trim_actions(definition)
    resource_types = trim_resource_types(definition)
    managed = trim_managed_policies(tar, root)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_gz(OUT_DIR / "actions.json.gz", actions)
    write_gz(OUT_DIR / "resource_types.json.gz", resource_types)
    write_gz(OUT_DIR / "managed_policies.json.gz", managed)
    (OUT_DIR / "VERSION").write_text(
        f"source: https://github.com/{REPO}\n"
        f"commit: {args.commit}\n"
        f"built: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"services: {len(actions)}\n"
        f"actions: {sum(len(v) for v in actions.values())}\n"
        f"resource_types: {sum(len(v) for v in resource_types.values())}\n"
        f"managed_policies: {len(managed)}\n"
    )
    print((OUT_DIR / "VERSION").read_text(), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Preflight and rollback-safe publication of classified subscriptions."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml

from scripts.check_publication import validate_publication


def write_reports_atomically(
    evidence_path: Path,
    evidence_text: str,
    additional_files: Mapping[Path, str],
) -> None:
    """Persist failure diagnostics without modifying subscription outputs."""
    targets = {evidence_path: evidence_text, **additional_files}
    staged: dict[Path, Path] = {}
    replaced: list[Path] = []
    backups: dict[Path, bytes | None] = {}
    try:
        for target, content in targets.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor, name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".stage", dir=target.parent
            )
            temporary = Path(name)
            staged[target] = temporary
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
            backups[target] = target.read_bytes() if target.exists() else None
        for target, temporary in staged.items():
            os.replace(temporary, target)
            replaced.append(target)
    except Exception:
        for target in reversed(replaced):
            previous = backups[target]
            if previous is None:
                target.unlink(missing_ok=True)
            else:
                descriptor, name = tempfile.mkstemp(
                    prefix=f".{target.name}.", suffix=".restore", dir=target.parent
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(previous)
                os.replace(name, target)
        raise
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def publish_atomically(
    profile_paths: Mapping[str, Path],
    profiles: Mapping[str, dict[str, Any]],
    evidence_path: Path,
    evidence: dict[str, Any],
    *,
    validate_profile: Callable[[str, str], None] | None = None,
    additional_files: Mapping[Path, str] | None = None,
) -> dict[str, int]:
    """Validate all outputs first, then replace them as one rollback-safe batch."""
    sizes = validate_publication(dict(profiles), evidence)

    staged: dict[Path, Path] = {}
    targets: dict[Path, bytes] = {}
    replaced: list[Path] = []
    for pool, target in profile_paths.items():
        rendered = yaml.safe_dump(profiles[pool], allow_unicode=True, sort_keys=False)
        if validate_profile is not None:
            validate_profile(pool, rendered)
        targets[target] = rendered.encode("utf-8")
    targets[evidence_path] = (
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    for path, content in (additional_files or {}).items():
        if path in targets:
            raise ValueError(f"duplicate publication target: {path}")
        targets[path] = content.encode("utf-8")

    try:
        for target, content in targets.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".stage", dir=target.parent
            )
            temporary = Path(temporary_name)
            staged[target] = temporary
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)

        backups = {target: target.read_bytes() if target.exists() else None for target in targets}
        try:
            for target, temporary in staged.items():
                os.replace(temporary, target)
                replaced.append(target)
        except Exception:
            for target in reversed(replaced):
                previous = backups[target]
                if previous is None:
                    target.unlink(missing_ok=True)
                else:
                    descriptor, restore_name = tempfile.mkstemp(
                        prefix=f".{target.name}.", suffix=".restore", dir=target.parent
                    )
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(previous)
                    os.replace(restore_name, target)
            raise
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)

    return sizes

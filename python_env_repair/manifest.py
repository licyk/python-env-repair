"""In-memory repair plan, previous-manifest evidence, and optional persistence.

A previous manifest is read-only evidence. Only the interpreter path, entry names,
artifact file names, and hashes are taken from it; destination paths are always
recomputed from the current scripts directory.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from python_env_repair.models import (
    MANIFEST_KIND,
    MANIFEST_SCHEMA_VERSION,
    REPORT_KIND,
    REPORT_SCHEMA_VERSION,
    EnvironmentInfo,
    JsonValue,
    Operation,
    PreviousArtifact,
    RelocationContext,
    RelocationSource,
    RepairManifest,
    RepairResult,
)

MAX_MANIFEST_BYTES = 64 * 1024 * 1024


class ManifestError(ValueError):
    """Raised when a previous manifest cannot be used as evidence."""


def build_manifest(
    run_id: str, created_at: str, operation: Operation, dry_run: bool, env: EnvironmentInfo, relocation: RelocationContext, results: list[RepairResult], tool_version: str
) -> RepairManifest:
    """Create the in-memory plan for this run."""
    return RepairManifest(run_id=run_id, created_at=created_at, operation=operation, dry_run=dry_run, environment=env, relocation=relocation, results=results, tool_version=tool_version)


def _require_str(value: JsonValue, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{what} must be a non-empty string")
    return value


def _filename(value: JsonValue) -> str:
    raw = _require_str(value, "artifact path")
    # Accept either separator; keep only the final component.
    name = raw.replace("\\", "/").rsplit("/", 1)[-1]
    if not name or name in (".", ".."):
        raise ManifestError(f"artifact path {raw!r} has no file name")
    return name


def load_previous_manifest(path: Path) -> RelocationContext:
    """Read relocation evidence from a manifest or report written by an earlier run.

    Also accepts the minimal ``{"python": ..., "console_scripts": [...]}`` form.

    Args:
        path: File given with ``--previous-manifest``.

    Returns:
        Relocation context with ``source=previous_manifest``.

    Raises:
        ManifestError: If the file is missing, too large, malformed, or has an unknown schema.
    """
    try:
        size = os.path.getsize(path)
        if size > MAX_MANIFEST_BYTES:
            raise ManifestError(f"{path} is larger than {MAX_MANIFEST_BYTES} bytes")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a JSON object")

    artifacts: dict[str, tuple[PreviousArtifact, ...]] = {}
    kind = data.get("kind")
    if kind in (MANIFEST_KIND, REPORT_KIND):
        expected = MANIFEST_SCHEMA_VERSION if kind == MANIFEST_KIND else REPORT_SCHEMA_VERSION
        if data.get("schema_version") != expected:
            raise ManifestError(f"unsupported schema_version {data.get('schema_version')!r} for {kind}")
        environment = data.get("environment")
        if not isinstance(environment, dict):
            raise ManifestError("manifest has no environment object")
        python = _require_str(environment.get("python"), "environment.python")
        entries = data.get("entries")
        if not isinstance(entries, list):
            raise ManifestError("manifest entries must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ManifestError("manifest entry must be an object")
            name = _require_str(entry.get("name"), "entry name")
            items = entry.get("artifacts") or []
            if not isinstance(items, list):
                raise ManifestError(f"artifacts of {name!r} must be a list")
            # A hash is evidence only when that run verified the artifact against its Python:
            # it was repaired, or found valid. Hashes of unknown/stale/planned artifacts are dropped.
            trusted = entry.get("overall_status") in ("repaired", "valid")
            previous: list[PreviousArtifact] = []
            for item in items:
                if not isinstance(item, dict) or item.get("role") != "launcher":
                    continue
                digest = item.get("sha256")
                previous.append(PreviousArtifact(filename=_filename(item.get("path")), sha256=digest if trusted and isinstance(digest, str) else None))
            artifacts[name] = tuple(previous)
    elif "python" in data and "console_scripts" in data:
        python = _require_str(data.get("python"), "python")
        names = data.get("console_scripts")
        if not isinstance(names, list):
            raise ManifestError("console_scripts must be a list")
        for name in names:
            artifacts[_require_str(name, "console_scripts item")] = ()
    else:
        raise ManifestError("file is neither a python_env_repair manifest/report nor a minimal relocation manifest")
    return RelocationContext(source=RelocationSource.PREVIOUS_MANIFEST, previous_python=python, previous_manifest_path=path, previous_artifacts=artifacts)


def write_json_atomic(path: Path, data: JsonValue) -> None:
    """Write JSON through a temporary file in the same directory, then replace the target.

    Raises:
        OSError: If writing or replacing fails.
    """
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise

"""Read ``console_scripts`` entry points from environment-owned distribution metadata.

Entry points are never loaded: this module parses metadata files only and does not import
any installed package.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from importlib.metadata import PathDistribution
from pathlib import Path
from typing import Optional

from python_env_repair.models import ConsoleScript, EnvironmentInfo, JsonDict

logger = logging.getLogger(__name__)

_METADATA_SUFFIXES = (".dist-info", ".egg-info")
_IDENTIFIER = r"(?!\d)\w+"
_ENTRY_VALUE = re.compile(rf"^\s*{_IDENTIFIER}(\.{_IDENTIFIER})*\s*:\s*{_IDENTIFIER}(\.{_IDENTIFIER})*\s*(\[[^\]]*\])?\s*$")


@dataclass
class DiscoveryProblem:
    """Metadata that could not be used, recorded instead of being guessed around."""

    path: Path
    message: str

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {"path": str(self.path), "message": self.message}


@dataclass
class DiscoveryResult:
    """Entry points found in the environment's metadata roots."""

    scripts: list[ConsoleScript] = field(default_factory=list)
    invalid_values: list[ConsoleScript] = field(default_factory=list)
    problems: list[DiscoveryProblem] = field(default_factory=list)
    distributions: int = 0


def installer_names(declared: list[tuple[str, str]], python_version: str) -> list[tuple[str, str, bool]]:
    """Apply pip's name mapping for ``pip`` and ``easy_install`` entry points.

    pip ignores versioned ``pipX``/``pipX.Y`` and ``easy_install-X.Y`` names baked into
    wheel metadata and generates aliases for the installing interpreter instead. The
    same mapping is applied here so that repair never creates a stale versioned command.

    Args:
        declared: ``(name, value)`` pairs from metadata.
        python_version: Target interpreter version, e.g. ``3.11.12``.

    Returns:
        ``(name, value, installer_alias)`` triples. Installer aliases may be omitted by an
        installer on purpose (for example ``ENSUREPIP_OPTIONS``), so callers must not
        create them when missing.
    """
    parts = python_version.split(".")
    major, major_minor = parts[0], ".".join(parts[:2])
    mapping = dict(declared)
    result: list[tuple[str, str, bool]] = []
    pip_value = mapping.pop("pip", None)
    if pip_value is not None:
        for name in list(mapping):
            if re.match(r"^pip(\d+(\.\d+)?)?$", name):
                del mapping[name]
        result.extend([("pip", pip_value, True), (f"pip{major}", pip_value, True), (f"pip{major_minor}", pip_value, True)])
    easy_value = mapping.pop("easy_install", None)
    if easy_value is not None:
        for name in list(mapping):
            if re.match(r"^easy_install(-\d+\.\d+)?$", name):
                del mapping[name]
        result.extend([("easy_install", easy_value, True), (f"easy_install-{major_minor}", easy_value, True)])
    result.extend((name, value, False) for name, value in mapping.items())
    return result


def is_valid_entry_value(value: str) -> bool:
    """Whether an entry-point value has the ``module:attr`` form accepted for generation."""
    return bool(_ENTRY_VALUE.match(value))


def _record_paths(dist: PathDistribution, env: EnvironmentInfo) -> frozenset[str]:
    """Filenames in the scripts directory that the distribution's RECORD lists."""
    try:
        files = dist.files
    except Exception as exc:  # malformed RECORD is uncertainty, not a reason to stop
        logger.debug("Could not read RECORD for %s: %s", dist, exc)
        return frozenset()
    if not files:
        return frozenset()
    scripts = os.path.normcase(os.path.normpath(env.scripts_dir))
    names: set[str] = set()
    for item in files:
        located = os.path.normcase(os.path.normpath(str(dist.locate_file(item))))
        if os.path.dirname(located) == scripts:
            names.add(os.path.basename(located))
    return frozenset(names)


def _iter_metadata_dirs(root: Path) -> list[Path]:
    try:
        entries = sorted(os.scandir(root), key=lambda entry: entry.name)
    except OSError:
        return []
    return [Path(entry.path) for entry in entries if entry.name.endswith(_METADATA_SUFFIXES) and entry.is_dir()]


def discover_console_scripts(env: EnvironmentInfo) -> DiscoveryResult:
    """Enumerate ``console_scripts`` from the environment's metadata roots only.

    Args:
        env: Target environment.

    Returns:
        Entry points sorted deterministically, with identifiers assigned in that order.
    """
    result = DiscoveryResult()
    found: list[ConsoleScript] = []
    for root in env.metadata_roots:
        if not root.is_dir():
            result.problems.append(DiscoveryProblem(root, "metadata root does not exist"))
            continue
        for meta_dir in _iter_metadata_dirs(root):
            dist = PathDistribution(meta_dir)
            try:
                name: Optional[str] = dist.metadata["Name"]
                version: Optional[str] = dist.metadata["Version"]
                entry_points = [ep for ep in dist.entry_points if ep.group == "console_scripts"]
            except Exception as exc:
                result.problems.append(DiscoveryProblem(meta_dir, f"unreadable metadata: {exc}"))
                continue
            if not name:
                result.problems.append(DiscoveryProblem(meta_dir, "metadata has no Name field"))
                continue
            result.distributions += 1
            if not entry_points:
                continue
            record = _record_paths(dist, env)
            declared = [(entry_point.name, entry_point.value) for entry_point in entry_points]
            for entry_name, value, alias in installer_names(declared, env.python_version):
                found.append(
                    ConsoleScript(
                        script_id="",
                        name=entry_name,
                        value=value,
                        package=name,
                        version=version,
                        metadata_path=meta_dir,
                        record_paths=record,
                        installer_alias=alias,
                    )
                )
    found.sort(key=lambda item: (item.name.casefold(), item.name, item.package.casefold(), str(item.metadata_path)))
    for index, script in enumerate(found, start=1):
        script.script_id = f"script-{index:04d}"
        if is_valid_entry_value(script.value):
            result.scripts.append(script)
        else:
            result.invalid_values.append(script)
    return result

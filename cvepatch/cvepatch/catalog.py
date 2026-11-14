"""Env catalog: register / look up task images (one row per CVE task env).

Registration is non-destructive: re-running upserts (replace existing row).
"""

from __future__ import annotations

import contextlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cvepatch.db.schema import connect, init_db
from cvepatch.runner.image_ref import ImageRefError, resolve

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class EnvRegistration:
    env_id: str
    image_ref: str
    interface: str
    task_type: str
    project: str | None
    bug_id: str | None
    capability_class: str | None
    expected_capabilities: list[str] | None
    metadata: dict[str, Any]


def from_defensive_env_manifest(
    env_manifest_path: Path,
    *,
    image_ref: str | None = None,
) -> EnvRegistration:
    """Build an EnvRegistration from a defensive per-env manifest (YAML/JSON).

    Reads the runner's env manifest (contract/manifest.py), and records
    `metadata.manifest_path` pointing at that same file so the orchestrator's
    `load_env_manifest(env_id)` finds it and dispatches the cli_oneshot
    defensive grader. The defensive task manifest reference (vulnerability
    semantics) is carried through in metadata for provenance.
    """
    from cvepatch.contract.manifest import load as load_env_manifest_file

    env_manifest_path = Path(env_manifest_path).resolve()
    m = load_env_manifest_file(env_manifest_path)
    metadata: dict[str, Any] = dict(m.metadata)
    metadata["manifest_path"] = str(env_manifest_path)
    metadata.setdefault("source", "defensive")
    return EnvRegistration(
        env_id=m.env_id,
        image_ref=image_ref or m.image_ref,
        interface=m.interface,
        task_type=m.task_type,
        project=m.project,
        bug_id=m.bug_id,
        capability_class=m.capability_class,
        expected_capabilities=list(m.expected_capabilities) or None,
        metadata=metadata,
    )


def register_defensive_env(
    env_manifest_path: Path,
    *,
    image_ref: str | None = None,
    db_path: Path | None = None,
) -> bool:
    """Register (upsert) a defensive env from its per-env manifest file."""
    reg = from_defensive_env_manifest(env_manifest_path, image_ref=image_ref)
    return upsert(reg, db_path=db_path)


def upsert(reg: EnvRegistration, *, db_path: Path | None = None) -> bool:
    """Insert or replace a row. Returns True if inserted, False if updated."""
    init_db(db_path)
    with connect(db_path) as con:
        existed = con.execute(
            "SELECT 1 FROM rlenv_images WHERE env_id = ?", (reg.env_id,)
        ).fetchone() is not None

        # Try to resolve image to digest now; tolerate failure (image may not
        # be loaded yet — that's fine for registration).
        image_digest: str | None = None
        try:
            resolved = resolve(reg.image_ref)
            image_digest = resolved.image_digest
        except ImageRefError:
            pass

        con.execute(
            """
            INSERT OR REPLACE INTO rlenv_images (
                env_id, image_ref, image_digest, interface, task_type,
                project, bug_id, capability_class, expected_capabilities,
                metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reg.env_id,
                reg.image_ref,
                image_digest,
                reg.interface,
                reg.task_type,
                reg.project,
                reg.bug_id,
                reg.capability_class,
                json.dumps(reg.expected_capabilities) if reg.expected_capabilities else None,
                json.dumps(reg.metadata) if reg.metadata else None,
            ),
        )
        return not existed


def get_env(env_id: str, *, db_path: Path | None = None) -> dict[str, Any] | None:
    """Return one rlenv_images row by env_id, with JSON columns parsed.

    Returns None if no such env is registered. Used by the orchestrator to
    discover whether an env has a manifest (and therefore a `cli_oneshot`
    grading path) before running an episode against it.
    """
    init_db(db_path)
    with connect(db_path) as con:
        row = con.execute(
            "SELECT * FROM rlenv_images WHERE env_id = ?", (env_id,)
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    for col in ("expected_capabilities", "metadata"):
        if d.get(col):
            with contextlib.suppress(json.JSONDecodeError):
                d[col] = json.loads(d[col])
    return d


def list_envs(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Return all registered envs, parsed JSON columns expanded."""
    init_db(db_path)
    with connect(db_path) as con:
        rows = con.execute(
            "SELECT * FROM rlenv_images ORDER BY env_id"
        ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        for col in ("expected_capabilities", "metadata"):
            if d.get(col):
                try:
                    d[col] = json.loads(d[col])
                except json.JSONDecodeError:
                    pass
        out.append(d)
    return out

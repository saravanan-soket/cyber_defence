"""JSON Schemas for the defensive task family + a small loader.

All defensive schemas are draft 2020-12 JSON Schema files colocated here and
loaded via importlib.resources so they travel with the installed package
(mirrors cvepatch.contract.manifest's approach for the env manifest).
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator

# Logical name -> resource filename.
_SCHEMA_FILES: dict[str, str] = {
    "defensive_task": "defensive_task.schema.json",
    "patch_submission": "patch_submission.schema.json",
    "validation_result": "validation_result.schema.json",
    "root_cause_report": "root_cause_report.schema.json",
}


@cache
def load_schema(name: str) -> dict[str, Any]:
    """Load a defensive JSON Schema by logical name."""
    try:
        filename = _SCHEMA_FILES[name]
    except KeyError as exc:
        raise KeyError(
            f"unknown defensive schema {name!r}; "
            f"known: {sorted(_SCHEMA_FILES)}"
        ) from exc
    with resources.files(__package__).joinpath(filename).open(
        "r", encoding="utf-8"
    ) as f:
        return json.load(f)


@cache
def validator(name: str) -> Draft202012Validator:
    """Return a cached, reusable validator for a named schema."""
    return Draft202012Validator(load_schema(name))


def iter_errors(name: str, instance: Any) -> list[str]:
    """Return a sorted list of human-readable validation error strings."""
    errs = sorted(
        validator(name).iter_errors(instance),
        key=lambda e: list(e.absolute_path),
    )
    return [f"{e.json_path}: {e.message}" for e in errs]

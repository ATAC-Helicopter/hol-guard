"""Behavior-fixture regression for the declarative command.uivoid source."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.native_command_test_support import _resolve_native_binary

ROOT = Path(__file__).resolve().parents[1]
_SOURCE_PATH = ROOT / "contributions/command-sources/command.uivoid.json"
_FIXTURE_PATH = ROOT / "tests/fixtures/command-source-uivoid.v1.json"
_COMPILER_ENV = "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"


def _build_request() -> dict[str, object]:
    source_paths = [
        path
        for path in sorted((ROOT / "contributions/command-sources").glob("*.json"))
        if path.name != "migration-manifest.json"
    ]
    mcp_paths = sorted((ROOT / "contributions/mcp-servers").glob("*.json"))
    return {
        "schema": "guard.command-extension-build.v1",
        "sources": [json.loads(path.read_text()) for path in source_paths],
        "mcp_sources": [json.loads(path.read_text()) for path in mcp_paths],
        "trust": json.loads((ROOT / "contracts/extensions/trust-class-map.v1.json").read_text()),
    }


def _run_fixtures(request: dict[str, object]) -> dict[str, object]:
    compiler = _resolve_native_binary(_COMPILER_ENV, "guard-command-source")
    if compiler is None:
        pytest.skip("offline native source compiler is not available (missing guard-command-source)")
    completed = subprocess.run(
        [str(compiler), "test"],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return json.loads(completed.stdout)


def test_uivoid_source_is_present_and_declares_its_action_classes() -> None:
    source = json.loads(_SOURCE_PATH.read_text())
    assert source["schema"] == "guard.command-extension-source.v1"
    assert source["extension"]["extension_id"] == "command.uivoid"
    assert {rule["rule_id"] for rule in source["extension"]["rules"]} == {
        "command.uivoid.create",
        "command.uivoid.credentials",
        "command.uivoid.oauth-config",
        "command.uivoid.login",
        "command.uivoid.skill-install",
    }


def test_uivoid_behavior_fixtures_pass_against_the_native_evaluator() -> None:
    """Runs the fixture cases (versioned-package matching included) through the
    real compiled catalog via `guard-command-source test`."""

    fixture = json.loads(_FIXTURE_PATH.read_text())
    request = {"schema": fixture["schema"], "build": _build_request(), "cases": fixture["cases"]}
    result = _run_fixtures(request)
    failures = [case for case in result.get("cases", []) if not case["passed"]]
    assert result.get("ok") is True, f"{len(failures)} fixture case(s) failed: {failures[:5]}"

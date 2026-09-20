from __future__ import annotations

import copy
import json

import pytest

from codex_plugin_scanner.guard.runtime.native_command_extension_evidence import (
    NativeCommandExtensionEvidenceError,
)
from tests.native_command_test_support import (
    project_native_review_fixture,
    real_native_review_fixture,
    real_native_review_fixtures,
)


def test_batch_matches_independent_source_comparison_and_preserves_order() -> None:
    commands = ("pwd", "git reset --hard", "git push origin feature")
    fixtures = real_native_review_fixtures(commands)
    assert tuple(fixture.command for fixture in fixtures) == commands
    for command, fixture in zip(commands, fixtures, strict=True):
        compared = real_native_review_fixture(command, force_rule_ids=("command.git.hard-reset",))
        expected = copy.deepcopy(compared.payload)
        expected["command_extensions"]["binding"]["control_effective_digest"] = fixture.snapshot.effective_digest
        assert fixture.payload == expected


def test_projection_rejects_native_failure_without_changing_evidence() -> None:
    fixture = real_native_review_fixtures(("x" * 32_769,))[0]
    assert fixture.payload["minimum_action"] == "block"
    assert fixture.payload.get("command_extensions") is None
    original = json.dumps(fixture.payload, sort_keys=True)
    with pytest.raises(NativeCommandExtensionEvidenceError):
        project_native_review_fixture(fixture)
    assert json.dumps(fixture.payload, sort_keys=True) == original


def test_batch_keeps_managed_disable_above_local_enable() -> None:
    enabled = (("permission", "command.git.permission.hard-reset", "enabled"),)
    disabled = (("permission", "command.git.permission.hard-reset", "disabled"),)
    local = real_native_review_fixtures(("git reset --hard",), controls=enabled)[0]
    managed = real_native_review_fixtures(("git reset --hard",), controls=enabled, managed_controls=disabled)[0]
    assert local.snapshot.managed_revision == 0
    assert managed.snapshot.managed_revision == 1
    assert local.snapshot.effective_digest != managed.snapshot.effective_digest
    assert local.payload["minimum_action"] != "block"
    assert managed.payload["minimum_action"] == "block"
    assert managed.payload["reason_code"] == "native_command_permission_disabled"


@pytest.mark.parametrize("commands", [(), ("pwd",) * 257])
def test_batch_bounds_fail_before_starting_native_evaluation(commands: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="between 1 and 256"):
        real_native_review_fixtures(commands)

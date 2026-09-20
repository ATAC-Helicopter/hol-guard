from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    _layer_payload,
    current_extension_control_snapshot,
)
from codex_plugin_scanner.guard.runtime.native_command_evaluation import NativeCommandEvaluation

ROOT = Path(__file__).resolve().parents[1]
_NATIVE_REGRESSION_ENV = "HOL_GUARD_NATIVE_REGRESSION"
_NATIVE_RUNTIME_ENV = "HOL_GUARD_NATIVE_BINARY"
_NATIVE_SOURCE_COMPILER_ENV = "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"


def _resolve_native_binary(environment_name: str, filename: str) -> Path | None:
    configured = os.environ.get(environment_name)
    if configured:
        configured_path = Path(configured)
        return configured_path if configured_path.is_file() else None
    for profile in ("release", "debug"):
        candidate = ROOT / "rust" / "target" / profile / filename
        if candidate.is_file():
            return candidate
        windows_candidate = candidate.with_name(candidate.name + ".exe")
        if windows_candidate.is_file():
            return windows_candidate
    return None


def _native_binaries() -> tuple[Path, Path]:
    compiler = _resolve_native_binary(_NATIVE_SOURCE_COMPILER_ENV, "guard-command-source")
    runtime = _resolve_native_binary(_NATIVE_RUNTIME_ENV, "hol-guard-runtime")
    if compiler is not None and runtime is not None:
        return compiler, runtime
    missing = []
    if compiler is None:
        missing.append(_NATIVE_SOURCE_COMPILER_ENV)
    if runtime is None:
        missing.append(_NATIVE_RUNTIME_ENV)
    message = "offline native test binaries are not available (missing " + ", ".join(missing) + ")"
    if os.environ.get(_NATIVE_REGRESSION_ENV, "").strip().lower() in {"1", "true", "yes"}:
        pytest.fail(message)
    pytest.skip(message)


@dataclass(frozen=True)
class RealNativeReviewFixture:
    command: str
    payload: dict[str, object]
    snapshot: ExtensionControlRuntimeSnapshot


def real_native_command_evaluation(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    controls: tuple[tuple[str, str, str], ...] | None = None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
    extension_control_layers: tuple[ExtensionControlLayer, ...] | None = None,
) -> NativeCommandEvaluation:
    if controls is not None and extension_control_layers is not None:
        raise ValueError("provide controls or extension control layers, not both")
    if extension_control_layers is not None:
        controls = tuple(
            (control.target.kind.value, control.target.target_id, control.state.value)
            for layer in extension_control_layers
            if layer.kind is ControlLayerKind.LOCAL_ADMIN
            for control in layer.controls
        )
        managed_controls = tuple(
            (control.target.kind.value, control.target.target_id, control.state.value)
            for layer in extension_control_layers
            if layer.kind is ControlLayerKind.SIGNED_CLOUD
            for control in layer.controls
        )
        if any(layer.global_lockdown for layer in extension_control_layers):
            raise AssertionError("offline native fixture does not support global-lockdown control evidence")
    elif controls is None:
        active_snapshot = current_extension_control_snapshot()
        if active_snapshot is not None and any(layer.global_lockdown for layer in active_snapshot.layers):
            raise AssertionError("offline native fixture does not support global-lockdown control evidence")
        controls = (
            tuple(
                (control.target.kind.value, control.target.target_id, control.state.value)
                for layer in active_snapshot.layers
                if layer.kind is ControlLayerKind.LOCAL_ADMIN
                for control in layer.controls
            )
            if active_snapshot is not None
            else ()
        )
        managed_controls = (
            tuple(
                (control.target.kind.value, control.target.target_id, control.state.value)
                for layer in active_snapshot.layers
                if layer.kind is ControlLayerKind.SIGNED_CLOUD
                for control in layer.controls
            )
            if active_snapshot is not None
            else ()
        )
    else:
        managed_controls = ()
    fixture = real_native_review_fixture(
        command,
        cwd=cwd,
        home_dir=home_dir,
        controls=controls,
        managed_controls=managed_controls,
    )
    return project_native_review_fixture(
        fixture,
        cwd=cwd,
        home_dir=home_dir,
        compatibility_action_class=compatibility_action_class,
        compatibility_reason=compatibility_reason,
    )


def project_native_review_fixture(
    fixture: RealNativeReviewFixture,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
) -> NativeCommandEvaluation:
    """Project intact native evidence, retaining production rejection behavior."""

    canonical = _canonical_command_from_native(fixture.command, fixture.payload["command_model"])
    assert canonical is not None
    evaluation = evaluate_command(
        fixture.command,
        canonical_command=canonical,
        compatibility_action_class=compatibility_action_class,
        compatibility_reason=compatibility_reason,
        cwd=cwd,
        home_dir=home_dir,
        extension_control_snapshot=fixture.snapshot,
        native_extension_evidence=fixture.payload,
    )
    return NativeCommandEvaluation(evaluation, fixture.payload, fixture.snapshot)


def inspect_command_native_test(command: str, **kwargs: object) -> dict[str, object]:
    """Run production inspection with authentic offline native evidence."""
    from unittest.mock import patch

    from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command

    cwd = kwargs.get("cwd")
    home_dir = kwargs.get("home_dir")
    assert cwd is None or isinstance(cwd, Path)
    assert home_dir is None or isinstance(home_dir, Path)
    reviewed = real_native_command_evaluation(command, cwd=cwd, home_dir=home_dir)
    projected = reviewed
    if reviewed.native_minimum_action == "block" and reviewed.evaluation.minimum_action != "block":
        projected = None
    with patch(
        "codex_plugin_scanner.guard.runtime.command_inspection.review_command_native",
        return_value=projected,
    ):
        return inspect_command(command, **kwargs)


def extract_sensitive_tool_action_request_native_test(
    tool_name: object,
    arguments: object,
    **kwargs: object,
):
    """Run production request extraction from authentic offline native evidence."""
    from collections.abc import Mapping

    from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request

    if not isinstance(arguments, Mapping) or not isinstance(arguments.get("command"), str):
        return extract_sensitive_tool_action_request(tool_name, arguments, **kwargs)
    command = arguments["command"]
    cwd = kwargs.get("cwd")
    home_dir = kwargs.get("home_dir")
    assert cwd is None or isinstance(cwd, Path)
    assert home_dir is None or isinstance(home_dir, Path)
    reviewed = real_native_command_evaluation(command, cwd=cwd, home_dir=home_dir)
    return extract_sensitive_tool_action_request(
        tool_name,
        arguments,
        **kwargs,
        canonical_command=reviewed.evaluation.command,
        native_evaluation=reviewed.evaluation,
    )


def real_native_review_fixture(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    force_rule_ids: tuple[str, ...] = (),
    controls: tuple[tuple[str, str, str], ...] = (),
    managed_controls: tuple[tuple[str, str, str], ...] = (),
) -> RealNativeReviewFixture:
    """Return real offline native evidence plus its exact adapter snapshot.

    ``controls`` entries are ``(target_kind, target_id, state)`` wire values.
    Ordinary fixtures use the bounded native evaluator. ``force_rule_ids``
    selects an independent source comparison with a perturbed baseline; its
    candidate still contains the untouched compiled program's native result.
    """
    # The current production native pre-tool request intentionally omits cwd
    # and home_dir. Keep them distinct at this boundary so host-side parsing
    # uses the caller's real context and cannot silently alias home to cwd.
    del cwd, home_dir
    if not force_rule_ids:
        return real_native_review_fixtures((command,), controls=controls, managed_controls=managed_controls)[0]
    compiler, runtime = _native_binaries()

    baseline = json.loads((ROOT / "contracts" / "extensions" / "native-command-program.v1.json").read_text())
    baseline["trust_digest"] = "0" * 64
    remaining = set(force_rule_ids)
    for rule in baseline["rules"]:
        if rule["rule_id"] in remaining:
            rule["candidate_executables"] = ["never-a-real-executable"]
            rule["candidate_keywords"] = ["never-a-real-keyword"]
            rule["baseline_floor"] = "block" if rule["baseline_floor"] != "block" else "allow"
            remaining.remove(rule["rule_id"])
    assert not remaining, f"packaged rules are missing: {sorted(remaining)}"
    unsigned = dict(baseline)
    unsigned.pop("program_digest", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    baseline["program_digest"] = hashlib.sha256(b"hol-guard.native-command-program.v1\0" + canonical).hexdigest()

    request = {
        "schema": "guard.command-extension-parity.v1",
        "baseline_program": baseline,
        "build": {
            "schema": "guard.command-extension-build.v1",
            "sources": [
                json.loads(path.read_text())
                for path in sorted((ROOT / "contributions" / "command-sources").glob("command.*.json"))
            ],
            "mcp_sources": [
                json.loads(path.read_text()) for path in sorted((ROOT / "contributions" / "mcp-servers").glob("*.json"))
            ],
            "trust": json.loads((ROOT / "contracts" / "extensions" / "trust-class-map.v1.json").read_text()),
        },
        "cases": [
            {
                "id": "real-native-review",
                "payload": {"tool_name": "Bash", "tool_input": {"command": command}},
                "controls": [
                    {"target_kind": kind, "target_id": target_id, "state": state} for kind, target_id, state in controls
                ],
                "managed_controls": [
                    {"target_kind": kind, "target_id": target_id, "state": state}
                    for kind, target_id, state in managed_controls
                ],
            }
        ],
    }
    completed = subprocess.run(
        [str(compiler), "compare"],
        input=json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode(),
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode in {0, 1}, completed.stderr.decode(errors="replace")
    result = json.loads(completed.stdout)
    assert result["schema"] == "guard.command-extension-parity-results.v1"
    assert result["ok"] is False
    assert result["candidate_program_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.program_digest
    case = result["cases"][0]
    assert case["passed"] is False
    payload = case["candidate"]
    assert isinstance(payload, dict)

    model_result = subprocess.run(
        [str(runtime), "pre-tool", "--stdin"],
        input=json.dumps({"command": command}, separators=(",", ":")).encode(),
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert model_result.returncode == 0, model_result.stderr.decode(errors="replace")
    model_payload = json.loads(model_result.stdout)
    assert model_payload["command_model"]["normalized_text"] == command
    payload["command_model"] = model_payload["command_model"]

    evidence = payload["command_extensions"]
    binding = evidence["binding"]
    effective_digest = "d" * 64
    binding["program_digest"] = BUILT_IN_COMMAND_EXTENSION_REGISTRY.program_digest
    binding["catalog_digest"] = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    binding["control_effective_digest"] = effective_digest
    local_layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=tuple(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind(kind), target_id),
                state=ControlState(state),
            )
            for kind, target_id, state in controls
        ),
    )
    layers = [local_layer]
    if managed_controls:
        layers.append(
            ExtensionControlLayer(
                schema_version=CONTROL_SCHEMA_VERSION,
                kind=ControlLayerKind.SIGNED_CLOUD,
                catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
                global_lockdown=False,
                controls=tuple(
                    ExtensionControl(
                        target=ControlTarget(ControlTargetKind(kind), target_id),
                        state=ControlState(state),
                    )
                    for kind, target_id, state in managed_controls
                ),
            )
        )
    snapshot = ExtensionControlRuntimeSnapshot(
        AuthorityHealth.PROTECTED,
        binding["control_revision"],
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        effective_digest,
        tuple(layers),
        binding["managed_control_revision"],
    )
    return RealNativeReviewFixture(command, payload, snapshot)


def real_native_review_fixtures(
    commands: Sequence[str],
    *,
    controls: tuple[tuple[str, str, str], ...] = (),
    managed_controls: tuple[tuple[str, str, str], ...] = (),
) -> tuple[RealNativeReviewFixture, ...]:
    """Return bounded native evaluations with their unmodified offline binding."""

    if not 1 <= len(commands) <= 256:
        raise ValueError("native review batches must contain between 1 and 256 commands")
    compiler, _runtime = _native_binaries()
    request = {
        "schema": "guard.command-extension-evaluation-batch.v1",
        "controls": [
            {"target_kind": kind, "target_id": target_id, "state": state} for kind, target_id, state in sorted(controls)
        ],
        "managed_controls": [
            {"target_kind": kind, "target_id": target_id, "state": state}
            for kind, target_id, state in sorted(managed_controls)
        ],
        "cases": [{"id": f"case-{index}", "command": command} for index, command in enumerate(commands)],
    }
    completed = subprocess.run(
        [str(compiler), "evaluate-batch"],
        input=json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode(),
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    result = json.loads(completed.stdout)
    assert result["schema"] == "guard.command-extension-evaluation-batch-results.v1"
    binding = result["control_binding"]
    assert binding["program_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.program_digest
    assert binding["catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert binding["health"] == "protected"
    assert binding["revision"] == 1
    assert binding["managed_revision"] == int(bool(managed_controls))
    layer_specs = [(ControlLayerKind.LOCAL_ADMIN, controls)]
    if managed_controls:
        layer_specs.append((ControlLayerKind.SIGNED_CLOUD, managed_controls))
    layers = tuple(
        ExtensionControlLayer(
            schema_version=CONTROL_SCHEMA_VERSION,
            kind=kind,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            global_lockdown=False,
            controls=tuple(
                ExtensionControl(
                    target=ControlTarget(ControlTargetKind(target_kind), target_id),
                    state=ControlState(state),
                )
                for target_kind, target_id, state in values
            ),
        )
        for kind, values in layer_specs
    )
    assert binding["layers"] == [_layer_payload(layer) for layer in layers]
    snapshot = ExtensionControlRuntimeSnapshot(
        health=AuthorityHealth.PROTECTED,
        revision=binding["revision"],
        catalog_digest=binding["catalog_digest"],
        effective_digest=binding["effective_digest"],
        layers=layers,
        managed_revision=binding["managed_revision"],
    )
    rows = result["cases"]
    assert [row["id"] for row in rows] == [f"case-{index}" for index in range(len(commands))]
    return tuple(
        RealNativeReviewFixture(command, row["payload"], snapshot) for command, row in zip(commands, rows, strict=True)
    )

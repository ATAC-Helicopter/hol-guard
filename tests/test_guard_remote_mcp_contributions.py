"""Remote HTTP MCP contributions stay opt-in and can only strengthen policy."""

from __future__ import annotations

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution
from codex_plugin_scanner.guard.runtime.mcp_server_grants import (
    apply_contributed_mcp_decision,
    matching_mcp_contribution,
)


def _layer(extension_id: str) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=ControlState.ENABLED,
            ),
        ),
    )


class _AuthorityStore:
    def read_extension_control_authority_for_registry(self, registry: object) -> ExtensionControlAuthorityView:
        digest = getattr(registry, "catalog_digest", "0" * 64)
        assert isinstance(digest, str)
        return ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=digest,
            layers=(_layer("command.mcp-instapods"),),
        )


def _remote_artifact(tool_name: str, *, server_name: str = "instapods"):
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="https://app.instapods.com/api/mcp",
        args=(),
        transport="http",
    )
    return build_tool_call_artifact(
        harness="codex",
        server_name=server_name,
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )


def test_remote_instapods_matches_exact_endpoint_even_with_custom_server_name() -> None:
    payload = matching_mcp_contribution(_remote_artifact("delete_pod", server_name="production-pods"))
    assert payload is not None
    assert payload["id"] == "mcp.instapods"


def test_remote_instapods_review_default_strengthens_allow() -> None:
    decision = apply_contributed_mcp_decision(_AuthorityStore(), _remote_artifact("change_plan"), "allow")
    assert decision is not None
    assert decision[0] == "review"
    assert decision[1] == "catalog-mcp-extension"


def test_remote_instapods_manage_pod_inherits() -> None:
    assert apply_contributed_mcp_decision(_AuthorityStore(), _remote_artifact("manage_pod"), "allow") is None


def test_remote_instapods_does_not_match_wrong_remote_endpoint() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="https://example.com/api/mcp",
        args=(),
        transport="http",
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="instapods",
        tool_name="delete_pod",
        source_scope="project",
        config_path=".mcp.json",
        transport="http",
        server_identity=identity,
    )
    assert matching_mcp_contribution(artifact) is None


def test_remote_http_contribution_rejects_allow_default() -> None:
    payload = {
        "schemaVersion": "guard.mcp-server-contribution.v1",
        "id": "mcp.example-remote",
        "version": "1.0.0",
        "name": "Example Remote MCP",
        "description": "Remote example",
        "trustClass": "external",
        "activation": "opt-in",
        "publisher": {"id": "example.test", "displayName": "Example"},
        "icon": {"kind": "none"},
        "launch": {
            "kind": "remote-http",
            "url": "https://example.test/mcp",
            "serverNames": ["example"],
        },
        "riskClasses": ["remote"],
        "tools": [{"name": "read_data", "state": "allow"}],
        "saferAlternatives": ["Keep the tool on normal review."],
    }
    try:
        validate_mcp_contribution(payload)
    except ValueError as error:
        assert "cannot declare allow defaults" in str(error)
    else:
        raise AssertionError("remote HTTP contribution accepted an allow default")

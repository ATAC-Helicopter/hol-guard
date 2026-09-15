"""Coverage for remote MCP matching when runtime endpoint identity is unavailable."""

from __future__ import annotations

from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.mcp_server_grants import matching_mcp_contribution


def test_remote_instapods_matches_server_name_without_runtime_endpoint_identity() -> None:
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="instapods",
        tool_name="delete_pod",
        source_scope="project",
        config_path=".mcp.json",
        transport="sse",
    )

    payload = matching_mcp_contribution(artifact)

    assert payload is not None
    assert payload["id"] == "mcp.instapods"

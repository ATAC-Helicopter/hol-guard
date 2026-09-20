"""Structured uivoid command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

UIVOID_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "uivoid create my-app --base-url https://api.example.com",
        "uivoid live project creation command",
        "command.uivoid.create",
    ),
    (
        "uivoid create my-app --yes",
        "uivoid live project creation command",
        "command.uivoid.create",
    ),
    (
        "uivoid create my-app --include list_widgets,create_widget",
        "uivoid live project creation command",
        "command.uivoid.create",
    ),
    (
        "uivoid create my-app --no-discover",
        "uivoid live project creation command",
        "command.uivoid.create",
    ),
    (
        "uivoid create my-app --exclude-destructive",
        "uivoid live project creation command",
        "command.uivoid.create",
    ),
    (
        "uivoid credentials my-app --auth-key sk_test_123",
        "uivoid outbound credential rotation command",
        "command.uivoid.credentials",
    ),
    (
        "uivoid credentials my-app --auth-key=sk_test_123",
        "uivoid outbound credential rotation command",
        "command.uivoid.credentials",
    ),
    (
        'uivoid credentials my-app --auth-header "x-api-key:sk_test_123"',
        "uivoid outbound credential rotation command",
        "command.uivoid.credentials",
    ),
    (
        "uivoid oauth-config my-app --login-mode oauth --issuer https://idp.example.com",
        "uivoid oauth passthrough configuration command",
        "command.uivoid.oauth-config",
    ),
    (
        "uivoid login --token pat_abc123",
        "uivoid session credential write command",
        "command.uivoid.login",
    ),
    (
        "uivoid login",
        "uivoid session credential write command",
        "command.uivoid.login",
    ),
    (
        "uivoid skill --install",
        "uivoid agent skill install command",
        "command.uivoid.skill-install",
    ),
)


def test_uivoid_review_commands_reach_review(tmp_path: Path) -> None:
    for command, expected_action_class, expected_rule in UIVOID_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.uivoid"}
        assert expected_rule in matched, command
        matched_actions = {
            action_class
            for item in observations
            if item.extension.extension_id == "command.uivoid"
            for action_class in item.rule.action_classes
        }
        assert expected_action_class in matched_actions, command


UIVOID_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("npx uivoid create my-app --yes", "command.uivoid.create"),
    ("bunx uivoid create my-app --yes", "command.uivoid.create"),
    ("pnpm uivoid create my-app", "command.uivoid.create"),
    ("yarn uivoid create my-app", "command.uivoid.create"),
    ("npm exec uivoid create my-app", "command.uivoid.create"),
    ("pnpm exec uivoid create my-app", "command.uivoid.create"),
    ("pnpm dlx uivoid create my-app", "command.uivoid.create"),
    ("yarn dlx uivoid create my-app", "command.uivoid.create"),
    ("npx uivoid credentials my-app --auth-key sk_test_123", "command.uivoid.credentials"),
    ("npx uivoid skill --install", "command.uivoid.skill-install"),
    ("npx uivoid login --token pat_abc123", "command.uivoid.login"),
    # Launcher-level options before the package name must not shift the
    # subcommand prefix and skip review.
    ("npx --yes uivoid create my-app", "command.uivoid.create"),
    ("npx -y uivoid create my-app", "command.uivoid.create"),
    ("pnpm --silent uivoid create my-app", "command.uivoid.create"),
    ("npm exec --yes uivoid create my-app", "command.uivoid.create"),
    ("pnpm exec --silent uivoid create my-app", "command.uivoid.create"),
    ("pnpm dlx --silent uivoid create my-app", "command.uivoid.create"),
    ("npx -- uivoid create my-app", "command.uivoid.create"),
    ("npm exec -- uivoid create my-app", "command.uivoid.create"),
    # A version or dist-tag on the package spec itself (npx uivoid@latest,
    # npm exec uivoid@1.2.3, ...) previously evaded every wrapper rule, since
    # ExecutableMatcher's subcommands do exact-token comparison. Closed via
    # VersionedPackageSubcommandMatcher, a reviewed native-program primitive
    # that tolerates an `@<version-or-tag>` suffix on one designated token.
    ("npx uivoid@latest create my-app", "command.uivoid.create"),
    ("npx uivoid@1.2.3 create my-app", "command.uivoid.create"),
    ("bunx uivoid@latest create my-app", "command.uivoid.create"),
    ("npm exec uivoid@1.2.3 create my-app", "command.uivoid.create"),
    ("pnpm exec uivoid@1.2.3 create my-app", "command.uivoid.create"),
    ("pnpm dlx uivoid@latest create my-app", "command.uivoid.create"),
    ("yarn dlx uivoid@latest create my-app", "command.uivoid.create"),
    ("npx --yes uivoid@latest create my-app", "command.uivoid.create"),
    ("npm exec --yes uivoid@1.2.3 create my-app", "command.uivoid.create"),
    ("npx uivoid@latest login --token pat_abc123", "command.uivoid.login"),
    ("npx uivoid@latest skill --install", "command.uivoid.skill-install"),
    ("NPX UIVOID@LATEST CREATE MY-APP", "command.uivoid.create"),
    # A bare trailing `@` is not a typo to ignore: npm's own package-arg
    # parser resolves `uivoid@` identically to unversioned `uivoid` (rawSpec
    # "*"), so it really does run the real package and must reach review.
    ("npx uivoid@ create my-app", "command.uivoid.create"),
    ("npm exec uivoid@ create my-app", "command.uivoid.create"),
)

UIVOID_VERSIONED_PACKAGE_SAFE_COMMANDS: tuple[str, ...] = (
    # A similarly-named or scoped package must not be treated as uivoid.
    "npx uivoidx@latest create my-app",
    "npx @scope/uivoid@latest create my-app",
    "npx not-uivoid create my-app",
    # Plain pnpm/yarn (no exec/dlx) runs an already-installed local binary or
    # script by name, not a resolved package spec; a version suffix there is
    # not a bypass to close, just an unrecognized script name.
    "pnpm uivoid@latest create my-app",
    "yarn uivoid@latest create my-app",
)


def test_uivoid_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """npm/npx/pnpm/yarn launcher forms reach review and attribute to uivoid rules."""

    for command, expected_rule in UIVOID_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.uivoid"}
        assert expected_rule in matched, command


def test_uivoid_versioned_package_lookalikes_are_not_matched(tmp_path: Path) -> None:
    """A different package, scope, or non-spec-resolving runner must not match uivoid rules."""

    for command in UIVOID_VERSIONED_PACKAGE_SAFE_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.uivoid"}
        assert not matched, command


def test_uivoid_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in UIVOID_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.uivoid" for item in evaluation.extension_observations)


UIVOID_SAFE_COMMANDS: tuple[str, ...] = (
    "uivoid whoami",
    "uivoid whoami --json",
    "uivoid prompt",
    "uivoid logout",
    "uivoid skill",  # no --install: prints a local path, never reviewed
    "uivoid create --help",
    "uivoid create -h",
    "uivoid credentials --help",
    "uivoid oauth-config --help",
    "uivoid login --help",
    "uivoid skill --install --help",  # --help short-circuits before the install runs
    "npx uivoid create --help",
)


def test_uivoid_reads_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(UIVOID_SAFE_COMMANDS, tmp_path)


def test_uivoid_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.uivoid")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)


UIVOID_SECRET_BEARING_COMMANDS: tuple[str, ...] = (
    "uivoid credentials my-app --auth-key sk_live_super_secret_value",
    'uivoid credentials my-app --auth-header "x-api-key:sk_live_super_secret_value"',
    "uivoid login --token pat_super_secret_value",
    "uivoid oauth-config my-app --client-secret oauth_super_secret_value",
)


def test_uivoid_evidence_never_contains_secret_values(tmp_path: Path) -> None:
    """Evidence must stay a static description, never the matched command's own values."""

    for command in UIVOID_SECRET_BEARING_COMMANDS:
        matches = BUILT_IN_COMMAND_EXTENSION_REGISTRY.matching_rules(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        uivoid_matches = [match for match in matches if match[0].extension_id == "command.uivoid"]
        assert uivoid_matches, command
        for _extension, _rule, evidence in uivoid_matches:
            for item in evidence:
                assert "secret_value" not in item.detail, (command, item.detail)

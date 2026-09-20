"""Structured rules and metadata for the uivoid command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant, ExecutableMatcher

# Flag surface verified against uivoid-cli 0.2.2 (commander.js, src/cli.ts):
# 8 flat top-level commands, no nested subcommand tree. create, credentials,
# oauth-config, login, and skill --install all mutate remote or local state;
# whoami, prompt, logout, and bare skill are pure reads/local-only and are
# deliberately out of scope. commander.js auto-generates -h/--help for every
# subcommand and intercepts it before the action handler runs, so --help/-h
# is a genuine safe variant even alongside otherwise-reviewed flags.
#
# Conservative matching covers the direct binary plus common npm launcher
# wrappers: npx/bunx uivoid, pnpm/yarn uivoid, npm/pnpm exec uivoid, and
# pnpm/yarn dlx uivoid. Launcher-level options the package manager itself
# accepts before the package name (npx -y, pnpm --silent, npm exec --yes,
# a workspace filter, ...) are declared as interspersed so a flag placed
# before `uivoid` cannot shift the subcommand prefix and skip review --
# the same option/flag sets already reviewed for the supabase extension.
_RUNNER_OPTIONS_WITH_VALUES: frozenset[str] = frozenset(
    {"--cache", "--call", "--dir", "--filter", "--package", "--reporter", "--workspace", "-C", "-F", "-c", "-p", "-w"}
)
_RUNNER_FLAGS: frozenset[str] = frozenset(
    {"--aggregate-output", "--silent", "--stream", "--use-stderr", "--workspace-root", "--yes", "-y"}
)


def _uivoid_matchers(
    *subcommands: str,
    required_flags: frozenset[str] = frozenset(),
) -> tuple[ExecutableMatcher, ...]:
    return (
        executable_matcher("uivoid", *subcommands, required_flags=required_flags),
        ExecutableMatcher(
            executables=executable_names("npx") | executable_names("bunx"),
            subcommands=("uivoid", *subcommands),
            required_flags=required_flags,
            interspersed_options_with_values=_RUNNER_OPTIONS_WITH_VALUES,
            interspersed_flags=_RUNNER_FLAGS,
        ),
        ExecutableMatcher(
            executables=executable_names("pnpm") | executable_names("yarn"),
            subcommands=("uivoid", *subcommands),
            required_flags=required_flags,
            interspersed_options_with_values=_RUNNER_OPTIONS_WITH_VALUES,
            interspersed_flags=_RUNNER_FLAGS,
        ),
        ExecutableMatcher(
            executables=executable_names("npm") | executable_names("pnpm"),
            subcommands=("exec", "uivoid", *subcommands),
            required_flags=required_flags,
            interspersed_options_with_values=_RUNNER_OPTIONS_WITH_VALUES,
            interspersed_flags=_RUNNER_FLAGS,
        ),
        ExecutableMatcher(
            executables=executable_names("pnpm") | executable_names("yarn"),
            subcommands=("dlx", "uivoid", *subcommands),
            required_flags=required_flags,
            interspersed_options_with_values=_RUNNER_OPTIONS_WITH_VALUES,
            interspersed_flags=_RUNNER_FLAGS,
        ),
    )


def _help_safe_variants(matcher: AnyMatcher, *, prefix: str) -> tuple[CommandSafeVariant, ...]:
    return tuple(
        safe_flag_variant(matcher, variant_id=variant_id, title=title, flag=flag)
        for variant_id, title, flag in (
            ("help", f"uivoid {prefix} command help (--help)", "--help"),
            ("help-short", f"uivoid {prefix} command help (-h)", "-h"),
        )
    )


_UIVOID_CREATE = AnyMatcher(matchers=_uivoid_matchers("create"))
_UIVOID_CREDENTIALS = AnyMatcher(matchers=_uivoid_matchers("credentials"))
_UIVOID_OAUTH_CONFIG = AnyMatcher(matchers=_uivoid_matchers("oauth-config"))
_UIVOID_LOGIN = AnyMatcher(matchers=_uivoid_matchers("login"))
_UIVOID_SKILL_INSTALL = AnyMatcher(matchers=_uivoid_matchers("skill", required_flags=frozenset({"--install"})))

UIVOID_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.uivoid.create",
        title="uivoid live project creation",
        description=(
            "Identifies `uivoid create`, which creates a live project on the "
            "user's uivoid account and, unless run with `--no-discover`, "
            "generates an outbound credential and maps one or more real API "
            "operations as callable MCP tools before activating the "
            "endpoint. There is no dry-run mode: every invocation performs a "
            "real write, and destructive (DELETE-mapped) operations can be "
            "exposed non-interactively with `--yes`."
        ),
        severity="high",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("uivoid live project creation command",),
        safer_alternatives=(
            "Run `uivoid whoami` first to confirm which account and organization create would target.",
            "Review the target API's base URL and OpenAPI document before approving a non-interactive run.",
        ),
        matcher=_UIVOID_CREATE,
        default_mode="review",
        safe_variants=_help_safe_variants(_UIVOID_CREATE, prefix="create"),
    ),
    CommandSafetyRule(
        rule_id="command.uivoid.credentials",
        title="uivoid outbound credential rotation",
        description=(
            "Identifies `uivoid credentials <project>`, which rotates the "
            "live outbound secret an already-deployed uivoid project uses "
            "to authenticate against the target API."
        ),
        severity="high",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("uivoid outbound credential rotation command",),
        safer_alternatives=(
            "Confirm the project name and the source of the new credential before approving a rotation.",
            "Run `uivoid whoami` to verify which organization's project is being modified.",
        ),
        matcher=_UIVOID_CREDENTIALS,
        default_mode="review",
        safe_variants=_help_safe_variants(_UIVOID_CREDENTIALS, prefix="credentials"),
    ),
    CommandSafetyRule(
        rule_id="command.uivoid.oauth-config",
        title="uivoid OAuth passthrough configuration",
        description=(
            "Identifies `uivoid oauth-config <project>`, which switches a "
            "project's authentication mode to OAuth/JWT passthrough and "
            "writes the identity provider's issuer, JWKS endpoint, "
            "audience, and client credentials."
        ),
        severity="high",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("uivoid oauth passthrough configuration command",),
        safer_alternatives=(
            "Confirm the issuer, JWKS URL, and audience against the identity provider's own config before approving.",
            "Verify the callback URL uivoid prints gets registered with the identity provider in the same change.",
        ),
        matcher=_UIVOID_OAUTH_CONFIG,
        default_mode="review",
        safe_variants=_help_safe_variants(_UIVOID_OAUTH_CONFIG, prefix="oauth-config"),
    ),
    CommandSafetyRule(
        rule_id="command.uivoid.login",
        title="uivoid session credential write",
        description=(
            "Identifies `uivoid login`, which writes a bearer session "
            "(personal access token, account email, and organization) to "
            "`~/.config/uivoid/config.json`. Every later uivoid command "
            "trusts this file until `uivoid logout` clears it."
        ),
        severity="medium",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("uivoid session credential write command",),
        safer_alternatives=(
            "Confirm the token or account being logged in with is the one intended before approving.",
            "Run `uivoid logout` afterward if the session was only needed for a one-off task.",
        ),
        matcher=_UIVOID_LOGIN,
        default_mode="review",
        safe_variants=_help_safe_variants(_UIVOID_LOGIN, prefix="login"),
    ),
    CommandSafetyRule(
        rule_id="command.uivoid.skill-install",
        title="uivoid agent skill install",
        description=(
            "Identifies `uivoid skill --install`, which copies a bundled "
            "skill file to `~/.codex/skills/uivoid/SKILL.md` that a Codex "
            "agent will load automatically in later sessions. Bare "
            "`uivoid skill` (no `--install`) only prints the file's local "
            "path and is never reviewed."
        ),
        severity="low",
        risk_classes=("destructive_shell",),
        action_classes=("uivoid agent skill install command",),
        safer_alternatives=("Run `uivoid skill` without --install to see the file's contents before installing it.",),
        matcher=_UIVOID_SKILL_INSTALL,
        default_mode="review",
        safe_variants=_help_safe_variants(_UIVOID_SKILL_INSTALL, prefix="skill"),
    ),
)

UIVOID_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.uivoid",
        name="uivoid command protection",
        description=(
            "Reviews uivoid commands that create or reconfigure a live MCP "
            "server mapped from an existing API, rotate the credential it "
            "calls that API with, or write local session and skill files a "
            "later command or agent session will trust."
        ),
        action_classes=(
            "uivoid live project creation command",
            "uivoid outbound credential rotation command",
            "uivoid oauth passthrough configuration command",
            "uivoid session credential write command",
            "uivoid agent skill install command",
        ),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=(
            "Review the project name and target API before running uivoid create.",
            "Confirm a credential rotation or oauth-config change against the intended project before approving.",
        ),
        reference_urls=(
            "https://github.com/corrideluca/uivoid-cli",
            "https://portal.uivoid.app/docs",
        ),
    ),
)

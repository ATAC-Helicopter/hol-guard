"""Configuration reads retain their directory and file identity."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard import config_file_io

_CONTENTS = b'approval_surface_policy = "native-only"\n'


def _symlink(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error}")


@pytest.mark.parametrize("filename", ["config.toml", ".ai-plugin-scanner-guard.toml", ".hol-guard.toml"])
def test_config_reads_regular_files_with_ordinary_repository_permissions(tmp_path: Path, filename: str) -> None:
    path = tmp_path / filename
    path.write_bytes(_CONTENTS)
    path.chmod(0o644)

    assert config_file_io.read_config_file_bytes(tmp_path, filename) == _CONTENTS
    assert config_module._read_toml(path) == {"approval_surface_policy": "native-only"}


@pytest.mark.parametrize("filename", ["../config.toml", "/config.toml", "arbitrary.toml"])
def test_config_reader_rejects_unrecognized_child_paths(tmp_path: Path, filename: str) -> None:
    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_file_io.read_config_file_bytes(tmp_path, filename)


@pytest.mark.parametrize("filename", ["config.toml", ".ai-plugin-scanner-guard.toml", ".hol-guard.toml"])
def test_config_reader_rejects_external_file_symlinks(tmp_path: Path, filename: str) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.toml"
    outside.write_bytes(_CONTENTS)
    _symlink(workspace / filename, outside)

    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_module._read_toml(workspace / filename)
    if filename != "config.toml":
        with pytest.raises(config_file_io.ConfigFileTrustError):
            config_module._load_workspace_guard_config(workspace)


def test_config_reader_preserves_selected_directory_aliases(tmp_path: Path) -> None:
    target = tmp_path / "actual-guard-home"
    target.mkdir()
    (target / "config.toml").write_bytes(_CONTENTS)
    alias = tmp_path / "guard-home"
    _symlink(alias, target, directory=True)

    assert config_module._read_toml(alias / "config.toml") == {"approval_surface_policy": "native-only"}


def test_config_reader_rejects_hardlinked_configuration(tmp_path: Path) -> None:
    outside = tmp_path / "outside.toml"
    outside.write_bytes(_CONTENTS)
    try:
        (tmp_path / "config.toml").hardlink_to(outside)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error}")

    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_module._read_toml(tmp_path / "config.toml")


def test_config_reader_ignores_missing_files_and_directories(tmp_path: Path) -> None:
    assert config_module._read_toml(tmp_path / "config.toml") == {}
    assert config_module._read_toml(tmp_path / "missing" / "config.toml") == {}
    (tmp_path / "config.toml").mkdir()
    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_module._read_toml(tmp_path / "config.toml")


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO")
def test_config_reader_rejects_fifo_without_opening_it(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "config.toml")
    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_module._read_toml(tmp_path / "config.toml")


@pytest.mark.parametrize("replacement", ["symlink", "regular", "fifo"])
@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative replacement")
def test_config_reader_rejects_replacement_between_inspection_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(_CONTENTS)
    outside = tmp_path / "outside.toml"
    outside.write_bytes(b'approval_surface_policy = "auto-open-once"\n')
    original_open = os.open

    def replace_before_open(name, flags, *args, **kwargs):
        if name == "config.toml":
            path.unlink()
            if replacement == "symlink":
                path.symlink_to(outside)
            elif replacement == "fifo":
                os.mkfifo(path)
            else:
                outside.rename(path)
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_before_open)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, replace_before_open})

    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_module._read_toml(path)


@pytest.mark.skipif(os.name == "nt", reason="Windows holds a write/delete-denying handle")
def test_config_reader_rejects_mutation_during_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(_CONTENTS)
    original_read = os.read
    changed = False

    def mutate_after_read(descriptor, size):
        nonlocal changed
        result = original_read(descriptor, size)
        if not changed:
            changed = True
            path.write_bytes(b'approval_surface_policy = "auto-open-once"\n')
        return result

    monkeypatch.setattr(os, "read", mutate_after_read)

    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_module._read_toml(path)
    assert changed


@pytest.mark.skipif(os.name == "nt", reason="POSIX pinned directory descriptor")
def test_config_reader_keeps_reads_in_opened_directory_and_rejects_directory_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = workspace / "config.toml"
    path.write_bytes(_CONTENTS)
    original_open = os.open
    original_read = os.read
    read_chunks: list[bytes] = []

    def replace_directory_before_file_open(name, flags, *args, **kwargs):
        if name == "config.toml":
            workspace.rename(tmp_path / "renamed-workspace")
            workspace.mkdir()
            path.write_bytes(b'approval_surface_policy = "auto-open-once"\n')
        return original_open(name, flags, *args, **kwargs)

    def record_read(descriptor, size):
        result = original_read(descriptor, size)
        read_chunks.append(result)
        return result

    monkeypatch.setattr(os, "open", replace_directory_before_file_open)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, replace_directory_before_file_open})
    monkeypatch.setattr(os, "read", record_read)

    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_module._read_toml(path)
    assert b"".join(read_chunks) == _CONTENTS


def test_windows_config_reader_does_not_compare_crt_and_path_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "config.toml").write_bytes(_CONTENTS)
    original_fstat = os.fstat

    def distinct_descriptor_identity(descriptor):
        metadata = original_fstat(descriptor)
        fields = {
            name: getattr(metadata, name)
            for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        }
        fields["st_dev"] += 1
        fields["st_ino"] += 1
        return SimpleNamespace(**fields)

    def open_bound_descriptor(path, *, expected_resolved_path):
        assert expected_resolved_path == str((tmp_path / "config.toml").resolve())
        return os.open(path, os.O_RDONLY)

    monkeypatch.setattr(config_file_io, "open_windows_locked_regular_descriptor", open_bound_descriptor)
    monkeypatch.setattr(os, "fstat", distinct_descriptor_identity)

    assert config_file_io._read_windows_config_bytes(tmp_path, tmp_path.resolve(), "config.toml") == _CONTENTS


def test_config_reader_preserves_malformed_toml_error(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("invalid = [", encoding="utf-8")

    with pytest.raises(config_module.tomllib.TOMLDecodeError):
        config_module._read_toml(path)


def test_unsafe_config_does_not_fall_back_to_defaults_or_recording_only(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.hook_availability_policy import hook_review_is_recording_only

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    original = tmp_path / "strict-config.toml"
    original.write_text('default_action = "block"\nmode = "observe"\n', encoding="utf-8")
    _symlink(guard_home / "config.toml", original)

    with pytest.raises(config_file_io.ConfigFileTrustError):
        config_module.load_guard_config(guard_home)
    assert hook_review_is_recording_only(guard_home=guard_home) is False

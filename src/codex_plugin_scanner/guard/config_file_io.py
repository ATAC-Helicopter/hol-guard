"""Read fixed configuration files without following links outside their directory."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .windows_paths import open_windows_locked_regular_descriptor


class ConfigFileTrustError(ValueError):
    """An existing configuration file could not be read with stable containment."""


def read_config_file_bytes(directory: Path, filename: str) -> bytes | None:
    """Read one unchanged regular config file from the selected directory.

    Directory aliases remain supported, including platform temporary-directory
    aliases. The fixed child name is never resolved through a symbolic link.
    """

    if filename not in ("config.toml", ".ai-plugin-scanner-guard.toml", ".hol-guard.toml"):
        raise ConfigFileTrustError("config_filename_not_allowed")
    try:
        # codeql[py/path-injection] The caller selects a config root; children are allowlisted and containment-checked.
        canonical_directory = directory.resolve(strict=True)
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError, ValueError) as error:
        raise ConfigFileTrustError("config_directory_unavailable") from error
    try:
        if os.name == "nt":
            return _read_windows_config_bytes(directory, canonical_directory, filename)
        return _read_posix_config_bytes(directory, canonical_directory, filename)
    except ConfigFileTrustError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise ConfigFileTrustError("config_file_unavailable_or_changed") from error


def _directory_key(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _file_key(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _regular_file(metadata: os.stat_result) -> bool:
    return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1


def _open_directory(directory: Path) -> int:
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("config_directory_open_unsupported")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    # codeql[py/path-injection] The root is opened component-by-component with O_NOFOLLOW before fixed child access.
    descriptor = os.open(directory.anchor, flags)
    try:
        for component in directory.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_stable_bytes(descriptor: int, opened: os.stat_result) -> bytes:
    chunks: list[bytes] = []
    remaining = opened.st_size + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) != opened.st_size or _file_key(os.fstat(descriptor)) != _file_key(opened):
        raise ConfigFileTrustError("config_file_changed_during_read")
    return payload


def _read_posix_config_bytes(directory: Path, canonical_directory: Path, filename: str) -> bytes | None:
    # codeql[py/path-injection] This verifies the chosen root before a descriptor-pinned, allowlisted child read.
    parent_before = canonical_directory.lstat()
    if not stat.S_ISDIR(parent_before.st_mode):
        raise ConfigFileTrustError("config_parent_not_directory")
    parent_descriptor = _open_directory(canonical_directory)
    try:
        parent_opened = os.fstat(parent_descriptor)
        if _directory_key(parent_before) != _directory_key(parent_opened):
            raise ConfigFileTrustError("config_directory_changed")
        try:
            before = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not _regular_file(before):
            raise ConfigFileTrustError("config_file_not_single_regular_file")
        # The directory descriptor pins containment; O_NONBLOCK also prevents a
        # concurrent replacement with a FIFO from hanging before fstat rejects it.
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(filename, flags, dir_fd=parent_descriptor)
        try:
            opened = os.fstat(descriptor)
            if not _regular_file(opened) or _file_key(before) != _file_key(opened):
                raise ConfigFileTrustError("config_file_changed_before_read")
            payload = _read_stable_bytes(descriptor, opened)
            after = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
            if _file_key(after) != _file_key(opened):
                raise ConfigFileTrustError("config_file_changed_during_read")
            # codeql[py/path-injection] This rechecks the descriptor-pinned root after the fixed child read.
            if _directory_key(canonical_directory.lstat()) != _directory_key(parent_opened):
                raise ConfigFileTrustError("config_directory_changed")
            # codeql[py/path-injection] This detects alias changes after containment is established.
            if directory.resolve(strict=True) != canonical_directory:
                raise ConfigFileTrustError("config_directory_alias_changed")
            return payload
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def _read_windows_config_bytes(directory: Path, canonical_directory: Path, filename: str) -> bytes | None:
    candidate = os.path.abspath(os.path.join(canonical_directory, filename))
    parent_prefix = os.fspath(canonical_directory).rstrip(os.sep) + os.sep
    if not candidate.startswith(parent_prefix):
        raise ConfigFileTrustError("config_file_outside_directory")
    # codeql[py/path-injection] This verifies the chosen root; candidate uses only the allowlisted filename.
    parent_before = canonical_directory.lstat()
    try:
        before = os.lstat(candidate)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(parent_before.st_mode) or not _regular_file(before):
        raise ConfigFileTrustError("config_file_not_single_regular_file")
    expected_resolved_path = os.path.realpath(candidate)
    if not expected_resolved_path.startswith(parent_prefix):
        raise ConfigFileTrustError("config_file_outside_directory")
    descriptor = open_windows_locked_regular_descriptor(candidate, expected_resolved_path=expected_resolved_path)
    try:
        opened = os.fstat(descriptor)
        # CRT descriptor identities differ from path identities on Windows.
        # The native handle denies writes/deletes, so compare each with its own
        # before/after stat while the handle remains locked.
        if not _regular_file(opened) or _file_key(os.lstat(candidate)) != _file_key(before):
            raise ConfigFileTrustError("config_file_changed_before_read")
        payload = _read_stable_bytes(descriptor, opened)
        if _file_key(os.lstat(candidate)) != _file_key(before):
            raise ConfigFileTrustError("config_file_changed_during_read")
        # codeql[py/path-injection] This rechecks the fixed root while the Windows descriptor denies replacement.
        if _directory_key(canonical_directory.lstat()) != _directory_key(parent_before):
            raise ConfigFileTrustError("config_directory_changed")
        # codeql[py/path-injection] This only detects a selected-directory alias change after the locked child read.
        if directory.resolve(strict=True) != canonical_directory:
            raise ConfigFileTrustError("config_directory_alias_changed")
        return payload
    finally:
        os.close(descriptor)

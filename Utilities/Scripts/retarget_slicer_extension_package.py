#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "packaging>=24.2,<27",
# ]
# ///

"""Audit and structurally retarget pure-Python 3D Slicer extension packages.

This tool changes package layout and target metadata. It does not certify
runtime compatibility. The investigation and safety boundary are documented in
``slicer-scripted-extension-package-retargeting-report.md``.
"""

from __future__ import annotations

import argparse
import ast
import binascii
import contextlib
import contextvars
import dataclasses
import datetime as dt
import email.parser
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
from typing import BinaryIO
from collections.abc import Iterable, Sequence
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from packaging.tags import Tag, parse_tag
from packaging.utils import InvalidWheelFilename, parse_wheel_filename


TOOL_NAME = "retarget-slicer-extension-package"
TOOL_VERSION = "0.1.0"
AUDIT_SCHEMA_VERSION = 1
RUNTIME_COMPATIBILITY_LABEL = "structurally retargeted; runtime compatibility not verified"

PACKAGE_SERVER_APP_ID = "5f4474d0e1d8c75dfc705482"
PACKAGE_SERVER_URL = f"https://slicer-packages.kitware.com/api/v1/app/{PACKAGE_SERVER_APP_ID}/package"
EXTENSION_STATS_URL = "https://raw.githubusercontent.com/Slicer/SlicerDeveloperToolsForExtensions/master/ExtensionStats/ExtensionStats.py"
NETWORK_TIMEOUT_SECONDS = 10
MAX_NETWORK_RESPONSE_BYTES = 4 * 1024 * 1024

DEFAULT_MAX_MEMBERS = 50_000
DEFAULT_MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MAX_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MAX_METADATA_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_NESTING = 3
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_TAR_METADATA_ENTRY_BYTES = 1024 * 1024
MAX_TAR_METADATA_CHAIN = 16
MAX_ARCHIVE_PATH_BYTES = 16 * 1024
MAX_ARCHIVE_COMPONENT_BYTES = 255
COPY_CHUNK_SIZE = 1024 * 1024
TEXT_SCAN_LIMIT = 2 * 1024 * 1024
WHEEL_METADATA_LIMIT = 1024 * 1024
ZIP_MINIMUM_YEAR = 1980
ZIP_MAXIMUM_YEAR = 2107

VERSIONED_ROOTS = frozenset({"lib", "share", "include", "libexec"})
TARGET_OPERATING_SYSTEMS = ("linux", "win", "macosx")
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
ARCH_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
TARGET_VERSION_PATTERN = re.compile(r"5\.(\d+)(?:\.(\d+))?\Z")
SLICER_PATH_VERSION_PATTERN = re.compile(r"Slicer-(5\.\d+)\Z")
MAC_EXTENSIONS_PATTERN = re.compile(r"Extensions-([0-9]+)\Z")
PEP3147_BYTECODE_PATTERN = re.compile(
    r"(?P<stem>.+)\.[^.]+(?:\.opt-[0-9]+)?\.py[co]\Z",
)
CONVENTIONAL_BASENAME_PATTERN = re.compile(
    r"(?P<revision>[0-9]+)-"
    r"(?P<os>linux|win|macosx)-"
    r"(?P<arch>[A-Za-z0-9][A-Za-z0-9._]*)-"
    r"(?P<tail>.+)-"
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})\Z",
)

NATIVE_SUFFIXES = (
    ".dll",
    ".dylib",
    ".pyd",
    ".exe",
    ".com",
    ".scr",
    ".cpl",
    ".ocx",
    ".sys",
    ".drv",
    ".obj",
    ".o",
    ".a",
    ".lib",
)
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"} | {f"COM{index}" for index in range(1, 10)} | {f"LPT{index}" for index in range(1, 10)},
)
MACH_O_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
COFF_MACHINE_TYPES = {
    0x014C,  # i386
    0x0166,  # MIPS little-endian
    0x01C0,  # ARM
    0x01C4,  # ARMv7
    0x01F0,  # PowerPC
    0x0200,  # IA64
    0x0EBC,  # EFI byte code
    0x5032,  # RISC-V 32
    0x5064,  # RISC-V 64
    0x5128,  # RISC-V 128
    0x6232,  # LoongArch 32
    0x6264,  # LoongArch 64
    0x8664,  # AMD64
    0xA641,  # ARM64EC
    0xA64E,  # ARM64X
    0xAA64,  # ARM64
}
TEXT_EXTENSIONS = frozenset(
    {
        ".bat",
        ".cfg",
        ".cmake",
        ".csv",
        ".ini",
        ".json",
        ".md",
        ".ps1",
        ".py",
        ".rst",
        ".s4ext",
        ".sh",
        ".toml",
        ".txt",
        ".ui",
        ".xml",
        ".yaml",
        ".yml",
    },
)
BINARY_RESOURCE_SUFFIXES = frozenset(
    {
        ".bmp",
        ".dcm",
        ".gif",
        ".h5",
        ".hdf5",
        ".ico",
        ".jpeg",
        ".jpg",
        ".mat",
        ".mha",
        ".mhd",
        ".nii",
        ".nii.gz",
        ".nrrd",
        ".nrrd.gz",
        ".npy",
        ".pdf",
        ".ply",
        ".png",
        ".stl",
        ".tif",
        ".tiff",
        ".ttf",
        ".vtk",
        ".vtp",
        ".vtu",
        ".wav",
        ".webp",
    },
)
ZIP_PATH_EXTRA_FIELD = 0x7075
ZIP_TYPE_EXTRA_FIELDS = frozenset({0x6C78, 0x756E})
WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>"|?*')
ASCII_DECIMAL_PATTERN = re.compile(r"[0-9]+\Z")
ACTIVE_TAR_SCAN_BUDGET: contextvars.ContextVar[ScanBudget | None] = contextvars.ContextVar(
    "active_tar_scan_budget",
    default=None,
)
ACTIVE_TAR_METADATA_DEPTH: contextvars.ContextVar[int] = contextvars.ContextVar(
    "active_tar_metadata_depth",
    default=0,
)


class RetargetError(Exception):
    """Expected validation or operational failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        operational: bool = False,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path
        self.operational = operational
        self.details = details or {}


class BoundedTarInfo(tarfile.TarInfo):
    """TarInfo that bounds metadata records processed before member yield."""

    def _check_metadata_size(self) -> None:
        if self.size > MAX_TAR_METADATA_ENTRY_BYTES:
            raise RetargetError(
                "archive-metadata-limit",
                (f"TAR metadata entry exceeds the supported {MAX_TAR_METADATA_ENTRY_BYTES}-byte limit."),
                path=self.name,
            )

    def _begin_metadata(
        self,
        tar_file: tarfile.TarFile,
    ) -> contextvars.Token[int]:
        self._check_metadata_size()
        budget = ACTIVE_TAR_SCAN_BUDGET.get()
        if not isinstance(budget, ScanBudget):
            raise RetargetError(
                "archive-metadata-limit",
                "Internal TAR metadata budget is unavailable.",
                path=self.name,
                operational=True,
            )
        budget.consume_member(label=f"TAR metadata:{self.name}")
        budget.consume_metadata_bytes(
            self._block(self.size),
            label=f"TAR metadata:{self.name}",
        )
        depth = ACTIVE_TAR_METADATA_DEPTH.get() + 1
        if depth > MAX_TAR_METADATA_CHAIN:
            raise RetargetError(
                "archive-metadata-limit",
                (f"TAR metadata chain exceeds the supported depth of {MAX_TAR_METADATA_CHAIN}."),
                path=self.name,
            )
        return ACTIVE_TAR_METADATA_DEPTH.set(depth)

    @staticmethod
    def _end_metadata(depth_token: contextvars.Token[int]) -> None:
        ACTIVE_TAR_METADATA_DEPTH.reset(depth_token)

    def _proc_pax(self, tar_file: tarfile.TarFile) -> tarfile.TarInfo:
        depth_token = self._begin_metadata(tar_file)
        try:
            return super()._proc_pax(tar_file)
        finally:
            self._end_metadata(depth_token)

    def _proc_gnulong(
        self,
        tar_file: tarfile.TarFile,
    ) -> tarfile.TarInfo:
        depth_token = self._begin_metadata(tar_file)
        try:
            return super()._proc_gnulong(tar_file)
        finally:
            self._end_metadata(depth_token)

    def _proc_sparse(self, tar_file: tarfile.TarFile) -> tarfile.TarInfo:
        del tar_file
        raise RetargetError(
            "archive-special-file",
            "GNU sparse TAR entries are not permitted.",
            path=self.name,
        )

    def _proc_gnusparse_00(
        self,
        next_info: tarfile.TarInfo,
        raw_headers: list[tuple[int, bytes, bytes]],
    ) -> None:
        del next_info, raw_headers
        raise RetargetError(
            "archive-special-file",
            "PAX sparse TAR entries are not permitted.",
            path=self.name,
        )

    def _proc_gnusparse_01(
        self,
        next_info: tarfile.TarInfo,
        pax_headers: dict[str, str],
    ) -> None:
        del next_info, pax_headers
        raise RetargetError(
            "archive-special-file",
            "PAX sparse TAR entries are not permitted.",
            path=self.name,
        )

    def _proc_gnusparse_10(
        self,
        next_info: tarfile.TarInfo,
        pax_headers: dict[str, str],
        tar_file: tarfile.TarFile,
    ) -> None:
        del next_info, pax_headers, tar_file
        raise RetargetError(
            "archive-special-file",
            "PAX sparse TAR entries are not permitted.",
            path=self.name,
        )


@dataclasses.dataclass(frozen=True, order=True)
class SafeArchivePath:
    """A validated, normalized, relative POSIX archive path."""

    value: str

    @property
    def parts(self) -> tuple[str, ...]:
        return tuple(self.value.split("/"))

    @property
    def name(self) -> str:
        return self.parts[-1]

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.value).suffix

    @property
    def parent(self) -> SafeArchivePath | None:
        parts = self.parts
        if len(parts) == 1:
            return None
        return safe_path_from_parts(parts[:-1])

    def child(self, *parts: str) -> SafeArchivePath:
        return safe_path_from_parts((*self.parts, *parts))


@dataclasses.dataclass
class Finding:
    code: str
    severity: str
    message: str
    path: str | None = None
    details: dict[str, object] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
        if self.path is not None:
            result["path"] = self.path
        if self.details:
            result["details"] = self.details
        return result


@dataclasses.dataclass
class ScanBudget:
    max_members: int = DEFAULT_MAX_MEMBERS
    max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES
    max_nesting: int = DEFAULT_MAX_NESTING
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES
    max_metadata_bytes: int = DEFAULT_MAX_METADATA_BYTES
    members: int = 0
    expanded_bytes: int = 0
    metadata_bytes: int = 0

    def consume_member(self, *, label: str) -> None:
        self.members += 1
        if self.members > self.max_members:
            raise RetargetError(
                "archive-member-limit",
                f"Archive member limit exceeded ({self.max_members}).",
                path=label,
            )

    def consume_bytes(self, count: int, *, label: str) -> None:
        if count < 0:
            raise RetargetError(
                "invalid-expanded-size",
                "A negative expanded byte count was reported.",
                path=label,
            )
        self.expanded_bytes += count
        if self.expanded_bytes > self.max_expanded_bytes:
            raise RetargetError(
                "archive-size-limit",
                (f"Expanded archive data exceeds the configured limit ({self.max_expanded_bytes} bytes)."),
                path=label,
            )

    def consume_metadata_bytes(self, count: int, *, label: str) -> None:
        if count < 0:
            raise RetargetError(
                "invalid-expanded-size",
                "A negative metadata byte count was reported.",
                path=label,
            )
        self.metadata_bytes += count
        if self.metadata_bytes > self.max_metadata_bytes:
            raise RetargetError(
                "archive-metadata-limit",
                (f"Aggregate archive metadata exceeds the configured limit ({self.max_metadata_bytes} bytes)."),
                path=label,
            )

    def check_depth(self, depth: int, *, label: str) -> None:
        if depth > self.max_nesting:
            raise RetargetError(
                "archive-nesting-limit",
                f"Nested archive depth exceeds the configured limit ({self.max_nesting}).",
                path=label,
            )


@dataclasses.dataclass
class StoredFile:
    path: SafeArchivePath
    storage_path: Path
    size: int
    sha256: str
    source_mode: int


@dataclasses.dataclass
class StagedArchive:
    format: str
    files: dict[str, StoredFile]
    directories: set[str]


@dataclasses.dataclass
class ExtensionMetadata:
    name: str
    scm: str
    scmrevision: str
    depends: list[str]
    recommends: list[str]
    fields: dict[str, str]


@dataclasses.dataclass
class SourceNameMetadata:
    revision: str | None = None
    os: str | None = None
    arch: str | None = None
    package_date: dt.date | None = None


@dataclasses.dataclass
class InspectedPackage:
    input_path: Path
    archive_format: str
    archive_sha256: str
    archive_size: int
    outer_root: str
    layout: str
    mac_revision: str | None
    payload_files: dict[str, StoredFile]
    payload_directories: set[str]
    source_version: str
    metadata: ExtensionMetadata
    name_metadata: SourceNameMetadata
    findings: list[Finding]
    eligible_targets: list[str]


@dataclasses.dataclass
class Target:
    version: str
    path_version: str
    revision: str
    os: str
    arch: str
    revision_source: str
    publication_status: str
    lookup_attempts: list[dict[str, object]]


@dataclasses.dataclass
class OutputPlan:
    root_name: str
    archive_format: str
    archive_suffix: str
    payload_files: dict[str, StoredFile]
    payload_directories: set[str]
    archive_files: dict[str, StoredFile]
    archive_directories: set[str]
    file_modes: dict[str, int]
    payload_file_modes: dict[str, int]
    package_date: dt.date


def new_audit(command: str, input_path: Path) -> dict[str, object]:
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "command": command,
        "status": "failed",
        "runtime_compatibility": "not_verified",
        "source": {"path": str(input_path)},
        "target": None,
        "findings": [],
        "transformations": [],
        "output": None,
    }


def add_finding(
    findings: list[Finding],
    code: str,
    severity: str,
    message: str,
    *,
    path: str | None = None,
    details: dict[str, object] | None = None,
) -> None:
    candidate = Finding(code, severity, message, path, details or {})
    key = (candidate.code, candidate.severity, candidate.path, candidate.message)
    if any((finding.code, finding.severity, finding.path, finding.message) == key for finding in findings):
        return
    findings.append(candidate)


def add_error_to_audit(audit: dict[str, object], error: RetargetError) -> None:
    findings = audit.setdefault("findings", [])
    assert isinstance(findings, list)
    finding: dict[str, object] = {
        "code": error.code,
        "severity": "error",
        "message": error.message,
    }
    if error.path:
        finding["path"] = error.path
    if error.details:
        finding["details"] = error.details
    findings.append(finding)
    audit["status"] = "failed" if error.operational else "rejected"


def validate_member_name(raw_name: str, *, is_directory: bool) -> SafeArchivePath:
    if not isinstance(raw_name, str) or not raw_name:
        raise RetargetError("unsafe-path", "Archive member name is empty.")
    if "\\" in raw_name:
        raise RetargetError(
            "unsafe-path",
            "Backslashes are not permitted in archive member paths.",
            path=raw_name,
        )
    if raw_name.startswith("/") or raw_name.startswith("//"):
        raise RetargetError(
            "unsafe-path",
            "Absolute archive member path rejected.",
            path=raw_name,
        )
    if re.match(r"^[A-Za-z]:", raw_name):
        raise RetargetError(
            "unsafe-path",
            "Drive-letter archive member path rejected.",
            path=raw_name,
        )
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in raw_name):
        raise RetargetError(
            "unsafe-path",
            "Control or surrogate characters are not permitted in archive paths.",
            path=raw_name,
        )

    candidate = raw_name
    if is_directory:
        if not candidate.endswith("/") and raw_name:
            candidate = raw_name
        elif candidate.endswith("//"):
            raise RetargetError(
                "unsafe-path",
                "Directory paths may have only one trailing slash.",
                path=raw_name,
            )
        else:
            candidate = candidate[:-1]
    elif candidate.endswith("/"):
        raise RetargetError(
            "path-kind-mismatch",
            "Regular file path unexpectedly ends in a slash.",
            path=raw_name,
        )

    raw_parts = candidate.split("/")
    if not raw_parts or any(part in {"", ".", ".."} for part in raw_parts):
        raise RetargetError(
            "unsafe-path",
            "Empty, dot, and parent components are not permitted in archive paths.",
            path=raw_name,
        )
    normalized_parts: list[str] = []
    for part in raw_parts:
        normalized = unicodedata.normalize("NFC", part)
        if normalized != part:
            raise RetargetError(
                "unsafe-path",
                "Non-NFC archive paths are rejected to avoid normalization collisions.",
                path=raw_name,
            )
        if len(normalized.encode("utf-8")) > MAX_ARCHIVE_COMPONENT_BYTES:
            raise RetargetError(
                "unsafe-path",
                (f"Archive path component exceeds the supported {MAX_ARCHIVE_COMPONENT_BYTES}-byte limit."),
                path=raw_name,
            )
        normalized_parts.append(normalized)
    normalized_path = "/".join(normalized_parts)
    if len(normalized_path.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES:
        raise RetargetError(
            "unsafe-path",
            (f"Archive member path exceeds the supported {MAX_ARCHIVE_PATH_BYTES}-byte limit."),
            path=raw_name,
        )
    return SafeArchivePath(normalized_path)


def safe_path_from_parts(parts: Iterable[str]) -> SafeArchivePath:
    part_tuple = tuple(parts)
    if not part_tuple:
        raise RetargetError("unsafe-path", "An empty logical path was constructed.")
    return validate_member_name("/".join(part_tuple), is_directory=False)


def validate_entry_set(
    files: Iterable[SafeArchivePath],
    directories: Iterable[SafeArchivePath],
) -> None:
    file_values = {item.value for item in files}
    directory_values = {item.value for item in directories}
    overlap = file_values & directory_values
    if overlap:
        path = sorted(overlap)[0]
        raise RetargetError(
            "path-kind-conflict",
            "The same archive path is declared as both a file and directory.",
            path=path,
        )
    for file_value in sorted(file_values):
        parts = file_value.split("/")
        for index in range(1, len(parts)):
            prefix = "/".join(parts[:index])
            if prefix in file_values:
                raise RetargetError(
                    "path-prefix-conflict",
                    "A regular file is also used as a parent directory.",
                    path=file_value,
                    details={"conflicting_prefix": prefix},
                )
    for directory_value in sorted(directory_values):
        parts = directory_value.split("/")
        for index in range(1, len(parts)):
            prefix = "/".join(parts[:index])
            if prefix in file_values:
                raise RetargetError(
                    "path-prefix-conflict",
                    "A regular file is also used as a parent directory.",
                    path=directory_value,
                    details={"conflicting_prefix": prefix},
                )


def ensure_single_root(paths: Iterable[SafeArchivePath]) -> str:
    roots = {path.parts[0] for path in paths}
    if len(roots) != 1:
        raise RetargetError(
            "archive-root-count",
            "The package must contain exactly one coherent top-level directory.",
            details={"roots": sorted(roots)},
        )
    return next(iter(roots))


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(COPY_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def private_archive_suffix(path: Path) -> str:
    lowered = path.name.casefold()
    if lowered.endswith(".tar.gz"):
        return ".tar.gz"
    if lowered.endswith(".tgz"):
        return ".tgz"
    if lowered.endswith(".zip"):
        return ".zip"
    return ".invalid"


def snapshot_input_archive(
    input_path: Path,
    destination: Path,
    budget: ScanBudget,
) -> tuple[int, str]:
    """Copy one stable input descriptor into private storage and hash it."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(input_path, flags)
        with (
            os.fdopen(descriptor, "rb", closefd=True) as source,
            destination.open("xb") as output,
        ):
            descriptor = None
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise RetargetError(
                    "input-not-file",
                    "Input package is not a regular file.",
                    path=str(input_path),
                )
            if before.st_size > budget.max_archive_bytes:
                raise RetargetError(
                    "archive-raw-size-limit",
                    (f"Input archive exceeds the configured raw-size limit ({budget.max_archive_bytes} bytes)."),
                    path=str(input_path),
                )

            digest = hashlib.sha256()
            size = 0
            while chunk := source.read(COPY_CHUNK_SIZE):
                size += len(chunk)
                if size > budget.max_archive_bytes:
                    raise RetargetError(
                        "archive-raw-size-limit",
                        (f"Input archive exceeds the configured raw-size limit ({budget.max_archive_bytes} bytes)."),
                        path=str(input_path),
                    )
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
            after = os.fstat(source.fileno())

        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        try:
            current = input_path.stat()
        except OSError as exc:
            raise RetargetError(
                "input-changed",
                "Input package changed while it was being copied.",
                path=str(input_path),
                operational=True,
            ) from exc
        if identity_before != identity_after or (current.st_dev, current.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise RetargetError(
                "input-changed",
                "Input package changed while it was being copied.",
                path=str(input_path),
            )
        if size != before.st_size:
            raise RetargetError(
                "input-changed",
                "Input package size changed while it was being copied.",
                path=str(input_path),
            )
        return size, digest.hexdigest()
    except RetargetError:
        raise
    except OSError as exc:
        raise RetargetError(
            "input-read-failed",
            "Unable to snapshot the input package.",
            path=str(input_path),
            operational=True,
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def copy_bounded(
    source: BinaryIO,
    destination: BinaryIO,
    budget: ScanBudget,
    *,
    label: str,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(COPY_CHUNK_SIZE):
        budget.consume_bytes(len(chunk), label=label)
        destination.write(chunk)
        digest.update(chunk)
        size += len(chunk)
    return size, digest.hexdigest()


def allocate_storage_path(storage_directory: Path, ordinal: int) -> Path:
    return storage_directory / f"{ordinal:08d}.payload"


def detect_archive_format(path: Path, *, require_official_suffix: bool) -> str:
    suffix_name = path.name.lower()
    with path.open("rb") as stream:
        magic = stream.read(8)
    if zipfile.is_zipfile(path):
        if require_official_suffix and not suffix_name.endswith(".zip"):
            raise RetargetError(
                "archive-suffix-mismatch",
                "ZIP input must use the .zip suffix.",
                path=str(path),
            )
        return "zip"
    if magic.startswith(b"\x1f\x8b"):
        if require_official_suffix and not (suffix_name.endswith(".tar.gz") or suffix_name.endswith(".tgz")):
            raise RetargetError(
                "archive-suffix-mismatch",
                "TGZ input must use the .tar.gz or .tgz suffix.",
                path=str(path),
            )
        return "tgz"
    raise RetargetError(
        "unsupported-archive",
        "Only official ZIP and gzip-compressed TAR packages are supported.",
        path=str(path),
    )


def preflight_zip_central_directory(
    archive_path: Path,
    budget: ScanBudget,
    *,
    label: str,
) -> None:
    """Bound central-directory allocation before ZipFile parses it."""

    try:
        archive_size = archive_path.stat().st_size
        if archive_size > budget.max_archive_bytes:
            raise RetargetError(
                "archive-raw-size-limit",
                (f"Archive exceeds the configured raw-size limit ({budget.max_archive_bytes} bytes)."),
                path=label,
            )
        tail_size = min(archive_size, 22 + 65_535)
        with archive_path.open("rb") as stream:
            stream.seek(archive_size - tail_size)
            tail = stream.read(tail_size)
    except RetargetError:
        raise
    except OSError as exc:
        raise RetargetError(
            "input-read-failed",
            "Unable to preflight ZIP metadata.",
            path=label,
            operational=True,
        ) from exc

    signature = b"PK\x05\x06"
    end_record: tuple[int, int, int, int, int, int, int] | None = None
    search_end = len(tail)
    while True:
        offset = tail.rfind(signature, 0, search_end)
        if offset < 0:
            break
        if offset + 22 <= len(tail):
            fields = struct.unpack_from("<4H2LH", tail, offset + 4)
            if offset + 22 + fields[-1] == len(tail):
                end_record = fields
                break
        search_end = offset
    if end_record is None:
        raise RetargetError(
            "malformed-archive",
            "ZIP end-of-central-directory record is missing or ambiguous.",
            path=label,
        )
    end_record_offset = archive_size - tail_size + offset

    (
        disk_number,
        central_disk,
        entries_on_disk,
        total_entries,
        central_size,
        central_offset,
        _comment_size,
    ) = end_record
    if disk_number != 0 or central_disk != 0 or entries_on_disk != total_entries:
        raise RetargetError(
            "unsupported-archive",
            "Multi-disk ZIP archives are not supported.",
            path=label,
        )
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise RetargetError(
            "zip64-central-directory-unsupported",
            "ZIP64 central directories are outside this tool's bounded package scope.",
            path=label,
        )
    if budget.members + total_entries > budget.max_members:
        raise RetargetError(
            "archive-member-limit",
            f"Archive member limit exceeded ({budget.max_members}).",
            path=label,
        )
    if central_size > MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        raise RetargetError(
            "archive-metadata-limit",
            (f"ZIP central directory exceeds the supported {MAX_ZIP_CENTRAL_DIRECTORY_BYTES}-byte limit."),
            path=label,
        )
    budget.consume_metadata_bytes(
        central_size,
        label=f"{label}!ZIP central directory",
    )
    if central_size > archive_size:
        raise RetargetError(
            "malformed-archive",
            "ZIP central directory is larger than the archive.",
            path=label,
        )
    if central_offset + central_size != end_record_offset:
        raise RetargetError(
            "ambiguous-zip-metadata",
            "ZIP central-directory offset or size is inconsistent.",
            path=label,
        )

    try:
        with archive_path.open("rb") as stream:
            stream.seek(central_offset)
            for _index in range(total_entries):
                fixed_header = stream.read(46)
                if len(fixed_header) != 46 or fixed_header[:4] != b"PK\x01\x02":
                    raise RetargetError(
                        "ambiguous-zip-metadata",
                        "ZIP central-directory entry count is inconsistent.",
                        path=label,
                    )
                name_size, extra_size, comment_size = struct.unpack_from(
                    "<3H",
                    fixed_header,
                    28,
                )
                if name_size > MAX_ARCHIVE_PATH_BYTES:
                    raise RetargetError(
                        "unsafe-path",
                        (f"ZIP encoded member name exceeds the supported {MAX_ARCHIVE_PATH_BYTES}-byte limit."),
                        path=label,
                    )
                variable_size = name_size + extra_size + comment_size
                if len(stream.read(variable_size)) != variable_size:
                    raise RetargetError(
                        "malformed-archive",
                        "ZIP central-directory entry is truncated.",
                        path=label,
                    )
            if stream.tell() != central_offset + central_size:
                raise RetargetError(
                    "ambiguous-zip-metadata",
                    "ZIP central-directory record count or size is inconsistent.",
                    path=label,
                )
    except RetargetError:
        raise
    except OSError as exc:
        raise RetargetError(
            "input-read-failed",
            "Unable to validate ZIP central-directory records.",
            path=label,
            operational=True,
        ) from exc


def validate_zip_extra_fields(
    extra: bytes,
    *,
    expected_name: str,
    raw_name: bytes,
    label: str,
) -> str | None:
    """Reject ZIP extra fields that can change libarchive path or type."""

    offset = 0
    unicode_path: str | None = None
    while offset < len(extra):
        remaining = len(extra) - offset
        if remaining < 4:
            if any(extra[offset:]):
                raise RetargetError(
                    "malformed-archive",
                    "ZIP extra data has a truncated field header.",
                    path=label,
                )
            break
        field_id, field_size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        field_end = offset + field_size
        if field_end > len(extra):
            raise RetargetError(
                "malformed-archive",
                "ZIP extra data has a truncated field body.",
                path=label,
            )
        data = extra[offset:field_end]
        offset = field_end
        if field_id in ZIP_TYPE_EXTRA_FIELDS:
            raise RetargetError(
                "ambiguous-zip-type",
                (f"ZIP extra field 0x{field_id:04x} can override the validated entry type."),
                path=label,
            )
        if field_id != ZIP_PATH_EXTRA_FIELD:
            continue
        if unicode_path is not None:
            raise RetargetError(
                "ambiguous-zip-path",
                "ZIP entry has more than one Unicode Path extra field.",
                path=label,
            )
        if len(data) < 5 or data[0] != 1:
            raise RetargetError(
                "ambiguous-zip-path",
                "ZIP Unicode Path extra field is malformed.",
                path=label,
            )
        expected_crc = binascii.crc32(raw_name) & 0xFFFFFFFF
        stored_crc = struct.unpack_from("<L", data, 1)[0]
        if stored_crc != expected_crc:
            raise RetargetError(
                "ambiguous-zip-path",
                "ZIP Unicode Path extra field has a mismatched filename CRC.",
                path=label,
            )
        try:
            unicode_path = data[5:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RetargetError(
                "ambiguous-zip-path",
                "ZIP Unicode Path extra field is not valid UTF-8.",
                path=label,
            ) from exc
        if unicode_path != expected_name:
            raise RetargetError(
                "ambiguous-zip-path",
                "ZIP alternate pathname differs from the validated member name.",
                path=label,
                details={"alternate_path": unicode_path},
            )
    return unicode_path


def unique_zip_extra_field(
    extra: bytes,
    field_id: int,
    *,
    label: str,
) -> bytes | None:
    offset = 0
    result: bytes | None = None
    while offset + 4 <= len(extra):
        candidate_id, field_size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        field_end = offset + field_size
        if field_end > len(extra):
            return None
        if candidate_id == field_id:
            if result is not None:
                raise RetargetError(
                    "ambiguous-zip-metadata",
                    f"ZIP entry has duplicate 0x{field_id:04x} extra fields.",
                    path=label,
                )
            result = extra[offset:field_end]
        offset = field_end
    return result


def validate_local_zip64_sizes(
    local_extra: bytes,
    *,
    compressed_size: int,
    uncompressed_size: int,
    info: zipfile.ZipInfo,
    label: str,
) -> None:
    if compressed_size != 0xFFFFFFFF and uncompressed_size != 0xFFFFFFFF:
        return
    data = unique_zip_extra_field(local_extra, 0x0001, label=label)
    if data is None:
        raise RetargetError(
            "ambiguous-zip-metadata",
            "ZIP64 local sizes lack a ZIP64 extra field.",
            path=label,
        )
    offset = 0
    for is_sentinel, expected, size_name in (
        (uncompressed_size == 0xFFFFFFFF, info.file_size, "uncompressed"),
        (compressed_size == 0xFFFFFFFF, info.compress_size, "compressed"),
    ):
        if not is_sentinel:
            continue
        if offset + 8 > len(data):
            raise RetargetError(
                "ambiguous-zip-metadata",
                f"ZIP64 local {size_name} size is truncated.",
                path=label,
            )
        local_size = struct.unpack_from("<Q", data, offset)[0]
        offset += 8
        if local_size != expected:
            raise RetargetError(
                "ambiguous-zip-metadata",
                f"ZIP64 local and central {size_name} sizes disagree.",
                path=label,
            )


def read_and_validate_local_zip_header(
    raw_archive: BinaryIO,
    info: zipfile.ZipInfo,
    budget: ScanBudget,
    *,
    label: str,
) -> str | None:
    try:
        raw_archive.seek(info.header_offset)
        fixed_header = raw_archive.read(30)
        if len(fixed_header) != 30:
            raise RetargetError(
                "malformed-archive",
                "ZIP local file header is truncated.",
                path=label,
            )
        (
            signature,
            _version,
            flags,
            compression,
            _time,
            _date,
            crc,
            compressed_size,
            uncompressed_size,
            name_size,
            extra_size,
        ) = struct.unpack("<4s5H3L2H", fixed_header)
        if signature != b"PK\x03\x04":
            raise RetargetError(
                "malformed-archive",
                "ZIP local file header signature is invalid.",
                path=label,
            )
        if name_size > MAX_ARCHIVE_PATH_BYTES:
            raise RetargetError(
                "unsafe-path",
                (f"ZIP encoded local member name exceeds the supported {MAX_ARCHIVE_PATH_BYTES}-byte limit."),
                path=label,
            )
        budget.consume_metadata_bytes(
            30 + name_size + extra_size,
            label=f"{label}!ZIP local file metadata",
        )
        raw_name = raw_archive.read(name_size)
        local_extra = raw_archive.read(extra_size)
        if len(raw_name) != name_size or len(local_extra) != extra_size:
            raise RetargetError(
                "malformed-archive",
                "ZIP local file header name or extra data is truncated.",
                path=label,
            )
    except RetargetError:
        raise
    except OSError as exc:
        raise RetargetError(
            "input-read-failed",
            "Unable to inspect ZIP local file metadata.",
            path=label,
            operational=True,
        ) from exc

    if flags != info.flag_bits:
        raise RetargetError(
            "ambiguous-zip-flags",
            "ZIP local and central flag fields disagree.",
            path=label,
        )
    if flags & 0x41:
        raise RetargetError(
            "encrypted-archive-member",
            "Encrypted ZIP members are not supported.",
            path=label,
        )
    if compression != info.compress_type:
        raise RetargetError(
            "ambiguous-zip-metadata",
            "ZIP local and central compression methods disagree.",
            path=label,
        )
    if not flags & 0x08:
        if crc != info.CRC:
            raise RetargetError(
                "ambiguous-zip-metadata",
                "ZIP local and central CRC values disagree.",
                path=label,
            )
        if compressed_size not in {info.compress_size, 0xFFFFFFFF}:
            raise RetargetError(
                "ambiguous-zip-metadata",
                "ZIP local and central compressed sizes disagree.",
                path=label,
            )
        if uncompressed_size not in {info.file_size, 0xFFFFFFFF}:
            raise RetargetError(
                "ambiguous-zip-metadata",
                "ZIP local and central uncompressed sizes disagree.",
                path=label,
            )
        validate_local_zip64_sizes(
            local_extra,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            info=info,
            label=label,
        )
    encoding = "utf-8" if flags & 0x800 else "cp437"
    try:
        local_name = raw_name.decode(encoding)
    except UnicodeDecodeError as exc:
        raise RetargetError(
            "ambiguous-zip-path",
            "ZIP local member name cannot be decoded unambiguously.",
            path=label,
        ) from exc
    if local_name != info.orig_filename:
        raise RetargetError(
            "ambiguous-zip-path",
            "ZIP local and central member names disagree.",
            path=label,
        )
    return validate_zip_extra_fields(
        local_extra,
        expected_name=info.filename,
        raw_name=raw_name,
        label=label,
    )


def stage_zip_archive(
    archive_path: Path,
    storage_directory: Path,
    budget: ScanBudget,
    *,
    label: str,
) -> StagedArchive:
    files: dict[str, StoredFile] = {}
    directories: set[str] = set()
    inventory: list[tuple[zipfile.ZipInfo, SafeArchivePath, bool, int]] = []
    preflight_zip_central_directory(archive_path, budget, label=label)
    try:
        with (
            archive_path.open("rb") as raw_archive,
            zipfile.ZipFile(archive_path, mode="r") as archive,
        ):
            for info in archive.infolist():
                budget.consume_member(label=f"{label}!{info.filename}")
                member_label = f"{label}!{info.filename}"
                if "\0" in info.orig_filename:
                    raise RetargetError(
                        "ambiguous-zip-path",
                        "ZIP raw member name contains a NUL character.",
                        path=member_label,
                    )
                if info.flag_bits & 0x41:
                    raise RetargetError(
                        "encrypted-archive-member",
                        "Encrypted ZIP members are not supported.",
                        path=member_label,
                    )
                encoding = "utf-8" if info.flag_bits & 0x800 else "cp437"
                try:
                    central_raw_name = info.orig_filename.encode(encoding)
                except UnicodeEncodeError as exc:
                    raise RetargetError(
                        "ambiguous-zip-path",
                        "ZIP central member name cannot be encoded unambiguously.",
                        path=member_label,
                    ) from exc
                central_unicode_path = validate_zip_extra_fields(
                    info.extra,
                    expected_name=info.filename,
                    raw_name=central_raw_name,
                    label=member_label,
                )
                if info.orig_filename != info.filename and central_unicode_path is None:
                    raise RetargetError(
                        "ambiguous-zip-path",
                        "ZIP member name contains data hidden by Python normalization.",
                        path=member_label,
                    )
                local_unicode_path = read_and_validate_local_zip_header(
                    raw_archive,
                    info,
                    budget,
                    label=member_label,
                )
                if central_unicode_path != local_unicode_path:
                    raise RetargetError(
                        "ambiguous-zip-path",
                        "ZIP local and central Unicode Path extra fields disagree.",
                        path=member_label,
                    )
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                unix_kind = stat.S_IFMT(unix_mode)
                declared_directory = info.is_dir()
                if info.create_system == 0 and bool(info.external_attr & 0x10) != declared_directory:
                    raise RetargetError(
                        "ambiguous-zip-type",
                        "ZIP DOS directory attribute disagrees with the member name.",
                        path=member_label,
                    )
                if unix_kind == stat.S_IFLNK:
                    raise RetargetError(
                        "archive-link",
                        "ZIP symlinks are not permitted.",
                        path=f"{label}!{info.filename}",
                    )
                if unix_kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise RetargetError(
                        "archive-special-file",
                        "ZIP special-file entries are not permitted.",
                        path=f"{label}!{info.filename}",
                    )
                if unix_kind == stat.S_IFDIR and not declared_directory:
                    raise RetargetError(
                        "path-kind-mismatch",
                        "ZIP metadata marks a non-directory name as a directory.",
                        path=f"{label}!{info.filename}",
                    )
                if unix_kind == stat.S_IFREG and declared_directory:
                    raise RetargetError(
                        "path-kind-mismatch",
                        "ZIP metadata marks a directory name as a regular file.",
                        path=f"{label}!{info.filename}",
                    )
                safe_path = validate_member_name(
                    info.filename,
                    is_directory=declared_directory,
                )
                if safe_path.value in files or safe_path.value in directories:
                    raise RetargetError(
                        "duplicate-archive-member",
                        "Duplicate normalized archive member path.",
                        path=f"{label}!{safe_path.value}",
                    )
                if declared_directory:
                    directories.add(safe_path.value)
                else:
                    files[safe_path.value] = StoredFile(
                        safe_path,
                        Path(),
                        0,
                        "",
                        unix_mode & 0o777,
                    )
                inventory.append((info, safe_path, declared_directory, unix_mode))

            validate_entry_set(
                (item.path for item in files.values()),
                (SafeArchivePath(item) for item in directories),
            )

            ordinal = 0
            for info, safe_path, is_directory, unix_mode in inventory:
                if is_directory:
                    continue
                ordinal += 1
                storage_path = allocate_storage_path(storage_directory, ordinal)
                try:
                    with (
                        archive.open(info, mode="r") as source,
                        storage_path.open(
                            "wb",
                        ) as destination,
                    ):
                        actual_size, sha256 = copy_bounded(
                            source,
                            destination,
                            budget,
                            label=f"{label}!{safe_path.value}",
                        )
                except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
                    raise RetargetError(
                        "malformed-archive",
                        "Unable to read ZIP member data.",
                        path=f"{label}!{safe_path.value}",
                    ) from exc
                if actual_size != info.file_size:
                    raise RetargetError(
                        "archive-size-mismatch",
                        "ZIP member expanded size differs from its header.",
                        path=f"{label}!{safe_path.value}",
                    )
                files[safe_path.value] = StoredFile(
                    safe_path,
                    storage_path,
                    actual_size,
                    sha256,
                    unix_mode & 0o777,
                )
    except RetargetError:
        raise
    except (zipfile.BadZipFile, OSError) as exc:
        raise RetargetError(
            "malformed-archive",
            "Unable to read ZIP archive.",
            path=label,
        ) from exc
    return StagedArchive("zip", files, directories)


def stage_tgz_archive(
    archive_path: Path,
    storage_directory: Path,
    budget: ScanBudget,
    *,
    label: str,
) -> StagedArchive:
    files: dict[str, StoredFile] = {}
    directories: set[str] = set()
    budget_token = ACTIVE_TAR_SCAN_BUDGET.set(budget)
    try:
        with tarfile.open(
            archive_path,
            mode="r|gz",
            tarinfo=BoundedTarInfo,
        ) as archive:
            ordinal = 0
            for member in archive:
                budget.consume_member(label=f"{label}!{member.name}")
                if not (member.isdir() or member.isreg()):
                    raise RetargetError(
                        "archive-special-file",
                        "TAR links and special-file entries are not permitted.",
                        path=f"{label}!{member.name}",
                    )
                if member.isreg() and getattr(member, "sparse", None):
                    raise RetargetError(
                        "archive-special-file",
                        "Sparse TAR entries are not permitted.",
                        path=f"{label}!{member.name}",
                    )
                safe_path = validate_member_name(
                    member.name,
                    is_directory=member.isdir(),
                )
                if safe_path.value in files or safe_path.value in directories:
                    raise RetargetError(
                        "duplicate-archive-member",
                        "Duplicate normalized archive member path.",
                        path=f"{label}!{safe_path.value}",
                    )
                if member.isdir():
                    directories.add(safe_path.value)
                else:
                    ordinal += 1
                    source = archive.extractfile(member)
                    if source is None:
                        raise RetargetError(
                            "malformed-archive",
                            "Unable to open TAR member data.",
                            path=f"{label}!{safe_path.value}",
                        )
                    storage_path = allocate_storage_path(
                        storage_directory,
                        ordinal,
                    )
                    with source, storage_path.open("wb") as destination:
                        actual_size, sha256 = copy_bounded(
                            source,
                            destination,
                            budget,
                            label=f"{label}!{safe_path.value}",
                        )
                    if actual_size != member.size:
                        raise RetargetError(
                            "archive-size-mismatch",
                            "TAR member expanded size differs from its header.",
                            path=f"{label}!{safe_path.value}",
                        )
                    files[safe_path.value] = StoredFile(
                        safe_path,
                        storage_path,
                        actual_size,
                        sha256,
                        member.mode & 0o777,
                    )

            validate_entry_set(
                (item.path for item in files.values()),
                (SafeArchivePath(item) for item in directories),
            )
    except RetargetError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise RetargetError(
            "malformed-archive",
            "Unable to read gzip-compressed TAR archive.",
            path=label,
        ) from exc
    finally:
        ACTIVE_TAR_SCAN_BUDGET.reset(budget_token)
    return StagedArchive("tgz", files, directories)


def stage_archive(
    archive_path: Path,
    storage_directory: Path,
    budget: ScanBudget,
    *,
    label: str,
    require_official_suffix: bool,
) -> StagedArchive:
    try:
        raw_size = archive_path.stat().st_size
    except OSError as exc:
        raise RetargetError(
            "input-read-failed",
            "Unable to read archive metadata.",
            path=label,
            operational=True,
        ) from exc
    if raw_size > budget.max_archive_bytes:
        raise RetargetError(
            "archive-raw-size-limit",
            (f"Archive exceeds the configured raw-size limit ({budget.max_archive_bytes} bytes)."),
            path=label,
        )
    archive_format = detect_archive_format(
        archive_path,
        require_official_suffix=require_official_suffix,
    )
    storage_directory.mkdir(parents=True, exist_ok=True)
    if archive_format == "zip":
        return stage_zip_archive(archive_path, storage_directory, budget, label=label)
    return stage_tgz_archive(archive_path, storage_directory, budget, label=label)


def strip_archive_suffix(name: str) -> str:
    lowered = name.lower()
    for suffix in (".tar.gz", ".tgz", ".zip"):
        if lowered.endswith(suffix):
            return name[: -len(suffix)]
    return name


def parse_calendar_date(value: str, *, option_name: str) -> dt.date:
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError as exc:
        raise RetargetError(
            "invalid-package-date",
            f"{option_name} must be a real calendar date in YYYY-MM-DD form.",
        ) from exc
    if parsed.isoformat() != value:
        raise RetargetError(
            "invalid-package-date",
            f"{option_name} must use exact YYYY-MM-DD form.",
        )
    return parsed


def parse_source_name_metadata(
    path: Path,
    metadata: ExtensionMetadata | None = None,
) -> SourceNameMetadata:
    basename = strip_archive_suffix(path.name)
    if metadata is not None:
        date_match = re.search(r"-(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})\Z", basename)
        if date_match:
            date_text = date_match.group("date")
            metadata_suffix = f"-{metadata.name}-{metadata.scm}{metadata.scmrevision}-{date_text}"
            if basename.endswith(metadata_suffix):
                prefix = basename[: -len(metadata_suffix)]
                prefix_parts = prefix.split("-", maxsplit=2)
                if len(prefix_parts) == 3 and ASCII_DECIMAL_PATTERN.fullmatch(prefix_parts[0]) and prefix_parts[1] in TARGET_OPERATING_SYSTEMS and ARCH_PATTERN.fullmatch(prefix_parts[2]):
                    return SourceNameMetadata(
                        revision=prefix_parts[0],
                        os=prefix_parts[1],
                        arch=prefix_parts[2],
                        package_date=parse_calendar_date(
                            date_text,
                            option_name="input package date",
                        ),
                    )
        return SourceNameMetadata()
    match = CONVENTIONAL_BASENAME_PATTERN.fullmatch(basename)
    if not match:
        return SourceNameMetadata()
    return SourceNameMetadata(
        revision=match.group("revision"),
        os=match.group("os"),
        arch=match.group("arch"),
        package_date=parse_calendar_date(
            match.group("date"),
            option_name="input package date",
        ),
    )


def parse_s4ext(file: StoredFile) -> ExtensionMetadata:
    if file.size > WHEEL_METADATA_LIMIT:
        raise RetargetError(
            "invalid-s4ext",
            "The extension description is unexpectedly large.",
            path=file.path.value,
        )
    try:
        text = file.storage_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        raise RetargetError(
            "invalid-s4ext",
            "The extension description is not valid UTF-8 text.",
            path=file.path.value,
        ) from exc
    fields: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pieces = stripped.split(maxsplit=1)
        keyword = pieces[0]
        value = pieces[1].strip() if len(pieces) == 2 else ""
        if keyword in fields:
            raise RetargetError(
                "invalid-s4ext",
                f"Duplicate '{keyword}' field in extension description.",
                path=file.path.value,
                details={"line": line_number},
            )
        fields[keyword] = value

    extension_name = PurePosixPath(file.path.value).stem
    scm = fields.get("scm", "")
    scmrevision = fields.get("scmrevision", "")
    for label, value in (
        ("extension name", extension_name),
        ("scm", scm),
        ("scmrevision", scmrevision),
    ):
        if not TOKEN_PATTERN.fullmatch(value):
            raise RetargetError(
                "unsafe-package-token",
                f"The {label} cannot safely be used in an output package name.",
                path=file.path.value,
            )

    def parse_extension_list(keyword: str) -> list[str]:
        value = fields.get(keyword, "")
        if not value or value == "NA":
            return []
        tokens = value.split()
        if any(not TOKEN_PATTERN.fullmatch(token) for token in tokens):
            raise RetargetError(
                "invalid-s4ext",
                f"The '{keyword}' field contains an unsafe extension name.",
                path=file.path.value,
            )
        return tokens

    return ExtensionMetadata(
        name=extension_name,
        scm=scm,
        scmrevision=scmrevision,
        depends=parse_extension_list("depends"),
        recommends=parse_extension_list("recommends"),
        fields=fields,
    )


def remove_root(path: SafeArchivePath, root: str) -> SafeArchivePath | None:
    parts = path.parts
    if parts[0] != root:
        raise RetargetError(
            "archive-root-count",
            "Archive entry is outside the selected top-level root.",
            path=path.value,
        )
    if len(parts) == 1:
        return None
    return safe_path_from_parts(parts[1:])


def normalize_layout(
    input_path: Path,
    staged: StagedArchive,
    archive_sha256: str,
    archive_size: int,
    findings: list[Finding],
) -> InspectedPackage:
    all_paths = [
        *(file.path for file in staged.files.values()),
        *(SafeArchivePath(value) for value in staged.directories),
    ]
    outer_root = ensure_single_root(all_paths)

    relative_files: dict[str, StoredFile] = {}
    relative_directories: set[str] = set()
    for file in staged.files.values():
        relative = remove_root(file.path, outer_root)
        if relative is None:
            raise RetargetError(
                "invalid-package-layout",
                "The top-level package root cannot itself be a regular file.",
                path=file.path.value,
            )
        relative_files[relative.value] = dataclasses.replace(file, path=relative)
    for value in staged.directories:
        relative = remove_root(SafeArchivePath(value), outer_root)
        if relative is not None:
            relative_directories.add(relative.value)

    layout = "flat"
    mac_revision: str | None = None
    payload_files = relative_files
    payload_directories = relative_directories
    if any(path.startswith("Slicer.app/") for path in relative_files):
        layout = "macosx"
        prefixes: set[tuple[str, str, str, str]] = set()
        for file in relative_files.values():
            parts = file.path.parts
            if len(parts) < 5:
                raise RetargetError(
                    "invalid-macos-layout",
                    "A file appears outside the expected macOS extension wrapper.",
                    path=file.path.value,
                )
            if parts[0] != "Slicer.app" or parts[1] != "Contents":
                raise RetargetError(
                    "invalid-macos-layout",
                    "A file appears outside Slicer.app/Contents.",
                    path=file.path.value,
                )
            revision_match = MAC_EXTENSIONS_PATTERN.fullmatch(parts[2])
            if not revision_match:
                raise RetargetError(
                    "invalid-macos-layout",
                    "The macOS Extensions directory is not revision-qualified.",
                    path=file.path.value,
                )
            prefixes.add((parts[0], parts[1], parts[2], parts[3]))
        if len(prefixes) != 1:
            raise RetargetError(
                "invalid-macos-layout",
                "The package contains more than one macOS extension wrapper.",
            )
        prefix = next(iter(prefixes))
        mac_revision = prefix[2].removeprefix("Extensions-")
        prefix_length = len(prefix)
        payload_files = {}
        for file in relative_files.values():
            payload_path = safe_path_from_parts(file.path.parts[prefix_length:])
            payload_files[payload_path.value] = dataclasses.replace(
                file,
                path=payload_path,
            )
        payload_directories = set()
        for directory in relative_directories:
            parts = SafeArchivePath(directory).parts
            if len(parts) <= prefix_length:
                if tuple(parts) != prefix[: len(parts)]:
                    raise RetargetError(
                        "invalid-macos-layout",
                        "A directory appears outside the expected macOS extension wrapper.",
                        path=directory,
                    )
                continue
            if tuple(parts[:prefix_length]) != prefix:
                raise RetargetError(
                    "invalid-macos-layout",
                    "A directory appears outside the expected macOS extension wrapper.",
                    path=directory,
                )
            if len(parts) > prefix_length:
                payload_directories.add(
                    safe_path_from_parts(parts[prefix_length:]).value,
                )
    elif any(path == "Slicer.app" or path.startswith("Slicer.app/") for path in relative_directories):
        raise RetargetError(
            "invalid-macos-layout",
            "An incomplete Slicer.app wrapper was found.",
        )

    s4ext_files = [file for file in payload_files.values() if file.path.suffix == ".s4ext"]
    if len(s4ext_files) != 1:
        raise RetargetError(
            "s4ext-count",
            "The package must contain exactly one .s4ext description.",
            details={"count": len(s4ext_files)},
        )
    metadata = parse_s4ext(s4ext_files[0])

    source_versions: set[str] = set()
    for path_value in [*payload_files, *payload_directories]:
        parts = SafeArchivePath(path_value).parts
        if len(parts) >= 2 and parts[0] in VERSIONED_ROOTS:
            match = SLICER_PATH_VERSION_PATTERN.fullmatch(parts[1])
            if match:
                source_versions.add(match.group(1))
            elif parts[1].startswith("Slicer-"):
                raise RetargetError(
                    "unsupported-source-version",
                    "Only stock Slicer 5.x version-qualified paths are supported.",
                    path=path_value,
                )
    if len(source_versions) != 1:
        raise RetargetError(
            "source-version-count",
            "Exactly one Slicer 5.x source path version must be present.",
            details={"versions": sorted(source_versions)},
        )
    source_version = next(iter(source_versions))
    expected_s4ext = f"share/Slicer-{source_version}/{metadata.name}.s4ext"
    if s4ext_files[0].path.value != expected_s4ext:
        raise RetargetError(
            "invalid-s4ext-location",
            "The .s4ext file is not at the standard Slicer 5.x share path.",
            path=s4ext_files[0].path.value,
            details={"expected": expected_s4ext},
        )
    if layout == "macosx":
        wrapper_extension = next(iter(prefixes))[3]
        if wrapper_extension != metadata.name:
            raise RetargetError(
                "invalid-macos-layout",
                "The macOS wrapper extension name differs from the .s4ext basename.",
                details={
                    "wrapper_extension": wrapper_extension,
                    "extension": metadata.name,
                },
            )

    if metadata.depends:
        add_finding(
            findings,
            "extension-dependencies-unverified",
            "warning",
            "Target availability of declared Slicer extension dependencies is unverified.",
            path=s4ext_files[0].path.value,
            details={"dependencies": metadata.depends},
        )

    eligible_targets = determine_eligible_targets(
        payload_files.keys(),
        payload_directories,
    )
    return InspectedPackage(
        input_path=input_path,
        archive_format=staged.format,
        archive_sha256=archive_sha256,
        archive_size=archive_size,
        outer_root=outer_root,
        layout=layout,
        mac_revision=mac_revision,
        payload_files=payload_files,
        payload_directories=payload_directories,
        source_version=source_version,
        metadata=metadata,
        name_metadata=parse_source_name_metadata(input_path, metadata),
        findings=findings,
        eligible_targets=eligible_targets,
    )


def windows_component_problem(component: str) -> str | None:
    if component.endswith((" ", ".")):
        return "trailing space or dot"
    if ":" in component:
        return "colon/alternate-data-stream syntax"
    forbidden = sorted(set(component) & WINDOWS_FORBIDDEN_CHARACTERS)
    if forbidden:
        return f"forbidden Windows character {forbidden[0]!r}"
    basename = component.split(".", maxsplit=1)[0].upper()
    if basename in WINDOWS_RESERVED_NAMES:
        return "reserved Windows device name"
    return None


def target_path_problem(
    file_paths: Iterable[str],
    directory_paths: Iterable[str],
    target_os: str,
) -> tuple[str, str] | None:
    file_values = set(file_paths)
    directory_values = set(directory_paths)
    directory_values.update(all_parent_directories(file_values | directory_values))
    for value in sorted(file_values | directory_values):
        safe_path = SafeArchivePath(value)
        if target_os == "win":
            for component in safe_path.parts:
                problem = windows_component_problem(component)
                if problem:
                    return value, problem

    if target_os in {"win", "macosx"}:
        casefolded: dict[str, tuple[str, str]] = {}
        entries = [
            *(("file", value) for value in sorted(file_values)),
            *(("directory", value) for value in sorted(directory_values)),
        ]
        for kind, value in entries:
            folded = unicodedata.normalize("NFC", value).casefold()
            previous = casefolded.get(folded)
            if previous is not None and previous != (kind, value):
                previous_kind, previous_value = previous
                return (
                    value,
                    (f"case-fold {kind} collision with {previous_kind} {previous_value}"),
                )
            casefolded[folded] = (kind, value)
    return None


def determine_eligible_targets(
    file_paths: Iterable[str],
    directory_paths: Iterable[str],
) -> list[str]:
    files = list(file_paths)
    directories = list(directory_paths)
    eligible: list[str] = []
    for target_os in TARGET_OPERATING_SYSTEMS:
        if target_path_problem(files, directories, target_os) is None:
            eligible.append(target_os)
    return eligible


def detect_native_kind(path: Path, logical_name: str) -> str | None:
    lowered = logical_name.casefold()
    if lowered.endswith(NATIVE_SUFFIXES) or re.search(r"\.so(?:\.[^/]*)?\Z", lowered):
        return "native-file-suffix"
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            header = stream.read(64 * 1024)
    except OSError as exc:
        raise RetargetError(
            "input-read-failed",
            "Unable to inspect staged member data.",
            path=logical_name,
            operational=True,
        ) from exc
    if header.startswith(b"\x7fELF"):
        return "ELF"
    if header[:4] in MACH_O_MAGICS:
        return "Mach-O"
    if header.startswith(b"!<arch>\n") or header.startswith(b"!<thin>\n"):
        return "ar"
    if header.startswith((b"BC\xc0\xde", b"\xde\xc0\x17\x0b")):
        return "LLVM-bitcode"
    if header.startswith(b"MZ"):
        if len(header) >= 64:
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            if pe_offset + 4 <= size:
                with path.open("rb") as stream:
                    stream.seek(pe_offset)
                    if stream.read(4) == b"PE\0\0":
                        return "PE"
        # MZ also identifies legacy DOS executables and self-extracting
        # executable stubs. Neither is a platform-neutral extension resource.
        return "MZ-executable"
    if len(header) >= 20:
        machine, section_count = struct.unpack_from("<HH", header, 0)
        optional_header_size = struct.unpack_from("<H", header, 16)[0]
        minimum_size = 20 + optional_header_size + section_count * 40
        if machine in COFF_MACHINE_TYPES and 1 <= section_count <= 96 and optional_header_size in {0, 28, 56, 224, 240} and minimum_size <= size:
            return "COFF"
    return None


def looks_like_text(path: Path) -> tuple[bool, str | None]:
    try:
        with path.open("rb") as stream:
            sample = stream.read(TEXT_SCAN_LIMIT + 1)
    except OSError:
        return False, None
    if b"\0" in sample:
        return False, None
    try:
        return True, sample.decode("utf-8")
    except UnicodeDecodeError:
        return False, None


def source_for_bytecode(path: SafeArchivePath) -> SafeArchivePath | None:
    suffix = path.suffix.casefold()
    if suffix not in {".pyc", ".pyo"}:
        return None
    parts = path.parts
    if len(parts) >= 2 and parts[-2] == "__pycache__":
        match = PEP3147_BYTECODE_PATTERN.fullmatch(parts[-1])
        if not match:
            return None
        return safe_path_from_parts((*parts[:-2], f"{match.group('stem')}.py"))
    filename = parts[-1]
    return safe_path_from_parts((*parts[:-1], f"{filename[:-1]}"))


def is_tar_header(block: bytes) -> bool:
    if len(block) != 512 or not any(block):
        return False
    checksum_field = block[148:156]
    stripped_checksum = checksum_field.strip(b" \0")
    try:
        stored_checksum = int(stripped_checksum or b"0", 8)
    except ValueError:
        return False
    checksum_block = block[:148] + (b" " * 8) + block[156:]
    unsigned_checksum = sum(checksum_block)
    signed_checksum = sum(value if value < 128 else value - 256 for value in checksum_block)
    return stored_checksum in {unsigned_checksum, signed_checksum}


def read_gzip_header(path: Path, size: int = 512) -> bytes:
    try:
        with gzip.open(path, mode="rb") as stream:
            return stream.read(size)
    except (gzip.BadGzipFile, EOFError, OSError):
        return b""


def nested_archive_kind(file: StoredFile) -> str | None:
    try:
        with file.storage_path.open("rb") as stream:
            header = stream.read(512)
    except OSError as exc:
        raise RetargetError(
            "input-read-failed",
            "Unable to inspect staged member data.",
            path=file.path.value,
            operational=True,
        ) from exc
    magic = header[:8]
    lowered = file.path.value.casefold()
    if lowered.endswith(".whl"):
        return "wheel"
    if zipfile.is_zipfile(file.storage_path):
        return "zip"
    if magic.startswith(b"\x1f\x8b"):
        if is_tar_header(read_gzip_header(file.storage_path)):
            return "tgz"
        if lowered.endswith((".tgz", ".tar.gz")):
            return "malformed"
        return None
    if (
        magic.startswith(b"7z\xbc\xaf\x27\x1c")
        or magic.startswith(b"\xfd7zXZ\x00")
        or magic.startswith(b"BZh")
        or magic.startswith(b"\x28\xb5\x2f\xfd")
        or is_tar_header(header)
        or lowered.endswith(
            (
                ".7z",
                ".rar",
                ".tar",
                ".tar.bz2",
                ".tar.xz",
                ".tar.zst",
                ".tbz2",
                ".txz",
                ".tzst",
            ),
        )
    ):
        return "unsupported"
    if magic.startswith(b"Rar!\x1a\x07"):
        return "unsupported"
    if lowered.endswith((".zip", ".tgz", ".tar.gz")):
        return "malformed"
    return None


def is_recognized_binary_resource(file: StoredFile) -> bool:
    lowered = file.path.value.casefold()
    if not any(lowered.endswith(suffix) for suffix in BINARY_RESOURCE_SUFFIXES):
        return False
    try:
        with file.storage_path.open("rb") as stream:
            header = stream.read(512)
    except OSError as exc:
        raise RetargetError(
            "input-read-failed",
            "Unable to classify staged binary resource data.",
            path=file.path.value,
            operational=True,
        ) from exc
    if lowered.endswith(".nii.gz"):
        decompressed = read_gzip_header(file.storage_path)
        return decompressed[344:348] in {b"n+1\x00", b"ni1\x00"}
    if lowered.endswith(".nrrd.gz"):
        return read_gzip_header(file.storage_path).startswith(b"NRRD")
    return (
        header.startswith(
            (
                b"\x89PNG\r\n\x1a\n",
                b"\xff\xd8\xff",
                b"GIF87a",
                b"GIF89a",
                b"%PDF-",
                b"BM",
                b"\x00\x00\x01\x00",
                b"\x89HDF\r\n\x1a\n",
                b"\x93NUMPY",
                b"NRRD",
                b"MATLAB 5.0 MAT-file",
                b"ObjectType",
                b"# vtk",
                b"ply",
                b"<?xml",
                b"\x00\x01\x00\x00",
                b"OTTO",
            ),
        )
        or header[:4] in {b"II*\x00", b"MM\x00*"}
        or header[8:12] in {b"WAVE", b"WEBP"}
        or header[128:132] == b"DICM"
        or header[344:348] in {b"n+1\x00", b"ni1\x00"}
    )


def display_nested_path(parent: str, child: str) -> str:
    return f"{parent}!{child}"


def validate_wheel_metadata(
    wheel_file: StoredFile,
    nested: StagedArchive,
    *,
    display_path: str,
) -> None:
    try:
        _, _, _, filename_tags = parse_wheel_filename(wheel_file.path.name)
    except InvalidWheelFilename as exc:
        raise RetargetError(
            "invalid-wheel",
            "Bundled wheel filename is invalid.",
            path=display_path,
        ) from exc
    if not filename_tags or any(tag.abi != "none" or tag.platform != "any" for tag in filename_tags):
        raise RetargetError(
            "platform-wheel",
            "Only wheels tagged with ABI 'none' and platform 'any' are permitted.",
            path=display_path,
        )
    wheel_metadata = [item for item in nested.files.values() if len(item.path.parts) >= 2 and item.path.parts[-2].endswith(".dist-info") and item.path.name == "WHEEL"]
    if len(wheel_metadata) != 1:
        raise RetargetError(
            "invalid-wheel",
            "A wheel must contain exactly one .dist-info/WHEEL metadata file.",
            path=display_path,
        )
    metadata_file = wheel_metadata[0]
    if metadata_file.size > WHEEL_METADATA_LIMIT:
        raise RetargetError(
            "invalid-wheel",
            "Wheel metadata is unexpectedly large.",
            path=display_nested_path(display_path, metadata_file.path.value),
        )
    try:
        metadata_text = metadata_file.storage_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        raise RetargetError(
            "invalid-wheel",
            "Wheel metadata is not valid UTF-8 text.",
            path=display_nested_path(display_path, metadata_file.path.value),
        ) from exc
    message = email.parser.Parser().parsestr(metadata_text)
    if message.get("Root-Is-Purelib", "").strip().casefold() != "true":
        raise RetargetError(
            "platform-wheel",
            "Bundled wheel does not declare Root-Is-Purelib: true.",
            path=display_path,
        )
    metadata_tags: set[Tag] = set()
    try:
        for tag_value in message.get_all("Tag", []):
            metadata_tags.update(parse_tag(tag_value.strip()))
    except (ValueError, TypeError) as exc:
        raise RetargetError(
            "invalid-wheel",
            "Wheel Tag metadata is malformed.",
            path=display_path,
        ) from exc
    if metadata_tags != set(filename_tags):
        raise RetargetError(
            "wheel-tag-mismatch",
            "Wheel filename tags and WHEEL metadata tags do not match.",
            path=display_path,
        )
    for target_os in ("win", "macosx"):
        problem = target_path_problem(
            nested.files,
            nested.directories,
            target_os,
        )
        if problem:
            problem_path, reason = problem
            raise RetargetError(
                "nonportable-wheel-path",
                (f"Pure-Python wheel contains a path incompatible with {target_os}: {reason}."),
                path=display_nested_path(display_path, problem_path),
            )


def scan_stored_file(
    file: StoredFile,
    *,
    display_path: str,
    budget: ScanBudget,
    storage_root: Path,
    depth: int,
    findings: list[Finding],
    source_version: str,
    source_name_metadata: SourceNameMetadata,
    nested: bool,
) -> None:
    native_kind = detect_native_kind(file.storage_path, file.path.value)
    if native_kind:
        raise RetargetError(
            "native-payload",
            f"Detected prohibited native payload ({native_kind}).",
            path=display_path,
        )

    is_text, text = looks_like_text(file.storage_path)
    has_execute_bit = bool(file.source_mode & 0o111)
    has_shebang = bool(text and text.startswith("#!"))
    if has_execute_bit and not is_text:
        raise RetargetError(
            "unclassified-executable",
            "Executable binary data could not be classified as a safe script.",
            path=display_path,
        )
    if has_execute_bit and is_text and not has_shebang:
        add_finding(
            findings,
            "executable-text-unverified",
            "warning",
            "Executable text without a shebang requires runtime review.",
            path=display_path,
        )

    if nested and file.path.suffix.casefold() in {".pyc", ".pyo"}:
        raise RetargetError(
            "nested-bytecode",
            "Bytecode inside a bundled archive cannot be safely retargeted.",
            path=display_path,
        )

    archive_kind = nested_archive_kind(file)
    if archive_kind == "unsupported":
        raise RetargetError(
            "unsupported-nested-archive",
            "A bundled archive uses an unsupported format.",
            path=display_path,
        )
    if archive_kind == "malformed":
        raise RetargetError(
            "malformed-nested-archive",
            "A bundled archive suffix does not match readable archive data.",
            path=display_path,
        )
    if archive_kind in {"wheel", "zip", "tgz"}:
        budget.check_depth(depth + 1, label=display_path)
        nested_storage = storage_root / f"nested-{budget.members}-{depth + 1}"
        nested_archive = stage_archive(
            file.storage_path,
            nested_storage,
            budget,
            label=display_path,
            require_official_suffix=False,
        )
        if archive_kind == "wheel":
            if nested_archive.format != "zip":
                raise RetargetError(
                    "invalid-wheel",
                    "A bundled wheel is not a ZIP archive.",
                    path=display_path,
                )
            validate_wheel_metadata(file, nested_archive, display_path=display_path)
        for nested_file in nested_archive.files.values():
            try:
                scan_stored_file(
                    nested_file,
                    display_path=display_nested_path(
                        display_path,
                        nested_file.path.value,
                    ),
                    budget=budget,
                    storage_root=storage_root,
                    depth=depth + 1,
                    findings=findings,
                    source_version=source_version,
                    source_name_metadata=source_name_metadata,
                    nested=True,
                )
            except RetargetError as error:
                if archive_kind != "wheel":
                    raise
                raise RetargetError(
                    "unsafe-wheel-content",
                    f"Bundled wheel contains unsafe content ({error.code}).",
                    path=error.path or display_path,
                    operational=error.operational,
                    details={"nested_code": error.code},
                ) from error
        if archive_kind == "wheel":
            add_finding(
                findings,
                "pure-wheel-runtime-unverified",
                "warning",
                "A verified pure-Python wheel is bundled; target Python compatibility remains unverified.",
                path=display_path,
            )

    if not is_text and archive_kind is None and file.path.suffix.casefold() not in {".pyc", ".pyo"} and not is_recognized_binary_resource(file):
        add_finding(
            findings,
            "unknown-binary-resource",
            "warning",
            "Opaque binary data was preserved but could not be classified as a known resource.",
            path=display_path,
        )

    if not nested and text is not None and file.size <= TEXT_SCAN_LIMIT:
        lower_name = file.path.name.casefold()
        if lower_name.startswith("requirements") or "pip_install(" in text:
            add_finding(
                findings,
                "runtime-python-dependencies",
                "warning",
                "The extension may install Python dependencies at runtime.",
                path=display_path,
            )
        if re.search(r"(^|\W)(ctypes|subprocess)(\W|$)", text):
            add_finding(
                findings,
                "runtime-native-behavior",
                "warning",
                "The source references ctypes or subprocess and requires target runtime review.",
                path=display_path,
            )
        source_markers = [f"Slicer-{source_version}"]
        if source_name_metadata.revision:
            source_markers.append(source_name_metadata.revision)
        if source_name_metadata.os:
            source_markers.append(source_name_metadata.os)
        if source_name_metadata.arch:
            source_markers.append(source_name_metadata.arch)
        if any(
            marker
            and re.search(
                rf"(?<![A-Za-z0-9]){re.escape(marker)}(?![A-Za-z0-9])",
                text,
            )
            for marker in source_markers
        ):
            add_finding(
                findings,
                "source-target-text-reference",
                "warning",
                "A text file contains source-target identifiers; contents were not rewritten.",
                path=display_path,
            )
        if file.path.suffix.casefold() in {".bat", ".cmd", ".ps1"} or re.search(
            (
                r"(?i)(?:\bpowershell(?:\.exe)?\b|\bcmd\.exe\b|"
                r"\bapt(?:-get)?\b|\bbrew\b|\bchmod\b|\bchown\b|"
                r"\.(?:dll|dylib|so)\b)"
            ),
            text,
        ):
            add_finding(
                findings,
                "platform-specific-command-reference",
                "warning",
                "Text contains a platform-specific command or native-library reference.",
                path=display_path,
            )
        if re.search(
            r"(?:/home/|/Users/|[A-Za-z]:[\\/](?:Users|build|src)[\\/])",
            text,
        ):
            add_finding(
                findings,
                "absolute-build-path-reference",
                "warning",
                "A text file appears to contain an absolute source/build path.",
                path=display_path,
            )


def verified_bytecode_paths(package: InspectedPackage) -> list[str]:
    file_paths = set(package.payload_files)
    removals: list[str] = []
    for value in sorted(file_paths):
        path = SafeArchivePath(value)
        if path.suffix.casefold() not in {".pyc", ".pyo"}:
            continue
        source = source_for_bytecode(path)
        if source is None or source.value not in file_paths:
            raise RetargetError(
                "orphan-bytecode",
                "Python bytecode lacks the exact corresponding .py source.",
                path=value,
            )
        removals.append(value)
    return removals


def remove_verified_bytecode(
    package: InspectedPackage,
    transformations: list[dict[str, object]],
) -> None:
    removals = verified_bytecode_paths(package)
    for value in removals:
        del package.payload_files[value]
    for directory in sorted(package.payload_directories, reverse=True):
        if SafeArchivePath(directory).name != "__pycache__":
            continue
        prefix = f"{directory}/"
        if not any(value.startswith(prefix) for value in package.payload_files):
            package.payload_directories.remove(directory)
    if removals:
        transformations.append(
            {
                "kind": "remove-bytecode",
                "paths": removals,
                "count": len(removals),
            },
        )


def inspect_package(
    input_path: Path,
    *,
    budget: ScanBudget,
    temporary_root: Path,
) -> InspectedPackage:
    try:
        resolved_input = input_path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise RetargetError(
            "input-not-found",
            "Input package does not exist or cannot be resolved.",
            path=str(input_path),
            operational=True,
        ) from exc
    private_input = temporary_root / f"input-package{private_archive_suffix(resolved_input)}"
    archive_size, archive_sha256 = snapshot_input_archive(
        resolved_input,
        private_input,
        budget,
    )

    findings: list[Finding] = []
    staged = stage_archive(
        private_input,
        temporary_root / "outer",
        budget,
        label=resolved_input.name,
        require_official_suffix=True,
    )
    package = normalize_layout(
        resolved_input,
        staged,
        archive_sha256,
        archive_size,
        findings,
    )
    for file in package.payload_files.values():
        scan_stored_file(
            file,
            display_path=file.path.value,
            budget=budget,
            storage_root=temporary_root,
            depth=0,
            findings=package.findings,
            source_version=package.source_version,
            source_name_metadata=package.name_metadata,
            nested=False,
        )
    verified_bytecode_paths(package)
    return package


def package_to_audit_source(package: InspectedPackage) -> dict[str, object]:
    source_name: dict[str, object] = {
        "revision": package.name_metadata.revision,
        "os": package.name_metadata.os,
        "arch": package.name_metadata.arch,
        "package_date": (package.name_metadata.package_date.isoformat() if package.name_metadata.package_date else None),
    }
    manifest = logical_manifest(
        package.payload_files,
        {value: file.source_mode & 0o777 for value, file in package.payload_files.items()},
    )
    return {
        "path": str(package.input_path),
        "archive_format": package.archive_format,
        "archive_sha256": package.archive_sha256,
        "archive_size": package.archive_size,
        "outer_root": package.outer_root,
        "layout": package.layout,
        "mac_revision": package.mac_revision,
        "slicer_path_version": package.source_version,
        "filename_metadata": source_name,
        "extension": {
            "name": package.metadata.name,
            "scm": package.metadata.scm,
            "scmrevision": package.metadata.scmrevision,
            "depends": package.metadata.depends,
            "recommends": package.metadata.recommends,
        },
        "inventory": {
            "file_count": len(package.payload_files),
            "directory_count": len(package.payload_directories),
            "payload_bytes": sum(file.size for file in package.payload_files.values()),
        },
        "eligible_targets": package.eligible_targets,
        "logical_manifest_sha256": manifest_hash(manifest),
        "logical_manifest": manifest,
    }


def logical_manifest(
    files: dict[str, StoredFile],
    file_modes: dict[str, int] | None = None,
) -> list[dict[str, object]]:
    manifest: list[dict[str, object]] = []
    for value, file in sorted(files.items()):
        item: dict[str, object] = {
            "path": value,
            "size": file.size,
            "sha256": file.sha256,
        }
        if file_modes is not None:
            item["mode"] = f"{file_modes[value] & 0o777:04o}"
        manifest.append(item)
    return manifest


def manifest_hash(manifest: list[dict[str, object]]) -> str:
    serialized = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def validate_target_version(
    version: str,
    explicit_revision: str | None,
) -> tuple[str, bool]:
    match = TARGET_VERSION_PATTERN.fullmatch(version)
    if not match:
        raise RetargetError(
            "invalid-target-version",
            "Target version must be stock Slicer 5.X or 5.X.Z.",
        )
    has_patch = match.group(2) is not None
    if explicit_revision is None and not has_patch:
        raise RetargetError(
            "target-version-requires-patch",
            "Online revision lookup requires an exact Slicer 5.X.Z version.",
        )
    return f"5.{match.group(1)}", has_patch


def fetch_https(url: str) -> tuple[bytes, str]:
    if urllib.parse.urlparse(url).scheme != "https":
        raise RetargetError(
            "insecure-lookup-url",
            "Revision lookup is restricted to HTTPS.",
            operational=True,
        )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/plain;q=0.9",
            "User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=NETWORK_TIMEOUT_SECONDS,
        ) as response:
            final_url = response.geturl()
            if urllib.parse.urlparse(final_url).scheme != "https":
                raise RetargetError(
                    "insecure-lookup-redirect",
                    "Revision lookup redirected away from HTTPS.",
                    operational=True,
                )
            body = response.read(MAX_NETWORK_RESPONSE_BYTES + 1)
    except RetargetError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RetargetError(
            "revision-lookup-network",
            "Revision lookup request failed.",
            operational=True,
            details={"url": url, "reason": type(exc).__name__},
        ) from exc
    if len(body) > MAX_NETWORK_RESPONSE_BYTES:
        raise RetargetError(
            "revision-lookup-response-size",
            "Revision lookup response exceeds the configured safety limit.",
            operational=True,
            details={"url": url},
        )
    return body, final_url


def resolve_from_package_server(
    version: str,
    target_os: str,
    target_arch: str,
) -> tuple[str, str, dict[str, object]]:
    query = urllib.parse.urlencode(
        {"release_id_or_name": version, "limit": "0"},
    )
    url = f"{PACKAGE_SERVER_URL}?{query}"
    body, final_url = fetch_https(url)
    body_hash = hashlib.sha256(body).hexdigest()
    attempt: dict[str, object] = {
        "source": "package-server",
        "url": final_url,
        "response_sha256": body_hash,
    }
    try:
        records = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetargetError(
            "revision-lookup-schema",
            "Package server returned malformed JSON.",
            operational=True,
            details=attempt,
        ) from exc
    if not isinstance(records, list):
        raise RetargetError(
            "revision-lookup-schema",
            "Package server response is not a package list.",
            operational=True,
            details=attempt,
        )
    matches: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("meta"), dict):
            continue
        metadata = record["meta"]
        record_version = metadata.get("version") or metadata.get("release")
        revision = metadata.get("revision")
        if metadata.get("baseName") == "Slicer" and record_version == version and isinstance(revision, str) and ASCII_DECIMAL_PATTERN.fullmatch(revision):
            matches.append(metadata)
    revisions = {str(metadata["revision"]) for metadata in matches}
    if len(revisions) > 1:
        raise RetargetError(
            "revision-lookup-conflict",
            "Package server returned conflicting revisions for the exact release.",
            details={**attempt, "revisions": sorted(revisions)},
        )
    if not revisions:
        raise RetargetError(
            "revision-lookup-no-match",
            "Package server has no exact stock-Slicer application record.",
            operational=True,
            details=attempt,
        )
    tuple_available = any(metadata.get("os") == target_os and metadata.get("arch") == target_arch for metadata in matches)
    publication_status = "published" if tuple_available else "not-published"
    attempt["result"] = "success"
    attempt["revision"] = next(iter(revisions))
    attempt["target_tuple_available"] = tuple_available
    return next(iter(revisions)), publication_status, attempt


def parse_extension_stats_mapping(source: bytes) -> dict[str, object]:
    try:
        text = source.decode("utf-8")
        tree = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise RetargetError(
            "revision-lookup-schema",
            "ExtensionStats source is not valid UTF-8 Python.",
            operational=True,
        ) from exc
    assignments: list[ast.expr] = []
    for class_node in tree.body:
        if not isinstance(class_node, ast.ClassDef) or class_node.name != "ExtensionStatsLogic":
            continue
        for function_node in class_node.body:
            if not isinstance(function_node, (ast.FunctionDef, ast.AsyncFunctionDef)) or function_node.name != "__init__":
                continue
            for node in function_node.body:
                if not isinstance(node, ast.Assign):
                    continue
                if any(isinstance(target, ast.Name) and target.id == "releases_revisionsDates" for target in node.targets):
                    assignments.append(node.value)
    if len(assignments) != 1:
        raise RetargetError(
            "revision-lookup-schema",
            "Could not locate one literal releases_revisionsDates assignment.",
            operational=True,
        )
    try:
        mapping = ast.literal_eval(assignments[0])
    except (ValueError, TypeError, SyntaxError) as exc:
        raise RetargetError(
            "revision-lookup-schema",
            "ExtensionStats release mapping is not a literal value.",
            operational=True,
        ) from exc
    if not isinstance(mapping, dict):
        raise RetargetError(
            "revision-lookup-schema",
            "ExtensionStats release mapping is not a dictionary.",
            operational=True,
        )
    return mapping


def resolve_from_extension_stats(
    version: str,
) -> tuple[str, dict[str, object]]:
    body, final_url = fetch_https(EXTENSION_STATS_URL)
    attempt: dict[str, object] = {
        "source": "extensionstats",
        "url": final_url,
        "response_sha256": hashlib.sha256(body).hexdigest(),
    }
    mapping = parse_extension_stats_mapping(body)
    value = mapping.get(version)
    if not isinstance(value, (list, tuple)) or not value or not isinstance(value[0], str) or not ASCII_DECIMAL_PATTERN.fullmatch(value[0]):
        raise RetargetError(
            "revision-lookup-no-match",
            "ExtensionStats has no exact decimal revision for the target release.",
            operational=True,
            details=attempt,
        )
    attempt["result"] = "success"
    attempt["revision"] = value[0]
    return value[0], attempt


def attempt_dict_from_error(source: str, error: RetargetError) -> dict[str, object]:
    result: dict[str, object] = {
        "source": source,
        "result": "failed",
        "code": error.code,
        "message": error.message,
    }
    result.update(error.details)
    return result


def resolve_target(
    *,
    version: str,
    explicit_revision: str | None,
    target_os: str,
    target_arch: str,
    findings: list[Finding],
) -> Target:
    path_version, _ = validate_target_version(version, explicit_revision)
    if not ARCH_PATTERN.fullmatch(target_arch):
        raise RetargetError(
            "invalid-target-architecture",
            "Target architecture contains unsafe characters.",
        )
    if explicit_revision is not None:
        if not ASCII_DECIMAL_PATTERN.fullmatch(explicit_revision) or int(explicit_revision) <= 0:
            raise RetargetError(
                "invalid-target-revision",
                "Target revision must be a positive decimal value.",
            )
        return Target(
            version,
            path_version,
            explicit_revision,
            target_os,
            target_arch,
            "explicit",
            "not-checked",
            [],
        )

    attempts: list[dict[str, object]] = []
    try:
        revision, publication_status, attempt = resolve_from_package_server(
            version,
            target_os,
            target_arch,
        )
        attempts.append(attempt)
        if publication_status == "not-published":
            add_finding(
                findings,
                "target-application-tuple-unpublished",
                "warning",
                "No official Slicer application package was found for the target OS/architecture.",
                details={"os": target_os, "arch": target_arch, "version": version},
            )
        return Target(
            version,
            path_version,
            revision,
            target_os,
            target_arch,
            "package-server",
            publication_status,
            attempts,
        )
    except RetargetError as package_error:
        if package_error.code == "revision-lookup-conflict":
            raise
        attempts.append(attempt_dict_from_error("package-server", package_error))

    try:
        revision, attempt = resolve_from_extension_stats(version)
        attempts.append(attempt)
        add_finding(
            findings,
            "target-publication-unverified",
            "warning",
            ("Target OS/architecture publication could not be verified because package-server lookup failed."),
            details={"os": target_os, "arch": target_arch, "version": version},
        )
        return Target(
            version,
            path_version,
            revision,
            target_os,
            target_arch,
            "extensionstats",
            "not-checked",
            attempts,
        )
    except RetargetError as extension_stats_error:
        attempts.append(
            attempt_dict_from_error("extensionstats", extension_stats_error),
        )
        raise RetargetError(
            "revision-lookup-failed",
            ("Could not resolve the exact Slicer revision. Pass --target-revision to work offline or override lookup."),
            details={"attempts": attempts},
        ) from extension_stats_error


def rewrite_payload_path(
    path: SafeArchivePath,
    source_version: str,
    target_version: str,
) -> SafeArchivePath:
    parts = list(path.parts)
    if len(parts) >= 2 and parts[0] in VERSIONED_ROOTS and parts[1] == f"Slicer-{source_version}":
        parts[1] = f"Slicer-{target_version}"
    return safe_path_from_parts(parts)


def transformed_payload(
    package: InspectedPackage,
    target: Target,
    transformations: list[dict[str, object]],
) -> tuple[dict[str, StoredFile], set[str]]:
    transformed_files: dict[str, StoredFile] = {}
    transformed_directories: set[str] = set()
    rewrites: list[dict[str, str]] = []
    for source_value, file in sorted(package.payload_files.items()):
        target_path = rewrite_payload_path(
            file.path,
            package.source_version,
            target.path_version,
        )
        if target_path.value in transformed_files:
            raise RetargetError(
                "target-path-collision",
                "Path rewriting produced a duplicate output path.",
                path=target_path.value,
            )
        transformed_files[target_path.value] = dataclasses.replace(
            file,
            path=target_path,
        )
        if source_value != target_path.value:
            rewrites.append({"from": source_value, "to": target_path.value})
    for directory in sorted(package.payload_directories):
        target_path = rewrite_payload_path(
            SafeArchivePath(directory),
            package.source_version,
            target.path_version,
        )
        transformed_directories.add(target_path.value)
    if rewrites:
        transformations.append(
            {"kind": "rewrite-versioned-paths", "paths": rewrites},
        )
    if package.source_version != target.path_version:
        add_finding(
            package.findings,
            "cross-version-runtime-unverified",
            "warning",
            "Cross-X.Y path retargeting does not establish Slicer API compatibility.",
            details={
                "source": package.source_version,
                "target": target.path_version,
            },
        )
    problem = target_path_problem(
        transformed_files,
        transformed_directories,
        target.os,
    )
    if problem:
        path, reason = problem
        raise RetargetError(
            "target-path-incompatible",
            f"A package path is incompatible with target {target.os}: {reason}.",
            path=path,
        )
    return transformed_files, transformed_directories


def all_parent_directories(paths: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for value in paths:
        parts = value.split("/")
        for index in range(1, len(parts)):
            result.add("/".join(parts[:index]))
    return result


def file_has_shebang(file: StoredFile) -> bool:
    try:
        with file.storage_path.open("rb") as stream:
            return stream.read(2) == b"#!"
    except OSError:
        return False


def build_output_plan(
    package: InspectedPackage,
    target: Target,
    package_date: dt.date,
    transformations: list[dict[str, object]],
) -> OutputPlan:
    payload_files, payload_directories = transformed_payload(
        package,
        target,
        transformations,
    )
    root_name = f"{target.revision}-{target.os}-{target.arch}-{package.metadata.name}-{package.metadata.scm}{package.metadata.scmrevision}-{package_date.isoformat()}"
    if not all(TOKEN_PATTERN.fullmatch(token) for token in (package.metadata.name, package.metadata.scm, package.metadata.scmrevision)):
        raise RetargetError(
            "unsafe-package-token",
            "Output package metadata contains an unsafe path token.",
        )
    archive_files: dict[str, StoredFile] = {}
    wrapper_parts: tuple[str, ...]
    if target.os == "macosx":
        wrapper_parts = (
            root_name,
            "Slicer.app",
            "Contents",
            f"Extensions-{target.revision}",
            package.metadata.name,
        )
        wrapper_kind = "macosx"
    else:
        wrapper_parts = (root_name,)
        wrapper_kind = "flat"
    for value, file in payload_files.items():
        archive_path = safe_path_from_parts((*wrapper_parts, *file.path.parts))
        archive_files[archive_path.value] = dataclasses.replace(
            file,
            path=archive_path,
        )
    archive_directories = {
        safe_path_from_parts(
            (*wrapper_parts, *SafeArchivePath(value).parts),
        ).value
        for value in payload_directories
    }
    archive_directories.update(
        all_parent_directories(
            [*archive_files, *archive_directories],
        ),
    )
    archive_directories.add(root_name)
    file_modes: dict[str, int] = {}
    payload_file_modes: dict[str, int] = {}
    for archive_value, file in archive_files.items():
        payload_parts = file.path.parts[len(wrapper_parts) :]
        executable = bool(file.source_mode & 0o111)
        if len(payload_parts) >= 3 and payload_parts[0] == "lib" and payload_parts[1] == f"Slicer-{target.path_version}" and payload_parts[2] == "bin" and file_has_shebang(file):
            executable = True
        normalized_mode = 0o755 if executable else 0o644
        file_modes[archive_value] = normalized_mode
        payload_file_modes["/".join(payload_parts)] = normalized_mode
    transformations.append(
        {
            "kind": "platform-wrapper",
            "from": package.layout,
            "to": wrapper_kind,
            "root": root_name,
        },
    )
    return OutputPlan(
        root_name=root_name,
        archive_format="zip" if target.os == "win" else "tgz",
        archive_suffix=".zip" if target.os == "win" else ".tar.gz",
        payload_files=payload_files,
        payload_directories=payload_directories,
        archive_files=archive_files,
        archive_directories=archive_directories,
        file_modes=file_modes,
        payload_file_modes=payload_file_modes,
        package_date=package_date,
    )


def zip_timestamp(package_date: dt.date) -> tuple[int, int, int, int, int, int]:
    return (package_date.year, package_date.month, package_date.day, 0, 0, 0)


def validate_package_date_for_target(
    package_date: dt.date,
    target_os: str,
) -> None:
    if target_os == "win" and not ZIP_MINIMUM_YEAR <= package_date.year <= ZIP_MAXIMUM_YEAR:
        raise RetargetError(
            "invalid-package-date",
            (f"Windows ZIP output requires a package date between {ZIP_MINIMUM_YEAR}-01-01 and {ZIP_MAXIMUM_YEAR}-12-31."),
        )


def package_epoch(package_date: dt.date) -> int:
    return (package_date - dt.date(1970, 1, 1)).days * 24 * 60 * 60


def write_zip(plan: OutputPlan, destination: Path) -> None:
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for directory in sorted(plan.archive_directories):
            info = zipfile.ZipInfo(f"{directory}/", date_time=zip_timestamp(plan.package_date))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
            archive.writestr(info, b"")
        for value, file in sorted(plan.archive_files.items()):
            info = zipfile.ZipInfo(value, date_time=zip_timestamp(plan.package_date))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | plan.file_modes[value]) << 16
            with (
                file.storage_path.open("rb") as source,
                archive.open(
                    info,
                    mode="w",
                    force_zip64=True,
                ) as output,
            ):
                shutil.copyfileobj(source, output, COPY_CHUNK_SIZE)


def configure_tar_info(
    info: tarfile.TarInfo,
    *,
    mode: int,
    mtime: int,
) -> tarfile.TarInfo:
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = mtime
    info.pax_headers = {}
    return info


def write_tgz(plan: OutputPlan, destination: Path) -> None:
    mtime = package_epoch(plan.package_date)
    gzip_mtime = min(max(mtime, 0), 0xFFFFFFFF)
    with destination.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=9,
            fileobj=raw_output,
            mtime=gzip_mtime,
        ) as gzip_output:
            with tarfile.open(
                fileobj=gzip_output,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for directory in sorted(plan.archive_directories):
                    info = configure_tar_info(
                        tarfile.TarInfo(directory),
                        mode=0o755,
                        mtime=mtime,
                    )
                    info.type = tarfile.DIRTYPE
                    info.size = 0
                    archive.addfile(info)
                for value, file in sorted(plan.archive_files.items()):
                    info = configure_tar_info(
                        tarfile.TarInfo(value),
                        mode=plan.file_modes[value],
                        mtime=mtime,
                    )
                    info.type = tarfile.REGTYPE
                    info.size = file.size
                    with file.storage_path.open("rb") as source:
                        archive.addfile(info, source)
        raw_output.flush()
        os.fsync(raw_output.fileno())


def write_output_archive(plan: OutputPlan, destination: Path) -> None:
    try:
        if plan.archive_format == "zip":
            write_zip(plan, destination)
            with destination.open("rb") as stream:
                os.fsync(stream.fileno())
        else:
            write_tgz(plan, destination)
    except RetargetError:
        raise
    except OSError as exc:
        raise RetargetError(
            "output-write-failed",
            "Unable to write the output archive.",
            path=str(destination),
            operational=True,
        ) from exc


def compare_output_to_plan(
    output_package: InspectedPackage,
    plan: OutputPlan,
    target: Target,
) -> None:
    if output_package.outer_root != plan.root_name:
        raise RetargetError(
            "output-validation-failed",
            "Output archive root differs from the planned package root.",
        )
    expected_layout = "macosx" if target.os == "macosx" else "flat"
    if output_package.layout != expected_layout:
        raise RetargetError(
            "output-validation-failed",
            "Output archive platform wrapper is incorrect.",
        )
    if target.os == "macosx" and output_package.mac_revision != target.revision:
        raise RetargetError(
            "output-validation-failed",
            "Output macOS wrapper contains the wrong Slicer revision.",
        )
    if output_package.source_version != target.path_version:
        raise RetargetError(
            "output-validation-failed",
            "Output archive contains the wrong Slicer path version.",
        )
    expected_manifest = logical_manifest(
        plan.payload_files,
        plan.payload_file_modes,
    )
    actual_manifest = logical_manifest(
        output_package.payload_files,
        {value: file.source_mode & 0o777 for value, file in output_package.payload_files.items()},
    )
    if actual_manifest != expected_manifest:
        raise RetargetError(
            "output-validation-failed",
            "Reopened output payload differs from the planned logical payload.",
            details={
                "expected_manifest_sha256": manifest_hash(expected_manifest),
                "actual_manifest_sha256": manifest_hash(actual_manifest),
            },
        )
    expected_directories = set(plan.payload_directories)
    expected_directories.update(
        all_parent_directories(
            [*plan.payload_files, *plan.payload_directories],
        ),
    )
    actual_directories = set(output_package.payload_directories)
    if actual_directories != expected_directories:
        raise RetargetError(
            "output-validation-failed",
            "Reopened output directories differ from the planned payload.",
            details={
                "missing": sorted(expected_directories - actual_directories)[:20],
                "unexpected": sorted(actual_directories - expected_directories)[:20],
            },
        )


def revalidate_output(
    output_path: Path,
    plan: OutputPlan,
    target: Target,
    *,
    temporary_root: Path,
    max_members: int,
    max_archive_bytes: int,
    max_expanded_bytes: int,
    max_metadata_bytes: int,
    max_nesting: int,
) -> InspectedPackage:
    budget = ScanBudget(
        max_members=max_members,
        max_expanded_bytes=max_expanded_bytes,
        max_nesting=max_nesting,
        max_archive_bytes=max_archive_bytes,
        max_metadata_bytes=max_metadata_bytes,
    )
    output_package = inspect_package(
        output_path,
        budget=budget,
        temporary_root=temporary_root,
    )
    if any(finding.severity == "error" for finding in output_package.findings):
        raise RetargetError(
            "output-validation-failed",
            "Output reinspection reported a hard finding.",
        )
    compare_output_to_plan(output_package, plan, target)
    return output_package


def audit_findings(findings: Iterable[Finding]) -> list[dict[str, object]]:
    return [
        finding.to_dict()
        for finding in sorted(
            findings,
            key=lambda item: (
                item.severity,
                item.code,
                item.path or "",
                item.message,
            ),
        )
    ]


def target_to_audit(target: Target) -> dict[str, object]:
    return {
        "version": target.version,
        "slicer_path_version": target.path_version,
        "revision": target.revision,
        "os": target.os,
        "arch": target.arch,
        "revision_source": target.revision_source,
        "publication_status": target.publication_status,
        "lookup_attempts": target.lookup_attempts,
    }


def write_json_file(path: Path, value: dict[str, object]) -> None:
    serialized = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
        + b"\n"
    )
    try:
        with path.open("xb") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise RetargetError(
            "audit-write-failed",
            "Unable to write the audit JSON.",
            path=str(path),
            operational=True,
        ) from exc


def path_exists_without_following(path: Path) -> bool:
    return os.path.lexists(path)


def reject_unsafe_destination(path: Path, *, input_path: Path) -> None:
    exists = path_exists_without_following(path)
    if exists:
        try:
            destination_stat = path.lstat()
        except OSError as exc:
            raise RetargetError(
                "unsafe-output-path",
                "Unable to inspect an existing output destination.",
                path=str(path),
                operational=True,
            ) from exc
        if stat.S_ISLNK(destination_stat.st_mode):
            raise RetargetError(
                "unsafe-output-path",
                "Output destinations may not be symbolic links.",
                path=str(path),
            )
        if not stat.S_ISREG(destination_stat.st_mode):
            raise RetargetError(
                "unsafe-output-path",
                "An existing output destination must be a regular file.",
                path=str(path),
            )
        try:
            if os.path.samefile(path, input_path):
                raise RetargetError(
                    "in-place-retarget-refused",
                    "The input package may never be overwritten or aliased.",
                    path=str(path),
                )
        except RetargetError:
            raise
        except OSError as exc:
            raise RetargetError(
                "unsafe-output-path",
                "Unable to compare output and input file identities.",
                path=str(path),
                operational=True,
            ) from exc
    try:
        if path.resolve(strict=False) == input_path.resolve(strict=True):
            raise RetargetError(
                "in-place-retarget-refused",
                "The input package may never be overwritten in place.",
                path=str(path),
            )
    except OSError as exc:
        raise RetargetError(
            "unsafe-output-path",
            "Unable to resolve output destination safely.",
            path=str(path),
            operational=True,
        ) from exc


def unique_backup_path(path: Path) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.backup-",
        dir=path.parent,
    )
    os.close(descriptor)
    return Path(temporary_name)


def fsync_directory(directory: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def publish_output_pair(
    temporary_archive: Path,
    temporary_audit: Path,
    final_archive: Path,
    final_audit: Path,
    *,
    overwrite: bool,
    input_path: Path,
) -> None:
    """Publish the audit last as a commit marker.

    Ordinary failures are rolled back. An abrupt process or machine failure
    can still leave an archive, temporary file, or backup requiring recovery.
    """

    for destination in (final_archive, final_audit):
        reject_unsafe_destination(destination, input_path=input_path)
    existing = [path for path in (final_archive, final_audit) if path_exists_without_following(path)]
    if existing and not overwrite:
        raise RetargetError(
            "output-exists",
            "Output archive or audit already exists; pass --overwrite to replace it.",
            details={"paths": [str(path) for path in existing]},
        )
    backups: dict[Path, Path] = {}
    published: list[Path] = []
    try:
        if overwrite:
            for final_path in existing:
                backup = unique_backup_path(final_path)
                try:
                    os.replace(final_path, backup)
                except Exception:
                    with contextlib.suppress(OSError):
                        backup.unlink()
                    raise
                backups[final_path] = backup
        else:
            for temporary_path, final_path in (
                (temporary_archive, final_archive),
                (temporary_audit, final_audit),
            ):
                try:
                    os.link(
                        temporary_path,
                        final_path,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise RetargetError(
                        "output-exists",
                        "Output appeared while preparing publication.",
                        path=str(final_path),
                    ) from exc
                published.append(final_path)
                temporary_path.unlink()
        if overwrite:
            os.replace(temporary_archive, final_archive)
            published.append(final_archive)
            os.replace(temporary_audit, final_audit)
            published.append(final_audit)
        fsync_directory(final_archive.parent)
    except Exception as exc:
        for path in reversed(published):
            with contextlib.suppress(OSError):
                path.unlink()
        for final_path, backup in backups.items():
            with contextlib.suppress(OSError):
                os.replace(backup, final_path)
        if isinstance(exc, RetargetError):
            raise
        raise RetargetError(
            "output-publication-failed",
            "Unable to publish the output archive and audit.",
            operational=True,
        ) from exc
    else:
        for backup in backups.values():
            with contextlib.suppress(OSError):
                backup.unlink()


def select_package_date(
    package: InspectedPackage,
    explicit_date: str | None,
) -> dt.date:
    if explicit_date is not None:
        return parse_calendar_date(explicit_date, option_name="--package-date")
    if package.name_metadata.package_date is None:
        raise RetargetError(
            "package-date-required",
            ("The input filename has no conventional package date; pass --package-date YYYY-MM-DD."),
        )
    return package.name_metadata.package_date


def ensure_no_blocking_warnings(
    findings: list[Finding],
    *,
    fail_on_warning: bool,
) -> None:
    if fail_on_warning and any(finding.severity == "warning" for finding in findings):
        raise RetargetError(
            "warnings-promoted",
            "Warnings were found and --fail-on-warning was requested.",
        )


def run_inspect(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    input_path = Path(args.package)
    audit = new_audit("inspect", input_path)
    try:
        with tempfile.TemporaryDirectory(prefix="slicer-extension-inspect-") as temporary:
            package = inspect_package(
                input_path,
                budget=ScanBudget(
                    max_members=args.max_members,
                    max_expanded_bytes=args.max_expanded_bytes,
                    max_nesting=args.max_nesting,
                    max_archive_bytes=args.max_archive_bytes,
                    max_metadata_bytes=args.max_metadata_bytes,
                ),
                temporary_root=Path(temporary),
            )
            if package.name_metadata.package_date is None:
                add_finding(
                    package.findings,
                    "package-date-required",
                    "warning",
                    "Retargeting will require --package-date because the input filename is nonconventional.",
                )
            audit["source"] = package_to_audit_source(package)
            audit["findings"] = audit_findings(package.findings)
            ensure_no_blocking_warnings(
                package.findings,
                fail_on_warning=args.fail_on_warning,
            )
            audit["status"] = "passed"
            return 0, audit
    except RetargetError as error:
        add_error_to_audit(audit, error)
        return 1, audit
    except Exception as exc:
        error = RetargetError(
            "unexpected-error",
            f"Unexpected {type(exc).__name__} while inspecting the package.",
            operational=True,
        )
        add_error_to_audit(audit, error)
        return 1, audit


def create_temporary_output_path(
    directory: Path,
    final_name: str,
    *,
    official_archive_suffix: str | None = None,
) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{final_name}.tmp-",
        suffix=official_archive_suffix or ".tmp",
        dir=directory,
    )
    os.close(descriptor)
    return Path(name)


def run_retarget(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    input_path = Path(args.package)
    audit = new_audit("retarget", input_path)
    temporary_archive: Path | None = None
    temporary_audit: Path | None = None
    publication_temporary: tempfile.TemporaryDirectory[str] | None = None
    package: InspectedPackage | None = None
    transformations: list[dict[str, object]] = []
    try:
        validate_target_version(args.target_version, args.target_revision)
        with tempfile.TemporaryDirectory(prefix="slicer-extension-retarget-") as temporary:
            temporary_root = Path(temporary)
            package = inspect_package(
                input_path,
                budget=ScanBudget(
                    max_members=args.max_members,
                    max_expanded_bytes=args.max_expanded_bytes,
                    max_nesting=args.max_nesting,
                    max_archive_bytes=args.max_archive_bytes,
                    max_metadata_bytes=args.max_metadata_bytes,
                ),
                temporary_root=temporary_root,
            )
            audit["source"] = package_to_audit_source(package)
            audit["findings"] = audit_findings(package.findings)
            remove_verified_bytecode(package, transformations)
            package_date = select_package_date(package, args.package_date)
            target = resolve_target(
                version=args.target_version,
                explicit_revision=args.target_revision,
                target_os=args.target_os,
                target_arch=args.target_arch,
                findings=package.findings,
            )
            validate_package_date_for_target(package_date, target.os)
            audit["target"] = target_to_audit(target)
            audit["findings"] = audit_findings(package.findings)
            if target.os not in package.eligible_targets:
                problem = target_path_problem(
                    package.payload_files,
                    package.payload_directories,
                    target.os,
                )
                detail = problem[1] if problem else "target-specific path rules"
                raise RetargetError(
                    "target-path-incompatible",
                    f"Package paths are incompatible with target {target.os}: {detail}.",
                    path=problem[0] if problem else None,
                )
            plan = build_output_plan(
                package,
                target,
                package_date,
                transformations,
            )
            audit["findings"] = audit_findings(package.findings)
            audit["transformations"] = transformations
            ensure_no_blocking_warnings(
                package.findings,
                fail_on_warning=args.fail_on_warning,
            )

            output_directory = Path(args.output_dir).expanduser() if args.output_dir else package.input_path.parent
            try:
                output_directory.mkdir(parents=True, exist_ok=True)
                output_directory = output_directory.resolve(strict=True)
            except OSError as exc:
                raise RetargetError(
                    "output-directory-failed",
                    "Unable to create or resolve the output directory.",
                    path=str(output_directory),
                    operational=True,
                ) from exc
            if not output_directory.is_dir():
                raise RetargetError(
                    "output-directory-failed",
                    "Output directory is not a directory.",
                    path=str(output_directory),
                )
            final_archive = output_directory / f"{plan.root_name}{plan.archive_suffix}"
            final_audit = output_directory / f"{final_archive.name}.audit.json"
            reject_unsafe_destination(final_archive, input_path=package.input_path)
            reject_unsafe_destination(final_audit, input_path=package.input_path)
            if final_archive == final_audit:
                raise RetargetError(
                    "unsafe-output-path",
                    "Archive and audit destinations unexpectedly alias.",
                )
            if not args.overwrite and (path_exists_without_following(final_archive) or path_exists_without_following(final_audit)):
                raise RetargetError(
                    "output-exists",
                    "Output archive or audit already exists; pass --overwrite.",
                    details={
                        "archive": str(final_archive),
                        "audit": str(final_audit),
                    },
                )

            publication_temporary = tempfile.TemporaryDirectory(
                prefix=".slicer-extension-retarget-publish-",
                dir=output_directory,
            )
            publication_directory = Path(publication_temporary.name)
            temporary_archive = create_temporary_output_path(
                publication_directory,
                final_archive.name,
                official_archive_suffix=plan.archive_suffix,
            )
            write_output_archive(plan, temporary_archive)
            revalidated = revalidate_output(
                temporary_archive,
                plan,
                target,
                temporary_root=temporary_root / "revalidate",
                max_members=args.max_members,
                max_archive_bytes=args.max_archive_bytes,
                max_expanded_bytes=args.max_expanded_bytes,
                max_metadata_bytes=args.max_metadata_bytes,
                max_nesting=args.max_nesting,
            )
            output_sha256 = hash_file(temporary_archive)
            output_size = temporary_archive.stat().st_size
            output_manifest = logical_manifest(
                revalidated.payload_files,
                {value: file.source_mode & 0o777 for value, file in revalidated.payload_files.items()},
            )
            audit["findings"] = audit_findings(package.findings)
            audit["transformations"] = transformations
            audit["status"] = "retargeted"
            audit["runtime_compatibility"] = RUNTIME_COMPATIBILITY_LABEL
            audit["output"] = {
                "path": str(final_archive),
                "audit_path": str(final_audit),
                "archive_format": plan.archive_format,
                "archive_sha256": output_sha256,
                "archive_size": output_size,
                "root": plan.root_name,
                "logical_manifest_sha256": manifest_hash(output_manifest),
                "logical_manifest": output_manifest,
            }
            temporary_audit = create_temporary_output_path(
                publication_directory,
                final_audit.name,
            )
            # create_temporary_output_path creates the file; write_json_file uses
            # exclusive creation so remove only this exact private placeholder.
            temporary_audit.unlink()
            write_json_file(temporary_audit, audit)
            publish_output_pair(
                temporary_archive,
                temporary_audit,
                final_archive,
                final_audit,
                overwrite=args.overwrite,
                input_path=package.input_path,
            )
            temporary_archive = None
            temporary_audit = None
            return 0, audit
    except RetargetError as error:
        if package is not None:
            audit["findings"] = audit_findings(package.findings)
            audit["transformations"] = transformations
        add_error_to_audit(audit, error)
        return 1, audit
    except Exception as exc:
        if package is not None:
            audit["findings"] = audit_findings(package.findings)
            audit["transformations"] = transformations
        error = RetargetError(
            "unexpected-error",
            f"Unexpected {type(exc).__name__} while retargeting the package.",
            operational=True,
        )
        add_error_to_audit(audit, error)
        return 1, audit
    finally:
        for temporary_path in (temporary_archive, temporary_audit):
            if temporary_path is not None:
                with contextlib.suppress(OSError):
                    temporary_path.unlink()
        if publication_temporary is not None:
            publication_temporary.cleanup()


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print the audit object as JSON on stdout.",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Reject a package if any review warning is emitted.",
    )
    parser.add_argument(
        "--max-members",
        type=positive_integer,
        default=DEFAULT_MAX_MEMBERS,
        metavar="N",
        help=f"Maximum aggregate archive members (default: {DEFAULT_MAX_MEMBERS}).",
    )
    parser.add_argument(
        "--max-archive-bytes",
        type=positive_integer,
        default=DEFAULT_MAX_ARCHIVE_BYTES,
        metavar="N",
        help=(f"Maximum bytes in any raw outer or nested archive (default: {DEFAULT_MAX_ARCHIVE_BYTES})."),
    )
    parser.add_argument(
        "--max-expanded-bytes",
        type=positive_integer,
        default=DEFAULT_MAX_EXPANDED_BYTES,
        metavar="N",
        help=(f"Maximum aggregate expanded bytes across outer and nested archives (default: {DEFAULT_MAX_EXPANDED_BYTES})."),
    )
    parser.add_argument(
        "--max-metadata-bytes",
        type=positive_integer,
        default=DEFAULT_MAX_METADATA_BYTES,
        metavar="N",
        help=(f"Maximum aggregate expanded archive metadata bytes (default: {DEFAULT_MAX_METADATA_BYTES})."),
    )
    parser.add_argument(
        "--max-nesting",
        type=nonnegative_integer,
        default=DEFAULT_MAX_NESTING,
        metavar="N",
        help=f"Maximum nested archive depth (default: {DEFAULT_MAX_NESTING}).",
    )


def positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def target_version_argument(value: str) -> str:
    if not TARGET_VERSION_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "must be a stock Slicer version in 5.X or 5.X.Z form",
        )
    return value


def target_revision_argument(value: str) -> str:
    if not ASCII_DECIMAL_PATTERN.fullmatch(value) or int(value) <= 0:
        raise argparse.ArgumentTypeError("must be a positive decimal revision")
    return value


def architecture_argument(value: str) -> str:
    if not ARCH_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "must match [A-Za-z0-9][A-Za-z0-9._-]*",
        )
    return value


def package_date_argument(value: str) -> str:
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a real calendar date in YYYY-MM-DD form",
        ) from exc
    if parsed.isoformat() != value:
        raise argparse.ArgumentTypeError("must use exact YYYY-MM-DD form")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Audit and structurally retarget stock Slicer 5.x pure-Python extension packages. Structural retargeting does not certify runtime compatibility."),
        epilog=("Successful output is labeled: structurally retargeted; runtime compatibility not verified. The audit sidecar is published last as a commit marker; abrupt termination can leave recovery files."),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Audit package structure without writing files.",
    )
    inspect_parser.add_argument("package", help="Input .zip, .tar.gz, or .tgz package.")
    add_common_options(inspect_parser)

    retarget_parser = subparsers.add_parser(
        "retarget",
        help="Audit, transform, validate, and write a target package.",
    )
    retarget_parser.add_argument(
        "package",
        help="Input .zip, .tar.gz, or .tgz package.",
    )
    retarget_parser.add_argument(
        "--target-version",
        required=True,
        type=target_version_argument,
        metavar="5.X[.Z]",
        help=("Target Slicer version. 5.X is allowed with an explicit revision; online lookup requires exact 5.X.Z."),
    )
    retarget_parser.add_argument(
        "--target-revision",
        type=target_revision_argument,
        help="Positive decimal Slicer revision; bypasses online lookup.",
    )
    retarget_parser.add_argument(
        "--target-os",
        required=True,
        choices=TARGET_OPERATING_SYSTEMS,
        help="Target Slicer operating-system token.",
    )
    retarget_parser.add_argument(
        "--target-arch",
        required=True,
        type=architecture_argument,
        help="Target Slicer architecture token, such as amd64 or arm64.",
    )
    retarget_parser.add_argument(
        "--package-date",
        type=package_date_argument,
        metavar="YYYY-MM-DD",
        help="Override the source package date used in output naming/timestamps.",
    )
    retarget_parser.add_argument(
        "--output-dir",
        help="Output directory (default: directory containing the input package).",
    )
    retarget_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace the exact derived archive and audit paths if they exist.",
    )
    add_common_options(retarget_parser)
    return parser


def terminal_safe(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


def print_human_result(command: str, exit_code: int, audit: dict[str, object]) -> None:
    findings = audit.get("findings", [])
    assert isinstance(findings, list)
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = terminal_safe(finding.get("severity", "info")).upper()
        path = f" [{terminal_safe(finding['path'])}]" if finding.get("path") else ""
        stream = sys.stderr if severity in {"ERROR", "WARNING"} else sys.stdout
        print(
            (f"{severity} {terminal_safe(finding.get('code', 'finding'))}{path}: {terminal_safe(finding.get('message', ''))}"),
            file=stream,
        )
    if exit_code == 0:
        if command == "retarget" and isinstance(audit.get("output"), dict):
            output = audit["output"]
            print(f"Wrote {terminal_safe(output['path'])}")
            print(f"Audit {terminal_safe(output['audit_path'])}")
            print(RUNTIME_COMPATIBILITY_LABEL)
        else:
            source = audit.get("source", {})
            eligible = source.get("eligible_targets", []) if isinstance(source, dict) else []
            print(
                f"Package passed structural inspection. Eligible targets: {', '.join(eligible)}",
            )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "inspect":
        exit_code, audit = run_inspect(args)
    else:
        exit_code, audit = run_retarget(args)
    if args.json_output:
        json.dump(audit, sys.stdout, indent=2, sort_keys=True, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print_human_result(args.command, exit_code, audit)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

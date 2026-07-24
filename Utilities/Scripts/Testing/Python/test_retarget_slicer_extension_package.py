#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "packaging>=24.2,<27",
#   "pytest>=9,<10",
# ]
# ///

"""Run from the repository root:

uv run --script Utilities/Scripts/Testing/Python/test_retarget_slicer_extension_package.py -q
"""

from __future__ import annotations

import binascii
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import types
import zipfile

import pytest


SCRIPT = Path(__file__).with_name("retarget_slicer_extension_package.py")
if not SCRIPT.is_file():
    SCRIPT = Path(__file__).resolve().parents[2] / SCRIPT.name
SOURCE_REVISION = "34045"
TARGET_REVISION = "35000"
EXTENSION_NAME = "Demo"
EXTENSION_REVISION = "abc1234"
PACKAGE_DATE = "2026-07-18"


def s4ext(
    *,
    name: str = EXTENSION_NAME,
    scm: str = "git",
    scmrevision: str = EXTENSION_REVISION,
    depends: str = "NA",
) -> bytes:
    del name  # The extension name is defined by the .s4ext basename.
    return (
        f"""scm {scm}
scmurl https://example.invalid/Demo.git
scmrevision {scmrevision}
depends {depends}
homepage https://example.invalid/Demo
contributors Example Developer
category Examples
iconurl
screenshoturls
status
description A small scripted extension fixture
"""
    ).encode()


def flat_payload(
    *,
    version: str = "5.10",
    bytecode: bool = False,
    cache_bytecode: bool = False,
    dependencies: str = "NA",
) -> dict[str, bytes]:
    module = b'"""Test module containing source target strings verbatim."""\nSOURCE_NOTE = "lib/Slicer-5.10 34045 linux"\n'
    payload = {
        f"share/Slicer-{version}/{EXTENSION_NAME}.s4ext": s4ext(depends=dependencies),
        f"lib/Slicer-{version}/qt-scripted-modules/{EXTENSION_NAME}.py": module,
        f"lib/Slicer-{version}/qt-scripted-modules/Resources/UI/{EXTENSION_NAME}.ui": (b'<ui version="4.0"/>\n'),
        f"lib/Slicer-{version}/qt-scripted-modules/Resources/Icons/{EXTENSION_NAME}.png": (b"\x89PNG\r\n\x1a\nfixture"),
    }
    if bytecode:
        payload[f"lib/Slicer-{version}/qt-scripted-modules/{EXTENSION_NAME}.pyc"] = b"\xcb\r\r\nfixture bytecode"
    if cache_bytecode:
        payload[f"lib/Slicer-{version}/qt-scripted-modules/__pycache__/{EXTENSION_NAME}.cpython-312.pyc"] = b"\xcb\r\r\ncached fixture bytecode"
    return payload


def mac_payload(
    *,
    revision: str = SOURCE_REVISION,
    version: str = "5.10",
) -> dict[str, bytes]:
    prefix = f"Slicer.app/Contents/Extensions-{revision}/{EXTENSION_NAME}"
    return {f"{prefix}/{path}": data for path, data in flat_payload(version=version).items()}


def conventional_stem(
    *,
    revision: str = SOURCE_REVISION,
    os_name: str = "linux",
    arch: str = "amd64",
    date: str = PACKAGE_DATE,
) -> str:
    return f"{revision}-{os_name}-{arch}-{EXTENSION_NAME}-git{EXTENSION_REVISION}-{date}"


def write_tgz(
    path: Path,
    payload: dict[str, bytes],
    *,
    root: str | None = None,
    modes: dict[str, int] | None = None,
) -> Path:
    root = root or path.name.removesuffix(".tar.gz").removesuffix(".tgz")
    modes = modes or {}
    with tarfile.open(path, "w:gz") as archive:
        for relative_path, data in payload.items():
            info = tarfile.TarInfo(f"{root}/{relative_path}")
            info.size = len(data)
            info.mode = modes.get(relative_path, 0o644)
            info.mtime = 1_752_796_800
            archive.addfile(info, io.BytesIO(data))
    return path


def write_zip(
    path: Path,
    payload: dict[str, bytes],
    *,
    root: str | None = None,
    modes: dict[str, int] | None = None,
) -> Path:
    root = root or path.stem
    modes = modes or {}
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path, data in payload.items():
            info = zipfile.ZipInfo(
                f"{root}/{relative_path}",
                date_time=(2026, 7, 18, 0, 0, 0),
            )
            info.create_system = 3
            info.external_attr = modes.get(relative_path, 0o644) << 16
            archive.writestr(info, data)
    return path


def add_zip_entry_with_local_unicode_override(
    path: Path,
    *,
    safe_name: str,
    alternate_name: str,
) -> None:
    raw_name = safe_name.encode("ascii")
    alternate = alternate_name.encode("utf-8")
    unicode_path_data = b"\x01" + struct.pack("<L", binascii.crc32(raw_name) & 0xFFFFFFFF) + alternate
    unicode_path_extra = struct.pack("<HH", 0x7075, len(unicode_path_data)) + unicode_path_data
    with zipfile.ZipFile(path, "a") as archive:
        info = zipfile.ZipInfo(safe_name)
        info.extra = unicode_path_extra
        archive.writestr(info, b"decoy")

    raw_archive = bytearray(path.read_bytes())
    central_signature = b"PK\x01\x02"
    offset = 0
    patched = False
    while (offset := raw_archive.find(central_signature, offset)) >= 0:
        filename_size, extra_size = struct.unpack_from("<HH", raw_archive, offset + 28)
        filename_start = offset + 46
        filename_end = filename_start + filename_size
        extra_start = filename_end
        if bytes(raw_archive[filename_start:filename_end]) == raw_name:
            assert extra_size >= 4
            assert struct.unpack_from("<H", raw_archive, extra_start)[0] == 0x7075
            struct.pack_into("<H", raw_archive, extra_start, 0xFFFF)
            patched = True
            break
        offset = filename_end + extra_size
    assert patched
    path.write_bytes(raw_archive)


@pytest.fixture
def linux_package(tmp_path: Path) -> Path:
    path = tmp_path / f"{conventional_stem()}.tar.gz"
    return write_tgz(path, flat_payload())


@pytest.fixture
def windows_package(tmp_path: Path) -> Path:
    path = tmp_path / f"{conventional_stem(os_name='win')}.zip"
    return write_zip(path, flat_payload())


@pytest.fixture
def mac_package(tmp_path: Path) -> Path:
    path = tmp_path / f"{conventional_stem(os_name='macosx')}.tar.gz"
    return write_tgz(path, mac_payload())


@pytest.fixture(scope="session")
def production_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "retarget_slicer_extension_package_under_test",
        SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_cli(
    *arguments: object,
    expected: int | None = 0,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    assert SCRIPT.is_file(), f"Production script is missing: {SCRIPT}"
    command = [sys.executable, str(SCRIPT), *(str(argument) for argument in arguments)]
    completed = subprocess.run(
        command,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )
    if expected is not None:
        assert completed.returncode == expected, f"Command returned {completed.returncode}, expected {expected}\ncommand: {command!r}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    return completed


def output_archive(output_dir: Path) -> Path:
    archives = sorted(path for path in output_dir.iterdir() if path.name.endswith((".zip", ".tar.gz", ".tgz")))
    assert len(archives) == 1, archives
    return archives[0]


def archive_files(path: Path) -> dict[str, bytes]:
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    with tarfile.open(path, "r:gz") as archive:
        return {member.name: archive.extractfile(member).read() for member in archive.getmembers() if member.isfile()}


def retarget(
    package: Path,
    output_dir: Path,
    *,
    target_os: str = "linux",
    target_version: str = "5.12",
    revision: str = TARGET_REVISION,
    extra: tuple[object, ...] = (),
    expected: int | None = 0,
) -> subprocess.CompletedProcess[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    arguments: list[object] = [
        "retarget",
        package,
        "--target-version",
        target_version,
        "--target-os",
        target_os,
        "--target-arch",
        "amd64",
        "--target-revision",
        revision,
        "--output-dir",
        output_dir,
        *extra,
    ]
    return run_cli(*arguments, expected=expected)


def relative_files_without_root(path: Path) -> dict[str, bytes]:
    files = archive_files(path)
    roots = {name.split("/", 1)[0] for name in files}
    assert len(roots) == 1
    root = roots.pop()
    return {name.removeprefix(f"{root}/"): data for name, data in files.items()}


def test_help_documents_structural_compatibility_boundary() -> None:
    completed = run_cli("--help")
    text = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "inspect" in text
    assert "retarget" in text
    assert "runtime compatibility" in text


def test_inspect_json_is_read_only_and_reports_target_eligibility(
    linux_package: Path,
) -> None:
    before = set(linux_package.parent.iterdir())
    completed = run_cli("inspect", linux_package, "--json")
    report = json.loads(completed.stdout)
    assert set(linux_package.parent.iterdir()) == before
    assert report["status"] == "passed"
    assert report["source"]["archive_format"] == "tgz"
    assert report["source"]["extension"]["name"] == EXTENSION_NAME
    assert report["source"]["filename_metadata"]["arch"] == "amd64"
    assert {"linux", "win", "macosx"} <= set(
        report["source"]["eligible_targets"],
    )


@pytest.mark.parametrize(
    ("source_fixture", "target_os", "suffix"),
    [
        ("linux_package", "linux", ".tar.gz"),
        ("linux_package", "win", ".zip"),
        ("linux_package", "macosx", ".tar.gz"),
        ("windows_package", "linux", ".tar.gz"),
        ("windows_package", "win", ".zip"),
        ("windows_package", "macosx", ".tar.gz"),
        ("mac_package", "linux", ".tar.gz"),
        ("mac_package", "win", ".zip"),
        ("mac_package", "macosx", ".tar.gz"),
    ],
)
def test_all_platform_layout_and_format_conversions(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    source_fixture: str,
    target_os: str,
    suffix: str,
) -> None:
    package = request.getfixturevalue(source_fixture)
    output_dir = tmp_path / "converted"
    retarget(package, output_dir, target_os=target_os)

    output = output_archive(output_dir)
    assert output.name.endswith(suffix)
    assert output.name.startswith(f"{TARGET_REVISION}-{target_os}-amd64-")

    files = relative_files_without_root(output)
    if target_os == "macosx":
        prefix = f"Slicer.app/Contents/Extensions-{TARGET_REVISION}/{EXTENSION_NAME}/"
        assert files
        assert all(name.startswith(prefix) for name in files)
        files = {name.removeprefix(prefix): data for name, data in files.items()}
    else:
        assert not any(name.startswith("Slicer.app/") for name in files)

    assert f"share/Slicer-5.12/{EXTENSION_NAME}.s4ext" in files
    assert f"lib/Slicer-5.12/qt-scripted-modules/{EXTENSION_NAME}.py" in files
    assert not any("Slicer-5.10" in name for name in files)


def test_path_retargeting_does_not_rewrite_file_contents(
    linux_package: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "converted"
    retarget(linux_package, output_dir)
    files = relative_files_without_root(output_archive(output_dir))
    module_path = f"lib/Slicer-5.12/qt-scripted-modules/{EXTENSION_NAME}.py"
    assert b"lib/Slicer-5.10 34045 linux" in files[module_path]


def test_revision_only_retarget_preserves_version_paths(
    linux_package: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "converted"
    retarget(linux_package, output_dir, target_version="5.10")
    files = relative_files_without_root(output_archive(output_dir))
    assert f"share/Slicer-5.10/{EXTENSION_NAME}.s4ext" in files
    assert not any("Slicer-5.12" in name for name in files)


def test_paired_sibling_and_cache_bytecode_are_removed(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    write_tgz(
        source,
        flat_payload(bytecode=True, cache_bytecode=True),
    )
    output_dir = tmp_path / "converted"
    retarget(source, output_dir)
    names = relative_files_without_root(output_archive(output_dir))
    assert not any(name.endswith((".pyc", ".pyo")) for name in names)
    assert not any("/__pycache__/" in name for name in names)

    audit_path = next(output_dir.glob("*.audit.json"))
    audit = json.loads(audit_path.read_text())
    removed = [transformation for transformation in audit["transformations"] if transformation["kind"] == "remove-bytecode"]
    assert len(removed) == 1
    assert removed[0]["count"] == 2
    assert len(removed[0]["paths"]) == 2


@pytest.mark.parametrize(
    "relative_bytecode",
    [
        "lib/Slicer-5.10/qt-scripted-modules/Orphan.pyc",
        "lib/Slicer-5.10/qt-scripted-modules/__pycache__/Orphan.cpython-312.pyc",
        "lib/Slicer-5.10/qt-scripted-modules/Orphan.pyo",
    ],
)
def test_orphan_bytecode_is_rejected(
    tmp_path: Path,
    relative_bytecode: str,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload[relative_bytecode] = b"\xcb\r\r\norphan"
    write_tgz(source, payload)
    completed = retarget(source, tmp_path / "converted", expected=1)
    assert "bytecode" in f"{completed.stdout}\n{completed.stderr}".lower()


def test_inspect_rejects_orphan_bytecode(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/Orphan.pyc"] = b"\xcb\r\r\norphan"
    write_tgz(source, payload)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert audit["status"] == "rejected"
    assert any(finding["code"] == "orphan-bytecode" for finding in audit["findings"])


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        ("lib/Slicer-5.10/qt-scripted-modules/data.bin", b"\x7fELF\x02\x01\x01"),
        ("lib/Slicer-5.10/qt-scripted-modules/data.bin", b"MZ" + b"\0" * 100),
        (
            "lib/Slicer-5.10/qt-scripted-modules/data.bin",
            b"\xcf\xfa\xed\xfe" + b"\0" * 20,
        ),
        ("lib/Slicer-5.10/qt-scripted-modules/plugin.so", b"not actually ELF"),
        ("lib/Slicer-5.10/qt-scripted-modules/plugin.pyd", b"opaque"),
        ("lib/Slicer-5.10/qt-scripted-modules/object.a", b"!<arch>\n"),
    ],
)
def test_native_payload_is_rejected_by_magic_or_suffix(
    tmp_path: Path,
    relative_path: str,
    content: bytes,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload[relative_path] = content
    write_tgz(source, payload)
    completed = retarget(source, tmp_path / "converted", expected=1)
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "native" in diagnostic or "executable" in diagnostic


def test_unknown_opaque_binary_is_warning_and_fail_on_warning_preserves_it(
    tmp_path: Path,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/opaque.bin"] = b"\x00\x01\x02unclassified"
    write_tgz(source, payload)

    inspected = run_cli("inspect", source, "--json")
    passed_audit = json.loads(inspected.stdout)
    assert passed_audit["status"] == "passed"
    assert any(finding["code"] == "unknown-binary-resource" for finding in passed_audit["findings"])

    promoted = run_cli(
        "inspect",
        source,
        "--json",
        "--fail-on-warning",
        expected=1,
    )
    rejected_audit = json.loads(promoted.stdout)
    finding_codes = {finding["code"] for finding in rejected_audit["findings"]}
    assert {"unknown-binary-resource", "warnings-promoted"} <= finding_codes


def test_resource_suffix_without_matching_magic_still_warns(
    tmp_path: Path,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/not-really.png"] = b"\x00opaque payload"
    write_tgz(source, payload)

    completed = run_cli("inspect", source, "--json")
    audit = json.loads(completed.stdout)
    assert any(finding["code"] == "unknown-binary-resource" for finding in audit["findings"])


def wheel_bytes(
    filename: str,
    *,
    purelib: bool = True,
    native_payload: bool = False,
    extra_payload: dict[str, bytes] | None = None,
) -> bytes:
    distribution = "sample"
    version = "1.0"
    wheel_tag = filename.removesuffix(".whl").rsplit("-", 3)[-3:]
    tag = "-".join(wheel_tag)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{distribution}/__init__.py", b"VALUE = 1\n")
        archive.writestr(
            f"{distribution}-{version}.dist-info/WHEEL",
            (f"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: {'true' if purelib else 'false'}\nTag: {tag}\n"),
        )
        archive.writestr(
            f"{distribution}-{version}.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: sample\nVersion: 1.0\n",
        )
        if native_payload:
            archive.writestr(f"{distribution}/hidden.dat", b"\x7fELF\x02\x01\x01")
        for path, data in (extra_payload or {}).items():
            archive.writestr(path, data)
    return stream.getvalue()


def uncompressed_tar_bytes(payload: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for relative_path, data in payload.items():
            info = tarfile.TarInfo(relative_path)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


@pytest.mark.parametrize("asset_name", ["assets.tar", "assets.dat"])
def test_nested_uncompressed_tar_with_elf_is_rejected(
    tmp_path: Path,
    asset_name: str,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload[f"lib/Slicer-5.10/qt-scripted-modules/{asset_name}"] = uncompressed_tar_bytes(
        {"payload/innocent-name.dat": b"\x7fELF\x02\x01\x01"},
    )
    write_tgz(source, payload)

    completed = run_cli("inspect", source, expected=1)
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "native" in diagnostic or "unsupported-nested-archive" in diagnostic
    assert asset_name in diagnostic


def test_pure_none_any_wheel_is_preserved_byte_for_byte(tmp_path: Path) -> None:
    wheel_name = "sample-1.0-py3-none-any.whl"
    wheel = wheel_bytes(wheel_name)
    payload = flat_payload()
    payload[f"lib/Slicer-5.10/qt-scripted-modules/{wheel_name}"] = wheel
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    write_tgz(source, payload)

    output_dir = tmp_path / "converted"
    retarget(source, output_dir)
    files = relative_files_without_root(output_archive(output_dir))
    target_path = f"lib/Slicer-5.12/qt-scripted-modules/{wheel_name}"
    assert files[target_path] == wheel


@pytest.mark.parametrize(
    ("wheel_name", "purelib", "native_payload"),
    [
        ("sample-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", False, True),
        ("sample-1.0-py3-none-any.whl", False, False),
        ("sample-1.0-py3-none-any.whl", True, True),
    ],
)
def test_unsafe_wheel_is_rejected(
    tmp_path: Path,
    wheel_name: str,
    purelib: bool,
    native_payload: bool,
) -> None:
    payload = flat_payload()
    payload[f"lib/Slicer-5.10/qt-scripted-modules/{wheel_name}"] = wheel_bytes(
        wheel_name,
        purelib=purelib,
        native_payload=native_payload,
    )
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    write_tgz(source, payload)
    completed = retarget(source, tmp_path / "converted", expected=1)
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "wheel" in diagnostic or "native" in diagnostic


@pytest.mark.parametrize(
    "extra_payload",
    [
        {"sample/Foo.py": b"", "sample/foo.py": b""},
        {"sample/CON.py": b""},
        {"sample/bad?.py": b""},
    ],
)
def test_pure_wheel_paths_must_be_portable(
    tmp_path: Path,
    extra_payload: dict[str, bytes],
) -> None:
    wheel_name = "sample-1.0-py3-none-any.whl"
    payload = flat_payload()
    payload[f"lib/Slicer-5.10/qt-scripted-modules/{wheel_name}"] = wheel_bytes(
        wheel_name,
        extra_payload=extra_payload,
    )
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    write_tgz(source, payload)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert any(finding["code"] in {"nonportable-wheel-path", "unsafe-wheel-content"} for finding in audit["findings"])


def test_gzip_tar_hidden_behind_data_suffix_is_scanned(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    nested_tar = uncompressed_tar_bytes(
        {"payload/innocent-name.dat": b"\x7fELF\x02\x01\x01"},
    )
    payload["lib/Slicer-5.10/qt-scripted-modules/assets.dat"] = gzip.compress(
        nested_tar,
    )
    write_tgz(source, payload)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert any(finding["code"] == "native-payload" for finding in audit["findings"])


def test_v7_gzip_tar_cannot_hide_behind_nifti_suffix(tmp_path: Path) -> None:
    nested_tar = bytearray(
        uncompressed_tar_bytes(
            {"payload/innocent-name.dat": b"\x7fELF\x02\x01\x01"},
        ),
    )
    nested_tar[257:265] = b"\0" * 8
    nested_tar[148:156] = b" " * 8
    checksum = sum(nested_tar[:512])
    nested_tar[148:156] = f"{checksum:06o}\0 ".encode()

    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/hidden.nii.gz"] = gzip.compress(
        nested_tar,
    )
    write_tgz(source, payload)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert any(finding["code"] == "native-payload" for finding in audit["findings"])


def test_prepended_zip_cannot_hide_behind_png_suffix(tmp_path: Path) -> None:
    nested_stream = io.BytesIO()
    with zipfile.ZipFile(nested_stream, "w") as archive:
        archive.writestr("payload/innocent-name.dat", b"\x7fELF\x02\x01\x01")
    polyglot = b"\x89PNG\r\n\x1a\nopaque-prefix" + nested_stream.getvalue()
    assert zipfile.is_zipfile(io.BytesIO(polyglot))

    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/hidden.png"] = polyglot
    write_tgz(source, payload)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert audit["status"] == "rejected"
    assert any(finding["code"] in {"native-payload", "ambiguous-zip-metadata"} for finding in audit["findings"])


def test_tar_path_traversal_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    root = conventional_stem()
    with tarfile.open(source, "w:gz") as archive:
        for relative_path, data in flat_payload().items():
            info = tarfile.TarInfo(f"{root}/{relative_path}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        malicious = b"escape"
        info = tarfile.TarInfo(f"{root}/../escaped.py")
        info.size = len(malicious)
        archive.addfile(info, io.BytesIO(malicious))
    completed = run_cli("inspect", source, expected=1)
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "unsafe" in diagnostic or "traversal" in diagnostic


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "/absolute.py",
        "C:/drive.py",
        r"root\windows.py",
        "//server/share/file.py",
        "root/control\x01.py",
    ],
)
def test_unsafe_zip_member_paths_are_rejected(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    source = tmp_path / f"{conventional_stem(os_name='win')}.zip"
    with zipfile.ZipFile(source, "w") as archive:
        root = conventional_stem(os_name="win")
        for relative_path, data in flat_payload().items():
            archive.writestr(f"{root}/{relative_path}", data)
        archive.writestr(unsafe_name, b"unsafe")
    completed = run_cli("inspect", source, expected=1)
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert any(marker in diagnostic for marker in ("unsafe", "path", "absolute", "drive", "backslash", "root"))


def test_zip_local_unicode_path_override_is_rejected(tmp_path: Path) -> None:
    root = conventional_stem(os_name="win")
    source = tmp_path / f"{root}.zip"
    write_zip(source, flat_payload(), root=root)
    safe_name = f"{root}/safe-resource.txt"
    add_zip_entry_with_local_unicode_override(
        source,
        safe_name=safe_name,
        alternate_name=f"{root}/../escape.txt",
    )

    with zipfile.ZipFile(source) as archive:
        assert safe_name in archive.namelist()
        assert not any("/../" in name for name in archive.namelist())

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert audit["status"] == "rejected"
    assert any(finding["code"] == "ambiguous-zip-path" for finding in audit["findings"])


def test_zip_raw_nul_name_is_rejected_even_with_python_truncation(
    tmp_path: Path,
) -> None:
    root = conventional_stem(os_name="win")
    source = tmp_path / f"{root}.zip"
    write_zip(source, flat_payload(), root=root)
    raw_name = f"{root}/safeXhidden.txt".encode()
    with zipfile.ZipFile(source, "a") as archive:
        archive.writestr(raw_name.decode(), b"decoy")
    raw_archive = source.read_bytes()
    assert raw_archive.count(raw_name) == 2
    source.write_bytes(raw_archive.replace(raw_name, raw_name.replace(b"X", b"\0")))

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert any(finding["code"] == "ambiguous-zip-path" for finding in audit["findings"])


def test_zip_local_type_override_extra_field_is_rejected(
    tmp_path: Path,
) -> None:
    root = conventional_stem(os_name="win")
    source = tmp_path / f"{root}.zip"
    write_zip(source, flat_payload(), root=root)
    safe_name = f"{root}/safe-resource.txt"
    with zipfile.ZipFile(source, "a") as archive:
        info = zipfile.ZipInfo(safe_name)
        info.extra = struct.pack("<HH", 0x6C78, 0)
        archive.writestr(info, b"decoy")

    raw_archive = bytearray(source.read_bytes())
    offset = 0
    patched = False
    while (offset := raw_archive.find(b"PK\x01\x02", offset)) >= 0:
        name_size, extra_size = struct.unpack_from("<HH", raw_archive, offset + 28)
        name_start = offset + 46
        name_end = name_start + name_size
        if bytes(raw_archive[name_start:name_end]) == safe_name.encode():
            assert extra_size == 4
            struct.pack_into("<H", raw_archive, name_end, 0xFFFF)
            patched = True
            break
        offset = name_end + extra_size
    assert patched
    source.write_bytes(raw_archive)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert any(finding["code"] == "ambiguous-zip-type" for finding in audit["findings"])


def test_zip_local_and_central_sizes_must_agree(tmp_path: Path) -> None:
    root = conventional_stem(os_name="win")
    source = tmp_path / f"{root}.zip"
    write_zip(source, flat_payload(), root=root)
    safe_name = f"{root}/size-resource.txt"
    with zipfile.ZipFile(source, "a") as archive:
        archive.writestr(safe_name, b"short")

    raw_archive = bytearray(source.read_bytes())
    name_offset = raw_archive.find(safe_name.encode())
    assert name_offset >= 30
    local_header_offset = name_offset - 30
    assert raw_archive[local_header_offset : local_header_offset + 4] == b"PK\x03\x04"
    struct.pack_into("<L", raw_archive, local_header_offset + 22, 2**31)
    source.write_bytes(raw_archive)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert any(finding["code"] == "ambiguous-zip-metadata" for finding in audit["findings"])


def test_zip_local_metadata_is_charged_to_aggregate_budget(
    production_module: types.ModuleType,
) -> None:
    raw_name = b"member.txt"
    local_extra = b"x" * 32
    header = struct.pack(
        "<4s5H3L2H",
        b"PK\x03\x04",
        20,
        0,
        zipfile.ZIP_STORED,
        0,
        0,
        0,
        0,
        0,
        len(raw_name),
        len(local_extra),
    )
    info = zipfile.ZipInfo(raw_name.decode())
    info.header_offset = 0
    budget = production_module.ScanBudget(
        max_metadata_bytes=30 + len(raw_name) + len(local_extra) - 1,
    )

    with pytest.raises(production_module.RetargetError) as error:
        production_module.read_and_validate_local_zip_header(
            io.BytesIO(header + raw_name + local_extra),
            info,
            budget,
            label="fixture.zip!member.txt",
        )
    assert error.value.code == "archive-metadata-limit"


def test_tar_symlink_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    root = conventional_stem()
    with tarfile.open(source, "w:gz") as archive:
        for relative_path, data in flat_payload().items():
            info = tarfile.TarInfo(f"{root}/{relative_path}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo(f"{root}/linked.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "lib/Slicer-5.10/qt-scripted-modules/Demo.py"
        archive.addfile(link)
    completed = run_cli("inspect", source, expected=1)
    assert "link" in f"{completed.stdout}\n{completed.stderr}".lower()


def test_file_cannot_also_be_an_implicit_parent_directory(
    tmp_path: Path,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/conflict"] = b"file"
    payload["lib/Slicer-5.10/qt-scripted-modules/conflict/child.txt"] = b"child"
    write_tgz(source, payload)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert audit["status"] == "rejected"
    assert any(finding["code"] == "path-prefix-conflict" for finding in audit["findings"])


def test_archive_path_cannot_be_both_file_and_explicit_directory(
    tmp_path: Path,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    root = conventional_stem()
    with tarfile.open(source, "w:gz") as archive:
        for relative_path, data in flat_payload().items():
            info = tarfile.TarInfo(f"{root}/{relative_path}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        conflict_path = f"{root}/lib/Slicer-5.10/conflict"
        file_info = tarfile.TarInfo(conflict_path)
        file_info.size = 4
        archive.addfile(file_info, io.BytesIO(b"file"))
        directory_info = tarfile.TarInfo(f"{conflict_path}/")
        directory_info.type = tarfile.DIRTYPE
        archive.addfile(directory_info)

    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert audit["status"] == "rejected"
    assert any(finding["code"] in {"path-kind-conflict", "duplicate-archive-member"} for finding in audit["findings"])


def test_retarget_closes_parents_of_explicit_empty_directories(
    tmp_path: Path,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    root = conventional_stem()
    leaf_directory = "lib/Slicer-5.10/empty/leaf"
    with tarfile.open(source, "w:gz") as archive:
        for relative_path, data in flat_payload().items():
            info = tarfile.TarInfo(f"{root}/{relative_path}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        directory_info = tarfile.TarInfo(f"{root}/{leaf_directory}/")
        directory_info.type = tarfile.DIRTYPE
        archive.addfile(directory_info)

    output_dir = tmp_path / "converted"
    retarget(source, output_dir)

    with tarfile.open(output_archive(output_dir), "r:gz") as archive:
        names = set(archive.getnames())
    output_root = conventional_stem(
        revision=TARGET_REVISION,
        date=PACKAGE_DATE,
    )
    assert f"{output_root}/lib/Slicer-5.12/empty" in names
    assert f"{output_root}/lib/Slicer-5.12/empty/leaf" in names


def test_multiple_archive_roots_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        for root in ("one", "two"):
            for relative_path, data in flat_payload().items():
                info = tarfile.TarInfo(f"{root}/{relative_path}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    completed = run_cli("inspect", source, expected=1)
    assert "root" in f"{completed.stdout}\n{completed.stderr}".lower()


def test_missing_and_multiple_s4ext_are_rejected(tmp_path: Path) -> None:
    missing = tmp_path / f"{conventional_stem(date='2026-07-17')}.tar.gz"
    missing_payload = {path: data for path, data in flat_payload().items() if not path.endswith(".s4ext")}
    write_tgz(missing, missing_payload)
    completed = run_cli("inspect", missing, expected=1)
    assert ".s4ext" in f"{completed.stdout}\n{completed.stderr}".lower()

    multiple = tmp_path / f"{conventional_stem()}.tar.gz"
    multiple_payload = flat_payload()
    multiple_payload["share/Slicer-5.10/Other.s4ext"] = s4ext()
    write_tgz(multiple, multiple_payload)
    completed = run_cli("inspect", multiple, expected=1)
    assert ".s4ext" in f"{completed.stdout}\n{completed.stderr}".lower()


def test_windows_casefold_collision_is_target_specific(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/data.txt"] = b"lower"
    payload["lib/Slicer-5.10/qt-scripted-modules/DATA.txt"] = b"upper"
    write_tgz(source, payload)

    # Linux keeps both distinct paths.
    retarget(source, tmp_path / "linux-output", target_os="linux")

    completed = retarget(
        source,
        tmp_path / "windows-output",
        target_os="win",
        expected=1,
    )
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "collision" in diagnostic or "case" in diagnostic


@pytest.mark.parametrize(
    "forbidden_character",
    ["<", ">", "\x22", "|", "?", "*"],
)
def test_windows_forbidden_filename_characters_are_target_specific(
    tmp_path: Path,
    forbidden_character: str,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload[f"lib/Slicer-5.10/qt-scripted-modules/forbidden{forbidden_character}name.txt"] = b"resource"
    write_tgz(source, payload)

    retarget(source, tmp_path / "linux-output", target_os="linux")

    completed = retarget(
        source,
        tmp_path / "windows-output",
        target_os="win",
        expected=1,
    )
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "windows" in diagnostic
    assert "forbidden" in diagnostic


def test_windows_casefolded_file_and_implicit_parent_conflict(
    tmp_path: Path,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/CasePath"] = b"regular file"
    payload["lib/Slicer-5.10/qt-scripted-modules/casepath/child.txt"] = b"child"
    write_tgz(source, payload)

    retarget(source, tmp_path / "linux-output", target_os="linux")

    completed = retarget(
        source,
        tmp_path / "windows-output",
        target_os="win",
        expected=1,
    )
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "case" in diagnostic
    assert "parent" in diagnostic or "collision" in diagnostic


def test_renamed_package_requires_explicit_package_date(tmp_path: Path) -> None:
    source = tmp_path / "renamed-input.tgz"
    write_tgz(source, flat_payload(), root=conventional_stem())
    completed = retarget(source, tmp_path / "missing-date", expected=1)
    assert "date" in f"{completed.stdout}\n{completed.stderr}".lower()

    output_dir = tmp_path / "with-date"
    retarget(
        source,
        output_dir,
        extra=("--package-date", "2026-07-20"),
    )
    assert "-2026-07-20.tar.gz" in output_archive(output_dir).name


def test_filename_metadata_mismatch_requires_explicit_date(
    tmp_path: Path,
) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    description_path = f"share/Slicer-5.10/{EXTENSION_NAME}.s4ext"
    payload[description_path] = s4ext(scmrevision="different-revision")
    write_tgz(source, payload)

    inspected = run_cli("inspect", source, "--json")
    audit = json.loads(inspected.stdout)
    assert audit["source"]["filename_metadata"] == {
        "revision": None,
        "os": None,
        "arch": None,
        "package_date": None,
    }
    assert any(finding["code"] == "package-date-required" for finding in audit["findings"])

    completed = retarget(source, tmp_path / "converted", expected=1)
    assert "package-date" in f"{completed.stdout}\n{completed.stderr}".lower()


def test_fail_on_warning_json_retains_original_warnings(tmp_path: Path) -> None:
    source = tmp_path / "renamed-input.tgz"
    write_tgz(source, flat_payload(), root=conventional_stem())

    completed = run_cli(
        "inspect",
        source,
        "--json",
        "--fail-on-warning",
        expected=1,
    )
    audit = json.loads(completed.stdout)
    assert audit["status"] == "rejected"
    finding_codes = {finding["code"] for finding in audit["findings"]}
    assert "package-date-required" in finding_codes
    assert "warnings-promoted" in finding_codes


@pytest.mark.parametrize("package_date", ["1979-12-31", "2108-01-01"])
def test_windows_output_rejects_dates_outside_zip_range(
    linux_package: Path,
    tmp_path: Path,
    package_date: str,
) -> None:
    output_dir = tmp_path / package_date
    completed = retarget(
        linux_package,
        output_dir,
        target_os="win",
        extra=("--package-date", package_date),
        expected=1,
    )
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "zip" in diagnostic
    assert "date" in diagnostic
    assert not list(output_dir.glob("*.zip"))
    assert not list(output_dir.glob("*.audit.json"))


def test_audit_has_required_provenance_and_compatibility_boundary(
    linux_package: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "converted"
    completed = retarget(
        linux_package,
        output_dir,
        extra=("--json",),
    )
    stdout_audit = json.loads(completed.stdout)
    sidecars = list(output_dir.glob("*.audit.json"))
    assert len(sidecars) == 1
    sidecar_audit = json.loads(sidecars[0].read_text())
    assert stdout_audit == sidecar_audit

    assert sidecar_audit["schema_version"]
    assert sidecar_audit["command"] == "retarget"
    assert sidecar_audit["status"] == "retargeted"
    assert sidecar_audit["runtime_compatibility"] == "structurally retargeted; runtime compatibility not verified"
    assert sidecar_audit["source"]["archive_sha256"]
    assert sidecar_audit["target"]["revision"] == TARGET_REVISION
    assert sidecar_audit["target"]["version"] == "5.12"
    assert sidecar_audit["target"]["os"] == "linux"
    assert sidecar_audit["output"]["archive_sha256"]
    assert sidecar_audit["output"]["path"]


def test_output_is_deterministic(linux_package: Path, tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    retarget(linux_package, first_dir)
    retarget(linux_package, second_dir)
    assert output_archive(first_dir).read_bytes() == output_archive(second_dir).read_bytes()


def test_existing_output_requires_overwrite(
    linux_package: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "converted"
    retarget(linux_package, output_dir)
    output = output_archive(output_dir)
    original = output.read_bytes()

    completed = retarget(linux_package, output_dir, expected=1)
    assert output.read_bytes() == original
    assert "exist" in f"{completed.stdout}\n{completed.stderr}".lower()

    retarget(linux_package, output_dir, extra=("--overwrite",))
    assert output.is_file()


@pytest.mark.parametrize("destination_kind", ["archive", "audit"])
def test_overwrite_refuses_existing_output_directories_without_moving_them(
    linux_package: Path,
    tmp_path: Path,
    destination_kind: str,
) -> None:
    output_dir = tmp_path / destination_kind
    output_dir.mkdir()
    basename = f"{TARGET_REVISION}-linux-amd64-{EXTENSION_NAME}-git{EXTENSION_REVISION}-{PACKAGE_DATE}.tar.gz"
    archive_path = output_dir / basename
    audit_path = output_dir / f"{basename}.audit.json"
    destination = archive_path if destination_kind == "archive" else audit_path
    destination.mkdir()
    marker = destination / "do-not-move.txt"
    marker.write_text("preserve this directory")

    completed = retarget(
        linux_package,
        output_dir,
        extra=("--overwrite",),
        expected=1,
    )
    assert destination.is_dir()
    assert marker.read_text() == "preserve this directory"
    assert not list(output_dir.glob(".*.backup-*"))
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    assert "directory" in diagnostic or "regular file" in diagnostic
    assert "refus" in diagnostic


def test_overwrite_refuses_hardlink_alias_of_input(
    linux_package: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "hardlink"
    output_dir.mkdir()
    output_name = f"{TARGET_REVISION}-linux-amd64-{EXTENSION_NAME}-git{EXTENSION_REVISION}-{PACKAGE_DATE}.tar.gz"
    alias = output_dir / output_name
    os.link(linux_package, alias)
    original = linux_package.read_bytes()

    completed = retarget(
        linux_package,
        output_dir,
        extra=("--overwrite",),
        expected=1,
    )
    assert linux_package.read_bytes() == original
    assert os.path.samefile(alias, linux_package)
    assert "alias" in f"{completed.stdout}\n{completed.stderr}".lower()


def test_no_overwrite_publication_does_not_replace_racing_file(
    production_module: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    temporary_archive = tmp_path / "temporary.tar.gz"
    temporary_audit = tmp_path / "temporary.audit.json"
    final_archive = tmp_path / "final.tar.gz"
    final_audit = tmp_path / "final.audit.json"
    input_path = tmp_path / "input.tar.gz"
    temporary_archive.write_bytes(b"new archive")
    temporary_audit.write_bytes(b"new audit")
    input_path.write_bytes(b"input")
    original_link = os.link

    def racing_link(
        source: object,
        destination: object,
        **kwargs: object,
    ) -> None:
        destination_path = Path(destination)
        if destination_path == final_archive and not destination_path.exists():
            destination_path.write_bytes(b"racing owner")
        original_link(source, destination, **kwargs)

    monkeypatch.setattr(production_module.os, "link", racing_link)
    with pytest.raises(production_module.RetargetError) as error:
        production_module.publish_output_pair(
            temporary_archive,
            temporary_audit,
            final_archive,
            final_audit,
            overwrite=False,
            input_path=input_path,
        )
    assert error.value.code == "output-exists"
    assert final_archive.read_bytes() == b"racing owner"
    assert not final_audit.exists()


def test_invalid_target_values_use_usage_exit_code(
    linux_package: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "converted"
    for version, os_name, revision in [
        ("five.ten", "linux", TARGET_REVISION),
        ("5.10", "solaris", TARGET_REVISION),
        ("5.10", "linux", "not-a-revision"),
    ]:
        completed = retarget(
            linux_package,
            output_dir,
            target_version=version,
            target_os=os_name,
            revision=revision,
            expected=None,
        )
        assert completed.returncode == 2


def test_raw_archive_size_limit_is_enforced(
    linux_package: Path,
) -> None:
    completed = run_cli(
        "inspect",
        linux_package,
        "--json",
        "--max-archive-bytes",
        "1",
        expected=1,
    )
    audit = json.loads(completed.stdout)
    assert any(finding["code"] == "archive-raw-size-limit" for finding in audit["findings"])


def test_tar_metadata_entry_bound_is_enforced_before_processing(
    production_module: types.ModuleType,
) -> None:
    info = production_module.BoundedTarInfo("large-pax-header")
    info.size = production_module.MAX_TAR_METADATA_ENTRY_BYTES + 1
    with pytest.raises(production_module.RetargetError) as error:
        info._check_metadata_size()
    assert error.value.code == "archive-metadata-limit"


def test_tar_metadata_chain_is_bounded_before_python_recursion(
    tmp_path: Path,
) -> None:
    def pax_record(key: str, value: str) -> bytes:
        body = f" {key}={value}\n".encode()
        length = len(body) + 1
        while True:
            record = str(length).encode() + body
            if len(record) == length:
                return record
            length = len(record)

    root = conventional_stem()
    normal_tar = uncompressed_tar_bytes(
        {f"{root}/{path}": data for path, data in flat_payload().items()},
    )
    metadata = bytearray()
    for index in range(20):
        data = pax_record(f"comment{index}", "value")
        info = tarfile.TarInfo(f"global-pax-{index}")
        info.type = tarfile.XGLTYPE
        info.size = len(data)
        metadata.extend(info.tobuf(format=tarfile.PAX_FORMAT))
        metadata.extend(data)
        metadata.extend(b"\0" * (-len(data) % 512))

    source = tmp_path / f"{root}.tar.gz"
    source.write_bytes(gzip.compress(bytes(metadata) + normal_tar))
    completed = run_cli("inspect", source, "--json", expected=1)
    audit = json.loads(completed.stdout)
    assert any(finding["code"] in {"archive-member-limit", "archive-metadata-limit"} for finding in audit["findings"])


def test_missing_command_uses_argparse_exit_code() -> None:
    completed = run_cli(expected=None)
    assert completed.returncode == 2
    assert completed.stderr


def test_explicit_revision_accepts_major_minor_without_network(
    linux_package: Path,
    tmp_path: Path,
) -> None:
    hostile_environment = os.environ.copy()
    hostile_environment.update(
        {
            "http_proxy": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
        },
    )
    output_dir = tmp_path / "converted"
    output_dir.mkdir()
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "retarget",
            str(linux_package),
            "--target-version",
            "5.12",
            "--target-os",
            "linux",
            "--target-arch",
            "amd64",
            "--target-revision",
            TARGET_REVISION,
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        check=False,
        env=hostile_environment,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"


def test_package_server_revision_lookup_uses_exact_release_and_tuple(
    production_module: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = json.dumps(
        [
            {
                "meta": {
                    "baseName": "Slicer",
                    "version": "5.12.3",
                    "revision": "35501",
                    "os": "linux",
                    "arch": "amd64",
                },
            },
            {
                "meta": {
                    "baseName": "Slicer",
                    "version": "5.12.3",
                    "revision": "35501",
                    "os": "win",
                    "arch": "amd64",
                },
            },
            {
                "meta": {
                    "baseName": "Slicer",
                    "version": "5.10.0",
                    "revision": SOURCE_REVISION,
                    "os": "linux",
                    "arch": "amd64",
                },
            },
        ],
    ).encode()
    requested_urls: list[str] = []

    def fake_fetch(url: str) -> tuple[bytes, str]:
        requested_urls.append(url)
        return response, url

    monkeypatch.setattr(production_module, "fetch_https", fake_fetch)
    findings: list[object] = []
    target = production_module.resolve_target(
        version="5.12.3",
        explicit_revision=None,
        target_os="win",
        target_arch="amd64",
        findings=findings,
    )

    assert target.revision == "35501"
    assert target.path_version == "5.12"
    assert target.revision_source == "package-server"
    assert target.publication_status == "published"
    assert findings == []
    assert len(requested_urls) == 1
    assert "release_id_or_name=5.12.3" in requested_urls[0]


def extension_stats_source(*, revision: str = "35501") -> bytes:
    return f"""
raise RuntimeError("must never execute downloaded source")

class ExtensionStatsLogic:
    def __init__(self):
        releases_revisionsDates = {{
            "5.12.3": ["{revision}", "2026-07-01"],
        }}
""".encode()


def test_extensionstats_mapping_is_parsed_without_execution(
    production_module: types.ModuleType,
) -> None:
    mapping = production_module.parse_extension_stats_mapping(
        extension_stats_source(),
    )
    assert mapping["5.12.3"] == ["35501", "2026-07-01"]


def test_revision_lookup_falls_back_to_extensionstats(
    production_module: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_fetch(url: str) -> tuple[bytes, str]:
        calls.append(url)
        if "slicer-packages.kitware.com" in url:
            return b"{malformed json", url
        return extension_stats_source(revision="35502"), url

    monkeypatch.setattr(production_module, "fetch_https", fake_fetch)
    target = production_module.resolve_target(
        version="5.12.3",
        explicit_revision=None,
        target_os="macosx",
        target_arch="arm64",
        findings=[],
    )

    assert target.revision == "35502"
    assert target.revision_source == "extensionstats"
    assert target.publication_status == "not-checked"
    assert [attempt["result"] for attempt in target.lookup_attempts] == [
        "failed",
        "success",
    ]
    assert len(calls) == 2


def test_conflicting_package_server_revisions_do_not_fall_back(
    production_module: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [
        {
            "meta": {
                "baseName": "Slicer",
                "version": "5.12.3",
                "revision": revision,
                "os": "linux",
                "arch": "amd64",
            },
        }
        for revision in ("35501", "35502")
    ]
    calls = 0

    def fake_fetch(url: str) -> tuple[bytes, str]:
        nonlocal calls
        calls += 1
        return json.dumps(records).encode(), url

    monkeypatch.setattr(production_module, "fetch_https", fake_fetch)
    with pytest.raises(production_module.RetargetError) as error:
        production_module.resolve_target(
            version="5.12.3",
            explicit_revision=None,
            target_os="linux",
            target_arch="amd64",
            findings=[],
        )
    assert error.value.code == "revision-lookup-conflict"
    assert calls == 1


def test_total_revision_lookup_failure_requests_explicit_revision(
    production_module: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_fetch(url: str) -> tuple[bytes, str]:
        raise production_module.RetargetError(
            "revision-lookup-network",
            f"offline while fetching {url}",
            operational=True,
        )

    monkeypatch.setattr(production_module, "fetch_https", fail_fetch)
    with pytest.raises(production_module.RetargetError) as error:
        production_module.resolve_target(
            version="5.12.3",
            explicit_revision=None,
            target_os="linux",
            target_arch="amd64",
            findings=[],
        )
    assert error.value.code == "revision-lookup-failed"
    assert "--target-revision" in error.value.message
    assert len(error.value.details["attempts"]) == 2


def test_explicit_revision_bypasses_lookup_function(
    production_module: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_fetch(url: str) -> tuple[bytes, str]:
        pytest.fail(f"Network lookup should have been bypassed: {url}")

    monkeypatch.setattr(production_module, "fetch_https", unexpected_fetch)
    target = production_module.resolve_target(
        version="5.12",
        explicit_revision=TARGET_REVISION,
        target_os="linux",
        target_arch="amd64",
        findings=[],
    )
    assert target.revision == TARGET_REVISION
    assert target.revision_source == "explicit"
    assert target.lookup_attempts == []


def test_input_archive_is_never_overwritten_even_with_flag(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem(revision=TARGET_REVISION)}.tar.gz"
    write_tgz(source, flat_payload())
    original = source.read_bytes()
    completed = run_cli(
        "retarget",
        source,
        "--target-version",
        "5.10",
        "--target-os",
        "linux",
        "--target-arch",
        "amd64",
        "--target-revision",
        TARGET_REVISION,
        "--output-dir",
        tmp_path,
        "--overwrite",
        expected=1,
    )
    assert source.read_bytes() == original
    assert "input" in f"{completed.stdout}\n{completed.stderr}".lower()


def test_failure_leaves_no_partial_archive_or_audit(tmp_path: Path) -> None:
    source = tmp_path / f"{conventional_stem()}.tar.gz"
    payload = flat_payload()
    payload["lib/Slicer-5.10/qt-scripted-modules/native.dat"] = b"\x7fELF"
    write_tgz(source, payload)
    output_dir = tmp_path / "converted"
    completed = retarget(source, output_dir, expected=1)
    assert completed.returncode == 1
    assert not list(output_dir.glob("*.zip"))
    assert not list(output_dir.glob("*.tar.gz"))
    assert not list(output_dir.glob("*.audit.json"))


@pytest.mark.skipif(
    not os.environ.get("SLICER_EXTENSION_PACKAGE"),
    reason="Set SLICER_EXTENSION_PACKAGE to exercise a real package",
)
def test_optional_real_package_inspection() -> None:
    package = Path(os.environ["SLICER_EXTENSION_PACKAGE"])
    completed = run_cli("inspect", package, "--json")
    report = json.loads(completed.stdout)
    assert report["status"] == "passed"
    assert report["source"]["extension"]["name"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, *sys.argv[1:]]))

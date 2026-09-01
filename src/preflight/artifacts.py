"""Content-address external artifacts without importing or building them."""

from __future__ import annotations

import hashlib
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from preflight.trust import ArtifactIdentity, ArtifactKind

CHUNK_SIZE = 1024 * 1024
MAX_FILES = 100_000
MAX_TOTAL_BYTES = 10 * 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXPANSION_RATIO = 1_000
RATIO_FLOOR_BYTES = 10 * 1024 * 1024
LOCAL_EXCLUDES = {".git", ".preflight", "preflight.lock"}


class ArtifactError(ValueError):
    """An artifact cannot be represented safely and deterministically."""


def _safe_archive_name(name: str) -> str:
    if not name or "\x00" in name:
        raise ArtifactError("archive contains an empty or NUL-bearing path")
    normalized = name.replace(chr(92), "/")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or ".." in path.parts
        or (path.parts and path.parts[0].endswith(":"))
    ):
        raise ArtifactError(f"archive path escapes its root: {name}")
    return path.as_posix().rstrip("/")


def _check_archive_members(
    members: list[tuple[str, int, int]], *, archive_size: int
) -> None:
    if len(members) > MAX_FILES:
        raise ArtifactError(f"archive contains more than {MAX_FILES} members")
    seen: set[str] = set()
    total = 0
    for name, size, compressed_size in members:
        normalized = _safe_archive_name(name)
        collision_key = normalized.casefold()
        if collision_key in seen:
            raise ArtifactError(f"archive contains a duplicate path: {normalized}")
        seen.add(collision_key)
        if size > MAX_MEMBER_BYTES:
            raise ArtifactError(f"archive member is too large: {normalized}")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ArtifactError(
                f"archive expands beyond the {MAX_TOTAL_BYTES}-byte limit"
            )
        if size >= RATIO_FLOOR_BYTES:
            denominator = max(compressed_size, 1)
            if size / denominator > MAX_EXPANSION_RATIO:
                raise ArtifactError(
                    f"archive member has an unsafe expansion ratio: {normalized}"
                )
    if archive_size > MAX_ARCHIVE_BYTES:
        raise ArtifactError(
            f"compressed artifact exceeds the {MAX_ARCHIVE_BYTES}-byte limit"
        )


def _inspect_zip(path: Path, *, wheel: bool) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            members: list[tuple[str, int, int]] = []
            names: list[str] = []
            for member in archive.infolist():
                normalized = _safe_archive_name(member.filename)
                names.append(normalized)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ArtifactError(
                        f"archive contains a symbolic link: {normalized}"
                    )
                if member.flag_bits & 1:
                    raise ArtifactError(
                        f"archive contains an encrypted member: {normalized}"
                    )
                if not member.is_dir():
                    members.append(
                        (member.filename, member.file_size, member.compress_size)
                    )
            _check_archive_members(members, archive_size=path.stat().st_size)
            if wheel and not (
                any(name.endswith(".dist-info/METADATA") for name in names)
                and any(name.endswith(".dist-info/WHEEL") for name in names)
            ):
                raise ArtifactError("wheel is missing required dist-info metadata")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ArtifactError(f"invalid zip artifact '{path.name}': {exc}") from exc


def _inspect_tar(path: Path) -> None:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members: list[tuple[str, int, int]] = []
            for member in archive.getmembers():
                normalized = _safe_archive_name(member.name)
                if not (member.isfile() or member.isdir()):
                    raise ArtifactError(
                        f"archive contains a link or special file: {normalized}"
                    )
                if member.isfile():
                    members.append((member.name, member.size, member.size))
            _check_archive_members(members, archive_size=path.stat().st_size)
    except (OSError, tarfile.TarError) as exc:
        raise ArtifactError(f"invalid tar artifact '{path.name}': {exc}") from exc


def _file_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _directory_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    count = 0
    root = path.resolve()
    for candidate in sorted(path.rglob("*"), key=lambda item: item.as_posix()):
        relative = candidate.relative_to(path)
        if LOCAL_EXCLUDES.intersection(relative.parts):
            continue
        if candidate.is_symlink():
            raise ArtifactError(f"artifact contains a symlink: {relative.as_posix()}")
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root):
            raise ArtifactError(
                f"artifact path resolves outside its root: {relative.as_posix()}"
            )
        count += 1
        if count > MAX_FILES:
            raise ArtifactError(f"artifact contains more than {MAX_FILES} files")
        file_digest, file_size = _file_digest(resolved)
        size += file_size
        if size > MAX_TOTAL_BYTES:
            raise ArtifactError(f"artifact contains more than {MAX_TOTAL_BYTES} bytes")
        name = relative.as_posix().encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(file_size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_digest))
    return digest.hexdigest(), size


def identify_artifact(
    path: Path | str, *, source: str | None = None
) -> ArtifactIdentity:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ArtifactError(f"artifact root is a symlink: {candidate}")
    resolved = candidate.resolve()
    if not resolved.exists():
        raise ArtifactError(f"artifact does not exist: {candidate}")
    if resolved.is_dir():
        digest, size = _directory_digest(resolved)
        kind = ArtifactKind.DIRECTORY
    elif resolved.is_file():
        suffixes = resolved.suffixes
        if resolved.suffix == ".whl":
            kind = ArtifactKind.WHEEL
            _inspect_zip(resolved, wheel=True)
        elif suffixes[-2:] == [".tar", ".gz"] or resolved.suffix == ".zip":
            kind = ArtifactKind.SDIST
            if resolved.suffix == ".zip":
                _inspect_zip(resolved, wheel=False)
            else:
                _inspect_tar(resolved)
        else:
            raise ArtifactError(
                f"unsupported artifact type: {resolved.name}; expected a directory, "
                "wheel, zip sdist, or tar.gz sdist"
            )
        digest, size = _file_digest(resolved)
    else:
        raise ArtifactError(f"artifact is neither a file nor directory: {candidate}")
    return ArtifactIdentity(
        kind=kind,
        source=source or str(resolved),
        content_sha256=digest,
        size=size,
    )

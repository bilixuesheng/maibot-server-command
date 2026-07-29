"""Fail-closed file preparation for QQ uploads."""

from __future__ import annotations

import base64
import hashlib
import io
import mimetypes
import os
import re
import stat
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


HARD_MAX_UPLOAD_BYTES = 10 * 1024 * 1024
_READ_CHUNK_BYTES = 256 * 1024
_MAX_PATH_BYTES = 4096
_MAX_ARCHIVE_ENTRIES = 512
_MAX_ARCHIVE_SCAN_BYTES = 32 * 1024 * 1024
_MAX_ENCODED_BLOCKS = 64
_OPAQUE_CONTAINER_MAGICS = (
    b"\x1f\x8b",
    b"7z\xbc\xaf'\x1c",
    b"Rar!\x1a\x07",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"Salted__",
    b"age-encryption.org/v1",
)
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

_SENSITIVE_DIRECTORY_NAMES = {
    ".aws",
    ".azure",
    ".config/gcloud",
    ".docker",
    ".gnupg",
    ".kube",
    ".password-store",
    ".ssh",
    "letsencrypt",
}
_SENSITIVE_EXACT_NAMES = {
    ".env",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "authorized_keys",
    "config.toml",
    "credentials",
    "credentials.json",
    "docker-config.json",
    "gshadow",
    "htpasswd",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "kubeconfig",
    "login.keyring",
    "master.key",
    "passwd",
    "secrets.yml",
    "shadow",
}
_SENSITIVE_SUFFIXES = {
    ".age",
    ".bak",
    ".db",
    ".dump",
    ".gpg",
    ".jks",
    ".key",
    ".kdbx",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}
_SENSITIVE_NAME_RE = re.compile(
    r"(?:^|[._\-\s])"
    r"(?:api[_-]?key|access[_-]?key|client[_-]?secret|credential|password|"
    r"passwd|private[_-]?key|secret|token)"
    r"(?:$|[._\-\s])",
    re.IGNORECASE,
)
_CONTENT_RULES: tuple[tuple[re.Pattern[bytes], str], ...] = (
    (
        re.compile(
            rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|"
            rb"-----BEGIN OPENSSH PRIVATE KEY-----|"
            rb"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            re.IGNORECASE,
        ),
        "检测到私钥内容",
    ),
    (
        re.compile(
            rb"(?:^|[^A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?:[^A-Za-z0-9]|$)|"
            rb"(?:^|[^A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,255}(?:[^A-Za-z0-9]|$)|"
            rb"(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{20,255}(?:[^A-Za-z0-9_-]|$)|"
            rb"(?:^|[^A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,255}"
            rb"(?:[^A-Za-z0-9-]|$)"
        ),
        "检测到访问令牌或云凭据格式",
    ),
    (
        re.compile(
            rb"(?:^|[^A-Za-z0-9_-])"
            rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
            rb"(?:[^A-Za-z0-9_-]|$)"
        ),
        "检测到 JWT 访问令牌",
    ),
    (
        re.compile(
            rb"(?i)(?:authorization\s*:\s*(?:bearer|basic)\s+\S+|"
            rb"(?:cookie|set-cookie)\s*:\s*\S+)"
        ),
        "检测到认证头或 Cookie",
    ),
    (
        re.compile(
            rb"(?i)(?:password|passwd|secret|token|api[_-]?key|"
            rb"access[_-]?key|client[_-]?secret|private[_-]?key)"
            rb"\s*[\"']?\s*(?::|=)\s*[\"']?[^\s\"']{4,}"
        ),
        "检测到疑似密码、令牌或密钥配置",
    ),
    (
        re.compile(
            rb"(?i)\b[a-z][a-z0-9+.-]{1,20}://"
            rb"[^/\s:@]{1,128}:[^/\s@]{1,256}@"
        ),
        "检测到 URL 中嵌入的用户名和密码",
    ),
    (
        re.compile(rb"SQLite format 3\x00"),
        "检测到数据库文件",
    ),
)
_BASE64_BLOCK_RE = re.compile(
    rb"(?<![A-Za-z0-9+/=_-])"
    rb"(?:[A-Za-z0-9+/_-]{4}){8,}(?:[A-Za-z0-9+/_-]{2}==|[A-Za-z0-9+/_-]{3}=)?"
    rb"(?![A-Za-z0-9+/=_-])"
)
_MANAGED_TASK_RE = re.compile(r"task-[0-9a-f]{32}\Z")


class FileUploadError(ValueError):
    """A safe, user-facing refusal reason."""


@dataclass(frozen=True)
class PreparedUpload:
    """Pinned file bytes and non-sensitive metadata ready for transport."""

    name: str
    size: int
    mime_type: str
    sha256: str
    base64_url: str
    source_scope: str
    cleanup_relative_parts: tuple[str, ...] | None = None
    cleanup_identity: tuple[int, int, int, int, int, int, int] | None = None

    def message_payload(self) -> dict[str, object]:
        return {
            "name": self.name,
            "size": self.size,
            "mime_type": self.mime_type,
            "url": self.base64_url,
        }


def normalized_upload_limit(configured_mb: int) -> int:
    """Clamp configuration to the IPC-safe hard range."""

    try:
        value = int(configured_mb)
    except (TypeError, ValueError) as exc:
        raise FileUploadError("上传大小配置不是有效整数。") from exc
    return min(max(value, 1), HARD_MAX_UPLOAD_BYTES // (1024 * 1024)) * 1024 * 1024


def validate_upload_name(name: str) -> str:
    """Accept a single, display-safe filename rather than a path."""

    candidate = str(name)
    if not candidate or candidate in {".", ".."}:
        raise FileUploadError("发送文件名不能为空。")
    if "/" in candidate or "\\" in candidate or "\x00" in candidate:
        raise FileUploadError("发送文件名只能是单个文件名，不能包含路径。")
    if any(unicodedata.category(char).startswith("C") for char in candidate):
        raise FileUploadError("发送文件名不能包含控制字符。")
    if len(candidate.encode("utf-8")) > 255:
        raise FileUploadError("发送文件名超过 255 字节。")
    reason = sensitive_path_reason(candidate)
    if reason is not None:
        raise FileUploadError(f"拒绝上传敏感文件：{reason}。")
    return candidate


def sensitive_path_reason(path_text: str) -> str | None:
    """Return a category without echoing the potentially sensitive path."""

    normalized = str(path_text).replace("\\", "/").casefold()
    parts = tuple(part for part in normalized.split("/") if part not in {"", "."})
    if not parts:
        return "路径无效"

    if parts[0] in {"proc", "sys", "dev"}:
        return "虚拟系统文件不允许上传"
    if "etc" in parts and any(part in {"shadow", "gshadow"} for part in parts):
        return "系统账户凭据文件"
    joined = "/".join(parts)
    if any(
        directory in parts or directory in joined
        for directory in _SENSITIVE_DIRECTORY_NAMES
    ):
        return "路径位于常见凭据目录"

    name = parts[-1]
    if name.startswith(".env") or name in _SENSITIVE_EXACT_NAMES:
        return "文件名属于常见凭据或配置文件"
    if any(name.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES):
        return "文件类型常用于密钥、凭据、数据库或备份"
    if _SENSITIVE_NAME_RE.search(name):
        return "文件名表明可能包含密码、令牌或密钥"
    if name in {".bash_history", ".zsh_history", "fish_history"}:
        return "Shell 历史可能包含敏感命令"
    return None


def _direct_sensitive_content_reason(data: bytes) -> str | None:
    for pattern, reason in _CONTENT_RULES:
        if pattern.search(data):
            return reason
    return None


def _decoded_sensitive_content_reason(data: bytes) -> str | None:
    """Scan likely Base64 wrappers so simple encoding cannot hide a secret."""

    candidates: list[bytes] = []
    stripped = re.sub(rb"\s+", b"", data)
    if (
        32 <= len(stripped) <= HARD_MAX_UPLOAD_BYTES * 2
        and re.fullmatch(rb"[A-Za-z0-9+/_-]+={0,2}", stripped)
    ):
        candidates.append(stripped)
    candidates.extend(
        match.group(0) for match in list(_BASE64_BLOCK_RE.finditer(data))[:_MAX_ENCODED_BLOCKS]
    )

    decoded_total = 0
    seen: set[bytes] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        padding = b"=" * ((4 - len(candidate) % 4) % 4)
        try:
            decoded = base64.b64decode(candidate + padding, altchars=b"-_", validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        decoded_total += len(decoded)
        if decoded_total > HARD_MAX_UPLOAD_BYTES * 2:
            break
        reason = _direct_sensitive_content_reason(decoded)
        if reason is not None:
            return f"检测到 Base64 编码内容中包含敏感信息（{reason}）"
        if decoded.startswith(_ZIP_MAGICS + _OPAQUE_CONTAINER_MAGICS):
            return "Base64 编码内容中包含无法可靠检查的压缩或加密容器"
    return None


def _zip_sensitive_content_reason(data: bytes) -> str | None:
    """Inspect bounded, unencrypted ZIP-compatible containers without extraction."""

    if not data.startswith(_ZIP_MAGICS):
        return None
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile):
        return "ZIP 容器损坏或无法安全检查"

    with archive:
        entries = archive.infolist()
        if len(entries) > _MAX_ARCHIVE_ENTRIES:
            return "压缩包条目过多，无法在安全上限内检查"
        declared_total = sum(max(0, entry.file_size) for entry in entries)
        if declared_total > _MAX_ARCHIVE_SCAN_BYTES:
            return "压缩包解压后内容过大，无法在安全上限内检查"

        scanned_total = 0
        for entry in entries:
            entry_name = str(entry.filename)
            pure_name = PurePosixPath(entry_name)
            if pure_name.is_absolute() or ".." in pure_name.parts:
                return "压缩包包含不安全路径"
            if entry.flag_bits & 0x1:
                return "加密压缩包无法检查敏感信息"
            unix_mode = (entry.external_attr >> 16) & 0xFFFF
            if unix_mode and stat.S_ISLNK(unix_mode):
                return "压缩包包含符号链接"
            if entry.is_dir():
                continue
            path_reason = sensitive_path_reason(entry_name)
            if path_reason is not None:
                return f"压缩包内存在敏感路径（{path_reason}）"
            if entry.file_size > _MAX_ARCHIVE_SCAN_BYTES - scanned_total:
                return "压缩包内容超过安全检查预算"
            try:
                with archive.open(entry, "r") as member:
                    member_data = member.read(entry.file_size + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                return "压缩包成员无法安全读取"
            if len(member_data) != entry.file_size:
                return "压缩包成员大小与声明不一致"
            scanned_total += len(member_data)
            if member_data.startswith(_ZIP_MAGICS + _OPAQUE_CONTAINER_MAGICS):
                return "压缩包包含嵌套压缩或加密容器，无法可靠检查"
            reason = _direct_sensitive_content_reason(member_data)
            if reason is None:
                reason = _decoded_sensitive_content_reason(member_data)
            if reason is not None:
                return f"压缩包内存在敏感内容（{reason}）"
    return None


def sensitive_content_reason(data: bytes) -> str | None:
    """Detect common plaintext, encoded and archived secret formats."""

    reason = _direct_sensitive_content_reason(data)
    if reason is not None:
        return reason
    reason = _decoded_sensitive_content_reason(data)
    if reason is not None:
        return reason
    reason = _zip_sensitive_content_reason(data)
    if reason is not None:
        return reason
    if data.startswith(_OPAQUE_CONTAINER_MAGICS):
        return "该压缩或加密容器无法可靠检查敏感信息"
    return None


def _validate_path_text(path_text: str) -> str:
    candidate = str(path_text)
    if not candidate or "\x00" in candidate:
        raise FileUploadError("文件路径不能为空或包含 NUL 字符。")
    if len(candidate.encode("utf-8")) > _MAX_PATH_BYTES:
        raise FileUploadError("文件路径过长。")
    return candidate


def _sandbox_relative_parts(path_text: str, sandbox_root: Path) -> tuple[str, ...]:
    candidate = _validate_path_text(path_text)
    pure = PurePosixPath(candidate)

    if pure.is_absolute():
        if pure == PurePosixPath("/work"):
            raise FileUploadError("/work 是目录，必须指定其中的普通文件。")
        if PurePosixPath("/work") in pure.parents:
            pure = pure.relative_to("/work")
        else:
            sandbox_absolute = Path(sandbox_root).absolute()
            try:
                pure = PurePosixPath(
                    os.path.relpath(candidate, os.fspath(sandbox_absolute))
                )
            except ValueError as exc:
                raise FileUploadError("低权限模式只能上传沙箱目录中的文件。") from exc
            if pure == PurePosixPath("..") or ".." in pure.parts:
                raise FileUploadError("低权限模式只能上传沙箱目录中的文件。")

    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise FileUploadError("文件路径不能包含空组件、`.` 或 `..`。")
    return tuple(parts)


def _required_open_flags(*, directory: bool = False) -> int:
    required_names = ("O_CLOEXEC", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required_names):
        raise FileUploadError("当前系统缺少安全打开文件所需的 Linux 标志。")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if directory:
        if not hasattr(os, "O_DIRECTORY"):
            raise FileUploadError("当前系统缺少安全目录遍历支持。")
        flags |= os.O_DIRECTORY
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _open_sandbox_file(path_text: str, sandbox_root: Path) -> tuple[int, str]:
    parts = _sandbox_relative_parts(path_text, sandbox_root)
    directory_fd = os.open(
        os.fspath(Path(sandbox_root).absolute()),
        _required_open_flags(directory=True),
    )
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                _required_open_flags(directory=True),
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1],
            _required_open_flags(),
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise FileUploadError("文件不存在、不可读，或路径中包含符号链接。") from exc
    finally:
        os.close(directory_fd)
    return file_fd, parts[-1]


def _open_root_file(path_text: str) -> tuple[int, str]:
    candidate = _validate_path_text(path_text)
    absolute = Path(candidate) if os.path.isabs(candidate) else Path("/root") / candidate
    try:
        file_fd = os.open(os.fspath(absolute), _required_open_flags())
    except OSError as exc:
        raise FileUploadError("文件不存在、不可读，或最终路径是符号链接。") from exc
    return file_fd, absolute.name


def _resolved_fd_path(file_fd: int) -> str:
    try:
        resolved = os.readlink(f"/proc/self/fd/{file_fd}")
    except OSError as exc:
        raise FileUploadError("无法确认已打开文件的真实路径。") from exc
    if resolved.endswith(" (deleted)"):
        raise FileUploadError("文件在检查期间被删除，已拒绝上传。")
    return resolved


def _read_pinned_regular_file(file_fd: int, max_bytes: int) -> tuple[bytes, os.stat_result]:
    before = os.fstat(file_fd)
    if not stat.S_ISREG(before.st_mode):
        raise FileUploadError("只允许上传普通文件，目录、FIFO、Socket 和设备均被拒绝。")
    if before.st_nlink != 1:
        raise FileUploadError("为防止通过硬链接绕过目录边界，不允许上传硬链接文件。")
    if before.st_size <= 0:
        raise FileUploadError("不允许上传空文件。")
    if before.st_size > max_bytes:
        raise FileUploadError(
            f"文件超过上传上限 {max_bytes // (1024 * 1024)} MiB。"
        )

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(file_fd, min(_READ_CHUNK_BYTES, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise FileUploadError(
                f"文件超过上传上限 {max_bytes // (1024 * 1024)} MiB。"
            )

    after = os.fstat(file_fd)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise FileUploadError("文件在读取期间发生变化，已拒绝上传。")
    if total != before.st_size:
        raise FileUploadError("文件实际读取大小与检查结果不一致，已拒绝上传。")
    return b"".join(chunks), after


def _managed_cleanup_metadata(
    resolved_path: str,
    managed_temp_root: Path | None,
    file_stat: os.stat_result,
) -> tuple[
    tuple[str, ...] | None,
    tuple[int, int, int, int, int, int, int] | None,
]:
    """Identify an unchanged file inside a plugin-created temporary task."""

    if managed_temp_root is None:
        return None, None
    try:
        root = Path(managed_temp_root).resolve(strict=True)
        root_stat = root.stat()
        resolved = Path(resolved_path).resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None, None

    parts = tuple(relative.parts)
    if (
        len(parts) < 2
        or _MANAGED_TASK_RE.fullmatch(parts[0]) is None
        or any(part in {"", ".", ".."} for part in parts)
        or file_stat.st_dev != root_stat.st_dev
    ):
        return None, None
    identity = (
        int(file_stat.st_dev),
        int(file_stat.st_ino),
        int(file_stat.st_mode),
        int(file_stat.st_nlink),
        int(file_stat.st_size),
        int(file_stat.st_mtime_ns),
        int(file_stat.st_ctime_ns),
    )
    return parts, identity


def prepare_file_upload(
    path_text: str,
    *,
    sandbox_root: Path | None,
    root_mode: bool,
    configured_max_mb: int,
    upload_name: str | None = None,
    managed_temp_root: Path | None = None,
) -> PreparedUpload:
    """Open, verify, scan and pin a file before the caller sends it."""

    max_bytes = normalized_upload_limit(configured_max_mb)
    if root_mode:
        file_fd, source_name = _open_root_file(path_text)
        source_scope = "root_all_files"
    else:
        if sandbox_root is None:
            raise FileUploadError("低权限沙箱尚未初始化。")
        file_fd, source_name = _open_sandbox_file(path_text, sandbox_root)
        source_scope = "sandbox_only"

    try:
        resolved_path = _resolved_fd_path(file_fd)
        for checked_path in (str(path_text), resolved_path):
            path_reason = sensitive_path_reason(checked_path)
            if path_reason is not None:
                raise FileUploadError(f"拒绝上传敏感文件：{path_reason}。")
        data, stable_stat = _read_pinned_regular_file(file_fd, max_bytes)
    finally:
        os.close(file_fd)

    content_reason = sensitive_content_reason(data)
    if content_reason is not None:
        raise FileUploadError(f"拒绝上传敏感文件：{content_reason}。")

    safe_name = validate_upload_name(upload_name if upload_name is not None else source_name)
    mime_type = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    digest = hashlib.sha256(data).hexdigest()
    encoded = base64.b64encode(data).decode("ascii")
    cleanup_relative_parts, cleanup_identity = _managed_cleanup_metadata(
        resolved_path,
        managed_temp_root,
        stable_stat,
    )
    return PreparedUpload(
        name=safe_name,
        size=len(data),
        mime_type=mime_type,
        sha256=digest,
        base64_url=f"base64://{encoded}",
        source_scope=source_scope,
        cleanup_relative_parts=cleanup_relative_parts,
        cleanup_identity=cleanup_identity,
    )

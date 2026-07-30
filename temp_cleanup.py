"""Safe lifecycle management for plugin-owned temporary command files."""

from __future__ import annotations

import errno
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MANAGED_TEMP_DIR_NAME = ".maibot-temp"
CLEANUP_INTERVAL_SECONDS = 60 * 60
MAX_TASKS_PER_PASS = 128
MAX_ENTRIES_PER_PASS = 10_000
MAX_DIRECTORY_DEPTH = 64
_TASK_NAME_RE = re.compile(r"task-[0-9a-f]{32}\Z")


class TempCleanupError(RuntimeError):
    """Raised when managed temporary storage cannot be handled safely."""


@dataclass(frozen=True)
class ManagedTempTask:
    """One plugin-created temporary directory exposed to a command."""

    task_id: str
    host_path: Path
    sandbox_path: str


@dataclass
class CleanupReport:
    """Bounded summary that never contains source paths or file names."""

    deleted_tasks: int = 0
    deleted_entries: int = 0
    skipped_active: int = 0
    skipped_mounts: int = 0
    skipped_unsafe: int = 0
    errors: int = 0
    budget_exhausted: bool = False


def is_managed_task_name(name: str) -> bool:
    return _TASK_NAME_RE.fullmatch(str(name)) is not None


def managed_temp_root(sandbox_root: Path) -> Path:
    return Path(sandbox_root).absolute() / MANAGED_TEMP_DIR_NAME


def stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Return fields that must remain stable before an immediate unlink."""

    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _directory_open_flags() -> int:
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise TempCleanupError("当前系统缺少安全管理临时目录所需的 Linux 标志。")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _file_open_flags() -> int:
    if not hasattr(os, "O_CLOEXEC") or not hasattr(os, "O_NOFOLLOW"):
        raise TempCleanupError("当前系统缺少安全删除临时文件所需的 Linux 标志。")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)


def _same_entry(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _open_verified_directory_at(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise TempCleanupError("受管临时路径不是普通目录。")
    child_fd = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    after = os.fstat(child_fd)
    if not _same_entry(before, after) or not stat.S_ISDIR(after.st_mode):
        os.close(child_fd)
        raise TempCleanupError("受管临时目录在检查期间被替换。")
    return child_fd, after


def ensure_managed_temp_root(sandbox_root: Path) -> Path:
    """Create and verify the dedicated root without following symlinks."""

    sandbox = Path(sandbox_root).absolute()
    sandbox_fd = os.open(os.fspath(sandbox), _directory_open_flags())
    try:
        try:
            os.mkdir(MANAGED_TEMP_DIR_NAME, 0o711, dir_fd=sandbox_fd)
        except FileExistsError:
            pass
        temp_fd, temp_stat = _open_verified_directory_at(
            sandbox_fd,
            MANAGED_TEMP_DIR_NAME,
        )
        try:
            if temp_stat.st_dev != os.fstat(sandbox_fd).st_dev:
                raise TempCleanupError("受管临时目录不能位于独立挂载点。")
            temp_path = managed_temp_root(sandbox)
            if os.path.ismount(temp_path):
                raise TempCleanupError("受管临时目录不能是挂载点。")
            os.fchmod(temp_fd, 0o711)
            if os.geteuid() == 0:
                os.fchown(temp_fd, 0, 0)
        finally:
            os.close(temp_fd)
    finally:
        os.close(sandbox_fd)
    return managed_temp_root(sandbox)


def create_managed_temp_task(
    sandbox_root: Path,
    *,
    command_uid: int,
    command_gid: int,
) -> ManagedTempTask:
    """Create one unguessable task directory owned by the command identity."""

    temp_root = ensure_managed_temp_root(sandbox_root)
    root_fd = os.open(os.fspath(temp_root), _directory_open_flags())
    try:
        for _ in range(32):
            task_id = f"task-{secrets.token_hex(16)}"
            try:
                os.mkdir(task_id, 0o700, dir_fd=root_fd)
            except FileExistsError:
                continue
            task_fd = -1
            try:
                task_fd, task_stat = _open_verified_directory_at(root_fd, task_id)
                if task_stat.st_dev != os.fstat(root_fd).st_dev:
                    raise TempCleanupError("新建临时任务目录落在了独立挂载点。")
                if os.geteuid() == 0:
                    os.fchown(task_fd, int(command_uid), int(command_gid))
                os.fchmod(task_fd, 0o700)
            except BaseException:
                if task_fd >= 0:
                    os.close(task_fd)
                try:
                    os.rmdir(task_id, dir_fd=root_fd)
                except OSError:
                    pass
                raise
            else:
                os.close(task_fd)
                return ManagedTempTask(
                    task_id=task_id,
                    host_path=temp_root / task_id,
                    sandbox_path=f"/work/{MANAGED_TEMP_DIR_NAME}/{task_id}",
                )
        raise TempCleanupError("无法分配唯一的临时任务目录。")
    finally:
        os.close(root_fd)


def reuse_managed_temp_task(
    sandbox_root: Path,
    *,
    task_id: str,
    command_uid: int,
    command_gid: int,
) -> ManagedTempTask:
    """Reopen an existing task directory without trusting a model-supplied path."""

    normalized_id = str(task_id)
    if not is_managed_task_name(normalized_id):
        raise TempCleanupError("临时任务 ID 格式无效。")
    temp_root = ensure_managed_temp_root(sandbox_root)
    root_fd = os.open(os.fspath(temp_root), _directory_open_flags())
    try:
        task_fd, task_stat = _open_verified_directory_at(root_fd, normalized_id)
        try:
            if task_stat.st_dev != os.fstat(root_fd).st_dev:
                raise TempCleanupError("临时任务目录位于独立挂载点。")
            if os.path.ismount(temp_root / normalized_id):
                raise TempCleanupError("临时任务目录不能是挂载点。")
            if (
                int(task_stat.st_uid) != int(command_uid)
                or int(task_stat.st_gid) != int(command_gid)
            ):
                raise TempCleanupError("临时任务目录的执行身份与当前权限模式不匹配。")
            if stat.S_IMODE(task_stat.st_mode) != 0o700:
                raise TempCleanupError("临时任务目录权限已变化，拒绝继续使用。")
            os.utime(task_fd, None)
        finally:
            os.close(task_fd)
    finally:
        os.close(root_fd)
    return ManagedTempTask(
        task_id=normalized_id,
        host_path=temp_root / normalized_id,
        sandbox_path=f"/work/{MANAGED_TEMP_DIR_NAME}/{normalized_id}",
    )


@dataclass
class _CleanupBudget:
    remaining_entries: int = MAX_ENTRIES_PER_PASS

    def consume(self) -> bool:
        if self.remaining_entries <= 0:
            return False
        self.remaining_entries -= 1
        return True


def _delete_tree_at(
    parent_fd: int,
    name: str,
    absolute_path: Path,
    *,
    root_device: int,
    depth: int,
    budget: _CleanupBudget,
    report: CleanupReport,
) -> bool:
    if depth > MAX_DIRECTORY_DEPTH:
        report.skipped_unsafe += 1
        return False
    if os.path.ismount(absolute_path):
        report.skipped_mounts += 1
        return False

    try:
        directory_fd, directory_stat = _open_verified_directory_at(parent_fd, name)
    except FileNotFoundError:
        return True
    except (OSError, TempCleanupError):
        report.skipped_unsafe += 1
        return False

    try:
        if directory_stat.st_dev != root_device:
            report.skipped_mounts += 1
            return False
        try:
            iterator = os.scandir(directory_fd)
        except OSError:
            report.errors += 1
            return False
        with iterator:
            for entry in iterator:
                if not budget.consume():
                    report.budget_exhausted = True
                    return False
                entry_path = absolute_path / entry.name
                try:
                    entry_stat = os.stat(
                        entry.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                except OSError:
                    report.errors += 1
                    continue

                if stat.S_ISDIR(entry_stat.st_mode):
                    if not _delete_tree_at(
                        directory_fd,
                        entry.name,
                        entry_path,
                        root_device=root_device,
                        depth=depth + 1,
                        budget=budget,
                        report=report,
                    ):
                        continue
                else:
                    try:
                        os.unlink(entry.name, dir_fd=directory_fd)
                    except FileNotFoundError:
                        continue
                    except OSError:
                        report.errors += 1
                        continue
                    report.deleted_entries += 1
    finally:
        os.close(directory_fd)

    try:
        os.rmdir(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    report.deleted_entries += 1
    return True


def cleanup_expired_tasks(
    sandbox_root: Path,
    *,
    retention_hours: int,
    active_task_ids: Iterable[str] = (),
) -> CleanupReport:
    """Delete only expired, inactive task directories within a bounded pass."""

    report = CleanupReport()
    temp_root = ensure_managed_temp_root(sandbox_root)
    root_fd = os.open(os.fspath(temp_root), _directory_open_flags())
    budget = _CleanupBudget()
    active = {str(item) for item in active_task_ids}
    hours = max(1, min(int(retention_hours), 24 * 30))
    cutoff_ns = time.time_ns() - hours * 60 * 60 * 1_000_000_000
    try:
        root_stat = os.fstat(root_fd)
        processed_tasks = 0
        with os.scandir(root_fd) as iterator:
            for entry in iterator:
                if not budget.consume():
                    report.budget_exhausted = True
                    break
                if processed_tasks >= MAX_TASKS_PER_PASS:
                    report.budget_exhausted = True
                    break
                if not is_managed_task_name(entry.name):
                    report.skipped_unsafe += 1
                    continue
                if entry.name in active:
                    report.skipped_active += 1
                    continue
                try:
                    task_stat = os.stat(
                        entry.name,
                        dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                except OSError:
                    report.errors += 1
                    continue
                if not stat.S_ISDIR(task_stat.st_mode):
                    report.skipped_unsafe += 1
                    continue
                if task_stat.st_dev != root_stat.st_dev:
                    report.skipped_mounts += 1
                    continue
                if max(task_stat.st_mtime_ns, task_stat.st_ctime_ns) > cutoff_ns:
                    continue

                processed_tasks += 1
                if _delete_tree_at(
                    root_fd,
                    entry.name,
                    temp_root / entry.name,
                    root_device=root_stat.st_dev,
                    depth=0,
                    budget=budget,
                    report=report,
                ):
                    report.deleted_tasks += 1
                if report.budget_exhausted:
                    break
    finally:
        os.close(root_fd)
    return report


def _validate_relative_parts(parts: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(str(part) for part in parts)
    if len(normalized) < 2 or len(normalized) > MAX_DIRECTORY_DEPTH + 2:
        raise TempCleanupError("临时文件清理令牌的路径深度无效。")
    if not is_managed_task_name(normalized[0]):
        raise TempCleanupError("临时文件清理令牌不属于受管任务目录。")
    if any(
        not part
        or part in {".", ".."}
        or "/" in part
        or "\\" in part
        or "\x00" in part
        for part in normalized
    ):
        raise TempCleanupError("临时文件清理令牌包含不安全路径组件。")
    return normalized


def delete_uploaded_managed_file(
    sandbox_root: Path,
    *,
    relative_parts: Iterable[str],
    expected_identity: tuple[int, int, int, int, int, int, int],
    active_task_ids: Iterable[str] = (),
) -> str:
    """Unlink a confirmed upload only if the managed source is unchanged."""

    parts = _validate_relative_parts(relative_parts)
    if parts[0] in {str(item) for item in active_task_ids}:
        return "retained_active"

    temp_root = ensure_managed_temp_root(sandbox_root)
    root_fd = os.open(os.fspath(temp_root), _directory_open_flags())
    open_directories = [root_fd]
    try:
        root_stat = os.fstat(root_fd)
        current_fd = root_fd
        current_path = temp_root
        for part in parts[:-1]:
            current_path = current_path / part
            if os.path.ismount(current_path):
                return "retained_mountpoint"
            try:
                next_fd, next_stat = _open_verified_directory_at(current_fd, part)
            except FileNotFoundError:
                return "not_found"
            except (OSError, TempCleanupError):
                return "retained_changed"
            if next_stat.st_dev != root_stat.st_dev:
                os.close(next_fd)
                return "retained_mountpoint"
            open_directories.append(next_fd)
            current_fd = next_fd

        file_name = parts[-1]
        try:
            file_fd = os.open(file_name, _file_open_flags(), dir_fd=current_fd)
        except FileNotFoundError:
            return "not_found"
        except OSError:
            return "retained_changed"
        try:
            current_stat = os.fstat(file_fd)
            if (
                not stat.S_ISREG(current_stat.st_mode)
                or current_stat.st_nlink != 1
                or stat_identity(current_stat) != tuple(expected_identity)
            ):
                return "retained_changed"
        finally:
            os.close(file_fd)

        try:
            final_stat = os.stat(
                file_name,
                dir_fd=current_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return "not_found"
        except OSError:
            return "retained_changed"
        if stat_identity(final_stat) != tuple(expected_identity):
            return "retained_changed"

        try:
            os.unlink(file_name, dir_fd=current_fd)
        except FileNotFoundError:
            return "not_found"
        except OSError:
            return "cleanup_failed"

        directory_names = parts[:-1]
        # Keep the top-level task directory so later commands in the same
        # lease keep a stable MAIBOT_TEMP_DIR even after uploading its last
        # file. Only empty nested directories are pruned immediately.
        for index in range(len(directory_names) - 1, 0, -1):
            try:
                os.rmdir(directory_names[index], dir_fd=open_directories[index])
            except OSError as exc:
                if exc.errno not in {
                    errno.ENOTEMPTY,
                    errno.EEXIST,
                    errno.ENOENT,
                    errno.EBUSY,
                }:
                    return "deleted_file_prune_failed"
                break
        return "deleted"
    finally:
        for directory_fd in reversed(open_directories):
            os.close(directory_fd)

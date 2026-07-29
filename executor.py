"""Ubuntu command runner confined to MaiBot's maibot-command-file directory."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import os
import pwd
import re
import resource
import shutil
import signal
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final


MAX_COMMAND_BYTES: Final = 16_384
ABSOLUTE_MAX_TIMEOUT_SECONDS: Final = 300
ABSOLUTE_MAX_OUTPUT_BYTES: Final = 1_048_576
ABSOLUTE_MAX_MEMORY_MB: Final = 2_048
ABSOLUTE_MAX_FILE_SIZE_MB: Final = 1_024
ABSOLUTE_MAX_PROCESSES: Final = 128
ROOT_SANDBOX_USER: Final = "nobody"
ROOT_WORKING_DIRECTORY: Final = Path("/root")
ROOT_SUPERVISOR_FLAG: Final = "--maibot-root-supervisor"
ROOT_SUPERVISOR_GRACE_SECONDS: Final = 5.0
MANAGED_TEMP_DIRECTORY_NAME: Final = ".maibot-temp"


_HIGH_RISK_COMMAND_RULES: Final = (
    (
        re.compile(
            r"(^|[;&|])\s*(?:sudo\s+)?rm\s+[^\n;&|]*(?:-[a-zA-Z]*r|--recursive)",
            re.IGNORECASE,
        ),
        "递归删除文件或目录",
    ),
    (
        re.compile(r"\b(?:shred|wipefs|mkfs(?:\.[a-z0-9_+-]+)?|fdisk|sfdisk|cfdisk|parted)\b", re.IGNORECASE),
        "擦除、格式化或修改磁盘/分区",
    ),
    (
        re.compile(r"\bdd\b[^\n;&|]*\bof\s*=\s*/dev/", re.IGNORECASE),
        "向块设备直接写入数据",
    ),
    (
        re.compile(r"\b(?:shutdown|reboot|poweroff|halt)\b", re.IGNORECASE),
        "关机、重启或停止服务器",
    ),
    (
        re.compile(r"\bsystemctl\s+(?:poweroff|reboot|halt|stop|disable|mask)\b", re.IGNORECASE),
        "停止服务器或禁用系统服务",
    ),
    (
        re.compile(
            r"\b(?:passwd|chpasswd|useradd|userdel|usermod|groupadd|groupdel|groupmod|visudo)\b",
            re.IGNORECASE,
        ),
        "修改系统账号、密码、用户组或 sudo 权限",
    ),
    (
        re.compile(r"\b(?:ufw|iptables|ip6tables|nft)\s+(?:disable|reset|flush|delete)\b", re.IGNORECASE),
        "关闭或清空服务器防火墙规则",
    ),
    (
        re.compile(
            r"\b(?:chmod|chown)\b[^\n;&|]*(?:-R|--recursive)[^\n;&|]*"
            r"(?:^|\s)/(?:etc|usr|bin|sbin|lib|lib64|boot|root|home|var)?(?:/|\s|$)",
            re.IGNORECASE,
        ),
        "递归修改系统目录的权限或所有者",
    ),
    (
        re.compile(r"\bfind\b[^\n;&|]*\s-delete(?:\s|$)", re.IGNORECASE),
        "批量删除 find 匹配到的文件",
    ),
    (
        re.compile(
            r"(?:/etc/(?:shadow|gshadow)|/root/\.ssh(?:/|\s|$)|/proc/(?:self|\d+)/environ)",
            re.IGNORECASE,
        ),
        "读取或修改账号凭据、SSH 密钥或进程机密环境",
    ),
    (
        re.compile(
            r"\b(?:curl|wget)\b[^\n]*(?:\||\$\(|`)\s*(?:sudo\s+)?(?:ba)?sh\b",
            re.IGNORECASE,
        ),
        "从网络下载内容后直接交给 Shell 执行",
    ),
    (
        re.compile(r"\b(?:apt|apt-get)\s+(?:remove|purge|autoremove)\b", re.IGNORECASE),
        "卸载系统软件包",
    ),
    (
        re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", re.IGNORECASE),
        "进程耗尽攻击（fork bomb）",
    ),
)


class SandboxError(RuntimeError):
    """Raised when a command cannot be executed without weakening isolation."""


class HighRiskCommandError(SandboxError):
    """Raised when root mode refuses an obviously dangerous command."""


@dataclass(frozen=True)
class SandboxLimits:
    timeout_seconds: int = 20
    max_output_bytes: int = 65_536
    memory_limit_mb: int = 256
    file_size_limit_mb: int = 64
    max_processes: int = 32

    def normalized(self) -> "SandboxLimits":
        return SandboxLimits(
            timeout_seconds=max(1, min(int(self.timeout_seconds), ABSOLUTE_MAX_TIMEOUT_SECONDS)),
            max_output_bytes=max(4_096, min(int(self.max_output_bytes), ABSOLUTE_MAX_OUTPUT_BYTES)),
            memory_limit_mb=max(64, min(int(self.memory_limit_mb), ABSOLUTE_MAX_MEMORY_MB)),
            file_size_limit_mb=max(1, min(int(self.file_size_limit_mb), ABSOLUTE_MAX_FILE_SIZE_MB)),
            max_processes=max(8, min(int(self.max_processes), ABSOLUTE_MAX_PROCESSES)),
        )


@dataclass(frozen=True)
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool

    def as_dict(self) -> dict[str, object]:
        status = "超时" if self.timed_out else ("成功" if self.exit_code == 0 else "失败")
        details = [
            f"状态：{status}",
            f"退出码：{self.exit_code}",
            f"标准输出：\n{self.stdout or '(空)'}",
            f"标准错误：\n{self.stderr or '(空)'}",
        ]
        if self.output_truncated:
            details.append("注意：输出超过限制，已截断。")
        return {
            "success": self.exit_code == 0 and not self.timed_out,
            "name": "run_server_command",
            "content": "\n".join(details),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
        }


@dataclass(frozen=True)
class ExecutionIdentity:
    uid: int
    gid: int
    name: str
    drop_from_root: bool


def command_audit_id(command: str) -> str:
    """Return a stable identifier so logs do not contain the raw command."""

    return hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()[:12]


def high_risk_command_reason(command: str) -> str | None:
    """Return a refusal category for obviously destructive root commands."""

    for pattern, reason in _HIGH_RISK_COMMAND_RULES:
        if pattern.search(command):
            return reason
    return None


def _validate_command_text(command: str) -> None:
    if "\x00" in command or not command.strip():
        raise SandboxError("命令不能为空，也不能包含 NUL 字符。")
    if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise SandboxError(f"命令过长，最多允许 {MAX_COMMAND_BYTES} 字节。")


def resolve_execution_identity() -> ExecutionIdentity:
    """Choose the host identity that is allowed to execute sandbox commands."""

    if os.geteuid() != 0:
        return ExecutionIdentity(
            uid=os.geteuid(),
            gid=os.getegid(),
            name=str(os.geteuid()),
            drop_from_root=False,
        )

    try:
        account = pwd.getpwnam(ROOT_SANDBOX_USER)
    except KeyError as exc:
        raise SandboxError(
            f"系统缺少固定的低权限用户 {ROOT_SANDBOX_USER!r}，拒绝以 root 执行命令。"
        ) from exc
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise SandboxError("低权限沙箱用户的 UID/GID 不能为 0。")
    return ExecutionIdentity(
        uid=account.pw_uid,
        gid=account.pw_gid,
        name=account.pw_name,
        drop_from_root=True,
    )


def find_maibot_root(plugin_file: str | Path) -> Path:
    """Resolve ``<MaiBot>/plugins/<plugin>/plugin.py`` to ``<MaiBot>``."""

    plugin_path = Path(plugin_file).resolve(strict=True)
    plugin_dir = plugin_path.parent
    plugins_dir = plugin_dir.parent
    if plugins_dir.name != "plugins":
        raise SandboxError("插件必须安装在 MaiBot 主程序的 plugins/<插件名>/ 目录中。")
    return plugins_dir.parent.resolve(strict=True)


def _chown_sandbox_tree(sandbox: Path, identity: ExecutionIdentity) -> None:
    """Transfer only the validated sandbox tree to the fixed command user."""

    validate_sandbox_contents(sandbox)
    for directory, dir_names, file_names in os.walk(sandbox, followlinks=False):
        base = Path(directory)
        os.chown(base, identity.uid, identity.gid, follow_symlinks=False)
        if base == sandbox and MANAGED_TEMP_DIRECTORY_NAME in dir_names:
            # Task directories preserve their execution-mode owner. The
            # root-owned 0711 parent permits traversal only when the caller
            # already knows its unguessable task ID.
            dir_names.remove(MANAGED_TEMP_DIRECTORY_NAME)
        for name in [*dir_names, *file_names]:
            os.chown(base / name, identity.uid, identity.gid, follow_symlinks=False)


def resolve_sandbox_directory(maibot_root: Path) -> Path:
    """Create and path-validate the writable directory without changing owners."""

    root = maibot_root.resolve(strict=True)
    candidate = root / "maibot-command-file"
    if candidate.exists() or candidate.is_symlink():
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SandboxError("maibot-command-file 必须是真实目录，不能是文件或符号链接。")
    else:
        candidate.mkdir(mode=0o700)

    sandbox = candidate.resolve(strict=True)
    if sandbox.parent != root:
        raise SandboxError("沙箱目录解析后越出了 MaiBot 主程序目录。")
    return sandbox


def prepare_sandbox(
    maibot_root: Path,
    identity: ExecutionIdentity | None = None,
) -> Path:
    """Create, validate and transfer the writable low-privilege directory."""

    execution_identity = identity or resolve_execution_identity()
    sandbox = resolve_sandbox_directory(maibot_root)
    if execution_identity.drop_from_root:
        _chown_sandbox_tree(sandbox, execution_identity)
        os.chmod(sandbox, 0o700)
    elif sandbox.stat().st_uid != execution_identity.uid:
        raise SandboxError("沙箱目录必须归运行 MaiBot 的系统用户所有。")
    return sandbox


def validate_sandbox_contents(sandbox: Path) -> None:
    """Reject hard links and special files before bind-mounting the sandbox."""

    for directory, dir_names, file_names in os.walk(sandbox, followlinks=False):
        base = Path(directory)
        for name in [*dir_names, *file_names]:
            path = base / name
            metadata = path.lstat()
            mode = metadata.st_mode
            if stat.S_ISLNK(mode) or stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise SandboxError(f"沙箱含有不允许的特殊文件：{path.relative_to(sandbox)}")
            if metadata.st_nlink != 1:
                raise SandboxError(f"沙箱含有硬链接文件，拒绝执行：{path.relative_to(sandbox)}")


def _system_mount_args() -> list[str]:
    """Expose Ubuntu command binaries read-only, excluding /usr/local."""

    args = ["--dir", "/usr"]
    for source in ("/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/share"):
        if Path(source).exists():
            args.extend(("--ro-bind", source, source))

    for target, destination in (
        ("/bin", "usr/bin"),
        ("/sbin", "usr/sbin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ):
        if Path(target).exists() or Path(target).is_symlink():
            args.extend(("--symlink", destination, target))
    return args


def _network_mount_args(network_enabled: bool) -> list[str]:
    """Expose only the host files needed for DNS and HTTPS verification."""

    if not network_enabled:
        return []

    args = ["--dir", "/etc"]
    for directory in ("/etc/ssl",):
        if Path(directory).is_dir():
            args.extend(("--dir", directory))

    for source in (
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/gai.conf",
        "/etc/services",
        "/etc/protocols",
        "/etc/ssl/certs",
    ):
        source_path = Path(source)
        if source_path.exists():
            args.extend(("--ro-bind", str(source_path.resolve(strict=True)), source))
    return args


def build_bwrap_argv(
    bwrap: str,
    sandbox: Path,
    command: str,
    identity: ExecutionIdentity,
    sandbox_fd: int | None = None,
    network_enabled: bool = False,
    managed_temp_directory: str | None = None,
) -> list[str]:
    """Build an argv without interpolating the untrusted command into options."""

    bind_args = (
        ["--bind-fd", str(sandbox_fd), "/work"]
        if sandbox_fd is not None
        else ["--bind", str(sandbox), "/work"]
    )
    if identity.drop_from_root:
        # Root can build the mount and process namespaces directly. Avoid a
        # user namespace here because many Ubuntu hosts forbid UID mapping.
        # The trusted setpriv wrapper drops to the fixed account before Bash
        # sees or parses the untrusted command.
        namespace_args = [
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup-try",
        ]
        if not network_enabled:
            namespace_args.append("--unshare-net")
        user_and_capability_args = [
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CAP_SETUID",
            "--cap-add",
            "CAP_SETGID",
            "--cap-add",
            "CAP_SETPCAP",
        ]
        command_args = [
            "/usr/bin/setpriv",
            "--reuid",
            str(identity.uid),
            "--regid",
            str(identity.gid),
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "/usr/bin/env",
            "--chdir=/work",
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            command,
        ]
        # Bubblewrap applies --chdir before exec. At that point it has already
        # dropped CAP_DAC_OVERRIDE but has not yet run setpriv, so root cannot
        # enter a 0700 directory owned by nobody. Start from the isolated root;
        # the fixed wrapper enters /work only after setpriv has changed to the
        # directory owner. The trusted env helper performs only that chdir, and
        # the untrusted command remains one opaque argv item.
        initial_workdir = "/"
    else:
        namespace_args = ["--unshare-all"]
        if network_enabled:
            namespace_args.append("--share-net")
        user_and_capability_args = [
            "--unshare-user",
            "--disable-userns",
            "--cap-drop",
            "ALL",
        ]
        command_args = [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            command,
        ]
        initial_workdir = "/work"
    environment_args = [
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/work",
        "--setenv",
        "LANG",
        "C",
    ]
    if managed_temp_directory:
        environment_args.extend(
            (
                "--setenv",
                "MAIBOT_TEMP_DIR",
                str(managed_temp_directory),
            )
        )
    if network_enabled:
        environment_args.extend(
            (
                "--setenv",
                "SSL_CERT_FILE",
                "/etc/ssl/certs/ca-certificates.crt",
                "--setenv",
                "SSL_CERT_DIR",
                "/etc/ssl/certs",
            )
        )
    return [
        bwrap,
        "--die-with-parent",
        "--new-session",
        *namespace_args,
        *user_and_capability_args,
        *environment_args,
        *_system_mount_args(),
        *_network_mount_args(network_enabled),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        *bind_args,
        "--chdir",
        initial_workdir,
        *command_args,
    ]


def _is_ubuntu() -> bool:
    try:
        fields = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value.strip().strip("\"'")
        return fields.get("ID", "").casefold() == "ubuntu"
    except OSError:
        return False


def _limit_child(
    limits: SandboxLimits,
    *,
    enforce_process_limit: bool = True,
) -> None:
    """Apply inherited Unix resource limits immediately before exec."""

    libc = ctypes.CDLL(None, use_errno=True)
    pr_set_no_new_privs = 38
    if libc.prctl(pr_set_no_new_privs, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "无法启用 no_new_privs")

    memory = limits.memory_limit_mb * 1024 * 1024
    file_size = limits.file_size_limit_mb * 1024 * 1024
    cpu_seconds = limits.timeout_seconds + 2
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    if enforce_process_limit:
        resource.setrlimit(
            resource.RLIMIT_NPROC,
            (limits.max_processes, limits.max_processes),
        )


def _prepare_bwrap(limits: SandboxLimits) -> None:
    """Apply inherited limits before the trusted Bubblewrap launcher starts."""

    _limit_child(limits)


async def _capture_stream(
    stream: asyncio.StreamReader,
    retained: bytearray,
    shared_budget: list[int],
    truncated: list[bool],
) -> None:
    while chunk := await stream.read(8_192):
        remaining = shared_budget[0]
        if remaining > 0:
            kept = chunk[:remaining]
            retained.extend(kept)
            shared_budget[0] -= len(kept)
        if len(chunk) > remaining:
            truncated[0] = True


def _set_child_subreaper() -> None:
    """Keep daemonized descendants attached to the dedicated root supervisor."""

    libc = ctypes.CDLL(None, use_errno=True)
    pr_set_child_subreaper = 36
    if libc.prctl(pr_set_child_subreaper, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "无法启用 root 子进程监督器")


def _read_proc_pid_and_parent(stat_file: Path) -> tuple[int, int] | None:
    try:
        contents = stat_file.read_text(encoding="ascii")
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None
    command_end = contents.rfind(")")
    if command_end < 0:
        return None
    try:
        pid = int(contents[: contents.index(" ")])
        fields_after_command = contents[command_end + 2 :].split()
        parent_pid = int(fields_after_command[1])
    except (ValueError, IndexError):
        return None
    return pid, parent_pid


def _procfs_self_pid() -> int:
    """Return the PID used by this /proc mount, accounting for nested PID namespaces."""

    values = _read_proc_pid_and_parent(Path("/proc/self/stat"))
    if values is None:
        return os.getpid()
    return values[0]


def _procfs_namespace_pids(procfs_pid: int) -> list[int]:
    status_file = Path(f"/proc/{procfs_pid}/status")
    try:
        for line in status_file.read_text(encoding="ascii").splitlines():
            if line.startswith("NSpid:"):
                return [int(value) for value in line.split()[1:]]
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError, ValueError):
        pass
    return []


def _local_pid_from_procfs(procfs_pid: int) -> int:
    """Translate a procfs PID into the PID visible from the caller's namespace."""

    target_namespace_pids = _procfs_namespace_pids(procfs_pid)
    caller_namespace_depth = len(_procfs_namespace_pids(_procfs_self_pid()))
    if target_namespace_pids and caller_namespace_depth > 0:
        index = min(caller_namespace_depth, len(target_namespace_pids)) - 1
        return target_namespace_pids[index]
    return procfs_pid


def _direct_child_pids(parent_pid: int) -> set[int]:
    """Scan procfs for direct children without relying on task/children support."""

    children: set[int] = set()
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        return children
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        values = _read_proc_pid_and_parent(entry / "stat")
        if values is not None and values[1] == parent_pid:
            children.add(values[0])
    return children


def _descendant_pids(parent_pid: int) -> set[int]:
    """Return every currently visible descendant, including new sessions."""

    descendants: set[int] = set()
    pending = list(_direct_child_pids(parent_pid))
    while pending:
        pid = pending.pop()
        if pid in descendants:
            continue
        descendants.add(pid)
        pending.extend(_direct_child_pids(pid) - descendants)
    return descendants


def _signal_pids(pids: set[int], sig: signal.Signals) -> None:
    for procfs_pid in sorted(pids, reverse=True):
        try:
            os.kill(_local_pid_from_procfs(procfs_pid), sig)
        except (ProcessLookupError, PermissionError):
            pass


def _reap_children_nonblocking() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _kill_supervised_descendants(supervisor_pid: int) -> None:
    """Freeze, kill and reap all descendants, even after setsid/double-fork."""

    for _ in range(20):
        descendants = _descendant_pids(supervisor_pid)
        if not descendants:
            _reap_children_nonblocking()
            if not _direct_child_pids(supervisor_pid):
                return
            time.sleep(0.01)
            continue

        # Freeze first so a process cannot race cleanup by repeatedly forking.
        _signal_pids(descendants, signal.SIGSTOP)
        time.sleep(0.01)
        descendants.update(_descendant_pids(supervisor_pid))
        _signal_pids(descendants, signal.SIGSTOP)
        _signal_pids(descendants, signal.SIGKILL)
        _reap_children_nonblocking()
        time.sleep(0.01)

    # Best-effort final sweep. A deliberately hostile unrestricted-root command
    # can attack any host-side mechanism, but ordinary detached descendants are
    # still terminated deterministically by the supervised lifecycle.
    _signal_pids(_descendant_pids(supervisor_pid), signal.SIGKILL)
    _reap_children_nonblocking()


def _wait_status_to_exit_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def _root_supervisor_main(command: str, limits: SandboxLimits) -> int:
    """Supervise one root shell and clean every descendant before returning."""

    _set_child_subreaper()
    termination_requested = False

    def request_termination(signum: int, frame: object) -> None:
        del signum, frame
        nonlocal termination_requested
        termination_requested = True

    signal.signal(signal.SIGTERM, request_termination)
    signal.signal(signal.SIGINT, request_termination)

    primary_pid = os.fork()
    if primary_pid == 0:
        try:
            os.setsid()
            _limit_child(limits, enforce_process_limit=False)
            os.chdir(ROOT_WORKING_DIRECTORY)
            environment = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/root",
                "USER": "root",
                "LOGNAME": "root",
                "LANG": "C.UTF-8",
            }
            managed_temp_directory = os.environ.get("MAIBOT_TEMP_DIR", "")
            if managed_temp_directory:
                environment["MAIBOT_TEMP_DIR"] = managed_temp_directory
            os.execve(
                "/bin/bash",
                ["/bin/bash", "--noprofile", "--norc", "-c", command],
                environment,
            )
        except BaseException as exc:
            message = f"无法启动 root Bash：{exc}\n".encode("utf-8", errors="replace")
            try:
                os.write(2, message)
            finally:
                os._exit(126)

    primary_status: int | None = None
    while primary_status is None and not termination_requested:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            time.sleep(0.02)
            continue
        if pid == primary_pid:
            primary_status = status

    _kill_supervised_descendants(_procfs_self_pid())
    if termination_requested:
        return 124
    if primary_status is None:
        return 1
    return _wait_status_to_exit_code(primary_status)


def _parse_root_supervisor_args(argv: list[str]) -> tuple[str, SandboxLimits]:
    if len(argv) != 8 or argv[1] != ROOT_SUPERVISOR_FLAG:
        raise ValueError("root supervisor 参数无效")
    limits = SandboxLimits(
        timeout_seconds=int(argv[2]),
        max_output_bytes=int(argv[3]),
        memory_limit_mb=int(argv[4]),
        file_size_limit_mb=int(argv[5]),
        max_processes=int(argv[6]),
    ).normalized()
    return argv[7], limits


async def _stop_root_supervisor(process: asyncio.subprocess.Process) -> None:
    """Ask the supervisor to clean descendants, with a hard fallback."""

    try:
        process.terminate()
    except ProcessLookupError:
        await process.wait()
        return

    try:
        await asyncio.wait_for(
            process.wait(),
            timeout=ROOT_SUPERVISOR_GRACE_SECONDS,
        )
        return
    except TimeoutError:
        pass

    # The supervisor normally exits in milliseconds. If it does not, clean the
    # visible tree from the MaiBot parent before killing the supervisor itself.
    procfs_self = _procfs_self_pid()
    supervisor_candidates = {
        pid
        for pid in _direct_child_pids(procfs_self)
        if _local_pid_from_procfs(pid) == process.pid
    }
    descendants: set[int] = set()
    for supervisor_pid in supervisor_candidates:
        descendants.update(_descendant_pids(supervisor_pid))
    _signal_pids(descendants, signal.SIGSTOP)
    for supervisor_pid in supervisor_candidates:
        descendants.update(_descendant_pids(supervisor_pid))
    _signal_pids(descendants, signal.SIGKILL)
    try:
        process.kill()
    except ProcessLookupError:
        pass
    await process.wait()


async def run_command(
    command: str,
    sandbox: Path,
    limits: SandboxLimits,
    requested_timeout: int | None = None,
    network_enabled: bool = False,
    managed_temp_directory: str | None = None,
) -> CommandResult:
    """Run a shell command inside a fail-closed Bubblewrap sandbox."""

    if os.name != "posix" or not _is_ubuntu():
        raise SandboxError("此插件仅支持 Ubuntu Linux。")
    _validate_command_text(command)

    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise SandboxError("服务器未安装 bubblewrap；请先执行 sudo apt install bubblewrap。")

    normalized = limits.normalized()
    timeout = normalized.timeout_seconds
    if requested_timeout is not None:
        timeout = max(1, min(int(requested_timeout), timeout))

    identity = resolve_execution_identity()
    if identity.drop_from_root:
        setpriv = Path("/usr/bin/setpriv")
        if not setpriv.is_file() or not os.access(setpriv, os.X_OK):
            raise SandboxError(
                "服务器缺少 /usr/bin/setpriv；请先安装 Ubuntu 的 util-linux 软件包。"
            )
    validate_sandbox_contents(sandbox)
    sandbox_fd = os.open(
        sandbox,
        os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    argv = build_bwrap_argv(
        bwrap,
        sandbox,
        command,
        identity,
        sandbox_fd=sandbox_fd,
        network_enabled=bool(network_enabled),
        managed_temp_directory=managed_temp_directory,
    )
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            close_fds=True,
            pass_fds=(sandbox_fd,),
            start_new_session=True,
            preexec_fn=lambda: _prepare_bwrap(normalized),
        )
    finally:
        os.close(sandbox_fd)
    assert process.stdout is not None
    assert process.stderr is not None

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    shared_budget = [normalized.max_output_bytes]
    truncated = [False]
    readers = [
        asyncio.create_task(_capture_stream(process.stdout, stdout_buffer, shared_budget, truncated)),
        asyncio.create_task(_capture_stream(process.stderr, stderr_buffer, shared_budget, truncated)),
    ]
    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except TimeoutError:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()
    finally:
        await asyncio.gather(*readers)

    exit_code = 124 if timed_out else int(process.returncode or 0)
    return CommandResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout_buffer.decode("utf-8", errors="replace"),
        stderr=stderr_buffer.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        output_truncated=truncated[0],
    )


async def _run_root_command(
    command: str,
    limits: SandboxLimits,
    requested_timeout: int | None = None,
    *,
    enforce_high_risk_guard: bool,
    managed_temp_directory: str | None = None,
) -> CommandResult:
    """Run an explicitly confirmed command as root in /root without Bubblewrap."""

    if os.name != "posix" or not _is_ubuntu():
        raise SandboxError("此插件仅支持 Ubuntu Linux。")
    if os.geteuid() != 0:
        raise SandboxError("root 最高权限模式只能在 MaiBot 由 root 用户运行时使用。")
    _validate_command_text(command)
    if enforce_high_risk_guard:
        risk_reason = high_risk_command_reason(command)
        if risk_reason is not None:
            raise HighRiskCommandError(f"高风险命令已被插件拒绝：{risk_reason}。")
    if not ROOT_WORKING_DIRECTORY.is_dir():
        raise SandboxError("root 工作目录 /root 不存在，拒绝执行命令。")

    normalized = limits.normalized()
    timeout = normalized.timeout_seconds
    if requested_timeout is not None:
        timeout = max(1, min(int(requested_timeout), timeout))

    supervisor_path = str(Path(__file__).resolve(strict=True))
    supervisor_environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
    }
    if managed_temp_directory:
        supervisor_environment["MAIBOT_TEMP_DIR"] = str(managed_temp_directory)

    process = await asyncio.create_subprocess_exec(
        sys.executable,
        supervisor_path,
        ROOT_SUPERVISOR_FLAG,
        str(normalized.timeout_seconds),
        str(normalized.max_output_bytes),
        str(normalized.memory_limit_mb),
        str(normalized.file_size_limit_mb),
        str(normalized.max_processes),
        command,
        cwd=str(ROOT_WORKING_DIRECTORY),
        env=supervisor_environment,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    shared_budget = [normalized.max_output_bytes]
    truncated = [False]
    readers = [
        asyncio.create_task(_capture_stream(process.stdout, stdout_buffer, shared_budget, truncated)),
        asyncio.create_task(_capture_stream(process.stderr, stderr_buffer, shared_budget, truncated)),
    ]
    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except TimeoutError:
        timed_out = True
        await _stop_root_supervisor(process)
    finally:
        await asyncio.gather(*readers)

    exit_code = 124 if timed_out else int(process.returncode or 0)
    return CommandResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout_buffer.decode("utf-8", errors="replace"),
        stderr=stderr_buffer.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        output_truncated=truncated[0],
    )


async def run_root_command(
    command: str,
    limits: SandboxLimits,
    requested_timeout: int | None = None,
    managed_temp_directory: str | None = None,
) -> CommandResult:
    """Run a restricted-root command after applying the high-risk regex guard."""

    return await _run_root_command(
        command,
        limits,
        requested_timeout=requested_timeout,
        enforce_high_risk_guard=True,
        managed_temp_directory=managed_temp_directory,
    )


async def run_unrestricted_root_command(
    command: str,
    limits: SandboxLimits,
    requested_timeout: int | None = None,
    managed_temp_directory: str | None = None,
) -> CommandResult:
    """Run a fully confirmed root command without the high-risk regex guard.

    Operational timeout, output capture and Unix resource ceilings remain in
    place so a tool call can terminate and return a bounded result. They do not
    restrict which root operations Bash is allowed to attempt.
    """

    return await _run_root_command(
        command,
        limits,
        requested_timeout=requested_timeout,
        enforce_high_risk_guard=False,
        managed_temp_directory=managed_temp_directory,
    )


if __name__ == "__main__":
    try:
        supervised_command, supervised_limits = _parse_root_supervisor_args(sys.argv)
        raise SystemExit(_root_supervisor_main(supervised_command, supervised_limits))
    except BaseException as exc:
        if isinstance(exc, SystemExit):
            raise
        print(f"root supervisor 启动失败：{exc}", file=sys.stderr)
        raise SystemExit(126)

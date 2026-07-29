"""MaiBot tool plugin for running commands in a fixed Ubuntu sandbox."""

import asyncio
import contextlib
import importlib.util
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from maibot_sdk import CONFIG_RELOAD_SCOPE_SELF, Field, MaiBotPlugin, PluginConfigBase, Tool
from maibot_sdk.types import ToolParameterInfo, ToolParamType


def _load_sibling_executor() -> Any:
    """Load executor.py without relying on the Runner's sys.path."""

    module_name = "_xuesheng_maibot_server_command_executor_v1_0_14"
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        return loaded

    executor_path = Path(__file__).resolve().with_name("executor.py")
    spec = importlib.util.spec_from_file_location(module_name, executor_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载插件执行器：{executor_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def _load_sibling_file_upload() -> Any:
    """Load file_upload.py without relying on the Runner's sys.path."""

    module_name = "_xuesheng_maibot_server_command_file_upload_v1_0_14"
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        return loaded

    upload_path = Path(__file__).resolve().with_name("file_upload.py")
    spec = importlib.util.spec_from_file_location(module_name, upload_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载插件文件上传模块：{upload_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def _load_sibling_temp_cleanup() -> Any:
    """Load temp_cleanup.py without relying on the Runner's sys.path."""

    module_name = "_xuesheng_maibot_server_command_temp_cleanup_v1_0_14"
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        return loaded

    cleanup_path = Path(__file__).resolve().with_name("temp_cleanup.py")
    spec = importlib.util.spec_from_file_location(module_name, cleanup_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载插件临时文件清理模块：{cleanup_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


_executor = _load_sibling_executor()
_file_upload = _load_sibling_file_upload()
_temp_cleanup = _load_sibling_temp_cleanup()
SandboxLimits = _executor.SandboxLimits
command_audit_id = _executor.command_audit_id
find_maibot_root = _executor.find_maibot_root
high_risk_command_reason = _executor.high_risk_command_reason
prepare_sandbox = _executor.prepare_sandbox
resolve_sandbox_directory = _executor.resolve_sandbox_directory
resolve_execution_identity = _executor.resolve_execution_identity
run_command = _executor.run_command
run_root_command = _executor.run_root_command
run_unrestricted_root_command = _executor.run_unrestricted_root_command
FileUploadError = _file_upload.FileUploadError
prepare_file_upload = _file_upload.prepare_file_upload
CleanupReport = _temp_cleanup.CleanupReport
CLEANUP_INTERVAL_SECONDS = _temp_cleanup.CLEANUP_INTERVAL_SECONDS
ManagedTempTask = _temp_cleanup.ManagedTempTask
TempCleanupError = _temp_cleanup.TempCleanupError
cleanup_expired_tasks = _temp_cleanup.cleanup_expired_tasks
create_managed_temp_task = _temp_cleanup.create_managed_temp_task
delete_uploaded_managed_file = _temp_cleanup.delete_uploaded_managed_file
ensure_managed_temp_root = _temp_cleanup.ensure_managed_temp_root
is_managed_task_name = _temp_cleanup.is_managed_task_name
reuse_managed_temp_task = _temp_cleanup.reuse_managed_temp_task

TEMP_SESSION_IDLE_SECONDS = 30 * 60


ROOT_MODE_NOTICE = (
    "⚠️ 当前权限模式：受限 ROOT（沙箱已关闭，工作目录为 /root）。\n"
    "你现在拥有服务器最高权限。必须坚决拒绝高风险、破坏性、提权维持、"
    "凭据读取或泄露数据的命令；不确定是否安全时不要执行。\n"
    "插件的正则防护无法保证识别 Base64、变量展开、eval 等混淆命令，"
    "不能把“未被拦截”视为命令安全。\n"
    "ROOT 文件上传可以读取全系统普通文件，但敏感文件始终禁止上传；"
    "不得通过改名、压缩、编码或复制到其他目录绕过。\n"
    "ROOT 不受“最大进程数”配置约束；命令结束或超时后，插件会清理本次命令"
    "直接产生的后台后代进程。"
)

UNRESTRICTED_ROOT_NOTICE = (
    "☢️ 当前权限模式：完全 ROOT（沙箱已关闭，工作目录为 /root）。\n"
    "管理员已完成十重认证，插件不会运行高风险命令正则拦截。"
    "你拥有服务器最高权限，仍必须自行判断并坚决拒绝高风险、破坏性、"
    "提权维持、凭据读取或泄露数据的命令；不确定是否安全时不要执行。\n"
    "完全 ROOT 只关闭命令正则拦截，不会关闭文件上传的敏感信息防护；"
    "不得上传、改名、打包或编码任何敏感数据。\n"
    "ROOT 不受“最大进程数”配置约束；命令结束或超时后，插件会清理本次命令"
    "直接产生的后台后代进程。"
)


class CommandSandboxConfig(PluginConfigBase):
    """控制麦麦运行 Ubuntu 命令时的权限与资源限制。"""

    __ui_label__ = "命令沙箱"
    __ui_icon__ = "terminal"
    __ui_order__ = 0

    enabled: bool = Field(
        default=True,
        description="是否允许麦麦调用沙箱命令工具",
        json_schema_extra={
            "label": "启用命令工具",
            "hint": "关闭后，麦麦不能调用服务器命令沙箱。",
            "x-widget": "switch",
        },
    )
    network_enabled: bool = Field(
        default=False,
        description="是否允许沙箱命令访问网络（包括公网、内网和本机服务）",
        json_schema_extra={
            "label": "允许命令联网",
            "hint": (
                "开启后可使用 curl、wget 等访问公网；命令也可访问 localhost、"
                "服务器内网和云元数据端点（如 169.254.169.254）。"
            ),
            "x-widget": "switch",
        },
    )
    timeout_seconds: int = Field(
        default=20,
        description="单条命令最长运行时间（1–300 秒）",
        json_schema_extra={
            "label": "命令超时时间（秒）",
            "hint": "单条命令最多运行多久；有效范围为 1–300 秒。",
            "x-widget": "number",
            "step": 1,
        },
    )
    max_output_bytes: int = Field(
        default=65_536,
        description="标准输出和错误输出合计保留字节数",
        json_schema_extra={
            "label": "最大输出大小（字节）",
            "hint": "stdout 与 stderr 合计最多保留多少字节；有效范围为 4096–1048576。",
            "x-widget": "number",
            "step": 1024,
        },
    )
    memory_limit_mb: int = Field(
        default=256,
        description="每个进程的最大虚拟内存（MB）",
        json_schema_extra={
            "label": "内存上限（MB）",
            "hint": "每个命令进程可使用的最大虚拟内存；有效范围为 64–2048 MB。",
            "x-widget": "number",
            "step": 64,
        },
    )
    file_size_limit_mb: int = Field(
        default=64,
        description="单个文件的最大大小（MB）",
        json_schema_extra={
            "label": "单文件大小上限（MB）",
            "hint": "命令创建的单个文件最大大小；有效范围为 1–1024 MB。",
            "x-widget": "number",
            "step": 1,
        },
    )
    max_processes: int = Field(
        default=32,
        description="低权限沙箱运行用户可拥有的最大进程数",
        json_schema_extra={
            "label": "低权限沙箱最大进程数",
            "hint": (
                "仅限制低权限沙箱命令及其子进程；有效范围为 8–128。"
                "Linux 不对 UID 0 执行 RLIMIT_NPROC，因此两种 ROOT 模式不应用此项。"
            ),
            "x-widget": "number",
            "step": 1,
        },
    )


class FileUploadConfig(PluginConfigBase):
    """控制服务器文件发送到 QQ 的独立高风险能力。"""

    __ui_label__ = "QQ 文件上传"
    __ui_icon__ = "file-up"
    __ui_order__ = 1

    enabled: bool = Field(
        default=False,
        description="是否允许麦麦把服务器文件发送到指定 QQ 会话",
        json_schema_extra={
            "label": "启用 QQ 文件上传",
            "hint": (
                "默认关闭。低权限模式只能读取 maibot-command-file；"
                "ROOT 模式可读取全系统普通文件。敏感文件始终禁止上传。"
            ),
            "x-widget": "switch",
        },
    )
    max_upload_mb: int = Field(
        default=8,
        ge=1,
        le=10,
        description="单次 QQ 文件上传大小上限（1–10 MiB）",
        json_schema_extra={
            "label": "单文件上传上限（MiB）",
            "hint": (
                "默认 8 MiB，硬上限 10 MiB。文件会经过 Base64 封装，"
                "该上限用于确保请求不超过 MaiBot 插件 IPC 帧限制。"
            ),
            "x-widget": "number",
            "step": 1,
        },
    )


class TemporaryFileCleanupConfig(PluginConfigBase):
    """控制插件专用临时任务目录的自动清理。"""

    __ui_label__ = "临时文件清理"
    __ui_icon__ = "trash-2"
    __ui_order__ = 2

    enabled: bool = Field(
        default=True,
        description="是否为命令创建受管临时目录并自动清理",
        json_schema_extra={
            "label": "启用受管临时目录",
            "hint": (
                "开启后，每个临时任务都会获得独立的 $MAIBOT_TEMP_DIR；"
                "同一轮任务的连续命令会自动复用。"
                "只有该目录中的文件会被自动清理；普通 /work 和系统目录永不自动删除。"
            ),
            "x-widget": "switch",
        },
    )
    retention_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="临时任务目录在停止使用后的保留时长（1–720 小时）",
        json_schema_extra={
            "label": "临时文件保留时长（小时）",
            "hint": "默认 24 小时；清理器每小时检查一次，因此实际清理时间可能稍晚。",
            "x-widget": "number",
            "step": 1,
        },
    )
    delete_after_upload: bool = Field(
        default=True,
        description="QQ 明确返回发送成功后立即删除受管临时源文件",
        json_schema_extra={
            "label": "QQ 发送成功后立即删除",
            "hint": (
                "只删除 $MAIBOT_TEMP_DIR 中且读取后未变化的源文件。"
                "发送失败、结果不确定、文件变化或任务仍在运行时都会保留。"
            ),
            "x-widget": "switch",
        },
    )


class RootPrivilegeConfig(PluginConfigBase):
    """需要多重确认才能启用的受限 root 模式。"""

    __ui_label__ = "受限 ROOT（极高风险）"
    __ui_icon__ = "triangle-alert"
    __ui_order__ = 3

    enabled: bool = Field(
        default=False,
        description="关闭命令沙箱并允许命令以 root 在 /root 中执行",
        json_schema_extra={
            "label": "关闭沙箱并启用受限 ROOT",
            "hint": "极高风险：仅当 MaiBot 进程由 root 用户运行时才可能生效。单独打开此开关不会启用。",
            "x-widget": "switch",
        },
    )
    confirmation_1: bool = Field(
        default=False,
        description="第一次确认已理解 root 命令可控制整台服务器",
        json_schema_extra={
            "label": "第一次确认：我理解这是最高权限",
            "hint": "确认麦麦执行的命令将不受 Bubblewrap 文件系统沙箱限制。",
            "x-widget": "switch",
        },
    )
    confirmation_2: bool = Field(
        default=False,
        description="第二次确认已理解命令可读取或修改服务器任意数据",
        json_schema_extra={
            "label": "第二次确认：我理解可能损坏服务器",
            "hint": "确认错误命令可能破坏系统、服务或重要数据。",
            "x-widget": "switch",
        },
    )
    confirmation_3: bool = Field(
        default=False,
        description="第三次确认愿意承担关闭沙箱的风险",
        json_schema_extra={
            "label": "第三次确认：我自愿承担全部风险",
            "hint": "确认已做好备份，并明确要求插件关闭命令沙箱。",
            "x-widget": "switch",
        },
    )
    confirmation_4: bool = Field(
        default=False,
        description="第四次确认允许 ROOT 访问全部文件并确认服务器没有敏感文件",
        json_schema_extra={
            "label": "第四次确认：服务器无敏感文件",
            "hint": (
                "ROOT 文件上传能读取全系统普通文件。请先确认服务器不存在密码、"
                "Token、私钥、Cookie、数据库、个人信息等敏感文件；"
                "插件仍会拒绝识别到的敏感文件。"
            ),
            "x-widget": "switch",
        },
    )
    final_confirmation: int = Field(
        default=0,
        ge=0,
        le=1,
        description="最终数字确认；必须手动从 0 改为 1",
        json_schema_extra={
            "label": "最终确认：把 0 改成 1",
            "hint": "只有数值等于 1，且上面四个确认开关全部开启时，受限 ROOT 才会生效。",
            "x-widget": "number",
            "step": 1,
        },
    )


class UnrestrictedRootConfig(PluginConfigBase):
    """只能从受限 ROOT 解锁的无命令正则拦截模式。"""

    __ui_label__ = "完全 ROOT（无命令正则拦截）"
    __ui_icon__ = "skull"
    __ui_order__ = 4

    enabled: bool = Field(
        default=False,
        description="在受限 ROOT 已生效后申请完全 ROOT",
        json_schema_extra={
            "label": "申请解锁完全 ROOT",
            "hint": (
                "必须先让上方受限 ROOT 真正生效，再完成下面十项认证；"
                "单独打开不会生效。"
            ),
            "x-widget": "switch",
        },
    )
    confirmation_1: bool = Field(
        default=False,
        description="第一项认证",
        json_schema_extra={
            "label": "认证 1：开启",
            "hint": "完全 ROOT 的第一项认证必须开启。",
            "x-widget": "switch",
        },
    )
    confirmation_2: bool = Field(
        default=False,
        description="第二项认证",
        json_schema_extra={
            "label": "认证 2：开启",
            "hint": "完全 ROOT 的第二项认证必须开启。",
            "x-widget": "switch",
        },
    )
    confirmation_3: bool = Field(
        default=False,
        description="第三项认证",
        json_schema_extra={
            "label": "认证 3：开启",
            "hint": "完全 ROOT 的第三项认证必须开启。",
            "x-widget": "switch",
        },
    )
    confirmation_4: bool = Field(
        default=False,
        description="第四项认证",
        json_schema_extra={
            "label": "认证 4：开启",
            "hint": "完全 ROOT 的第四项认证必须开启。",
            "x-widget": "switch",
        },
    )
    confirmation_5: bool = Field(
        default=False,
        description="第五项认证",
        json_schema_extra={
            "label": "认证 5：开启",
            "hint": "完全 ROOT 的第五项认证必须开启。",
            "x-widget": "switch",
        },
    )
    confirmation_6: bool = Field(
        default=True,
        description="第六项认证；必须关闭",
        json_schema_extra={
            "label": "认证 6：关闭",
            "hint": "此项默认开启，必须手动关闭。",
            "x-widget": "switch",
        },
    )
    confirmation_7: bool = Field(
        default=False,
        description="第七项认证；必须开启",
        json_schema_extra={
            "label": "认证 7：开启",
            "hint": "此项必须开启。",
            "x-widget": "switch",
        },
    )
    confirmation_8: bool = Field(
        default=True,
        description="第八项认证；必须关闭",
        json_schema_extra={
            "label": "认证 8：关闭",
            "hint": "此项默认开启，必须手动关闭。",
            "x-widget": "switch",
        },
    )
    confirmation_9: int = Field(
        default=1,
        ge=0,
        le=1,
        description="第九项认证；必须从 1 改为 0",
        json_schema_extra={
            "label": "认证 9：把 1 改成 0",
            "hint": "此项默认是 1，必须手动改为 0。",
            "x-widget": "number",
            "step": 1,
        },
    )
    confirmation_10: bool = Field(
        default=True,
        description="第十项认证；必须从 true 改为 false",
        json_schema_extra={
            "label": "认证 10：把 true 改成 false",
            "hint": "此项默认开启（true），必须手动关闭为 false。",
            "x-widget": "switch",
        },
    )


class PluginMetadataConfig(PluginConfigBase):
    """插件配置文件的内部版本信息。"""

    __ui_label__ = "插件信息"
    __ui_icon__ = "info"
    __ui_order__ = -1

    config_version: str = Field(
        default="1.0.14",
        description="配置结构版本",
        json_schema_extra={
            "label": "配置版本",
            "hint": "由插件自动维护，请勿手动修改。",
            "disabled": True,
        },
    )


class ServerCommandPluginConfig(PluginConfigBase):
    """插件完整配置。"""

    plugin: PluginMetadataConfig = Field(default_factory=PluginMetadataConfig)
    sandbox: CommandSandboxConfig = Field(default_factory=CommandSandboxConfig)
    file_upload: FileUploadConfig = Field(default_factory=FileUploadConfig)
    temp_cleanup: TemporaryFileCleanupConfig = Field(
        default_factory=TemporaryFileCleanupConfig
    )
    root_mode: RootPrivilegeConfig = Field(default_factory=RootPrivilegeConfig)
    unrestricted_root: UnrestrictedRootConfig = Field(default_factory=UnrestrictedRootConfig)


class ServerCommandPlugin(MaiBotPlugin):
    """Expose fail-closed command and QQ file tools to Maisaka."""

    config_model = ServerCommandPluginConfig

    def __init__(self) -> None:
        super().__init__()
        self._sandbox_path = None
        self._sandbox_error = ""
        self._sandbox_prepared_for_low_privilege = False
        self._managed_temp_root = None
        self._cleanup_task: asyncio.Task[None] | None = None
        self._cleanup_lock = asyncio.Lock()
        self._active_temp_tasks: dict[str, int] = {}
        self._known_temp_tasks: dict[str, tuple[ManagedTempTask, bool, float]] = {}
        self._stream_temp_tasks: dict[str, str] = {}

    def _root_mode_state(self) -> tuple[bool, str]:
        settings = self.config.root_mode
        if not settings.enabled:
            return False, "ROOT 模式总开关未开启"

        missing = []
        if os.geteuid() != 0:
            missing.append("MaiBot 不是由 root 用户运行")
        if not settings.confirmation_1:
            missing.append("第一次确认未开启")
        if not settings.confirmation_2:
            missing.append("第二次确认未开启")
        if not settings.confirmation_3:
            missing.append("第三次确认未开启")
        if not settings.confirmation_4:
            missing.append("第四次确认未开启")
        if int(settings.final_confirmation) != 1:
            missing.append("最终确认值不是 1")
        if missing:
            return False, "；".join(missing)
        return True, "已满足 root 用户、总开关、四次开关和数值 1 的全部条件"

    def _unrestricted_root_state(
        self,
        restricted_root_active: bool | None = None,
    ) -> tuple[bool, str]:
        settings = self.config.unrestricted_root
        if not settings.enabled:
            return False, "完全 ROOT 总开关未开启"

        if restricted_root_active is None:
            restricted_root_active, _ = self._root_mode_state()

        missing = []
        if not restricted_root_active:
            missing.append("受限 ROOT 尚未生效")
        for index in range(1, 6):
            if not bool(getattr(settings, f"confirmation_{index}")):
                missing.append(f"认证 {index} 未开启")
        if settings.confirmation_6:
            missing.append("认证 6 未关闭")
        if not settings.confirmation_7:
            missing.append("认证 7 未开启")
        if settings.confirmation_8:
            missing.append("认证 8 未关闭")
        if int(settings.confirmation_9) != 0:
            missing.append("认证 9 未从 1 改为 0")
        if settings.confirmation_10:
            missing.append("认证 10 未从 true 改为 false")
        if missing:
            return False, "；".join(missing)
        return True, "受限 ROOT 已生效且十项认证全部匹配"

    @staticmethod
    def _root_result(result: Any) -> dict[str, object]:
        payload = result.as_dict()
        payload["content"] = f"{ROOT_MODE_NOTICE}\n\n{payload['content']}"
        payload["execution_mode"] = "root_restricted"
        payload["command_regex_guard"] = "enabled"
        payload["working_directory"] = "/root"
        payload["process_limit"] = "not_enforced_for_uid_0"
        payload["descendant_cleanup"] = "on_command_exit_or_timeout"
        return payload

    @staticmethod
    def _unrestricted_root_result(result: Any) -> dict[str, object]:
        payload = result.as_dict()
        payload["content"] = f"{UNRESTRICTED_ROOT_NOTICE}\n\n{payload['content']}"
        payload["execution_mode"] = "root_unrestricted"
        payload["command_regex_guard"] = "disabled"
        payload["working_directory"] = "/root"
        payload["process_limit"] = "not_enforced_for_uid_0"
        payload["descendant_cleanup"] = "on_command_exit_or_timeout"
        return payload

    def _initialize_sandbox(self, *, low_privilege: bool | None = None) -> None:
        maibot_root = find_maibot_root(__file__)
        if low_privilege is None:
            root_active, _ = self._root_mode_state()
            low_privilege = not root_active
        if low_privilege:
            identity = resolve_execution_identity()
            self._sandbox_path = prepare_sandbox(maibot_root, identity)
            self._sandbox_prepared_for_low_privilege = True
        else:
            self._sandbox_path = resolve_sandbox_directory(maibot_root)
        if self.config.temp_cleanup.enabled:
            self._managed_temp_root = ensure_managed_temp_root(self._sandbox_path)
        else:
            self._managed_temp_root = None
        self._sandbox_error = ""

    async def _run_cleanup_once(self, trigger: str) -> CleanupReport:
        if not self.config.temp_cleanup.enabled:
            return CleanupReport()
        async with self._cleanup_lock:
            if self._sandbox_path is None or self._managed_temp_root is None:
                await asyncio.to_thread(self._initialize_sandbox)
            report = await asyncio.to_thread(
                cleanup_expired_tasks,
                self._sandbox_path,
                retention_hours=self.config.temp_cleanup.retention_hours,
                active_task_ids=tuple(self._active_temp_tasks),
            )
        if (
            report.deleted_tasks
            or report.deleted_entries
            or report.skipped_mounts
            or report.skipped_unsafe
            or report.errors
            or report.budget_exhausted
        ):
            self.ctx.logger.info(
                "受管临时文件清理完成：trigger=%s deleted_tasks=%s "
                "deleted_entries=%s skipped_active=%s skipped_mounts=%s "
                "skipped_unsafe=%s errors=%s budget_exhausted=%s",
                trigger,
                report.deleted_tasks,
                report.deleted_entries,
                report.skipped_active,
                report.skipped_mounts,
                report.skipped_unsafe,
                report.errors,
                report.budget_exhausted,
            )
        return report

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
            try:
                await self._run_cleanup_once("scheduled")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.ctx.logger.error(
                    "受管临时文件定时清理失败：error_type=%s",
                    type(exc).__name__,
                )

    def _start_cleanup_loop(self) -> None:
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(
                self._cleanup_loop(),
                name="maibot-server-command-temp-cleanup",
            )

    async def _stop_cleanup_loop(self) -> None:
        task = self._cleanup_task
        self._cleanup_task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _refresh_cleanup_service(self, *, run_now: bool) -> None:
        if not self.config.temp_cleanup.enabled:
            await self._stop_cleanup_loop()
            self._managed_temp_root = None
            return
        root_active, _ = self._root_mode_state()
        low_privilege = not root_active
        if (
            self._sandbox_path is None
            or self._managed_temp_root is None
            or (low_privilege and not self._sandbox_prepared_for_low_privilege)
        ):
            await asyncio.to_thread(
                self._initialize_sandbox,
                low_privilege=low_privilege,
            )
        if run_now:
            await self._run_cleanup_once("startup_or_config")
        self._start_cleanup_loop()

    async def _create_command_temp(
        self,
        *,
        root_active: bool,
        session_key: str,
        requested_task_id: str,
        start_new_task: bool,
    ) -> ManagedTempTask | None:
        if not self.config.temp_cleanup.enabled:
            return None
        async with self._cleanup_lock:
            if (
                self._sandbox_path is None
                or self._managed_temp_root is None
                or (
                    not root_active
                    and not self._sandbox_prepared_for_low_privilege
                )
            ):
                await asyncio.to_thread(
                    self._initialize_sandbox,
                    low_privilege=not root_active,
                )
            if root_active:
                command_uid = 0
                command_gid = 0
            else:
                identity = resolve_execution_identity()
                command_uid = identity.uid
                command_gid = identity.gid

            requested = str(requested_task_id).strip()
            stream_key = str(session_key).strip()
            if requested and start_new_task:
                raise TempCleanupError(
                    "temp_task_id 与 start_new_temp_task 不能同时使用。"
                )
            if requested and not is_managed_task_name(requested):
                raise TempCleanupError("temp_task_id 格式无效。")

            now = asyncio.get_running_loop().time()
            task: ManagedTempTask | None = None
            explicit_reuse = bool(requested)
            candidate_id = requested
            if not candidate_id and not start_new_task and stream_key:
                session_id = self._stream_temp_tasks.get(stream_key, "")
                session_record = self._known_temp_tasks.get(session_id)
                if (
                    session_record is not None
                    and session_record[1] == root_active
                    and now - session_record[2] <= TEMP_SESSION_IDLE_SECONDS
                ):
                    candidate_id = session_id
                elif session_id:
                    self._stream_temp_tasks.pop(stream_key, None)

            if candidate_id:
                record = self._known_temp_tasks.get(candidate_id)
                if record is not None and record[1] != root_active:
                    if explicit_reuse:
                        raise TempCleanupError(
                            "指定临时任务的权限模式与当前命令不一致。"
                        )
                    record = None
                try:
                    task = await asyncio.to_thread(
                        reuse_managed_temp_task,
                        self._sandbox_path,
                        task_id=candidate_id,
                        command_uid=command_uid,
                        command_gid=command_gid,
                    )
                except Exception:
                    self._known_temp_tasks.pop(candidate_id, None)
                    if explicit_reuse:
                        raise TempCleanupError(
                            "指定临时任务不存在、已过期或安全属性发生变化。"
                        )
                    task = None

            if task is None:
                task = await asyncio.to_thread(
                    create_managed_temp_task,
                    self._sandbox_path,
                    command_uid=command_uid,
                    command_gid=command_gid,
                )
            self._known_temp_tasks[task.task_id] = (task, root_active, now)
            if stream_key:
                self._stream_temp_tasks[stream_key] = task.task_id
            self._active_temp_tasks[task.task_id] = (
                self._active_temp_tasks.get(task.task_id, 0) + 1
            )
            return task

    async def _release_command_temp(self, task: ManagedTempTask | None) -> None:
        if task is None:
            return
        async with self._cleanup_lock:
            remaining = self._active_temp_tasks.get(task.task_id, 0) - 1
            if remaining > 0:
                self._active_temp_tasks[task.task_id] = remaining
            else:
                self._active_temp_tasks.pop(task.task_id, None)
            record = self._known_temp_tasks.get(task.task_id)
            if record is not None:
                self._known_temp_tasks[task.task_id] = (
                    record[0],
                    record[1],
                    asyncio.get_running_loop().time(),
                )

    def _decorate_temp_policy(
        self,
        payload: dict[str, object],
        task: ManagedTempTask | None,
        *,
        root_active: bool,
    ) -> dict[str, object]:
        if task is None:
            payload["managed_temp_cleanup"] = "disabled"
            return payload
        visible_path = os.fspath(task.host_path) if root_active else task.sandbox_path
        retention_hours = int(self.config.temp_cleanup.retention_hours)
        payload["managed_temp_cleanup"] = "enabled"
        payload["managed_temp_dir"] = visible_path
        payload["temp_task_id"] = task.task_id
        payload["managed_temp_retention_hours"] = retention_hours
        payload["managed_temp_delete_after_upload"] = bool(
            self.config.temp_cleanup.delete_after_upload
        )
        payload["content"] = (
            f"{payload.get('content', '')}\n\n"
            f"临时文件目录：{visible_path}（环境变量 $MAIBOT_TEMP_DIR）。"
            f"临时内容默认保留 {retention_hours} 小时；"
            "需要长期保留的成果必须移出该目录。"
            + (
                "其中的文件经 QQ 明确发送成功且未发生变化后会立即删除。"
                if self.config.temp_cleanup.delete_after_upload
                else "管理员已关闭 QQ 发送成功后的立即删除。"
            )
            + "绝不能把系统目录或普通 /work 文件当作可自动清理对象。"
        )
        return payload

    async def _delete_uploaded_temp_file(self, prepared: Any) -> str:
        if (
            not self.config.temp_cleanup.enabled
            or not self.config.temp_cleanup.delete_after_upload
            or prepared.cleanup_relative_parts is None
            or prepared.cleanup_identity is None
        ):
            return "not_requested"
        async with self._cleanup_lock:
            if self._sandbox_path is None or self._managed_temp_root is None:
                return "cleanup_unavailable"
            return await asyncio.to_thread(
                delete_uploaded_managed_file,
                self._sandbox_path,
                relative_parts=prepared.cleanup_relative_parts,
                expected_identity=prepared.cleanup_identity,
                active_task_ids=tuple(self._active_temp_tasks),
            )

    async def on_load(self) -> None:
        root_active, root_reason = self._root_mode_state()
        unrestricted_active, unrestricted_reason = self._unrestricted_root_state(root_active)
        if self.config.temp_cleanup.enabled:
            try:
                await self._refresh_cleanup_service(run_now=True)
            except Exception as exc:
                self._managed_temp_root = None
                self.ctx.logger.error(
                    "受管临时文件服务初始化失败：error_type=%s",
                    type(exc).__name__,
                )
        if unrestricted_active:
            self._sandbox_error = ""
            self.ctx.logger.critical(
                "完全 ROOT 模式已启用：sandbox=disabled cwd=/root regex_guard=disabled；"
                "命令不会经过高风险正则拦截"
            )
            return
        if self.config.unrestricted_root.enabled:
            self.ctx.logger.warning(
                "完全 ROOT 模式未生效：reason=%s",
                unrestricted_reason,
            )
        if root_active:
            self._sandbox_error = ""
            self.ctx.logger.critical(
                "受限 ROOT 模式已启用：沙箱已关闭，命令将以 root 在 /root 执行；"
                "插件会拒绝识别到的高风险命令"
            )
            return
        if self.config.root_mode.enabled:
            self.ctx.logger.warning(
                "受限 ROOT 模式未生效，将继续使用低权限沙箱：reason=%s",
                root_reason,
            )
        try:
            if (
                self._sandbox_path is None
                or not self._sandbox_prepared_for_low_privilege
            ):
                self._initialize_sandbox(low_privilege=True)
        except Exception as exc:
            self._sandbox_path = None
            self._sandbox_prepared_for_low_privilege = False
            self._sandbox_error = str(exc)
            self.ctx.logger.exception(
                "命令沙箱初始化暂不可用，插件仍会加载并在调用时重试：error=%s",
                exc,
            )
        else:
            identity = resolve_execution_identity()
            self.ctx.logger.info(
                "命令沙箱插件已加载：path=%s command_user=%s uid=%s gid=%s network_enabled=%s",
                self._sandbox_path,
                identity.name,
                identity.uid,
                identity.gid,
                self.config.sandbox.network_enabled,
            )

    async def on_unload(self) -> None:
        await self._stop_cleanup_loop()
        self._active_temp_tasks.clear()
        self._known_temp_tasks.clear()
        self._stream_temp_tasks.clear()
        self.ctx.logger.info("命令沙箱插件已卸载")

    async def on_config_update(self, scope: str, config_data: dict[str, object], version: str) -> None:
        del config_data
        if scope == CONFIG_RELOAD_SCOPE_SELF:
            try:
                await self._refresh_cleanup_service(run_now=True)
            except Exception as exc:
                self.ctx.logger.error(
                    "配置更新后受管临时文件服务不可用：error_type=%s",
                    type(exc).__name__,
                )
            root_active, root_reason = self._root_mode_state()
            unrestricted_active, unrestricted_reason = self._unrestricted_root_state(root_active)
            if unrestricted_active:
                self.ctx.logger.critical(
                    "配置更新后完全 ROOT 已启用：version=%s cwd=/root "
                    "sandbox=disabled regex_guard=disabled",
                    version,
                )
            elif root_active:
                if self.config.unrestricted_root.enabled:
                    self.ctx.logger.warning(
                        "配置更新后完全 ROOT 未生效：reason=%s",
                        unrestricted_reason,
                    )
                self.ctx.logger.critical(
                    "配置更新后受限 ROOT 已启用：version=%s cwd=/root "
                    "sandbox=disabled regex_guard=enabled",
                    version,
                )
            else:
                self.ctx.logger.info(
                    "命令插件配置已更新：version=%s network_enabled=%s "
                    "root_mode=false root_reason=%s unrestricted_reason=%s",
                    version,
                    self.config.sandbox.network_enabled,
                    root_reason,
                    unrestricted_reason,
                )

    @staticmethod
    def _stream_identifier(stream: dict[str, object]) -> str:
        value = stream.get("stream_id") or stream.get("session_id")
        return str(value or "")

    @staticmethod
    def _stream_account_id(stream: dict[str, object]) -> str:
        return str(stream.get("account_id") or "")

    @staticmethod
    def _normalize_stream_list(value: Any) -> list[dict[str, object]]:
        if isinstance(value, dict):
            value = value.get("streams", [])
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @staticmethod
    def _tool_temp_session_key(
        stream_id: str,
        message: Any,
    ) -> str:
        """Scope automatic reuse to one triggering message when possible."""

        normalized_stream = str(stream_id).strip()
        message_id = ""
        if isinstance(message, dict):
            message_id = str(
                message.get("message_id")
                or message.get("id")
                or ""
            ).strip()
            message_info = message.get("message_info")
            if not message_id and isinstance(message_info, dict):
                message_id = str(
                    message_info.get("message_id")
                    or message_info.get("id")
                    or ""
                ).strip()
        if normalized_stream and message_id:
            return f"{normalized_stream}\x1f{message_id}"
        return normalized_stream

    async def _resolve_qq_stream(
        self,
        target_type: str,
        target_id: str,
        account_id: str,
        current_stream_id: str,
    ) -> tuple[str, str]:
        kind = str(target_type).strip().lower()
        requested_target = str(target_id).strip()
        requested_account = str(account_id).strip()
        if kind not in {"current", "stream", "group", "private"}:
            raise FileUploadError(
                "target_type 只能是 current、stream、group 或 private。"
            )

        if kind == "current":
            requested_target = requested_target or str(current_stream_id).strip()
            if not requested_target:
                raise FileUploadError(
                    "当前调用没有可用的 QQ stream_id；请改用 group、private 或 stream 并填写 target_id。"
                )
            kind = "stream"
        elif not requested_target:
            raise FileUploadError("指定 QQ 会话时必须填写 target_id。")

        if kind == "group":
            raw_streams = await self.ctx.chat.get_group_streams("qq")
            match_key = "group_id"
        elif kind == "private":
            raw_streams = await self.ctx.chat.get_private_streams("qq")
            match_key = "user_id"
        else:
            raw_streams = await self.ctx.chat.get_all_streams("qq")
            match_key = ""

        streams = self._normalize_stream_list(raw_streams)
        matches: list[dict[str, object]] = []
        for stream in streams:
            platform = str(stream.get("platform") or "qq").lower()
            if platform != "qq":
                continue
            if kind == "stream":
                matched = self._stream_identifier(stream) == requested_target
            else:
                matched = str(stream.get(match_key) or "") == requested_target
            if not matched:
                continue
            if requested_account and self._stream_account_id(stream) != requested_account:
                continue
            if self._stream_identifier(stream):
                matches.append(stream)

        unique_matches: dict[str, dict[str, object]] = {
            self._stream_identifier(stream): stream for stream in matches
        }
        matches = list(unique_matches.values())
        if not matches:
            raise FileUploadError(
                "未找到匹配的 QQ 会话；目标必须已经在 MaiBot 中建立聊天流，"
                "并且 target_id、target_type 和 account_id 必须完全匹配。"
            )
        if len(matches) > 1:
            candidate_accounts = sorted(
                {
                    self._stream_account_id(stream)
                    for stream in matches
                    if self._stream_account_id(stream)
                }
            )
            suffix = (
                f" 可选 account_id：{', '.join(candidate_accounts)}。"
                if candidate_accounts
                else ""
            )
            raise FileUploadError(
                "有多个 QQ 机器人账号匹配该目标，拒绝猜测；请填写 account_id。"
                f"{suffix}"
            )

        stream = matches[0]
        return self._stream_identifier(stream), kind

    @Tool(
        "send_server_file_to_qq",
        brief_description="把服务器上的非敏感普通文件发送到指定 QQ 会话",
        detailed_description=(
            "仅当用户明确要求发送某个具体文件时调用，不得主动、批量或猜测性上传。"
            "target_type 可为 current（当前 QQ 会话）、stream（MaiBot 聊天流 ID）、"
            "group（QQ群号）或 private（QQ 用户号）；group/private 目标必须已经与"
            "MaiBot 建立聊天流。多 QQ 机器人账号匹配时必须提供 account_id，绝不能"
            "自行选择。默认低权限模式只能读取 /work（宿主机 maibot-command-file）"
            "中的普通文件；受限 ROOT 或完全 ROOT 生效后可读取全系统普通文件。"
            "无论哪种模式，都绝对禁止上传密码、Token、私钥、Cookie、认证配置、"
            "数据库、备份、个人信息或其他敏感数据，也不得通过改名、复制、压缩、"
            "编码等方式绕过；不确定文件是否敏感时必须拒绝调用。内置路径和内容扫描"
            "只是额外防线，扫描未命中不代表文件安全。符号链接、硬链接、目录、FIFO、"
            "Socket、设备、空文件、读取中发生变化的文件和超过大小上限的文件都会被拒绝。"
            "若文件来自 $MAIBOT_TEMP_DIR，且 QQ 明确返回发送成功、文件身份未变化、"
            "任务也已结束，插件会按管理员配置立即删除该临时源文件；普通 /work、"
            "/root、/etc 等路径永不因此自动删除。发送失败或结果不确定时必须保留，"
            "也不得自动重试，以免 QQ 重复收到文件。"
        ),
        parameters=[
            ToolParameterInfo(
                name="file_path",
                param_type=ToolParamType.STRING,
                description=(
                    "服务器文件路径。低权限模式使用 /work/文件名或相对路径；"
                    "ROOT 模式相对路径从 /root 解析，也可使用绝对路径"
                ),
                required=True,
            ),
            ToolParameterInfo(
                name="target_type",
                param_type=ToolParamType.STRING,
                description="目标类型：current、stream、group 或 private",
                required=True,
            ),
            ToolParameterInfo(
                name="target_id",
                param_type=ToolParamType.STRING,
                description=(
                    "目标 ID：stream 填聊天流 ID，group 填 QQ 群号，private 填 QQ 号；"
                    "current 可留空"
                ),
                required=False,
                default="",
            ),
            ToolParameterInfo(
                name="account_id",
                param_type=ToolParamType.STRING,
                description="多 QQ 机器人账号匹配时用于消歧的机器人 QQ 号",
                required=False,
                default="",
            ),
            ToolParameterInfo(
                name="upload_name",
                param_type=ToolParamType.STRING,
                description="可选的 QQ 显示文件名；只能是单个非敏感文件名，不能包含路径",
                required=False,
                default="",
            ),
        ],
    )
    async def handle_send_server_file_to_qq(
        self,
        file_path: str,
        target_type: str,
        target_id: str = "",
        account_id: str = "",
        upload_name: str = "",
        **kwargs: Any,
    ) -> dict[str, object]:
        audit_id = secrets.token_hex(8)
        if not self.config.file_upload.enabled:
            self.ctx.logger.warning(
                "QQ 文件上传被拒绝：upload_id=%s reason=tool_disabled",
                audit_id,
            )
            return {
                "success": False,
                "name": "send_server_file_to_qq",
                "content": "QQ 文件上传工具已被管理员禁用。",
                "upload_id": audit_id,
            }

        try:
            stream_id, resolved_kind = await self._resolve_qq_stream(
                target_type,
                target_id,
                account_id,
                str(kwargs.get("stream_id") or ""),
            )
        except FileUploadError as exc:
            self.ctx.logger.warning(
                "QQ 文件上传被拒绝：upload_id=%s reason=target_resolution_failed",
                audit_id,
            )
            return {
                "success": False,
                "name": "send_server_file_to_qq",
                "content": f"QQ 目标会话解析失败，文件未读取也未发送：{exc}",
                "upload_id": audit_id,
            }
        except Exception as exc:
            self.ctx.logger.error(
                "QQ 会话查询异常：upload_id=%s error_type=%s",
                audit_id,
                type(exc).__name__,
            )
            return {
                "success": False,
                "name": "send_server_file_to_qq",
                "content": "QQ 会话查询异常，文件未读取也未发送。",
                "upload_id": audit_id,
            }

        root_active, root_reason = self._root_mode_state()
        unrestricted_active, unrestricted_reason = self._unrestricted_root_state(root_active)
        if unrestricted_active:
            execution_mode = "root_unrestricted"
        elif root_active:
            execution_mode = "root_restricted"
        else:
            execution_mode = "sandbox"
            if self.config.root_mode.enabled:
                self.ctx.logger.warning(
                    "ROOT 配置不完整，QQ 文件上传继续限制在沙箱：upload_id=%s reason=%s",
                    audit_id,
                    root_reason,
                )
            if self.config.unrestricted_root.enabled:
                self.ctx.logger.warning(
                    "完全 ROOT 配置不完整，QQ 文件上传未获得全文件访问："
                    "upload_id=%s reason=%s",
                    audit_id,
                    unrestricted_reason,
                )
            if (
                self._sandbox_path is None
                or not self._sandbox_prepared_for_low_privilege
            ):
                try:
                    self._initialize_sandbox(low_privilege=True)
                except Exception as exc:
                    self._sandbox_error = str(exc)
                    self.ctx.logger.exception(
                        "QQ 文件上传失败：沙箱初始化失败：upload_id=%s",
                        audit_id,
                    )
                    return {
                        "success": False,
                        "name": "send_server_file_to_qq",
                        "content": f"沙箱初始化失败，文件未读取也未发送：{exc}",
                        "upload_id": audit_id,
                        "execution_mode": execution_mode,
                    }

        if self.config.temp_cleanup.enabled and self._managed_temp_root is None:
            try:
                await asyncio.to_thread(
                    self._initialize_sandbox,
                    low_privilege=not root_active,
                )
            except Exception as exc:
                self.ctx.logger.error(
                    "QQ 上传前无法初始化受管临时目录：upload_id=%s error_type=%s",
                    audit_id,
                    type(exc).__name__,
                )

        try:
            prepared = await asyncio.to_thread(
                prepare_file_upload,
                str(file_path),
                sandbox_root=self._sandbox_path,
                root_mode=root_active,
                configured_max_mb=self.config.file_upload.max_upload_mb,
                upload_name=str(upload_name) if upload_name else None,
                managed_temp_root=self._managed_temp_root,
            )
        except FileUploadError as exc:
            self.ctx.logger.warning(
                "QQ 文件上传被拒绝：upload_id=%s mode=%s reason=file_validation_failed",
                audit_id,
                execution_mode,
            )
            return {
                "success": False,
                "name": "send_server_file_to_qq",
                "content": f"文件安全检查未通过，文件未发送：{exc}",
                "upload_id": audit_id,
                "execution_mode": execution_mode,
                "sensitive_file_guard": "enabled",
            }
        except Exception as exc:
            self.ctx.logger.error(
                "QQ 文件安全检查异常：upload_id=%s mode=%s error_type=%s",
                audit_id,
                execution_mode,
                type(exc).__name__,
            )
            return {
                "success": False,
                "name": "send_server_file_to_qq",
                "content": "文件安全检查发生内部异常，文件未发送。",
                "upload_id": audit_id,
                "execution_mode": execution_mode,
                "sensitive_file_guard": "enabled",
            }

        try:
            self.ctx.logger.warning(
                "准备向 QQ 发送服务器文件：upload_id=%s mode=%s scope=%s "
                "bytes=%s target_type=%s",
                audit_id,
                execution_mode,
                prepared.source_scope,
                prepared.size,
                resolved_kind,
            )
            send_result = await self.ctx.send.custom(
                "file",
                prepared.message_payload(),
                stream_id,
                storage_message=False,
                show_log=False,
                sync_to_maisaka_history=False,
            )
            confirmed_success = send_result is True or (
                isinstance(send_result, dict) and send_result.get("success") is True
            )
            if not confirmed_success:
                raise RuntimeError("QQ 适配器未明确确认发送成功")
        except Exception as exc:
            self.ctx.logger.error(
                "QQ 文件发送失败或结果不确定：upload_id=%s mode=%s error_type=%s",
                audit_id,
                execution_mode,
                type(exc).__name__,
            )
            return {
                "success": False,
                "name": "send_server_file_to_qq",
                "content": (
                    "QQ 文件发送失败或结果不确定。"
                    "请先人工检查目标会话，不要自动重试，以免重复发送。"
                ),
                "upload_id": audit_id,
                "execution_mode": execution_mode,
                "source_scope": prepared.source_scope,
                "sensitive_file_guard": "enabled",
                "retry_safe": False,
                "temporary_file_cleanup": "retained_send_unconfirmed",
            }

        try:
            cleanup_status = await self._delete_uploaded_temp_file(prepared)
        except Exception as exc:
            cleanup_status = "cleanup_failed"
            self.ctx.logger.error(
                "QQ 已明确发送成功，但临时源文件清理异常："
                "upload_id=%s mode=%s error_type=%s",
                audit_id,
                execution_mode,
                type(exc).__name__,
            )
        self.ctx.logger.warning(
            "QQ 文件发送完成：upload_id=%s mode=%s scope=%s bytes=%s "
            "temporary_cleanup=%s",
            audit_id,
            execution_mode,
            prepared.source_scope,
            prepared.size,
            cleanup_status,
        )
        if cleanup_status in {"deleted", "deleted_file_prune_failed"}:
            cleanup_notice = "该文件来自受管临时目录，发送成功后源文件已安全删除。"
        elif (
            prepared.cleanup_relative_parts is not None
            and not self.config.temp_cleanup.delete_after_upload
        ):
            cleanup_notice = "该文件来自受管临时目录，但管理员已关闭发送成功后的立即删除。"
        elif prepared.cleanup_relative_parts is not None:
            cleanup_notice = (
                "该文件来自受管临时目录，但因任务仍活动、文件变化或清理不可用而保留；"
                "之后仍会按保留期限检查。"
            )
        else:
            cleanup_notice = "源文件不属于受管临时目录，插件没有删除它。"
        return {
            "success": True,
            "name": "send_server_file_to_qq",
            "content": (
                f"文件已发送到指定 QQ 会话：{prepared.name}（{prepared.size} 字节）。"
                f"{cleanup_notice}"
                "敏感文件禁令仍然有效；内置扫描通过不代表可忽略人工判断。"
            ),
            "upload_id": audit_id,
            "execution_mode": execution_mode,
            "source_scope": prepared.source_scope,
            "sensitive_file_guard": "enabled",
            "file_name": prepared.name,
            "file_size": prepared.size,
            "sha256": prepared.sha256,
            "target_type": resolved_kind,
            "temporary_file_cleanup": cleanup_status,
        }

    @Tool(
        "run_server_command",
        brief_description="在服务器的专用 Ubuntu 沙箱目录中运行命令",
        detailed_description=(
            "默认仅在 MaiBot 主程序目录下的 maibot-command-file 沙箱中执行 Bash 命令。"
            "管理员完成受限 ROOT 的全部确认后，沙箱会关闭，命令将以 root 在 /root "
            "中执行，并拦截正则能够识别的明显高风险命令；正则无法保证识别混淆命令。"
            "只有受限 ROOT 已生效且十项认证全部匹配，才会进入不做命令正则拦截的完全 ROOT。"
            "两种 ROOT 模式下都必须坚决拒绝高风险、破坏性、凭据读取、维持提权或"
            "数据外传命令；不确定是否安全时不要调用。"
            "低权限沙箱由管理员的联网开关控制；两种 ROOT 模式直接使用宿主机网络，"
            "不受该联网开关限制。"
            "启用临时清理后，每个临时任务都有独立的 $MAIBOT_TEMP_DIR；短期中间文件应"
            "只写入这个环境变量指向的目录。同一条用户消息触发的连续命令会自动复用；"
            "若运行时没有消息 ID，则同一会话在 30 分钟空闲租约内复用。也可以把上一"
            "条结果的 temp_task_id 传给下一条命令，以跨消息明确继续同一任务。只有"
            "明确开始新任务时才设置 start_new_temp_task=true。"
            "需要保留的成果必须放到普通 /work 或管理员指定的持久位置。不得把其他"
            "目录中的文件当成可自动清理文件。"
            "调用前先根据返回的权限模式判断实际边界。"
        ),
        parameters=[
            ToolParameterInfo(
                name="command",
                param_type=ToolParamType.STRING,
                description="要执行的 Ubuntu Bash 命令",
                required=True,
            ),
            ToolParameterInfo(
                name="timeout_seconds",
                param_type=ToolParamType.INTEGER,
                description="本次超时秒数；不得超过插件配置上限",
                required=False,
                default=20,
            ),
            ToolParameterInfo(
                name="temp_task_id",
                param_type=ToolParamType.STRING,
                description=(
                    "可选的受管临时任务 ID。需要多条命令继续使用同一批临时文件时，"
                    "传入上一条结果返回的 temp_task_id；不得自行编造"
                ),
                required=False,
                default="",
            ),
            ToolParameterInfo(
                name="start_new_temp_task",
                param_type=ToolParamType.BOOLEAN,
                description=(
                    "是否明确开始新的临时任务。仅当上一任务已结束且不应复用其目录时设为 true；"
                    "不能与 temp_task_id 同时使用"
                ),
                required=False,
                default=False,
            ),
        ],
    )
    async def handle_run_server_command(
        self,
        command: str,
        timeout_seconds: int = 20,
        temp_task_id: str = "",
        start_new_temp_task: bool = False,
        **kwargs: Any,
    ) -> dict[str, object]:
        current_stream_id = str(kwargs.get("stream_id") or "")
        temp_session_key = self._tool_temp_session_key(
            current_stream_id,
            kwargs.get("message"),
        )
        if not self.config.sandbox.enabled:
            self.ctx.logger.warning("麦麦调用沙箱命令被拒绝：工具已被管理员禁用")
            return {
                "success": False,
                "name": "run_server_command",
                "content": "命令沙箱工具已被管理员禁用。",
            }

        root_active, root_reason = self._root_mode_state()
        unrestricted_active, unrestricted_reason = self._unrestricted_root_state(root_active)
        settings = self.config.sandbox
        audit_id = command_audit_id(str(command))
        limits = SandboxLimits(
            timeout_seconds=settings.timeout_seconds,
            max_output_bytes=settings.max_output_bytes,
            memory_limit_mb=settings.memory_limit_mb,
            file_size_limit_mb=settings.file_size_limit_mb,
            max_processes=settings.max_processes,
        )
        if unrestricted_active:
            try:
                temp_task = await self._create_command_temp(
                    root_active=True,
                    session_key=temp_session_key,
                    requested_task_id=temp_task_id,
                    start_new_task=bool(start_new_temp_task),
                )
            except Exception as exc:
                self.ctx.logger.error(
                    "完全 ROOT 命令未执行：受管临时目录不可用："
                    "command_id=%s error_type=%s",
                    audit_id,
                    type(exc).__name__,
                )
                return {
                    "success": False,
                    "name": "run_server_command",
                    "content": (
                        f"{UNRESTRICTED_ROOT_NOTICE}\n\n"
                        "受管临时目录初始化失败，命令未执行。"
                    ),
                    "execution_mode": "root_unrestricted",
                    "managed_temp_cleanup": "unavailable",
                }
            try:
                self.ctx.logger.critical(
                    "麦麦准备执行完全 ROOT 命令：command_id=%s cwd=/root "
                    "regex_guard=disabled timeout=%ss",
                    audit_id,
                    min(max(1, int(timeout_seconds)), limits.normalized().timeout_seconds),
                )
                result = await run_unrestricted_root_command(
                    str(command),
                    limits,
                    requested_timeout=timeout_seconds,
                    managed_temp_directory=(
                        os.fspath(temp_task.host_path) if temp_task is not None else None
                    ),
                )
                if result.timed_out:
                    self.ctx.logger.warning(
                        "完全 ROOT 命令执行超时：command_id=%s exit_code=%s",
                        audit_id,
                        result.exit_code,
                    )
                elif result.exit_code != 0:
                    self.ctx.logger.warning(
                        "完全 ROOT 命令执行失败：command_id=%s exit_code=%s",
                        audit_id,
                        result.exit_code,
                    )
                else:
                    self.ctx.logger.warning(
                        "完全 ROOT 命令执行成功：command_id=%s exit_code=0",
                        audit_id,
                    )
                payload = self._unrestricted_root_result(result)
            except Exception as exc:
                self.ctx.logger.exception(
                    "完全 ROOT 命令未执行或插件异常：command_id=%s error=%s",
                    audit_id,
                    exc,
                )
                payload = {
                    "success": False,
                    "name": "run_server_command",
                    "content": f"{UNRESTRICTED_ROOT_NOTICE}\n\n命令未执行：{exc}",
                    "execution_mode": "root_unrestricted",
                    "command_regex_guard": "disabled",
                    "working_directory": "/root",
                    "process_limit": "not_enforced_for_uid_0",
                    "descendant_cleanup": "on_command_exit_or_timeout",
                }
            finally:
                await self._release_command_temp(temp_task)
            return self._decorate_temp_policy(
                payload,
                temp_task,
                root_active=True,
            )

        if self.config.unrestricted_root.enabled:
            self.ctx.logger.warning(
                "完全 ROOT 配置不完整，本次使用受限 ROOT 或低权限沙箱：reason=%s",
                unrestricted_reason,
            )

        if root_active:
            risk_reason = high_risk_command_reason(str(command))
            if risk_reason is not None:
                self.ctx.logger.critical(
                    "受限 ROOT 命令被安全策略拒绝：command_id=%s risk=%s",
                    audit_id,
                    risk_reason,
                )
                return {
                    "success": False,
                    "name": "run_server_command",
                    "content": (
                        f"{ROOT_MODE_NOTICE}\n\n"
                        f"状态：已拒绝\n原因：检测到高风险操作（{risk_reason}）。"
                    ),
                    "execution_mode": "root_restricted",
                    "command_regex_guard": "enabled",
                    "working_directory": "/root",
                    "process_limit": "not_enforced_for_uid_0",
                    "descendant_cleanup": "on_command_exit_or_timeout",
                }
            try:
                temp_task = await self._create_command_temp(
                    root_active=True,
                    session_key=temp_session_key,
                    requested_task_id=temp_task_id,
                    start_new_task=bool(start_new_temp_task),
                )
            except Exception as exc:
                self.ctx.logger.error(
                    "受限 ROOT 命令未执行：受管临时目录不可用："
                    "command_id=%s error_type=%s",
                    audit_id,
                    type(exc).__name__,
                )
                return {
                    "success": False,
                    "name": "run_server_command",
                    "content": (
                        f"{ROOT_MODE_NOTICE}\n\n"
                        "受管临时目录初始化或复用失败，命令未执行。"
                    ),
                    "execution_mode": "root_restricted",
                    "managed_temp_cleanup": "unavailable",
                }
            try:
                self.ctx.logger.critical(
                    "麦麦准备执行受限 ROOT 命令：command_id=%s cwd=/root timeout=%ss",
                    audit_id,
                    min(max(1, int(timeout_seconds)), limits.normalized().timeout_seconds),
                )
                result = await run_root_command(
                    str(command),
                    limits,
                    requested_timeout=timeout_seconds,
                    managed_temp_directory=(
                        os.fspath(temp_task.host_path) if temp_task is not None else None
                    ),
                )
                if result.timed_out:
                    self.ctx.logger.warning(
                        "受限 ROOT 命令执行超时：command_id=%s exit_code=%s",
                        audit_id,
                        result.exit_code,
                    )
                elif result.exit_code != 0:
                    self.ctx.logger.warning(
                        "受限 ROOT 命令执行失败：command_id=%s exit_code=%s",
                        audit_id,
                        result.exit_code,
                    )
                else:
                    self.ctx.logger.warning(
                        "受限 ROOT 命令执行成功：command_id=%s exit_code=0",
                        audit_id,
                    )
                payload = self._root_result(result)
            except Exception as exc:
                self.ctx.logger.exception(
                    "受限 ROOT 命令被拒绝或插件异常：command_id=%s error=%s",
                    audit_id,
                    exc,
                )
                payload = {
                    "success": False,
                    "name": "run_server_command",
                    "content": f"{ROOT_MODE_NOTICE}\n\n命令未执行：{exc}",
                    "execution_mode": "root_restricted",
                    "command_regex_guard": "enabled",
                    "working_directory": "/root",
                    "process_limit": "not_enforced_for_uid_0",
                    "descendant_cleanup": "on_command_exit_or_timeout",
                }
            finally:
                await self._release_command_temp(temp_task)
            return self._decorate_temp_policy(
                payload,
                temp_task,
                root_active=True,
            )

        if self.config.root_mode.enabled:
            self.ctx.logger.warning(
                "受限 ROOT 配置不完整，本次继续使用低权限沙箱：reason=%s",
                root_reason,
            )
        if (
            self._sandbox_path is None
            or not self._sandbox_prepared_for_low_privilege
        ):
            try:
                self._initialize_sandbox(low_privilege=True)
            except Exception as exc:
                self._sandbox_error = str(exc)
                self.ctx.logger.exception("麦麦调用沙箱命令失败：沙箱初始化失败：error=%s", exc)
                return {
                    "success": False,
                    "name": "run_server_command",
                    "content": f"沙箱初始化失败，命令未执行：{exc}",
                }

        try:
            temp_task = await self._create_command_temp(
                root_active=False,
                session_key=temp_session_key,
                requested_task_id=temp_task_id,
                start_new_task=bool(start_new_temp_task),
            )
        except Exception as exc:
            self.ctx.logger.error(
                "沙箱命令未执行：受管临时目录不可用："
                "command_id=%s error_type=%s",
                audit_id,
                type(exc).__name__,
            )
            return {
                "success": False,
                "name": "run_server_command",
                "content": "受管临时目录初始化或复用失败，命令未执行。",
                "execution_mode": "sandbox",
                "managed_temp_cleanup": "unavailable",
            }

        try:
            self.ctx.logger.info(
                "麦麦准备执行沙箱命令：command_id=%s network_enabled=%s timeout=%ss",
                audit_id,
                settings.network_enabled,
                min(max(1, int(timeout_seconds)), limits.normalized().timeout_seconds),
            )
            result = await run_command(
                str(command),
                self._sandbox_path,
                limits,
                requested_timeout=timeout_seconds,
                network_enabled=settings.network_enabled,
                managed_temp_directory=(
                    temp_task.sandbox_path if temp_task is not None else None
                ),
            )
            if result.timed_out:
                self.ctx.logger.warning(
                    "沙箱命令执行超时：command_id=%s exit_code=%s",
                    audit_id,
                    result.exit_code,
                )
            elif result.exit_code != 0:
                self.ctx.logger.warning(
                    "沙箱命令执行失败：command_id=%s exit_code=%s",
                    audit_id,
                    result.exit_code,
                )
            else:
                self.ctx.logger.info(
                    "沙箱命令执行成功：command_id=%s exit_code=0",
                    audit_id,
                )
            payload = result.as_dict()
        except Exception as exc:
            self.ctx.logger.exception(
                "沙箱命令被拒绝或插件异常：command_id=%s error=%s",
                audit_id,
                exc,
            )
            payload = {
                "success": False,
                "name": "run_server_command",
                "content": f"命令未执行：{exc}",
            }
        finally:
            await self._release_command_temp(temp_task)
        return self._decorate_temp_policy(
            payload,
            temp_task,
            root_active=False,
        )


def create_plugin() -> ServerCommandPlugin:
    return ServerCommandPlugin()

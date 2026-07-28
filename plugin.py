"""MaiBot tool plugin for running commands in a fixed Ubuntu sandbox."""

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

from maibot_sdk import CONFIG_RELOAD_SCOPE_SELF, Field, MaiBotPlugin, PluginConfigBase, Tool
from maibot_sdk.types import ToolParameterInfo, ToolParamType


def _load_sibling_executor() -> Any:
    """Load executor.py without relying on the Runner's sys.path."""

    module_name = "_xuesheng_maibot_server_command_executor_v1_0_10"
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


_executor = _load_sibling_executor()
SandboxLimits = _executor.SandboxLimits
command_audit_id = _executor.command_audit_id
find_maibot_root = _executor.find_maibot_root
high_risk_command_reason = _executor.high_risk_command_reason
prepare_sandbox = _executor.prepare_sandbox
resolve_execution_identity = _executor.resolve_execution_identity
run_command = _executor.run_command
run_root_command = _executor.run_root_command


ROOT_MODE_NOTICE = (
    "⚠️ 当前权限模式：ROOT 最高权限（沙箱已关闭，工作目录为 /root）。\n"
    "你现在拥有服务器最高权限。必须坚决拒绝高风险、破坏性、提权维持、"
    "凭据读取或泄露数据的命令；不确定是否安全时不要执行。"
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
            "hint": "开启后可使用 curl、wget 等访问公网、内网和本机网络服务。",
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
        description="运行用户可拥有的最大进程数",
        json_schema_extra={
            "label": "最大进程数",
            "hint": "限制命令及其子进程数量；有效范围为 8–128。",
            "x-widget": "number",
            "step": 1,
        },
    )


class RootPrivilegeConfig(PluginConfigBase):
    """需要多重确认才能启用的 root 最高权限模式。"""

    __ui_label__ = "ROOT 最高权限（极高风险）"
    __ui_icon__ = "triangle-alert"
    __ui_order__ = 1

    enabled: bool = Field(
        default=False,
        description="关闭命令沙箱并允许命令以 root 在 /root 中执行",
        json_schema_extra={
            "label": "关闭沙箱并启用 ROOT 最高权限",
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
    final_confirmation: int = Field(
        default=0,
        ge=0,
        le=1,
        description="最终数字确认；必须手动从 0 改为 1",
        json_schema_extra={
            "label": "最终确认：把 0 改成 1",
            "hint": "只有数值等于 1，且上面三个确认开关全部开启时，ROOT 模式才会生效。",
            "x-widget": "number",
            "step": 1,
        },
    )


class PluginMetadataConfig(PluginConfigBase):
    """插件配置文件的内部版本信息。"""

    __ui_label__ = "插件信息"
    __ui_icon__ = "info"
    __ui_order__ = -1

    config_version: str = Field(
        default="1.0.10",
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
    root_mode: RootPrivilegeConfig = Field(default_factory=RootPrivilegeConfig)


class ServerCommandPlugin(MaiBotPlugin):
    """Expose one fail-closed command tool to Maisaka."""

    config_model = ServerCommandPluginConfig

    def __init__(self) -> None:
        super().__init__()
        self._sandbox_path = None
        self._sandbox_error = ""

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
        if int(settings.final_confirmation) != 1:
            missing.append("最终确认值不是 1")
        if missing:
            return False, "；".join(missing)
        return True, "已满足 root 用户、总开关、三次开关和数值 1 的全部条件"

    @staticmethod
    def _root_result(result: Any) -> dict[str, object]:
        payload = result.as_dict()
        payload["content"] = f"{ROOT_MODE_NOTICE}\n\n{payload['content']}"
        payload["execution_mode"] = "root"
        payload["working_directory"] = "/root"
        return payload

    def _initialize_sandbox(self) -> None:
        maibot_root = find_maibot_root(__file__)
        identity = resolve_execution_identity()
        self._sandbox_path = prepare_sandbox(maibot_root, identity)
        self._sandbox_error = ""

    async def on_load(self) -> None:
        root_active, root_reason = self._root_mode_state()
        if root_active:
            self._sandbox_path = None
            self._sandbox_error = ""
            self.ctx.logger.critical(
                "ROOT 最高权限模式已启用：沙箱已关闭，命令将以 root 在 /root 执行；"
                "插件会拒绝识别到的高风险命令"
            )
            return
        if self.config.root_mode.enabled:
            self.ctx.logger.warning(
                "ROOT 最高权限模式未生效，将继续使用低权限沙箱：reason=%s",
                root_reason,
            )
        try:
            self._initialize_sandbox()
        except Exception as exc:
            self._sandbox_path = None
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
        self.ctx.logger.info("命令沙箱插件已卸载")

    async def on_config_update(self, scope: str, config_data: dict[str, object], version: str) -> None:
        del config_data
        if scope == CONFIG_RELOAD_SCOPE_SELF:
            root_active, root_reason = self._root_mode_state()
            if root_active:
                self.ctx.logger.critical(
                    "配置更新后 ROOT 最高权限模式已启用：version=%s cwd=/root sandbox=disabled",
                    version,
                )
            else:
                self.ctx.logger.info(
                    "命令插件配置已更新：version=%s network_enabled=%s root_mode=false reason=%s",
                    version,
                    self.config.sandbox.network_enabled,
                    root_reason,
                )

    @Tool(
        "run_server_command",
        brief_description="在服务器的专用 Ubuntu 沙箱目录中运行命令",
        detailed_description=(
            "默认仅在 MaiBot 主程序目录下的 maibot-command-file 沙箱中执行 Bash 命令。"
            "管理员完成 ROOT 最高权限模式的全部多重确认后，沙箱会关闭，命令将以 root "
            "在 /root 中执行；每次结果都会明确提示当前拥有服务器最高权限。"
            "ROOT 模式下必须坚决拒绝高风险、破坏性、凭据读取、维持提权或数据外传命令；"
            "不确定是否安全时不要调用，插件也会拦截能够识别的明显高风险命令。"
            "低权限沙箱由管理员的联网开关控制；ROOT 模式直接使用宿主机网络，"
            "不受该联网开关限制。"
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
        ],
    )
    async def handle_run_server_command(
        self,
        command: str,
        timeout_seconds: int = 20,
        **kwargs: Any,
    ) -> dict[str, object]:
        del kwargs
        if not self.config.sandbox.enabled:
            self.ctx.logger.warning("麦麦调用沙箱命令被拒绝：工具已被管理员禁用")
            return {
                "success": False,
                "name": "run_server_command",
                "content": "命令沙箱工具已被管理员禁用。",
            }

        root_active, root_reason = self._root_mode_state()
        settings = self.config.sandbox
        audit_id = command_audit_id(str(command))
        limits = SandboxLimits(
            timeout_seconds=settings.timeout_seconds,
            max_output_bytes=settings.max_output_bytes,
            memory_limit_mb=settings.memory_limit_mb,
            file_size_limit_mb=settings.file_size_limit_mb,
            max_processes=settings.max_processes,
        )
        if root_active:
            risk_reason = high_risk_command_reason(str(command))
            if risk_reason is not None:
                self.ctx.logger.critical(
                    "ROOT 最高权限命令被安全策略拒绝：command_id=%s risk=%s",
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
                    "execution_mode": "root",
                    "working_directory": "/root",
                }
            try:
                self.ctx.logger.critical(
                    "麦麦准备执行 ROOT 最高权限命令：command_id=%s cwd=/root timeout=%ss",
                    audit_id,
                    min(max(1, int(timeout_seconds)), limits.normalized().timeout_seconds),
                )
                result = await run_root_command(
                    str(command),
                    limits,
                    requested_timeout=timeout_seconds,
                )
                if result.timed_out:
                    self.ctx.logger.warning(
                        "ROOT 最高权限命令执行超时：command_id=%s exit_code=%s",
                        audit_id,
                        result.exit_code,
                    )
                elif result.exit_code != 0:
                    self.ctx.logger.warning(
                        "ROOT 最高权限命令执行失败：command_id=%s exit_code=%s",
                        audit_id,
                        result.exit_code,
                    )
                else:
                    self.ctx.logger.warning(
                        "ROOT 最高权限命令执行成功：command_id=%s exit_code=0",
                        audit_id,
                    )
                return self._root_result(result)
            except Exception as exc:
                self.ctx.logger.exception(
                    "ROOT 最高权限命令被拒绝或插件异常：command_id=%s error=%s",
                    audit_id,
                    exc,
                )
                return {
                    "success": False,
                    "name": "run_server_command",
                    "content": f"{ROOT_MODE_NOTICE}\n\n命令未执行：{exc}",
                    "execution_mode": "root",
                    "working_directory": "/root",
                }

        if self.config.root_mode.enabled:
            self.ctx.logger.warning(
                "ROOT 最高权限配置不完整，本次继续使用低权限沙箱：reason=%s",
                root_reason,
            )
        if self._sandbox_path is None:
            try:
                self._initialize_sandbox()
            except Exception as exc:
                self._sandbox_error = str(exc)
                self.ctx.logger.exception("麦麦调用沙箱命令失败：沙箱初始化失败：error=%s", exc)
                return {
                    "success": False,
                    "name": "run_server_command",
                    "content": f"沙箱初始化失败，命令未执行：{exc}",
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
            return result.as_dict()
        except Exception as exc:
            self.ctx.logger.exception(
                "沙箱命令被拒绝或插件异常：command_id=%s error=%s",
                audit_id,
                exc,
            )
            return {
                "success": False,
                "name": "run_server_command",
                "content": f"命令未执行：{exc}",
            }


def create_plugin() -> ServerCommandPlugin:
    return ServerCommandPlugin()

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

    module_name = "_xuesheng_maibot_server_command_executor_v1_0_12"
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
run_unrestricted_root_command = _executor.run_unrestricted_root_command


ROOT_MODE_NOTICE = (
    "⚠️ 当前权限模式：受限 ROOT（沙箱已关闭，工作目录为 /root）。\n"
    "你现在拥有服务器最高权限。必须坚决拒绝高风险、破坏性、提权维持、"
    "凭据读取或泄露数据的命令；不确定是否安全时不要执行。\n"
    "插件的正则防护无法保证识别 Base64、变量展开、eval 等混淆命令，"
    "不能把“未被拦截”视为命令安全。\n"
    "ROOT 不受“最大进程数”配置约束；命令结束或超时后，插件会清理本次命令"
    "直接产生的后台后代进程。"
)

UNRESTRICTED_ROOT_NOTICE = (
    "☢️ 当前权限模式：完全 ROOT（沙箱已关闭，工作目录为 /root）。\n"
    "管理员已完成十重认证，插件不会运行高风险命令正则拦截。"
    "你拥有服务器最高权限，仍必须自行判断并坚决拒绝高风险、破坏性、"
    "提权维持、凭据读取或泄露数据的命令；不确定是否安全时不要执行。\n"
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


class RootPrivilegeConfig(PluginConfigBase):
    """需要多重确认才能启用的受限 root 模式。"""

    __ui_label__ = "受限 ROOT（极高风险）"
    __ui_icon__ = "triangle-alert"
    __ui_order__ = 1

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
    final_confirmation: int = Field(
        default=0,
        ge=0,
        le=1,
        description="最终数字确认；必须手动从 0 改为 1",
        json_schema_extra={
            "label": "最终确认：把 0 改成 1",
            "hint": "只有数值等于 1，且上面三个确认开关全部开启时，受限 ROOT 才会生效。",
            "x-widget": "number",
            "step": 1,
        },
    )


class UnrestrictedRootConfig(PluginConfigBase):
    """只能从受限 ROOT 解锁的无命令正则拦截模式。"""

    __ui_label__ = "完全 ROOT（无命令正则拦截）"
    __ui_icon__ = "skull"
    __ui_order__ = 2

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
        default="1.0.12",
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
    unrestricted_root: UnrestrictedRootConfig = Field(default_factory=UnrestrictedRootConfig)


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

    def _initialize_sandbox(self) -> None:
        maibot_root = find_maibot_root(__file__)
        identity = resolve_execution_identity()
        self._sandbox_path = prepare_sandbox(maibot_root, identity)
        self._sandbox_error = ""

    async def on_load(self) -> None:
        root_active, root_reason = self._root_mode_state()
        unrestricted_active, unrestricted_reason = self._unrestricted_root_state(root_active)
        if unrestricted_active:
            self._sandbox_path = None
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
            self._sandbox_path = None
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
                return self._unrestricted_root_result(result)
            except Exception as exc:
                self.ctx.logger.exception(
                    "完全 ROOT 命令未执行或插件异常：command_id=%s error=%s",
                    audit_id,
                    exc,
                )
                return {
                    "success": False,
                    "name": "run_server_command",
                    "content": f"{UNRESTRICTED_ROOT_NOTICE}\n\n命令未执行：{exc}",
                    "execution_mode": "root_unrestricted",
                    "command_regex_guard": "disabled",
                    "working_directory": "/root",
                    "process_limit": "not_enforced_for_uid_0",
                    "descendant_cleanup": "on_command_exit_or_timeout",
                }

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
                self.ctx.logger.critical(
                    "麦麦准备执行受限 ROOT 命令：command_id=%s cwd=/root timeout=%ss",
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
                return self._root_result(result)
            except Exception as exc:
                self.ctx.logger.exception(
                    "受限 ROOT 命令被拒绝或插件异常：command_id=%s error=%s",
                    audit_id,
                    exc,
                )
                return {
                    "success": False,
                    "name": "run_server_command",
                    "content": f"{ROOT_MODE_NOTICE}\n\n命令未执行：{exc}",
                    "execution_mode": "root_restricted",
                    "command_regex_guard": "enabled",
                    "working_directory": "/root",
                    "process_limit": "not_enforced_for_uid_0",
                    "descendant_cleanup": "on_command_exit_or_timeout",
                }

        if self.config.root_mode.enabled:
            self.ctx.logger.warning(
                "受限 ROOT 配置不完整，本次继续使用低权限沙箱：reason=%s",
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

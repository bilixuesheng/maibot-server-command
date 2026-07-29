from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from executor import CommandResult
from plugin import (
    ROOT_MODE_NOTICE,
    UNRESTRICTED_ROOT_NOTICE,
    ServerCommandPlugin,
    create_plugin,
)


def test_factory_and_tool_declaration() -> None:
    plugin = create_plugin()
    assert isinstance(plugin, ServerCommandPlugin)
    components = plugin.get_components()
    tools = [item for item in components if item["name"] == "run_server_command"]
    assert len(tools) == 1


def test_default_configuration_is_enabled_and_bounded() -> None:
    config = ServerCommandPlugin.build_default_config()
    assert config["plugin"]["config_version"] == "1.0.12"
    assert config["sandbox"]["enabled"] is True
    assert config["sandbox"]["network_enabled"] is False
    assert config["sandbox"]["timeout_seconds"] == 20
    assert config["root_mode"]["enabled"] is False
    assert config["root_mode"]["confirmation_1"] is False
    assert config["root_mode"]["confirmation_2"] is False
    assert config["root_mode"]["confirmation_3"] is False
    assert config["root_mode"]["final_confirmation"] == 0
    assert config["unrestricted_root"]["enabled"] is False
    for index in range(1, 6):
        assert config["unrestricted_root"][f"confirmation_{index}"] is False
    assert config["unrestricted_root"]["confirmation_6"] is True
    assert config["unrestricted_root"]["confirmation_7"] is False
    assert config["unrestricted_root"]["confirmation_8"] is True
    assert config["unrestricted_root"]["confirmation_9"] == 1
    assert config["unrestricted_root"]["confirmation_10"] is True


def test_sdk_can_normalize_and_inject_default_configuration() -> None:
    plugin = create_plugin()
    plugin.set_plugin_config({})
    assert plugin.config.plugin.config_version == "1.0.12"
    assert plugin.config.sandbox.enabled is True


def test_runtime_configuration_is_generated_instead_of_committed() -> None:
    config_path = Path(__file__).resolve().parents[1] / "config.toml"
    assert not config_path.exists()

    config = ServerCommandPlugin.build_default_config()
    assert config["sandbox"]["network_enabled"] is False
    assert config["root_mode"]["enabled"] is False
    assert config["unrestricted_root"]["enabled"] is False


def test_manifest_is_v2_and_matches_plugin_version() -> None:
    manifest_path = Path(__file__).resolve().parents[1] / "_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == 2
    assert manifest["id"] == "xuesheng.maibot-server-command"
    assert manifest["version"] == "1.0.12"
    assert manifest["name"] == "服务器命令执行"
    assert manifest["description"] == (
        "让 MaiBot 在低权限沙箱中运行 Ubuntu 命令，并提供可选 ROOT 最高权限模式"
    )
    assert manifest["author"]["url"] == "https://github.com/bilixuesheng"
    assert manifest["urls"]["repository"] == (
        "https://github.com/bilixuesheng/maibot-server-command"
    )
    assert manifest["plugin_type"] == "tool"
    icon = manifest["display"]["icon"]
    assert icon["type"] == "local"
    assert icon["value"] == "assets/icon.png"
    assert icon["fallback"] == "terminal"
    assert icon["background"] == "#F3F4F6"
    icon_path = manifest_path.parent / icon["value"]
    assert icon_path.is_file()
    assert icon_path.suffix.lower() == ".png"
    assert icon_path.stat().st_size <= 512 * 1024


def test_webui_schema_uses_chinese_labels_and_hints() -> None:
    schema = create_plugin().get_webui_config_schema(
        plugin_id="xuesheng.maibot-server-command",
        plugin_name="服务器命令执行",
        plugin_version="1.0.12",
    )
    assert schema["sections"]["plugin"]["title"] == "插件信息"
    assert schema["sections"]["sandbox"]["title"] == "命令沙箱"
    assert schema["sections"]["root_mode"]["title"] == "受限 ROOT（极高风险）"
    assert schema["sections"]["unrestricted_root"]["title"] == (
        "完全 ROOT（无命令正则拦截）"
    )

    plugin_fields = schema["sections"]["plugin"]["fields"]
    sandbox_fields = schema["sections"]["sandbox"]["fields"]
    root_fields = schema["sections"]["root_mode"]["fields"]
    unrestricted_fields = schema["sections"]["unrestricted_root"]["fields"]
    assert plugin_fields["config_version"]["label"] == "配置版本"
    assert plugin_fields["config_version"]["disabled"] is True
    assert sandbox_fields["enabled"]["label"] == "启用命令工具"
    assert sandbox_fields["network_enabled"]["label"] == "允许命令联网"
    assert sandbox_fields["timeout_seconds"]["label"] == "命令超时时间（秒）"
    assert sandbox_fields["max_output_bytes"]["label"] == "最大输出大小（字节）"
    assert sandbox_fields["memory_limit_mb"]["label"] == "内存上限（MB）"
    assert sandbox_fields["file_size_limit_mb"]["label"] == "单文件大小上限（MB）"
    assert sandbox_fields["max_processes"]["label"] == "低权限沙箱最大进程数"
    assert "两种 ROOT 模式不应用此项" in sandbox_fields["max_processes"]["hint"]
    assert sandbox_fields["network_enabled"]["ui_type"] == "switch"
    assert sandbox_fields["timeout_seconds"]["ui_type"] == "number"
    network_hint = sandbox_fields["network_enabled"]["hint"]
    assert "localhost" in network_hint
    assert "内网" in network_hint
    assert "169.254.169.254" in network_hint
    assert root_fields["enabled"]["label"] == "关闭沙箱并启用受限 ROOT"
    assert root_fields["confirmation_1"]["label"].startswith("第一次确认")
    assert root_fields["confirmation_2"]["label"].startswith("第二次确认")
    assert root_fields["confirmation_3"]["label"].startswith("第三次确认")
    assert root_fields["final_confirmation"]["label"] == "最终确认：把 0 改成 1"
    assert root_fields["enabled"]["ui_type"] == "switch"
    assert root_fields["final_confirmation"]["ui_type"] == "number"
    assert unrestricted_fields["enabled"]["label"] == "申请解锁完全 ROOT"
    for index in range(1, 9):
        assert unrestricted_fields[f"confirmation_{index}"]["ui_type"] == "switch"
    assert unrestricted_fields["confirmation_9"]["ui_type"] == "number"
    assert unrestricted_fields["confirmation_10"]["ui_type"] == "switch"


def test_root_mode_requires_root_and_every_confirmation(monkeypatch) -> None:
    plugin = create_plugin()
    plugin.set_plugin_config(
        {
            "plugin": {"config_version": "1.0.12"},
            "root_mode": {
                "enabled": True,
                "confirmation_1": True,
                "confirmation_2": True,
                "confirmation_3": True,
                "final_confirmation": 1,
            }
        }
    )
    monkeypatch.setattr("plugin.os.geteuid", lambda: 0)
    active, reason = plugin._root_mode_state()
    assert active is True
    assert "全部条件" in reason

    plugin.config.root_mode.confirmation_2 = False
    active, reason = plugin._root_mode_state()
    assert active is False
    assert "第二次确认未开启" in reason

    plugin.config.root_mode.confirmation_2 = True
    monkeypatch.setattr("plugin.os.geteuid", lambda: 1000)
    active, reason = plugin._root_mode_state()
    assert active is False
    assert "不是由 root 用户运行" in reason


def _complete_unrestricted_root_config() -> dict[str, object]:
    return {
        "enabled": True,
        "confirmation_1": True,
        "confirmation_2": True,
        "confirmation_3": True,
        "confirmation_4": True,
        "confirmation_5": True,
        "confirmation_6": False,
        "confirmation_7": True,
        "confirmation_8": False,
        "confirmation_9": 0,
        "confirmation_10": False,
    }


def test_unrestricted_root_requires_restricted_root_and_all_ten_confirmations(
    monkeypatch,
) -> None:
    plugin = create_plugin()
    plugin.set_plugin_config(
        {
            "plugin": {"config_version": "1.0.12"},
            "root_mode": {
                "enabled": True,
                "confirmation_1": True,
                "confirmation_2": True,
                "confirmation_3": True,
                "final_confirmation": 1,
            },
            "unrestricted_root": _complete_unrestricted_root_config(),
        }
    )
    monkeypatch.setattr("plugin.os.geteuid", lambda: 0)

    restricted_active, _ = plugin._root_mode_state()
    active, reason = plugin._unrestricted_root_state(restricted_active)
    assert restricted_active is True
    assert active is True
    assert "十项认证全部匹配" in reason

    plugin.config.unrestricted_root.confirmation_6 = True
    active, reason = plugin._unrestricted_root_state(restricted_active)
    assert active is False
    assert "认证 6 未关闭" in reason

    plugin.config.unrestricted_root.confirmation_6 = False
    plugin.config.unrestricted_root.confirmation_9 = 1
    active, reason = plugin._unrestricted_root_state(restricted_active)
    assert active is False
    assert "认证 9 未从 1 改为 0" in reason

    plugin.config.unrestricted_root.confirmation_9 = 0
    plugin.config.root_mode.enabled = False
    restricted_active, _ = plugin._root_mode_state()
    active, reason = plugin._unrestricted_root_state(restricted_active)
    assert active is False
    assert "受限 ROOT 尚未生效" in reason


@pytest.mark.parametrize(
    ("field", "wrong_value", "expected_reason"),
    [
        ("confirmation_1", False, "认证 1 未开启"),
        ("confirmation_2", False, "认证 2 未开启"),
        ("confirmation_3", False, "认证 3 未开启"),
        ("confirmation_4", False, "认证 4 未开启"),
        ("confirmation_5", False, "认证 5 未开启"),
        ("confirmation_6", True, "认证 6 未关闭"),
        ("confirmation_7", False, "认证 7 未开启"),
        ("confirmation_8", True, "认证 8 未关闭"),
        ("confirmation_9", 1, "认证 9 未从 1 改为 0"),
        ("confirmation_10", True, "认证 10 未从 true 改为 false"),
    ],
)
def test_each_unrestricted_root_confirmation_is_required(
    monkeypatch,
    field: str,
    wrong_value: object,
    expected_reason: str,
) -> None:
    plugin = create_plugin()
    unrestricted = _complete_unrestricted_root_config()
    unrestricted[field] = wrong_value
    plugin.set_plugin_config(
        {
            "plugin": {"config_version": "1.0.12"},
            "root_mode": {
                "enabled": True,
                "confirmation_1": True,
                "confirmation_2": True,
                "confirmation_3": True,
                "final_confirmation": 1,
            },
            "unrestricted_root": unrestricted,
        }
    )
    monkeypatch.setattr("plugin.os.geteuid", lambda: 0)
    restricted_active, _ = plugin._root_mode_state()
    active, reason = plugin._unrestricted_root_state(restricted_active)
    assert active is False
    assert expected_reason in reason


def test_root_result_explicitly_warns_maimai_about_highest_privilege() -> None:
    result = CommandResult(
        command="pwd",
        exit_code=0,
        stdout="/root\n",
        stderr="",
        timed_out=False,
        output_truncated=False,
    )
    payload = ServerCommandPlugin._root_result(result)
    assert str(payload["content"]).startswith(ROOT_MODE_NOTICE)
    assert "你现在拥有服务器最高权限" in str(payload["content"])
    assert "坚决拒绝高风险" in str(payload["content"])
    assert "正则防护无法保证识别" in str(payload["content"])
    assert payload["execution_mode"] == "root_restricted"
    assert payload["command_regex_guard"] == "enabled"
    assert payload["working_directory"] == "/root"
    assert payload["process_limit"] == "not_enforced_for_uid_0"
    assert payload["descendant_cleanup"] == "on_command_exit_or_timeout"


def test_unrestricted_root_result_explicitly_reports_disabled_regex_guard() -> None:
    result = CommandResult(
        command="pwd",
        exit_code=0,
        stdout="/root\n",
        stderr="",
        timed_out=False,
        output_truncated=False,
    )
    payload = ServerCommandPlugin._unrestricted_root_result(result)
    assert str(payload["content"]).startswith(UNRESTRICTED_ROOT_NOTICE)
    assert "插件不会运行高风险命令正则拦截" in str(payload["content"])
    assert payload["execution_mode"] == "root_unrestricted"
    assert payload["command_regex_guard"] == "disabled"
    assert payload["working_directory"] == "/root"
    assert payload["process_limit"] == "not_enforced_for_uid_0"
    assert payload["descendant_cleanup"] == "on_command_exit_or_timeout"


def test_unrestricted_handler_does_not_call_high_risk_regex_guard(monkeypatch) -> None:
    plugin = create_plugin()
    plugin.set_plugin_config(
        {
            "plugin": {"config_version": "1.0.12"},
            "root_mode": {
                "enabled": True,
                "confirmation_1": True,
                "confirmation_2": True,
                "confirmation_3": True,
                "final_confirmation": 1,
            },
            "unrestricted_root": _complete_unrestricted_root_config(),
        }
    )
    plugin._set_context(SimpleNamespace(logger=Mock()))
    monkeypatch.setattr("plugin.os.geteuid", lambda: 0)

    def guard_must_not_run(command: str) -> str | None:
        raise AssertionError(f"完全 ROOT 不应调用正则拦截：{command}")

    async def fake_run(command, limits, requested_timeout=None):
        del limits, requested_timeout
        return CommandResult(
            command=command,
            exit_code=0,
            stdout="ok\n",
            stderr="",
            timed_out=False,
            output_truncated=False,
        )

    monkeypatch.setattr("plugin.high_risk_command_reason", guard_must_not_run)
    monkeypatch.setattr("plugin.run_unrestricted_root_command", fake_run)
    payload = asyncio.run(
        plugin.handle_run_server_command("rm -rf /root/example", timeout_seconds=5)
    )
    assert payload["success"] is True
    assert payload["execution_mode"] == "root_unrestricted"
    assert payload["command_regex_guard"] == "disabled"


def test_runner_style_file_loading_finds_sibling_executor(tmp_path: Path) -> None:
    plugin_path = Path(__file__).resolve().parents[1] / "plugin.py"
    script = (
        "import importlib.util\n"
        f"path = {str(plugin_path)!r}\n"
        "spec = importlib.util.spec_from_file_location('maibot_runner_plugin', path)\n"
        "assert spec is not None and spec.loader is not None\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        "plugin = module.create_plugin()\n"
        "assert plugin.__class__.__name__ == 'ServerCommandPlugin'\n"
        "plugin.set_plugin_config({})\n"
        "assert plugin.config.plugin.config_version == '1.0.12'\n"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_readme_states_ubuntu_only_testing() -> None:
    readme_path = Path(__file__).resolve().parents[1] / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    assert "仅在 Ubuntu 上测试过" in readme
    assert "sudo apt update" in readme
    assert "sudo apt install bubblewrap" in readme
    assert "完全 ROOT" in readme
    assert "十项认证" in readme

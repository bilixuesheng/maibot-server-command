from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

from executor import CommandResult
from plugin import ROOT_MODE_NOTICE, ServerCommandPlugin, create_plugin


def test_factory_and_tool_declaration() -> None:
    plugin = create_plugin()
    assert isinstance(plugin, ServerCommandPlugin)
    components = plugin.get_components()
    tools = [item for item in components if item["name"] == "run_server_command"]
    assert len(tools) == 1


def test_default_configuration_is_enabled_and_bounded() -> None:
    config = ServerCommandPlugin.build_default_config()
    assert config["plugin"]["config_version"] == "1.0.10"
    assert config["sandbox"]["enabled"] is True
    assert config["sandbox"]["network_enabled"] is False
    assert config["sandbox"]["timeout_seconds"] == 20
    assert config["root_mode"]["enabled"] is False
    assert config["root_mode"]["confirmation_1"] is False
    assert config["root_mode"]["confirmation_2"] is False
    assert config["root_mode"]["confirmation_3"] is False
    assert config["root_mode"]["final_confirmation"] == 0


def test_sdk_can_normalize_and_inject_default_configuration() -> None:
    plugin = create_plugin()
    plugin.set_plugin_config({})
    assert plugin.config.plugin.config_version == "1.0.10"
    assert plugin.config.sandbox.enabled is True


def test_packaged_configuration_is_sdk_valid() -> None:
    config_path = Path(__file__).resolve().parents[1] / "config.toml"
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    plugin = create_plugin()
    plugin.set_plugin_config(config)
    assert plugin.config.plugin.config_version == "1.0.10"
    assert plugin.config.sandbox.network_enabled is True
    assert plugin.config.root_mode.enabled is False
    config_text = config_path.read_text(encoding="utf-8")
    assert "# 是否允许麦麦自主调用命令工具。" in config_text
    assert "# 是否允许低权限沙箱命令访问公网、内网和本机网络服务。" in config_text
    assert "# 最终确认：必须手动把 0 改成 1。" in config_text


def test_manifest_is_v2_and_matches_plugin_version() -> None:
    manifest_path = Path(__file__).resolve().parents[1] / "_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == 2
    assert manifest["id"] == "xuesheng.maibot-server-command"
    assert manifest["version"] == "1.0.10"
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
        plugin_version="1.0.10",
    )
    assert schema["sections"]["plugin"]["title"] == "插件信息"
    assert schema["sections"]["sandbox"]["title"] == "命令沙箱"
    assert schema["sections"]["root_mode"]["title"] == "ROOT 最高权限（极高风险）"

    plugin_fields = schema["sections"]["plugin"]["fields"]
    sandbox_fields = schema["sections"]["sandbox"]["fields"]
    root_fields = schema["sections"]["root_mode"]["fields"]
    assert plugin_fields["config_version"]["label"] == "配置版本"
    assert plugin_fields["config_version"]["disabled"] is True
    assert sandbox_fields["enabled"]["label"] == "启用命令工具"
    assert sandbox_fields["network_enabled"]["label"] == "允许命令联网"
    assert sandbox_fields["timeout_seconds"]["label"] == "命令超时时间（秒）"
    assert sandbox_fields["max_output_bytes"]["label"] == "最大输出大小（字节）"
    assert sandbox_fields["memory_limit_mb"]["label"] == "内存上限（MB）"
    assert sandbox_fields["file_size_limit_mb"]["label"] == "单文件大小上限（MB）"
    assert sandbox_fields["max_processes"]["label"] == "最大进程数"
    assert sandbox_fields["network_enabled"]["ui_type"] == "switch"
    assert sandbox_fields["timeout_seconds"]["ui_type"] == "number"
    assert sandbox_fields["network_enabled"]["hint"]
    assert root_fields["enabled"]["label"] == "关闭沙箱并启用 ROOT 最高权限"
    assert root_fields["confirmation_1"]["label"].startswith("第一次确认")
    assert root_fields["confirmation_2"]["label"].startswith("第二次确认")
    assert root_fields["confirmation_3"]["label"].startswith("第三次确认")
    assert root_fields["final_confirmation"]["label"] == "最终确认：把 0 改成 1"
    assert root_fields["enabled"]["ui_type"] == "switch"
    assert root_fields["final_confirmation"]["ui_type"] == "number"


def test_root_mode_requires_root_and_every_confirmation(monkeypatch) -> None:
    plugin = create_plugin()
    plugin.set_plugin_config(
        {
            "plugin": {"config_version": "1.0.10"},
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
    assert payload["execution_mode"] == "root"
    assert payload["working_directory"] == "/root"


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
        "assert plugin.config.plugin.config_version == '1.0.10'\n"
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

"""Temporary release-gate tests for v1.0.15; never include in the release ZIP."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


file_upload = load_module("release_gate_file_upload", ROOT / "file_upload.py")
executor = load_module("release_gate_executor", ROOT / "executor.py")
temp_cleanup = load_module("release_gate_temp_cleanup", ROOT / "temp_cleanup.py")
plugin_module = load_module("release_gate_plugin", ROOT / "plugin.py")


def expect_upload_error(callable_object: Any, contains: str | None = None) -> str:
    try:
        callable_object()
    except file_upload.FileUploadError as exc:
        if contains is not None:
            assert contains in str(exc), (contains, str(exc))
        return str(exc)
    raise AssertionError("expected FileUploadError")


class QuietLogger:
    def __getattr__(self, _name: str) -> Any:
        return lambda *_args, **_kwargs: None


class ChatStub:
    def __init__(self, streams: list[dict[str, object]]) -> None:
        self.streams = streams

    async def get_private_streams(self, platform: str = "qq") -> Any:
        assert platform == "qq"
        return self.streams

    async def get_group_streams(self, platform: str = "qq") -> Any:
        assert platform == "qq"
        return []

    async def get_all_streams(self, platform: str = "qq") -> Any:
        assert platform == "qq"
        return self.streams


class SendStub:
    def __init__(self, result: object = True) -> None:
        self.result = result
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def custom(self, *args: object, **kwargs: object) -> object:
        self.calls.append((args, kwargs))
        return self.result


class ContextStub:
    def __init__(
        self,
        streams: list[dict[str, object]],
        send_result: object = True,
    ) -> None:
        self.chat = ChatStub(streams)
        self.send = SendStub(send_result)
        self.logger = QuietLogger()


def configure_plugin(plugin: Any, updates: dict[str, dict[str, object]]) -> None:
    config = plugin.build_default_config()
    for section_name, values in updates.items():
        section = config.setdefault(section_name, {})
        assert isinstance(section, dict)
        section.update(values)
    plugin.set_plugin_config(config)


def test_manifest_and_components() -> None:
    manifest = json.loads((ROOT / "_manifest.json").read_text())
    assert manifest["version"] == "1.0.15"
    assert manifest["host_application"]["min_version"] == "1.1.0"
    assert manifest["sdk"]["min_version"] == "2.3.0"

    plugin = plugin_module.ServerCommandPlugin()
    old_config = plugin.build_default_config()
    old_config["unrestricted_root"]["confirmation_10"] = False
    plugin.set_plugin_config(old_config)
    assert plugin.config.unrestricted_root.confirmation_10 == "false"

    fresh_config = plugin.build_default_config()["unrestricted_root"]
    for index in range(1, 9):
        assert fresh_config[f"confirmation_{index}"] is False
    assert fresh_config["confirmation_9"] == 1
    assert fresh_config["confirmation_10"] == "true"

    unrestricted_schema = plugin_module.UnrestrictedRootConfig.model_json_schema()
    properties = unrestricted_schema["properties"]
    for index in range(1, 9):
        field = properties[f"confirmation_{index}"]
        assert field["default"] is False
        assert field.get("x-widget") == "switch"
        assert "：开启" not in field["label"]
        assert "：关闭" not in field["label"]
    assert properties["confirmation_9"].get("x-widget") == "number"
    assert properties["confirmation_10"].get("x-widget") == "text"

    components = {item["name"]: item for item in plugin.get_components()}
    for action_name, expected_timeout in (
        ("run_trusted_private_server_command", 330_000),
        ("send_trusted_private_server_file", 1_800_000),
    ):
        component = components[action_name]
        assert component["type"] == "TOOL"
        assert component["chat_scope"] == "private"
        assert component["timeout_ms"] == expected_timeout
        assert component["metadata"]["invoke_method"] == "plugin.invoke_action"
        parameters = component["metadata"]["parameters_raw"]["properties"]
        assert "stream_id" not in parameters
    assert components["run_server_command"]["timeout_ms"] == 330_000
    assert components["send_server_file_to_qq"]["timeout_ms"] == 1_800_000


def test_scanner_and_staging() -> None:
    assert file_upload.sensitive_content_reason((ROOT / "file_upload.py").read_bytes()) is None
    self_archive_data = io.BytesIO()
    with zipfile.ZipFile(self_archive_data, "w", zipfile.ZIP_DEFLATED) as archive:
        for release_path in (
            ".gitignore",
            "LICENSE",
            "README.md",
            "_manifest.json",
            "assets/icon.png",
            "executor.py",
            "file_upload.py",
            "plugin.py",
            "requirements.txt",
            "temp_cleanup.py",
        ):
            archive.write(ROOT / release_path, release_path)
    assert file_upload.sensitive_content_reason(self_archive_data.getvalue()) is None

    with tempfile.TemporaryDirectory(prefix="v1015-file-") as temp_directory:
        root = Path(temp_directory)
        sandbox = root / "work"
        sandbox.mkdir()
        staging_root = file_upload.ensure_local_staging_root(str(root / "shared"))

        key_path = root / "generated.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(key_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        key_bytes = key_path.read_bytes()
        assert "私钥" in (file_upload.sensitive_content_reason(key_bytes) or "")
        assert "Base64" in (
            file_upload.sensitive_content_reason(base64.b64encode(key_bytes)) or ""
        )

        ssh_key_path = root / "id_ed25519"
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(ssh_key_path),
            ],
            check=True,
        )
        assert "私钥" in (
            file_upload.sensitive_content_reason(ssh_key_path.read_bytes()) or ""
        )

        archive_data = io.BytesIO()
        with zipfile.ZipFile(archive_data, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("neutral.txt", key_bytes)
        assert "压缩包内" in (
            file_upload.sensitive_content_reason(archive_data.getvalue()) or ""
        )

        for safe_sample in (
            b"-----BEGIN PRIVATE KEY-----",
            b"-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----",
            b"-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----",
            b"pattern = rb'-----BEGIN PRIVATE KEY-----'",
            b"-----END PRIVATE KEY-----",
        ):
            assert file_upload.sensitive_content_reason(safe_sample) is None

        large_path = sandbox / "large.bin"
        large_path.write_bytes(b"x" * (11 * 1024 * 1024))
        prepared = file_upload.prepare_file_upload(
            "/work/large.bin",
            sandbox_root=sandbox,
            root_mode=False,
            configured_max_mb=8,
            transport="napcat_local",
            configured_local_max_mb=64,
            local_staging_root=staging_root,
            napcat_staging_root="/napcat/shared",
        )
        staged_path = staging_root / prepared.staging_name
        assert prepared.base64_url == f"file:///napcat/shared/{prepared.staging_name}"
        assert stat.S_IMODE(staged_path.stat().st_mode) == 0o444
        assert staged_path.read_bytes() == large_path.read_bytes()

        staged_path.chmod(0o644)
        assert (
            file_upload.verify_local_staging_file(
                staging_root,
                staging_name=prepared.staging_name,
                expected_identity=prepared.staging_identity,
            )
            == "staging_changed"
        )
        assert (
            file_upload.delete_local_staging_file(
                staging_root,
                staging_name=prepared.staging_name,
                expected_identity=prepared.staging_identity,
            )
            == "staging_changed"
        )
        staged_path.unlink()

        marker = staging_root / ".maibot-napcat-staging-v1"
        marker.unlink()
        expect_upload_error(
            lambda: file_upload.cleanup_stale_local_uploads(
                staging_root,
                retention_hours=1,
            )
        )
        assert not marker.exists()
        assert file_upload.find_existing_local_staging_root(str(staging_root)) is None
        staging_root = file_upload.ensure_local_staging_root(str(staging_root))

        secret_path = sandbox / "neutral.txt"
        secret_path.write_bytes(key_bytes)
        expect_upload_error(
            lambda: file_upload.prepare_file_upload(
                "/work/neutral.txt",
                sandbox_root=sandbox,
                root_mode=False,
                configured_max_mb=8,
            ),
            "私钥",
        )
        trusted = file_upload.prepare_file_upload(
            "/work/neutral.txt",
            sandbox_root=sandbox,
            root_mode=False,
            configured_max_mb=8,
            sensitive_guard_enabled=False,
            transport="napcat_local",
            configured_local_max_mb=64,
            local_staging_root=staging_root,
            napcat_staging_root="/napcat/shared",
        )
        assert (staging_root / trusted.staging_name).exists()

        old_name = "upload-" + "a" * 32
        old_path = staging_root / old_name
        old_path.write_bytes(b"old")
        old_path.chmod(0o444)
        original_time_ns = file_upload.time.time_ns
        try:
            file_upload.time.time_ns = (
                lambda: original_time_ns() + 2 * 60 * 60 * 1_000_000_000
            )
            report = file_upload.cleanup_stale_local_uploads(
                staging_root,
                retention_hours=1,
                active_names=(trusted.staging_name,),
            )
        finally:
            file_upload.time.time_ns = original_time_ns
        assert report.deleted_files == 1
        assert report.skipped_active == 1
        assert not old_path.exists()
        assert (staging_root / trusted.staging_name).exists()

        boundary_secret = base64.b64encode(key_bytes)
        boundary_offset = 4 * 1024 * 1024 - len(boundary_secret) // 2
        boundary_path = sandbox / "boundary.bin"
        boundary_path.write_bytes(
            b"x" * (boundary_offset - 1)
            + b"\n"
            + boundary_secret
            + b"\n"
            + b"y" * (11 * 1024 * 1024 - boundary_offset - len(boundary_secret) - 1)
        )
        expect_upload_error(
            lambda: file_upload.prepare_file_upload(
                "/work/boundary.bin",
                sandbox_root=sandbox,
                root_mode=False,
                configured_max_mb=8,
                transport="napcat_local",
                configured_local_max_mb=64,
                local_staging_root=staging_root,
                napcat_staging_root="/napcat/shared",
            ),
            "私钥",
        )


async def test_plugin_authorization_and_delivery() -> None:
    private_streams = [
        {
            "stream_id": "private-1",
            "platform": "qq",
            "chat_type": "private",
            "user_id": "12345678",
            "account_id": "87654321",
        }
    ]
    plugin = plugin_module.ServerCommandPlugin()
    plugin._set_context(ContextStub(private_streams))
    configure_plugin(
        plugin,
        {
            "trusted_private_bypass": {
                "enabled": True,
                "qq_user_ids": "12345678",
            }
        },
    )
    assert (await plugin._trusted_private_caller("private-1"))[0]

    plugin.ctx.chat.streams = [
        {
            "stream_id": "private-1",
            "platform": "qq",
            "chat_type": "group",
            "group_id": "55555",
            "user_id": "12345678",
        }
    ]
    assert not (await plugin._trusted_private_caller("private-1"))[0]
    plugin.ctx.chat.streams = [
        {
            "stream_id": "private-1",
            "platform": "qq",
            "chat_type": "private",
            "user_id": "12345678",
            "account_id": "1",
        },
        {
            "stream_id": "private-1",
            "platform": "qq",
            "chat_type": "private",
            "user_id": "12345678",
            "account_id": "2",
        },
    ]
    assert not (await plugin._trusted_private_caller("private-1"))[0]
    plugin.ctx.chat.streams = private_streams
    assert not (await plugin._trusted_private_caller("model-forged-stream"))[0]

    configure_plugin(
        plugin,
        {
            "sandbox": {"enabled": False},
            "trusted_private_bypass": {
                "enabled": True,
                "qq_user_ids": "12345678",
            },
        },
    )
    command_denial = await plugin.handle_run_trusted_private_server_command(
        stream_id="private-1",
        command="printf ok",
    )
    assert not command_denial["success"]
    assert "总开关" in command_denial["content"]

    configure_plugin(
        plugin,
        {
            "file_upload": {"enabled": False},
            "trusted_private_bypass": {
                "enabled": True,
                "qq_user_ids": "12345678",
            },
        },
    )
    file_denial = await plugin.handle_send_trusted_private_server_file(
        stream_id="private-1",
        file_path="/tmp/does-not-matter",
    )
    assert not file_denial["success"]
    assert "总开关" in file_denial["content"]

    with tempfile.TemporaryDirectory(prefix="v1015-plugin-") as temp_directory:
        root = Path(temp_directory)
        staging_root = root / "shared"
        source_path = root / "ordinary.txt"
        source_path.write_text("ordinary")
        configure_plugin(
            plugin,
            {
                "file_upload": {
                    "enabled": True,
                    "use_napcat_local_path": True,
                    "local_path_max_upload_mb": 64,
                    "maibot_staging_directory": str(staging_root),
                    "napcat_staging_directory": "/napcat/shared",
                },
                "temp_cleanup": {"enabled": False},
                "trusted_private_bypass": {
                    "enabled": True,
                    "qq_user_ids": "12345678",
                },
            },
        )
        delivered = await plugin.handle_send_trusted_private_server_file(
            stream_id="private-1",
            file_path=str(source_path),
        )
        assert delivered["success"]
        assert delivered["trusted_private_bypass"]
        assert delivered["staging_cleanup"] == "staging_deleted"
        assert not list(staging_root.glob("upload-*"))
        sent_url = plugin.ctx.send.calls[-1][0][1]["url"]
        assert str(sent_url).startswith("file:///napcat/shared/upload-")

        plugin.ctx.send.result = False
        uncertain = await plugin.handle_send_trusted_private_server_file(
            stream_id="private-1",
            file_path=str(source_path),
        )
        assert not uncertain["success"]
        assert uncertain["retry_safe"] is False
        assert uncertain["staging_cleanup"] == "staging_retained_send_unconfirmed"
        assert len(list(staging_root.glob("upload-*"))) == 1

        plugin.ctx.send.result = True
        prepared = await plugin._prepare_qq_upload(
            str(source_path),
            root_mode=True,
            upload_name=None,
            sensitive_guard_enabled=False,
        )
        staged_path = Path(prepared.staging_root) / prepared.staging_name
        staged_path.chmod(0o644)
        previous_call_count = len(plugin.ctx.send.calls)
        sent, status, error_type = await plugin._send_prepared_file(
            prepared,
            "private-1",
        )
        assert not sent
        assert status == "staging_changed"
        assert error_type == "StagingVerificationFailed"
        assert len(plugin.ctx.send.calls) == previous_call_count
        assert staged_path.exists()
        assert (
            str(prepared.staging_root),
            prepared.staging_name,
        ) not in plugin._active_staging_uploads

        cancelled_prepared = await plugin._prepare_qq_upload(
            str(source_path),
            root_mode=True,
            upload_name=None,
            sensitive_guard_enabled=False,
        )
        original_verify = plugin_module.verify_local_staging_file

        def cancel_during_verification(*_args: object, **_kwargs: object) -> str:
            raise asyncio.CancelledError

        plugin_module.verify_local_staging_file = cancel_during_verification
        try:
            try:
                await plugin._send_prepared_file(
                    cancelled_prepared,
                    "private-1",
                )
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("delivery cancellation was not propagated")
        finally:
            plugin_module.verify_local_staging_file = original_verify
        assert (
            str(cancelled_prepared.staging_root),
            cancelled_prepared.staging_name,
        ) not in plugin._active_staging_uploads
        assert (
            Path(cancelled_prepared.staging_root)
            / cancelled_prepared.staging_name
        ).exists()

        sandbox = root / "work"
        sandbox.mkdir()
        (sandbox / "large.bin").write_bytes(b"x" * (11 * 1024 * 1024))
        plugin._sandbox_path = sandbox
        plugin._sandbox_prepared_for_low_privilege = True
        normal = await plugin.handle_send_server_file_to_qq(
            "/work/large.bin",
            "current",
            stream_id="private-1",
        )
        assert normal["success"]
        assert normal["upload_transport"] == "napcat_local"
        assert normal["sensitive_file_guard"] == "enabled"


async def test_real_bubblewrap_and_root_execution() -> None:
    if os.geteuid() != 0:
        raise AssertionError("real integration test must run as root")
    limits = executor.SandboxLimits(
        timeout_seconds=15,
        max_output_bytes=65_536,
        memory_limit_mb=256,
        file_size_limit_mb=64,
        max_processes=32,
    )
    with tempfile.TemporaryDirectory(prefix="v1015-bwrap-") as temp_directory:
        maibot_root = Path(temp_directory)
        identity = executor.resolve_execution_identity()
        assert identity.drop_from_root
        sandbox = executor.prepare_sandbox(maibot_root, identity)
        task = temp_cleanup.create_managed_temp_task(
            sandbox,
            command_uid=identity.uid,
            command_gid=identity.gid,
        )
        first = await executor.run_command(
            'printf first > "$MAIBOT_TEMP_DIR/step.txt"; id -u; pwd',
            sandbox,
            limits,
            managed_temp_directory=task.sandbox_path,
        )
        assert first.exit_code == 0 and not first.timed_out, first
        assert str(identity.uid) in first.stdout
        assert "/work" in first.stdout
        second = await executor.run_command(
            'test "$(cat "$MAIBOT_TEMP_DIR/step.txt")" = first; printf second',
            sandbox,
            limits,
            managed_temp_directory=task.sandbox_path,
        )
        assert second.exit_code == 0 and second.stdout == "second", second

        root_task = temp_cleanup.create_managed_temp_task(
            sandbox,
            command_uid=0,
            command_gid=0,
        )
        root_result = await executor.run_unrestricted_root_command(
            'test "$MAIBOT_TEMP_DIR" != ""; printf root > "$MAIBOT_TEMP_DIR/root.txt"',
            limits,
            managed_temp_directory=str(root_task.host_path),
        )
        assert root_result.exit_code == 0, root_result
        assert (root_task.host_path / "root.txt").read_text() == "root"


async def main() -> None:
    test_manifest_and_components()
    test_scanner_and_staging()
    await test_plugin_authorization_and_delivery()
    await test_real_bubblewrap_and_root_execution()
    print("v1.0.15 release-gate validation: PASS")


if __name__ == "__main__":
    asyncio.run(main())

# Updating this temporary gate file intentionally triggers the isolated branch workflow.

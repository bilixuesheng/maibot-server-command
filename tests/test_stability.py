from __future__ import annotations

import asyncio
import base64
import gzip
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import executor
import file_upload
import plugin as plugin_module
import temp_cleanup


ROOT = Path(__file__).resolve().parents[1]


def patched_zip_flags(data: bytes, mask: int) -> bytes:
    """Set general-purpose flags in every local and central ZIP header."""

    patched = bytearray(data)
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        cursor = 0
        while True:
            cursor = patched.find(signature, cursor)
            if cursor < 0:
                break
            field_start = cursor + offset
            flags = int.from_bytes(
                patched[field_start : field_start + 2],
                "little",
            )
            patched[field_start : field_start + 2] = (
                flags | mask
            ).to_bytes(2, "little")
            cursor += len(signature)
    return bytes(patched)


def patched_zip_method(data: bytes, method: int) -> bytes:
    """Replace compression methods in every local and central ZIP header."""

    patched = bytearray(data)
    for signature, offset in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        cursor = 0
        while True:
            cursor = patched.find(signature, cursor)
            if cursor < 0:
                break
            field_start = cursor + offset
            patched[field_start : field_start + 2] = int(method).to_bytes(
                2,
                "little",
            )
            cursor += len(signature)
    return bytes(patched)


def patched_zip_declared_size(data: bytes, size: int) -> bytes:
    """Replace 32-bit uncompressed-size declarations in test ZIP headers."""

    patched = bytearray(data)
    for signature, offset in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        cursor = 0
        while True:
            cursor = patched.find(signature, cursor)
            if cursor < 0:
                break
            field_start = cursor + offset
            patched[field_start : field_start + 4] = int(size).to_bytes(
                4,
                "little",
            )
            cursor += len(signature)
    return bytes(patched)


def corrupt_first_stored_zip_byte(data: bytes) -> bytes:
    """Flip one stored member byte while leaving its recorded CRC untouched."""

    patched = bytearray(data)
    local = patched.find(b"PK\x03\x04")
    if local < 0:
        raise AssertionError("测试 ZIP 缺少本地文件头")
    name_size = int.from_bytes(patched[local + 26 : local + 28], "little")
    extra_size = int.from_bytes(patched[local + 28 : local + 30], "little")
    payload = local + 30 + name_size + extra_size
    patched[payload] ^= 0x01
    return bytes(patched)


class QuietLogger:
    def __getattr__(self, _name: str):
        return lambda *_args, **_kwargs: None


class ChatStub:
    def __init__(self, streams: list[dict[str, object]]) -> None:
        self.streams = streams

    async def get_private_streams(self, platform: str = "qq"):
        if platform != "qq":
            raise AssertionError(platform)
        return self.streams

    async def get_group_streams(self, platform: str = "qq"):
        if platform != "qq":
            raise AssertionError(platform)
        return self.streams

    async def get_all_streams(self, platform: str = "qq"):
        if platform != "qq":
            raise AssertionError(platform)
        return self.streams


class ContextStub:
    def __init__(
        self,
        streams: list[dict[str, object]],
        send_result: object = True,
    ) -> None:
        self.chat = ChatStub(streams)
        self.logger = QuietLogger()
        self.send = SendStub(send_result)


class SendStub:
    def __init__(self, result: object = True) -> None:
        self.result = result
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def custom(self, *args: object, **kwargs: object) -> object:
        self.calls.append((args, kwargs))
        return self.result


class FakeProcess:
    def __init__(self) -> None:
        self.pid = 424_242
        self.returncode: int | None = None
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.started = asyncio.Event()
        self._done = asyncio.Event()

    async def wait(self) -> int:
        self.started.set()
        await self._done.wait()
        return int(self.returncode or 0)

    def stop(self, returncode: int = -signal.SIGKILL) -> None:
        if self.returncode is not None:
            return
        self.returncode = returncode
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._done.set()

    def terminate(self) -> None:
        self.stop(-signal.SIGTERM)

    def kill(self) -> None:
        self.stop()


def configure_plugin(
    plugin: plugin_module.ServerCommandPlugin,
    updates: dict[str, dict[str, object]],
) -> None:
    config = plugin.build_default_config()
    for section_name, values in updates.items():
        section = config.setdefault(section_name, {})
        if not isinstance(section, dict):
            raise AssertionError(section_name)
        section.update(values)
    plugin.set_plugin_config(config)


class DeclarationTests(unittest.TestCase):
    def test_manifest_and_component_contract(self) -> None:
        manifest = json.loads((ROOT / "_manifest.json").read_text(encoding="utf-8"))
        self.assertRegex(manifest["version"], re.compile(r"\A\d+\.\d+\.\d+\Z"))
        self.assertEqual(plugin_module.PLUGIN_VERSION, manifest["version"])
        self.assertEqual(
            plugin_module.PluginMetadataConfig().config_version,
            manifest["version"],
        )
        self.assertEqual(manifest["host_application"]["min_version"], "1.1.0")
        self.assertEqual(manifest["host_application"]["max_version"], "1.1.2")
        self.assertEqual(manifest["sdk"]["min_version"], "2.3.0")
        self.assertEqual(manifest["sdk"]["max_version"], "2.7.1")

        plugin = plugin_module.ServerCommandPlugin()
        components = {item["name"]: item for item in plugin.get_components()}
        component_text = json.dumps(components, ensure_ascii=False)
        self.assertNotIn("同一轮立即调用", component_text)
        self.assertNotIn("不得等待再次提醒", component_text)
        self.assertNotIn("白名单 QQ 本人在群聊触发", component_text)
        self.assertNotIn("可信群聊", component_text)
        self.assertIn("所有群聊始终执行普通扫描", component_text)
        self.assertEqual(components["run_server_command"]["timeout_ms"], 330_000)
        self.assertEqual(
            components["send_server_file_to_qq"]["timeout_ms"],
            1_800_000,
        )
        self.assertEqual(
            components["send_server_file_to_qq"]["metadata"]["invoke_method"],
            "plugin.invoke_action",
        )
        for action_name in (
            "run_trusted_private_server_command",
            "send_trusted_private_server_file",
        ):
            component = components[action_name]
            self.assertEqual(component["type"], "TOOL")
            self.assertEqual(component["chat_scope"], "private")
            self.assertEqual(
                component["metadata"]["invoke_method"],
                "plugin.invoke_action",
            )
            parameters = component["metadata"]["parameters_raw"]["properties"]
            self.assertNotIn("stream_id", parameters)

    def test_sibling_module_cache_names_are_content_addressed(self) -> None:
        names = (
            plugin_module._executor.__name__,
            plugin_module._file_upload.__name__,
            plugin_module._temp_cleanup.__name__,
        )
        for name in names:
            self.assertRegex(name, re.compile(r"_[0-9a-f]{16}\Z"))

    def test_sibling_content_change_gets_a_fresh_module(self) -> None:
        with tempfile.TemporaryDirectory(prefix="maibot-reload-") as directory:
            copy_root = Path(directory)
            for name in (
                "_manifest.json",
                "executor.py",
                "file_upload.py",
                "plugin.py",
                "temp_cleanup.py",
            ):
                shutil.copy2(ROOT / name, copy_root / name)

            def load_copy(name: str):
                path = copy_root / "plugin.py"
                spec = importlib.util.spec_from_file_location(name, path)
                if spec is None or spec.loader is None:
                    raise AssertionError("无法构造测试模块")
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                try:
                    spec.loader.exec_module(module)
                finally:
                    sys.modules.pop(name, None)
                return module

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                first = load_copy("stability_reload_first")
                executor_copy = copy_root / "executor.py"
                executor_copy.write_text(
                    executor_copy.read_text(encoding="utf-8") + "\n",
                    encoding="utf-8",
                )
                second = load_copy("stability_reload_second")

        self.assertNotEqual(first._executor.__name__, second._executor.__name__)
        for module in (
            first._executor,
            first._file_upload,
            first._temp_cleanup,
            second._executor,
            second._file_upload,
            second._temp_cleanup,
        ):
            sys.modules.pop(module.__name__, None)

    def test_unrestricted_root_requires_the_exact_confirmation_pattern(self) -> None:
        plugin = plugin_module.ServerCommandPlugin()
        config = plugin.build_default_config()
        config["root_mode"].update(
            {
                "enabled": True,
                "confirmation_1": True,
                "confirmation_2": True,
                "confirmation_3": True,
                "confirmation_4": True,
                "final_confirmation": 1,
            }
        )
        config["unrestricted_root"].update(
            {
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
                "confirmation_10": "false",
            }
        )
        plugin.set_plugin_config(config)

        with patch.object(plugin_module.os, "geteuid", return_value=0):
            restricted_active, _ = plugin._root_mode_state()
            self.assertTrue(restricted_active)
            self.assertTrue(
                plugin._unrestricted_root_state(restricted_active)[0]
            )
            plugin.config.unrestricted_root.confirmation_8 = True
            self.assertFalse(
                plugin._unrestricted_root_state(restricted_active)[0]
            )


class FileUploadTests(unittest.TestCase):
    def test_private_key_and_base64_wrapper_are_blocked(self) -> None:
        encoded_body = base64.b64encode(b"\x30" * 64)
        private_key = (
            b"-----BEGIN PRIVATE KEY-----\n"
            + encoded_body
            + b"\n-----END PRIVATE KEY-----\n"
        )
        self.assertIn(
            "私钥",
            file_upload.sensitive_content_reason(private_key) or "",
        )
        self.assertIn(
            "Base64",
            file_upload.sensitive_content_reason(
                base64.b64encode(private_key)
            )
            or "",
        )
        self.assertIsNone(
            file_upload.sensitive_content_reason(
                b"-----BEGIN PRIVATE KEY-----\nnot-a-key"
            )
        )

    def test_binary_symbols_are_not_credentials_but_real_headers_still_are(self) -> None:
        false_positive_samples = (
            b"QNetworkCookie::SameSite\x00QNetworkCookie::RawForm",
            b"Proxy-Authorization: Basic %s\r\n",
            b"PublicKeyToken=b77a5c561934e089",
            b"QSslSocket::setPrivateKey: Couldn't open file",
            b", password = \x00Access manager destroyed",
            b"unexpected token: '%.*s'\x00",
            b'token = os.getenv("TOKEN")',
            b"password = None",
            b'{"token": "<your-token>"}',
            b"client_secret = process.env.CLIENT_SECRET",
            b"api_key = ${API_KEY}",
            b'password = input("Password: ")',
            b"token=changeme",
            b"postgres://user:password@example.invalid/db",
        )
        for sample in false_positive_samples:
            with self.subTest(sample=sample):
                self.assertIsNone(
                    file_upload._direct_sensitive_content_reason(sample)
                )

        sensitive_samples = (
            b"Authorization: Bearer actual-secret-token-value",
            b"Authorization: Basic dXNlcjpwYXNz",
            b"Cookie: session_id=actual-secret-value; Secure",
            b'{"password": "actual-secret-value"}',
            b"token=actual-secret-value",
        )
        for sample in sensitive_samples:
            with self.subTest(sample=sample):
                self.assertIsNotNone(
                    file_upload._direct_sensitive_content_reason(sample)
                )

    def test_opaque_or_encrypted_content_is_not_sensitive_by_itself(self) -> None:
        ordinary_payloads = (
            gzip.compress(b"ordinary application payload"),
            b"age-encryption.org/v1\nordinary encrypted payload",
            b"Salted__" + b"\x01" * 64,
        )
        for payload in ordinary_payloads:
            with self.subTest(prefix=payload[:16]):
                self.assertIsNone(
                    file_upload.sensitive_content_reason(payload)
                )
                self.assertIsNone(
                    file_upload.sensitive_content_reason(
                        base64.b64encode(payload)
                    )
                )

    def test_encrypted_zip_member_is_allowed_unless_its_path_is_high_risk(
        self,
    ) -> None:
        ordinary_buffer = io.BytesIO()
        with zipfile.ZipFile(ordinary_buffer, "w") as archive:
            archive.writestr("payload.bin", b"ordinary encrypted payload")
        ordinary_buffer.seek(0)
        ordinary = patched_zip_flags(ordinary_buffer.read(), 0x1)
        self.assertIsNone(file_upload.sensitive_content_reason(ordinary))
        encrypted_large_declaration = patched_zip_declared_size(
            ordinary,
            64 * 1024 * 1024,
        )
        self.assertIsNone(
            file_upload.sensitive_content_reason(
                encrypted_large_declaration
            )
        )

        risky_buffer = io.BytesIO()
        with zipfile.ZipFile(risky_buffer, "w") as archive:
            archive.writestr(".ssh/id_rsa", b"encrypted payload")
        risky_buffer.seek(0)
        risky = patched_zip_flags(risky_buffer.read(), 0x1)
        self.assertIn(
            "敏感路径",
            file_upload.sensitive_content_reason(risky) or "",
        )

    def test_normal_archive_metadata_does_not_create_false_positives(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "certifi/cacert.pem",
                (
                    b"-----BEGIN CERTIFICATE-----\n"
                    b"MIIBordinary-public-certificate\n"
                    b"-----END CERTIFICATE-----\n"
                ),
            )
            archive.writestr(
                "app/view/components/token_line_edit.pyc",
                b"\x00compiled user-interface component\x00",
            )
            archive.writestr(
                "assets/application.db",
                b"SQLite format 3\x00ordinary bundled application data",
            )
            archive.writestr(
                "lib/arm64-v8a/libsqlite3.so",
                b"\x7fELF\x00SQLite format 3\x00library symbol",
            )
        buffer.seek(0)
        self.assertIsNone(
            file_upload.sensitive_content_reason(buffer.read())
        )

    def test_nested_zip_still_scans_visible_sensitive_content(self) -> None:
        private_key = (
            b"-----BEGIN PRIVATE KEY-----\n"
            + base64.b64encode(b"\x30" * 64)
            + b"\n-----END PRIVATE KEY-----\n"
        )
        inner_buffer = io.BytesIO()
        with zipfile.ZipFile(
            inner_buffer,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            archive.writestr("ordinary.txt", private_key)
        inner_buffer.seek(0)

        outer_buffer = io.BytesIO()
        with zipfile.ZipFile(outer_buffer, "w") as archive:
            archive.writestr("nested.zip", inner_buffer.read())
        outer_buffer.seek(0)
        self.assertIn(
            "私钥",
            file_upload.sensitive_content_reason(outer_buffer.read()) or "",
        )
        inner_buffer.seek(0)
        self.assertIn(
            "私钥",
            file_upload.sensitive_content_reason(
                base64.b64encode(inner_buffer.read())
            )
            or "",
        )

    def test_archive_structure_checks_do_not_depend_on_filename_suffixes(
        self,
    ) -> None:
        for unsafe_name in (
            r"..\secret.txt",
            "C:\\secret.txt",
            "\\\\server\\share\\secret.txt",
            "..／secret.txt",
        ):
            with self.subTest(unsafe_name=unsafe_name):
                traversal_buffer = io.BytesIO()
                with zipfile.ZipFile(traversal_buffer, "w") as archive:
                    archive.writestr(unsafe_name, b"ordinary")
                traversal_buffer.seek(0)
                self.assertIn(
                    "不安全路径",
                    file_upload.sensitive_content_reason(
                        traversal_buffer.read()
                    )
                    or "",
                )

        symlink_buffer = io.BytesIO()
        with zipfile.ZipFile(symlink_buffer, "w") as archive:
            link = zipfile.ZipInfo("ordinary-link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "ordinary-target")
        symlink_buffer.seek(0)
        self.assertIn(
            "符号链接",
            file_upload.sensitive_content_reason(symlink_buffer.read()) or "",
        )

        special_buffer = io.BytesIO()
        with zipfile.ZipFile(special_buffer, "w") as archive:
            special = zipfile.ZipInfo("ordinary-pipe")
            special.create_system = 3
            special.external_attr = (stat.S_IFIFO | 0o600) << 16
            archive.writestr(special, b"")
        special_buffer.seek(0)
        self.assertIn(
            "特殊文件",
            file_upload.sensitive_content_reason(special_buffer.read()) or "",
        )

        stored_buffer = io.BytesIO()
        with zipfile.ZipFile(
            stored_buffer,
            "w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            archive.writestr("ordinary.txt", b"ordinary payload")
        stored_buffer.seek(0)
        corrupt = corrupt_first_stored_zip_byte(stored_buffer.read())
        self.assertIn(
            "无法安全读取",
            file_upload.sensitive_content_reason(corrupt) or "",
        )

    def test_format_edge_cases_are_scanned_without_magic_only_refusals(
        self,
    ) -> None:
        self.assertIsNone(
            file_upload.sensitive_content_reason(
                b"PK\x03\x04not actually a ZIP container"
            )
        )

        unknown_buffer = io.BytesIO()
        with zipfile.ZipFile(
            unknown_buffer,
            "w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            archive.writestr("ordinary.bin", b"ordinary")
        unknown_buffer.seek(0)
        unknown = patched_zip_method(unknown_buffer.read(), 99)
        self.assertIsNone(file_upload.sensitive_content_reason(unknown))

        zip64_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip64_buffer,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            with archive.open(
                "ordinary-zip64.bin",
                "w",
                force_zip64=True,
            ) as member:
                member.write(b"ordinary")
        zip64_buffer.seek(0)
        self.assertIsNone(
            file_upload.sensitive_content_reason(zip64_buffer.read())
        )

        class NonSeekableBuffer(io.BytesIO):
            def seekable(self) -> bool:
                return False

            def seek(self, *_args: object, **_kwargs: object) -> int:
                raise OSError("non-seekable test stream")

        descriptor_buffer = NonSeekableBuffer()
        with zipfile.ZipFile(
            descriptor_buffer,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            archive.writestr("ordinary-descriptor.bin", b"ordinary")
        descriptor_data = descriptor_buffer.getvalue()
        with zipfile.ZipFile(io.BytesIO(descriptor_data)) as archive:
            self.assertTrue(archive.infolist()[0].flag_bits & 0x08)
        self.assertIsNone(
            file_upload.sensitive_content_reason(descriptor_data)
        )

        duplicate_buffer = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate_buffer, "w") as archive:
                archive.writestr("same-name.txt", b"ordinary")
                archive.writestr(
                    "same-name.txt",
                    b"ghp_12345678901234567890",
                )
        duplicate_buffer.seek(0)
        self.assertIn(
            "访问令牌",
            file_upload.sensitive_content_reason(duplicate_buffer.read())
            or "",
        )

        comment_buffer = io.BytesIO()
        with zipfile.ZipFile(comment_buffer, "w") as archive:
            archive.writestr("ordinary.txt", b"ordinary")
            archive.comment = b"ghp_12345678901234567890"
        comment_buffer.seek(0)
        self.assertIn(
            "访问令牌",
            file_upload.sensitive_content_reason(comment_buffer.read()) or "",
        )

        with tempfile.TemporaryDirectory(prefix="maibot-zip-tail-") as directory:
            tailed_zip = Path(directory) / "tailed.zip"
            tailed_zip.write_bytes(
                unknown
                + b"\nghp_12345678901234567890\n"
            )
            fd = os.open(tailed_zip, os.O_RDONLY)
            try:
                self.assertIn(
                    "访问令牌",
                    file_upload.sensitive_file_content_reason(
                        fd,
                        tailed_zip.stat().st_size,
                    )
                    or "",
                )
            finally:
                os.close(fd)

    def test_real_apk_passes_full_visible_content_scan(self) -> None:
        apk = ROOT.parent / "Ghost-Downloader-v4.2.2-Android-arm64-v8a.apk"
        if not apk.is_file():
            self.skipTest("真实 APK 样本不在测试工作区")
        fd = os.open(apk, os.O_RDONLY)
        try:
            self.assertIsNone(
                file_upload.sensitive_file_content_reason(
                    fd,
                    apk.stat().st_size,
                    max_archive_scan_bytes=1024 * 1024 * 1024,
                )
            )
        finally:
            os.close(fd)

    def test_large_zip_uses_transport_budget_and_streams_sensitive_scan(self) -> None:
        ordinary_size = 33 * 1024 * 1024
        with tempfile.TemporaryDirectory(prefix="maibot-large-zip-") as directory:
            ordinary_zip = Path(directory) / "ordinary.zip"
            with zipfile.ZipFile(
                ordinary_zip,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.writestr("ordinary.bin", b"0" * ordinary_size)

            fd = os.open(ordinary_zip, os.O_RDONLY)
            try:
                self.assertIn(
                    "当前安全扫描预算",
                    file_upload.sensitive_file_content_reason(
                        fd,
                        ordinary_zip.stat().st_size,
                    )
                    or "",
                )
            finally:
                os.close(fd)

            staging_root = file_upload.ensure_local_staging_root(
                str(Path(directory) / "shared")
            )
            with patch.object(
                file_upload,
                "_resolved_fd_path",
                return_value=str(ordinary_zip),
            ):
                prepared = file_upload.prepare_file_upload(
                    str(ordinary_zip),
                    sandbox_root=None,
                    root_mode=True,
                    configured_max_mb=8,
                    transport="napcat_local",
                    configured_local_max_mb=64,
                    local_staging_root=staging_root,
                    napcat_staging_root="/napcat/shared",
                )
            self.assertEqual(prepared.source_scope, "root_all_files")
            self.assertEqual(prepared.transport, "napcat_local")
            self.assertEqual(
                file_upload.delete_local_staging_file(
                    staging_root,
                    staging_name=str(prepared.staging_name),
                    expected_identity=prepared.staging_identity,
                ),
                "staging_deleted",
            )

            sensitive_zip = Path(directory) / "sensitive.zip"
            with zipfile.ZipFile(
                sensitive_zip,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.writestr(
                    "ordinary.txt",
                    b"0" * ordinary_size + b"\npassword=not-for-upload\n",
                )

            fd = os.open(sensitive_zip, os.O_RDONLY)
            try:
                self.assertIn(
                    "敏感内容",
                    file_upload.sensitive_file_content_reason(
                        fd,
                        sensitive_zip.stat().st_size,
                        max_archive_scan_bytes=64 * 1024 * 1024,
                    )
                    or "",
                )
            finally:
                os.close(fd)

    def test_napcat_copy_is_read_only_verified_and_exactly_deleted(self) -> None:
        if not Path("/proc/self/fd").is_dir():
            self.skipTest("当前运行环境没有 /proc/self/fd")
        with tempfile.TemporaryDirectory(prefix="maibot-upload-") as directory:
            root = Path(directory)
            source = root / "ordinary.txt"
            source.write_text("ordinary", encoding="utf-8")
            staging_root = file_upload.ensure_local_staging_root(
                str(root / "shared")
            )
            prepared = file_upload.prepare_file_upload(
                str(source),
                sandbox_root=None,
                root_mode=True,
                configured_max_mb=8,
                transport="napcat_local",
                configured_local_max_mb=64,
                local_staging_root=staging_root,
                napcat_staging_root="/napcat/shared",
            )

            self.assertEqual(prepared.transport, "napcat_local")
            self.assertTrue(
                prepared.base64_url.startswith("file:///napcat/shared/upload-")
            )
            self.assertEqual(
                file_upload.verify_local_staging_file(
                    staging_root,
                    staging_name=str(prepared.staging_name),
                    expected_identity=prepared.staging_identity,
                ),
                "staging_verified",
            )
            self.assertEqual(
                file_upload.delete_local_staging_file(
                    staging_root,
                    staging_name=str(prepared.staging_name),
                    expected_identity=prepared.staging_identity,
                ),
                "staging_deleted",
            )
            self.assertFalse(
                (staging_root / str(prepared.staging_name)).exists()
            )


class CleanupTests(unittest.TestCase):
    def test_root_scan_obeys_the_shared_entry_budget(self) -> None:
        class TinyBudget:
            def __init__(self) -> None:
                self.remaining_entries = 3

            def consume(self) -> bool:
                if self.remaining_entries <= 0:
                    return False
                self.remaining_entries -= 1
                return True

        with tempfile.TemporaryDirectory(prefix="maibot-cleanup-") as directory:
            sandbox = Path(directory)
            managed_root = temp_cleanup.ensure_managed_temp_root(sandbox)
            for index in range(6):
                (managed_root / f"unmanaged-{index}").write_text(
                    "keep",
                    encoding="utf-8",
                )

            with patch.object(
                temp_cleanup,
                "_CleanupBudget",
                return_value=TinyBudget(),
            ):
                report = temp_cleanup.cleanup_expired_tasks(
                    sandbox,
                    retention_hours=1,
                )

        self.assertTrue(report.budget_exhausted)
        self.assertEqual(report.skipped_unsafe, 3)

    def test_active_task_is_retained_then_expires(self) -> None:
        with tempfile.TemporaryDirectory(prefix="maibot-cleanup-") as directory:
            sandbox = Path(directory)
            task = temp_cleanup.create_managed_temp_task(
                sandbox,
                command_uid=os.geteuid(),
                command_gid=os.getegid(),
            )
            (task.host_path / "temporary.txt").write_text(
                "temporary",
                encoding="utf-8",
            )
            future_ns = temp_cleanup.time.time_ns() + 2 * 60 * 60 * 1_000_000_000
            with patch.object(
                temp_cleanup.time,
                "time_ns",
                return_value=future_ns,
            ):
                active_report = temp_cleanup.cleanup_expired_tasks(
                    sandbox,
                    retention_hours=1,
                    active_task_ids=(task.task_id,),
                )
                expired_report = temp_cleanup.cleanup_expired_tasks(
                    sandbox,
                    retention_hours=1,
                )

        self.assertEqual(active_report.skipped_active, 1)
        self.assertEqual(expired_report.deleted_tasks, 1)
        self.assertFalse(task.host_path.exists())


class AuthorizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_trusted_private_identity_is_fail_closed(self) -> None:
        private_stream = {
            "stream_id": "private-1",
            "platform": "qq",
            "chat_type": "private",
            "user_id": "12345678",
            "account_id": "87654321",
        }
        plugin = plugin_module.ServerCommandPlugin()
        plugin._set_context(ContextStub([private_stream]))
        configure_plugin(
            plugin,
            {
                "trusted_private_bypass": {
                    "enabled": True,
                    "qq_user_ids": "12345678",
                }
            },
        )

        self.assertTrue((await plugin._trusted_private_caller("private-1"))[0])
        self.assertFalse(
            (await plugin._trusted_private_caller("model-forged-stream"))[0]
        )
        plugin.ctx.chat.streams = [
            private_stream,
            {**private_stream, "account_id": "11223344"},
        ]
        self.assertFalse(
            (await plugin._trusted_private_caller("private-1"))[0]
        )
        plugin.ctx.chat.streams = [
            {
                "stream_id": "group-1",
                "platform": "qq",
                "chat_type": "group",
                "group_id": "22334455",
                "user_id": "",
                "account_id": "87654321",
            }
        ]
        self.assertFalse(
            (await plugin._trusted_private_caller("group-1"))[0]
        )

    async def test_normal_upload_auto_uses_same_trusted_private_bypass(self) -> None:
        private_stream = {
            "stream_id": "private-1",
            "platform": "qq",
            "chat_type": "private",
            "user_id": "12345678",
            "account_id": "87654321",
        }
        plugin = plugin_module.ServerCommandPlugin()
        plugin._set_context(ContextStub([private_stream]))
        private_lookup = AsyncMock(return_value=[private_stream])
        plugin.ctx.chat.get_private_streams = private_lookup
        configure_plugin(
            plugin,
            {
                "file_upload": {"enabled": True},
                "temp_cleanup": {"enabled": False},
                "trusted_private_bypass": {
                    "enabled": True,
                    "qq_user_ids": "12345678",
                },
            },
        )
        prepared = plugin_module._file_upload.PreparedUpload(
            name="application.apk",
            size=68 * 1024 * 1024,
            mime_type="application/vnd.android.package-archive",
            sha256="0" * 64,
            base64_url="file:///shared/upload-test",
            source_scope="root_all_files",
            transport="napcat_local",
        )

        with (
            patch.object(plugin_module.os, "geteuid", return_value=0),
            patch.object(
                plugin,
                "_prepare_qq_upload",
                AsyncMock(return_value=prepared),
            ) as prepare_mock,
        ):
            result = await plugin.handle_send_server_file_to_qq(
                file_path="/root/application.apk",
                target_type="current",
                stream_id="private-1",
            )

        self.assertTrue(result["success"])
        self.assertTrue(result["trusted_private_bypass"])
        self.assertEqual(
            result["sensitive_file_guard"],
            "disabled_by_trusted_private",
        )
        prepare_mock.assert_awaited_once_with(
            "/root/application.apk",
            root_mode=True,
            upload_name=None,
            sensitive_guard_enabled=False,
        )
        private_lookup.assert_awaited_once_with("qq")
        self.assertEqual(plugin.ctx.send.calls[0][0][2], "private-1")

    async def test_scan_refusal_keeps_1016_failure_shape(
        self,
    ) -> None:
        private_stream = {
            "stream_id": "private-1",
            "platform": "qq",
            "chat_type": "private",
            "user_id": "12345678",
            "account_id": "87654321",
        }
        plugin = plugin_module.ServerCommandPlugin()
        plugin._set_context(ContextStub([private_stream]))
        configure_plugin(
            plugin,
            {
                "file_upload": {"enabled": True},
                "temp_cleanup": {"enabled": False},
                "trusted_private_bypass": {
                    "enabled": True,
                    "qq_user_ids": "11223344",
                },
                "root_mode": {
                    "enabled": True,
                    "confirmation_1": True,
                    "confirmation_2": True,
                    "confirmation_3": True,
                    "confirmation_4": True,
                    "final_confirmation": 1,
                },
            },
        )

        with (
            patch.object(plugin_module.os, "geteuid", return_value=0),
            patch.object(
                plugin,
                "_prepare_qq_upload",
                AsyncMock(
                    side_effect=plugin_module.FileUploadError(
                        "拒绝上传敏感文件：压缩包包含嵌套压缩或加密容器，无法可靠检查。"
                    )
                ),
            ),
        ):
            result = await plugin.handle_send_server_file_to_qq(
                file_path="/root/application.apk",
                target_type="current",
                stream_id="private-1",
        )

        self.assertFalse(result["success"])
        self.assertNotIn("trusted_private_bypass", result)
        self.assertNotIn("retry_safe", result)
        self.assertNotIn("未进入可信私聊绕过", result["content"])

    async def test_group_upload_always_keeps_sensitive_scan_enabled(self) -> None:
        group_stream = {
            "stream_id": "group-1",
            "platform": "qq",
            "chat_type": "group",
            "group_id": "22334455",
            "user_id": "12345678",
            "account_id": "87654321",
        }
        plugin = plugin_module.ServerCommandPlugin()
        plugin._set_context(ContextStub([group_stream]))
        configure_plugin(
            plugin,
            {
                "file_upload": {"enabled": True},
                "temp_cleanup": {"enabled": False},
                "trusted_private_bypass": {
                    "enabled": True,
                    "qq_user_ids": "12345678",
                },
                "root_mode": {
                    "enabled": True,
                    "confirmation_1": True,
                    "confirmation_2": True,
                    "confirmation_3": True,
                    "confirmation_4": True,
                    "final_confirmation": 1,
                },
            },
        )
        prepared = plugin_module._file_upload.PreparedUpload(
            name="ordinary.apk",
            size=8,
            mime_type="application/vnd.android.package-archive",
            sha256="0" * 64,
            base64_url="base64://b3JkaW5hcnk=",
            source_scope="root_all_files",
        )

        with (
            patch.object(plugin_module.os, "geteuid", return_value=0),
            patch.object(
                plugin,
                "_prepare_qq_upload",
                AsyncMock(return_value=prepared),
            ) as prepare_mock,
        ):
            result = await plugin.handle_send_server_file_to_qq(
                file_path="/root/ordinary.apk",
                target_type="current",
                stream_id="group-1",
            )

        self.assertTrue(result["success"])
        self.assertFalse(result["trusted_private_bypass"])
        self.assertEqual(result["sensitive_file_guard"], "enabled")
        prepare_mock.assert_awaited_once_with(
            "/root/ordinary.apk",
            root_mode=True,
            upload_name=None,
            sensitive_guard_enabled=True,
        )

    async def test_trusted_source_cannot_bypass_to_another_private_stream(self) -> None:
        streams = [
            {
                "stream_id": "private-1",
                "platform": "qq",
                "chat_type": "private",
                "user_id": "12345678",
                "account_id": "87654321",
            },
            {
                "stream_id": "private-2",
                "platform": "qq",
                "chat_type": "private",
                "user_id": "11223344",
                "account_id": "87654321",
            },
        ]
        plugin = plugin_module.ServerCommandPlugin()
        plugin._set_context(ContextStub(streams))
        configure_plugin(
            plugin,
            {
                "file_upload": {"enabled": True},
                "temp_cleanup": {"enabled": False},
                "trusted_private_bypass": {
                    "enabled": True,
                    "qq_user_ids": "12345678",
                },
                "root_mode": {
                    "enabled": True,
                    "confirmation_1": True,
                    "confirmation_2": True,
                    "confirmation_3": True,
                    "confirmation_4": True,
                    "final_confirmation": 1,
                },
            },
        )
        prepared = plugin_module._file_upload.PreparedUpload(
            name="ordinary.txt",
            size=8,
            mime_type="text/plain",
            sha256="0" * 64,
            base64_url="base64://b3JkaW5hcnk=",
            source_scope="root_all_files",
        )

        with (
            patch.object(plugin_module.os, "geteuid", return_value=0),
            patch.object(
                plugin,
                "_prepare_qq_upload",
                AsyncMock(return_value=prepared),
            ) as prepare_mock,
        ):
            result = await plugin.handle_send_server_file_to_qq(
                file_path="/root/ordinary.txt",
                target_type="private",
                target_id="11223344",
                stream_id="private-1",
            )

        self.assertTrue(result["success"])
        self.assertFalse(result["trusted_private_bypass"])
        self.assertEqual(result["sensitive_file_guard"], "enabled")
        prepare_mock.assert_awaited_once_with(
            "/root/ordinary.txt",
            root_mode=True,
            upload_name=None,
            sensitive_guard_enabled=True,
        )
        self.assertEqual(plugin.ctx.send.calls[0][0][2], "private-2")

    async def test_ambiguous_target_does_not_disclose_bot_account_ids(self) -> None:
        account_ids = ("87654321", "11223344")
        streams = [
            {
                "stream_id": f"private-{index}",
                "platform": "qq",
                "chat_type": "private",
                "user_id": "12345678",
                "account_id": account_id,
            }
            for index, account_id in enumerate(account_ids)
        ]
        plugin = plugin_module.ServerCommandPlugin()
        plugin._set_context(ContextStub(streams))

        with self.assertRaises(plugin_module.FileUploadError) as caught:
            await plugin._resolve_qq_stream(
                "private",
                "12345678",
                "",
                "",
            )
        message = str(caught.exception)
        self.assertIn("account_id", message)
        for account_id in account_ids:
            self.assertNotIn(account_id, message)

    async def test_adapter_result_must_explicitly_confirm_delivery(self) -> None:
        plugin = plugin_module.ServerCommandPlugin()
        plugin._set_context(ContextStub([], send_result="truthy-but-ambiguous"))
        prepared = plugin_module._file_upload.PreparedUpload(
            name="ordinary.txt",
            size=8,
            mime_type="text/plain",
            sha256="0" * 64,
            base64_url="base64://b3JkaW5hcnk=",
            source_scope="sandbox_only",
        )

        sent, staging_status, error_type = await plugin._send_prepared_file(
            prepared,
            "private-1",
        )
        self.assertFalse(sent)
        self.assertEqual(staging_status, "not_applicable")
        self.assertEqual(error_type, "UnconfirmedAdapterResult")

        plugin.ctx.send.result = {"success": True}
        sent, staging_status, error_type = await plugin._send_prepared_file(
            prepared,
            "private-1",
        )
        self.assertTrue(sent)
        self.assertEqual(staging_status, "not_applicable")
        self.assertEqual(error_type, "")


class CancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_sandbox_cancellation_kills_and_reaps_process_group(self) -> None:
        fake_process = FakeProcess()

        async def fake_create_subprocess(*_args, **_kwargs):
            return fake_process

        def fake_killpg(pid: int, sig: signal.Signals) -> None:
            self.assertEqual(pid, fake_process.pid)
            self.assertEqual(sig, signal.SIGKILL)
            fake_process.stop()

        identity = executor.ExecutionIdentity(
            uid=os.geteuid(),
            gid=os.getegid(),
            name="test",
            drop_from_root=False,
        )
        with tempfile.TemporaryDirectory(prefix="maibot-cancel-") as directory:
            sandbox = Path(directory)
            with (
                patch.object(executor, "_is_ubuntu", return_value=True),
                patch.object(executor.shutil, "which", return_value="/usr/bin/bwrap"),
                patch.object(
                    executor,
                    "resolve_execution_identity",
                    return_value=identity,
                ),
                patch.object(executor, "validate_sandbox_contents"),
                patch.object(executor, "build_bwrap_argv", return_value=["fake"]),
                patch.object(
                    executor.asyncio,
                    "create_subprocess_exec",
                    side_effect=fake_create_subprocess,
                ),
                patch.object(executor.os, "killpg", side_effect=fake_killpg) as killpg,
            ):
                task = asyncio.create_task(
                    executor.run_command(
                        "sleep 60",
                        sandbox,
                        executor.SandboxLimits(timeout_seconds=300),
                    )
                )
                await asyncio.wait_for(fake_process.started.wait(), timeout=1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=1)

        killpg.assert_called_once_with(fake_process.pid, signal.SIGKILL)
        self.assertIsNotNone(fake_process.returncode)

    async def test_root_cancellation_runs_supervisor_cleanup(self) -> None:
        fake_process = FakeProcess()

        async def fake_create_subprocess(*_args, **_kwargs):
            return fake_process

        async def fake_stop_root(process: FakeProcess) -> None:
            self.assertIs(process, fake_process)
            process.terminate()
            await process.wait()

        stop_supervisor = AsyncMock(side_effect=fake_stop_root)
        with (
            patch.object(executor, "_is_ubuntu", return_value=True),
            patch.object(executor.os, "geteuid", return_value=0),
            patch.object(
                executor.asyncio,
                "create_subprocess_exec",
                side_effect=fake_create_subprocess,
            ),
            patch.object(
                executor,
                "_stop_root_supervisor",
                stop_supervisor,
            ),
        ):
            task = asyncio.create_task(
                executor.run_unrestricted_root_command(
                    "sleep 60",
                    executor.SandboxLimits(timeout_seconds=300),
                )
            )
            await asyncio.wait_for(fake_process.started.wait(), timeout=1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=1)

        stop_supervisor.assert_awaited_once_with(fake_process)
        self.assertIsNotNone(fake_process.returncode)


class RealUbuntuIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_bubblewrap_and_root_execution(self) -> None:
        if os.environ.get("MAIBOT_INTEGRATION") != "1":
            self.skipTest("未启用真实 Ubuntu 集成测试")
        if (
            os.geteuid() != 0
            or not executor._is_ubuntu()
            or shutil.which("bwrap") is None
            or not Path("/proc/self/stat").is_file()
        ):
            self.skipTest("真实集成测试需要 Ubuntu root、Bubblewrap 和 procfs")

        with tempfile.TemporaryDirectory(
            prefix="maibot-integration-",
            dir="/tmp",
        ) as directory:
            maibot_root = Path(directory)
            identity = executor.resolve_execution_identity()
            sandbox = executor.prepare_sandbox(maibot_root, identity)
            sandbox_result = await executor.run_command(
                "pwd; id -u; printf sandbox-ok > integration.txt",
                sandbox,
                executor.SandboxLimits(timeout_seconds=10),
                requested_timeout=10,
            )
            self.assertEqual(sandbox_result.exit_code, 0, sandbox_result.stderr)
            self.assertEqual(
                sandbox_result.stdout.splitlines(),
                ["/work", str(identity.uid)],
            )
            self.assertEqual(
                (sandbox / "integration.txt").read_text(encoding="utf-8"),
                "sandbox-ok",
            )

            root_result = await executor.run_unrestricted_root_command(
                "printf '%s:' \"$PWD\"; id -u",
                executor.SandboxLimits(timeout_seconds=5),
                requested_timeout=5,
            )
            self.assertEqual(root_result.exit_code, 0, root_result.stderr)
            self.assertEqual(root_result.stdout, "/root:0\n")


if __name__ == "__main__":
    unittest.main()

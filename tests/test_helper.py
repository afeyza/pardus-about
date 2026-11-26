"""Tests for src/BootHealthHelper.py and its polkit action.

Run from the repository root:
    python3 -m unittest discover -s tests -v

The helper is tested against a fake EFI partition in a temporary
directory. os.path.ismount is patched, because a temporary directory is
never a mount point.
"""

import builtins
import io
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)

import BootHealthHelper as helper  # noqa: E402
from util.boothealth import pe  # noqa: E402
from pe_builder import (  # noqa: E402
    build_pe, sbat_section, vendor_cert_section,
)

POLICY_FILE = os.path.join(
    ROOT, "polkit", "tr.org.pardus.pkexec.pardus-about.boot-health.policy"
)
ACTION_ID = "tr.org.pardus.pkexec.pardus-about.boot-health"
INSTALLED_HELPER = "/usr/share/pardus/pardus-about/src/BootHealthHelper.py"

SHIM = build_pe([(".text", b"s" * 64),
                 (".vendor_cert", vendor_cert_section(b"cert"))],
                signatures=1)
GRUB = build_pe([(".text", b"g" * 64),
                 (".sbat", sbat_section(("grub", 5)))])


def write_file(esp, relative_path, data):
    path = os.path.join(esp, relative_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def run_main(esp, argv):
    """Run helper.main() on esp with the given argv; return stdout."""
    out = io.StringIO()
    with mock.patch.object(helper, "ESP_PATH", esp), \
            mock.patch.object(sys, "argv", argv), \
            mock.patch("os.path.ismount", return_value=True), \
            redirect_stdout(out):
        exit_code = helper.main()
    return exit_code, out.getvalue()


def snapshot(directory):
    """Every path under directory with its size and modification time."""
    result = {}
    for parent, dirs, files in os.walk(directory):
        for name in dirs + files:
            path = os.path.join(parent, name)
            info = os.stat(path)
            result[path] = (info.st_size, info.st_mtime_ns)
    return result


class FakeEspTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.esp = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def collect(self):
        with mock.patch("os.path.ismount", return_value=True):
            return helper.collect_esp(self.esp)

    def files_by_role(self, result):
        return {entry["role"]: entry for entry in result["files"]}


class SchemaTests(FakeEspTestCase):
    """The output must match the "esp" field in docs/mimari.md."""

    def test_top_level_fields(self):
        result = self.collect()
        self.assertEqual(set(result), {"path", "files", "errors"})
        self.assertEqual(result["path"], self.esp)
        self.assertEqual(result["errors"], [])

    def test_three_roles_in_fixed_order(self):
        roles = [entry["role"] for entry in self.collect()["files"]]
        self.assertEqual(roles, ["shim", "grub", "fallback"])

    def test_file_entry_fields(self):
        for entry in self.collect()["files"]:
            self.assertEqual(set(entry), {"role", "path", "status", "pe"})

    def test_paths_are_absolute_and_under_esp(self):
        for entry in self.collect()["files"]:
            self.assertTrue(entry["path"].startswith(self.esp + os.sep))

    def test_status_values_are_from_the_schema(self):
        allowed = {"ok", "missing", "unreadable", "malformed"}
        write_file(self.esp, "EFI/pardus/grubx64.efi", b"not a PE file")
        for entry in self.collect()["files"]:
            self.assertIn(entry["status"], allowed)

    def test_pe_is_null_unless_status_is_ok(self):
        write_file(self.esp, "EFI/pardus/shimx64.efi", SHIM)
        write_file(self.esp, "EFI/pardus/grubx64.efi", b"not a PE file")
        for entry in self.collect()["files"]:
            if entry["status"] == "ok":
                self.assertIsNotNone(entry["pe"])
            else:
                self.assertIsNone(entry["pe"])

    def test_output_is_json_serializable(self):
        write_file(self.esp, "EFI/pardus/shimx64.efi", SHIM)
        result = self.collect()
        self.assertEqual(json.loads(json.dumps(result)), result)


class FileTests(FakeEspTestCase):
    def test_present_files_are_parsed(self):
        write_file(self.esp, "EFI/pardus/shimx64.efi", SHIM)
        write_file(self.esp, "EFI/pardus/grubx64.efi", GRUB)
        write_file(self.esp, "EFI/BOOT/BOOTX64.EFI", SHIM)
        files = self.files_by_role(self.collect())

        self.assertEqual(files["shim"]["status"], "ok")
        self.assertEqual(files["shim"]["pe"], pe.parse(SHIM))
        self.assertTrue(files["shim"]["pe"]["signed"])
        self.assertTrue(files["shim"]["pe"]["vendor_cert_present"])

        self.assertEqual(files["grub"]["pe"], pe.parse(GRUB))
        self.assertFalse(files["grub"]["pe"]["signed"])

        self.assertEqual(files["fallback"]["status"], "ok")

    def test_missing_file(self):
        write_file(self.esp, "EFI/pardus/shimx64.efi", SHIM)
        files = self.files_by_role(self.collect())
        self.assertEqual(files["grub"]["status"], "missing")
        self.assertIsNone(files["grub"]["pe"])
        self.assertEqual(files["fallback"]["status"], "missing")

    def test_empty_esp_is_not_an_error(self):
        result = self.collect()
        self.assertEqual(result["errors"], [])
        for entry in result["files"]:
            self.assertEqual(entry["status"], "missing")

    def test_malformed_file(self):
        write_file(self.esp, "EFI/pardus/grubx64.efi", b"MZ" + b"\0" * 10)
        files = self.files_by_role(self.collect())
        self.assertEqual(files["grub"]["status"], "malformed")
        self.assertIsNone(files["grub"]["pe"])

    def test_directory_in_place_of_file_is_not_ok(self):
        os.makedirs(os.path.join(self.esp, "EFI/pardus/grubx64.efi"))
        files = self.files_by_role(self.collect())
        self.assertEqual(files["grub"]["status"], "unreadable")


class NotMountedTests(FakeEspTestCase):
    def collect_unmounted(self):
        with mock.patch("os.path.ismount", return_value=False):
            return helper.collect_esp(self.esp)

    def test_error_is_reported(self):
        result = self.collect_unmounted()
        self.assertEqual(result["errors"], ["esp_not_mounted"])

    def test_files_are_unreadable_and_not_opened(self):
        # A stale file under an unmounted /boot/efi must not be read.
        write_file(self.esp, "EFI/pardus/grubx64.efi", GRUB)
        with mock.patch.object(pe, "inspect_file") as inspect:
            result = self.collect_unmounted()
        inspect.assert_not_called()
        for entry in result["files"]:
            self.assertEqual(entry["status"], "unreadable")
            self.assertIsNone(entry["pe"])

    def test_still_lists_three_roles(self):
        self.assertEqual(len(self.collect_unmounted()["files"]), 3)


class ArgumentTests(FakeEspTestCase):
    """Command line parameters must be ignored."""

    def setUp(self):
        super().setUp()
        write_file(self.esp, "EFI/pardus/grubx64.efi", GRUB)
        self.other = tempfile.TemporaryDirectory()
        write_file(self.other.name, "EFI/pardus/grubx64.efi", SHIM)

    def tearDown(self):
        self.other.cleanup()
        super().tearDown()

    def test_output_does_not_depend_on_argv(self):
        _, without_args = run_main(self.esp, ["BootHealthHelper.py"])
        for argv in (
            ["BootHealthHelper.py", self.other.name],
            ["BootHealthHelper.py", "--esp", self.other.name],
            ["BootHealthHelper.py", "/etc/shadow", "--help", "-v"],
        ):
            _, with_args = run_main(self.esp, argv)
            self.assertEqual(with_args, without_args, argv)

    def test_other_directory_is_never_read(self):
        opened = []
        real_open = builtins.open

        def recording_open(path, *args, **kwargs):
            opened.append(str(path))
            return real_open(path, *args, **kwargs)

        with mock.patch("builtins.open", recording_open):
            run_main(self.esp, ["BootHealthHelper.py", self.other.name])
        for path in opened:
            self.assertFalse(path.startswith(self.other.name), path)


class NoWriteTests(FakeEspTestCase):
    """The helper must not write anything to disk."""

    def setUp(self):
        super().setUp()
        write_file(self.esp, "EFI/pardus/shimx64.efi", SHIM)
        write_file(self.esp, "EFI/pardus/grubx64.efi", GRUB)

    def test_files_are_opened_read_only(self):
        modes = []
        real_open = builtins.open

        def recording_open(path, mode="r", *args, **kwargs):
            modes.append(mode)
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", recording_open):
            run_main(self.esp, ["BootHealthHelper.py"])
        self.assertTrue(modes, "the helper opened no files")
        for mode in modes:
            self.assertFalse(set(mode) & set("wax+"), mode)

    def test_esp_is_unchanged(self):
        before = snapshot(self.esp)
        run_main(self.esp, ["BootHealthHelper.py"])
        self.assertEqual(snapshot(self.esp), before)

    def test_bytecode_writing_is_disabled(self):
        # Importing util.boothealth.pe as root would otherwise create
        # __pycache__ directories under /usr/share/pardus.
        self.assertTrue(sys.dont_write_bytecode)


class MainTests(FakeEspTestCase):
    def test_prints_one_json_object(self):
        write_file(self.esp, "EFI/pardus/grubx64.efi", GRUB)
        _, output = run_main(self.esp, ["BootHealthHelper.py"])
        self.assertEqual(json.loads(output), self.collect())

    def test_exit_code_is_zero_even_when_not_mounted(self):
        out = io.StringIO()
        with mock.patch.object(helper, "ESP_PATH", self.esp), \
                mock.patch("os.path.ismount", return_value=False), \
                redirect_stdout(out):
            self.assertEqual(helper.main(), 0)
        self.assertEqual(json.loads(out.getvalue())["errors"],
                         ["esp_not_mounted"])

    def test_real_esp_path(self):
        self.assertEqual(helper.ESP_PATH, "/boot/efi")


class PolicyTests(unittest.TestCase):
    def setUp(self):
        tree = ElementTree.parse(POLICY_FILE)
        actions = tree.getroot().findall("action")
        self.assertEqual(len(actions), 1)
        self.action = actions[0]

    def annotation(self, key):
        for element in self.action.findall("annotate"):
            if element.get("key") == key:
                return element.text
        return None

    def test_action_id(self):
        self.assertEqual(self.action.get("id"), ACTION_ID)

    def test_exec_path_is_the_installed_helper(self):
        self.assertEqual(
            self.annotation("org.freedesktop.policykit.exec.path"),
            INSTALLED_HELPER,
        )

    def test_always_asks_for_password(self):
        # Unlike the system_info action (allow_active = yes), this action
        # must never run without the user's consent.
        defaults = self.action.find("defaults")
        for name in ("allow_any", "allow_inactive", "allow_active"):
            self.assertIn(defaults.find(name).text,
                          ("auth_admin", "auth_admin_keep"), name)

    def test_has_turkish_message(self):
        lang = "{http://www.w3.org/XML/1998/namespace}lang"
        languages = [element.get(lang)
                     for element in self.action.findall("message")]
        self.assertIn("tr", languages)

    def test_installed_by_meson(self):
        with open(os.path.join(ROOT, "polkit", "meson.build")) as f:
            meson = f.read()
        self.assertIn(os.path.basename(POLICY_FILE), meson)
        self.assertIn("/usr/share/polkit-1/actions/", meson)

    def test_helper_is_installed_by_meson(self):
        with open(os.path.join(ROOT, "meson.build")) as f:
            self.assertIn("install_subdir('src'", f.read())

    def test_helper_is_executable(self):
        # pkexec runs the file directly, so it needs the executable bit.
        path = os.path.join(ROOT, "src", "BootHealthHelper.py")
        self.assertTrue(os.access(path, os.X_OK))


if __name__ == "__main__":
    unittest.main()

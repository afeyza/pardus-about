"""Tests for util.boothealth.collect.

Each test builds a fake root holding the files collect.py reads, so
nothing here needs a UEFI machine, Pardus or root.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from util.boothealth import collect, efivars  # noqa: E402
from pe_builder import build_pe  # noqa: E402
from test_efivars import (  # noqa: E402
    FAKE_CERT, GRUB_HASH, REALISTIC_SBAT, RUNTIME_ONLY, FakeRoot,
    sha256_list, x509_list,
)

RELEASE = "6.12.48+deb13-amd64"

DPKG_STATUS = """\
Package: base-files
Status: install ok installed
Architecture: amd64

Package: shim-signed
Status: install ok installed
Architecture: amd64
Version: 1.46+15.8-1

Package: grub-efi-amd64-signed
Status: deinstall ok config-files
Architecture: amd64
"""


class SystemRoot(FakeRoot):
    """FakeRoot plus the non-EFI files collect.py reads."""

    def write_file(self, relative, data):
        path = os.path.join(self.path, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path, mode) as f:
            f.write(data)

    def remove_efi(self):
        os.rmdir(self.vars_dir)
        os.rmdir(os.path.dirname(self.vars_dir))

    def secure_boot(self, value):
        self.write("SecureBoot", efivars.GLOBAL_GUID, bytes([value]))

    def setup_mode(self, value):
        self.write("SetupMode", efivars.GLOBAL_GUID, bytes([value]))

    def shim(self, mok=None, sb_state=None, sbat=REALISTIC_SBAT):
        """Variables shim leaves behind when it boots the system."""
        mok = x509_list(FAKE_CERT) if mok is None else mok
        self.write("MokListRT", efivars.SHIM_GUID, mok, RUNTIME_ONLY)
        if sb_state is not None:
            self.write("MokSBStateRT", efivars.SHIM_GUID,
                       bytes([sb_state]), RUNTIME_ONLY)
        if sbat is not None:
            self.write("SbatLevelRT", efivars.SHIM_GUID, sbat, RUNTIME_ONLY)

    def kernel(self, signatures=1, release=RELEASE):
        self.write_file(os.path.join("boot", "vmlinuz-" + release),
                        build_pe(signatures=signatures))

    def cmdline(self, text):
        self.write_file(os.path.join("proc", "cmdline"), text + "\n")

    def dpkg(self, text=DPKG_STATUS):
        self.write_file(os.path.join("var", "lib", "dpkg", "status"), text)


class CollectTestCase(unittest.TestCase):
    def setUp(self):
        self.root = SystemRoot()
        self.addCleanup(self.root.cleanup)

    def collect(self):
        return collect.collect(self.root.path, kernel_release=RELEASE)


class ShapeTests(CollectTestCase):
    def test_top_level_fields(self):
        state = self.collect()
        self.assertEqual(
            sorted(state),
            ["esp", "firmware", "kernel", "live_session", "packages",
             "schema", "shim"],
        )
        self.assertEqual(state["schema"], 1)
        self.assertIsNone(state["esp"])

    def test_typical_installed_system(self):
        root = self.root
        root.secure_boot(1)
        root.setup_mode(0)
        root.shim(mok=x509_list(FAKE_CERT) + sha256_list(GRUB_HASH))
        root.kernel(signatures=1)
        root.cmdline("BOOT_IMAGE=/boot/vmlinuz-{} root=UUID=1 ro quiet"
                     .format(RELEASE))
        root.dpkg()

        state = self.collect()
        self.assertEqual(state["live_session"], False)
        self.assertEqual(
            state["firmware"],
            {"uefi": True, "secure_boot": True, "setup_mode": False},
        )
        self.assertEqual(
            state["shim"],
            {"validation_disabled": False,
             "mok_hashes": [GRUB_HASH.hex()],
             "sbat_level": {"shim": 4, "grub": 3, "grub.debian": 4}},
        )
        self.assertEqual(state["kernel"]["path"],
                         "/boot/vmlinuz-" + RELEASE)
        self.assertEqual(state["kernel"]["status"], "ok")
        self.assertTrue(state["kernel"]["pe"]["signed"])
        self.assertEqual(
            state["packages"],
            {"shim-signed": True, "grub-efi-amd64-signed": False},
        )


class FirmwareTests(CollectTestCase):
    def test_legacy_boot(self):
        self.root.remove_efi()
        firmware = self.collect()["firmware"]
        self.assertFalse(firmware["uefi"])

    def test_secure_boot_off(self):
        self.root.secure_boot(0)
        self.assertFalse(self.collect()["firmware"]["secure_boot"])

    def test_missing_secure_boot_means_off(self):
        # Firmware without Secure Boot support (e.g. a plain VM).
        firmware = self.collect()["firmware"]
        self.assertTrue(firmware["uefi"])
        self.assertFalse(firmware["secure_boot"])
        self.assertFalse(firmware["setup_mode"])

    def test_unreadable_secure_boot_is_null(self):
        self.root.make_unreadable("SecureBoot", efivars.GLOBAL_GUID)
        self.assertIsNone(self.collect()["firmware"]["secure_boot"])

    def test_malformed_setup_mode_is_null(self):
        self.root.write("SetupMode", efivars.GLOBAL_GUID, b"\x05")
        self.assertIsNone(self.collect()["firmware"]["setup_mode"])

    def test_setup_mode_on(self):
        self.root.setup_mode(1)
        self.assertTrue(self.collect()["firmware"]["setup_mode"])


class ShimTests(CollectTestCase):
    def test_missing_sb_state_with_shim_means_enabled(self):
        self.root.shim(sb_state=None)
        self.assertIs(self.collect()["shim"]["validation_disabled"], False)

    def test_validation_disabled(self):
        self.root.shim(sb_state=1)
        self.assertIs(self.collect()["shim"]["validation_disabled"], True)

    def test_without_shim_everything_is_unknown(self):
        self.assertEqual(
            self.collect()["shim"],
            {"validation_disabled": None, "mok_hashes": None,
             "sbat_level": None},
        )

    def test_unreadable_sb_state_is_null_even_with_shim(self):
        self.root.shim()
        self.root.make_unreadable("MokSBStateRT", efivars.SHIM_GUID)
        self.assertIsNone(self.collect()["shim"]["validation_disabled"])

    def test_malformed_mok_list(self):
        self.root.shim(mok=b"\x00" * 10)
        shim = self.collect()["shim"]
        self.assertIsNone(shim["mok_hashes"])
        # Without a readable MokListRT we cannot tell whether shim ran.
        self.assertIsNone(shim["validation_disabled"])

    def test_empty_mok_list_is_an_empty_list(self):
        self.root.shim(mok=b"")
        self.assertEqual(self.collect()["shim"]["mok_hashes"], [])

    def test_shim_without_sbat(self):
        self.root.shim(sbat=None)
        self.assertIsNone(self.collect()["shim"]["sbat_level"])

    def test_malformed_sbat_is_null(self):
        self.root.shim(sbat=b"garbage")
        self.assertIsNone(self.collect()["shim"]["sbat_level"])


class KernelTests(CollectTestCase):
    def test_unsigned_kernel(self):
        self.root.kernel(signatures=0)
        kernel = self.collect()["kernel"]
        self.assertEqual(kernel["status"], "ok")
        self.assertFalse(kernel["pe"]["signed"])

    def test_kernel_for_another_release_is_ignored(self):
        self.root.kernel(release="6.1.0-old-amd64")
        kernel = self.collect()["kernel"]
        self.assertEqual(kernel["status"], "missing")
        self.assertIsNone(kernel["pe"])

    def test_unreadable_kernel_does_not_crash(self):
        os.makedirs(os.path.join(self.root.path, "boot",
                                 "vmlinuz-" + RELEASE))
        kernel = self.collect()["kernel"]
        self.assertEqual(kernel["status"], "unreadable")
        self.assertIsNone(kernel["pe"])

    def test_malformed_kernel(self):
        self.root.write_file(os.path.join("boot", "vmlinuz-" + RELEASE),
                             b"not a PE file")
        self.assertEqual(self.collect()["kernel"]["status"], "malformed")

    def test_default_release_is_the_running_kernel(self):
        state = collect.collect(self.root.path)
        self.assertTrue(state["kernel"]["path"].startswith("/boot/vmlinuz-"))


class LiveSessionTests(CollectTestCase):
    def test_live_session_reads_kernel_from_live_medium(self):
        self.root.cmdline("BOOT_IMAGE=/live/vmlinuz boot=live components")
        self.root.write_file(
            os.path.join("run", "live", "medium", "live", "vmlinuz"),
            build_pe(signatures=1),
        )
        state = self.collect()
        self.assertTrue(state["live_session"])
        self.assertEqual(state["kernel"]["path"],
                         "/run/live/medium/live/vmlinuz")
        self.assertTrue(state["kernel"]["pe"]["signed"])

    def test_versioned_live_kernel_name(self):
        self.root.cmdline("boot=live")
        self.root.write_file(
            os.path.join("run", "live", "medium", "live",
                         "vmlinuz-" + RELEASE),
            build_pe(signatures=0),
        )
        self.assertEqual(self.collect()["kernel"]["path"],
                         "/run/live/medium/live/vmlinuz-" + RELEASE)

    def test_live_session_without_medium_falls_back_to_boot(self):
        self.root.cmdline("boot=live")
        self.root.kernel()
        self.assertEqual(self.collect()["kernel"]["path"],
                         "/boot/vmlinuz-" + RELEASE)

    def test_similar_word_is_not_live(self):
        self.root.cmdline("root=/dev/sda1 noboot=live")
        self.assertIs(self.collect()["live_session"], False)

    def test_unreadable_cmdline_is_null(self):
        self.assertIsNone(self.collect()["live_session"])


class PackageTests(CollectTestCase):
    def test_missing_status_file_is_null(self):
        self.assertEqual(
            self.collect()["packages"],
            {"shim-signed": None, "grub-efi-amd64-signed": None},
        )

    def test_package_not_listed_is_false(self):
        self.root.dpkg("Package: base-files\nStatus: install ok installed\n")
        self.assertEqual(
            self.collect()["packages"],
            {"shim-signed": False, "grub-efi-amd64-signed": False},
        )

    def test_half_installed_is_false(self):
        self.root.dpkg("Package: shim-signed\n"
                       "Status: install reinstreq half-installed\n")
        self.assertFalse(self.collect()["packages"]["shim-signed"])

    def test_both_installed(self):
        self.root.dpkg(
            "Package: shim-signed\nStatus: install ok installed\n\n"
            "Package: grub-efi-amd64-signed\nStatus: install ok installed\n"
        )
        self.assertEqual(
            self.collect()["packages"],
            {"shim-signed": True, "grub-efi-amd64-signed": True},
        )


if __name__ == "__main__":
    unittest.main()

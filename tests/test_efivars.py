"""Tests for util.boothealth.efivars.

Each test builds a fake root with a sys/firmware/efi/efivars directory,
so nothing here needs a UEFI machine or root.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""

import hashlib
import os
import struct
import sys
import tempfile
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from util.boothealth import efivars  # noqa: E402

# Attribute field efivarfs puts in front of the data:
# NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS.
DEFAULT_ATTRIBUTES = struct.pack("<I", 0x07)
RUNTIME_ONLY = struct.pack("<I", 0x06)  # how shim creates the *RT copies


class FakeRoot:
    """A temporary directory laid out like the root of a UEFI system."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = self._tmp.name
        self.vars_dir = os.path.join(self.path, efivars.EFIVARS_DIR)
        os.makedirs(self.vars_dir)

    def cleanup(self):
        self._tmp.cleanup()

    def _var_path(self, name, guid):
        return os.path.join(self.vars_dir, "{}-{}".format(name, guid))

    def write(self, name, guid, data, attributes=DEFAULT_ATTRIBUTES):
        with open(self._var_path(name, guid), "wb") as f:
            f.write(attributes + data)

    def write_raw(self, name, guid, raw):
        """Write the file exactly as given, without an attribute field."""
        with open(self._var_path(name, guid), "wb") as f:
            f.write(raw)

    def make_unreadable(self, name, guid):
        # open() on a directory fails with an OSError even for root, so
        # this works in CI and in a root container alike.
        os.mkdir(self._var_path(name, guid))


def signature_list(sig_type, entries, owner=efivars.SHIM_GUID, header=b""):
    """Build one EFI_SIGNATURE_LIST holding the given entries."""
    owner_bytes = uuid.UUID(owner).bytes_le
    sig_size = 16 + len(entries[0])
    body = b"".join(owner_bytes + entry for entry in entries)
    list_size = efivars.ESL_HEADER.size + len(header) + len(body)
    return efivars.ESL_HEADER.pack(
        sig_type, list_size, len(header), sig_size
    ) + header + body


def sha256_list(*digests):
    return signature_list(efivars.CERT_SHA256_GUID, list(digests))


def x509_list(cert):
    return signature_list(efivars.CERT_X509_GUID, [cert])


GRUB_HASH = hashlib.sha256(b"grubx64.efi").digest()
KERNEL_HASH = hashlib.sha256(b"vmlinuz").digest()
# Not a real certificate; only its length and position matter here.
FAKE_CERT = b"\x30\x82\x03\x10" + bytes(range(256)) * 3


class FakeRootTestCase(unittest.TestCase):
    def setUp(self):
        self.root = FakeRoot()
        self.addCleanup(self.root.cleanup)


class GuidTests(unittest.TestCase):
    def test_sha256_guid_is_stored_mixed_endian(self):
        # UEFI stores the first three GUID fields little-endian. Using
        # uuid.bytes instead of bytes_le would silently match nothing.
        self.assertEqual(
            efivars.CERT_SHA256_GUID.hex(),
            "2616c4c14c509240aca941f936934328",
        )


class ReadVariableTests(FakeRootTestCase):
    def test_strips_attribute_field(self):
        self.root.write("SecureBoot", efivars.GLOBAL_GUID, b"\x01")
        status, data = efivars.read_variable(
            "SecureBoot", efivars.GLOBAL_GUID, self.root.path
        )
        self.assertEqual(status, "ok")
        self.assertEqual(data, b"\x01")

    def test_missing(self):
        self.assertEqual(
            efivars.read_variable("SecureBoot", efivars.GLOBAL_GUID,
                                  self.root.path),
            ("missing", None),
        )

    def test_missing_efivars_directory(self):
        with tempfile.TemporaryDirectory() as empty_root:
            status, _ = efivars.read_variable(
                "SecureBoot", efivars.GLOBAL_GUID, empty_root
            )
        self.assertEqual(status, "missing")

    def test_unreadable(self):
        self.root.make_unreadable("SecureBoot", efivars.GLOBAL_GUID)
        status, data = efivars.read_variable(
            "SecureBoot", efivars.GLOBAL_GUID, self.root.path
        )
        self.assertEqual((status, data), ("unreadable", None))

    def test_shorter_than_attribute_field(self):
        self.root.write_raw("SecureBoot", efivars.GLOBAL_GUID, b"\x07\x00")
        status, _ = efivars.read_variable(
            "SecureBoot", efivars.GLOBAL_GUID, self.root.path
        )
        self.assertEqual(status, "malformed")

    def test_oversized(self):
        self.root.write("SecureBoot", efivars.GLOBAL_GUID,
                        bytes(efivars.MAX_VARIABLE_SIZE + 1))
        status, _ = efivars.read_variable(
            "SecureBoot", efivars.GLOBAL_GUID, self.root.path
        )
        self.assertEqual(status, "malformed")

    def test_guid_must_match(self):
        self.root.write("SecureBoot", efivars.SHIM_GUID, b"\x01")
        status, _ = efivars.read_variable(
            "SecureBoot", efivars.GLOBAL_GUID, self.root.path
        )
        self.assertEqual(status, "missing")


class FlagTests(FakeRootTestCase):
    """SecureBoot, SetupMode and MokSBStateRT share one reader."""

    READERS = [
        ("SecureBoot", efivars.GLOBAL_GUID, efivars.read_secure_boot),
        ("SetupMode", efivars.GLOBAL_GUID, efivars.read_setup_mode),
        ("MokSBStateRT", efivars.SHIM_GUID, efivars.read_mok_sb_state),
    ]

    def check_each(self, prepare, expected):
        for name, guid, reader in self.READERS:
            with self.subTest(variable=name):
                root = FakeRoot()
                self.addCleanup(root.cleanup)
                prepare(root, name, guid)
                self.assertEqual(reader(root.path), expected)

    def test_on(self):
        self.check_each(
            lambda root, name, guid: root.write(name, guid, b"\x01"),
            {"status": "ok", "value": True},
        )

    def test_off(self):
        self.check_each(
            lambda root, name, guid: root.write(name, guid, b"\x00"),
            {"status": "ok", "value": False},
        )

    def test_missing(self):
        self.check_each(
            lambda root, name, guid: None,
            {"status": "missing", "value": None},
        )

    def test_unreadable(self):
        self.check_each(
            lambda root, name, guid: root.make_unreadable(name, guid),
            {"status": "unreadable", "value": None},
        )

    def test_value_out_of_range(self):
        self.check_each(
            lambda root, name, guid: root.write(name, guid, b"\x02"),
            {"status": "malformed", "value": None},
        )

    def test_wrong_length(self):
        self.check_each(
            lambda root, name, guid: root.write(name, guid, b"\x01\x00"),
            {"status": "malformed", "value": None},
        )

    def test_empty_data(self):
        self.check_each(
            lambda root, name, guid: root.write(name, guid, b""),
            {"status": "malformed", "value": None},
        )


class MokListTests(FakeRootTestCase):
    def write_mok(self, data, name="MokListRT"):
        self.root.write(name, efivars.SHIM_GUID, data, RUNTIME_ONLY)

    def test_realistic_list(self):
        # The layout a Pardus user would get after enrolling a DKMS
        # signing key and one GRUB hash with mokutil: shim's own vendor
        # certificate first, then the user's entries.
        self.write_mok(
            x509_list(FAKE_CERT)
            + x509_list(FAKE_CERT[:600])
            + sha256_list(GRUB_HASH)
        )
        result = efivars.read_mok_list(self.root.path)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["sha256"], [GRUB_HASH.hex()])
        self.assertEqual(result["x509_count"], 2)

    def test_several_hashes_in_one_list(self):
        self.write_mok(sha256_list(GRUB_HASH, KERNEL_HASH))
        result = efivars.read_mok_list(self.root.path)
        self.assertEqual(result["sha256"],
                         [GRUB_HASH.hex(), KERNEL_HASH.hex()])
        self.assertEqual(result["x509_count"], 0)

    def test_signature_header_is_skipped(self):
        self.write_mok(signature_list(
            efivars.CERT_SHA256_GUID, [GRUB_HASH], header=b"\xaa" * 8
        ))
        result = efivars.read_mok_list(self.root.path)
        self.assertEqual(result["sha256"], [GRUB_HASH.hex()])

    def test_unknown_signature_type_is_ignored(self):
        other = uuid.uuid4().bytes_le
        self.write_mok(
            signature_list(other, [b"\x00" * 20]) + sha256_list(GRUB_HASH)
        )
        result = efivars.read_mok_list(self.root.path)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["sha256"], [GRUB_HASH.hex()])

    def test_empty_list(self):
        self.write_mok(b"")
        self.assertEqual(
            efivars.read_mok_list(self.root.path),
            {"status": "ok", "sha256": [], "x509_count": 0},
        )

    def test_split_list_is_joined(self):
        self.write_mok(x509_list(FAKE_CERT))
        self.write_mok(sha256_list(GRUB_HASH), "MokListRT1")
        self.write_mok(sha256_list(KERNEL_HASH), "MokListRT2")
        result = efivars.read_mok_list(self.root.path)
        self.assertEqual(result["sha256"],
                         [GRUB_HASH.hex(), KERNEL_HASH.hex()])
        self.assertEqual(result["x509_count"], 1)

    def test_parts_after_a_gap_are_not_read(self):
        self.write_mok(sha256_list(GRUB_HASH))
        self.write_mok(sha256_list(KERNEL_HASH), "MokListRT2")
        result = efivars.read_mok_list(self.root.path)
        self.assertEqual(result["sha256"], [GRUB_HASH.hex()])

    def test_unreadable_part(self):
        self.write_mok(sha256_list(GRUB_HASH))
        self.root.make_unreadable("MokListRT1", efivars.SHIM_GUID)
        self.assertEqual(efivars.read_mok_list(self.root.path)["status"],
                         "unreadable")

    def test_missing(self):
        self.assertEqual(
            efivars.read_mok_list(self.root.path),
            {"status": "missing", "sha256": None, "x509_count": None},
        )

    def test_unreadable(self):
        self.root.make_unreadable("MokListRT", efivars.SHIM_GUID)
        self.assertEqual(efivars.read_mok_list(self.root.path)["status"],
                         "unreadable")

    def test_truncated_header(self):
        self.write_mok(sha256_list(GRUB_HASH)[:20])
        self.assertEqual(efivars.read_mok_list(self.root.path)["status"],
                         "malformed")

    def test_list_size_past_end(self):
        self.write_mok(sha256_list(GRUB_HASH)[:-1])
        self.assertEqual(efivars.read_mok_list(self.root.path)["status"],
                         "malformed")

    def test_partial_entry(self):
        data = bytearray(sha256_list(GRUB_HASH))
        struct.pack_into("<I", data, 16, len(data) + 4)  # list size
        self.write_mok(bytes(data) + b"\x00" * 4)
        self.assertEqual(efivars.read_mok_list(self.root.path)["status"],
                         "malformed")

    def test_sha256_entry_with_wrong_size(self):
        self.write_mok(signature_list(
            efivars.CERT_SHA256_GUID, [b"\x00" * 20]
        ))
        self.assertEqual(efivars.read_mok_list(self.root.path)["status"],
                         "malformed")

    def test_zero_signature_size_does_not_loop(self):
        data = bytearray(sha256_list(GRUB_HASH))
        struct.pack_into("<I", data, 24, 0)  # signature size
        self.write_mok(bytes(data))
        self.assertEqual(efivars.read_mok_list(self.root.path)["status"],
                         "malformed")


# shim's SBAT_VAR_LATEST has this shape: a header line, then one
# "component,generation" line per revoked component.
REALISTIC_SBAT = b"sbat,1,2024010900\nshim,4\ngrub,3\ngrub.debian,4\n"


class SbatLevelTests(FakeRootTestCase):
    def write_sbat(self, data):
        self.root.write("SbatLevelRT", efivars.SHIM_GUID, data, RUNTIME_ONLY)

    def test_realistic_level(self):
        self.write_sbat(REALISTIC_SBAT)
        self.assertEqual(
            efivars.read_sbat_level(self.root.path),
            {"status": "ok",
             "components": {"shim": 4, "grub": 3, "grub.debian": 4}},
        )

    def test_header_only(self):
        self.write_sbat(b"sbat,1,2021030218\n")
        self.assertEqual(efivars.read_sbat_level(self.root.path),
                         {"status": "ok", "components": {}})

    def test_trailing_nul_and_crlf(self):
        self.write_sbat(b"sbat,1,2022052400\r\ngrub,2\r\n\0")
        self.assertEqual(
            efivars.read_sbat_level(self.root.path)["components"],
            {"grub": 2},
        )

    def test_duplicate_component_keeps_higher_generation(self):
        self.write_sbat(b"sbat,1,2024010900\ngrub,3\ngrub,2\n")
        self.assertEqual(
            efivars.read_sbat_level(self.root.path)["components"],
            {"grub": 3},
        )

    def test_missing(self):
        self.assertEqual(efivars.read_sbat_level(self.root.path),
                         {"status": "missing", "components": None})

    def test_unreadable(self):
        self.root.make_unreadable("SbatLevelRT", efivars.SHIM_GUID)
        self.assertEqual(efivars.read_sbat_level(self.root.path)["status"],
                         "unreadable")

    def test_missing_header(self):
        self.write_sbat(b"shim,4\ngrub,3\n")
        self.assertEqual(efivars.read_sbat_level(self.root.path)["status"],
                         "malformed")

    def test_empty(self):
        self.write_sbat(b"")
        self.assertEqual(efivars.read_sbat_level(self.root.path)["status"],
                         "malformed")

    def test_non_numeric_generation(self):
        self.write_sbat(b"sbat,1,2024010900\ngrub,three\n")
        self.assertEqual(efivars.read_sbat_level(self.root.path)["status"],
                         "malformed")

    def test_not_ascii(self):
        self.write_sbat(b"sbat,1,2024010900\ngr\xfcb,3\n")
        self.assertEqual(efivars.read_sbat_level(self.root.path)["status"],
                         "malformed")


class ReadAllTests(FakeRootTestCase):
    def test_secure_boot_system_with_shim(self):
        root = self.root
        root.write("SecureBoot", efivars.GLOBAL_GUID, b"\x01")
        root.write("SetupMode", efivars.GLOBAL_GUID, b"\x00")
        root.write("MokListRT", efivars.SHIM_GUID,
                   x509_list(FAKE_CERT), RUNTIME_ONLY)
        root.write("SbatLevelRT", efivars.SHIM_GUID,
                   REALISTIC_SBAT, RUNTIME_ONLY)

        result = efivars.read_all(root.path)
        self.assertEqual(
            sorted(result),
            ["MokListRT", "MokSBStateRT", "SbatLevelRT", "SecureBoot",
             "SetupMode"],
        )
        self.assertTrue(result["SecureBoot"]["value"])
        self.assertFalse(result["SetupMode"]["value"])
        # Absent means "validation enabled", but deciding that is
        # collect.py's job; here it is just missing.
        self.assertEqual(result["MokSBStateRT"]["status"], "missing")
        self.assertEqual(result["MokListRT"]["x509_count"], 1)
        self.assertEqual(result["SbatLevelRT"]["components"]["grub"], 3)

    def test_legacy_system_reports_everything_missing(self):
        with tempfile.TemporaryDirectory() as empty_root:
            result = efivars.read_all(empty_root)
        for name, value in result.items():
            with self.subTest(variable=name):
                self.assertEqual(value["status"], "missing")


if __name__ == "__main__":
    unittest.main()

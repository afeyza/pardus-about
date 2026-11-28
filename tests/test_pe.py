"""Tests for util.boothealth.pe.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""

import hashlib
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from util.boothealth import pe  # noqa: E402
from pe_builder import build_pe, sbat_section, vendor_cert_section  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures", "efi")


class SignatureTableTests(unittest.TestCase):
    def test_unsigned_image(self):
        info = pe.parse(build_pe())
        self.assertFalse(info["signed"])
        self.assertEqual(info["signature_count"], 0)

    def test_single_signature(self):
        info = pe.parse(build_pe(signatures=1))
        self.assertTrue(info["signed"])
        self.assertEqual(info["signature_count"], 1)

    def test_dual_signature(self):
        info = pe.parse(build_pe(signatures=2))
        self.assertEqual(info["signature_count"], 2)

    def test_pe32_image(self):
        info = pe.parse(build_pe(signatures=1, pe32_plus=False))
        self.assertTrue(info["signed"])

    def test_non_authenticode_entry_is_not_a_signature(self):
        data = bytearray(build_pe(signatures=1))
        cert_offset = struct.unpack_from("<I", data, 64 + 24 + 112 + 32)[0]
        struct.pack_into("<H", data, cert_offset + 6, 0x0001)  # X.509 type
        self.assertFalse(pe.parse(bytes(data))["signed"])


class SectionTests(unittest.TestCase):
    def test_sbat_is_parsed(self):
        sections = [(".text", b"x" * 10),
                    (".sbat", sbat_section(("grub", 5), ("grub.pardus", 2)))]
        info = pe.parse(build_pe(sections))
        self.assertEqual(info["sbat"], [
            {"component": "sbat", "generation": 1},
            {"component": "grub", "generation": 5},
            {"component": "grub.pardus", "generation": 2},
        ])

    def test_missing_sbat_is_none(self):
        self.assertIsNone(pe.parse(build_pe())["sbat"])

    def test_garbage_sbat_lines_are_skipped(self):
        raw = b"no commas here\ngrub,notanumber,x\nshim,4,x\n"
        sections = [(".sbat", raw)]
        self.assertEqual(pe.parse(build_pe(sections))["sbat"],
                         [{"component": "shim", "generation": 4}])

    def test_vendor_cert_present(self):
        sections = [(".vendor_cert", vendor_cert_section(b"\x30\x82" * 50))]
        self.assertTrue(pe.parse(build_pe(sections))["vendor_cert_present"])

    def test_vendor_cert_empty(self):
        sections = [(".vendor_cert", vendor_cert_section(b""))]
        self.assertFalse(pe.parse(build_pe(sections))["vendor_cert_present"])

    def test_long_section_name_without_string_table(self):
        # "/4" with no string table must not crash; the name stays as is.
        sections = [(".vendor_cert", vendor_cert_section(b"x"))]
        data = bytearray(build_pe(sections))
        struct.pack_into("<I", data, 64 + 4 + 8, 0)  # PointerToSymbolTable
        self.assertIsNone(pe.parse(bytes(data))["vendor_cert_present"])

    def test_vendor_cert_absent_is_none(self):
        self.assertIsNone(pe.parse(build_pe())["vendor_cert_present"])


class AuthenticodeHashTests(unittest.TestCase):
    def test_signing_does_not_change_the_hash(self):
        # Size is a multiple of 8, so signing adds no padding.
        unsigned = build_pe()
        signed = build_pe(signatures=2)
        self.assertEqual(pe.parse(unsigned)["authenticode_sha256"],
                         pe.parse(signed)["authenticode_sha256"])

    def test_differs_from_plain_file_hash(self):
        data = build_pe(signatures=1)
        self.assertNotEqual(pe.parse(data)["authenticode_sha256"],
                            hashlib.sha256(data).hexdigest())

    def test_checksum_field_is_ignored(self):
        data = bytearray(build_pe())
        before = pe.parse(bytes(data))["authenticode_sha256"]
        struct.pack_into("<I", data, 64 + 24 + 64, 0xDEADBEEF)
        self.assertEqual(pe.parse(bytes(data))["authenticode_sha256"], before)

    def test_content_change_changes_the_hash(self):
        data = bytearray(build_pe())
        before = pe.parse(bytes(data))["authenticode_sha256"]
        data[512] ^= 0xFF  # first byte of .text
        after = pe.parse(bytes(data))["authenticode_sha256"]
        self.assertNotEqual(after, before)

    def test_trailing_data_is_hashed(self):
        self.assertNotEqual(
            pe.parse(build_pe(trailing=b"A" * 64))["authenticode_sha256"],
            pe.parse(build_pe(trailing=b"B" * 64))["authenticode_sha256"])

    def test_matches_independent_implementation(self):
        """Cross-check against the LIEF library when it is installed."""
        try:
            import lief
        except ImportError:
            self.skipTest("lief is not installed (pip install lief)")
        lief.logging.disable()
        images = [
            build_pe(),
            build_pe(signatures=1),
            build_pe([(".text", b"a" * 700),
                      (".sbat", sbat_section(("grub", 3)))],
                     signatures=2, trailing=b"T" * 40),
            build_pe([(".text", b"b" * 9),
                      (".vendor_cert", vendor_cert_section(b"c" * 30))]),
            build_pe(pe32_plus=False, signatures=1),
        ]
        for image in images:
            binary = lief.PE.parse(list(image))
            digest = binary.authentihash(lief.PE.ALGORITHMS.SHA_256)
            expected = bytes(digest).hex()
            self.assertEqual(pe.parse(image)["authenticode_sha256"], expected)


class MalformedInputTests(unittest.TestCase):
    def assertMalformed(self, data):
        with self.assertRaises(pe.PEError):
            pe.parse(bytes(data))

    def test_empty_file(self):
        self.assertMalformed(b"")

    def test_not_a_pe_file(self):
        self.assertMalformed(b"#!/bin/sh\necho hello\n" * 10)

    def test_bad_pe_signature(self):
        data = bytearray(build_pe())
        data[64:68] = b"XX\0\0"
        self.assertMalformed(data)

    def test_truncated_headers(self):
        self.assertMalformed(build_pe()[:100])

    def test_pe_offset_outside_file(self):
        data = bytearray(build_pe())
        struct.pack_into("<I", data, 0x3C, 0x7FFFFFFF)
        self.assertMalformed(data)

    def test_unknown_optional_header_magic(self):
        data = bytearray(build_pe())
        struct.pack_into("<H", data, 64 + 24, 0x1234)
        self.assertMalformed(data)

    def test_certificate_table_outside_file(self):
        data = build_pe(signatures=1)
        self.assertMalformed(data[:-16])

    def test_corrupt_certificate_entry_length(self):
        data = bytearray(build_pe(signatures=1))
        cert_offset = struct.unpack_from("<I", data, 64 + 24 + 112 + 32)[0]
        struct.pack_into("<I", data, cert_offset, 4)  # shorter than its header
        self.assertMalformed(data)

    def test_section_outside_file(self):
        data = build_pe()
        self.assertMalformed(data[:600])


class InspectFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name, data):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_ok(self):
        result = pe.inspect_file(self._write("a.efi", build_pe(signatures=1)))
        self.assertEqual(result["status"], pe.STATUS_OK)
        self.assertTrue(result["pe"]["signed"])

    def test_missing(self):
        result = pe.inspect_file(os.path.join(self.tmp.name, "nope.efi"))
        self.assertEqual(result, {"status": pe.STATUS_MISSING, "pe": None})

    def test_unreadable(self):
        # A directory can not be opened for reading: same code path as EACCES.
        result = pe.inspect_file(self.tmp.name)
        self.assertEqual(result, {"status": pe.STATUS_UNREADABLE, "pe": None})

    def test_malformed(self):
        result = pe.inspect_file(self._write("bad.efi", b"not a pe file"))
        self.assertEqual(result, {"status": pe.STATUS_MALFORMED, "pe": None})


class RealFileTests(unittest.TestCase):
    """Run only when the files extracted from the Pardus ISO are present.

    Put them in tests/fixtures/efi/ (see docs/mimari.md).
    """

    def _inspect(self, name):
        path = os.path.join(FIXTURES, name)
        if not os.path.exists(path):
            self.skipTest("{} not found in tests/fixtures/efi".format(name))
        result = pe.inspect_file(path)
        self.assertEqual(result["status"], pe.STATUS_OK)
        return result["pe"]

    def test_iso_grub_is_unsigned(self):
        info = self._inspect("grubx64.efi")
        self.assertFalse(info["signed"])

    def test_iso_shim_is_signed(self):
        info = self._inspect("bootx64.efi")
        self.assertTrue(info["signed"])
        self.assertTrue(info["vendor_cert_present"])
        self.assertIsNotNone(info["sbat"])


if __name__ == "__main__":
    unittest.main()

"""Builds small synthetic PE images for the tests.

The images are not runnable; they only have the structure pe.py reads:
DOS header, COFF header, optional header, section table, section data
and an optional certificate table.
"""

import struct

FILE_ALIGNMENT = 512


def _align(value, boundary):
    return (value + boundary - 1) // boundary * boundary


def build_pe(sections=None, signatures=0, trailing=b"", pe32_plus=True):
    """Return the bytes of a synthetic PE image.

    sections   -- list of (name, data) tuples
    signatures -- number of fake Authenticode entries to append
    trailing   -- extra bytes placed after the last section
    pe32_plus  -- True for PE32+ (x86_64), False for PE32
    """
    if sections is None:
        sections = [(".text", b"\x90" * 100)]

    opt_size = 240 if pe32_plus else 224
    dirs_offset = 112 if pe32_plus else 96
    pe_offset = 64
    opt_offset = pe_offset + 4 + 20
    table_offset = opt_offset + opt_size
    headers_size = _align(table_offset + 40 * len(sections), FILE_ALIGNMENT)

    # Lay out the section data. Names longer than 8 bytes go into a COFF
    # string table and are referenced as "/<offset>", as binutils does.
    body = b""
    table = b""
    strings = b""
    for name, data in sections:
        raw_offset = headers_size + len(body)
        raw = data.ljust(_align(len(data), FILE_ALIGNMENT), b"\0")
        short_name = name.encode("ascii")
        if len(short_name) > 8:
            short_name = "/{}".format(4 + len(strings)).encode("ascii")
            strings += name.encode("ascii") + b"\0"
        table += struct.pack(
            "<8sIIIIIIHHI",
            short_name, len(data), 0x1000, len(raw), raw_offset,
            0, 0, 0, 0, 0,
        )
        body += raw

    strtab_offset = 0
    if strings:
        strtab_offset = headers_size + len(body)
        body += struct.pack("<I", 4 + len(strings)) + strings
    body += trailing

    # Certificate table: WIN_CERTIFICATE entries, 8-byte aligned.
    certs = b""
    for i in range(signatures):
        payload = bytes([0x30, 0x82, i]) * 20  # not a real PKCS#7 blob
        entry = struct.pack("<IHH", 8 + len(payload), 0x0200, 0x0002) + payload
        certs += entry.ljust(_align(len(entry), 8), b"\0")

    unsigned_size = headers_size + len(body)
    if certs:
        pad = _align(unsigned_size, 8) - unsigned_size
        body += b"\0" * pad
        unsigned_size += pad

    dos = b"MZ".ljust(0x3C, b"\0") + struct.pack("<I", pe_offset)
    coff = struct.pack(
        "<HHIIIHH", 0x8664 if pe32_plus else 0x014C, len(sections),
        0, strtab_offset, 0, opt_size, 0x0022,
    )

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if pe32_plus else 0x10B)
    struct.pack_into("<I", opt, 60, headers_size)
    struct.pack_into("<I", opt, 64, 0)  # checksum
    struct.pack_into("<I", opt, dirs_offset - 4, 16)
    if certs:
        struct.pack_into(
            "<II", opt, dirs_offset + 4 * 8, unsigned_size, len(certs))

    headers = dos + b"PE\0\0" + coff + bytes(opt) + table
    return headers.ljust(headers_size, b"\0") + body + certs


def sbat_section(*entries):
    """Build .sbat content from (component, generation) tuples."""
    lines = ["sbat,1,SBAT Version,sbat,1,"
             "https://github.com/rhboot/shim/blob/main/SBAT.md"]
    for component, generation in entries:
        lines.append("{},{},Vendor,{},1.0,https://example.org".format(
            component, generation, component))
    return ("\n".join(lines) + "\n").encode("utf-8")


def vendor_cert_section(cert=b""):
    """Build shim's .vendor_cert section around a certificate blob."""
    return struct.pack("<IIII", len(cert), 0, 16, 16 + len(cert)) + cert

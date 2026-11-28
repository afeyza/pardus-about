"""Read-only PE/COFF parser for EFI boot binaries (shim, GRUB, kernel).

Pure Python, standard library only. Nothing here verifies a signature
cryptographically: "signed" means "an Authenticode signature is present
in the certificate table", nothing more.

Public API:
    parse(data)         -> dict, raises PEError on a malformed file
    inspect_file(path)  -> {"status": ..., "pe": dict or None}, never raises
"""

import hashlib
import struct

# Largest file we are willing to read. shim, GRUB and distro kernels are
# far below this; the limit only protects the privileged helper.
MAX_FILE_SIZE = 128 * 1024 * 1024

PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B

CERT_TABLE_INDEX = 4  # IMAGE_DIRECTORY_ENTRY_SECURITY
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_UNREADABLE = "unreadable"
STATUS_MALFORMED = "malformed"


class PEError(Exception):
    """The file is not a PE image we can parse."""


def _unpack(fmt, data, offset):
    """struct.unpack_from with a bounds check that raises PEError."""
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise PEError(
            "truncated file (need {} bytes at {})".format(size, offset)
        )
    return struct.unpack_from(fmt, data, offset)


def _section_name(data, raw_name, strtab_offset):
    """Decode a section name.

    Names longer than 8 bytes (".vendor_cert", ".sbatlevel") are stored
    as "/<decimal offset>" pointing into the COFF string table.
    """
    name = raw_name.rstrip(b"\0").decode("ascii", "replace")
    if not name.startswith("/") or not strtab_offset:
        return name
    try:
        start = strtab_offset + int(name[1:])
    except ValueError:
        return name
    end = data.find(b"\0", start, start + 256)
    if start >= len(data) or end == -1:
        return name
    return data[start:end].decode("ascii", "replace")


def _parse_headers(data):
    """Locate the headers. Returns a dict of offsets and the section list."""
    if data[:2] != b"MZ":
        raise PEError("missing MZ header")

    (pe_offset,) = _unpack("<I", data, 0x3C)
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise PEError("missing PE signature")

    coff = pe_offset + 4
    fields = _unpack("<HHIIIHH", data, coff)
    section_count, opt_size = fields[1], fields[5]
    symtab_offset, symbol_count = fields[3], fields[4]
    # Long section names live in the COFF string table, right after the
    # symbol table (18 bytes per symbol).
    strtab_offset = symtab_offset + symbol_count * 18 if symtab_offset else 0

    opt = coff + 20
    (magic,) = _unpack("<H", data, opt)
    if magic == PE32_PLUS_MAGIC:
        dirs_offset = opt + 112
    elif magic == PE32_MAGIC:
        dirs_offset = opt + 96
    else:
        raise PEError("unknown optional header magic 0x{:x}".format(magic))

    (headers_size,) = _unpack("<I", data, opt + 60)
    (dir_count,) = _unpack("<I", data, dirs_offset - 4)

    # The certificate table entry is special: its first field is a plain
    # file offset, not a virtual address.
    cert_entry = dirs_offset + CERT_TABLE_INDEX * 8
    cert_offset, cert_size = 0, 0
    if dir_count > CERT_TABLE_INDEX:
        cert_offset, cert_size = _unpack("<II", data, cert_entry)
        if cert_size and cert_offset + cert_size > len(data):
            raise PEError("certificate table points outside the file")

    sections = []
    table = opt + opt_size
    for i in range(section_count):
        entry = table + i * 40
        (raw_name,) = _unpack("<8s", data, entry)
        virtual_size, _, raw_size, raw_offset = _unpack(
            "<IIII", data, entry + 8
        )
        if raw_size and raw_offset + raw_size > len(data):
            raise PEError("section points outside the file")
        sections.append({
            "name": _section_name(data, raw_name, strtab_offset),
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
        })

    return {
        "checksum_offset": opt + 64,
        "cert_entry_offset": cert_entry,
        "has_cert_entry": dir_count > CERT_TABLE_INDEX,
        "cert_offset": cert_offset,
        "cert_size": cert_size,
        "headers_size": headers_size,
        "sections": sections,
    }


def _count_signatures(data, headers):
    """Walk the WIN_CERTIFICATE entries and count Authenticode signatures."""
    count = 0
    pos = headers["cert_offset"]
    end = pos + headers["cert_size"]
    while pos + 8 <= end:
        length, _revision, cert_type = _unpack("<IHH", data, pos)
        if length < 8 or pos + length > end:
            raise PEError("corrupt certificate table entry")
        if cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA and length > 8:
            count += 1
        pos += (length + 7) & ~7  # entries are 8-byte aligned
    return count


def _section_data(data, headers, name):
    """Raw bytes of the named section, or None when it does not exist."""
    for section in headers["sections"]:
        if section["name"] == name:
            size = section["raw_size"]
            if section["virtual_size"]:
                size = min(size, section["virtual_size"])
            start = section["raw_offset"]
            return data[start:start + size]
    return None


def _parse_sbat(raw):
    """Parse the .sbat CSV into [{"component": str, "generation": int}]."""
    if raw is None:
        return None
    entries = []
    text = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
    for line in text.splitlines():
        fields = line.strip().split(",")
        if len(fields) < 2:
            continue
        try:
            generation = int(fields[1])
        except ValueError:
            continue
        entries.append({"component": fields[0], "generation": generation})
    return entries


def _vendor_cert_present(raw):
    """shim keeps its embedded vendor certificate in .vendor_cert.

    The section starts with four little-endian u32 values; the first is
    the size of the authorized (trusted) certificate data.
    """
    if raw is None:
        return None
    if len(raw) < 16:
        return False
    (authorized_size,) = struct.unpack_from("<I", raw, 0)
    return authorized_size > 0


def authenticode_sha256(data, headers=None):
    """SHA-256 Authenticode digest of a PE image, as a hex string.

    This is the digest shim compares against MOK hash entries. It is not
    the plain file hash: the checksum field, the certificate table entry
    and the certificate table itself are left out.
    """
    if headers is None:
        headers = _parse_headers(data)

    digest = hashlib.sha256()
    checksum = headers["checksum_offset"]
    cert_entry = headers["cert_entry_offset"]
    headers_end = headers["headers_size"]
    if headers_end > len(data):
        raise PEError("header size is larger than the file")

    # 1. Headers, skipping the checksum and the certificate table entry.
    digest.update(data[:checksum])
    if headers["has_cert_entry"]:
        digest.update(data[checksum + 4:cert_entry])
        digest.update(data[cert_entry + 8:headers_end])
    else:
        digest.update(data[checksum + 4:headers_end])

    # 2. Section contents, in file order.
    hashed = headers_end
    for section in sorted(headers["sections"], key=lambda s: s["raw_offset"]):
        if section["raw_size"] == 0:
            continue
        start = section["raw_offset"]
        digest.update(data[start:start + section["raw_size"]])
        hashed += section["raw_size"]

    # 3. Anything after the sections, except the certificate table.
    tail_end = len(data) - headers["cert_size"]
    if tail_end > hashed:
        digest.update(data[hashed:tail_end])

    return digest.hexdigest()


def parse(data):
    """Parse a PE image held in memory. Raises PEError when malformed."""
    headers = _parse_headers(data)
    signature_count = _count_signatures(data, headers)
    return {
        "signed": signature_count > 0,
        "signature_count": signature_count,
        "authenticode_sha256": authenticode_sha256(data, headers),
        "sbat": _parse_sbat(_section_data(data, headers, ".sbat")),
        "vendor_cert_present": _vendor_cert_present(
            _section_data(data, headers, ".vendor_cert")
        ),
    }


def inspect_file(path):
    """Read and parse one file. Never raises; the outcome is in "status"."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_FILE_SIZE + 1)
    except FileNotFoundError:
        return {"status": STATUS_MISSING, "pe": None}
    except OSError:
        return {"status": STATUS_UNREADABLE, "pe": None}

    if len(data) > MAX_FILE_SIZE:
        return {"status": STATUS_MALFORMED, "pe": None}

    try:
        return {"status": STATUS_OK, "pe": parse(data)}
    except PEError:
        return {"status": STATUS_MALFORMED, "pe": None}

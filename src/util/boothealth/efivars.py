"""Read-only access to the UEFI variables the boot health check needs.

Reads files under /sys/firmware/efi/efivars, which an unprivileged user
can read. Standard library only, nothing is ever written.

This module reports what it found, not what it means. A missing
variable is reported as "missing"; deciding that a missing MokSBStateRT
means "shim validation is enabled" is collect.py's job.

Public API:
    read_variable(name, guid, root="/")  -> (status, data or None)
    read_secure_boot(root="/")           -> {"status", "value"}
    read_setup_mode(root="/")            -> {"status", "value"}
    read_mok_sb_state(root="/")          -> {"status", "value"}
    read_mok_list(root="/")              -> {"status", "sha256", "x509_count"}
    read_sbat_level(root="/")            -> {"status", "components"}
    read_all(root="/")                   -> dict of the five results above

None of these raise. "status" is one of ok, missing, unreadable,
malformed (the same values pe.inspect_file uses). Every other field is
None unless status is ok.
"""

import os
import struct
import uuid

from .pe import STATUS_MALFORMED, STATUS_MISSING, STATUS_OK, \
    STATUS_UNREADABLE

EFIVARS_DIR = os.path.join("sys", "firmware", "efi", "efivars")

# EFI_GLOBAL_VARIABLE: SecureBoot, SetupMode.
GLOBAL_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
# SHIM_LOCK_GUID: the *RT variables shim mirrors for the running OS.
SHIM_GUID = "605dab50-e046-4300-abb6-3dd810dd8b23"

# Signature types inside an EFI_SIGNATURE_LIST.
CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328").bytes_le
CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").bytes_le

# Every efivarfs file starts with a 4-byte attribute field.
ATTRIBUTE_SIZE = 4

# Largest variable we are willing to read. Real MOK lists are a few
# kilobytes; the limit only protects against a corrupt variable.
MAX_VARIABLE_SIZE = 1024 * 1024

# shim splits a large MokListRT into MokListRT, MokListRT1, MokListRT2...
MAX_MOK_LIST_PARTS = 64

ESL_HEADER = struct.Struct("<16sIII")  # type, list size, header size, size
SHA256_SIZE = 32
OWNER_GUID_SIZE = 16


class _Malformed(Exception):
    """The variable exists but its content does not follow its format."""


def read_variable(name, guid, root="/"):
    """Return (status, data). data excludes the attribute field."""
    path = os.path.join(root, EFIVARS_DIR, "{}-{}".format(name, guid))
    try:
        with open(path, "rb") as f:
            raw = f.read(ATTRIBUTE_SIZE + MAX_VARIABLE_SIZE + 1)
    except FileNotFoundError:
        return STATUS_MISSING, None
    except OSError:
        return STATUS_UNREADABLE, None

    if len(raw) < ATTRIBUTE_SIZE:
        return STATUS_MALFORMED, None
    if len(raw) > ATTRIBUTE_SIZE + MAX_VARIABLE_SIZE:
        return STATUS_MALFORMED, None
    return STATUS_OK, raw[ATTRIBUTE_SIZE:]


def _read_flag(name, guid, root):
    """A one-byte variable whose value is 0 or 1."""
    status, data = read_variable(name, guid, root)
    if status != STATUS_OK:
        return {"status": status, "value": None}
    if len(data) != 1 or data[0] not in (0, 1):
        return {"status": STATUS_MALFORMED, "value": None}
    return {"status": STATUS_OK, "value": data[0] == 1}


def read_secure_boot(root="/"):
    return _read_flag("SecureBoot", GLOBAL_GUID, root)


def read_setup_mode(root="/"):
    return _read_flag("SetupMode", GLOBAL_GUID, root)


def read_mok_sb_state(root="/"):
    """value True means shim's signature validation is disabled."""
    return _read_flag("MokSBStateRT", SHIM_GUID, root)


def parse_signature_lists(data):
    """Parse a sequence of EFI_SIGNATURE_LIST structures.

    Returns {"sha256": [hex, ...], "x509_count": int}. Other signature
    types are skipped. Raises _Malformed if the structure is broken.
    """
    sha256 = []
    x509_count = 0
    offset = 0
    while offset < len(data):
        if offset + ESL_HEADER.size > len(data):
            raise _Malformed("truncated signature list header")
        sig_type, list_size, header_size, sig_size = \
            ESL_HEADER.unpack_from(data, offset)

        body_start = offset + ESL_HEADER.size + header_size
        list_end = offset + list_size
        if list_size < ESL_HEADER.size + header_size or list_end > len(data):
            raise _Malformed("signature list size out of range")
        if sig_size <= OWNER_GUID_SIZE:
            raise _Malformed("signature entry too small")
        if (list_end - body_start) % sig_size:
            raise _Malformed("signature list is not a whole number of entries")

        if sig_type == CERT_SHA256_GUID:
            if sig_size != OWNER_GUID_SIZE + SHA256_SIZE:
                raise _Malformed("SHA-256 entry has the wrong size")
            for entry in range(body_start, list_end, sig_size):
                digest = data[entry + OWNER_GUID_SIZE:entry + sig_size]
                sha256.append(digest.hex())
        elif sig_type == CERT_X509_GUID:
            x509_count += (list_end - body_start) // sig_size

        offset = list_end
    return {"sha256": sha256, "x509_count": x509_count}


def _read_mok_list_data(root):
    """Join MokListRT, MokListRT1, MokListRT2... into one byte string."""
    status, data = read_variable("MokListRT", SHIM_GUID, root)
    if status != STATUS_OK:
        return status, None

    parts = [data]
    for index in range(1, MAX_MOK_LIST_PARTS):
        status, data = read_variable(
            "MokListRT{}".format(index), SHIM_GUID, root
        )
        if status == STATUS_MISSING:
            break
        if status != STATUS_OK:
            return status, None
        parts.append(data)
    return STATUS_OK, b"".join(parts)


def read_mok_list(root="/"):
    """SHA-256 hashes and the number of certificates enrolled in MOK."""
    status, data = _read_mok_list_data(root)
    if status != STATUS_OK:
        return {"status": status, "sha256": None, "x509_count": None}
    try:
        parsed = parse_signature_lists(data)
    except _Malformed:
        return {"status": STATUS_MALFORMED, "sha256": None,
                "x509_count": None}
    return {"status": STATUS_OK, "sha256": parsed["sha256"],
            "x509_count": parsed["x509_count"]}


def parse_sbat_level(data):
    """Parse SbatLevelRT text into {component: generation}.

    The first line is the "sbat,1,<date>" header; every other line is
    "<component>,<generation>". If a component appears twice the higher
    generation wins, since that is the stricter revocation.
    Raises _Malformed if the text does not follow this format.
    """
    try:
        text = data.rstrip(b"\0").decode("ascii")
    except UnicodeDecodeError:
        raise _Malformed("not ASCII text")

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or not lines[0].startswith("sbat,"):
        raise _Malformed("missing sbat header line")

    components = {}
    for line in lines[1:]:
        fields = line.split(",")
        if len(fields) < 2 or not fields[0]:
            raise _Malformed("bad line: {}".format(line))
        try:
            generation = int(fields[1])
        except ValueError:
            raise _Malformed("bad generation: {}".format(line))
        name = fields[0]
        components[name] = max(generation, components.get(name, generation))
    return components


def read_sbat_level(root="/"):
    """Minimum generation shim accepts for each component."""
    status, data = read_variable("SbatLevelRT", SHIM_GUID, root)
    if status != STATUS_OK:
        return {"status": status, "components": None}
    try:
        components = parse_sbat_level(data)
    except _Malformed:
        return {"status": STATUS_MALFORMED, "components": None}
    return {"status": STATUS_OK, "components": components}


def read_all(root="/"):
    """Every variable the boot health check uses, keyed by variable name."""
    return {
        "SecureBoot": read_secure_boot(root),
        "SetupMode": read_setup_mode(root),
        "MokSBStateRT": read_mok_sb_state(root),
        "MokListRT": read_mok_list(root),
        "SbatLevelRT": read_sbat_level(root),
    }

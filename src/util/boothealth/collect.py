"""Build the boot health state object from everything readable without root.

Fills every field of the state object in docs/mimari.md except "esp",
which comes from the privileged helper (BootHealthHelper.py) and is
merged in by the caller. Standard library only; no subprocess, nothing
is written.

This is where raw readings get their meaning. The rule throughout:
write true or false only when the reading settles the question, null
otherwise. rules.py turns a null into "this check could not be done",
never into a warning.

Public API:
    collect(root="/", kernel_release=None) -> state object (dict)
"""

import os
import platform

from . import efivars, pe

SCHEMA_VERSION = 1

EFI_DIR = os.path.join("sys", "firmware", "efi")
CMDLINE = os.path.join("proc", "cmdline")
DPKG_STATUS = os.path.join("var", "lib", "dpkg", "status")
BOOT_DIR = "boot"
LIVE_KERNEL_DIR = os.path.join("run", "live", "medium", "live")

# Debian package names; Pardus 25.2 is expected to use the same ones
# (to be confirmed on an installed system, #7).
PACKAGES = ("shim-signed", "grub-efi-amd64-signed")

# dpkg's status file is a few megabytes at most.
MAX_DPKG_STATUS_SIZE = 64 * 1024 * 1024


def _join(root, relative):
    return os.path.join(root, relative)


def _system_path(relative):
    """The path as the user would see it on the running system."""
    return "/" + relative.replace(os.sep, "/")


def _flag(reading, when_missing):
    """Turn an efivars flag reading into true, false or null."""
    if reading["status"] == efivars.STATUS_OK:
        return reading["value"]
    if reading["status"] == efivars.STATUS_MISSING:
        return when_missing
    return None


def is_live_session(root="/"):
    """True on a Debian live system (boot=live), null if unknown."""
    try:
        with open(_join(root, CMDLINE), "r", encoding="ascii",
                  errors="replace") as f:
            cmdline = f.read(64 * 1024)
    except OSError:
        return None
    return "boot=live" in cmdline.split()


def collect_firmware(root, variables):
    return {
        "uefi": os.path.isdir(_join(root, EFI_DIR)),
        # SecureBoot and SetupMode are standard since UEFI 2.3.1. If they
        # are absent the firmware has no Secure Boot, so it is off.
        "secure_boot": _flag(variables["SecureBoot"], False),
        "setup_mode": _flag(variables["SetupMode"], False),
    }


def collect_shim(variables):
    mok_list = variables["MokListRT"]
    sbat_level = variables["SbatLevelRT"]

    # shim always creates MokListRT when it boots the system. Without
    # shim in the chain a missing MokSBStateRT tells us nothing.
    shim_booted = mok_list["status"] == efivars.STATUS_OK
    return {
        "validation_disabled": _flag(
            variables["MokSBStateRT"], False if shim_booted else None
        ),
        "mok_hashes": mok_list["sha256"] if shim_booted else None,
        # Missing here means a shim older than SBAT: we cannot compare.
        "sbat_level": sbat_level["components"]
        if sbat_level["status"] == efivars.STATUS_OK else None,
    }


def _live_kernel(root):
    """Relative path of the kernel on a live medium, or None."""
    directory = _join(root, LIVE_KERNEL_DIR)
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return None
    if "vmlinuz" in names:
        return os.path.join(LIVE_KERNEL_DIR, "vmlinuz")
    for name in names:
        if name.startswith("vmlinuz"):
            return os.path.join(LIVE_KERNEL_DIR, name)
    return None


def collect_kernel(root, kernel_release, live_session):
    """Signature status of the kernel the system is running."""
    relative = None
    if live_session:
        relative = _live_kernel(root)
    if relative is None:
        relative = os.path.join(BOOT_DIR, "vmlinuz-" + kernel_release)

    result = pe.inspect_file(_join(root, relative))
    return {
        "path": _system_path(relative),
        "status": result["status"],
        "pe": result["pe"],
    }


def parse_dpkg_status(text, wanted):
    """Return {package: installed?} for each wanted package."""
    installed = {name: False for name in wanted}
    for stanza in text.split("\n\n"):
        package = status = None
        for line in stanza.splitlines():
            if line.startswith("Package:"):
                package = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                status = line.split(":", 1)[1].split()
        # "install ok installed": the last word is the current state.
        if package in installed and status and status[-1] == "installed":
            installed[package] = True
    return installed


def collect_packages(root):
    try:
        with open(_join(root, DPKG_STATUS), "r", encoding="utf-8",
                  errors="replace") as f:
            text = f.read(MAX_DPKG_STATUS_SIZE + 1)
    except OSError:
        return {name: None for name in PACKAGES}
    if len(text) > MAX_DPKG_STATUS_SIZE:
        return {name: None for name in PACKAGES}
    return parse_dpkg_status(text, PACKAGES)


def collect(root="/", kernel_release=None):
    """The state object, with "esp" left as None for the helper to fill."""
    if kernel_release is None:
        kernel_release = platform.release()

    variables = efivars.read_all(root)
    live_session = is_live_session(root)
    return {
        "schema": SCHEMA_VERSION,
        "live_session": live_session,
        "firmware": collect_firmware(root, variables),
        "shim": collect_shim(variables),
        "kernel": collect_kernel(root, kernel_release, live_session),
        "packages": collect_packages(root),
        "esp": None,
    }

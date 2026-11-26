#!/usr/bin/python3
"""Privileged helper of the Boot Health module.

Run by the GUI through pkexec (polkit action
tr.org.pardus.pkexec.pardus-about.boot-health). It reads the boot files
on the EFI system partition, parses them with pe.py and prints the
"esp" part of the state object (docs/mimari.md) as JSON on stdout.

Rules this file must keep (docs/mimari.md, decision 4):
    - It takes no parameters. Anything on the command line is ignored;
      the paths below are fixed.
    - It writes nothing to disk. Files are only opened for reading and
      Python is told not to write .pyc files.
    - The exit code is always 0. A non-zero code therefore always comes
      from pkexec itself (126: dialog dismissed, 127: not authorized).
"""

import sys

# Must be set before importing our own modules, otherwise Python running
# as root would write __pycache__ directories next to them.
sys.dont_write_bytecode = True

import json  # noqa: E402
import os  # noqa: E402

from util.boothealth import pe  # noqa: E402

ESP_PATH = "/boot/efi"

# (role, path relative to ESP_PATH). The ESP is FAT, so case does not
# matter on a real system.
ESP_FILES = (
    ("shim", "EFI/pardus/shimx64.efi"),
    ("grub", "EFI/pardus/grubx64.efi"),
    ("fallback", "EFI/BOOT/BOOTX64.EFI"),
)

ERROR_ESP_NOT_MOUNTED = "esp_not_mounted"


def collect_esp(esp_path):
    """Return the "esp" object of the state object for esp_path."""
    mounted = os.path.ismount(esp_path)
    errors = []
    if not mounted:
        # Without the partition, the directory may still hold stale files
        # from the root file system. Do not read them.
        errors.append(ERROR_ESP_NOT_MOUNTED)

    files = []
    for role, relative_path in ESP_FILES:
        path = os.path.join(esp_path, relative_path)
        if mounted:
            result = pe.inspect_file(path)
        else:
            result = {"status": pe.STATUS_UNREADABLE, "pe": None}
        files.append({
            "role": role,
            "path": path,
            "status": result["status"],
            "pe": result["pe"],
        })

    return {"path": esp_path, "files": files, "errors": errors}


def main():
    # sys.argv is deliberately not read.
    print(json.dumps(collect_esp(ESP_PATH)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

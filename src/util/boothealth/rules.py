"""Rule engine: turn a state object into a list of findings.

Input is the state object of docs/mimari.md (collect.py plus the
helper's "esp" field). Output is the rule engine result described in the
same document. No text is produced here; messages.py maps finding ids to
translatable messages.

The one principle this module exists to enforce: a value that could not
be read (null) never produces a warning. It produces check_unavailable
(or esp_not_checked when the user did not grant access), which tells the
user the result was given without that check.

Public API:
    evaluate(state) -> {"live_session", "overall", "findings"}
"""

LEVEL_OK = "ok"
LEVEL_INFO = "info"
LEVEL_WARNING = "warning"
LEVEL_ORDER = {LEVEL_OK: 0, LEVEL_INFO: 1, LEVEL_WARNING: 2}

EVIDENCE_ABSENT = "signature_absent"
EVIDENCE_PRESENT = "signature_present"
EVIDENCE_BOOTED = "booted_with_secure_boot"
EVIDENCE_STATE = "state"

# Finding id -> (level, evidence). docs/mimari.md, "Bulgu kimlikleri".
FINDINGS = {
    "legacy_boot": (LEVEL_INFO, EVIDENCE_STATE),
    "sb_off_chain_signed": (LEVEL_INFO, EVIDENCE_PRESENT),
    "sb_off_grub_unsigned": (LEVEL_WARNING, EVIDENCE_ABSENT),
    "sb_off_kernel_unsigned": (LEVEL_WARNING, EVIDENCE_ABSENT),
    "sb_on_chain_ok": (LEVEL_OK, EVIDENCE_BOOTED),
    "sb_on_grub_mok_hash": (LEVEL_INFO, EVIDENCE_BOOTED),
    "sb_on_grub_changed": (LEVEL_WARNING, EVIDENCE_ABSENT),
    "sb_on_kernel_unsigned": (LEVEL_WARNING, EVIDENCE_ABSENT),
    "shim_validation_disabled": (LEVEL_WARNING, EVIDENCE_STATE),
    "setup_mode": (LEVEL_WARNING, EVIDENCE_STATE),
    "grub_sbat_revoked": (LEVEL_WARNING, EVIDENCE_STATE),
    "esp_not_checked": (LEVEL_INFO, None),
    "check_unavailable": (LEVEL_INFO, None),
}

# Values of the "variant" field of shim_validation_disabled (decision 5:
# the engine picks the advice, the user is not offered a choice).
VARIANT_CHAIN_SIGNED = "chain_signed"      # turn validation back on
VARIANT_CHAIN_UNSIGNED = "chain_unsigned"  # leave it as it is
# None: we could not tell; messages.py must show the cautious advice.


class _Findings:
    """Collects findings; check_unavailable appears once per subject."""

    def __init__(self):
        self.items = []
        self._subjects = set()
        self._esp_reported = False

    def add(self, finding_id, **extra):
        level, evidence = FINDINGS[finding_id]
        finding = {"id": finding_id, "level": level, "evidence": evidence}
        finding.update(extra)
        self.items.append(finding)

    def unavailable(self, subject):
        if subject not in self._subjects:
            self._subjects.add(subject)
            self.add("check_unavailable", subject=subject)

    def esp_not_checked(self):
        if not self._esp_reported:
            self._esp_reported = True
            self.add("esp_not_checked")


class _Boot:
    """The parts of the state object the rules look at, read once.

    A signature value is True, False, or None (unknown). When it is None,
    reason_<name> says why: "esp" (the user did not grant access) or the
    subject to report in check_unavailable.
    """

    def __init__(self, state):
        firmware = state.get("firmware") or {}
        shim = state.get("shim") or {}
        self.uefi = firmware.get("uefi")
        self.secure_boot = firmware.get("secure_boot")
        self.setup_mode = firmware.get("setup_mode")
        self.validation_disabled = shim.get("validation_disabled")
        self.mok_hashes = shim.get("mok_hashes")
        self.sbat_level = shim.get("sbat_level")

        self.esp = state.get("esp")
        self.kernel_pe = _pe_of(state.get("kernel"))
        self.grub_pe = self._esp_pe("grub")
        self.shim_pe = self._esp_pe("shim")

    def _esp_pe(self, role):
        if self.esp is None:
            return None
        for entry in self.esp.get("files") or []:
            if entry.get("role") == role:
                return _pe_of(entry)
        return None

    def signed(self, name):
        """(True/False/None, reason) for "kernel", "grub" or "shim"."""
        info = getattr(self, name + "_pe")
        if info is not None:
            return info.get("signed"), None
        if name != "kernel" and self.esp is None:
            return None, "esp"
        return None, name


def _pe_of(entry):
    """The pe object of a kernel or ESP file entry, if it was parsed."""
    if not entry or entry.get("status") != "ok":
        return None
    return entry.get("pe")


def _report_unknown(findings, reason):
    if reason == "esp":
        findings.esp_not_checked()
    elif reason is not None:
        findings.unavailable(reason)


def _secure_boot_off(boot, findings):
    results = {name: boot.signed(name) for name in ("shim", "grub", "kernel")}

    if results["grub"][0] is False:
        findings.add("sb_off_grub_unsigned")
    if results["kernel"][0] is False:
        findings.add("sb_off_kernel_unsigned")

    unknown = [name for name, (value, _) in results.items() if value is None]
    for name in unknown:
        _report_unknown(findings, results[name][1])

    if all(value is True for value, _ in results.values()):
        findings.add("sb_off_chain_signed")


def _secure_boot_on(boot, findings):
    if boot.validation_disabled is True:
        # shim did not verify anything, so "booted with Secure Boot" is no
        # evidence about the chain. shim_validation_disabled covers it.
        return

    kernel, kernel_reason = boot.signed("kernel")
    grub, grub_reason = boot.signed("grub")

    if kernel is False:
        findings.add("sb_on_kernel_unsigned")
    elif kernel is None:
        _report_unknown(findings, kernel_reason)

    if grub is None:
        # Without GRUB we cannot claim the chain is fine (decision 1).
        _report_unknown(findings, grub_reason)
        return

    if grub is False:
        if boot.mok_hashes is None:
            findings.unavailable("MokListRT")
            return
        digest = boot.grub_pe.get("authenticode_sha256")
        if digest is not None and digest.lower() in boot.mok_hashes:
            findings.add("sb_on_grub_mok_hash")
        else:
            findings.add("sb_on_grub_changed")
        return

    if kernel is True:
        findings.add("sb_on_chain_ok")


def _chain_variant(boot):
    grub, _ = boot.signed("grub")
    kernel, _ = boot.signed("kernel")
    if grub is True and kernel is True:
        return VARIANT_CHAIN_SIGNED
    if grub is False or kernel is False:
        return VARIANT_CHAIN_UNSIGNED
    return None


def _independent(boot, findings):
    """Rules that stand next to the chain findings (combination rule 4)."""
    if boot.validation_disabled is True:
        findings.add("shim_validation_disabled", variant=_chain_variant(boot))
    elif boot.validation_disabled is None and boot.secure_boot is True:
        # With Secure Boot off shim verifies nothing either way, so not
        # knowing this value is only worth reporting when it is on.
        findings.unavailable("MokSBStateRT")

    if boot.setup_mode is True:
        findings.add("setup_mode")
    elif boot.setup_mode is None:
        findings.unavailable("SetupMode")

    _sbat(boot, findings)


def _sbat(boot, findings):
    _, reason = boot.signed("grub")  # only to learn why GRUB is unknown
    if boot.grub_pe is None:
        _report_unknown(findings, reason)
        return
    grub_sbat = boot.grub_pe.get("sbat")
    if grub_sbat is None:
        findings.unavailable("grub_sbat")
        return
    if boot.sbat_level is None:
        findings.unavailable("SbatLevelRT")
        return

    for entry in grub_sbat:
        minimum = boot.sbat_level.get(entry.get("component"))
        if minimum is not None and entry.get("generation", 0) < minimum:
            findings.add("grub_sbat_revoked")
            return


def evaluate(state):
    """Return {"live_session", "overall", "findings"} for a state object."""
    boot = _Boot(state)
    findings = _Findings()

    if boot.uefi is False:
        # Combination rule 1: nothing else applies to a Legacy boot.
        findings.add("legacy_boot")
    else:
        if boot.secure_boot is None:
            findings.unavailable("SecureBoot")
        elif boot.secure_boot:
            _secure_boot_on(boot, findings)
        else:
            _secure_boot_off(boot, findings)
        _independent(boot, findings)

    # Most serious first; the order within a level is the order above.
    items = sorted(findings.items,
                   key=lambda item: -LEVEL_ORDER[item["level"]])
    overall = items[0]["level"] if items else LEVEL_OK
    return {
        "live_session": state.get("live_session"),
        "overall": overall,
        "findings": items,
    }

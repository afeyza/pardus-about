"""Tests for util.boothealth.rules.

States are built directly as dictionaries in the shape docs/mimari.md
defines, so each test shows exactly which input produces which finding.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""

import copy
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from util.boothealth import rules  # noqa: E402

GRUB_DIGEST = "9f2c" + "0" * 60
OTHER_DIGEST = "ab12" + "0" * 60


def pe_info(signed, digest=GRUB_DIGEST, sbat=None):
    return {
        "signed": signed,
        "signature_count": 1 if signed else 0,
        "authenticode_sha256": digest,
        "sbat": sbat,
        "vendor_cert_present": None,
    }


def esp_file(role, signed=True, status="ok", **pe_fields):
    return {
        "role": role,
        "path": "/boot/efi/EFI/pardus/{}.efi".format(role),
        "status": status,
        "pe": pe_info(signed, **pe_fields) if status == "ok" else None,
    }


GRUB_SBAT = [{"component": "sbat", "generation": 1},
             {"component": "grub", "generation": 4},
             {"component": "grub.debian", "generation": 5}]


def healthy_state():
    """Secure Boot on, everything signed and readable."""
    return {
        "schema": 1,
        "live_session": False,
        "firmware": {"uefi": True, "secure_boot": True, "setup_mode": False},
        "shim": {
            "validation_disabled": False,
            "mok_hashes": [],
            "sbat_level": {"shim": 4, "grub": 3, "grub.debian": 4},
        },
        "kernel": {"path": "/boot/vmlinuz-6.12", "status": "ok",
                   "pe": pe_info(True, digest=OTHER_DIGEST)},
        "packages": {"shim-signed": True, "grub-efi-amd64-signed": True},
        "esp": {
            "path": "/boot/efi",
            "files": [
                esp_file("shim"),
                esp_file("grub", sbat=GRUB_SBAT),
                esp_file("fallback"),
            ],
            "errors": [],
        },
    }


def make_state(secure_boot=True, grub=True, kernel=True, shim=True,
               **changes):
    """healthy_state() with the given signatures and dotted-path changes.

    grub, kernel, shim: True / False for signed / unsigned, or a status
    string ("missing", "unreadable", "malformed").
    changes: e.g. {"shim.mok_hashes": None} written as shim__mok_hashes.
    """
    state = healthy_state()
    state["firmware"]["secure_boot"] = secure_boot

    def apply(entry, value):
        if isinstance(value, bool):
            entry["pe"]["signed"] = value
            entry["pe"]["signature_count"] = 1 if value else 0
        else:
            entry["status"] = value
            entry["pe"] = None

    apply(state["kernel"], kernel)
    files = {entry["role"]: entry for entry in state["esp"]["files"]}
    apply(files["grub"], grub)
    apply(files["shim"], shim)

    for key, value in changes.items():
        target = state
        parts = key.split("__")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
    return state


def ids(result):
    return [finding["id"] for finding in result["findings"]]


def unavailable_subjects(result):
    return sorted(finding["subject"] for finding in result["findings"]
                  if finding["id"] == "check_unavailable")


class RulesTestCase(unittest.TestCase):
    def evaluate(self, state):
        return rules.evaluate(state)

    def assertFindings(self, state, expected):
        self.assertEqual(sorted(ids(self.evaluate(state))), sorted(expected))


class ScenarioTests(RulesTestCase):
    """One test per finding id of docs/mimari.md, in the table's order."""

    def test_legacy_boot_suppresses_everything_else(self):
        state = make_state(grub=False, kernel=False,
                           firmware__setup_mode=True)
        state["firmware"]["uefi"] = False
        self.assertFindings(state, ["legacy_boot"])

    def test_sb_off_chain_signed(self):
        self.assertFindings(make_state(secure_boot=False),
                            ["sb_off_chain_signed"])

    def test_sb_off_grub_unsigned(self):
        # Pardus 25.2 ISO: shim signed, grubx64.efi has no signature.
        self.assertFindings(make_state(secure_boot=False, grub=False),
                            ["sb_off_grub_unsigned"])

    def test_sb_off_kernel_unsigned(self):
        self.assertFindings(make_state(secure_boot=False, kernel=False),
                            ["sb_off_kernel_unsigned"])

    def test_sb_off_both_unsigned(self):
        self.assertFindings(
            make_state(secure_boot=False, grub=False, kernel=False),
            ["sb_off_grub_unsigned", "sb_off_kernel_unsigned"],
        )

    def test_sb_off_unsigned_shim_is_not_chain_signed(self):
        # No finding id covers an unsigned shim; listed in #27.
        self.assertFindings(make_state(secure_boot=False, shim=False), [])

    def test_sb_on_chain_ok(self):
        result = self.evaluate(make_state())
        self.assertEqual(ids(result), ["sb_on_chain_ok"])
        self.assertEqual(result["overall"], "ok")

    def test_sb_on_grub_mok_hash(self):
        state = make_state(grub=False, shim__mok_hashes=[GRUB_DIGEST])
        self.assertFindings(state, ["sb_on_grub_mok_hash"])

    def test_mok_hash_comparison_ignores_case(self):
        state = make_state(grub=False, shim__mok_hashes=[GRUB_DIGEST])
        state["esp"]["files"][1]["pe"]["authenticode_sha256"] = \
            GRUB_DIGEST.upper()
        self.assertFindings(state, ["sb_on_grub_mok_hash"])

    def test_sb_on_grub_changed(self):
        state = make_state(grub=False, shim__mok_hashes=[OTHER_DIGEST])
        self.assertFindings(state, ["sb_on_grub_changed"])

    def test_sb_on_kernel_unsigned(self):
        self.assertFindings(make_state(kernel=False),
                            ["sb_on_kernel_unsigned"])

    def test_shim_validation_disabled(self):
        state = make_state(shim__validation_disabled=True)
        self.assertFindings(state, ["shim_validation_disabled"])

    def test_setup_mode(self):
        state = make_state(firmware__setup_mode=True)
        self.assertFindings(state, ["sb_on_chain_ok", "setup_mode"])

    def test_grub_sbat_revoked(self):
        state = make_state(shim__sbat_level={"grub": 5})
        self.assertFindings(state, ["sb_on_chain_ok", "grub_sbat_revoked"])

    def test_esp_not_checked(self):
        self.assertFindings(make_state(esp=None), ["esp_not_checked"])


class EvidenceTests(RulesTestCase):
    def finding(self, state, finding_id):
        for finding in self.evaluate(state)["findings"]:
            if finding["id"] == finding_id:
                return finding
        self.fail("{} not produced".format(finding_id))

    def test_levels_and_evidence_follow_the_table(self):
        cases = [
            (make_state(secure_boot=False, grub=False),
             "sb_off_grub_unsigned", "warning", "signature_absent"),
            (make_state(secure_boot=False),
             "sb_off_chain_signed", "info", "signature_present"),
            (make_state(), "sb_on_chain_ok", "ok", "booted_with_secure_boot"),
            (make_state(firmware__setup_mode=True),
             "setup_mode", "warning", "state"),
            (make_state(esp=None), "esp_not_checked", "info", None),
        ]
        for state, finding_id, level, evidence in cases:
            with self.subTest(finding=finding_id):
                finding = self.finding(state, finding_id)
                self.assertEqual(finding["level"], level)
                self.assertEqual(finding["evidence"], evidence)

    def test_only_check_unavailable_has_a_subject(self):
        state = make_state(secure_boot=False, kernel="unreadable",
                           grub=False)
        for finding in self.evaluate(state)["findings"]:
            with self.subTest(finding=finding["id"]):
                self.assertEqual("subject" in finding,
                                 finding["id"] == "check_unavailable")

    def test_validation_variant_signed_chain(self):
        state = make_state(shim__validation_disabled=True)
        finding = self.finding(state, "shim_validation_disabled")
        self.assertEqual(finding["variant"], "chain_signed")

    def test_validation_variant_unsigned_chain(self):
        state = make_state(grub=False, shim__validation_disabled=True)
        finding = self.finding(state, "shim_validation_disabled")
        self.assertEqual(finding["variant"], "chain_unsigned")

    def test_validation_variant_unknown_without_esp(self):
        state = make_state(esp=None, shim__validation_disabled=True)
        finding = self.finding(state, "shim_validation_disabled")
        self.assertIsNone(finding["variant"])


class NullTests(RulesTestCase):
    """A value that could not be read never produces a warning."""

    def assertNoWarning(self, state):
        result = self.evaluate(state)
        warnings = [f["id"] for f in result["findings"]
                    if f["level"] == "warning"]
        self.assertEqual(warnings, [])
        return result

    def test_secure_boot_unknown(self):
        result = self.assertNoWarning(make_state(secure_boot=None))
        self.assertEqual(unavailable_subjects(result), ["SecureBoot"])

    def test_secure_boot_unknown_still_checks_independent_rules(self):
        state = make_state(secure_boot=None, firmware__setup_mode=True)
        self.assertFindings(state, ["check_unavailable", "setup_mode"])

    def test_setup_mode_unknown(self):
        result = self.assertNoWarning(make_state(firmware__setup_mode=None))
        self.assertIn("SetupMode", unavailable_subjects(result))

    def test_validation_unknown_with_secure_boot_on(self):
        result = self.assertNoWarning(
            make_state(shim__validation_disabled=None)
        )
        self.assertIn("MokSBStateRT", unavailable_subjects(result))
        # The chain can still be judged: nothing says validation was off.
        self.assertIn("sb_on_chain_ok", ids(result))

    def test_validation_unknown_with_secure_boot_off_is_not_reported(self):
        result = self.assertNoWarning(
            make_state(secure_boot=False, shim__validation_disabled=None)
        )
        self.assertEqual(ids(result), ["sb_off_chain_signed"])

    def test_mok_list_unknown_with_unsigned_grub(self):
        result = self.assertNoWarning(
            make_state(grub=False, shim__mok_hashes=None)
        )
        self.assertEqual(unavailable_subjects(result), ["MokListRT"])

    def test_sbat_level_unknown(self):
        result = self.assertNoWarning(make_state(shim__sbat_level=None))
        self.assertIn("SbatLevelRT", unavailable_subjects(result))

    def test_grub_without_sbat_section(self):
        state = make_state()
        state["esp"]["files"][1]["pe"]["sbat"] = None
        result = self.assertNoWarning(state)
        self.assertIn("grub_sbat", unavailable_subjects(result))

    def test_every_file_status_is_unavailable_not_warning(self):
        for status in ("missing", "unreadable", "malformed"):
            for name in ("grub", "kernel", "shim"):
                for secure_boot in (True, False):
                    with self.subTest(file=name, status=status,
                                      secure_boot=secure_boot):
                        state = make_state(secure_boot=secure_boot,
                                           **{name: status})
                        self.assertNoWarning(state)

    def test_unreadable_kernel_with_sb_off(self):
        result = self.evaluate(make_state(secure_boot=False,
                                          kernel="unreadable"))
        self.assertEqual(ids(result), ["check_unavailable"])
        self.assertEqual(unavailable_subjects(result), ["kernel"])

    def test_esp_not_mounted(self):
        # What the helper reports when /boot/efi is not mounted.
        state = make_state(grub="unreadable", shim="unreadable")
        state["esp"]["errors"] = ["esp_not_mounted"]
        result = self.assertNoWarning(state)
        self.assertEqual(unavailable_subjects(result), ["grub"])

    def test_empty_state_does_not_crash(self):
        result = self.assertNoWarning({})
        self.assertIn("SecureBoot", unavailable_subjects(result))

    def test_check_unavailable_is_reported_once_per_subject(self):
        state = make_state(secure_boot=False, grub="unreadable")
        subjects = unavailable_subjects(self.evaluate(state))
        self.assertEqual(subjects, sorted(set(subjects)))


class EspTests(RulesTestCase):
    """Decisions 1 and 2 of 28 November: what happens without the ESP."""

    def test_sb_on_without_esp_claims_nothing_about_the_chain(self):
        self.assertFindings(make_state(esp=None), ["esp_not_checked"])

    def test_sb_on_without_esp_still_reports_unsigned_kernel(self):
        self.assertFindings(make_state(esp=None, kernel=False),
                            ["sb_on_kernel_unsigned", "esp_not_checked"])

    def test_sb_off_without_esp_still_reports_unsigned_kernel(self):
        self.assertFindings(
            make_state(secure_boot=False, esp=None, kernel=False),
            ["sb_off_kernel_unsigned", "esp_not_checked"],
        )

    def test_without_esp_no_check_unavailable_for_esp_files(self):
        result = self.evaluate(make_state(secure_boot=False, esp=None))
        self.assertEqual(ids(result), ["esp_not_checked"])

    def test_esp_not_checked_appears_once(self):
        result = self.evaluate(make_state(esp=None))
        self.assertEqual(ids(result).count("esp_not_checked"), 1)


class CombinationTests(RulesTestCase):
    def test_sb_off_findings_are_exclusive(self):
        for grub in (True, False):
            for kernel in (True, False):
                with self.subTest(grub=grub, kernel=kernel):
                    found = ids(self.evaluate(make_state(
                        secure_boot=False, grub=grub, kernel=kernel
                    )))
                    signed = "sb_off_chain_signed" in found
                    unsigned = ("sb_off_grub_unsigned" in found
                                or "sb_off_kernel_unsigned" in found)
                    self.assertNotEqual(signed, unsigned)

    def test_sb_on_findings_are_exclusive(self):
        exclusive = {"sb_on_chain_ok", "sb_on_grub_mok_hash",
                     "sb_on_grub_changed"}
        for grub in (True, False):
            for mok in ([], [GRUB_DIGEST]):
                with self.subTest(grub=grub, mok=mok):
                    found = set(ids(self.evaluate(make_state(
                        grub=grub, shim__mok_hashes=mok
                    ))))
                    self.assertEqual(len(found & exclusive), 1)

    def test_validation_disabled_suppresses_sb_on_findings(self):
        state = make_state(grub=False, kernel=False,
                           shim__validation_disabled=True)
        self.assertFindings(state, ["shim_validation_disabled"])

    def test_independent_findings_stack(self):
        state = make_state(secure_boot=False, grub=False,
                           firmware__setup_mode=True,
                           shim__validation_disabled=True,
                           shim__sbat_level={"grub.debian": 9})
        self.assertFindings(state, [
            "sb_off_grub_unsigned", "shim_validation_disabled",
            "setup_mode", "grub_sbat_revoked",
        ])

    def test_sbat_any_component_below_level_is_revoked(self):
        state = make_state(shim__sbat_level={"grub": 1, "grub.debian": 6})
        self.assertIn("grub_sbat_revoked", ids(self.evaluate(state)))

    def test_sbat_equal_generation_is_not_revoked(self):
        state = make_state(shim__sbat_level={"grub": 4, "grub.debian": 5})
        self.assertNotIn("grub_sbat_revoked", ids(self.evaluate(state)))

    def test_sbat_unknown_component_is_ignored(self):
        state = make_state(shim__sbat_level={"systemd-boot": 9})
        self.assertNotIn("grub_sbat_revoked", ids(self.evaluate(state)))


class OutputTests(RulesTestCase):
    def test_overall_is_the_most_serious_level(self):
        cases = [
            (make_state(), "ok"),
            (make_state(esp=None), "info"),
            (make_state(firmware__setup_mode=True), "warning"),
        ]
        for state, overall in cases:
            with self.subTest(overall=overall):
                self.assertEqual(self.evaluate(state)["overall"], overall)

    def test_findings_are_sorted_most_serious_first(self):
        state = make_state(esp=None, firmware__setup_mode=True)
        levels = [f["level"] for f in self.evaluate(state)["findings"]]
        self.assertEqual(levels, ["warning", "info"])

    def test_live_session_is_passed_through(self):
        for live in (True, False, None):
            with self.subTest(live=live):
                result = self.evaluate(make_state(live_session=live))
                self.assertIs(result["live_session"], live)

    def test_live_session_does_not_change_findings(self):
        live = self.evaluate(make_state(grub=False, live_session=True))
        installed = self.evaluate(make_state(grub=False, live_session=False))
        self.assertEqual(live["findings"], installed["findings"])

    def test_input_is_not_modified(self):
        state = make_state(grub=False)
        before = copy.deepcopy(state)
        self.evaluate(state)
        self.assertEqual(state, before)

    def test_every_finding_id_is_documented(self):
        mimari = os.path.join(HERE, "..", "docs", "mimari.md")
        with open(mimari, encoding="utf-8") as f:
            text = f.read()
        for finding_id in rules.FINDINGS:
            with self.subTest(finding=finding_id):
                self.assertIn("`{}`".format(finding_id), text)


if __name__ == "__main__":
    unittest.main()

import unittest

from chatcli.tools.behavior_capability import _match_capabilities
from chatcli.tools.behavior_validator import BehaviorCoverageMatrixTool
from chatcli.tools.attack_chain import AttackChainBuilderTool
from chatcli.tools.attack_technique import _build_mappings
from chatcli.tools.attack_technique_plan import AttackTechniquePlannerTool
from chatcli.tools.command_capability import _map_commands


def _cap_by_category(capabilities, category):
    for item in capabilities:
        if item["category"] == category:
            return item
    raise AssertionError(f"missing capability: {category}")


def _command_by_category(commands, category):
    for item in commands:
        if item["category"] == category:
            return item
    raise AssertionError(f"missing command capability: {category}")


class BehaviorCapabilityTests(unittest.TestCase):
    def test_process_injection_missing_remote_process_access_is_capped(self):
        capabilities = _match_capabilities(
            [
                {"value": "VirtualAllocEx WriteProcessMemory CreateRemoteThread", "source": "imports"},
            ],
            max_results=10,
        )

        injection = _cap_by_category(capabilities, "process_injection")
        self.assertEqual(injection["confidence"], "medium")
        self.assertTrue(injection["behavior_composition_gaps"])
        self.assertIn("remote process access", injection["behavior_composition_gaps"][0])

    def test_process_injection_complete_sequence_can_stay_high_confidence(self):
        capabilities = _match_capabilities(
            [
                {
                    "value": "OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread",
                    "source": "runtime telemetry",
                },
            ],
            max_results=10,
        )

        injection = _cap_by_category(capabilities, "process_injection")
        self.assertEqual(injection["confidence"], "high")
        self.assertEqual(injection["behavior_composition_gaps"], [])

    def test_generic_credential_words_are_low_without_artifact(self):
        capabilities = _match_capabilities(
            [{"value": "password credential token", "source": "strings"}],
            max_results=10,
        )

        credential = _cap_by_category(capabilities, "credential_access")
        self.assertEqual(credential["confidence"], "low")
        self.assertIn("credential artifact", credential["behavior_composition_gaps"][0])

    def test_lateral_movement_without_remote_execution_is_capped(self):
        capabilities = _match_capabilities(
            [{"value": "admin$ smb", "source": "runtime telemetry"}],
            max_results=10,
        )

        lateral = _cap_by_category(capabilities, "lateral_movement")
        self.assertEqual(lateral["confidence"], "medium")
        self.assertIn("remote execution or auth action", lateral["behavior_composition_gaps"][0])

    def test_single_evidence_many_terms_is_not_high_by_term_count_alone(self):
        capabilities = _match_capabilities(
            [{"value": "http://host gate.php user-agent beacon send recv", "source": "strings"}],
            max_results=10,
        )

        c2 = _cap_by_category(capabilities, "c2_network")
        self.assertEqual(c2["confidence"], "medium")
        self.assertIn("evidence_count=1", c2["confidence_reason"])

    def test_anti_debug_is_reported_as_specific_behavior(self):
        capabilities = _match_capabilities(
            [
                {"value": "IsDebuggerPresent", "source": "imports"},
                {"value": "NtQueryInformationProcess checks DebugPort", "source": "pseudocode"},
            ],
            max_results=10,
        )

        anti_debug = _cap_by_category(capabilities, "anti_debug")
        self.assertEqual(anti_debug["confidence"], "medium")
        self.assertTrue(anti_debug["claim_gate"])

    def test_uac_bypass_is_reported_as_specific_behavior(self):
        capabilities = _match_capabilities(
            [{"value": "fodhelper DelegateExecute ms-settings", "source": "pseudocode"}],
            max_results=10,
        )

        uac = _cap_by_category(capabilities, "uac_bypass")
        self.assertEqual(uac["confidence"], "medium")
        self.assertEqual(uac["behavior_composition_gaps"], [])
        self.assertTrue(uac["claim_gate"])

    def test_byovd_requires_driver_artifact(self):
        capabilities = _match_capabilities(
            [{"value": "CreateService DeviceIoControl ioctl", "source": "runtime telemetry"}],
            max_results=10,
        )

        byovd = _cap_by_category(capabilities, "byovd_abuse")
        self.assertEqual(byovd["confidence"], "medium")
        self.assertIn("vulnerable driver artifact", byovd["behavior_composition_gaps"][0])

    def test_wmi_persistence_is_reported_as_specific_behavior(self):
        capabilities = _match_capabilities(
            [
                {
                    "value": "__EventFilter root\\subscription CommandLineEventConsumer",
                    "source": "pseudocode",
                },
            ],
            max_results=10,
        )

        wmi = _cap_by_category(capabilities, "wmi_persistence")
        self.assertEqual(wmi["confidence"], "medium")
        self.assertEqual(wmi["behavior_composition_gaps"], [])

    def test_startup_folder_persistence_is_reported(self):
        capabilities = _match_capabilities(
            [{"value": "shell:startup CreateShortcut payload.lnk", "source": "pseudocode"}],
            max_results=20,
        )

        startup = _cap_by_category(capabilities, "startup_folder_persistence")
        self.assertEqual(startup["confidence"], "medium")
        self.assertEqual(startup["behavior_composition_gaps"], [])

    def test_account_persistence_is_reported(self):
        capabilities = _match_capabilities(
            [{"value": "hidden account net user /add net localgroup administrators", "source": "pseudocode"}],
            max_results=20,
        )

        account = _cap_by_category(capabilities, "account_persistence")
        self.assertEqual(account["confidence"], "medium")
        self.assertEqual(account["behavior_composition_gaps"], [])

    def test_silent_download_and_payload_dropper_are_reported(self):
        capabilities = _match_capabilities(
            [
                {
                    "value": "URLDownloadToFile silent download download and execute",
                    "source": "pseudocode",
                },
                {
                    "value": "dropper FindResource LoadResource WriteFile payload.exe %TEMP%",
                    "source": "pseudocode",
                },
            ],
            max_results=20,
        )

        downloader = _cap_by_category(capabilities, "silent_downloader")
        dropper = _cap_by_category(capabilities, "payload_dropper")
        self.assertEqual(downloader["confidence"], "medium")
        self.assertEqual(downloader["behavior_composition_gaps"], [])
        self.assertEqual(dropper["confidence"], "high")
        self.assertEqual(dropper["behavior_composition_gaps"], [])

    def test_accessibility_and_ifeo_persistence_are_reported(self):
        capabilities = _match_capabilities(
            [{"value": "Image File Execution Options sethc.exe Debugger", "source": "pseudocode"}],
            max_results=20,
        )

        accessibility = _cap_by_category(capabilities, "accessibility_hijack_persistence")
        ifeo = _cap_by_category(capabilities, "ifeo_debugger_persistence")
        self.assertEqual(accessibility["confidence"], "medium")
        self.assertEqual(ifeo["confidence"], "medium")

    def test_registry_autostart_extension_persistence_is_reported(self):
        capabilities = _match_capabilities(
            [{"value": "AppInit_DLLs Active Setup StubPath", "source": "pseudocode"}],
            max_results=20,
        )

        registry = _cap_by_category(capabilities, "registry_autostart_extension_persistence")
        self.assertEqual(registry["confidence"], "medium")
        self.assertEqual(registry["behavior_composition_gaps"], [])

    def test_bits_jobs_persistence_is_reported(self):
        capabilities = _match_capabilities(
            [{"value": "bitsadmin /create bitsadmin /setnotifycmdline", "source": "pseudocode"}],
            max_results=20,
        )

        bits = _cap_by_category(capabilities, "bits_jobs_persistence")
        self.assertEqual(bits["confidence"], "medium")
        self.assertEqual(bits["behavior_composition_gaps"], [])

    def test_lsass_dumping_is_reported_as_specific_behavior(self):
        capabilities = _match_capabilities(
            [{"value": "LSASS MiniDumpWriteDump dbghelp.dll", "source": "pseudocode"}],
            max_results=10,
        )

        lsass = _cap_by_category(capabilities, "lsass_dumping")
        self.assertEqual(lsass["confidence"], "medium")
        self.assertEqual(lsass["behavior_composition_gaps"], [])

    def test_specific_credential_dumping_suppresses_generic_credential_access(self):
        capabilities = _match_capabilities(
            [{"value": "LSASS MiniDumpWriteDump comsvcs.dll password", "source": "runtime telemetry"}],
            max_results=20,
        )

        credential = _cap_by_category(capabilities, "credential_access")
        self.assertEqual(credential["confidence"], "low")
        self.assertEqual(credential["overlap_suppressed_by"], ["lsass_dumping"])
        self.assertIn("lsass_dumping", credential["family_suppressed_by"])
        self.assertEqual(credential["analysis_family"], "credential_collection")
        self.assertIn("more specific behavior category", credential["confidence_reason"])
        self.assertNotIn("same family matched shared evidence", credential["confidence_reason"])

    def test_registry_credential_dumping_is_reported_as_specific_behavior(self):
        capabilities = _match_capabilities(
            [{"value": "HKLM\\SAM HKLM\\SECURITY reg save", "source": "pseudocode"}],
            max_results=20,
        )

        registry = _cap_by_category(capabilities, "registry_credential_dumping")
        self.assertEqual(registry["confidence"], "medium")
        self.assertEqual(registry["behavior_composition_gaps"], [])

    def test_registry_credential_dumping_vss_esentutl_artifacts(self):
        capabilities = _match_capabilities(
            [{"value": "sam.hiv system.hiv security.hiv esentutl vssadmin", "source": "pseudocode"}],
            max_results=20,
        )

        registry = _cap_by_category(capabilities, "registry_credential_dumping")
        self.assertEqual(registry["confidence"], "high")
        self.assertEqual(registry["behavior_composition_gaps"], [])

    def test_silent_process_exit_dump_configuration_is_reported(self):
        capabilities = _match_capabilities(
            [
                {
                    "value": "SilentProcessExit\\lsass.exe MonitorProcess ReportingMode DumpType DumpFolder",
                    "source": "pseudocode",
                },
            ],
            max_results=20,
        )

        silent = _cap_by_category(capabilities, "silent_process_exit_dump")
        self.assertEqual(silent["confidence"], "high")
        self.assertEqual(silent["behavior_composition_gaps"], [])

    def test_ssp_credential_capture_is_reported(self):
        capabilities = _match_capabilities(
            [{"value": "Security Packages mimilib.dll kiwissp.log", "source": "pseudocode"}],
            max_results=20,
        )

        ssp = _cap_by_category(capabilities, "ssp_credential_capture")
        self.assertEqual(ssp["confidence"], "medium")
        self.assertEqual(ssp["behavior_composition_gaps"], [])

    def test_lsass_dumping_variants_from_validation_summary(self):
        capabilities = _match_capabilities(
            [{"value": "LSASS HandleKatz direct syscalls lsass.dmp", "source": "runtime telemetry"}],
            max_results=20,
        )

        lsass = _cap_by_category(capabilities, "lsass_dumping")
        self.assertEqual(lsass["confidence"], "high")
        self.assertEqual(lsass["behavior_composition_gaps"], [])

    def test_domain_credential_dumping_paths_are_reported(self):
        capabilities = _match_capabilities(
            [
                {"value": "ntds.dit ntdsutil system hive", "source": "pseudocode"},
                {"value": "DCSync DsGetNCChanges krbtgt", "source": "pseudocode"},
            ],
            max_results=20,
        )

        ntds = _cap_by_category(capabilities, "ntds_dumping")
        dcsync = _cap_by_category(capabilities, "dcsync_replication")
        self.assertEqual(ntds["confidence"], "medium")
        self.assertEqual(dcsync["confidence"], "medium")

    def test_kerberos_and_dpapi_access_are_reported(self):
        capabilities = _match_capabilities(
            [
                {"value": "Kerberoast TGS kirbi", "source": "pseudocode"},
                {"value": "DPAPI masterkey CryptUnprotectData", "source": "pseudocode"},
            ],
            max_results=20,
        )

        kerberos = _cap_by_category(capabilities, "kerberos_ticket_access")
        dpapi = _cap_by_category(capabilities, "dpapi_credential_access")
        self.assertEqual(kerberos["confidence"], "medium")
        self.assertEqual(dpapi["confidence"], "medium")

    def test_banking_credential_theft_is_reported(self):
        capabilities = _match_capabilities(
            [{"value": "banking webinject form grabber HttpSendRequest", "source": "pseudocode"}],
            max_results=20,
        )

        banking = _cap_by_category(capabilities, "banking_credential_theft")
        self.assertEqual(banking["confidence"], "medium")
        self.assertEqual(banking["behavior_composition_gaps"], [])

    def test_unix_shadow_access_is_reported_as_specific_behavior(self):
        capabilities = _match_capabilities(
            [{"value": "/etc/shadow getspnam", "source": "pseudocode"}],
            max_results=20,
        )

        unix = _cap_by_category(capabilities, "unix_shadow_access")
        self.assertEqual(unix["confidence"], "medium")
        self.assertEqual(unix["behavior_composition_gaps"], [])

    def test_archive_staging_is_reported_as_specific_behavior(self):
        capabilities = _match_capabilities(
            [{"value": "zip documents staging directory", "source": "pseudocode"}],
            max_results=10,
        )

        archive = _cap_by_category(capabilities, "archive_staging")
        self.assertEqual(archive["confidence"], "medium")
        self.assertEqual(archive["behavior_composition_gaps"], [])

    def test_windows_adware_toolbar_and_fraud_behaviors_are_reported(self):
        capabilities = _match_capabilities(
            [
                {
                    "value": "adware browser helper object default search ProxyEnable inject ads",
                    "source": "pseudocode",
                },
                {
                    "value": "browser extension ExtensionInstallForcelist manifest.json browser toolbar",
                    "source": "pseudocode",
                },
                {
                    "value": "phishing fake login credential prompt security warning",
                    "source": "pseudocode",
                },
            ],
            max_results=30,
        )

        adware = _cap_by_category(capabilities, "adware_browser_manipulation")
        toolbar = _cap_by_category(capabilities, "browser_extension_toolbar")
        fraud = _cap_by_category(capabilities, "user_deception_fraud")
        self.assertEqual(adware["analysis_family"], "credential_collection")
        self.assertEqual(toolbar["analysis_family"], "persistence_privilege")
        self.assertEqual(fraud["analysis_family"], "credential_collection")
        self.assertEqual(adware["confidence"], "high")
        self.assertEqual(toolbar["confidence"], "high")
        self.assertEqual(fraud["confidence"], "medium")
        self.assertEqual(adware["behavior_composition_gaps"], [])
        self.assertEqual(toolbar["behavior_composition_gaps"], [])
        self.assertEqual(fraud["behavior_composition_gaps"], [])

    def test_named_pipe_ipc_requires_control_context(self):
        capabilities = _match_capabilities(
            [{"value": r"\\.\pipe\svc CreateNamedPipe", "source": "runtime telemetry"}],
            max_results=10,
        )

        pipe = _cap_by_category(capabilities, "named_pipe_ipc")
        self.assertEqual(pipe["confidence"], "medium")
        self.assertIn("control or role context", pipe["behavior_composition_gaps"][0])

    def test_remote_access_tool_abuse_is_reported_as_specific_behavior(self):
        capabilities = _match_capabilities(
            [{"value": "AnyDesk remote access ngrok", "source": "pseudocode"}],
            max_results=10,
        )

        rat = _cap_by_category(capabilities, "remote_access_tool_abuse")
        self.assertEqual(rat["confidence"], "medium")
        self.assertEqual(rat["behavior_composition_gaps"], [])


class CommandCapabilityTests(unittest.TestCase):
    def test_powershell_does_not_also_match_generic_shell(self):
        commands = _map_commands(["powershell"], max_commands=10)

        shell = _command_by_category(commands, "shell_execution")
        self.assertEqual(shell["matched_terms"], ["powershell"])
        self.assertEqual(shell["confidence"], "low")
        self.assertEqual(shell["analysis_family"], "command_control_exfil")
        self.assertEqual(shell["family_label"], "C2/远控/外传")

    def test_uninstall_does_not_also_match_install(self):
        commands = _map_commands(["uninstall"], max_commands=10)

        persistence = _command_by_category(commands, "persistence_control")
        self.assertEqual(persistence["matched_terms"], ["uninstall"])


class BehaviorCoverageMatrixTests(unittest.TestCase):
    def test_coverage_report_hints_include_family_counts(self):
        capabilities = _match_capabilities(
            [{"value": "URLDownloadToFile silent download download and execute", "source": "pseudocode"}],
            max_results=10,
        )

        result = BehaviorCoverageMatrixTool().execute(capabilities=capabilities)

        self.assertFalse(result.is_error)
        self.assertIn("family_counts", result.metadata["report_hints"])
        self.assertIn("entry_execution", result.metadata["report_hints"]["family_counts"])


class AttackTechniquePlannerTests(unittest.TestCase):
    def test_planner_builds_family_first_queue(self):
        capabilities = _match_capabilities(
            [{"value": "URLDownloadToFile silent download download and execute", "source": "pseudocode"}],
            max_results=10,
        )

        result = AttackTechniquePlannerTool().execute(capabilities=capabilities)

        self.assertFalse(result.is_error)
        self.assertIn("analysis_plan", result.metadata)
        family = result.metadata["analysis_plan"][0]
        self.assertEqual(family["family"], "entry_execution")
        self.assertEqual(family["label"], "入口/执行/载荷链")
        self.assertTrue(family["candidates"])


class AttackTechniqueMappingTests(unittest.TestCase):
    def test_attack_chain_preserves_family_fields(self):
        capabilities = _match_capabilities(
            [{"value": "URLDownloadToFile silent download download and execute", "source": "pseudocode"}],
            max_results=10,
        )

        result = AttackChainBuilderTool().execute(capabilities=capabilities, max_steps=10)

        self.assertFalse(result.is_error)
        step = result.metadata["steps"][0]
        self.assertEqual(step["analysis_family"], "entry_execution")
        self.assertEqual(step["family_label"], "入口/执行/载荷链")

    def test_mapping_uses_lower_attack_chain_confidence(self):
        capabilities = [{
            "category": "lotl_abuse",
            "label": "Living-off-the-land 工具滥用迹象",
            "analysis_family": "entry_execution",
            "family_label": "入口/执行/载荷链",
            "matched_terms": ["mshta", "rundll32"],
            "evidence": ["mshta launches rundll32 from decoded command table"],
            "confidence": "high",
        }]
        attack_chain = [{
            "source_category": "lotl_abuse",
            "confidence": "low",
            "gate_status": "not_required",
            "gaps": "",
        }]

        mappings, issues = _build_mappings(capabilities, attack_chain, [], max_mappings=10)

        self.assertEqual(issues, [])
        self.assertEqual(mappings[0]["status"], "hypothesis")
        self.assertEqual(mappings[0]["confidence"], "low")
        self.assertEqual(mappings[0]["analysis_family"], "entry_execution")
        self.assertEqual(mappings[0]["family_label"], "入口/执行/载荷链")


if __name__ == "__main__":
    unittest.main()

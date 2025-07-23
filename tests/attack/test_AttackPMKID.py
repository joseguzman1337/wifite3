#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import MagicMock, patch

from wifite.attack.pmkid import AttackPMKID
from wifite.model.target import (
    Target,
)  # Assuming Target can be instantiated for testing
from wifite.config import Configuration

# from wifite.realtime_crack_manager import RealtimeCrackManager # Not strictly needed if mocking the instance


class TestAttackPMKID(unittest.TestCase):

    def setUp(self):
        Configuration.initialize(load_yaml=False)
        Configuration.hashcat_realtime = (
            False  # Default to off unless specified in test
        )
        Configuration.wordlist = (
            None  # Avoid actual cracking attempts by default
        )
        Configuration.ignore_old_handshakes = (
            True  # Focus on capture part for some tests
        )
        Configuration.pmkid_timeout = 10  # Short timeout for tests
        Configuration.temp_dir = "/tmp/wifite_test_temp_pmkid"
        if not os.path.exists(Configuration.temp_dir):
            os.makedirs(Configuration.temp_dir)

    def tearDown(self):
        if os.path.exists(Configuration.temp_dir):
            import shutil

            shutil.rmtree(Configuration.temp_dir)

    @patch("wifite.tools.hashcat.HcxDumpTool")  # Mocks the entire class
    @patch("wifite.tools.hashcat.HcxPcapTool")  # Mocks the entire class
    @patch(
        "wifite.tools.hashcat.Hashcat.crack_pmkid"
    )  # Mock the actual cracking call
    @patch(
        "os.path.exists", return_value=True
    )  # Assume files exist generally
    def test_run_starts_realtime_crack_if_enabled(
        self,
        mock_path_exists,
        mock_crack_pmkid,
        MockHcxPcapTool,
        MockHcxDumpTool,
    ):
        Configuration.hashcat_realtime = True
        Configuration.wordlist = (
            None  # Don't proceed to local cracking for this test
        )

        # Mock target
        mock_target_fields = [
            "PM:KI:DB:SS:ID:00",
            "2023-01-01 10:00:00",
            "2023-01-01 10:00:00",
            "1",
            "300",
            "WPA2",
            "CCMP",
            "PSK",
            "-40",
            "10",
            "0",
            "0.0.0.0",
            "8",
            "PMKIDNet",
            "",
        ]
        target = Target(mock_target_fields)

        # Mock HcxPcapTool instance and its get_pmkid_hash method
        mock_pcaptool_instance = MockHcxPcapTool.return_value
        # Simulate a captured PMKID hash string being returned and then saved to a file
        test_pmkid_hash_string = (
            "testpmkid*pmkidbssid*pmkidstation*pmkidessid"
        )
        mock_pcaptool_instance.get_pmkid_hash.return_value = (
            test_pmkid_hash_string
        )

        # Mock HcxDumpTool instance
        mock_dumptool_instance = MockHcxDumpTool.return_value
        # Allow poll to be called, make it indicate process is running then stopped
        mock_dumptool_instance.poll.side_effect = [None, None, True]

        # Mock RealtimeCrackManager
        mock_rt_manager = MagicMock()
        mock_rt_manager.is_actively_cracking.return_value = False
        mock_rt_manager.get_cracked_password.return_value = None

        # Mock save_pmkid to return a predictable file path
        expected_pmkid_filepath = os.path.join(
            Configuration.wpa_handshake_dir,
            "pmkid_PMKIDNet_PM-KI-DB-SS-ID-00_YYYY-MM-DDTHH-MM-SS.16800",
        )

        attack = AttackPMKID(target, realtime_crack_manager=mock_rt_manager)

        # Patch the save_pmkid method within the instance for this test
        # to control the returned filename and avoid actual file system operations for saving.
        with patch.object(
            attack, "save_pmkid", return_value=expected_pmkid_filepath
        ) as mock_save:
            with patch("time.sleep"):  # Patch time.sleep to speed up loops
                attack.run()

            mock_save.assert_called_once_with(test_pmkid_hash_string)

        # Assert that start_target_crack_session was called on the manager
        mock_rt_manager.start_target_crack_session.assert_called_once_with(
            target_bssid=target.bssid,
            essid=target.essid,
            hash_file_path=expected_pmkid_filepath,
            hash_type=16800,
        )

        # Since we mocked crack_pmkid, and real-time is started,
        # the .success might depend on whether run() considers starting RT as success
        # The current run() returns True if PMKID is captured.
        self.assertTrue(attack.run())  # Re-check based on current logic


if __name__ == "__main__":
    # Need to ensure Configuration is initialized for standalone runs if not using a test runner
    # For simplicity, this is often handled by running tests via `python -m unittest discover`
    # or specific test runner configurations.
    if not hasattr(Configuration, "temp_dir"):  # Basic check
        Configuration.initialize(load_yaml=False)
        Configuration.temp_dir = "/tmp/wifite_test_temp_pmkid_main"
        if not os.path.exists(Configuration.temp_dir):
            os.makedirs(Configuration.temp_dir)

    unittest.main()

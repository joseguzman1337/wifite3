#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import MagicMock, patch

from wifite.attack.all import AttackAll
from wifite.model.target import Target
from wifite.config import Configuration


class TestAttackAll(unittest.TestCase):

    def setUp(self):
        Configuration.initialize(load_yaml=False)
        # Prevent actual attacks or lengthy operations
        Configuration.no_deauth = True
        Configuration.wps_pixie = False
        Configuration.wps_pin = False
        Configuration.use_pmkid_only = (
            False  # Allow WPA handshake attack to be queued
        )
        Configuration.wordlist = None  # Prevent local cracking attempts
        Configuration.hashcat_realtime = True  # Enable for these tests
        Configuration.temp_dir = "/tmp/wifite_test_temp_all"
        if not os.path.exists(Configuration.temp_dir):
            os.makedirs(Configuration.temp_dir)

    def tearDown(self):
        if os.path.exists(Configuration.temp_dir):
            import shutil

            shutil.rmtree(Configuration.temp_dir)

    @patch("wifite.attack.all.AttackWPA")  # Mock the AttackWPA class
    @patch("wifite.attack.all.AttackPMKID")  # Mock the AttackPMKID class
    @patch("wifite.attack.all.AttackWEP")  # Mock AttackWEP
    @patch(
        "wifite.attack.all.AttackWPS.can_attack_wps", return_value=False
    )  # No WPS attacks for simplicity
    def test_attack_single_skips_if_realtime_cracked(
        self, mock_can_wps, MockAttackWEP, MockAttackPMKID, MockAttackWPA
    ):
        """Test that attack_single skips other attacks if RealtimeCrackManager reports password."""

        mock_target_fields = [
            "RT:CR:AC:KE:D0:00",
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
            "10",
            "CrackedNet",
            "",
        ]
        target = Target(mock_target_fields)

        mock_rt_manager = MagicMock()
        # Simulate that update_status finds a password for this target
        mock_rt_manager.update_status.return_value = (
            target.bssid,
            "password123",
        )
        # get_cracked_password will also be checked by attack_multiple before even calling attack_single
        mock_rt_manager.get_cracked_password.return_value = "password123"

        # Call attack_multiple, which will call attack_single internally
        # We are interested if attack_single correctly uses the info from update_status
        # Need to patch Color.pl as it's called when a target is skipped due to being pre-cracked.
        with patch("wifite.util.color.Color.pl") as mock_color_pl:
            AttackAll.attack_multiple(
                [target], realtime_crack_manager=mock_rt_manager
            )

        # Assert that no actual attack class (PMKID, WPA) was instantiated or run
        # because the real-time manager should have "cracked" it.
        MockAttackPMKID.assert_not_called()
        MockAttackWPA.assert_not_called()

        # Check for the message indicating it was skipped because already cracked
        found_skip_message = False
        for call_arg in mock_color_pl.call_args_list:
            if "already cracked by real-time manager" in call_arg[0][0]:
                found_skip_message = True
                break
        self.assertTrue(
            found_skip_message,
            "Should print message that target was already cracked by real-time manager.",
        )

    @patch(
        "wifite.attack.wpa.AttackWPA.run", return_value=True
    )  # Mock AttackWPA's run to succeed
    @patch(
        "wifite.attack.wpa.AttackWPA.__init__", return_value=None
    )  # Mock init to avoid issues
    @patch(
        "wifite.attack.pmkid.AttackPMKID"
    )  # Mock PMKID to prevent its run
    @patch("wifite.attack.all.AttackWPS.can_attack_wps", return_value=False)
    def test_attack_single_stops_realtime_if_other_attack_succeeds(
        self, mock_can_wps, MockAttackPMKID, mock_wpa_init, mock_wpa_run
    ):
        """Test that attack_single stops real-time cracking if a standard attack succeeds."""
        Configuration.use_pmkid_only = False  # Ensure WPA attack is in queue

        mock_target_fields = [
            "RT:ST:OP:ME:XX:00",
            "2023-01-01 10:00:00",
            "2023-01-01 10:00:00",
            "6",
            "144",
            "WPA2",
            "CCMP",
            "PSK",
            "-50",
            "10",
            "0",
            "0.0.0.0",
            "12",
            "StopRealTime",
            "",
        ]
        target = Target(mock_target_fields)

        mock_rt_manager = MagicMock()
        mock_rt_manager.update_status.return_value = (
            None  # Real-time does not find password initially
        )
        mock_rt_manager.get_cracked_password.return_value = (
            None  # Not pre-cracked
        )
        mock_rt_manager.is_actively_cracking.return_value = (
            True  # Simulate it's active for this BSSID
        )

        # For AttackWPA to be "successful", its crack_result needs to be set.
        # We mock the run to return True, and need to mock the attack object itself.
        mock_wpa_instance = MagicMock()
        mock_wpa_instance.run = mock_wpa_run
        mock_wpa_instance.success = (
            True  # Simulate successful crack by AttackWPA
        )
        mock_wpa_instance.crack_result = (
            MagicMock()
        )  # Needs a crack_result object with save()
        mock_wpa_instance.crack_result.save = MagicMock()

        # When AttackWPA is instantiated, return our mock_wpa_instance
        # Need to use a new variable for the class mock to avoid conflict with instance mock
        with patch(
            "wifite.attack.all.AttackWPA", return_value=mock_wpa_instance
        ) as PatchedAttackWPA:
            AttackAll.attack_single(
                target, 0, realtime_crack_manager=mock_rt_manager
            )

        # Assert that AttackWPA was instantiated with the target and manager
        PatchedAttackWPA.assert_called_once_with(target, mock_rt_manager)

        # Assert that run was called on the WPA attack instance
        mock_wpa_instance.run.assert_called_once()

        # Assert that stop_current_crack_attempt was called on the manager
        mock_rt_manager.stop_current_crack_attempt.assert_called_once_with(
            cleanup_hash_file=False
        )


if __name__ == "__main__":
    if not hasattr(Configuration, "temp_dir"):
        Configuration.initialize(load_yaml=False)
        Configuration.temp_dir = "/tmp/wifite_test_temp_all_main"
        if not os.path.exists(Configuration.temp_dir):
            os.makedirs(Configuration.temp_dir)
    unittest.main()

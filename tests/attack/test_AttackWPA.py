#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import Mock, patch

# Adjust import paths based on Wifite's structure
# This assumes Wifite can be imported if tests are run from the project root
from wifite.attack.wpa import AttackWPA
from wifite.model.target import Target
from wifite.util.color import Color
from wifite.config import Configuration

class TestAttackWPA(unittest.TestCase):

    def setUp(self):
        # Basic configuration mock needed for some functions called within AttackWPA
        # We might not need all of these, but it's good to have a base.
        Configuration.initialize(load_yaml=False) # Avoid loading external config
        Configuration.wordlist = None # Ensure no cracking is attempted
        Configuration.wps_only = False
        Configuration.use_pmkid_only = False
        Configuration.no_deauth = True # Avoid actual deauth calls

    @patch('sys.stdout', new_callable=unittest.mock.StringIO) # Capture stdout
    def test_run_on_wpa3_target(self, mock_stdout):
        '''Test AttackWPA.run() with a WPA3 target.'''
        # Mock a Target object that identifies as WPA3
        mock_target_wpa3_fields = ['W3:MA:CA:DD:RE:SS', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '1', '1201', 'WPA3 PSK', 'GCMP', 'SAE', '-40', '10', '0', '0.0.0.0', '8', 'WPA3Test', '']
        target_wpa3 = Target(mock_target_wpa3_fields)
        # Ensure is_wpa3 is explicitly True as per Target class logic
        self.assertTrue(target_wpa3.is_wpa3) 

        attack = AttackWPA(target_wpa3)
        
        # Since AttackWPA.run() involves complex interactions (airodump, aireplay),
        # we focus on the initial WPA3 check.
        # The run method should return False early for WPA3.
        result = attack.run()
        self.assertFalse(result, "AttackWPA.run() should return False for WPA3 targets.")

        # Check if the informational message was printed
        output = mock_stdout.getvalue()
        expected_msg_part = "Target WPA3Test is WPA3-SAE. Traditional 4-way handshake capture is ineffective."
        self.assertIn(expected_msg_part, Color.strip(output), "WPA3 warning message not found in stdout.")

    # We can add a test for WPA2 targets to ensure it tries to proceed,
    # but that would involve more mocking of Airodump, Handshake, etc.
    # For this subtask, focusing on the WPA3 branch is key.
    
    @patch('wifite.attack.wpa.AttackWPA.capture_handshake', return_value=None) # Mock handshake capture to prevent it from running
    @patch('wifite.util.color.Color.pl') # Mock Color.pl to check calls
    def test_run_on_wpa2_target_proceeds(self, mock_color_pl, mock_capture_handshake):
        '''Test AttackWPA.run() with a WPA2 target to ensure it proceeds (superficially).'''
        mock_target_wpa2_fields = ['W2:MA:CA:DD:RE:SS', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '6', '300', 'WPA2', 'CCMP', 'PSK', '-50', '10', '0', '0.0.0.0', '8', 'WPA2Test', '']
        target_wpa2 = Target(mock_target_wpa2_fields)
        self.assertFalse(target_wpa2.is_wpa3)

        attack = AttackWPA(target_wpa2)
        
        # We've mocked capture_handshake to return None, so it should fail there.
        # The key is that it didn't exit due to WPA3 check.
        result = attack.run()
        self.assertFalse(result) # It will be False because capture_handshake returns None

        # Check that the WPA3 warning was NOT printed.
        # We check calls to Color.pl to see if the WPA3 message was among them.
        wpa3_warning_printed = False
        for call_args in mock_color_pl.call_args_list:
            if "is WPA3-SAE" in call_args[0][0]:
                wpa3_warning_printed = True
                break
        self.assertFalse(wpa3_warning_printed, "WPA3 warning should not be printed for a WPA2 target.")

    @patch('wifite.attack.wpa.Handshake') # Mock the Handshake object operations
    @patch('wifite.tools.hashcat.HcxPcapTool.generate_hccapx_file') # Mock .hccapx generation
    @patch('wifite.tools.aircrack.Aircrack.crack_handshake') # Mock aircrack-ng cracking
    @patch('os.path.exists', return_value=True) # Assume files exist
    def test_run_starts_realtime_crack_on_wpa2_target_if_enabled(self, mock_path_exists, mock_aircrack_crack, mock_gen_hccapx, MockHandshake):
        Configuration.hashcat_realtime = True
        Configuration.wordlist = None # Don't proceed to local aircrack cracking for this specific test focus

        # Mock target
        mock_target_wpa2_fields = ['W2:RT:CA:DD:RE:SS', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '6', '300', 'WPA2', 'CCMP', 'PSK', '-50', '10', '0', '0.0.0.0', '10', 'WPA2RealTm', '']
        target_wpa2 = Target(mock_target_wpa2_fields)
        self.assertFalse(target_wpa2.is_wpa3)

        # Mock RealtimeCrackManager
        mock_rt_manager = MagicMock()
        mock_rt_manager.is_actively_cracking.return_value = False
        mock_rt_manager.get_cracked_password.return_value = None
        
        attack = AttackWPA(target_wpa2, realtime_crack_manager=mock_rt_manager)

        # Mock capture_handshake to return a mock Handshake object
        mock_handshake_obj = MockHandshake.return_value
        mock_handshake_obj.capfile = '/tmp/fake_handshake.cap' # Used by generate_hccapx_file
        mock_handshake_obj.bssid = target_wpa2.bssid
        mock_handshake_obj.essid = target_wpa2.essid
        mock_handshake_obj.has_handshake.return_value = True # Simulate successful capture
        
        with patch.object(attack, 'capture_handshake', return_value=mock_handshake_obj) as mock_capture:
            # Mock generate_hccapx_file to return a predictable path
            expected_hccapx_path = '/tmp/generated_for_realtime.hccapx'
            mock_gen_hccapx.return_value = expected_hccapx_path
            
            # Mock save_handshake as it's called after capture
            with patch.object(attack, 'save_handshake') as mock_save_hs:
                attack.run()
        
        mock_capture.assert_called_once()
        mock_gen_hccapx.assert_called_once_with(mock_handshake_obj)
        
        # Assert that start_target_crack_session was called on the manager
        mock_rt_manager.start_target_crack_session.assert_called_once_with(
            target_bssid=target_wpa2.bssid,
            essid=target_wpa2.essid,
            hash_file_path=expected_hccapx_path,
            hash_type=2500 # WPA/WPA2 HCCAPX
        )
        # The run method will return False because Configuration.wordlist is None,
        # preventing aircrack-ng from running and thus not finding a key.
        self.assertFalse(attack.success)


if __name__ == '__main__':
    unittest.main()

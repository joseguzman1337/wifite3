#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
from unittest.mock import patch, MagicMock, mock_open, call

# Assuming wifite is in PYTHONPATH or tests are run from project root
from wifite.realtime_crack_manager import RealtimeCrackManager
from wifite.tools.hashcat import (
    RealtimeHashcatSession,
)  # Needed for type hinting and mocking
from wifite.config import Configuration

# Mock a basic Configuration object for tests
mock_config = MagicMock()
mock_config.hashcat_realtime = True
mock_config.hashcat_realtime_wordlist_file = None
mock_config.hashcat_realtime_wordlist_dir = "/fake/wordlist_dir"
mock_config.hashcat_realtime_options = None
mock_config.hashcat_realtime_force_cpu = False
mock_config.hashcat_realtime_gpu_devices = None
mock_config.temp = lambda x: os.path.join("/tmp/wifite_test_temp", x)  # Mock temp dir
mock_config.verbose = 0  # Default verbosity


class TestRealtimeCrackManager(unittest.TestCase):

    def setUp(self):
        # Reset parts of the mock_config that might be changed by tests
        Configuration.hashcat_realtime = True
        Configuration.hashcat_realtime_wordlist_file = None
        Configuration.hashcat_realtime_wordlist_dir = "/fake/wordlist_dir"
        Configuration.hashcat_realtime_options = None
        Configuration.hashcat_realtime_force_cpu = False
        Configuration.hashcat_realtime_gpu_devices = None
        Configuration.temp_dir = "/tmp/wifite_test_temp"  # Used by Configuration.temp()
        if not os.path.exists(Configuration.temp_dir):
            os.makedirs(Configuration.temp_dir)

        # Patch os.path.exists globally for this test class for simplicity,
        # specific tests can override its side_effect if needed.
        self.patcher_os_path_exists = patch("os.path.exists")
        self.mock_os_path_exists = self.patcher_os_path_exists.start()
        self.mock_os_path_exists.return_value = True  # Default to files/dirs existing

        self.patcher_os_path_isfile = patch("os.path.isfile")
        self.mock_os_path_isfile = self.patcher_os_path_isfile.start()
        self.mock_os_path_isfile.return_value = True

        self.patcher_os_path_isdir = patch("os.path.isdir")
        self.mock_os_path_isdir = self.patcher_os_path_isdir.start()
        self.mock_os_path_isdir.return_value = True

        self.patcher_os_path_getsize = patch("os.path.getsize")
        self.mock_os_path_getsize = self.patcher_os_path_getsize.start()
        self.mock_os_path_getsize.return_value = 100  # Default to non-empty

        self.patcher_os_listdir = patch("os.listdir")
        self.mock_os_listdir = self.patcher_os_listdir.start()

        self.patcher_color_pl = patch("wifite.util.color.Color.pl")
        self.mock_color_pl = self.patcher_color_pl.start()

        self.manager = RealtimeCrackManager(Configuration)

    def tearDown(self):
        self.patcher_os_path_exists.stop()
        self.patcher_os_path_isfile.stop()
        self.patcher_os_path_isdir.stop()
        self.patcher_os_path_getsize.stop()
        self.patcher_os_listdir.stop()
        self.patcher_color_pl.stop()
        # Clean up temp dir
        if os.path.exists(Configuration.temp_dir):
            import shutil

            shutil.rmtree(Configuration.temp_dir)

    def test_load_wordlists_single_file_valid(self):
        Configuration.hashcat_realtime_wordlist_file = "/fake/wordlist.txt"
        Configuration.hashcat_realtime_wordlist_dir = None  # Ensure dir is not used
        self.manager._load_wordlists()
        self.assertEqual(len(self.manager.wordlist_queue), 1)
        self.assertEqual(self.manager.wordlist_queue[0], "/fake/wordlist.txt")

    def test_load_wordlists_single_file_invalid(self):
        Configuration.hashcat_realtime_wordlist_file = "/fake/nonexistent.txt"
        self.mock_os_path_exists.side_effect = lambda x: (
            False if x == "/fake/nonexistent.txt" else True
        )
        self.manager._load_wordlists()
        self.assertEqual(len(self.manager.wordlist_queue), 0)
        self.mock_color_pl.assert_any_call(f"{{R}}Real-time: Specified wordlist file {{O}}{Configuration.hashcat_realtime_wordlist_file}{{R}} not found or empty.{{W}}")

    def test_load_wordlists_directory_valid_multiple_files(self):
        Configuration.hashcat_realtime_wordlist_dir = "/fake/wordlist_dir"
        Configuration.hashcat_realtime_wordlist_file = None
        self.mock_os_listdir.return_value = [
            "wl1.txt",
            "wl2.lst",
            "some.potfile",
        ]
        # os.path.isfile needs to be True for these paths
        self.mock_os_path_isfile.side_effect = lambda x: x.endswith((".txt", ".lst"))

        self.manager._load_wordlists()
        self.assertEqual(len(self.manager.wordlist_queue), 2)
        self.assertIn(
            os.path.join("/fake/wordlist_dir", "wl1.txt"),
            self.manager.wordlist_queue,
        )
        self.assertIn(
            os.path.join("/fake/wordlist_dir", "wl2.lst"),
            self.manager.wordlist_queue,
        )
        self.assertNotIn(
            os.path.join("/fake/wordlist_dir", "some.potfile"),
            self.manager.wordlist_queue,
        )

    def test_load_wordlists_directory_empty(self):
        Configuration.hashcat_realtime_wordlist_dir = "/fake/empty_dir"
        Configuration.hashcat_realtime_wordlist_file = None
        self.mock_os_listdir.return_value = []
        self.manager._load_wordlists()
        self.assertEqual(len(self.manager.wordlist_queue), 0)
        self.mock_color_pl.assert_any_call(f"{{R}}Real-time: No valid wordlists found. Real-time cracking disabled for this target.{{W}}")

    def test_load_wordlists_directory_invalid(self):
        Configuration.hashcat_realtime_wordlist_dir = "/fake/invalid_dir"
        Configuration.hashcat_realtime_wordlist_file = None
        self.mock_os_path_isdir.side_effect = lambda x: (
            False if x == "/fake/invalid_dir" else True
        )
        self.manager._load_wordlists()
        self.assertEqual(len(self.manager.wordlist_queue), 0)
        self.mock_color_pl.assert_any_call(f"{{R}}Real-time: Wordlist directory {{O}}{Configuration.hashcat_realtime_wordlist_dir}{{R}} not found.{{W}}")

    @patch.object(RealtimeCrackManager, "_load_wordlists")
    @patch.object(RealtimeCrackManager, "_try_next_wordlist")
    @patch.object(RealtimeCrackManager, "stop_current_crack_attempt")
    def test_start_target_crack_session(self, mock_stop, mock_try_next, mock_load_wl):
        self.manager.active_session = MagicMock()  # Simulate an existing session
        self.manager.start_target_crack_session(
            "NEW_BSSID", "NewESSID", "/path/to/hash2.txt", 16800
        )

        mock_stop.assert_called_once_with(cleanup_hash_file=True)
        self.assertEqual(self.manager.current_target_bssid, "NEW_BSSID")
        self.assertEqual(self.manager.current_hash_file_path, "/path/to/hash2.txt")
        self.assertEqual(self.manager.current_hash_type, 16800)
        mock_load_wl.assert_called_once()
        mock_try_next.assert_called_once()

    @patch("wifite.tools.hashcat.Hashcat.start_realtime_crack")
    @patch.object(RealtimeCrackManager, "stop_current_crack_attempt")
    def test_try_next_wordlist_starts_session(
        self, mock_stop_current, mock_start_hashcat
    ):
        self.manager.wordlist_queue = ["/fake/wl1.txt"]
        self.manager.current_target_bssid = "TARGET_BSSID"
        self.manager.current_hash_file_path = "/path/to/hash.txt"
        self.manager.current_hash_type = 2500

        mock_session_obj = MagicMock(spec=RealtimeHashcatSession)
        mock_start_hashcat.return_value = mock_session_obj

        self.manager._try_next_wordlist()

        mock_start_hashcat.assert_called_once_with(
            "TARGET_BSSID",
            "/path/to/hash.txt",
            2500,
            "/fake/wl1.txt",
            user_hashcat_options=[],
            user_preferences={},
        )
        self.assertEqual(self.manager.active_session, mock_session_obj)
        self.assertEqual(self.manager.current_wordlist_path, "/fake/wl1.txt")
        mock_stop_current.assert_not_called()  # Should not be called if session starts

    @patch("wifite.tools.hashcat.Hashcat.start_realtime_crack")
    @patch.object(RealtimeCrackManager, "stop_current_crack_attempt")
    def test_try_next_wordlist_no_wordlists(
        self, mock_stop_current, mock_start_hashcat
    ):
        self.manager.wordlist_queue = []
        self.manager.current_target_bssid = "TARGET_BSSID"
        self.manager.current_hash_file_path = (
            "/path/to/temp_hash.txt"  # Assume temp for cleanup check
        )
        Configuration.temp_dir = "/tmp"  # ensure temp path check works

    @patch('wifite.tools.hashcat.Hashcat.start_realtime_crack', return_value=None)
    @patch.object(RealtimeCrackManager, '_try_next_wordlist', wraps=RealtimeCrackManager._try_next_wordlist, autospec=True)
    def test_try_next_wordlist_hashcat_start_fails(self, mock_recursive_try_next, mock_start_hashcat):
        self.manager.wordlist_queue = ['/fake/wl1.txt', '/fake/wl2.txt']
        self.manager.current_target_bssid = 'TARGET_BSSID'
        self.manager.current_hash_file_path = '/path/to/hash.txt'
        self.manager.current_hash_type = 2500
        initial_errors = self.manager.consecutive_hashcat_errors

        self.manager._try_next_wordlist()  # This will call mock_start_hashcat which returns None

        self.assertEqual(self.manager.consecutive_hashcat_errors, initial_errors + 1)
        self.mock_color_pl.assert_any_call(f"{{R}}Real-time: Failed to start Hashcat with wordlist {{O}}{os.path.basename('/fake/wl1.txt')}{{R}} for {{C}}TARGET_BSSID{{W}}")
        mock_recursive_try_next.assert_called_once() # Checks if it tries the next list

    def test_update_status_no_active_session(self):
        self.manager.active_session = None
        result = self.manager.update_status()
        self.assertIsNone(result)

    @patch("wifite.tools.hashcat.Hashcat.check_realtime_crack_status")
    @patch(
        "wifite.model.wpa_result.CrackResultWPA.dump"
    )  # Mock save to avoid actual file IO
    @patch.object(RealtimeCrackManager, "stop_current_crack_attempt")
    def test_update_status_password_cracked(
        self, mock_stop_attempt, mock_dump, mock_check_status
    ):
        mock_session = MagicMock(spec=RealtimeHashcatSession)
        mock_session.hash_file_path = (
            "/path/to/hashfile.hccapx"  # Needed for CrackResultWPA
        )
        self.manager.active_session = mock_session
        self.manager.current_target_bssid = "CRACKED_BSSID"
        self.manager.current_target_essid = "CrackedESSID"
        self.manager.current_hash_type = 2500

        mock_check_status.return_value = {
            "status_lines": ["Some status"],
            "cracked_password": "the_password",
            "is_process_complete": True,  # Typically true when password found
            "error_lines": [],
        }

        result_bssid, result_password = self.manager.update_status()

        self.assertEqual(result_bssid, "CRACKED_BSSID")
        self.assertEqual(result_password, "the_password")
        self.mock_color_pl.assert_any_call(
            "{G}SUCCESS: Real-time crack for {C}CRACKED_BSSID{G} (ESSID: CrackedESSID)! Password: {R}the_password{W}"
        )
        mock_dump.assert_called_once()
        self.assertEqual(
            self.manager.realtime_cracked_passwords["CRACKED_BSSID"],
            "the_password",
        )
        mock_stop_attempt.assert_called_once()

    @patch("wifite.tools.hashcat.Hashcat.check_realtime_crack_status")
    @patch(
        "wifite.tools.hashcat.Hashcat.stop_realtime_crack"
    )  # Mock this directly for this test
    @patch.object(RealtimeCrackManager, "_try_next_wordlist")
    def test_update_status_process_complete_no_password(
        self, mock_try_next, mock_hashcat_stop, mock_check_status
    ):
        mock_session = MagicMock(spec=RealtimeHashcatSession)
        self.manager.active_session = mock_session
        self.manager.current_target_bssid = "TARGET_BSSID"
        self.manager.current_wordlist_path = "/fake/wl_exhausted.txt"

        mock_check_status.return_value = {
            "status_lines": ["Exhausted"],
            "cracked_password": None,
            "is_process_complete": True,
            "error_lines": [],
        }

        result = self.manager.update_status()
        self.assertIsNone(result)
        self.mock_color_pl.assert_any_call(f"{{G}}Real-time: Wordlist {{C}}{os.path.basename('/fake/wl_exhausted.txt')}{{W}} exhausted for {{C}}TARGET_BSSID{{W}}.")
        mock_hashcat_stop.assert_called_once_with(mock_session, cleanup_hash_file=False)
        self.assertIsNone(self.manager.active_session)  # Should be cleared
        mock_try_next.assert_called_once()

    @patch("wifite.tools.hashcat.Hashcat.stop_realtime_crack")
    def test_stop_current_crack_attempt(self, mock_hashcat_stop):
        mock_session = MagicMock(spec=RealtimeHashcatSession)
        mock_session.hash_file_path = os.path.join(
            Configuration.temp_dir, "temp_hash.16800"
        )  # Temp file
        self.manager.active_session = mock_session
        self.manager.current_target_bssid = "ANY_BSSID"
        self.manager.current_hash_file_path = mock_session.hash_file_path

        self.manager.stop_current_crack_attempt(cleanup_hash_file=True)

        mock_hashcat_stop.assert_called_once_with(mock_session, cleanup_hash_file=True)
        self.assertIsNone(self.manager.active_session)
        self.assertIsNone(
            self.manager.current_target_bssid
        )  # Cleared because cleanup_hash_file was true


if __name__ == "__main__":
    unittest.main()

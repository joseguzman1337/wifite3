#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Real-time crack manager for Wifite3.

This module provides real-time password cracking capabilities using Hashcat
for WPA/WPA2 and PMKID attacks. It manages wordlist queues, crack sessions,
and provides status updates for ongoing attacks.
"""

import os

from .config import Configuration
from .model.wpa_result import CrackResultWPA
from .tools.hashcat import Hashcat, RealtimeHashcatSession
from .util.color import Color

# Color shortcuts for consistent usage
W = ""  # White/reset color

class RealtimeCrackManager:
    def __init__(self, config):
        self.config = config # Should be an instance of Configuration
        self.active_session: RealtimeHashcatSession = None
        self.current_target_bssid = None
        self.current_hash_file_path = None # Path to the file Hashcat is currently working on
        self.current_hash_type = None
        self.wordlist_queue = []
        self.current_wordlist_path = None
        self.consecutive_hashcat_errors = 0
        self.max_hashcat_errors = 3 # Stop trying after this many consecutive Hashcat start failures
        # Stores BSSID:password for already cracked targets in this Wifite session by real-time cracker
        self.realtime_cracked_passwords = {}

    def _load_wordlists(self):
        self.wordlist_queue = []
        if Configuration.hashcat_realtime_wordlist_file:
            if os.path.exists(Configuration.hashcat_realtime_wordlist_file) and \
               os.path.getsize(Configuration.hashcat_realtime_wordlist_file) > 0:
                self.wordlist_queue.append(Configuration.hashcat_realtime_wordlist_file)
            else:
                Color.pl(f"{{R}}Real-time: Specified wordlist file {{O}}{Configuration.hashcat_realtime_wordlist_file}{{R}} not found or empty.{W}")
        elif Configuration.hashcat_realtime_wordlist_dir:
            if os.path.isdir(Configuration.hashcat_realtime_wordlist_dir):
                try:
                    for filename in sorted(os.listdir(Configuration.hashcat_realtime_wordlist_dir)):
                        filepath = os.path.join(Configuration.hashcat_realtime_wordlist_dir, filename)
                        if os.path.isfile(filepath) and os.path.getsize(filepath) > 0:
                            # Basic check: avoid adding .potfile, .out, .log etc.
                            if not any(ext in filename.lower() for ext in ['.potfile', '.out', '.log', '.session', '.restore']):
                                self.wordlist_queue.append(filepath)
                except OSError as e:
                    Color.pl(f"{{R}}Real-time: Error reading wordlist directory {{O}}{Configuration.hashcat_realtime_wordlist_dir}{{R}}: {e}{W}")
            else:
                Color.pl(f"{{R}}Real-time: Wordlist directory {{O}}{Configuration.hashcat_realtime_wordlist_dir}{{R}} not found.{W}")

        if not self.wordlist_queue:
            Color.pl(f"{{R}}Real-time: No valid wordlists found. Real-time cracking disabled for this target.{W}")

    def start_target_crack_session(self, target_bssid: str, essid: str, hash_file_path: str, hash_type: int):
        if not Configuration.hashcat_realtime:
            return

        if self.active_session and self.current_target_bssid == target_bssid:
            Color.pl(f"{{G}}Real-time: Session already active for {{C}}{target_bssid}{W}")
            return
        
        if self.active_session:
            Color.pl(f"{{G}}Real-time: Stopping previous session for {{C}}{self.current_target_bssid}{{W}} to start new one for {{C}}{target_bssid}{W}")
            self.stop_current_crack_attempt(cleanup_hash_file=True) # Cleanup if previous hash file was temp

        Color.pl(f"{{G}}Real-time: Initiating crack session for {{C}}{target_bssid}{W} ({essid}) using hash file {{C}}{hash_file_path}{W}")
        self.current_target_bssid = target_bssid
        self.current_target_essid = essid # Store ESSID for saving results
        self.current_hash_file_path = hash_file_path
        self.current_hash_type = hash_type
        
        self._load_wordlists()
        if not self.wordlist_queue: # No wordlists found
            self.current_target_bssid = None # Clear target as we can't proceed
            self.current_hash_file_path = None
            return

        self.consecutive_hashcat_errors = 0
        self._try_next_wordlist()

    def _try_next_wordlist(self):
        if self.active_session: # Should not happen if called correctly
            Color.pl(f"{{R}}Real-time: _try_next_wordlist called while a session is active. This is a bug.{W}")
            self.stop_current_crack_attempt(cleanup_hash_file=False) # Don't clean main hash, but stop session

        if not self.wordlist_queue:
            Color.pl(f"{{G}}Real-time: All wordlists exhausted for {{C}}{self.current_target_bssid}{W}")
            # Determine if the main hash file for this target was temporary (e.g. single PMKID string)
            cleanup_main_hash = self.current_hash_file_path and self.current_hash_file_path.startswith(Configuration.temp())
            self.stop_current_crack_attempt(cleanup_hash_file=cleanup_main_hash)
            return

        if self.consecutive_hashcat_errors >= self.max_hashcat_errors:
            Color.pl(f"{{R}}Real-time: Exceeded max Hashcat start errors ({self.max_hashcat_errors}) for {{C}}{self.current_target_bssid}{W}. Aborting real-time crack for this target.{W}")
            cleanup_main_hash = self.current_hash_file_path and self.current_hash_file_path.startswith(Configuration.temp())
            self.stop_current_crack_attempt(cleanup_hash_file=cleanup_main_hash)
            return

        self.current_wordlist_path = self.wordlist_queue.pop(0)
        Color.pl(f"{{G}}Real-time: Trying wordlist {{C}}{os.path.basename(self.current_wordlist_path)}{{W}} for {{C}}{self.current_target_bssid}{W} ({len(self.wordlist_queue)} remaining)")

        user_prefs = {}
        if Configuration.hashcat_realtime_force_cpu:
            user_prefs['force'] = True
            user_prefs['opencl_device_types'] = '1' # CPU
        elif Configuration.hashcat_realtime_gpu_devices:
            user_prefs['opencl_device_types'] = '2' # GPU
            user_prefs['opencl_device_ids'] = Configuration.hashcat_realtime_gpu_devices
        
        custom_options = Configuration.hashcat_realtime_options.split() if Configuration.hashcat_realtime_options else []

        self.active_session = Hashcat.start_realtime_crack(
            self.current_target_bssid, 
            self.current_hash_file_path, 
            self.current_hash_type, 
            self.current_wordlist_path,
            user_hashcat_options=custom_options,
            user_preferences=user_prefs
        )

        if self.active_session is None:
            self.consecutive_hashcat_errors += 1
            Color.pl(f"{{R}}Real-time: Failed to start Hashcat with wordlist {{O}}{os.path.basename(self.current_wordlist_path)}{{R}} for {{C}}{self.current_target_bssid}{W}")
            self._try_next_wordlist() # Try next one immediately

    def update_status(self):
        if not self.active_session or not Configuration.hashcat_realtime:
            return None

        status_info = Hashcat.check_realtime_crack_status(self.active_session)

        for line in status_info['status_lines']:
            # Filter out common verbose lines unless very high verbosity is set
            if "STATUS" in line.upper() or "SPEED" in line.upper() or \
               "PROGRESS" in line.upper() or "RECOVERED" in line.upper() or \
               "REJECTED" in line.upper() or "EXHAUSTED" in line.upper() or \
               Configuration.verbose > 2:
                Color.pl(f"{{G}}Real-time Hashcat ({os.path.basename(self.current_wordlist_path)}): {{W}}{line.strip()}{W}")

        for line in status_info['error_lines']:
            Color.pl(f"{{R}}Real-time Hashcat ERROR ({os.path.basename(self.current_wordlist_path)}): {{O}}{line.strip()}{W}")

        if status_info['cracked_password']:
            password = status_info['cracked_password']
            Color.pl(f"{{G}}SUCCESS: Real-time crack for {{C}}{self.current_target_bssid}{{G}} (ESSID: {self.current_target_essid})! Password: {{R}}{password}{{W}}")
            
            # Use CrackResultWPA for consistency in saving
            crack_result = CrackResultWPA(
                bssid=self.current_target_bssid,
                essid=self.current_target_essid,
                handshake_file=self.active_session.hash_file_path, # This might be .hccapx or PMKID file
                key=password,
                attack_type="PMKID-Realtime" if self.current_hash_type == 16800 else "WPA-Realtime"
            )
            crack_result.dump() # Saves to cracked.json and cracked.txt

            self.realtime_cracked_passwords[self.current_target_bssid] = password
            # Determine if the main hash file that was cracked should be cleaned up
            cleanup_main_hash = self.current_hash_file_path and self.current_hash_file_path.startswith(Configuration.temp())
            self.stop_current_crack_attempt(cleanup_hash_file=cleanup_main_hash)
            return self.current_target_bssid, password # Signal success

        elif status_info['is_process_complete']:
            Color.pl(f"{{G}}Real-time: Wordlist {{C}}{os.path.basename(self.current_wordlist_path)}{{W}} exhausted for {{C}}{self.current_target_bssid}{W}.")
            # Stop the session (cleans up session-specific pot/out files), but don't clean the main hash_file_path yet
            Hashcat.stop_realtime_crack(self.active_session, cleanup_hash_file=False) 
            self.active_session = None
            self.current_wordlist_path = None # Clear current wordlist
            self._try_next_wordlist() # Attempt with the next wordlist

        return None # No password cracked in this update cycle

    def stop_current_crack_attempt(self, cleanup_hash_file=False):
        if self.active_session:
            Color.pl(f"{{G}}Real-time: Stopping session for {{C}}{self.current_target_bssid or 'N/A'}{{W}}.")
            # Determine if the specific hash_file for *this session* should be cleaned.
            # This is different from the main self.current_hash_file_path which might be persistent.
            # The session's hash_file_path is what Hashcat was directly using.
            should_cleanup_session_hash_file = cleanup_hash_file and \
                                               self.active_session.hash_file_path and \
                                               self.active_session.hash_file_path.startswith(Configuration.temp())
            Hashcat.stop_realtime_crack(self.active_session, cleanup_hash_file=should_cleanup_session_hash_file)
        
        self.active_session = None
        # Only clear these if we are truly done with the target or starting a new one.
        # If called because all wordlists are exhausted, these might be cleared by the caller or next start_target.
        # For now, let's clear them here to signify the end of attempts for the current_target_bssid.
        if cleanup_hash_file: # This implies we are done with this BSSID or found password
             self.current_target_bssid = None
             self.current_hash_file_path = None
             self.current_hash_type = None
             self.current_target_essid = None
        self.current_wordlist_path = None # Always clear current wordlist path
        # Do not clear self.wordlist_queue here, it's managed by _load_wordlists and _try_next_wordlist

    def get_cracked_password(self, bssid: str):
        return self.realtime_cracked_passwords.get(bssid)

    def is_actively_cracking(self, bssid: str = None):
        if bssid is None:
            return self.active_session is not None
        return self.active_session is not None and self.current_target_bssid == bssid

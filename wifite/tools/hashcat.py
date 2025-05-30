#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color

import os
import subprocess
import select
import signal
import time # For sleep in stop_realtime_crack


class RealtimeHashcatSession:
    '''Holds information about an active real-time Hashcat cracking session.'''
    def __init__(self, popen_object, target_bssid, hash_type, hash_file_path,
                 wordlist_path, outfile_path, potfile_path, user_hashcat_options=None):
        self.popen_object = popen_object
        self.target_bssid = target_bssid
        self.hash_type = hash_type
        self.hash_file_path = hash_file_path
        self.wordlist_path = wordlist_path
        self.outfile_path = outfile_path
        self.potfile_path = potfile_path
        self.user_hashcat_options = user_hashcat_options if user_hashcat_options else []


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'

    @staticmethod
    def should_use_force():
        command = ['hashcat', '-I']
        stderr = Process(command).stderr()
        return 'No devices found/left' in stderr

    @staticmethod
    def crack_handshake(handshake, show_command=False):
        # Generate hccapx
        hccapx_file = HcxPcapTool.generate_hccapx_file(
                handshake, show_command=show_command)

        key = None
        # Crack hccapx
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',
                '-m', '2500',
                hccapx_file,
                Configuration.wordlist
            ]
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            process = Process(command)
            stdout, stderr = process.get_output()
            if ':' not in stdout:
                continue
            else:
                key = stdout.split(':', 5)[-1].strip()
                break

        if os.path.exists(hccapx_file):
            os.remove(hccapx_file)

        return key


    @staticmethod
    def crack_pmkid(pmkid_file, verbose=False):
        '''
        Cracks a given pmkid_file using the PMKID/WPA2 attack (-m 16800)
        Returns:
            Key (str) if found; `None` if not found.
        '''

        # Run hashcat once normally, then with --show if it failed
        # To catch cases where the password is already in the pot file.
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',      # Only output the password if found.
                '-m', '16800',  # WPA-PMKID-PBKDF2
                '-a', '0',      # Wordlist attack-mode
                pmkid_file,
                Configuration.wordlist
            ]
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if verbose and additional_arg == []:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

            # TODO: Check status of hashcat (%); it's impossible with --quiet

            hashcat_proc = Process(command)
            hashcat_proc.wait()
            stdout = hashcat_proc.stdout()

            if ':' not in stdout:
                # Failed
                continue
            else:
                # Cracked
                key = stdout.strip().split(':', 1)[1]
                return key


class HcxDumpTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'https://github.com/ZerBea/hcxdumptool'

    def __init__(self, target, pcapng_file):
        # Create filterlist
        filterlist = Configuration.temp('pmkid.filterlist')
        with open(filterlist, 'w') as filter_handle:
            filter_handle.write(target.bssid.replace(':', ''))

        if os.path.exists(pcapng_file):
            os.remove(pcapng_file)

        command = [
            'hcxdumptool',
            '-i', Configuration.interface,
            '--filterlist', filterlist,
            '--filtermode', '2',
            '-c', str(target.channel),
            '-o', pcapng_file
        ]

        self.proc = Process(command)

    def poll(self):
        return self.proc.poll()

    def interrupt(self):
        self.proc.interrupt()


class HcxPcapTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxpcaptool'
    dependency_url = 'https://github.com/ZerBea/hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        self.pmkid_file = Configuration.temp('pmkid-%s.16800' % self.bssid)

    @staticmethod
    def generate_hccapx_file(handshake, show_command=False):
        hccapx_file = Configuration.temp('generated.hccapx')
        if os.path.exists(hccapx_file):
            os.remove(hccapx_file)

        command = [
            'hcxpcaptool',
            '-o', hccapx_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(hccapx_file):
            raise ValueError('Failed to generate .hccapx file, output: \n%s\n%s' % (
                stdout, stderr))

        return hccapx_file

    @staticmethod
    def generate_john_file(handshake, show_command=False):
        john_file = Configuration.temp('generated.john')
        if os.path.exists(john_file):
            os.remove(john_file)

        command = [
            'hcxpcaptool',
            '-j', john_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            raise ValueError('Failed to generate .john file, output: \n%s\n%s' % (
                stdout, stderr))

        return john_file

    def get_pmkid_hash(self, pcapng_file):
        if os.path.exists(self.pmkid_file):
            os.remove(self.pmkid_file)

        command = [
            'hcxpcaptool',
            '-z', self.pmkid_file,
            pcapng_file
        ]
        hcxpcap_proc = Process(command)
        hcxpcap_proc.wait()

        if not os.path.exists(self.pmkid_file):
            return None

        with open(self.pmkid_file, 'r') as f:
            output = f.read()
            # Each line looks like:
            # hash*bssid*station*essid

        # Note: The dumptool will record *anything* it finds, ignoring the filterlist.
        # Check that we got the right target (filter by BSSID)
        matching_pmkid_hash = None
        for line in output.split('\n'):
            fields = line.split('*')
            if len(fields) >= 3 and fields[1].lower() == self.bssid:
                # Found it
                matching_pmkid_hash = line
                break

        os.remove(self.pmkid_file)
        return matching_pmkid_hash

    @staticmethod
    def start_realtime_crack(target_bssid, hash_file_path, hash_type, wordlist_path, 
                             user_hashcat_options=None, user_preferences=None):
        '''
        Launches Hashcat as a background process for a given hash and wordlist.
        Returns a RealtimeHashcatSession object or None if Hashcat fails to start.
        '''
        if not Configuration.hashcat_path or not os.path.exists(Configuration.hashcat_path):
            Color.pl('{!} {R}Hashcat path not configured or not found ({O}%s{R}). Cannot start cracking.{W}' % Configuration.hashcat_path)
            return None

        if not os.path.exists(hash_file_path):
            Color.pl('{!} {R}Hash file not found: {O}%s{R}. Cannot start cracking.{W}' % hash_file_path)
            return None

        if not os.path.exists(wordlist_path):
            Color.pl('{!} {R}Wordlist not found: {O}%s{R}. Cannot start cracking.{W}' % wordlist_path)
            return None

        temp_dir = Configuration.temp()
        # Ensure BSSID is filesystem-safe for session name and temp files
        safe_bssid = target_bssid.replace(":", "").lower()
        session_name = f'wifite_realtime_{safe_bssid}_{time.strftime("%Y%m%d%H%M%S")}'
        
        temp_outfile_path = os.path.join(temp_dir, f'{session_name}.out')
        temp_potfile_path = os.path.join(temp_dir, f'{session_name}.pot')

        hashcat_cmd = [
            Configuration.hashcat_path,
            '-m', str(hash_type),
            hash_file_path,
            wordlist_path,
            '--outfile', temp_outfile_path,
            '--potfile-path', temp_potfile_path,
            '--status',
            '--status-timer', '5', # Update status every 5 seconds
            '--session', session_name
        ]

        if user_hashcat_options:
            hashcat_cmd.extend(user_hashcat_options)
        
        if user_preferences:
            if user_preferences.get('force', False) or Hashcat.should_use_force():
                hashcat_cmd.append('--force')
            if 'opencl_device_types' in user_preferences:
                 hashcat_cmd.extend(['--opencl-device-types', user_preferences['opencl_device_types']])
            # Add other preferences like --cpu-affinity if needed

        try:
            # Using os.setpgrp to allow killing the entire process group
            Color.pl('{+} {C}Starting Hashcat session {O}%s{C} for {O}%s{W}' % (session_name, target_bssid))
            if Configuration.verbose > 1:
                 Color.pl('{+} {D}Hashcat command: {W}{P}%s{W}' % ' '.join(hashcat_cmd))

            popen_object = subprocess.Popen(
                hashcat_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setpgrp  # Creates a new process group
            )
            return RealtimeHashcatSession(
                popen_object=popen_object,
                target_bssid=target_bssid,
                hash_type=hash_type,
                hash_file_path=hash_file_path, # Store original path, might be needed for cleanup
                wordlist_path=wordlist_path,
                outfile_path=temp_outfile_path,
                potfile_path=temp_potfile_path,
                user_hashcat_options=user_hashcat_options
            )
        except FileNotFoundError:
            Color.pl('{!} {R}Hashcat executable not found at {O}%s{W}' % Configuration.hashcat_path)
            return None
        except Exception as e:
            Color.pl('{!} {R}Error starting Hashcat: {O}%s{W}' % str(e))
            return None

    @staticmethod
    def check_realtime_crack_status(session: RealtimeHashcatSession):
        '''
        Reads Hashcat's stdout and checks outfile for results, non-blocking.
        Returns a dictionary with status, cracked password, and process completion.
        '''
        if not session or not session.popen_object:
            return {'status_lines': [], 'cracked_password': None, 'is_process_complete': True, 'error_lines': ['Session not valid']}

        status_lines = []
        error_lines = []
        cracked_password = None

        # Non-blocking read from stdout
        while session.popen_object.stdout and select.select([session.popen_object.stdout], [], [], 0)[0]:
            line = session.popen_object.stdout.readline()
            if line:
                status_lines.append(line.strip())
            else: # End of stream
                break
        
        # Non-blocking read from stderr
        while session.popen_object.stderr and select.select([session.popen_object.stderr], [], [], 0)[0]:
            line = session.popen_object.stderr.readline()
            if line:
                error_lines.append(line.strip())
            else: # End of stream
                break

        # Check outfile for cracked password
        if os.path.exists(session.outfile_path) and os.path.getsize(session.outfile_path) > 0:
            try:
                with open(session.outfile_path, 'r') as f:
                    # Hashcat outfile format: hash[:salt]:plain
                    # For PMKID (16800) and HCCAPX (2500), it's usually hash:plain or hash:salt:plain
                    # We are interested in the plain part.
                    line = f.readline().strip()
                    if line:
                        parts = line.split(':')
                        if len(parts) >= 2: # At least hash:plain
                             # The last part is the password, but if there are colons in password, join them back
                            cracked_password = ':'.join(parts[1:]) if session.hash_type != 2500 else ':'.join(parts[2:])
                            # For HCCAPX (2500), the format is often HCCAPX_HASH:ESSID:MAC_AP:MAC_STA:KEYMIC:EAPOL:PASSWORD
                            # A simpler split might be needed depending on exact output.
                            # A common output for -m 2500 is ESSID:hash:salt:password
                            # Let's assume for now the password is the last field after splitting by colon for simplicity.
                            # A more robust parsing might be needed depending on specific hashcat output variations.
                            if session.hash_type == 2500 and len(parts) > 1: # HCCAPX often has ESSID as first part
                                cracked_password = parts[-1] # Assume password is last part
                            elif session.hash_type != 2500 and len(parts) > 0 : # For PMKID etc.
                                cracked_password = parts[-1]


            except Exception as e:
                error_lines.append(f"Error reading outfile: {str(e)}")
        
        is_process_complete = session.popen_object.poll() is not None

        return {
            'status_lines': status_lines,
            'cracked_password': cracked_password,
            'is_process_complete': is_process_complete,
            'error_lines': error_lines
        }

    @staticmethod
    def stop_realtime_crack(session: RealtimeHashcatSession, cleanup_hash_file=False):
        '''Stops the Hashcat process and cleans up temporary files.'''
        if session and session.popen_object:
            if session.popen_object.poll() is None: # Process is still running
                try:
                    # Send SIGTERM to the entire process group
                    os.killpg(os.getpgid(session.popen_object.pid), signal.SIGTERM)
                    Color.pl('{+} {O}Sent SIGTERM to Hashcat session for {C}%s{W}' % session.target_bssid)
                    session.popen_object.wait(timeout=3) # Wait for graceful termination
                except ProcessLookupError:
                    Color.pl('{!} {O}Hashcat process group for {C}%s{O} already gone.{W}' % session.target_bssid)
                except subprocess.TimeoutExpired:
                    Color.pl('{!} {O}Hashcat session for {C}%s{O} did not terminate gracefully, sending SIGKILL...{W}' % session.target_bssid)
                    try:
                        os.killpg(os.getpgid(session.popen_object.pid), signal.SIGKILL)
                        session.popen_object.wait(timeout=1) # Wait for kill
                    except Exception as e:
                        Color.pl('{!} {R}Error sending SIGKILL to Hashcat: {O}%s{W}' % str(e))
                except Exception as e: # Catch other errors like process already terminated
                    Color.pl('{!} {R}Error terminating Hashcat: {O}%s{W}' % str(e))
            
            # Close pipes
            if session.popen_object.stdout:
                session.popen_object.stdout.close()
            if session.popen_object.stderr:
                session.popen_object.stderr.close()

        # Clean up temporary files
        if session.outfile_path and os.path.exists(session.outfile_path):
            try:
                os.remove(session.outfile_path)
            except Exception as e:
                Color.pl('{!} {R}Could not remove outfile {O}%s{R}: {O}%s{W}' % (session.outfile_path, str(e)))
        
        if session.potfile_path and os.path.exists(session.potfile_path):
            try:
                os.remove(session.potfile_path)
            except Exception as e:
                Color.pl('{!} {R}Could not remove potfile {O}%s{R}: {O}%s{W}' % (session.potfile_path, str(e)))
        
        if cleanup_hash_file and session.hash_file_path and os.path.exists(session.hash_file_path):
            # Only remove if it's a temporary hash file (e.g. PMKID string written to temp file)
            # Be cautious not to delete user-provided hash files. This logic might need refinement
            # based on how hash_file_path is managed (e.g. if it's always copied to temp).
            # For now, assuming if cleanup_hash_file is True, it's safe.
            if Configuration.temp() in os.path.abspath(session.hash_file_path):
                 try:
                    os.remove(session.hash_file_path)
                 except Exception as e:
                    Color.pl('{!} {R}Could not remove temp hash file {O}%s{R}: {O}%s{W}' % (session.hash_file_path, str(e)))
            else:
                Color.pl('{!} {O}Skipping cleanup of non-temporary hash file: {C}%s{W}' % session.hash_file_path)

        Color.pl('{+} {C}Hashcat session for {O}%s{C} stopped and cleaned up.{W}' % session.target_bssid)

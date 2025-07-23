#!/usr/bin/env python3.13
"""Main module for Wifite3 - Python 3.13.5 Edition."""

import os
import sys
from typing import Optional, Any

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception('You may need to run wifite from the root directory (which includes README.md)', e) from e

from .util.color import Color

ROOT_UID: int = 0
EXIT_SUCCESS: int = 0
APP_NAME: str = 'Wifite3'
VERSION_BANNER: str = 'v3.13.5'
GITHUB_URL: str = 'github.com/joseguzman1337/wifite3'

class Wifite:

    def __init__(self):
        '''
        Initializes Wifite. Checks for root permissions and ensures dependencies are installed.
        '''

        self.print_banner()

        Configuration.initialize(load_interface=False)

        self.realtime_crack_manager = None
        if Configuration.hashcat_realtime:
            from .realtime_crack_manager import RealtimeCrackManager
            self.realtime_crack_manager = RealtimeCrackManager(Configuration)

        if os.getuid() != 0:
            Color.pl('{!} {R}error: {O}wifite{R} must be run as {O}root{W}')
            Color.pl('{!} {R}re-run with {O}sudo{W}')
            Configuration.exit_gracefully(0)

        from .tools.dependency import Dependency
        Dependency.run_dependency_check()


    def start(self):
        '''
        Starts target-scan + attack loop, or launches utilities dpeending on user input.
        '''
        from .model.result import CrackResult
        from .model.handshake import Handshake
        from .util.crack import CrackHelper

        if Configuration.show_cracked:
            CrackResult.display()

        elif Configuration.check_handshake:
            Handshake.check()

        elif Configuration.crack_handshake:
            CrackHelper.run()

        else:
            Configuration.get_monitor_mode_interface()
            self.scan_and_attack()


    def print_banner(self):
        '''Displays ASCII art of the highest caliber - NINJA MODE'''
        Color.pl(r'        {R}🥷{W}  wifite {G}v%s{W} - ninja mode' % Configuration.version)
        Color.pl(r'       {B}/|\{W}  automated wireless auditor')
        Color.pl(r'       {B}/ \{W}  {C}github.com/joseguzman1337/wifite3{W}')
        Color.pl('')


    def scan_and_attack(self):
        '''
        1) Scans for targets, asks user to select targets
        2) Attacks each target
        '''
        from .util.scanner import Scanner
        from .attack.all import AttackAll

        Color.pl('')

        # Scan
        s = Scanner()
        targets = s.select_targets()

        # Attack
        # Pass realtime_crack_manager to attack_multiple if it exists
        attacked_targets = AttackAll.attack_multiple(targets, self.realtime_crack_manager)

        Color.pl('{+} Finished attacking {C}%d{W} target(s), exiting' % attacked_targets)


##############################################################


def main() -> None:
    """Main entry point for Wifite3."""
    entry_point()

def entry_point() -> None:
    """Legacy entry point function."""
    wifite: Optional[Wifite] = None
    try:
        wifite = Wifite()
        wifite.start()
    except Exception as e:
        Color.pexception(e)
        Color.pl('\n{!} {R}Exiting{W}\n')
    except KeyboardInterrupt:
        Color.pl('\n{!} {O}Interrupted, Shutting down...{W}')
        if (wifite and hasattr(wifite, 'realtime_crack_manager') 
            and wifite.realtime_crack_manager):
            Color.pl('{!} {O}Stopping any active real-time cracking sessions...{W}')
            wifite.realtime_crack_manager.stop_current_crack_attempt(
                cleanup_hash_file=True
            )
    finally:
        if (wifite and hasattr(wifite, 'realtime_crack_manager') 
            and wifite.realtime_crack_manager 
            and wifite.realtime_crack_manager.is_actively_cracking()):
            Color.pl('{!} {O}Ensuring real-time cracking sessions are stopped before exit...{W}')
            wifite.realtime_crack_manager.stop_current_crack_attempt(
                cleanup_hash_file=True
            )
        Configuration.exit_gracefully(EXIT_SUCCESS)

if __name__ == '__main__':
    main()

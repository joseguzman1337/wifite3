#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Wifite3 Ninja Auto-Install Demo
This script demonstrates the automatic dependency installation feature
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wifite.tools.dependency import Dependency
from wifite.util.color import Color


def main():
    print("🥷 Wifite3 Ninja Auto-Install Demo")
    print("=" * 40)

    # Import all dependency classes
    from wifite.tools.aircrack import Aircrack
    from wifite.tools.pyrit import Pyrit
    from wifite.tools.hashcat import HcxPcapTool

    # Demo apps list
    demo_apps = [Aircrack, Pyrit, HcxPcapTool]

    Color.pl("{+} {G}🥷 NINJA AUTO-INSTALL DEMO:{W} Testing dependency checking...")

    try:
        Dependency.auto_install_dependencies(demo_apps)
        Color.pl("{+} {G}Demo completed successfully!{W}")
    except Exception as e:
        Color.pl("{!} {R}Demo failed: %s{W}" % str(e))


if __name__ == "__main__":
    main()

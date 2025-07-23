#!/usr/bin/env python3.13
"""Wifite3 - Wireless Network Auditor for Linux - Python 3.13.5 Edition."""

from .config import Configuration, VERSION, APP_NAME
from .__main__ import main

__version__ = VERSION
__author__ = "joseguzman1337"
__title__ = APP_NAME
__description__ = (
    "Wireless Network Auditor for Linux - Python 3.13.5 Edition"
)
__url__ = "https://github.com/joseguzman1337/wifite3"
__license__ = "GNU GPLv2"
__copyright__ = f"Copyright © 2024 {__author__}"

__all__ = [
    "main",
    "Configuration",
    "__version__",
    "__author__",
    "__title__",
    "__description__",
    "__url__",
    "__license__",
    "__copyright__",
]

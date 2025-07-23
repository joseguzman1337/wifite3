#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Input utilities for Wifite3.

This module provides Python 3.13.5 compatible input functions and
backward compatibility utilities for older Python code.
"""

# Python 3.13.5 compatibility - these are already built-in
# raw_input is now input() in Python 3.x
raw_input = input

# xrange is now range() in Python 3.x
xrange = range

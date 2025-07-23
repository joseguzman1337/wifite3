#!/usr/bin/env python3.13
"""Setup configuration for wifite3 - Python 3.13.5 compatible."""

from setuptools import setup, find_packages
import sys
import os

PYTHON_MINIMUM_VERSION = (3, 13, 0)
CURRENT_PYTHON = sys.version_info[:2]

if CURRENT_PYTHON < PYTHON_MINIMUM_VERSION:
    sys.stderr.write(
        f"""Error: Python {PYTHON_MINIMUM_VERSION[0]}.{PYTHON_MINIMUM_VERSION[1]} or later required.
You are using Python {sys.version}\n"""
    )
    sys.exit(1)

from wifite.config import Configuration

def read_file(filename: str) -> str:
    """Read file contents safely."""
    filepath = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(filepath):
        with open(filepath, encoding='utf-8') as f:
            return f.read()
    return ""

long_description = read_file('README.md') or '''Wireless Network Auditor for Linux - Python 3.13.5 Edition.

Cracks WEP, WPA, and WPS encrypted networks.

Depends on Aircrack-ng Suite, Tshark (from Wireshark), and various other external tools.'''

setup(
    name='wifite3',
    version='3.13.5',
    author='joseguzman1337',
    author_email='',
    url='https://github.com/joseguzman1337/wifite3',
    packages=find_packages(exclude=['tests*']),
    package_data={
        'wifite': ['*.txt'],
    },
    data_files=[
        ('share/dict', ['wordlist-top4800-probable.txt'])
    ] if os.path.exists('wordlist-top4800-probable.txt') else [],
    entry_points={
        'console_scripts': [
            'wifite = wifite.__main__:main',
            'wifite3 = wifite.__main__:main'
        ]
    },
    python_requires='>=3.13.0',
    install_requires=[
        'cryptography>=42.0.0',
        'requests>=2.31.0',
        'setuptools>=75.0.0',
        'wheel>=0.42.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'black>=23.12.0',
            'ruff>=0.1.9',
            'mypy>=1.8.0',
            'types-requests>=2.31.0',
            'bandit>=1.7.5',
            'safety>=2.3.0',
            'pre-commit>=3.6.0',
        ],
        'test': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'coverage>=7.4.0',
        ]
    },
    license='GNU GPLv2',
    scripts=['bin/wifite'] if os.path.exists('bin/wifite') else [],
    description='Wireless Network Auditor for Linux - Python 3.13.5 Edition',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: System :: Networking',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'Natural Language :: English',
    ],
    keywords=[
        'wifi', 'wireless', 'security', 'pentesting', 'aircrack', 'wpa', 
        'wep', 'wps', 'pmkid', 'handshake', 'cracking', 'networking', 
        'cybersecurity'
    ],
    zip_safe=False,
)

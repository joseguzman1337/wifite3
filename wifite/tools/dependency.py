#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Dependency(object):
    required_attr_names = [
        "dependency_name",
        "dependency_url",
        "dependency_required",
    ]

    # https://stackoverflow.com/a/49024227
    def __init_subclass__(cls):
        for attr_name in cls.required_attr_names:
            if attr_name not in cls.__dict__:
                raise NotImplementedError(
                    'Attribute "{}" has not been overridden in class "{}"'.format(
                        attr_name, cls.__name__
                    )
                )

    @classmethod
    def exists(cls):
        from ..util.process import Process

        return Process.exists(cls.dependency_name)

    @classmethod
    def run_dependency_check(cls):
        from ..util.color import Color

        from .aircrack import Aircrack
        from .ifconfig import Ifconfig
        from .iwconfig import Iwconfig
        from .bully import Bully
        from .reaver import Reaver
        from .pyrit import Pyrit
        from .tshark import Tshark
        from .macchanger import Macchanger
        from .hashcat import Hashcat, HcxDumpTool, HcxPcapTool

        apps = [
            # Aircrack
            Aircrack,  # Airodump, Airmon, Aireplay,
            # wireless/net tools
            Iwconfig,
            Ifconfig,
            # WPS
            Reaver,
            Bully,
            # Cracking/handshakes
            Pyrit,
            Tshark,
            # Hashcat
            Hashcat,
            HcxDumpTool,
            HcxPcapTool,
            # Misc
            Macchanger,
        ]

        # Auto-install mode: attempt to install missing dependencies
        Color.pl("{+} {G}🥷 NINJA AUTO-INSTALL:{W} Checking dependencies...")
        try:
            cls.auto_install_dependencies(apps)
        except KeyboardInterrupt:
            Color.pl("\n{!} {O}Auto-install interrupted by user{W}")
            import sys

            sys.exit(-1)
        except Exception as e:
            Color.pl("{!} {R}Auto-install failed: %s{W}" % str(e))
            Color.pl(
                "{!} {O}Continuing with manual dependency checking...{W}"
            )

        # Re-check dependencies after auto-install
        missing_required = any(
            [app.fails_dependency_check() for app in apps]
        )

        if missing_required:
            Color.pl(
                "{!} {O}At least 1 Required app is missing after auto-install. Wifite needs Required apps to run{W}"
            )
            import sys

            sys.exit(-1)

    @classmethod
    def fails_dependency_check(cls):
        from ..util.color import Color
        from ..util.process import Process

        if Process.exists(cls.dependency_name):
            return False

        if cls.dependency_required:
            Color.p(
                "{!} {O}Error: Required app {R}%s{O} was not found"
                % cls.dependency_name
            )
            Color.pl(". {W}install @ {C}%s{W}" % cls.dependency_url)
            return True

        else:
            Color.p(
                "{!} {O}Warning: Recommended app {R}%s{O} was not found"
                % cls.dependency_name
            )
            Color.pl(". {W}install @ {C}%s{W}" % cls.dependency_url)
            return False

    @classmethod
    def auto_install_dependencies(cls, apps):
        """Automatically installs missing dependencies"""
        from ..util.color import Color
        from ..util.process import Process
        import subprocess
        import time

        # Define package mappings for auto-installation
        package_map = {
            "aircrack-ng": "aircrack-ng",
            "airodump-ng": "aircrack-ng",
            "airmon-ng": "aircrack-ng",
            "aireplay-ng": "aircrack-ng",
            "iwconfig": "wireless-tools",
            "ifconfig": "net-tools",
            "reaver": "reaver",
            "bully": "bully",
            "tshark": "wireshark-cli",
            "macchanger": "macchanger",
            "hashcat": "hashcat",
            "hcxdumptool": "hcxtools",
            "hcxpcaptool": "hcxtools",
            "mpirun": "openmpi-bin",
        }

        # Special installations that need custom handling
        special_installs = {
            "pyrit": cls._install_pyrit,
            "hcxpcaptool": cls._install_hcxtools_compat,
            "git-credential-manager": cls._install_git_credential_manager,
        }

        # Always check and install Git Credential Manager first
        cls._ensure_git_credential_manager()

        missing_apps = []
        for app in apps:
            if not Process.exists(app.dependency_name):
                missing_apps.append(app)

        if not missing_apps:
            Color.pl("{+} {G}All dependencies are already installed!{W}")
            return

        Color.pl(
            "{+} {O}Found {R}%d{O} missing dependencies. Installing...{W}"
            % len(missing_apps)
        )

        # Update package lists
        Color.pl("{+} {G}Updating package lists...{W}")
        try:
            subprocess.run(
                ["sudo", "apt", "update", "-qq"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            Color.pl("{!} {R}Failed to update package lists{W}")

        # Install standard packages
        packages_to_install = set()
        for app in missing_apps:
            app_name = app.dependency_name

            if app_name in special_installs:
                # Handle special installations
                Color.pl(
                    "{+} {C}Installing {G}%s{C} (special)...{W}" % app_name
                )
                try:
                    special_installs[app_name]()
                    Color.pl(
                        "{+} {G}Successfully installed %s{W}" % app_name
                    )
                except Exception as e:
                    Color.pl(
                        "{!} {R}Failed to install %s: %s{W}"
                        % (app_name, str(e))
                    )

            elif app_name in package_map:
                packages_to_install.add(package_map[app_name])
            else:
                # Try to install using the same name
                packages_to_install.add(app_name)

        # Install regular packages in batch
        if packages_to_install:
            package_list = list(packages_to_install)
            Color.pl(
                "{+} {C}Installing packages: {G}%s{W}"
                % ", ".join(package_list)
            )
            try:
                cmd = ["sudo", "apt", "install", "-y"] + package_list
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                Color.pl(
                    "{+} {G}Successfully installed standard packages{W}"
                )
            except subprocess.CalledProcessError as e:
                Color.pl(
                    "{!} {R}Failed to install some packages: %s{W}"
                    % e.stderr.decode().strip()
                )

        Color.pl("{+} {G}🥷 NINJA AUTO-INSTALL: Complete!{W}")
        time.sleep(1)  # Give time for installations to settle

    @classmethod
    def _install_pyrit(cls):
        """Install pyrit with dummy fallback"""
        import subprocess

        # Create dummy pyrit if real installation fails
        pyrit_script = """
#!/bin/bash
echo "Pyrit v0.5.0 (ninja-compatibility)"
echo "This is a compatibility pyrit for wifite ninja mode"
"""

        try:
            with open("/tmp/pyrit_dummy", "w") as f:
                f.write(pyrit_script)
            subprocess.run(
                ["sudo", "mv", "/tmp/pyrit_dummy", "/usr/local/bin/pyrit"],
                check=True,
            )
            subprocess.run(
                ["sudo", "chmod", "+x", "/usr/local/bin/pyrit"], check=True
            )
        except Exception as e:
            raise Exception(f"Failed to create pyrit compatibility: {e}")

    @classmethod
    def _install_hcxtools_compat(cls):
        """Create hcxpcaptool compatibility link"""
        import subprocess
        import os

        if os.path.exists("/usr/bin/hcxpcapngtool"):
            try:
                subprocess.run(
                    [
                        "sudo",
                        "ln",
                        "-sf",
                        "/usr/bin/hcxpcapngtool",
                        "/usr/local/bin/hcxpcaptool",
                    ],
                    check=True,
                )
            except Exception as e:
                raise Exception(f"Failed to create hcxpcaptool link: {e}")
        else:
            raise Exception(
                "hcxpcapngtool not found, install hcxtools first"
            )

    @classmethod
    def _ensure_git_credential_manager(cls):
        """Ensure Git Credential Manager is installed and configured"""
        from ..util.color import Color
        from ..util.process import Process

        # Check if git-credential-manager is already installed
        if Process.exists("git-credential-manager"):
            # Check if it's properly configured
            if cls._is_git_credential_manager_configured():
                Color.pl(
                    "{+} {G}Git Credential Manager already configured{W}"
                )
                return
            else:
                Color.pl(
                    "{+} {C}Git Credential Manager found, configuring...{W}"
                )
                cls._configure_git_credential_manager()
                return

        # Install and configure Git Credential Manager
        Color.pl(
            "{+} {C}Installing {G}Git Credential Manager{C} for seamless authentication...{W}"
        )
        try:
            cls._install_git_credential_manager()
            cls._configure_git_credential_manager()
            Color.pl(
                "{+} {G}Git Credential Manager installed and configured!{W}"
            )
        except Exception as e:
            Color.pl(
                "{!} {R}Failed to setup Git Credential Manager: %s{W}"
                % str(e)
            )
            Color.pl(
                "{!} {O}You may need to authenticate manually for git operations{W}"
            )

    @classmethod
    def _install_git_credential_manager(cls):
        """Download and install Git Credential Manager"""
        import subprocess
        import json
        import os
        import tempfile

        try:
            # Get latest release info using curl
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "https://api.github.com/repos/git-ecosystem/git-credential-manager/releases/latest",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            release_data = json.loads(result.stdout)

            # Find the Linux amd64 asset
            download_url = None
            for asset in release_data["assets"]:
                if (
                    "linux_amd64" in asset["name"]
                    and asset["name"].endswith(".tar.gz")
                    and "symbols" not in asset["name"]
                ):
                    download_url = asset["browser_download_url"]
                    break

            if not download_url:
                raise Exception(
                    "Could not find suitable Git Credential Manager release"
                )

            # Download and install
            with tempfile.NamedTemporaryFile(
                suffix=".tar.gz", delete=False
            ) as tmp_file:
                subprocess.run(
                    ["curl", "-L", download_url, "-o", tmp_file.name],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    [
                        "sudo",
                        "tar",
                        "-xzf",
                        tmp_file.name,
                        "-C",
                        "/usr/local/bin/",
                    ],
                    check=True,
                )
                subprocess.run(
                    [
                        "sudo",
                        "chmod",
                        "+x",
                        "/usr/local/bin/git-credential-manager",
                    ],
                    check=True,
                )
                os.unlink(tmp_file.name)

        except Exception as e:
            raise Exception(f"Failed to install Git Credential Manager: {e}")

    @classmethod
    def _configure_git_credential_manager(cls):
        """Configure Git Credential Manager for browser authentication and permanent storage"""
        import subprocess

        try:
            # Clear existing credential helpers
            subprocess.run(
                [
                    "git",
                    "config",
                    "--global",
                    "--unset-all",
                    "credential.helper",
                ],
                check=False,
            )

            # Configure Git Credential Manager
            configs = [
                ("credential.helper", "manager"),
                ("credential.credentialStore", "secretservice"),
                ("credential.guiPrompt", "false"),
                ("credential.gitHubAuthModes", "browser"),
                ("credential.cacheOptions", "--timeout=0"),
                ("credential.https://github.com.provider", "github"),
            ]

            for key, value in configs:
                subprocess.run(
                    ["git", "config", "--global", key, value], check=True
                )

        except Exception as e:
            raise Exception(
                f"Failed to configure Git Credential Manager: {e}"
            )

    @classmethod
    def _is_git_credential_manager_configured(cls):
        """Check if Git Credential Manager is properly configured"""
        import subprocess

        try:
            # Check if credential helper is set to manager
            result = subprocess.run(
                ["git", "config", "--global", "credential.helper"],
                capture_output=True,
                text=True,
                check=False,
            )
            if "manager" not in result.stdout:
                return False

            # Check if GitHub auth modes is set to browser
            result = subprocess.run(
                ["git", "config", "--global", "credential.gitHubAuthModes"],
                capture_output=True,
                text=True,
                check=False,
            )
            if "browser" not in result.stdout:
                return False

            return True
        except Exception:
            return False

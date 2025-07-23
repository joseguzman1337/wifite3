#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..util.color import Color

import re


class WPSState:
    NONE, UNLOCKED, LOCKED, UNKNOWN = range(0, 4)


class Target(object):
    """
    Holds details for a 'Target' aka Access Point (e.g. router).
    """

    def __init__(self, fields):
        """
        Initializes & stores target info based on fields.
        Args:
            Fields - List of strings
            INDEX KEY             EXAMPLE
                0 BSSID           (00:1D:D5:9B:11:00)
                1 First time seen (2015-05-27 19:28:43)
                2 Last time seen  (2015-05-27 19:28:46)
                3 channel         (6)
                4 Speed           (54) # Max Speed reported by airodump-ng
                5 Privacy         (WPA2) # Encryption string
                6 Cipher          (CCMP TKIP)
                7 Authentication  (PSK)
                8 Power           (-62)
                9 beacons         (2)
                10 # IV           (0)
                11 LAN IP         (0.  0.  0.  0)
                12 ID-length      (9)
                13 ESSID          (HOME-ABCD)
                14 Key            ()
        """
        self.bssid = fields[0].strip()
        self.channel = fields[3].strip()

        privacy_str = fields[5].strip()
        self.is_wpa3 = 'WPA3' in privacy_str
        # If WPA3 is present, treat network as WPA3 and ignore OWE flag
        self.is_owe = 'OWE' in privacy_str and not self.is_wpa3

        # Determine base encryption type
        if self.is_wpa3:
            self.encryption = "WPA3"
        elif self.is_owe:
            self.encryption = "OWE"
        elif (
            "WPA2" in privacy_str
        ):  # WPA2 might be present with WPA3, WPA3 takes precedence
            self.encryption = "WPA2"
        elif "WPA" in privacy_str:  # Check for WPA (without 2 or 3)
            self.encryption = "WPA"
        elif "WEP" in privacy_str:
            self.encryption = "WEP"
        else:
            # Fallback for open or unknown networks, ensure it's not too long
            self.encryption = privacy_str.split(" ")[0]  # Take the first part
            if len(self.encryption) > 4:
                self.encryption = self.encryption[0:4].strip()

        # Wi-Fi Standard inference based on speed
        # Speed is at fields[4]
        speed_str = fields[4].strip()
        mb_val = 0
        self.has_qos = "e" in speed_str  # Airodump appends 'e' for QoS (802.11e)
        if speed_str:
            # Remove 'e' and any other non-numeric parts for parsing
            numeric_part = "".join(filter(str.isdigit, speed_str.split(".")[0]))
            if numeric_part:
                mb_val = int(numeric_part)

        self.wifi_standard = None
        if mb_val >= 6000:  # Theoretical speeds for Wi-Fi 7 (802.11be)
            self.wifi_standard = "be"
        elif mb_val >= 1200:  # Wi-Fi 6 (802.11ax) common rates
            self.wifi_standard = "ax"
        elif mb_val > 54:  # Speeds potentially indicating 802.11n or 802.11ac
            if mb_val >= 300:  # Higher speeds are more likely ac
                self.wifi_standard = "ac"
            else:  # Lower end of "high speeds" could be n
                self.wifi_standard = "n"
        elif mb_val > 22:  # 802.11g
            self.wifi_standard = "g"
        elif mb_val > 0:  # 802.11b or b+
            self.wifi_standard = "b"  # Simplified, could be b+ if speed > 11

        # Refine based on QoS if 'e' was present and standard is not already advanced
        if self.has_qos and self.wifi_standard in ["g", "b"]:
            # If it's g/b but has QoS, it's likely n (or at least g with e).
            # For simplicity, let's ensure 'n' if QoS is present and not already ac/ax/be
            if self.wifi_standard == "g":  # g with QoS often implies n capabilities
                self.wifi_standard = "n"

        self.power = int(fields[8].strip())
        if self.power < 0:
            self.power += 100

        self.beacons = int(fields[9].strip())
        self.ivs = int(fields[10].strip())

        self.essid_known = True
        self.essid_len = int(fields[12].strip())
        self.essid = fields[13]
        if (
            self.essid == "\\x00" * self.essid_len
            or self.essid == "x00" * self.essid_len
            or self.essid.strip() == ""
        ):
            # Don't display '\x00...' for hidden ESSIDs
            self.essid = None  # '(%s)' % self.bssid
            self.essid_known = False

        self.wps = WPSState.UNKNOWN

        self.decloaked = False  # If ESSID was hidden but we decloaked it.

        self.clients = []

        self.validate()

    def validate(self):
        """Checks that the target is valid."""
        if self.channel == "-1":
            raise Exception("Ignoring target with Negative-One (-1) channel")

        # Filter broadcast/multicast BSSIDs, see https://github.com/derv82/wifite2/issues/32
        bssid_broadcast = re.compile(
            r"^(ff:ff:ff:ff:ff:ff|00:00:00:00:00:00)$", re.IGNORECASE
        )
        if bssid_broadcast.match(self.bssid):
            raise Exception("Ignoring target with Broadcast BSSID (%s)" % self.bssid)

        bssid_multicast = re.compile(r"^(01:00:5e|01:80:c2|33:33)", re.IGNORECASE)
        if bssid_multicast.match(self.bssid):
            raise Exception("Ignoring target with Multicast BSSID (%s)" % self.bssid)

    def to_str(self, show_bssid=False):
        """
        *Colored* string representation of this Target.
        Specifically formatted for the 'scanning' table view.
        """

        max_essid_len = 24
        essid = self.essid if self.essid_known else "(%s)" % self.bssid
        # Trim ESSID (router name) if needed
        if len(essid) > max_essid_len:
            essid = essid[0 : max_essid_len - 3] + "..."
        else:
            essid = essid.rjust(max_essid_len)

        if self.essid_known:
            # Known ESSID
            essid = Color.s("{C}%s" % essid)
        else:
            # Unknown ESSID
            essid = Color.s("{O}%s" % essid)

        # Add a '*' if we decloaked the ESSID
        decloaked_char = "*" if self.decloaked else " "
        # essid += Color.s('{P}%s' % decloaked_char) # Decloak marker can be integrated or removed if too cluttered

        # Display Wi-Fi standard if known
        std_str = ""
        if self.wifi_standard:
            std_str = Color.s("{C}[%s]" % self.wifi_standard.upper())

        essid_display = "%s%s %s" % (
            essid,
            Color.s("{P}%s" % decloaked_char),
            std_str,
        )

        if show_bssid:
            bssid = Color.s("{O}%s  " % self.bssid)
        else:
            bssid = ""

        channel_color = "{G}"
        if int(self.channel) > 14:
            channel_color = "{C}"
        channel = Color.s("%s%s" % (channel_color, str(self.channel).rjust(3)))

        encryption = self.encryption.rjust(4)
        if "WEP" in encryption:
            encryption = Color.s("{G}%s" % encryption)
        elif "WPA3" in encryption:
            encryption = Color.s("{R}%s" % encryption)  # Red for WPA3
        elif "OWE" in encryption:
            encryption = Color.s("{M}%s" % encryption)  # Magenta for OWE
        elif "WPA2" in encryption:  # Keep WPA2 as Orange
            encryption = Color.s("{O}%s" % encryption)
        elif "WPA" in encryption:  # Original WPA also Orange
            encryption = Color.s("{O}%s" % encryption)

        power = "%sdb" % str(self.power).rjust(3)
        if self.power > 50:
            color = "G"
        elif self.power > 35:
            color = "O"
        else:
            color = "R"
        power = Color.s("{%s}%s" % (color, power))

        if self.wps == WPSState.UNLOCKED:
            wps = Color.s("{G} yes")
        elif self.wps == WPSState.NONE:
            wps = Color.s("{O}  no")
        elif self.wps == WPSState.LOCKED:
            wps = Color.s("{R}lock")
        elif self.wps == WPSState.UNKNOWN:
            wps = Color.s("{O} n/a")

        clients = "       "
        if len(self.clients) > 0:
            clients = Color.s("{G}  " + str(len(self.clients)))

        result = "%s  %s%s  %s  %s  %s  %s" % (
            essid_display.ljust(max_essid_len + 8),  # Adjusted ljust for new std_str
            bssid,
            channel,
            encryption,
            power,
            wps,
            clients,
        )
        result += Color.s("{W}")
        return result


if __name__ == "__main__":
    fields = "AA:BB:CC:DD:EE:FF,2015-05-27 19:28:44,2015-05-27 19:28:46,1,54,WPA2,CCMP TKIP,PSK,-58,2,0,0.0.0.0,9,HOME-ABCD,".split(
        ","
    )
    t = Target(fields)
    t.clients.append("asdf")
    t.clients.append("asdf")
    print(t.to_str())

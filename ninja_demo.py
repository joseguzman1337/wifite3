#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🥷 WIFITE3 NINJA INTELLIGENCE DEMONSTRATION
============================================

This script demonstrates the comprehensive network intelligence and analysis
capabilities added to wifite3, including:

1. Network Type Detection
2. Vendor Identification
3. Device Type Classification
4. Client-Side Analysis
5. Risk Assessment
6. Channel Usage Analysis
7. Comprehensive Intelligence Reporting

Usage: python3 ninja_demo.py
"""

import sys

# Add wifite3 to path
sys.path.insert(0, ".")

try:
    from wifite.tools.openmpi import OpenMPI
    from wifite.util.color import Color

    def demo_network_detection():
        """Demonstrate network type detection capabilities"""
        Color.pl("\n{+} {R}🥷 NINJA NETWORK TYPE DETECTION{W}")
        Color.pl("{+} {G}=" * 50 + "{W}")

        test_networks = [
            ("WPA2", "CCMP", "PSK", "HomeNetwork", "Standard home router"),
            ("", "", "", "", "Open/unsecured network"),
            ("WEP", "WEP", "Open", "OldRouter", "Legacy WEP security"),
            ("WPA2", "CCMP", "EAP", "CorporateNet", "Enterprise network"),
            ("WPA3", "CCMP", "SAE", "ModernHome", "Modern WPA3 security"),
            ("WPA2", "CCMP", "PSK", "GuestNetwork", "Guest access point"),
            ("WPA2", "CCMP", "PSK", "SmartCam_IoT", "IoT device network"),
            ("WPA2", "CCMP", "PSK", "FreeWiFi_Public", "Public hotspot"),
        ]

        for privacy, cipher, auth, essid, description in test_networks:
            net_type = OpenMPI._detect_network_type(privacy, cipher, auth, essid)
            Color.pl(
                "  {C}%-12s{W} | {G}%-15s{W} | {D}%s{W}"
                % (net_type, essid, description)
            )

    def demo_vendor_detection():
        """Demonstrate vendor identification from MAC addresses"""
        Color.pl("\n{+} {R}🥷 NINJA VENDOR DETECTION{W}")
        Color.pl("{+} {G}=" * 50 + "{W}")

        test_devices = [
            ("00:1B:63:AA:BB:CC", "Apple iPhone/iPad"),
            ("00:50:F2:11:22:33", "Microsoft Surface/Xbox"),
            ("34:23:87:DD:EE:FF", "Samsung Galaxy/Smart TV"),
            ("00:0F:DE:44:55:66", "Intel WiFi adapter"),
            ("00:04:20:77:88:99", "Cisco access point"),
            ("00:23:04:AB:CD:EF", "Huawei router"),
            ("AA:BB:CC:DD:EE:FF", "Unknown/Generic device"),
            ("AC:DE:48:11:22:33", "Modern device (generic)"),
        ]

        for mac, description in test_devices:
            vendor = OpenMPI._detect_vendor_from_mac(mac)
            Color.pl(
                "  {C}%-8s{W} | {G}%-17s{W} | {D}%s{W}" % (vendor, mac, description)
            )

    def demo_device_classification():
        """Demonstrate device type classification"""
        Color.pl("\n{+} {R}🥷 NINJA DEVICE CLASSIFICATION{W}")
        Color.pl("{+} {G}=" * 50 + "{W}")

        test_clients = [
            (
                "00:1B:63:AA:BB:CC",
                "iPhone_Network,HomeWiFi",
                "iPhone connecting to home",
            ),
            (
                "00:50:F2:11:22:33",
                "laptop,windows_network",
                "Windows laptop",
            ),
            (
                "AA:BB:CC:DD:EE:FF",
                "RingCam,IoT_Device,SmartHome",
                "Ring doorbell camera",
            ),
            ("34:23:87:DD:EE:FF", "HP_Printer,PrintNet", "Network printer"),
            (
                "00:0F:DE:AA:BB:CC",
                "xbox_live,gaming_network",
                "Xbox console",
            ),
            (
                "00:16:EA:11:22:33",
                "android_phone,mobile_hotspot",
                "Android device",
            ),
            (
                "00:1A:11:33:44:55",
                "google_home,nest_cam",
                "Google smart device",
            ),
        ]

        for mac, probed, description in test_clients:
            device_type = OpenMPI._detect_device_type(mac, probed)
            vendor = OpenMPI._detect_vendor_from_mac(mac)
            Color.pl(
                "  {C}%-8s{W} | {G}%-8s{W} | {Y}%-17s{W} | {D}%s{W}"
                % (device_type, vendor, mac, description)
            )

    def demo_intelligence_report():
        """Demonstrate comprehensive intelligence reporting format"""
        Color.pl("\n{+} {R}🥷 NINJA INTELLIGENCE REPORT PREVIEW{W}")
        Color.pl("{+} {G}=" * 60 + "{W}")

        # Simulate network statistics
        network_stats = {
            "total_networks": 25,
            "open_networks": 3,
            "wep_networks": 1,
            "wpa_networks": 2,
            "wpa2_networks": 17,
            "wpa3_networks": 1,
            "enterprise_networks": 1,
            "hidden_networks": 4,
            "total_clients": 47,
            "unique_vendors": {
                "Apple",
                "Samsung",
                "Intel",
                "Cisco",
                "Google",
                "Microsoft",
            },
            "channel_usage": {1: 8, 6: 12, 11: 5, 36: 3, 149: 2},
            "network_types": {
                "WPA2": 17,
                "Open": 3,
                "WPA": 2,
                "Enterprise": 1,
                "WPA3": 1,
                "IoT": 1,
            },
        }

        # Network overview
        Color.pl("{+} {C}📡 NETWORK OVERVIEW:{W}")
        Color.pl("  {G}Total Networks:{W} {C}%d{W}" % network_stats["total_networks"])
        Color.pl("  {G}Total Clients:{W} {C}%d{W}" % network_stats["total_clients"])
        Color.pl("  {G}Hidden Networks:{W} {C}%d{W}" % network_stats["hidden_networks"])
        Color.pl(
            "  {G}Unique Vendors:{W} {C}%d{W}" % len(network_stats["unique_vendors"])
        )

        # Security analysis
        Color.pl("")
        Color.pl("{+} {C}🔒 SECURITY ANALYSIS:{W}")
        Color.pl("  {R}Open Networks:{W} {C}%d{W}" % network_stats["open_networks"])
        Color.pl("  {O}WEP Networks:{W} {C}%d{W}" % network_stats["wep_networks"])
        Color.pl("  {Y}WPA Networks:{W} {C}%d{W}" % network_stats["wpa_networks"])
        Color.pl("  {G}WPA2 Networks:{W} {C}%d{W}" % network_stats["wpa2_networks"])
        Color.pl("  {G}WPA3 Networks:{W} {C}%d{W}" % network_stats["wpa3_networks"])
        Color.pl("  {B}Enterprise:{W} {C}%d{W}" % network_stats["enterprise_networks"])

        # Channel usage
        Color.pl("")
        Color.pl("{+} {C}📶 CHANNEL USAGE:{W}")
        for channel, count in sorted(
            network_stats["channel_usage"].items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            band = "2.4GHz" if channel <= 14 else "5GHz"
            Color.pl("  {G}Ch %d (%s):{W} {C}%d networks{W}" % (channel, band, count))

        # Risk assessment
        Color.pl("")
        Color.pl("{+} {C}⚠️  RISK ASSESSMENT:{W}")
        total = network_stats["total_networks"]
        risk_score = (
            (network_stats["open_networks"] * 3)
            + (network_stats["wep_networks"] * 2)
            + (network_stats["wpa_networks"] * 1)
            + (network_stats["hidden_networks"] * 1)
        ) / total

        if risk_score > 2.0:
            risk_level = "{R}HIGH{W}"
        elif risk_score > 1.0:
            risk_level = "{O}MEDIUM{W}"
        else:
            risk_level = "{G}LOW{W}"

        Color.pl(
            "  {G}Environment Risk Level:{W} %s {C}(%.1f){W}" % (risk_level, risk_score)
        )

    def demo_mpi_capabilities():
        """Demonstrate MPI parallel scanning capabilities"""
        Color.pl("\n{+} {R}🥷 NINJA MPI PARALLEL CAPABILITIES{W}")
        Color.pl("{+} {G}=" * 50 + "{W}")

        if OpenMPI.exists():
            cpu_count = OpenMPI.get_cpu_count()
            Color.pl("  {G}✅ OpenMPI Available:{W} {C}Ready for parallel scanning{W}")
            Color.pl("  {G}CPU Cores:{W} {C}%d processes available{W}" % cpu_count)
            Color.pl("  {G}Channel Coverage:{W} {C}39 channels (2.4GHz + 5GHz){W}")
            Color.pl("  {G}Scan Duration:{W} {C}137 seconds comprehensive{W}")
            Color.pl("  {G}Analysis Features:{W} {C}Real-time intelligence{W}")
        else:
            Color.pl("  {O}⚠️  OpenMPI Not Available:{W} {C}Sequential mode only{W}")
            Color.pl("  {G}Install with:{W} {C}apt-get install openmpi-bin{W}")

    def main():
        """Main demonstration function"""
        Color.pl("{+} {R}🥷 WIFITE3 NINJA INTELLIGENCE SYSTEM DEMO{W}")
        Color.pl("{+} {G}================================================{W}")
        Color.pl("{+} {C}Comprehensive wireless network reconnaissance{W}")
        Color.pl("{+} {C}and intelligence analysis platform{W}")

        demo_network_detection()
        demo_vendor_detection()
        demo_device_classification()
        demo_intelligence_report()
        demo_mpi_capabilities()

        Color.pl("")
        Color.pl("{+} {G}🥷 NINJA FEATURES SUMMARY:{W}")
        Color.pl(
            "  {C}• Network Type Classification:{W} Open/WEP/WPA/WPA2/WPA3/Enterprise/Guest/IoT"
        )
        Color.pl(
            "  {C}• Vendor Identification:{W} Apple/Samsung/Intel/Cisco/Huawei/Google/Microsoft"
        )
        Color.pl("  {C}• Device Classification:{W} Mobile/Computer/IoT/Printer/Gaming")
        Color.pl("  {C}• Client Analysis:{W} MAC/Vendor/Type/Probed Networks/Activity")
        Color.pl(
            "  {C}• Risk Assessment:{W} Environment security scoring (High/Medium/Low)"
        )
        Color.pl("  {C}• Channel Analysis:{W} 2.4GHz/5GHz usage mapping and congestion")
        Color.pl(
            "  {C}• MPI Parallelization:{W} Multi-core scanning for maximum coverage"
        )
        Color.pl(
            "  {C}• Intelligence Reporting:{W} Comprehensive statistics and insights"
        )

        Color.pl("")
        Color.pl("{+} {G}✅ WIFITE3 NINJA INTELLIGENCE SYSTEM READY!{W}")
        Color.pl("{+} {C}Use: python3 wifite --ninja-scan for full reconnaissance{W}")

    # Run the demonstration
    if __name__ == "__main__":
        main()

except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the wifite3 directory")
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback

    traceback.print_exc()

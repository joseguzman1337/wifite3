#!/usr/bin/env python
# -*- coding: utf-8 -*-

from wifite.tools.airodump import Airodump
from wifite.model.target import Target # Import Target class directly
from wifite.util.color import Color # For testing to_str() output

import unittest

class TestTarget(unittest.TestCase):
    ''' Test suite for Target parsing an generation '''

    airodump_csv = 'airodump.csv'

    def getTargets(self, filename):
        ''' Helper method to parse targets from filename '''
        import os, inspect
        this_file = os.path.abspath(inspect.getsourcefile(TestTarget.getTargets))
        this_dir = os.path.dirname(this_file)
        csv_file = os.path.join(this_dir, 'files', filename)
        # Load targets from CSV file
        return Airodump.get_targets_from_csv(csv_file)

    def testTargetParsing(self):
        ''' Asserts target parsing finds targets '''
        targets = self.getTargets(TestTarget.airodump_csv)
        assert(len(targets) > 0)

    def testTargetClients(self):
        ''' Asserts target parsing captures clients properly '''
        targets = self.getTargets(TestTarget.airodump_csv)
        for t in targets:
            if t.bssid == '00:1D:D5:9B:11:00':
                assert(len(t.clients) > 0)

    def test_wpa3_parsing(self):
        '''Tests parsing of WPA3 networks'''
        # BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, beacons, # IV, LAN IP, ID-length, ESSID, Key
        row_wpa3 = ['AA:BB:CC:DD:EE:FF', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '6', '300', 'WPA3 OWE', 'GCMP', 'SAE', '-50', '10', '0', '0.0.0.0', '4', 'WPA3NET', '']
        target = Target(row_wpa3)
        self.assertTrue(target.is_wpa3)
        self.assertFalse(target.is_owe) # OWE is in privacy but WPA3 takes precedence for is_wpa3, encryption should be WPA3
        self.assertEqual(target.encryption, 'WPA3')

        row_wpa2_wpa3 = ['AA:BB:CC:DD:EE:FE', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '1', '300', 'WPA3 WPA2', 'GCMP CCMP', 'PSK SAE', '-55', '10', '0', '0.0.0.0', '9', 'MIXEDMODE', '']
        target_mixed = Target(row_wpa2_wpa3)
        self.assertTrue(target_mixed.is_wpa3)
        self.assertEqual(target_mixed.encryption, 'WPA3') # WPA3 should be preferred

    def test_owe_parsing(self):
        '''Tests parsing of OWE networks'''
        row_owe = ['AA:BB:CC:DD:EE:FD', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '11', '300', 'OWE', 'GCMP', 'OWE', '-60', '10', '0', '0.0.0.0', '7', 'OWENET', '']
        target = Target(row_owe)
        self.assertFalse(target.is_wpa3)
        self.assertTrue(target.is_owe)
        self.assertEqual(target.encryption, 'OWE')

    def test_wifi_standard_parsing(self):
        '''Tests inference of Wi-Fi standards (ax, be, ac, n, g, b)'''
        # Test BE (Wi-Fi 7)
        row_be = ['BE:BE:BE:BE:BE:BE', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '36', '6000', 'WPA3', 'GCMP', 'SAE', '-40', '10', '0', '0.0.0.0', '3', 'BE', '']
        target = Target(row_be)
        self.assertEqual(target.wifi_standard, 'be')

        # Test AX (Wi-Fi 6)
        row_ax = ['AX:AX:AX:AX:AX:AX', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '1', '1201', 'WPA3', 'GCMP', 'SAE', '-45', '10', '0', '0.0.0.0', '3', 'AX', '']
        target = Target(row_ax)
        self.assertEqual(target.wifi_standard, 'ax')
        
        row_ax_high = ['AX:AX:AX:AX:AX:A1', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '1', '2402', 'WPA3', 'GCMP', 'SAE', '-45', '10', '0', '0.0.0.0', '3', 'AX2', '']
        target = Target(row_ax_high)
        self.assertEqual(target.wifi_standard, 'ax')

        # Test AC (Wi-Fi 5)
        row_ac = ['AC:AC:AC:AC:AC:AC', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '40', '866', 'WPA2', 'CCMP', 'PSK', '-50', '10', '0', '0.0.0.0', '3', 'AC', '']
        target = Target(row_ac)
        self.assertEqual(target.wifi_standard, 'ac')
        
        # Test N (high speed)
        row_n_high = ['N0:N0:N0:N0:N0:N0', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '11', '300', 'WPA2', 'CCMP', 'PSK', '-55', '10', '0', '0.0.0.0', '4', 'N300', '']
        target = Target(row_n_high)
        self.assertEqual(target.wifi_standard, 'ac') # Current logic pushes >=300 to 'ac'

        row_n_low = ['N1:N1:N1:N1:N1:N1', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '6', '144', 'WPA2', 'CCMP', 'PSK', '-58', '10', '0', '0.0.0.0', '3', 'N144', '']
        target = Target(row_n_low)
        self.assertEqual(target.wifi_standard, 'n')

        # Test G
        row_g = ['GG:GG:GG:GG:GG:GG', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '1', '54', 'WPA2', 'TKIP', 'PSK', '-60', '10', '0', '0.0.0.0', '1', 'G', '']
        target = Target(row_g)
        self.assertEqual(target.wifi_standard, 'g')
        
        # Test G with QoS (should be upgraded to N by current logic)
        row_g_qos = ['GQ:GQ:GQ:GQ:GQ:GQ', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '1', '54e', 'WPA2', 'TKIP', 'PSK', '-60', '10', '0', '0.0.0.0', '3', 'GQE', '']
        target = Target(row_g_qos)
        self.assertEqual(target.wifi_standard, 'n')


        # Test B
        row_b = ['BB:BB:BB:BB:BB:BB', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '11', '11', 'WEP', 'WEP', '', '-70', '10', '0', '0.0.0.0', '1', 'B', '']
        target = Target(row_b)
        self.assertEqual(target.wifi_standard, 'b')

    def test_target_to_str_formatting(self):
        '''Tests the to_str() method for new WPA3/OWE/Wi-Fi standard indicators'''
        # WPA3-SAE and AX
        row_wpa3_ax = ['AX:AX:AX:AX:AX:AX', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '1', '1201', 'WPA3', 'GCMP', 'SAE', '-45', '10', '0', '0.0.0.0', '6', 'WPA3AX', '']
        target_wpa3_ax = Target(row_wpa3_ax)
        target_str = Color.strip(target_wpa3_ax.to_str()) # Strip color codes for simple substring check
        self.assertIn('[AX]', target_str)
        self.assertIn('WPA3', target_str) # Encryption field

        # OWE and AC
        row_owe_ac = ['AC:AC:AC:AC:AC:AC', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '40', '866', 'OWE', 'GCMP', 'OWE', '-50', '10', '0', '0.0.0.0', '6', 'OWE-AC', '']
        target_owe_ac = Target(row_owe_ac)
        target_str_owe = Color.strip(target_owe_ac.to_str())
        self.assertIn('[AC]', target_str_owe)
        self.assertIn('OWE', target_str_owe)
        
        # BE standard
        row_be = ['BE:BE:BE:BE:BE:BE', '2023-01-01 10:00:00', '2023-01-01 10:00:00', '36', '7000', 'WPA3', 'GCMP', 'SAE', '-40', '10', '0', '0.0.0.0', '6', 'WIFI7', '']
        target_be = Target(row_be)
        target_str_be = Color.strip(target_be.to_str())
        self.assertIn('[BE]', target_str_be)

        # Check colors (more involved, might need specific color code checks if critical)
        # For now, we assume the color codes used in to_str() are correct if the substrings are present.
        # Example: WPA3 should be Red.
        target_str_wpa3_color = target_wpa3_ax.to_str()
        self.assertIn(Color.s('{R}WPA3'), target_str_wpa3_color) # Check if WPA3 is wrapped in Red color

        target_str_owe_color = target_owe_ac.to_str()
        self.assertIn(Color.s('{M} OWE'), target_str_owe_color) # Check if OWE is wrapped in Magenta (note space due to rjust(4))

        target_str_ax_color = target_wpa3_ax.to_str()
        self.assertIn(Color.s('{C}[AX]'), target_str_ax_color) # Check if [AX] is wrapped in Cyan


if __name__ == '__main__':
    unittest.main()

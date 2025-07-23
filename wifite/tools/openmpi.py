#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..util.process import Process

class OpenMPI(Dependency):
    ''' Wrapper for OpenMPI parallel processing '''
    dependency_required = False
    dependency_name = 'mpirun'
    dependency_url = 'apt-get install openmpi-bin'

    def __init__(self):
        pass

    @staticmethod
    def exists():
        return Process.exists('mpirun')

    @staticmethod
    def get_cpu_count():
        '''Get number of available CPU cores for MPI processes'''
        import multiprocessing
        return multiprocessing.cpu_count()

    @staticmethod
    def run_parallel_scan(interface, channels, scan_duration=137):
        '''Run parallel airodump scan across multiple channels using MPI'''
        from ..util.color import Color
        from ..config import Configuration
        import subprocess
        import tempfile
        import os
        import time
        from multiprocessing import cpu_count

        if not OpenMPI.exists():
            Color.pl('{!} {R}OpenMPI not available, falling back to sequential scan{W}')
            return None

        Color.pl('{+} {G}🥷 NINJA PARALLEL SCAN:{W} Deploying {C}%d{W} MPI processes for {C}%d{W} seconds...' % (cpu_count(), scan_duration))
        
        # Create temporary directory for parallel scan results
        temp_dir = tempfile.mkdtemp(prefix='wifite_mpi_')
        
        try:
            # Create MPI scanner script
            scanner_script = OpenMPI._create_mpi_scanner_script(interface, channels, scan_duration, temp_dir)
            
            # Run parallel scan using MPI
            num_processes = min(len(channels), cpu_count())
            Color.pl('{+} {C}Launching {G}%d parallel scanners{C} across channels {G}%s{W}' % (num_processes, str(channels)))
            
            start_time = time.time()
            
            # Execute MPI parallel scan
            cmd = [
                'mpirun', 
                '-np', str(num_processes),
                '--allow-run-as-root',
                '--oversubscribe',
                'python3', scanner_script
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_duration + 30)
            
            elapsed_time = time.time() - start_time
            Color.pl('{+} {G}Parallel scan completed in {C}%.1f{G} seconds{W}' % elapsed_time)
            
            # Show any MPI output for debugging
            if result.stdout.strip():
                Color.pl('{+} {C}MPI Output:{W}')
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        Color.pl('    {D}%s{W}' % line)
            
            if result.stderr.strip():
                Color.pl('{!} {O}MPI Warnings:{W}')
                for line in result.stderr.strip().split('\n'):
                    if line.strip() and 'WARNING' not in line.upper():
                        Color.pl('    {O}%s{W}' % line)
            
            # Aggregate results from all processes
            return OpenMPI._aggregate_scan_results(temp_dir)
            
        except subprocess.TimeoutExpired:
            Color.pl('{!} {O}Parallel scan timed out, returning partial results{W}')
            return OpenMPI._aggregate_scan_results(temp_dir)
            
        except Exception as e:
            Color.pl('{!} {R}Parallel scan failed: %s{W}' % str(e))
            return None
            
        finally:
            # Cleanup temporary files
            import shutil
            try:
                shutil.rmtree(temp_dir)
            except:
                pass

    @staticmethod
    def _create_mpi_scanner_script(interface, channels, scan_duration, temp_dir):
        '''Create MPI scanner script for parallel execution'''
        import tempfile
        import os
        
        scanner_script_content = f'''
#!/usr/bin/env python3
import os
import sys
import subprocess
import time

# Simple rank-based parallelization without mpi4py dependency
rank = int(os.environ.get('OMPI_COMM_WORLD_RANK', '0'))
size = int(os.environ.get('OMPI_COMM_WORLD_SIZE', '1'))

# Channel assignment for this process
channels = {channels}
channels_per_process = len(channels) // size
start_idx = rank * channels_per_process
end_idx = start_idx + channels_per_process if rank < size - 1 else len(channels)
my_channels = channels[start_idx:end_idx]

# Scan parameters
interface = "{interface}"
scan_duration = {scan_duration}
temp_dir = "{temp_dir}"

print(f"[Rank {{rank}}/{{size}}] Ninja scanning channels {{my_channels}}")

try:
    for channel in my_channels:
        # Calculate time per channel
        time_per_channel = max(1, scan_duration // len(my_channels)) if my_channels else scan_duration
        
        print(f"[Rank {{rank}}] Channel {{channel}} -> {{time_per_channel}}s")
        
        # Run airodump for this channel
        output_prefix = f"{{temp_dir}}/ninja_rank{{rank}}_ch{{channel}}"
        cmd = [
            'timeout', str(time_per_channel),
            'airodump-ng', 
            '--channel', str(channel),
            '--write', output_prefix,
            '--output-format', 'csv',
            interface
        ]
        
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
except Exception as e:
    print(f"[Rank {{rank}}] Error: {{e}}")

print(f"[Rank {{rank}}] Ninja scan complete for {{len(my_channels)}} channels")
'''
        
        # Write script to temporary file
        script_fd, script_path = tempfile.mkstemp(suffix='.py', prefix='mpi_scanner_')
        with os.fdopen(script_fd, 'w') as f:
            f.write(scanner_script_content)
        
        os.chmod(script_path, 0o755)
        return script_path

    @staticmethod
    def _aggregate_scan_results(temp_dir):
        '''Aggregate scan results from all MPI processes with comprehensive analysis'''
        from ..util.color import Color
        import os
        import glob
        import csv
        import re
        
        all_targets = {}
        all_clients = {}
        network_stats = {
            'total_networks': 0,
            'open_networks': 0,
            'wep_networks': 0,
            'wpa_networks': 0,
            'wpa2_networks': 0,
            'wpa3_networks': 0,
            'enterprise_networks': 0,
            'hidden_networks': 0,
            'total_clients': 0,
            'unique_vendors': set(),
            'channel_usage': {},
            'network_types': {}
        }
        
        # Look for airodump CSV files (they end with -01.csv)
        csv_files = glob.glob(os.path.join(temp_dir, '*-01.csv'))
        
        Color.pl('{+} {C}🥷 NINJA ANALYSIS:{W} Processing {G}%d{C} scan files...{W}' % len(csv_files))
        
        for csv_file in csv_files:
            try:
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Split content into AP and Station sections
                    if 'Station MAC' in content:
                        parts = content.split('Station MAC')
                        ap_section = parts[0]
                        station_section = 'Station MAC' + parts[1] if len(parts) > 1 else ''
                    else:
                        ap_section = content
                        station_section = ''
                    
                    # Parse Access Points
                    OpenMPI._parse_access_points(ap_section, all_targets, network_stats)
                    
                    # Parse Client Stations
                    if station_section:
                        OpenMPI._parse_client_stations(station_section, all_clients, network_stats)
                        
            except Exception as e:
                Color.pl('{!} {O}Warning: Failed to parse %s: %s{W}' % (csv_file, str(e)))
                continue
        
        # Display comprehensive analysis
        OpenMPI._display_network_intelligence(network_stats, all_targets, all_clients)
        
        return {
            'targets': list(all_targets.values()),
            'clients': list(all_clients.values()),
            'stats': network_stats
        }

    @staticmethod
    def ninja_comprehensive_scan(interface, scan_time=137):
        '''Perform comprehensive ninja scan using MPI parallelization'''
        from ..util.color import Color
        from ..config import Configuration
        
        # Define comprehensive channel list (2.4GHz + 5GHz)
        channels_24ghz = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        channels_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
        
        all_channels = channels_24ghz + channels_5ghz if Configuration.five_ghz else channels_24ghz
        
        Color.pl('{+} {R}🥷 NINJA COMPREHENSIVE SCAN:{W} Scanning {C}%d{W} channels in {C}%d{W} seconds' % (len(all_channels), scan_time))
        Color.pl('{+} {G}Channel distribution:{W} 2.4GHz({C}%d{W}) + 5GHz({C}%d{W})' % (len(channels_24ghz), len(channels_5ghz) if Configuration.five_ghz else 0))
        
        # Run parallel scan
        return OpenMPI.run_parallel_scan(interface, all_channels, scan_time)

    @staticmethod
    def _parse_access_points(ap_section, all_targets, network_stats):
        '''Parse access points from airodump CSV output'''
        import re
        
        lines = ap_section.strip().split('\n')
        for line in lines[1:]:  # Skip header
            if line.strip() and 'BSSID' not in line:
                parts = [p.strip() for p in line.split(', ')]
                if len(parts) >= 14 and parts[0] and ':' in parts[0]:
                    bssid = parts[0].upper()
                    if bssid and bssid != 'BSSID':
                        # Extract network information
                        privacy = parts[5] if len(parts) > 5 else ''
                        cipher = parts[6] if len(parts) > 6 else ''
                        auth = parts[7] if len(parts) > 7 else ''
                        power = parts[8] if len(parts) > 8 else ''
                        beacons = parts[9] if len(parts) > 9 else ''
                        iv = parts[10] if len(parts) > 10 else ''
                        lan_ip = parts[11] if len(parts) > 11 else ''
                        id_length = parts[12] if len(parts) > 12 else ''
                        essid = parts[13] if len(parts) > 13 else ''
                        key = parts[14] if len(parts) > 14 else ''
                        
                        # Detect network type and security
                        network_type = OpenMPI._detect_network_type(privacy, cipher, auth, essid)
                        vendor = OpenMPI._detect_vendor_from_mac(bssid)
                        
                        # Store enhanced network info
                        enhanced_parts = parts + [network_type, vendor]
                        all_targets[bssid] = enhanced_parts
                        
                        # Update statistics
                        network_stats['total_networks'] += 1
                        OpenMPI._update_security_stats(network_stats, privacy, cipher, auth)
                        
                        if not essid or essid == '':
                            network_stats['hidden_networks'] += 1
                        
                        # Track channel usage
                        try:
                            channel = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                            if channel > 0:
                                network_stats['channel_usage'][channel] = network_stats['channel_usage'].get(channel, 0) + 1
                        except:
                            pass
                        
                        # Track network types
                        network_stats['network_types'][network_type] = network_stats['network_types'].get(network_type, 0) + 1
                        network_stats['unique_vendors'].add(vendor)

    @staticmethod
    def _parse_client_stations(station_section, all_clients, network_stats):
        '''Parse client stations from airodump CSV output'''
        lines = station_section.strip().split('\n')
        for line in lines[1:]:  # Skip header
            if line.strip() and 'Station MAC' not in line:
                parts = [p.strip() for p in line.split(', ')]
                if len(parts) >= 6 and parts[0] and ':' in parts[0]:
                    station_mac = parts[0].upper()
                    first_time = parts[1] if len(parts) > 1 else ''
                    last_time = parts[2] if len(parts) > 2 else ''
                    power = parts[3] if len(parts) > 3 else ''
                    packets = parts[4] if len(parts) > 4 else ''
                    bssid = parts[5] if len(parts) > 5 else ''
                    probed_essids = parts[6] if len(parts) > 6 else ''
                    
                    # Analyze client information
                    vendor = OpenMPI._detect_vendor_from_mac(station_mac)
                    device_type = OpenMPI._detect_device_type(station_mac, probed_essids)
                    
                    client_info = {
                        'mac': station_mac,
                        'first_seen': first_time,
                        'last_seen': last_time,
                        'power': power,
                        'packets': packets,
                        'associated_bssid': bssid,
                        'probed_essids': probed_essids,
                        'vendor': vendor,
                        'device_type': device_type
                    }
                    
                    all_clients[station_mac] = client_info
                    network_stats['total_clients'] += 1
                    network_stats['unique_vendors'].add(vendor)

    @staticmethod
    def _detect_network_type(privacy, cipher, auth, essid):
        '''Detect network type based on security parameters'''
        privacy = privacy.lower() if privacy else ''
        cipher = cipher.lower() if cipher else ''
        auth = auth.lower() if auth else ''
        essid = essid.lower() if essid else ''
        
        # Enterprise networks
        if 'eap' in auth or 'enterprise' in auth or '802.1x' in auth:
            return 'Enterprise'
        
        # WPA3 detection
        if 'sae' in auth or 'wpa3' in privacy or 'owe' in auth:
            return 'WPA3'
        
        # WPA2 detection
        if 'wpa2' in privacy or 'ccmp' in cipher or 'psk' in auth:
            return 'WPA2'
        
        # WPA detection
        if 'wpa' in privacy and 'wpa2' not in privacy:
            return 'WPA'
        
        # WEP detection
        if 'wep' in privacy or 'wep' in cipher:
            return 'WEP'
        
        # Open networks
        if not privacy or privacy == '' or 'none' in privacy:
            return 'Open'
        
        # Guest networks
        if any(keyword in essid for keyword in ['guest', 'public', 'free', 'open']):
            return 'Guest'
        
        # IoT/Smart devices
        if any(keyword in essid for keyword in ['iot', 'smart', 'cam', 'ring', 'nest', 'alexa']):
            return 'IoT'
        
        return 'Unknown'

    @staticmethod
    def _detect_vendor_from_mac(mac_address):
        '''Detect device vendor from MAC address OUI'''
        if not mac_address or len(mac_address) < 8:
            return 'Unknown'
        
        oui = mac_address[:8].upper().replace(':', '')
        
        # Common vendor OUI prefixes
        vendor_ouis = {
            '00:1B:63': 'Apple',
            '00:23:6C': 'Apple', 
            '00:26:08': 'Apple',
            '3C:07:54': 'Apple',
            '00:50:F2': 'Microsoft',
            '00:15:5D': 'Microsoft',
            '00:1D:D8': 'Microsoft',
            '00:16:EA': 'Samsung',
            '00:12:FB': 'Samsung',
            '34:23:87': 'Samsung',
            '00:0F:DE': 'Intel',
            '00:15:00': 'Intel',
            '00:21:6A': 'Intel',
            '00:04:20': 'Cisco',
            '00:1B:D4': 'Cisco',
            '00:26:CA': 'Cisco',
            '00:23:04': 'Huawei',
            '00:E0:FC': 'Huawei',
            '34:6B:D3': 'Huawei',
            '00:1E:10': 'Google',
            '00:1A:11': 'Google'
        }
        
        # Check exact OUI match first
        for vendor_oui, vendor_name in vendor_ouis.items():
            if oui.startswith(vendor_oui.replace(':', '')):
                return vendor_name
        
        # Generic detection based on patterns
        if oui.startswith('00'):
            return 'Legacy'
        elif oui.startswith(('AC', 'BC', 'CC')):
            return 'Modern'
        else:
            return 'Unknown'

    @staticmethod
    def _detect_device_type(mac_address, probed_essids):
        '''Detect device type based on MAC and probed networks'''
        vendor = OpenMPI._detect_vendor_from_mac(mac_address)
        probed = probed_essids.lower() if probed_essids else ''
        
        # Mobile devices
        if vendor in ['Apple', 'Samsung'] or 'iphone' in probed or 'android' in probed:
            return 'Mobile'
        
        # Laptops/Computers
        if vendor in ['Intel', 'Microsoft'] or 'laptop' in probed or 'windows' in probed:
            return 'Computer'
        
        # IoT devices
        if any(iot_term in probed for iot_term in ['cam', 'iot', 'smart', 'ring', 'nest']):
            return 'IoT'
        
        # Printers
        if any(printer_term in probed for printer_term in ['print', 'canon', 'hp', 'epson']):
            return 'Printer'
        
        # Gaming devices
        if any(gaming_term in probed for gaming_term in ['xbox', 'playstation', 'nintendo']):
            return 'Gaming'
        
        return 'Unknown'

    @staticmethod
    def _update_security_stats(network_stats, privacy, cipher, auth):
        '''Update security statistics based on network parameters'''
        privacy = privacy.lower() if privacy else ''
        cipher = cipher.lower() if cipher else ''
        auth = auth.lower() if auth else ''
        
        if 'eap' in auth or 'enterprise' in auth:
            network_stats['enterprise_networks'] += 1
        elif 'sae' in auth or 'wpa3' in privacy:
            network_stats['wpa3_networks'] += 1
        elif 'wpa2' in privacy or 'ccmp' in cipher:
            network_stats['wpa2_networks'] += 1
        elif 'wpa' in privacy and 'wpa2' not in privacy:
            network_stats['wpa_networks'] += 1
        elif 'wep' in privacy or 'wep' in cipher:
            network_stats['wep_networks'] += 1
        elif not privacy or privacy == '' or 'none' in privacy:
            network_stats['open_networks'] += 1

    @staticmethod
    def _display_network_intelligence(network_stats, all_targets, all_clients):
        '''Display comprehensive network intelligence analysis'''
        from ..util.color import Color
        
        Color.pl('')
        Color.pl('{+} {R}🥷 NINJA NETWORK INTELLIGENCE REPORT{W}')
        Color.pl('{+} {G}=' * 60 + '{W}')
        
        # Network overview
        Color.pl('{+} {C}📡 NETWORK OVERVIEW:{W}')
        Color.pl('  {G}Total Networks:{W} {C}%d{W}' % network_stats['total_networks'])
        Color.pl('  {G}Total Clients:{W} {C}%d{W}' % network_stats['total_clients'])
        Color.pl('  {G}Hidden Networks:{W} {C}%d{W}' % network_stats['hidden_networks'])
        Color.pl('  {G}Unique Vendors:{W} {C}%d{W}' % len(network_stats['unique_vendors']))
        
        # Security analysis
        Color.pl('')
        Color.pl('{+} {C}🔒 SECURITY ANALYSIS:{W}')
        Color.pl('  {R}Open Networks:{W} {C}%d{W}' % network_stats['open_networks'])
        Color.pl('  {O}WEP Networks:{W} {C}%d{W}' % network_stats['wep_networks'])
        Color.pl('  {Y}WPA Networks:{W} {C}%d{W}' % network_stats['wpa_networks'])
        Color.pl('  {G}WPA2 Networks:{W} {C}%d{W}' % network_stats['wpa2_networks'])
        Color.pl('  {G}WPA3 Networks:{W} {C}%d{W}' % network_stats['wpa3_networks'])
        Color.pl('  {B}Enterprise:{W} {C}%d{W}' % network_stats['enterprise_networks'])
        
        # Network types
        if network_stats['network_types']:
            Color.pl('')
            Color.pl('{+} {C}🏷️  NETWORK TYPES:{W}')
            for net_type, count in sorted(network_stats['network_types'].items(), key=lambda x: x[1], reverse=True):
                Color.pl('  {G}%s:{W} {C}%d{W}' % (net_type, count))
        
        # Channel usage
        if network_stats['channel_usage']:
            Color.pl('')
            Color.pl('{+} {C}📶 CHANNEL USAGE:{W}')
            sorted_channels = sorted(network_stats['channel_usage'].items(), key=lambda x: x[1], reverse=True)[:10]
            for channel, count in sorted_channels:
                band = '2.4GHz' if channel <= 14 else '5GHz'
                Color.pl('  {G}Ch %d (%s):{W} {C}%d networks{W}' % (channel, band, count))
        
        # Top vendors
        if network_stats['unique_vendors']:
            Color.pl('')
            Color.pl('{+} {C}🏭 DETECTED VENDORS:{W}')
            vendor_list = list(network_stats['unique_vendors'])[:10]
            Color.pl('  {G}%s{W}' % ', '.join(vendor_list))
        
        # Risk assessment
        Color.pl('')
        Color.pl('{+} {C}⚠️  RISK ASSESSMENT:{W}')
        total = network_stats['total_networks']
        if total > 0:
            risk_score = (
                (network_stats['open_networks'] * 3) +
                (network_stats['wep_networks'] * 2) +
                (network_stats['wpa_networks'] * 1) +
                (network_stats['hidden_networks'] * 1)
            ) / total
            
            if risk_score > 2.0:
                risk_level = '{R}HIGH{W}'
            elif risk_score > 1.0:
                risk_level = '{O}MEDIUM{W}'
            else:
                risk_level = '{G}LOW{W}'
                
            Color.pl('  {G}Environment Risk Level:{W} %s {C}(%.1f){W}' % (risk_level, risk_score))
        
        Color.pl('')
        Color.pl('{+} {G}🥷 Ninja analysis complete!{W}')

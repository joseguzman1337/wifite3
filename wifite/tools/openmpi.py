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
        '''Aggregate scan results from all MPI processes'''
        from ..util.color import Color
        import os
        import glob
        import csv
        
        all_targets = {}
        csv_files = glob.glob(os.path.join(temp_dir, '*.csv'))
        
        Color.pl('{+} {C}Aggregating results from {G}%d{C} scan files...{W}' % len(csv_files))
        
        for csv_file in csv_files:
            try:
                with open(csv_file, 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) > 13 and row[0] != 'BSSID':  # Skip header
                            bssid = row[0].strip()
                            if bssid:
                                # Store unique networks by BSSID
                                all_targets[bssid] = row
            except Exception:
                continue
        
        Color.pl('{+} {G}Found {C}%d{G} unique networks from parallel scan{W}' % len(all_targets))
        
        return list(all_targets.values())

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

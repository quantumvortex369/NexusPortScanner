"""
Port Scanner Module
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from utils import get_service_name

class PortScanner:
    """Advanced port scanner with support for multiple scan types."""
    
    def __init__(self, target: str, ports: List[int], scan_type: str = 'tcp',
                 timeout: float = 1.0, max_threads: int = 100, rate_limit: int = 0,
                 grab_banners: bool = False, verbose: int = 0):
        """
        Initialize the port scanner.
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan
            scan_type: Type of scan ('tcp', 'syn', 'udp')
            timeout: Connection timeout in seconds
            max_threads: Maximum number of threads to use
            rate_limit: Maximum requests per second (0 for unlimited)
            grab_banners: Whether to grab service banners
            verbose: Verbosity level (0-3)
        """
        self.target = target
        self.ports = ports
        self.scan_type = scan_type.lower()
        self.timeout = timeout
        self.max_threads = max_threads
        self.rate_limit = rate_limit
        self.grab_banners = grab_banners
        self.verbose = verbose
        
        # Scan statistics
        self.stats = {
            'start_time': None,
            'end_time': None,
            'ports_scanned': 0,
            'open_ports': 0,
            'filtered_ports': 0,
            'closed_ports': 0,
            'errors': 0
        }
        
        # Results storage
        self.results = []
    
    def scan(self) -> List[Dict]:
        """
        Run the port scan.
        
        Returns:
            List of scan results
        """
        self.stats['start_time'] = datetime.now()
        self._log(f"Starting {self.scan_type.upper()} scan of {self.target}", 1)
        
        # Select the appropriate scan method
        scan_method = self._get_scan_method()
        
        # Create thread pool
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all ports for scanning
            future_to_port = {
                executor.submit(scan_method, port): port
                for port in self.ports
            }
            
            # Process results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    self._process_result(port, result)
                except Exception as e:
                    self._log(f"Error scanning port {port}: {str(e)}", 2)
                    self.stats['errors'] += 1
                
                # Apply rate limiting if specified
                if self.rate_limit > 0:
                    time.sleep(1 / self.rate_limit)
        
        # Update statistics
        self.stats['end_time'] = datetime.now()
        self._log_scan_summary()
        
        return self.results
    
    def _get_scan_method(self):
        """Get the appropriate scan method based on scan type."""
        if self.scan_type == 'tcp':
            return self._tcp_scan
        elif self.scan_type == 'syn':
            return self._syn_scan
        elif self.scan_type == 'udp':
            return self._udp_scan
        else:
            raise ValueError(f"Unsupported scan type: {self.scan_type}")
    
    def _tcp_scan(self, port: int) -> Dict:
        """
        Perform a TCP connect scan.
        
        Returns:
            Dictionary with scan results
        """
        result = {
            'port': port,
            'protocol': 'tcp',
            'state': 'closed',
            'service': '',
            'banner': '',
            'reason': ''
        }
        
        try:
            # Create a new socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect
            start_time = time.time()
            connection = sock.connect_ex((self.target, port))
            elapsed = (time.time() - start_time) * 1000  # Convert to ms
            
            if connection == 0:  # Port is open
                result['state'] = 'open'
                result['service'] = get_service_name(port)
                
                # Try to grab banner if requested
                if self.grab_banners:
                    try:
                        banner = self._grab_banner(sock)
                        if banner:
                            result['banner'] = banner
                    except Exception as e:
                        if self.verbose > 1:
                            self._log(f"Banner grab failed on port {port}: {str(e)}", 2)
            
            sock.close()
            return result
            
        except socket.timeout:
            result['state'] = 'filtered'
            result['reason'] = 'timeout'
        except ConnectionRefusedError:
            result['state'] = 'closed'
            result['reason'] = 'connection_refused'
        except socket.error as e:
            result['state'] = 'filtered'
            result['reason'] = str(e)
        except Exception as e:
            self._log(f"Unexpected error scanning port {port}: {str(e)}", 2)
            result['state'] = 'error'
            result['reason'] = str(e)
        
        return result
    
    def _syn_scan(self, port: int) -> Dict:
        """
        Perform a TCP SYN scan (requires root/Admin privileges).
        
        Note: This is a simplified implementation. A real SYN scan would
        require raw socket access which needs root/Admin privileges.
        """
        # Fall back to TCP connect scan if not running as root/Admin
        if not self._is_running_as_root():
            self._log("Warning: SYN scan requires root/Admin privileges. Falling back to TCP connect scan.", 1)
            return self._tcp_scan(port)
            
        # Implementation would go here
        # For now, just use TCP connect scan
        return self._tcp_scan(port)
    
    def _udp_scan(self, port: int) -> Dict:
        """
        Perform a UDP port scan.
        """
        result = {
            'port': port,
            'protocol': 'udp',
            'state': 'open|filtered',  # UDP is stateless, so we can't be sure
            'service': get_service_name(port, 'udp'),
            'banner': '',
            'reason': ''
        }
        
        try:
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target, port))
            
            try:
                # Try to receive a response
                data, _ = sock.recvfrom(1024)
                result['state'] = 'open'
                result['banner'] = data.decode('utf-8', 'ignore').strip()
            except socket.timeout:
                # No response could mean the port is open and filtered
                # or the service accepted the packet but sent no reply
                pass
                
            sock.close()
            
        except socket.error as e:
            result['state'] = 'filtered'
            result['reason'] = str(e)
        
        return result
    
    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        """
        Attempt to grab a banner from the service.
        
        Args:
            sock: Connected socket
            
        Returns:
            Banner string or None if no banner could be grabbed
        """
        try:
            # Set a short timeout for banner grabbing
            sock.settimeout(2.0)
            
            # Try to read some data
            banner = sock.recv(1024)
            
            if banner:
                return banner.decode('utf-8', 'ignore').strip()
                
        except (socket.timeout, socket.error):
            pass
            
        return None
    
    def _process_result(self, port: int, result: Dict) -> None:
        """Process and store scan results."""
        self.stats['ports_scanned'] += 1
        
        if result['state'] == 'open':
            self.stats['open_ports'] += 1
            self._log(f"Port {port}/tcp {Fore.GREEN}open{Style.RESET_ALL} - {result['service']}" + 
                     (f" - {result['banner']}" if result['banner'] else ""), 1)
        elif result['state'] == 'filtered':
            self.stats['filtered_ports'] += 1
            self._log(f"Port {port}/tcp filtered ({result.get('reason', '')})", 3)
        else:  # closed or error
            if 'error' in result['state']:
                self.stats['errors'] += 1
            else:
                self.stats['closed_ports'] += 1
            self._log(f"Port {port}/tcp {result['state']}", 3)
        
        self.results.append(result)
    
    def get_scan_duration(self) -> float:
        """Return the duration of the scan in seconds."""
        if not self.stats['start_time'] or not self.stats['end_time']:
            return 0.0
        return (self.stats['end_time'] - self.stats['start_time']).total_seconds()
    
    def _log_scan_summary(self) -> None:
        """Log a summary of the scan results."""
        duration = self.get_scan_duration()
        summary = (
            f"\nScan Statistics:"
            f"\n  Target: {self.target}"
            f"\n  Ports scanned: {self.stats['ports_scanned']}"
            f"\n  Open ports: {self.stats['open_ports']}"
            f"\n  Filtered ports: {self.stats['filtered_ports']}"
            f"\n  Closed ports: {self.stats['closed_ports']}"
            f"\n  Errors: {self.stats['errors']}"
            f"\n  Scan duration: {duration:.2f} seconds"
        )
        self._log(summary, 1)
    
    def _log(self, message: str, min_verbosity: int = 0) -> None:
        """Log a message if verbosity level is sufficient."""
        if self.verbose >= min_verbosity:
            print(f"{message}")
    
    @staticmethod
    def _is_running_as_root() -> bool:
        """Check if the script is running as root/Admin."""
        try:
            import os
            return os.geteuid() == 0
        except AttributeError:
            # Not on Unix, check for Windows admin
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False

#!/usr/bin/env python3
"""
Nexus Port Scanner - Advanced port scanning tool
"""

import argparse
import socket
import sys
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union

import ipaddress
from colorama import Fore, Style, init

# Import local modules
from port_scanner import PortScanner
from utils import (
    parse_ports, 
    validate_ip, 
    resolve_host,
    get_service_name,
    print_banner,
    save_results
)

def get_arguments() -> argparse.Namespace:
    """Parse and return command line arguments."""
    parser = argparse.ArgumentParser(description='Nexus Port Scanner - Advanced port scanning tool')
    
    # Required arguments
    parser.add_argument('target', help='Target IP address or hostname')
    
    # Port specification
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', '--ports', default='1-1024',
                          help='Ports to scan (e.g., 80,443 or 1-1000)')
    port_group.add_argument('--top-ports', type=int, metavar='N',
                          help='Scan top N most common ports')
    
    # Scan options
    parser.add_argument('-t', '--threads', type=int, default=100,
                      help='Number of threads to use (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0,
                      help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-r', '--rate-limit', type=int, default=0,
                      help='Maximum requests per second (0 for unlimited)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text',
                      help='Output format (default: text)')
    
    # Scan types
    scan_type = parser.add_mutually_exclusive_group()
    scan_type.add_argument('-sS', '--syn-scan', action='store_true',
                          help='TCP SYN scan (requires root)')
    scan_type.add_argument('-sT', '--tcp-scan', action='store_true',
                          help='TCP connect scan (default)')
    scan_type.add_argument('-sU', '--udp-scan', action='store_true',
                          help='UDP scan')
    
    # Additional options
    parser.add_argument('-v', '--verbose', action='count', default=0,
                      help='Increase verbosity level (-v, -vv, -vvv)')
    parser.add_argument('--banner', action='store_true',
                      help='Attempt to grab service banners')
    parser.add_argument('--version', action='version', version='Nexus Port Scanner 2.0')
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    return parser.parse_args()

def main():
    """Main function."""
    # Initialize colorama
    init(autoreset=True)
    
    # Print banner
    print_banner()
    
    # Parse command line arguments
    args = get_arguments()
    
    try:
        # Resolve target
        ip, hostname = resolve_host(args.target)
        
        # Determine ports to scan
        if args.top_ports:
            # Use top N ports if specified
            from common_ports import TOP_PORTS
            ports = TOP_PORTS[:args.top_ports]
        else:
            # Parse port ranges
            ports = parse_ports(args.ports)
        
        # Create scanner instance
        scanner = PortScanner(
            target=ip,
            ports=ports,
            scan_type='syn' if args.syn_scan else 'udp' if args.udp_scan else 'tcp',
            timeout=args.timeout,
            max_threads=args.threads,
            rate_limit=args.rate_limit,
            grab_banners=args.banner,
            verbose=args.verbose
        )
        
        # Start scanning
        print(f"[+] Starting scan of {ip} ({hostname})")
        print(f"[+] Scanning {len(ports)} ports using {args.threads} threads")
        
        results = scanner.scan()
        
        # Save results if output file specified
        if args.output:
            save_results(results, args.output, args.format)
            print(f"\n[+] Results saved to {args.output}")
        
        # Print summary
        print(f"\n[+] Scan completed in {scanner.get_scan_duration():.2f} seconds")
        print(f"[+] Found {len([r for r in results if r['state'] == 'open'])} open ports")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        if args.verbose > 0:
            import traceback
            traceback.print_exc()
        print(f"{Fore.RED}[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

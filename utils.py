"""
Utility functions for Nexus Port Scanner
"""

import csv
import json
import re
import socket
import ipaddress
from typing import Dict, List, Optional, Tuple, Union, Any

def parse_ports(port_spec: str) -> List[int]:
    """
    Parse a port specification string into a list of port numbers.
    
    Examples:
        "80" -> [80]
        "80,443" -> [80, 443]
        "1-100" -> [1, 2, ..., 100]
        "1-100,443,8080-8085" -> [1, 2, ..., 100, 443, 8080, 8081, ..., 8085]
    
    Args:
        port_spec: Port specification string
        
    Returns:
        List of port numbers
    """
    ports = set()
    
    # Split by commas and process each part
    for part in port_spec.split(','):
        part = part.strip()
        if not part:
            continue
            
        # Check for range
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start, end + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range format: {part}") from e
        else:
            # Single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
            except ValueError as e:
                raise ValueError(f"Invalid port number: {part}") from e
    
    return sorted(ports)

def validate_ip(ip: str) -> bool:
    """
    Validate an IP address.
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_host(hostname: str) -> Tuple[str, str]:
    """
    Resolve a hostname to an IP address and get the reverse DNS name.
    
    Args:
        hostname: Hostname or IP address to resolve
        
    Returns:
        Tuple of (ip_address, hostname)
    """
    try:
        # Check if it's already an IP address
        if validate_ip(hostname):
            ip = hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = ip
        else:
            # Resolve hostname to IP
            ip = socket.gethostbyname(hostname)
            
        return ip, hostname
        
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve hostname: {hostname}") from e

def get_service_name(port: int, protocol: str = 'tcp') -> str:
    """
    Get the service name for a given port and protocol.
    
    Args:
        port: Port number
        protocol: Protocol ('tcp' or 'udp')
        
    Returns:
        Service name or 'unknown' if not found
    """
    try:
        return socket.getservbyport(port, protocol)
    except (OSError, socket.error):
        # Check common ports if not found in services
        common_ports = {
            # TCP
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps',
            995: 'pop3s', 1723: 'pptp', 3306: 'mysql', 3389: 'ms-wbt-server',
            5900: 'vnc', 8080: 'http-proxy', 8443: 'https-alt',
            # UDP
            53: 'domain', 67: 'dhcps', 68: 'dhcpc', 69: 'tftp', 123: 'ntp',
            161: 'snmp', 162: 'snmptrap', 500: 'isakmp', 1701: 'l2tp',
            4500: 'ipsec-nat-t'
        }
        return common_ports.get(port, 'unknown')

def print_banner() -> None:
    """Print the Nexus Port Scanner banner."""
    banner = """

888b    888 8888888888 Y88b   d88P 888     888  .d8888b.  
8888b   888 888         Y88b d88P  888     888 d88P  Y88b 
88888b  888 888          Y88o88P   888     888 Y88b.      
888Y88b 888 8888888       Y888P    888     888  "Y888b.   
888 Y88b888 888           d888b    888     888     "Y88b. 
888  Y88888 888          d88888b   888     888       "888 
888   Y8888 888         d88P Y88b  Y88b. .d88P Y88b  d88P 
888    Y888 8888888888 d88P   Y88b  "Y88888P"   "Y8888P"  
                                                          
                                                          
                                                          
                                                
    Nexus Advanced Port Scanner - Version 2.0        
    -----------------------------------
    """
    print(banner)

def save_results(results: List[Dict[str, Any]], filename: str, format_type: str = 'text') -> None:
    """
    Save scan results to a file in the specified format.
    
    Args:
        results: List of scan results
        filename: Output filename (without extension)
        format_type: Output format ('text', 'json', or 'csv')
        
    Raises:
        ValueError: If format_type is not one of 'text', 'json', or 'csv'
        IOError: If there's an error writing to the file
    """
    if not results:
        print("[!] No results to save")
        return
        
    try:
        if format_type == 'json':
            with open(f"{filename}.json", 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
                
        elif format_type == 'csv':
            with open(f"{filename}.csv", 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['port', 'protocol', 'state', 'service', 'banner', 'reason']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(results)
                
        elif format_type == 'text':
            with open(f"{filename}.txt", 'w', encoding='utf-8') as f:
                f.write(f"# Nexus Port Scanner Results\n")
                f.write(f"# Generated: {datetime.datetime.now().isoformat()}\n")
                f.write("PORT\tSTATE\tSERVICE\tBANNER\n")
                f.write("-" * 80 + "\n")
                
                for result in results:
                    if result.get('state') == 'open':
                        port = result.get('port', '')
                        protocol = result.get('protocol', 'tcp')
                        service = result.get('service', '')
                        banner = result.get('banner', '')
                        f.write(f"{port}/{protocol}\topen\t{service}\t{banner}\n")
        else:
            raise ValueError(f"Unsupported format: {format_type}")
            
        print(f"[+] Results saved to {filename}.{format_type}")
        
    except (IOError, OSError) as e:
        raise IOError(f"Failed to save results: {str(e)}") from e

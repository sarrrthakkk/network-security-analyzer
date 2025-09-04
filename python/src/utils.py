#!/usr/bin/env python3
"""
Network Utilities - Network Security Analyzer
Spring 2024 Security Software Development

Provides utility functions for network operations, data formatting,
and common network security analysis tasks.
"""

import socket
import struct
import hashlib
import base64
import re
import ipaddress
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import logging


class NetworkUtils:
    """Utility class for network operations and data formatting."""
    
    # Common port mappings
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt"
    }
    
    # Private IP ranges
    PRIVATE_IP_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12", 
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16"
    ]
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if an IP address is in private ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for private_range in NetworkUtils.PRIVATE_IP_RANGES:
                if ip_obj in ipaddress.ip_network(private_range):
                    return True
            return False
        except ValueError:
            return False
    
    @staticmethod
    def is_loopback_ip(ip: str) -> bool:
        """Check if an IP address is a loopback address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback
        except ValueError:
            return False
    
    @staticmethod
    def ip_to_binary(ip: str) -> str:
        """Convert IP address to binary representation."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return format(int(ip_obj), '032b')
        except ValueError:
            return ""
    
    @staticmethod
    def binary_to_ip(binary: str) -> str:
        """Convert binary representation to IP address."""
        try:
            if len(binary) != 32:
                return ""
            ip_int = int(binary, 2)
            return str(ipaddress.ip_address(ip_int))
        except (ValueError, TypeError):
            return ""
    
    @staticmethod
    def ip_to_uint32(ip: str) -> int:
        """Convert IP address to 32-bit unsigned integer."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return int(ip_obj)
        except ValueError:
            return 0
    
    @staticmethod
    def uint32_to_ip(ip_int: int) -> str:
        """Convert 32-bit unsigned integer to IP address."""
        try:
            return str(ipaddress.ip_address(ip_int))
        except ValueError:
            return ""
    
    @staticmethod
    def get_ip_class(ip: str) -> str:
        """Get the class of an IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return "Private"
            elif ip_obj.is_loopback:
                return "Loopback"
            elif ip_obj.is_link_local:
                return "Link-Local"
            elif ip_obj.is_multicast:
                return "Multicast"
            else:
                return "Public"
        except ValueError:
            return "Invalid"
    
    @staticmethod
    def get_subnet_mask(ip: str) -> str:
        """Get the default subnet mask for an IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                # Simple class-based subnet masks
                first_octet = int(ip.split('.')[0])
                if first_octet < 128:
                    return "255.0.0.0"  # Class A
                elif first_octet < 192:
                    return "255.255.0.0"  # Class B
                else:
                    return "255.255.255.0"  # Class C
            return ""
        except (ValueError, IndexError):
            return ""
    
    @staticmethod
    def is_valid_port(port: int) -> bool:
        """Check if a port number is valid."""
        return 0 <= port <= 65535
    
    @staticmethod
    def is_well_known_port(port: int) -> bool:
        """Check if a port is a well-known port (0-1023)."""
        return 0 <= port <= 1023
    
    @staticmethod
    def is_registered_port(port: int) -> bool:
        """Check if a port is a registered port (1024-49151)."""
        return 1024 <= port <= 49151
    
    @staticmethod
    def is_dynamic_port(port: int) -> bool:
        """Check if a port is a dynamic port (49152-65535)."""
        return 49152 <= port <= 65535
    
    @staticmethod
    def get_service_name(port: int) -> str:
        """Get the service name for a well-known port."""
        return NetworkUtils.COMMON_PORTS.get(port, "Unknown")
    
    @staticmethod
    def get_common_ports() -> List[int]:
        """Get list of common ports."""
        return list(NetworkUtils.COMMON_PORTS.keys())
    
    @staticmethod
    def get_protocol_name(protocol: int) -> str:
        """Get the protocol name for a protocol number."""
        protocol_names = {
            1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"
        }
        return protocol_names.get(protocol, f"Protocol-{protocol}")
    
    @staticmethod
    def get_protocol_number(protocol: str) -> int:
        """Get the protocol number for a protocol name."""
        protocol_numbers = {
            "ICMP": 1, "TCP": 6, "UDP": 17, "ICMPv6": 58
        }
        return protocol_numbers.get(protocol.upper(), 0)
    
    @staticmethod
    def is_tcp_protocol(protocol: int) -> bool:
        """Check if protocol number represents TCP."""
        return protocol == 6
    
    @staticmethod
    def is_udp_protocol(protocol: int) -> bool:
        """Check if protocol number represents UDP."""
        return protocol == 17
    
    @staticmethod
    def is_icmp_protocol(protocol: int) -> bool:
        """Check if protocol number represents ICMP."""
        return protocol == 1
    
    @staticmethod
    def format_timestamp(timestamp: datetime) -> str:
        """Format timestamp for display."""
        return timestamp.strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def format_duration(duration_seconds: float) -> str:
        """Format duration in seconds to human-readable format."""
        if duration_seconds < 60:
            return f"{duration_seconds:.1f}s"
        elif duration_seconds < 3600:
            minutes = int(duration_seconds // 60)
            seconds = int(duration_seconds % 60)
            return f"{minutes}m {seconds}s"
        else:
            hours = int(duration_seconds // 3600)
            minutes = int((duration_seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    @staticmethod
    def get_current_time() -> datetime:
        """Get current timestamp."""
        return datetime.now()
    
    @staticmethod
    def get_timestamp_ms() -> int:
        """Get current timestamp in milliseconds."""
        return int(datetime.now().timestamp() * 1000)
    
    @staticmethod
    def get_timestamp_us() -> int:
        """Get current timestamp in microseconds."""
        return int(datetime.now().timestamp() * 1000000)
    
    @staticmethod
    def md5_hash(data: str) -> str:
        """Generate MD5 hash of data."""
        return hashlib.md5(data.encode()).hexdigest()
    
    @staticmethod
    def sha1_hash(data: str) -> str:
        """Generate SHA1 hash of data."""
        return hashlib.sha1(data.encode()).hexdigest()
    
    @staticmethod
    def sha256_hash(data: str) -> str:
        """Generate SHA256 hash of data."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def generate_uuid() -> str:
        """Generate a simple UUID-like string."""
        import uuid
        return str(uuid.uuid4())
    
    @staticmethod
    def hash_string(text: str) -> int:
        """Generate a simple hash of a string."""
        return hash(text) & 0xFFFFFFFFFFFFFFFF  # 64-bit hash
    
    @staticmethod
    def base64_encode(data: bytes) -> str:
        """Encode data to base64."""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def base64_decode(encoded: str) -> bytes:
        """Decode base64 data."""
        return base64.b64decode(encoded)
    
    @staticmethod
    def hex_encode(data: bytes) -> str:
        """Encode data to hexadecimal."""
        return data.hex()
    
    @staticmethod
    def hex_decode(encoded: str) -> bytes:
        """Decode hexadecimal data."""
        return bytes.fromhex(encoded)
    
    @staticmethod
    def url_encode(text: str) -> str:
        """URL encode a string."""
        import urllib.parse
        return urllib.parse.quote(text)
    
    @staticmethod
    def url_decode(encoded: str) -> str:
        """URL decode a string."""
        import urllib.parse
        return urllib.parse.unquote(encoded)
    
    @staticmethod
    def resolve_hostname(hostname: str) -> str:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return ""
    
    @staticmethod
    def get_dns_servers() -> List[str]:
        """Get list of DNS servers."""
        try:
            import subprocess
            result = subprocess.run(['cat', '/etc/resolv.conf'], 
                                 capture_output=True, text=True)
            dns_servers = []
            for line in result.stdout.split('\n'):
                if line.startswith('nameserver'):
                    dns_servers.append(line.split()[1])
            return dns_servers
        except Exception:
            return ["8.8.8.8", "8.8.4.4"]  # Default to Google DNS
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def get_interface_ip(interface: str) -> str:
        """Get IP address of a specific interface."""
        try:
            import netifaces
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
            return ""
        except ImportError:
            # Fallback method
            try:
                import subprocess
                result = subprocess.run(['ip', 'addr', 'show', interface], 
                                     capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'inet ' in line:
                        return line.split()[1].split('/')[0]
                return ""
            except Exception:
                return ""
    
    @staticmethod
    def get_network_interfaces() -> List[str]:
        """Get list of network interfaces."""
        try:
            import netifaces
            return netifaces.interfaces()
        except ImportError:
            # Fallback method
            try:
                import subprocess
                result = subprocess.run(['ip', 'link', 'show'], 
                                     capture_output=True, text=True)
                interfaces = []
                for line in result.stdout.split('\n'):
                    if ':' in line and not line.startswith(' '):
                        interface = line.split(':')[1].strip()
                        if interface:
                            interfaces.append(interface)
                return interfaces
            except Exception:
                return []
    
    @staticmethod
    def is_port_open(ip: str, port: int) -> bool:
        """Check if a port is open on a remote host."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                return result == 0
        except Exception:
            return False
    
    @staticmethod
    def format_bytes(bytes_value: int) -> str:
        """Format bytes to human-readable format."""
        if bytes_value < 1024:
            return f"{bytes_value} B"
        elif bytes_value < 1024**2:
            return f"{bytes_value / 1024:.1f} KB"
        elif bytes_value < 1024**3:
            return f"{bytes_value / (1024**2):.1f} MB"
        elif bytes_value < 1024**4:
            return f"{bytes_value / (1024**3):.1f} GB"
        else:
            return f"{bytes_value / (1024**4):.1f} TB"
    
    @staticmethod
    def format_bits_per_second(bps: int) -> str:
        """Format bits per second to human-readable format."""
        if bps < 1000:
            return f"{bps} bps"
        elif bps < 1000000:
            return f"{bps / 1000:.1f} Kbps"
        elif bps < 1000000000:
            return f"{bps / 1000000:.1f} Mbps"
        else:
            return f"{bps / 1000000000:.1f} Gbps"
    
    @staticmethod
    def format_packets_per_second(pps: int) -> str:
        """Format packets per second to human-readable format."""
        if pps < 1000:
            return f"{pps} pps"
        elif pps < 1000000:
            return f"{pps / 1000:.1f} Kpps"
        else:
            return f"{pps / 1000000:.1f} Mpps"
    
    @staticmethod
    def calculate_percentage(value: float, total: float) -> float:
        """Calculate percentage of value relative to total."""
        if total == 0:
            return 0.0
        return (value / total) * 100.0
    
    @staticmethod
    def calculate_percentage_change(old_value: float, new_value: float) -> float:
        """Calculate percentage change between two values."""
        if old_value == 0:
            return 0.0 if new_value == 0 else 100.0
        return ((new_value - old_value) / old_value) * 100.0
    
    @staticmethod
    def is_numeric(text: str) -> bool:
        """Check if a string is numeric."""
        try:
            float(text)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_alpha(text: str) -> bool:
        """Check if a string contains only alphabetic characters."""
        return text.isalpha()
    
    @staticmethod
    def is_alphanumeric(text: str) -> bool:
        """Check if a string contains only alphanumeric characters."""
        return text.isalnum()
    
    @staticmethod
    def is_email(email: str) -> bool:
        """Check if a string is a valid email address."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def is_url(url: str) -> bool:
        """Check if a string is a valid URL."""
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))
    
    @staticmethod
    def is_mac_address(mac: str) -> bool:
        """Check if a string is a valid MAC address."""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))
    
    @staticmethod
    def is_valid_filename(filename: str) -> bool:
        """Check if a string is a valid filename."""
        invalid_chars = '<>:"/\\|?*'
        return not any(char in filename for char in invalid_chars)


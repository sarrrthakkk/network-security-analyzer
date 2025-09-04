#!/usr/bin/env python3
"""
Packet Analyzer Module - Network Security Analyzer
Spring 2024 Security Software Development

Performs deep packet inspection and protocol analysis.
"""

import re
import logging
from typing import Dict, List, Optional, Any
from scapy.all import IP, TCP, UDP, ICMP, Raw, DNS
from scapy.layers.dns import DNSQR, DNSRR


class PacketAnalyzer:
    """
    Deep packet inspection and protocol analysis.

    Analyzes network packets at multiple protocol layers to extract
    meaningful information for security analysis.
    """

    def __init__(self):
        """Initialize the packet analyzer."""
        self.analyze_payloads = True
        self.analyze_encrypted = False
        self.max_payload_size = 1024
        self.logger = logging.getLogger(__name__)

        # Analysis cache
        self.analysis_cache = {}

        # Common patterns for detection
        self.suspicious_patterns = [
            rb'password',
            rb'admin',
            rb'root',
            rb'shell',
            rb'cmd',
            rb'exec',
            rb'system',
            rb'<script',
            rb'javascript:',
            rb'vbscript:',
            rb'data:text/html',
            rb'base64',
            rb'%3Cscript',
            rb'%3Ciframe'
        ]

        # HTTP methods
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']

        # Common file extensions
        self.file_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.js',
            '.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.xml', '.json'
        ]

    def initialize(self, config) -> None:
        """Initialize the analyzer with configuration."""
        self.analyze_payloads = getattr(config, 'analyze_payloads', True)
        self.analyze_encrypted = getattr(config, 'analyze_encrypted', False)
        self.max_payload_size = getattr(config, 'max_payload_size', 1024)

        self.logger.info("Packet analyzer initialized")

    def analyze_packet(self, packet) -> Dict[str, Any]:
        """Analyze a single packet and return analysis results."""
        try:
            analysis = {
                'timestamp': None,
                'protocol': 'Unknown',
                'source_ip': None,
                'dest_ip': None,
                'source_port': None,
                'dest_port': None,
                'packet_size': len(packet),
                'flags': {},
                'payload_analysis': {},
                'protocol_specific': {},
                'suspicious_indicators': [],
                'metadata': {}
            }

            # Basic packet information
            if IP in packet:
                analysis['source_ip'] = packet[IP].src
                analysis['dest_ip'] = packet[IP].dst
                analysis['timestamp'] = packet.time if hasattr(packet, 'time') else None

            # Protocol-specific analysis
            if TCP in packet:
                analysis['protocol'] = 'TCP'
                analysis['source_port'] = packet[TCP].sport
                analysis['dest_port'] = packet[TCP].dport
                analysis['flags'] = self._analyze_tcp_flags(packet[TCP])
                analysis['protocol_specific'] = self._analyze_tcp(packet)

            elif UDP in packet:
                analysis['protocol'] = 'UDP'
                analysis['source_port'] = packet[UDP].sport
                analysis['dest_port'] = packet[UDP].dport
                analysis['protocol_specific'] = self._analyze_udp(packet)

            elif ICMP in packet:
                analysis['protocol'] = 'ICMP'
                analysis['protocol_specific'] = self._analyze_icmp(packet)

            # Higher-layer protocol analysis
            if DNS in packet:
                analysis['protocol'] = 'DNS'
                analysis['protocol_specific'].update(self._analyze_dns(packet))

            # HTTP analysis (basic pattern matching)
            if Raw in packet:
                http_analysis = self._analyze_http_basic(packet)
                if http_analysis:
                    analysis['protocol'] = 'HTTP'
                    analysis['protocol_specific'].update(http_analysis)

            # Payload analysis
            if self.analyze_payloads and Raw in packet:
                analysis['payload_analysis'] = self._analyze_payload(packet)

            # Suspicious indicators
            analysis['suspicious_indicators'] = self._detect_suspicious_indicators(packet, analysis)

            # Cache analysis results
            packet_id = self._generate_packet_id(packet)
            self.analysis_cache[packet_id] = analysis

            return analysis

        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
            return {'error': str(e)}

    def _analyze_tcp_flags(self, tcp_layer) -> Dict[str, bool]:
        """Analyze TCP flags."""
        return {
            'SYN': bool(tcp_layer.flags & 0x02),
            'ACK': bool(tcp_layer.flags & 0x10),
            'FIN': bool(tcp_layer.flags & 0x01),
            'RST': bool(tcp_layer.flags & 0x04),
            'PSH': bool(tcp_layer.flags & 0x08),
            'URG': bool(tcp_layer.flags & 0x20)
        }

    def _analyze_tcp(self, packet) -> Dict[str, Any]:
        """Analyze TCP-specific information."""
        tcp_info = {}

        if TCP in packet:
            tcp = packet[TCP]
            tcp_info = {
                'seq': tcp.seq,
                'ack': tcp.ack,
                'window': tcp.window,
                'urgptr': tcp.urgptr,
                'options': str(tcp.options) if tcp.options else None
            }

            # Detect port scanning
            if tcp.flags & 0x02:  # SYN flag
                tcp_info['connection_type'] = 'SYN'
            elif tcp.flags & 0x01:  # FIN flag
                tcp_info['connection_type'] = 'FIN'
            elif tcp.flags & 0x04:  # RST flag
                tcp_info['connection_type'] = 'RST'
            else:
                tcp_info['connection_type'] = 'Data'

        return tcp_info

    def _analyze_udp(self, packet) -> Dict[str, Any]:
        """Analyze UDP-specific information."""
        udp_info = {}

        if UDP in packet:
            udp = packet[UDP]
            udp_info = {
                'length': udp.len,
                'checksum': udp.chksum
            }

            # Detect potential DNS tunneling
            if udp.sport == 53 or udp.dport == 53:
                udp_info['dns_related'] = True

        return udp_info

    def _analyze_icmp(self, packet) -> Dict[str, Any]:
        """Analyze ICMP-specific information."""
        icmp_info = {}

        if ICMP in packet:
            icmp = packet[ICMP]
            icmp_info = {
                'type': icmp.type,
                'code': icmp.code,
                'id': icmp.id,
                'seq': icmp.seq
            }

            # ICMP type descriptions
            icmp_types = {
                0: 'Echo Reply',
                3: 'Destination Unreachable',
                5: 'Redirect',
                8: 'Echo Request',
                11: 'Time Exceeded',
                13: 'Timestamp',
                14: 'Timestamp Reply'
            }

            icmp_info['type_description'] = icmp_types.get(icmp.type, 'Unknown')

        return icmp_info

    def _analyze_http_basic(self, packet) -> Optional[Dict[str, Any]]:
        """Enhanced HTTP analysis using pattern matching."""
        try:
            if Raw in packet:
                payload = bytes(packet[Raw])
                payload_str = payload.decode('utf-8', errors='ignore')

                http_info = {}

                # Check for HTTP methods
                for method in self.http_methods:
                    if payload_str.startswith(method + ' '):
                        http_info['method'] = method
                        http_info['request_type'] = 'Request'
                        
                        # Extract path
                        lines = payload_str.split('\n')
                        if lines:
                            first_line = lines[0].strip()
                            parts = first_line.split(' ')
                            if len(parts) >= 2:
                                http_info['path'] = parts[1]
                                # Extract query parameters
                                if '?' in parts[1]:
                                    path, query = parts[1].split('?', 1)
                                    http_info['path'] = path
                                    http_info['query_params'] = query
                        
                        break

                # Check for HTTP response
                if payload_str.startswith('HTTP/'):
                    http_info['request_type'] = 'Response'
                    
                    # Extract status code
                    lines = payload_str.split('\n')
                    if lines:
                        first_line = lines[0].strip()
                        parts = first_line.split(' ')
                        if len(parts) >= 2:
                            try:
                                http_info['status_code'] = int(parts[1])
                                # Add status description
                                status_descriptions = {
                                    200: 'OK', 201: 'Created', 301: 'Moved Permanently',
                                    302: 'Found', 400: 'Bad Request', 401: 'Unauthorized',
                                    403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error',
                                    502: 'Bad Gateway', 503: 'Service Unavailable'
                                }
                                http_info['status_description'] = status_descriptions.get(int(parts[1]), 'Unknown')
                            except ValueError:
                                http_info['status_code'] = 'Unknown'

                # Extract HTTP headers
                headers = {}
                lines = payload_str.split('\n')
                for line in lines:
                    if ':' in line and not line.startswith('HTTP/') and not line.startswith('GET ') and not line.startswith('POST '):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip()] = value.strip()
                
                if headers:
                    http_info['headers'] = headers
                    
                    # Extract specific headers
                    if 'Host:' in payload_str:
                        host_line = [line for line in lines if line.startswith('Host:')]
                        if host_line:
                            http_info['host'] = host_line[0].split(':', 1)[1].strip()
                    
                    if 'User-Agent:' in payload_str:
                        ua_line = [line for line in lines if line.startswith('User-Agent:')]
                        if ua_line:
                            http_info['user_agent'] = ua_line[0].split(':', 1)[1].strip()
                    
                    if 'Content-Type:' in payload_str:
                        ct_line = [line for line in lines if line.startswith('Content-Type:')]
                        if ct_line:
                            http_info['content_type'] = ct_line[0].split(':', 1)[1].strip()
                    
                    if 'Content-Length:' in payload_str:
                        cl_line = [line for line in lines if line.startswith('Content-Length:')]
                        if cl_line:
                            try:
                                http_info['content_length'] = int(cl_line[0].split(':', 1)[1].strip())
                            except ValueError:
                                pass

                # Detect potential security issues
                security_indicators = []
                
                # Check for suspicious paths
                if 'path' in http_info:
                    path = http_info['path'].lower()
                    suspicious_paths = ['/admin', '/login', '/wp-admin', '/phpmyadmin', '/config', '/.env']
                    for suspicious in suspicious_paths:
                        if suspicious in path:
                            security_indicators.append(f'Suspicious path: {suspicious}')
                
                # Check for suspicious headers
                if 'headers' in http_info:
                    headers_lower = {k.lower(): v for k, v in http_info['headers'].items()}
                    if 'x-forwarded-for' in headers_lower:
                        security_indicators.append('Proxy detected')
                    if 'x-real-ip' in headers_lower:
                        security_indicators.append('Real IP header detected')
                
                # Check for potential injection attempts
                injection_patterns = ["'", ';', '--', '/*', '*/', '<script', 'javascript:', 'vbscript:']
                for pattern in injection_patterns:
                    if pattern.lower() in payload_str.lower():
                        security_indicators.append(f'Potential injection: {pattern}')
                
                if security_indicators:
                    http_info['security_indicators'] = security_indicators

                if http_info:
                    return http_info

            return None

        except Exception as e:
            self.logger.error(f"Error in enhanced HTTP analysis: {e}")
            return None

    def _analyze_dns(self, packet) -> Dict[str, Any]:
        """Analyze DNS traffic."""
        dns_info = {}

        try:
            if DNS in packet:
                dns = packet[DNS]
                dns_info['qr'] = dns.qr  # 0=Query, 1=Response
                dns_info['opcode'] = dns.opcode
                dns_info['aa'] = dns.aa  # Authoritative Answer
                dns_info['tc'] = dns.tc  # Truncation
                dns_info['rd'] = dns.rd  # Recursion Desired
                dns_info['ra'] = dns.ra  # Recursion Available
                dns_info['z'] = dns.z
                dns_info['rcode'] = dns.rcode

                # DNS Queries
                if DNSQR in packet:
                    qr = packet[DNSQR]
                    dns_info['query_name'] = qr.qname.decode() if qr.qname else 'Unknown'
                    dns_info['query_type'] = qr.qtype
                    dns_info['query_class'] = qr.qclass

                # DNS Responses
                if DNSRR in packet:
                    rr = packet[DNSRR]
                    dns_info['response_name'] = rr.rrname.decode() if rr.rrname else 'Unknown'
                    dns_info['response_type'] = rr.type
                    dns_info['response_class'] = rr.rclass
                    dns_info['response_ttl'] = rr.ttl
                    dns_info['response_data'] = str(rr.rdata)

                # Detect potential DNS tunneling
                if dns_info.get('query_name'):
                    query = dns_info['query_name']
                    if len(query) > 100:  # Very long domain names
                        dns_info['potential_tunneling'] = True
                    elif query.count('.') > 10:  # Many subdomains
                        dns_info['potential_tunneling'] = True

        except Exception as e:
            self.logger.error(f"Error analyzing DNS: {e}")
            dns_info['error'] = str(e)

        return dns_info

    def _analyze_payload(self, packet) -> Dict[str, Any]:
        """Analyze packet payload."""
        payload_analysis = {
            'size': 0,
            'encoding': None,
            'content_type': None,
            'suspicious_patterns': [],
            'entropy': 0.0,
            'printable_ratio': 0.0
        }

        try:
            if Raw in packet:
                payload = bytes(packet[Raw])
                payload_analysis['size'] = len(payload)

                if payload_analysis['size'] > self.max_payload_size:
                    payload = payload[:self.max_payload_size]

                # Detect encoding
                payload_analysis['encoding'] = self._detect_encoding(payload)

                # Detect content type
                payload_analysis['content_type'] = self._detect_content_type(payload)

                # Check for suspicious patterns
                for pattern in self.suspicious_patterns:
                    if pattern in payload.lower():
                        payload_analysis['suspicious_patterns'].append(pattern.decode())

                # Calculate entropy
                payload_analysis['entropy'] = self._calculate_entropy(payload)

                # Calculate printable character ratio
                payload_analysis['printable_ratio'] = self._calculate_printable_ratio(payload)

        except Exception as e:
            self.logger.error(f"Error analyzing payload: {e}")

        return payload_analysis

    def _detect_encoding(self, data: bytes) -> str:
        """Detect encoding of binary data."""
        if data.startswith(b'\x1f\x8b'):
            return 'gzip'
        elif data.startswith(b'PK'):
            return 'zip'
        elif data.startswith(b'\x89PNG'):
            return 'png'
        elif data.startswith(b'\xff\xd8\xff'):
            return 'jpeg'
        elif data.startswith(b'GIF8'):
            return 'gif'
        elif data.startswith(b'%PDF'):
            return 'pdf'
        elif data.startswith(b'\x7fELF'):
            return 'elf'
        elif data.startswith(b'MZ'):
            return 'pe'
        else:
            return 'unknown'

    def _detect_content_type(self, data: bytes) -> str:
        """Detect content type of data."""
        if data.startswith(b'<') and b'>' in data:
            if b'<html' in data.lower() or b'<!doctype' in data.lower():
                return 'html'
            elif b'<?xml' in data.lower():
                return 'xml'
            else:
                return 'markup'
        elif data.startswith(b'{') or data.startswith(b'['):
            return 'json'
        elif b'\x00' in data[:100]:  # Binary data
            return 'binary'
        else:
            return 'text'

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        try:
            # Count byte frequencies
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1

            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts.values():
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)

            return entropy
        except Exception:
            return 0.0

    def _calculate_printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable ASCII characters."""
        if not data:
            return 0.0

        try:
            printable_count = sum(1 for byte in data if 32 <= byte <= 126)
            return printable_count / len(data)
        except Exception:
            return 0.0

    def _detect_suspicious_indicators(self, packet, analysis: Dict[str, Any]) -> List[str]:
        """Detect suspicious indicators in the packet."""
        indicators = []

        try:
            # Check for unusual packet sizes
            if analysis['packet_size'] > 1500:  # Larger than typical MTU
                indicators.append('Large packet size')

            # Check for unusual ports
            if analysis['source_port'] and analysis['source_port'] < 1024:
                if analysis['source_port'] not in [80, 443, 22, 21, 25, 53]:
                    indicators.append('Unusual source port')

            # Check for potential port scanning
            if analysis['protocol'] == 'TCP' and analysis['flags'].get('SYN') and not analysis['flags'].get('ACK'):
                indicators.append('SYN scan indicator')

            # Check for potential DDoS indicators
            if analysis['packet_size'] < 64:  # Very small packets
                indicators.append('Small packet size (potential DDoS)')

            # Check payload analysis for suspicious patterns
            if analysis['payload_analysis'].get('suspicious_patterns'):
                indicators.extend(analysis['payload_analysis']['suspicious_patterns'])

            # Check for potential data exfiltration
            if analysis['payload_analysis'].get('size', 0) > 1000:
                if analysis['payload_analysis'].get('entropy', 0) > 7.5:
                    indicators.append('High entropy payload (potential encryption/compression)')

        except Exception as e:
            self.logger.error(f"Error detecting suspicious indicators: {e}")

        return indicators

    def _generate_packet_id(self, packet) -> str:
        """Generate a unique ID for the packet."""
        try:
            if IP in packet and TCP in packet:
                return f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}-{packet.time}"
            elif IP in packet and UDP in packet:
                return f"{packet[IP].src}:{packet[UDP].sport}-{packet[IP].dst}:{packet[UDP].dport}-{packet.time}"
            elif IP in packet:
                return f"{packet[IP].src}-{packet[IP].dst}-{packet.time}"
            else:
                # For non-IP packets, use a combination of packet properties
                return f"non-ip-{len(packet)}-{id(packet)}-{packet.time}"
        except Exception as e:
            # Fallback to a safe identifier
            return f"fallback-{id(packet)}-{packet.time}"

    def get_analysis(self, packet) -> Dict[str, Any]:
        """Get cached analysis for a packet."""
        packet_id = self._generate_packet_id(packet)
        return self.analysis_cache.get(packet_id, {})

    def clear_cache(self) -> None:
        """Clear the analysis cache."""
        self.analysis_cache.clear()
        self.logger.info("Analysis cache cleared")

    def reset(self) -> None:
        """Reset the analyzer state."""
        self.clear_cache()
        self.logger.info("Packet analyzer reset")


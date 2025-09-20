#!/usr/bin/env python3
"""
Threat Detector Module - Network Security Analyzer
Spring 2024 Security Software Development

Identifies specific security threats and vulnerabilities in network traffic.
"""

import re
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass


@dataclass
class Threat:
    """Represents a detected security threat."""
    id: str
    timestamp: datetime
    level: str
    type: str
    description: str
    source_ip: str
    dest_ip: str
    evidence: Dict[str, Any]
    confidence: float


class ThreatDetector:
    """
    Threat detection for network security analysis.
    
    Identifies specific security threats including DDoS attacks,
    port scanning, malware traffic, HTTP attacks, and other security issues.
    """
    
    def __init__(self):
        """Initialize the threat detector."""
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.sensitivity_level = "medium"
        self.threat_threshold = 0.8
        
        # Detection state
        self.ddos_detection_enabled = True
        self.port_scan_detection_enabled = True
        self.malware_detection_enabled = True
        self.data_exfiltration_detection_enabled = True
        self.http_threat_detection_enabled = True
        
        # Detected threats
        self.threats = []
        self.threat_counts = defaultdict(int)
        
        # Detection state tracking
        self.detection_state = {
            'connection_attempts': defaultdict(lambda: deque(maxlen=1000)),
            'scanned_ports': defaultdict(set),
            'packet_counts': defaultdict(int),
            'byte_counts': defaultdict(int),
            'last_seen': defaultdict(lambda: datetime.now())
        }
        
        # Threat ID counter
        self.threat_id_counter = 0
        
        # Whitelist for trusted IPs
        self.whitelisted_ips = set()
        
        # Common malicious patterns
        self.malicious_patterns = [
            rb'cmd\.exe',
            rb'powershell',
            rb'wget',
            rb'curl',
            rb'nc\s+-l',
            rb'netcat',
            rb'backdoor',
            rb'shell',
            rb'rootkit',
            rb'keylogger',
            rb'ransomware',
            rb'trojan',
            rb'virus',
            rb'worm',
            rb'spyware'
        ]
        
        # HTTP threat patterns
        self.http_threat_patterns = {
            'xss': [
                rb'<script[^>]*>',
                rb'javascript:',
                rb'vbscript:',
                rb'onload=',
                rb'onerror=',
                rb'onclick=',
                rb'<iframe[^>]*>',
                rb'<object[^>]*>',
                rb'<embed[^>]*>'
            ],
            'sql_injection': [
                rb"' or '1'='1",
                rb"' or 1=1--",
                rb"'; drop table",
                rb"union select",
                rb"select \* from",
                rb"insert into",
                rb"update set",
                rb"delete from"
            ],
            'command_injection': [
                rb'cmd\.exe',
                rb'powershell',
                rb'wget',
                rb'curl',
                rb'nc -l',
                rb'; ls',
                rb'; cat',
                rb'; rm',
                rb'; mkdir'
            ],
            'directory_traversal': [
                rb'\.\./',
                rb'\.\.\\',
                rb'/etc/passwd',
                rb'c:\\windows',
                rb'\.\.%2f',
                rb'\.\.%5c'
            ],
            'scanning_tools': [
                rb'sqlmap',
                rb'nikto',
                rb'nmap',
                rb'w3af',
                rb'burp',
                rb'zap',
                rb'acunetix',
                rb'nessus',
                rb'openvas',
                rb'metasploit'
            ]
        }
        
        # Suspicious file extensions
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs',
            '.js', '.jar', '.msi', '.ps1', '.sh', '.pl', '.py', '.rb'
        ]
    
    def initialize(self, config) -> None:
        """Initialize detector with configuration from the analyzer."""
        try:
            self.config = config
            if hasattr(config, 'threat_threshold'):
                self.threat_threshold = config.threat_threshold
            if hasattr(config, 'verbose') and config.verbose:
                self.logger.setLevel(logging.DEBUG)
            # Optional feature toggles if present on config
            self.http_threat_detection_enabled = getattr(config, 'http_detection', True)
        except Exception as e:
            self.logger.error(f"Failed to initialize ThreatDetector: {e}")

    def process_packet(self, packet, analysis: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Process a packet and detect threats.
        Accepts optional precomputed analysis; if missing, performs payload-only checks.
        """
        threats = []

        try:
            analysis = analysis or {}

            # Extract basic packet info
            source_ip = analysis.get('source_ip', 'Unknown')
            dest_ip = analysis.get('dest_ip', 'Unknown')
            protocol = analysis.get('protocol', 'Unknown')
            dest_port = analysis.get('dest_port')

            # Skip whitelisted IPs
            if source_ip in self.whitelisted_ips:
                return threats

            # Update detection state (requires minimal fields, safe with defaults)
            self._update_detection_state(packet, analysis)

            # Run threat detection methods
            threats.extend(self._detect_ddos_attack(packet, analysis))
            threats.extend(self._detect_port_scan(packet, analysis))
            threats.extend(self._detect_malware_traffic(packet, analysis))
            threats.extend(self._detect_data_exfiltration(packet, analysis))
            threats.extend(self._detect_http_threats(packet, analysis))

            # Add threats to the list
            for threat in threats:
                self.threats.append(threat)
                self.threat_counts[threat['type']] += 1

        except Exception as e:
            self.logger.error(f"Error processing packet for threat detection: {e}")

        return threats
    
    def _detect_http_threats(self, packet, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect HTTP-specific threats."""
        threats = []
        
        try:
            # Check if this is HTTP traffic
            if analysis.get('protocol') != 'HTTP/HTTPS':
                return threats
            
            # Get packet payload
            if 'Raw' in packet:
                payload = bytes(packet['Raw'])
                
                # Check for XSS attacks
                for pattern in self.http_threat_patterns['xss']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        threats.append({
                            'id': f"threat_{self.threat_id_counter}",
                            'timestamp': datetime.now(),
                            'type': 'XSS_ATTACK',
                            'level': 'high',
                            'description': f'Cross-site scripting attempt detected',
                            'source_ip': analysis.get('source_ip', 'Unknown'),
                            'dest_ip': analysis.get('dest_ip', 'Unknown'),
                            'evidence': {'pattern': pattern.decode(), 'payload_sample': payload[:100]},
                            'confidence': 0.9
                        })
                        self.threat_id_counter += 1
                
                # Check for SQL injection
                for pattern in self.http_threat_patterns['sql_injection']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        threats.append({
                            'id': f"threat_{self.threat_id_counter}",
                            'timestamp': datetime.now(),
                            'type': 'SQL_INJECTION',
                            'level': 'high',
                            'description': f'SQL injection attempt detected',
                            'source_ip': analysis.get('source_ip', 'Unknown'),
                            'dest_ip': analysis.get('dest_ip', 'Unknown'),
                            'evidence': {'pattern': pattern.decode(), 'payload_sample': payload[:100]},
                            'confidence': 0.9
                        })
                        self.threat_id_counter += 1
                
                # Check for command injection
                for pattern in self.http_threat_patterns['command_injection']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        threats.append({
                            'id': f"threat_{self.threat_id_counter}",
                            'timestamp': datetime.now(),
                            'type': 'COMMAND_INJECTION',
                            'level': 'high',
                            'description': f'Command injection attempt detected',
                            'source_ip': analysis.get('source_ip', 'Unknown'),
                            'dest_ip': analysis.get('dest_ip', 'Unknown'),
                            'evidence': {'pattern': pattern.decode(), 'payload_sample': payload[:100]},
                            'confidence': 0.9
                        })
                        self.threat_id_counter += 1
                
                # Check for directory traversal
                for pattern in self.http_threat_patterns['directory_traversal']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        threats.append({
                            'id': f"threat_{self.threat_id_counter}",
                            'timestamp': datetime.now(),
                            'type': 'DIRECTORY_TRAVERSAL',
                            'level': 'medium',
                            'description': f'Directory traversal attempt detected',
                            'source_ip': analysis.get('source_ip', 'Unknown'),
                            'dest_ip': analysis.get('dest_ip', 'Unknown'),
                            'evidence': {'pattern': pattern.decode(), 'payload_sample': payload[:100]},
                            'confidence': 0.8
                        })
                        self.threat_id_counter += 1
                
                # Check for scanning tools
                for pattern in self.http_threat_patterns['scanning_tools']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        threats.append({
                            'id': f"threat_{self.threat_id_counter}",
                            'timestamp': datetime.now(),
                            'type': 'SCANNING_TOOL',
                            'level': 'medium',
                            'description': f'Scanning tool detected',
                            'source_ip': analysis.get('source_ip', 'Unknown'),
                            'dest_ip': analysis.get('dest_ip', 'Unknown'),
                            'evidence': {'tool': pattern.decode(), 'payload_sample': payload[:100]},
                            'confidence': 0.7
                        })
                        self.threat_id_counter += 1
        
        except Exception as e:
            self.logger.error(f"Error detecting HTTP threats: {e}")
        
        return threats
    
    def _detect_ddos_attack(self, packet, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect DDoS attacks."""
        threats = []
        
        try:
            source_ip = analysis.get('source_ip', 'Unknown')
            dest_ip = analysis.get('dest_ip', 'Unknown')
            
            # Check for high packet rate from single source
            recent_packets = self.detection_state['packet_counts'][source_ip]
            if recent_packets > 100:  # More than 100 packets in short time
                threats.append({
                    'id': f"threat_{self.threat_id_counter}",
                    'timestamp': datetime.now(),
                    'type': 'DDoS_ATTACK',
                    'level': 'high',
                    'description': f'DDoS attack detected from {source_ip}',
                    'source_ip': source_ip,
                    'dest_ip': dest_ip,
                    'evidence': {'packet_count': recent_packets},
                    'confidence': 0.8
                })
                self.threat_id_counter += 1
        
        except Exception as e:
            self.logger.error(f"Error detecting DDoS attack: {e}")
        
        return threats
    
    def _detect_port_scan(self, packet, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect port scanning."""
        threats = []
        
        try:
            source_ip = analysis.get('source_ip', 'Unknown')
            dest_port = analysis.get('dest_port')
            
            if dest_port:
                scanned_ports = self.detection_state['scanned_ports'][source_ip]
                scanned_ports.add(dest_port)
                
                if len(scanned_ports) > 20:  # More than 20 different ports
                    threats.append({
                        'id': f"threat_{self.threat_id_counter}",
                        'timestamp': datetime.now(),
                        'type': 'PORT_SCAN',
                        'level': 'medium',
                        'description': f'Port scan detected from {source_ip}',
                        'source_ip': source_ip,
                        'dest_ip': analysis.get('dest_ip', 'Unknown'),
                        'evidence': {'scanned_ports': list(scanned_ports)},
                        'confidence': 0.7
                    })
                    self.threat_id_counter += 1
        
        except Exception as e:
            self.logger.error(f"Error detecting port scan: {e}")
        
        return threats
    
    def _detect_malware_traffic(self, packet, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect malware traffic patterns."""
        threats = []
        
        try:
            if 'Raw' in packet:
                payload = bytes(packet['Raw'])
                
                for pattern in self.malicious_patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        threats.append({
                            'id': f"threat_{self.threat_id_counter}",
                            'timestamp': datetime.now(),
                            'type': 'MALWARE_TRAFFIC',
                            'level': 'high',
                            'description': f'Malware traffic detected',
                            'source_ip': analysis.get('source_ip', 'Unknown'),
                            'dest_ip': analysis.get('dest_ip', 'Unknown'),
                            'evidence': {'pattern': pattern.decode(), 'payload_sample': payload[:100]},
                            'confidence': 0.8
                        })
                        self.threat_id_counter += 1
        
        except Exception as e:
            self.logger.error(f"Error detecting malware traffic: {e}")
        
        return threats
    
    def _detect_data_exfiltration(self, packet, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect data exfiltration attempts."""
        threats = []
        
        try:
            # Check for large data transfers to external IPs
            packet_size = analysis.get('size', 0)
            if packet_size > 10000:  # Large packet
                threats.append({
                    'id': f"threat_{self.threat_id_counter}",
                    'timestamp': datetime.now(),
                    'type': 'DATA_EXFILTRATION',
                    'level': 'medium',
                    'description': f'Large data transfer detected',
                    'source_ip': analysis.get('source_ip', 'Unknown'),
                    'dest_ip': analysis.get('dest_ip', 'Unknown'),
                    'evidence': {'packet_size': packet_size},
                    'confidence': 0.6
                })
                self.threat_id_counter += 1
        
        except Exception as e:
            self.logger.error(f"Error detecting data exfiltration: {e}")
        
        return threats
    
    def _update_detection_state(self, packet, analysis: Dict[str, Any]) -> None:
        """Update detection state with packet information."""
        try:
            source_ip = analysis.get('source_ip', 'Unknown')
            dest_ip = analysis.get('dest_ip', 'Unknown')
            
            # Update packet counts
            self.detection_state['packet_counts'][source_ip] += 1
            self.detection_state['byte_counts'][source_ip] += analysis.get('size', 0)
            self.detection_state['last_seen'][source_ip] = datetime.now()
            
            # Update connection attempts
            connection_key = f"{source_ip}:{dest_ip}"
            self.detection_state['connection_attempts'][connection_key].append(datetime.now())
        
        except Exception as e:
            self.logger.error(f"Error updating detection state: {e}")
    
    def get_threats(self) -> List[Dict[str, Any]]:
        """Get all detected threats."""
        return self.threats
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get a summary of detected threats."""
        return {
            'total_threats': len(self.threats),
            'threat_counts': dict(self.threat_counts),
            'recent_threats': [t for t in self.threats if (datetime.now() - t['timestamp']).seconds < 300]
        }
    
    def reset(self) -> None:
        """Reset the threat detector state."""
        self.threats = []
        self.threat_counts.clear()
        self.detection_state = {
            'connection_attempts': defaultdict(lambda: deque(maxlen=1000)),
            'scanned_ports': defaultdict(set),
            'packet_counts': defaultdict(int),
            'byte_counts': defaultdict(int),
            'last_seen': defaultdict(lambda: datetime.now())
        }
        self.threat_id_counter = 0

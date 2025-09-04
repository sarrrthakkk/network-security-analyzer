#!/usr/bin/env python3
"""
Anomaly Detector Module - Network Security Analyzer
Spring 2024 Security Software Development

Uses statistical methods to detect anomalous network behavior.
"""

import time
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from datetime import datetime, timedelta
import numpy as np
from dataclasses import dataclass


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    id: str
    timestamp: datetime
    type: str
    source_ip: str
    dest_ip: str
    description: str
    confidence: float
    evidence: Dict[str, Any]
    severity: str = "medium"


class AnomalyDetector:
    """
    Statistical anomaly detection for network traffic.
    
    Detects unusual patterns in network behavior using various
    statistical methods and thresholds.
    """
    
    def __init__(self):
        """Initialize the anomaly detector."""
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.volume_threshold = 2.0
        self.frequency_threshold = 2.0
        self.pattern_threshold = 2.0
        self.behavioral_threshold = 2.0
        
        # Detection state
        self.volume_detection_enabled = True
        self.frequency_detection_enabled = True
        self.pattern_detection_enabled = True
        self.behavioral_detection_enabled = True
        
        # Historical data storage
        self.recent_packets = deque(maxlen=10000)
        self.recent_flows = deque(maxlen=1000)
        self.ip_timestamps = defaultdict(lambda: deque(maxlen=1000))
        self.port_timestamps = defaultdict(lambda: deque(maxlen=1000))
        
        # Statistical models
        self.ip_models = defaultdict(self._create_statistical_model)
        self.port_models = defaultdict(self._create_statistical_model)
        self.protocol_models = defaultdict(self._create_statistical_model)
        
        # Detected anomalies
        self.anomalies = []
        self.anomaly_counts = defaultdict(int)
        
        # Anomaly ID counter
        self.anomaly_id_counter = 0
        
        # Time windows for analysis
        self.analysis_windows = [60, 300, 900, 3600]  # 1min, 5min, 15min, 1hour
    
    def initialize(self, config) -> None:
        """Initialize the detector with configuration."""
        self.volume_threshold = getattr(config, 'anomaly_threshold', 2.0)
        self.frequency_threshold = getattr(config, 'anomaly_threshold', 2.0)
        self.pattern_threshold = getattr(config, 'anomaly_threshold', 2.0)
        self.behavioral_threshold = getattr(config, 'anomaly_threshold', 2.0)
        
        self.logger.info("Anomaly detector initialized")
    
    def process_packet(self, packet) -> None:
        """Process a packet for anomaly detection."""
        try:
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Store packet for analysis
            self.recent_packets.append(packet_info)
            
            # Update timestamps for frequency analysis
            self._update_timestamps(packet_info)
            
            # Perform anomaly detection
            self._detect_volume_anomalies(packet_info)
            self._detect_frequency_anomalies(packet_info)
            self._detect_pattern_anomalies(packet_info)
            self._detect_behavioral_anomalies(packet_info)
            
            # Update statistical models
            self._update_statistical_models(packet_info)
            
            # Cleanup old data
            self._cleanup_old_data()
            
        except Exception as e:
            self.logger.error(f"Error processing packet for anomaly detection: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extract relevant information from a packet."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            
            packet_info = {
                'timestamp': datetime.now(),
                'size': len(packet),
                'source_ip': None,
                'dest_ip': None,
                'source_port': None,
                'dest_port': None,
                'protocol': 'Unknown'
            }
            
            if IP in packet:
                packet_info['source_ip'] = packet[IP].src
                packet_info['dest_ip'] = packet[IP].dst
                
                if TCP in packet:
                    packet_info['protocol'] = 'TCP'
                    packet_info['source_port'] = packet[TCP].sport
                    packet_info['dest_port'] = packet[TCP].dport
                elif UDP in packet:
                    packet_info['protocol'] = 'UDP'
                    packet_info['source_port'] = packet[UDP].sport
                    packet_info['dest_port'] = packet[UDP].dport
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _update_timestamps(self, packet_info: Dict[str, Any]) -> None:
        """Update timestamp tracking for frequency analysis."""
        timestamp = packet_info['timestamp']
        
        # Update IP timestamps
        if packet_info['source_ip']:
            self.ip_timestamps[packet_info['source_ip']].append(timestamp)
        
        # Update port timestamps
        if packet_info['source_port']:
            self.port_timestamps[packet_info['source_port']].append(timestamp)
    
    def _detect_volume_anomalies(self, packet_info: Dict[str, Any]) -> None:
        """Detect anomalies based on traffic volume."""
        if not self.volume_detection_enabled:
            return
        
        try:
            # Analyze packet size anomalies
            packet_size = packet_info['size']
            if packet_size > 0:
                size_z_score = self._calculate_z_score(packet_size, self._get_size_model())
                if abs(size_z_score) > self.volume_threshold:
                    self._add_anomaly(
                        type="VOLUME_SPIKE",
                        source_ip=packet_info['source_ip'],
                        dest_ip=packet_info['dest_ip'],
                        description=f"Unusual packet size: {packet_size} bytes (z-score: {size_z_score:.2f})",
                        confidence=min(abs(size_z_score) / 5.0, 1.0),
                        evidence={'packet_size': packet_size, 'z_score': size_z_score}
                    )
            
            # Analyze traffic volume over time windows
            for window in self.analysis_windows:
                volume_anomaly = self._detect_volume_anomaly_in_window(window, packet_info)
                if volume_anomaly:
                    self._add_anomaly(**volume_anomaly)
                    
        except Exception as e:
            self.logger.error(f"Error in volume anomaly detection: {e}")
    
    def _detect_frequency_anomalies(self, packet_info: Dict[str, Any]) -> None:
        """Detect anomalies based on traffic frequency."""
        if not self.frequency_detection_enabled:
            return
        
        try:
            source_ip = packet_info['source_ip']
            if not source_ip:
                return
            
            # Analyze IP frequency
            ip_frequency = self._calculate_ip_frequency(source_ip)
            if ip_frequency > 0:
                freq_z_score = self._calculate_z_score(ip_frequency, self.ip_models[source_ip])
                if abs(freq_z_score) > self.frequency_threshold:
                    self._add_anomaly(
                        type="FREQUENCY_ANOMALY",
                        source_ip=source_ip,
                        dest_ip=packet_info['dest_ip'],
                        description=f"Unusual traffic frequency from {source_ip} (z-score: {freq_z_score:.2f})",
                        confidence=min(abs(freq_z_score) / 5.0, 1.0),
                        evidence={'frequency': ip_frequency, 'z_score': freq_z_score}
                    )
            
            # Analyze port frequency
            source_port = packet_info['source_port']
            if source_port:
                port_frequency = self._calculate_port_frequency(source_port)
                if port_frequency > 0:
                    port_freq_z_score = self._calculate_z_score(port_frequency, self.port_models[source_port])
                    if abs(port_freq_z_score) > self.frequency_threshold:
                        self._add_anomaly(
                            type="PORT_FREQUENCY_ANOMALY",
                            source_ip=source_ip,
                            dest_ip=packet_info['dest_ip'],
                            description=f"Unusual port {source_port} usage frequency (z-score: {port_freq_z_score:.2f})",
                            confidence=min(abs(port_freq_z_score) / 5.0, 1.0),
                            evidence={'port': source_port, 'frequency': port_frequency, 'z_score': port_freq_z_score}
                        )
                        
        except Exception as e:
            self.logger.error(f"Error in frequency anomaly detection: {e}")
    
    def _detect_pattern_anomalies(self, packet_info: Dict[str, Any]) -> None:
        """Detect anomalies based on traffic patterns."""
        if not self.pattern_detection_enabled:
            return
        
        try:
            # Detect burst patterns
            burst_anomaly = self._detect_burst_pattern(packet_info)
            if burst_anomaly:
                self._add_anomaly(**burst_anomaly)
            
            # Detect scanning patterns
            scanning_anomaly = self._detect_scanning_pattern(packet_info)
            if scanning_anomaly:
                self._add_anomaly(**scanning_anomaly)
            
            # Detect protocol violations
            protocol_anomaly = self._detect_protocol_violation(packet_info)
            if protocol_anomaly:
                self._add_anomaly(**protocol_anomaly)
                
        except Exception as e:
            self.logger.error(f"Error in pattern anomaly detection: {e}")
    
    def _detect_behavioral_anomalies(self, packet_info: Dict[str, Any]) -> None:
        """Detect anomalies based on behavioral patterns."""
        if not self.behavioral_detection_enabled:
            return
        
        try:
            source_ip = packet_info['source_ip']
            if not source_ip:
                return
            
            # Analyze time-based behavior
            time_anomaly = self._detect_time_anomaly(packet_info)
            if time_anomaly:
                self._add_anomaly(**time_anomaly)
            
            # Analyze connection behavior
            connection_anomaly = self._detect_connection_anomaly(packet_info)
            if connection_anomaly:
                self._add_anomaly(**connection_anomaly)
                
        except Exception as e:
            self.logger.error(f"Error in behavioral anomaly detection: {e}")
    
    def _detect_volume_anomaly_in_window(self, window_seconds: int, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect volume anomalies in a specific time window."""
        try:
            cutoff_time = datetime.now() - timedelta(seconds=window_seconds)
            window_packets = [p for p in self.recent_packets if p['timestamp'] > cutoff_time]
            
            if len(window_packets) < 10:  # Need minimum data
                return None
            
            # Calculate volume metrics
            total_bytes = sum(p['size'] for p in window_packets)
            avg_bytes_per_packet = total_bytes / len(window_packets)
            
            # Check for anomalies
            if avg_bytes_per_packet > 1500:  # Unusually large average packet size
                return {
                    'type': 'VOLUME_WINDOW_ANOMALY',
                    'source_ip': packet_info['source_ip'],
                    'dest_ip': packet_info['dest_ip'],
                    'description': f"High average packet size ({avg_bytes_per_packet:.1f} bytes) in {window_seconds}s window",
                    'confidence': 0.7,
                    'evidence': {'window_seconds': window_seconds, 'avg_bytes_per_packet': avg_bytes_per_packet}
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting volume anomaly in window: {e}")
            return None
    
    def _detect_burst_pattern(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect burst traffic patterns."""
        try:
            source_ip = packet_info['source_ip']
            if not source_ip:
                return None
            
            # Check for rapid successive packets from same source
            # Convert deque to list first, then slice
            all_recent_packets = list(self.recent_packets)
            recent_packets = [p for p in all_recent_packets[-100:] if p['source_ip'] == source_ip]
            
            if len(recent_packets) < 5:
                return None
            
            # Calculate time intervals between packets
            intervals = []
            for i in range(1, len(recent_packets)):
                interval = (recent_packets[i]['timestamp'] - recent_packets[i-1]['timestamp']).total_seconds()
                intervals.append(interval)
            
            if intervals:
                avg_interval = np.mean(intervals)
                if avg_interval < 0.01:  # Less than 10ms between packets
                    return {
                        'type': 'BURST_TRAFFIC',
                        'source_ip': source_ip,
                        'dest_ip': packet_info['dest_ip'],
                        'description': f"Burst traffic pattern detected (avg interval: {avg_interval*1000:.1f}ms)",
                        'confidence': 0.8,
                        'evidence': {'avg_interval': avg_interval, 'packet_count': len(recent_packets)}
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting burst pattern: {e}")
            return None
    
    def _detect_scanning_pattern(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect port scanning patterns."""
        try:
            source_ip = packet_info['source_ip']
            if not source_ip:
                return None
            
            # Check for rapid port scanning
            # Convert deque to list first, then slice
            all_recent_packets = list(self.recent_packets)
            recent_packets = [p for p in all_recent_packets[-100:] if p['source_ip'] == source_ip]
            
            if len(recent_packets) < 10:
                return None
            
            # Count unique destination ports
            dest_ports = set(p['dest_port'] for p in recent_packets if p['dest_port'])
            
            if len(dest_ports) > 20:  # Many different ports
                time_span = (recent_packets[-1]['timestamp'] - recent_packets[0]['timestamp']).total_seconds()
                if time_span < 60:  # Within 1 minute
                    return {
                        'type': 'PORT_SCAN',
                        'source_ip': source_ip,
                        'dest_ip': packet_info['dest_ip'],
                        'description': f"Potential port scan detected ({len(dest_ports)} ports in {time_span:.1f}s)",
                        'confidence': 0.9,
                        'evidence': {'unique_ports': len(dest_ports), 'time_span': time_span}
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting scanning pattern: {e}")
            return None
    
    def _detect_protocol_violation(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect protocol violations."""
        try:
            # Check for unusual port-protocol combinations
            if packet_info['protocol'] == 'TCP' and packet_info['dest_port']:
                if packet_info['dest_port'] == 53:  # DNS typically uses UDP
                    return {
                        'type': 'PROTOCOL_VIOLATION',
                        'source_ip': packet_info['source_ip'],
                        'dest_ip': packet_info['dest_ip'],
                        'description': f"TCP traffic to DNS port {packet_info['dest_port']}",
                        'confidence': 0.6,
                        'evidence': {'protocol': 'TCP', 'port': packet_info['dest_port'], 'expected': 'UDP'}
                    }
            
            # Check for unusual source ports
            if packet_info['source_port'] and packet_info['source_port'] < 1024:
                if packet_info['source_port'] not in [80, 443, 22, 21, 25, 53]:
                    return {
                        'type': 'UNUSUAL_SOURCE_PORT',
                        'source_ip': packet_info['source_ip'],
                        'dest_ip': packet_info['dest_ip'],
                        'description': f"Traffic from unusual source port {packet_info['source_port']}",
                        'confidence': 0.5,
                        'evidence': {'source_port': packet_info['source_port']}
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting protocol violation: {e}")
            return None
    
    def _detect_time_anomaly(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect time-based behavioral anomalies."""
        try:
            # This is a placeholder for time-based anomaly detection
            # Could include analysis of traffic patterns at different times of day
            # For now, return None
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting time anomaly: {e}")
            return None
    
    def _detect_connection_anomaly(self, packet_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect connection-based behavioral anomalies."""
        try:
            # This is a placeholder for connection-based anomaly detection
            # Could include analysis of connection patterns, session duration, etc.
            # For now, return None
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting connection anomaly: {e}")
            return None
    
    def _calculate_ip_frequency(self, ip: str) -> float:
        """Calculate traffic frequency for an IP address."""
        try:
            cutoff_time = datetime.now() - timedelta(seconds=60)  # Last minute
            recent_packets = [p for p in self.recent_packets if p['source_ip'] == ip and p['timestamp'] > cutoff_time]
            return len(recent_packets) / 60.0  # Packets per second
            
        except Exception as e:
            self.logger.error(f"Error calculating IP frequency: {e}")
            return 0.0
    
    def _calculate_port_frequency(self, port: int) -> float:
        """Calculate traffic frequency for a port."""
        try:
            cutoff_time = datetime.now() - timedelta(seconds=60)  # Last minute
            recent_packets = [p for p in self.recent_packets if p['source_port'] == port and p['timestamp'] > cutoff_time]
            return len(recent_packets) / 60.0  # Packets per second
            
        except Exception as e:
            self.logger.error(f"Error calculating port frequency: {e}")
            return 0.0
    
    def _get_size_model(self):
        """Get statistical model for packet sizes."""
        # Use a simple model for packet sizes
        sizes = [p['size'] for p in list(self.recent_packets)[-1000:]]
        if len(sizes) < 10:
            return self._create_statistical_model()
        
        model = self._create_statistical_model()
        for size in sizes:
            self._update_statistical_model(model, size)
        return model
    
    def _update_statistical_models(self, packet_info: Dict[str, Any]) -> None:
        """Update statistical models with new packet data."""
        try:
            # Update IP model
            if packet_info['source_ip']:
                self._update_statistical_model(self.ip_models[packet_info['source_ip']], 1)
            
            # Update port model
            if packet_info['source_port']:
                self._update_statistical_model(self.port_models[packet_info['source_port']], 1)
            
            # Update protocol model
            self._update_statistical_model(self.protocol_models[packet_info['protocol']], 1)
            
        except Exception as e:
            self.logger.error(f"Error updating statistical models: {e}")
    
    def _create_statistical_model(self):
        """Create a new statistical model."""
        return {
            'mean': 0.0,
            'std_dev': 0.0,
            'variance': 0.0,
            'count': 0,
            'recent_values': deque(maxlen=100)
        }
    
    def _update_statistical_model(self, model: Dict[str, Any], value: float) -> None:
        """Update a statistical model with a new value."""
        try:
            model['count'] += 1
            model['recent_values'].append(value)
            
            # Update mean
            old_mean = model['mean']
            model['mean'] = old_mean + (value - old_mean) / model['count']
            
            # Update variance
            if model['count'] > 1:
                model['variance'] = ((model['count'] - 1) * model['variance'] + 
                                   (value - old_mean) * (value - model['mean'])) / model['count']
            
            # Update standard deviation
            model['std_dev'] = model['variance'] ** 0.5
            
        except Exception as e:
            self.logger.error(f"Error updating statistical model: {e}")
    
    def _calculate_z_score(self, value: float, model: Dict[str, Any]) -> float:
        """Calculate z-score for a value relative to a statistical model."""
        try:
            if model['std_dev'] == 0:
                return 0.0
            return (value - model['mean']) / model['std_dev']
        except Exception:
            return 0.0
    
    def _add_anomaly(self, type: str, source_ip: str, dest_ip: str, description: str, 
                     confidence: float, evidence: Dict[str, Any]) -> None:
        """Add a detected anomaly."""
        try:
            self.anomaly_id_counter += 1
            anomaly_id = f"anomaly_{self.anomaly_id_counter}"
            
            anomaly = Anomaly(
                id=anomaly_id,
                timestamp=datetime.now(),
                type=type,
                source_ip=source_ip or "Unknown",
                dest_ip=dest_ip or "Unknown",
                description=description,
                confidence=confidence,
                evidence=evidence,
                severity=self._determine_severity(confidence)
            )
            
            self.anomalies.append(anomaly)
            self.anomaly_counts[type] += 1
            
            self.logger.info(f"Anomaly detected: {type} - {description}")
            
        except Exception as e:
            self.logger.error(f"Error adding anomaly: {e}")
    
    def _determine_severity(self, confidence: float) -> str:
        """Determine severity based on confidence level."""
        if confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"
    
    def _cleanup_old_data(self) -> None:
        """Clean up old data to prevent memory issues."""
        try:
            # Keep only recent anomalies (last 24 hours)
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.anomalies = [a for a in self.anomalies if a.timestamp > cutoff_time]
            
            # Clean up old timestamps
            cutoff_time = datetime.now() - timedelta(hours=1)
            for ip in list(self.ip_timestamps.keys()):
                self.ip_timestamps[ip] = deque(
                    [t for t in self.ip_timestamps[ip] if t > cutoff_time],
                    maxlen=1000
                )
            
            for port in list(self.port_timestamps.keys()):
                self.port_timestamps[port] = deque(
                    [t for t in self.port_timestamps[port] if t > cutoff_time],
                    maxlen=1000
                )
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
    
    def get_anomalies(self) -> List[Dict[str, Any]]:
        """Get list of detected anomalies."""
        return [self._anomaly_to_dict(a) for a in self.anomalies]
    
    def _anomaly_to_dict(self, anomaly: Anomaly) -> Dict[str, Any]:
        """Convert anomaly object to dictionary."""
        return {
            'id': anomaly.id,
            'timestamp': anomaly.timestamp.isoformat(),
            'type': anomaly.type,
            'source_ip': anomaly.source_ip,
            'dest_ip': anomaly.dest_ip,
            'description': anomaly.description,
            'confidence': anomaly.confidence,
            'evidence': anomaly.evidence,
            'severity': anomaly.severity
        }
    
    def get_anomaly_statistics(self) -> Dict[str, int]:
        """Get statistics about detected anomalies."""
        return dict(self.anomaly_counts)
    
    def clear_anomalies(self) -> None:
        """Clear all detected anomalies."""
        self.anomalies.clear()
        self.anomaly_counts.clear()
        self.anomaly_id_counter = 0
        self.logger.info("All anomalies cleared")
    
    def reset(self) -> None:
        """Reset the anomaly detector."""
        self.clear_anomalies()
        self.recent_packets.clear()
        self.recent_flows.clear()
        self.ip_timestamps.clear()
        self.port_timestamps.clear()
        self.ip_models.clear()
        self.port_models.clear()
        self.protocol_models.clear()
        self.logger.info("Anomaly detector reset")


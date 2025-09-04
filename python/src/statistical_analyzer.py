#!/usr/bin/env python3
"""
Statistical Analyzer Module - Network Security Analyzer
Spring 2024 Security Software Development

Provides comprehensive network traffic statistics and metrics.
"""

import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import numpy as np
from dataclasses import dataclass


@dataclass
class StatisticalSummary:
    """Statistical summary of network data."""
    mean: float
    median: float
    std_dev: float
    variance: float
    min: float
    max: float
    percentile_25: float
    percentile_75: float
    percentile_95: float
    percentile_99: float


class StatisticalAnalyzer:
    """
    Comprehensive network traffic statistical analysis.
    
    Provides detailed statistics, metrics, and analysis of network
    traffic patterns and behavior.
    """
    
    def __init__(self):
        """Initialize the statistical analyzer."""
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.history_size = 1000
        self.update_interval = 1.0  # seconds
        self.real_time_updates_enabled = True
        
        # Current statistics
        self.current_stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'avg_packet_size': 0.0,
            'packets_per_second': 0.0,
            'bytes_per_second': 0.0,
            'start_time': None,
            'last_update': None
        }
        
        # Historical statistics
        self.historical_stats = deque(maxlen=1000)
        self.history_timestamps = deque(maxlen=1000)
        
        # Detailed statistics
        self.detailed_stats = {
            'ip_packet_counts': defaultdict(int),
            'ip_byte_counts': defaultdict(int),
            'port_packet_counts': defaultdict(int),
            'port_byte_counts': defaultdict(int),
            'protocol_packet_counts': defaultdict(int),
            'protocol_byte_counts': defaultdict(int),
            'ip_packet_history': defaultdict(lambda: deque(maxlen=100)),
            'ip_byte_history': defaultdict(lambda: deque(maxlen=100)),
            'port_packet_history': defaultdict(lambda: deque(maxlen=100)),
            'port_byte_history': defaultdict(lambda: deque(maxlen=100)),
            'packet_size_history': deque(maxlen=1000),
            'packet_timestamps': deque(maxlen=1000)
        }
        
        # Update tracking
        self.last_update = datetime.now()
        self.packet_counter = 0
        self.byte_counter = 0
        
        # Protocol mapping
        self.protocol_mapping = {
            'TCP': 'TCP',
            'UDP': 'UDP',
            'ICMP': 'ICMP',
            'HTTP': 'HTTP',
            'HTTPS': 'HTTPS',
            'DNS': 'DNS',
            'FTP': 'FTP',
            'SMTP': 'SMTP',
            'SSH': 'SSH'
        }
    
    def initialize(self, config) -> None:
        """Initialize the analyzer with configuration."""
        self.history_size = getattr(config, 'history_size', 1000)
        self.update_interval = getattr(config, 'update_interval', 1.0)
        self.real_time_updates_enabled = getattr(config, 'real_time_updates', True)
        
        self.logger.info("Statistical analyzer initialized")
    
    def process_packet(self, packet) -> None:
        """Process a packet for statistical analysis."""
        try:
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Update basic statistics
            self._update_basic_statistics(packet_info)
            
            # Update detailed statistics
            self._update_detailed_statistics(packet_info)
            
            # Update time series data
            self._update_time_series_data(packet_info)
            
            # Periodic historical update
            current_time = datetime.now()
            if (current_time - self.last_update).total_seconds() >= self.update_interval:
                self._update_historical_statistics()
                self.last_update = current_time
            
        except Exception as e:
            self.logger.error(f"Error processing packet for statistics: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extract relevant information from a packet."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP, DNS
            
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
            
            # Higher-layer protocol detection (basic pattern matching)
            if packet_info['dest_port'] == 80 or packet_info['dest_port'] == 443:
                packet_info['protocol'] = 'HTTP/HTTPS'
            elif DNS in packet:
                packet_info['protocol'] = 'DNS'
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _update_basic_statistics(self, packet_info: Dict[str, Any]) -> None:
        """Update basic packet statistics."""
        try:
            # Update counters
            self.current_stats['total_packets'] += 1
            self.current_stats['total_bytes'] += packet_info['size']
            self.packet_counter += 1
            self.byte_counter += packet_info['size']
            
            # Update protocol-specific counts
            protocol = packet_info['protocol']
            if protocol == 'TCP':
                self.current_stats['tcp_packets'] += 1
            elif protocol == 'UDP':
                self.current_stats['udp_packets'] += 1
            elif protocol == 'ICMP':
                self.current_stats['icmp_packets'] += 1
            else:
                self.current_stats['other_packets'] += 1
            
            # Update start time if not set
            if not self.current_stats['start_time']:
                self.current_stats['start_time'] = packet_info['timestamp']
            
            # Update last update time
            self.current_stats['last_update'] = packet_info['timestamp']
            
        except Exception as e:
            self.logger.error(f"Error updating basic statistics: {e}")
    
    def _update_detailed_statistics(self, packet_info: Dict[str, Any]) -> None:
        """Update detailed statistics."""
        try:
            source_ip = packet_info['source_ip']
            dest_ip = packet_info['dest_ip']
            source_port = packet_info['source_port']
            dest_port = packet_info['dest_port']
            protocol = packet_info['protocol']
            size = packet_info['size']
            
            # Update IP statistics
            if source_ip:
                self.detailed_stats['ip_packet_counts'][source_ip] += 1
                self.detailed_stats['ip_byte_counts'][source_ip] += size
            
            if dest_ip:
                self.detailed_stats['ip_packet_counts'][dest_ip] += 1
                self.detailed_stats['ip_byte_counts'][dest_ip] += size
            
            # Update port statistics
            if source_port:
                self.detailed_stats['port_packet_counts'][source_port] += 1
                self.detailed_stats['port_byte_counts'][source_port] += size
            
            if dest_port:
                self.detailed_stats['port_packet_counts'][dest_port] += 1
                self.detailed_stats['port_byte_counts'][dest_port] += size
            
            # Update protocol statistics
            if protocol in self.protocol_mapping:
                mapped_protocol = self.protocol_mapping[protocol]
                self.detailed_stats['protocol_packet_counts'][mapped_protocol] += 1
                self.detailed_stats['protocol_byte_counts'][mapped_protocol] += size
            
        except Exception as e:
            self.logger.error(f"Error updating detailed statistics: {e}")
    
    def _update_time_series_data(self, packet_info: Dict[str, Any]) -> None:
        """Update time series data."""
        try:
            # Update packet size history
            self.detailed_stats['packet_size_history'].append(packet_info['size'])
            self.detailed_stats['packet_timestamps'].append(packet_info['timestamp'])
            
            # Update IP history
            source_ip = packet_info['source_ip']
            if source_ip:
                self.detailed_stats['ip_packet_history'][source_ip].append(1)
                self.detailed_stats['ip_byte_history'][source_ip].append(packet_info['size'])
            
            # Update port history
            source_port = packet_info['source_port']
            if source_port:
                self.detailed_stats['port_packet_history'][source_port].append(1)
                self.detailed_stats['port_byte_history'][source_port].append(packet_info['size'])
            
        except Exception as e:
            self.logger.error(f"Error updating time series data: {e}")
    
    def _update_historical_statistics(self) -> None:
        """Update historical statistics."""
        try:
            # Calculate current rates
            self._calculate_current_rates()
            
            # Create historical snapshot
            historical_snapshot = self.current_stats.copy()
            historical_snapshot['timestamp'] = datetime.now()
            
            # Store historical data
            self.historical_stats.append(historical_snapshot)
            self.history_timestamps.append(datetime.now())
            
            # Cleanup old historical data
            self._cleanup_old_time_series_data()
            
        except Exception as e:
            self.logger.error(f"Error updating historical statistics: {e}")
    
    def _calculate_current_rates(self) -> None:
        """Calculate current packet and byte rates."""
        try:
            if not self.current_stats['start_time']:
                return
            
            current_time = datetime.now()
            elapsed_time = (current_time - self.current_stats['start_time']).total_seconds()
            
            if elapsed_time > 0:
                # Calculate packets per second
                self.current_stats['packets_per_second'] = self.current_stats['total_packets'] / elapsed_time
                
                # Calculate bytes per second
                self.current_stats['bytes_per_second'] = self.current_stats['total_bytes'] / elapsed_time
                
                # Calculate average packet size
                if self.current_stats['total_packets'] > 0:
                    self.current_stats['avg_packet_size'] = self.current_stats['total_bytes'] / self.current_stats['total_packets']
            
        except Exception as e:
            self.logger.error(f"Error calculating current rates: {e}")
    
    def _cleanup_old_time_series_data(self) -> None:
        """Clean up old time series data."""
        try:
            # Keep only recent data (last hour)
            cutoff_time = datetime.now() - timedelta(hours=1)
            
            # Clean up IP history
            for ip in list(self.detailed_stats['ip_packet_history'].keys()):
                self.detailed_stats['ip_packet_history'][ip] = deque(
                    [v for v in self.detailed_stats['ip_packet_history'][ip]],
                    maxlen=100
                )
                self.detailed_stats['ip_byte_history'][ip] = deque(
                    [v for v in self.detailed_stats['ip_byte_history'][ip]],
                    maxlen=100
                )
            
            # Clean up port history
            for port in list(self.detailed_stats['port_packet_history'].keys()):
                self.detailed_stats['port_packet_history'][port] = deque(
                    [v for v in self.detailed_stats['port_packet_history'][port]],
                    maxlen=100
                )
                self.detailed_stats['port_byte_history'][port] = deque(
                    [v for v in self.detailed_stats['port_byte_history'][port]],
                    maxlen=100
                )
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old time series data: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics."""
        try:
            # Ensure rates are up to date
            self._calculate_current_rates()
            
            # Create comprehensive statistics
            stats = self.current_stats.copy()
            
            # Add protocol breakdown
            stats['protocol_breakdown'] = dict(self.detailed_stats['protocol_packet_counts'])
            
            # Add IP and port frequencies
            stats['ip_frequencies'] = dict(self.detailed_stats['ip_packet_counts'])
            stats['port_frequencies'] = dict(self.detailed_stats['port_packet_counts'])
            
            # Add protocol frequencies
            stats['protocol_frequencies'] = dict(self.detailed_stats['protocol_packet_counts'])
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}
    
    def get_historical_statistics(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get historical statistics."""
        try:
            return list(self.historical_stats)[-count:]
        except Exception as e:
            self.logger.error(f"Error getting historical statistics: {e}")
            return []
    
    def get_ip_statistics(self) -> Dict[str, int]:
        """Get IP address statistics."""
        return dict(self.detailed_stats['ip_packet_counts'])
    
    def get_port_statistics(self) -> Dict[int, int]:
        """Get port statistics."""
        return dict(self.detailed_stats['port_packet_counts'])
    
    def get_protocol_statistics(self) -> Dict[str, int]:
        """Get protocol statistics."""
        return dict(self.detailed_stats['protocol_packet_counts'])
    
    def get_time_series_data(self, metric: str, start: datetime, end: datetime, 
                            interval: timedelta) -> Dict[str, List[int]]:
        """Get time series data for a specific metric."""
        try:
            # This is a placeholder for time series data retrieval
            # Could implement more sophisticated time series analysis
            return {}
            
        except Exception as e:
            self.logger.error(f"Error getting time series data: {e}")
            return {}
    
    def get_packet_size_summary(self) -> StatisticalSummary:
        """Get statistical summary of packet sizes."""
        try:
            sizes = list(self.detailed_stats['packet_size_history'])
            if not sizes:
                return StatisticalSummary(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            
            return self._calculate_statistical_summary(sizes)
            
        except Exception as e:
            self.logger.error(f"Error getting packet size summary: {e}")
            return StatisticalSummary(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    
    def get_packet_rate_summary(self) -> StatisticalSummary:
        """Get statistical summary of packet rates."""
        try:
            # Calculate packet rates from historical data
            rates = []
            for i in range(1, len(self.historical_stats)):
                if self.history_timestamps[i] and self.history_timestamps[i-1]:
                    time_diff = (self.history_timestamps[i] - self.history_timestamps[i-1]).total_seconds()
                    if time_diff > 0:
                        packet_diff = self.historical_stats[i]['total_packets'] - self.historical_stats[i-1]['total_packets']
                        rate = packet_diff / time_diff
                        rates.append(rate)
            
            if not rates:
                return StatisticalSummary(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            
            return self._calculate_statistical_summary(rates)
            
        except Exception as e:
            self.logger.error(f"Error getting packet rate summary: {e}")
            return StatisticalSummary(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    
    def get_byte_rate_summary(self) -> StatisticalSummary:
        """Get statistical summary of byte rates."""
        try:
            # Calculate byte rates from historical data
            rates = []
            for i in range(1, len(self.historical_stats)):
                if self.history_timestamps[i] and self.history_timestamps[i-1]:
                    time_diff = (self.history_timestamps[i] - self.history_timestamps[i-1]).total_seconds()
                    if time_diff > 0:
                        byte_diff = self.historical_stats[i]['total_bytes'] - self.historical_stats[i-1]['total_bytes']
                        rate = byte_diff / time_diff
                        rates.append(rate)
            
            if not rates:
                return StatisticalSummary(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            
            return self._calculate_statistical_summary(rates)
            
        except Exception as e:
            self.logger.error(f"Error getting byte rate summary: {e}")
            return StatisticalSummary(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    
    def _calculate_statistical_summary(self, values: List[float]) -> StatisticalSummary:
        """Calculate comprehensive statistical summary."""
        try:
            if not values:
                return StatisticalSummary(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
            
            # Convert to numpy array for calculations
            np_values = np.array(values)
            
            # Basic statistics
            mean = np.mean(np_values)
            median = np.median(np_values)
            std_dev = np.std(np_values)
            variance = np.var(np_values)
            min_val = np.min(np_values)
            max_val = np.max(np_values)
            
            # Percentiles
            percentile_25 = np.percentile(np_values, 25)
            percentile_75 = np.percentile(np_values, 75)
            percentile_95 = np.percentile(np_values, 95)
            percentile_99 = np.percentile(np_values, 99)
            
            return StatisticalSummary(
                mean=float(mean),
                median=float(median),
                std_dev=float(std_dev),
                variance=float(variance),
                min=float(min_val),
                max=float(max_val),
                percentile_25=float(percentile_25),
                percentile_75=float(percentile_75),
                percentile_95=float(percentile_95),
                percentile_99=float(percentile_99)
            )
            
        except Exception as e:
            self.logger.error(f"Error calculating statistical summary: {e}")
            return StatisticalSummary(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    
    def get_top_source_ips(self, count: int = 10) -> List[Tuple[str, int]]:
        """Get top source IP addresses by packet count."""
        try:
            ip_counts = self.detailed_stats['ip_packet_counts']
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:count]
            
        except Exception as e:
            self.logger.error(f"Error getting top source IPs: {e}")
            return []
    
    def get_top_dest_ips(self, count: int = 10) -> List[Tuple[str, int]]:
        """Get top destination IP addresses by packet count."""
        try:
            # For destination IPs, we can use the same data structure
            # since we're tracking both source and destination
            ip_counts = self.detailed_stats['ip_packet_counts']
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:count]
            
        except Exception as e:
            self.logger.error(f"Error getting top destination IPs: {e}")
            return []
    
    def get_top_ports(self, count: int = 10) -> List[Tuple[int, int]]:
        """Get top ports by packet count."""
        try:
            port_counts = self.detailed_stats['port_packet_counts']
            sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ports[:count]
            
        except Exception as e:
            self.logger.error(f"Error getting top ports: {e}")
            return []
    
    def get_top_talkers(self) -> Dict[str, Any]:
        """Get top talkers summary."""
        try:
            return {
                'top_source_ips': self.get_top_source_ips(10),
                'top_dest_ips': self.get_top_dest_ips(10),
                'top_ports': self.get_top_ports(10),
                'top_protocols': sorted(
                    self.detailed_stats['protocol_packet_counts'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            }
            
        except Exception as e:
            self.logger.error(f"Error getting top talkers: {e}")
            return {}
    
    def get_traffic_patterns(self) -> Dict[str, Any]:
        """Get traffic patterns analysis."""
        try:
            # This is a placeholder for traffic pattern analysis
            # Could include analysis of traffic bursts, time-based patterns, etc.
            return {}
            
        except Exception as e:
            self.logger.error(f"Error getting traffic patterns: {e}")
            return {}
    
    def get_bandwidth_usage(self) -> Dict[str, Any]:
        """Get bandwidth usage analysis."""
        try:
            # This is a placeholder for bandwidth usage analysis
            # Could include analysis of bandwidth trends, peak usage, etc.
            return {}
            
        except Exception as e:
            self.logger.error(f"Error getting bandwidth usage: {e}")
            return {}
    
    def clear_statistics(self) -> None:
        """Clear all statistics."""
        try:
            # Reset current statistics
            self.current_stats = {
                'total_packets': 0,
                'total_bytes': 0,
                'tcp_packets': 0,
                'udp_packets': 0,
                'icmp_packets': 0,
                'other_packets': 0,
                'avg_packet_size': 0.0,
                'packets_per_second': 0.0,
                'bytes_per_second': 0.0,
                'start_time': None,
                'last_update': None
            }
            
            # Clear historical data
            self.historical_stats.clear()
            self.history_timestamps.clear()
            
            # Clear detailed statistics
            self.detailed_stats = {
                'ip_packet_counts': defaultdict(int),
                'ip_byte_counts': defaultdict(int),
                'port_packet_counts': defaultdict(int),
                'port_byte_counts': defaultdict(int),
                'protocol_packet_counts': defaultdict(int),
                'protocol_byte_counts': defaultdict(int),
                'ip_packet_history': defaultdict(lambda: deque(maxlen=100)),
                'ip_byte_history': defaultdict(lambda: deque(maxlen=100)),
                'port_packet_history': defaultdict(lambda: deque(maxlen=100)),
                'port_byte_history': defaultdict(lambda: deque(maxlen=100)),
                'packet_size_history': deque(maxlen=1000),
                'packet_timestamps': deque(maxlen=1000)
            }
            
            # Reset counters
            self.packet_counter = 0
            self.byte_counter = 0
            self.last_update = datetime.now()
            
            self.logger.info("Statistics cleared")
            
        except Exception as e:
            self.logger.error(f"Error clearing statistics: {e}")
    
    def export_statistics(self, filename: str, format: str = "json") -> bool:
        """Export statistics to file."""
        try:
            import json
            
            data = {
                'current_stats': self.get_statistics(),
                'historical_stats': self.get_historical_statistics(),
                'top_talkers': self.get_top_talkers(),
                'export_timestamp': datetime.now().isoformat()
            }
            
            if format.lower() == "json":
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            else:
                self.logger.error(f"Unsupported export format: {format}")
                return False
            
            self.logger.info(f"Statistics exported to: {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting statistics: {e}")
            return False
    
    def set_history_size(self, size: int) -> None:
        """Set the history size for statistics."""
        self.history_size = size
        self.historical_stats = deque(maxlen=size)
        self.history_timestamps = deque(maxlen=size)
    
    def set_update_interval(self, interval: float) -> None:
        """Set the update interval for statistics."""
        self.update_interval = interval
    
    def enable_real_time_updates(self, enabled: bool) -> None:
        """Enable or disable real-time updates."""
        self.real_time_updates_enabled = enabled
    
    def reset(self) -> None:
        """Reset the statistical analyzer."""
        self.clear_statistics()
        self.logger.info("Statistical analyzer reset")


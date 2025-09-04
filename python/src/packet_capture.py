#!/usr/bin/env python3
"""
Packet Capture Module - Network Security Analyzer
Spring 2024 Security Software Development

Handles network packet capture using scapy library.
"""

import time
import threading
from typing import Callable, Optional, List
from scapy.all import sniff, conf, get_if_list, get_if_addr
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import logging

try:
    from utils import NetworkUtils
except ImportError:
    # Fallback for when running as module
    from .utils import NetworkUtils


class PacketCapture:
    """
    Network packet capture using scapy.

    Provides real-time packet capture capabilities with filtering
    and callback support for packet processing.
    """

    def __init__(self):
        """Initialize the packet capture module."""
        self.running = False
        self.capture_thread = None
        self.stop_event = threading.Event()
        self.packet_callback = None
        self.interface = None
        self.filter = None
        self.max_packets = 0
        self.packet_count = 0
        self.start_time = None
        self.logger = logging.getLogger(__name__)

        # Capture statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'start_time': None,
            'end_time': None
        }

    def initialize(self, config) -> bool:
        """Initialize packet capture with configuration."""
        try:
            self.interface = config.interface
            self.filter = config.filter
            self.max_packets = config.max_packets

            # Auto-detect interface if not specified
            if self.interface == "auto":
                self.interface = self._auto_detect_interface()
                if not self.interface:
                    self.logger.error("No suitable network interface found")
                    return False

            # Verify interface exists
            if not self._verify_interface(self.interface):
                self.logger.error(f"Interface {self.interface} not found or not accessible")
                return False

            self.logger.info(f"Packet capture initialized on interface: {self.interface}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize packet capture: {e}")
            return False

    def start_capture(self, callback: Callable) -> bool:
        """Start packet capture with the specified callback."""
        if self.running:
            self.logger.warning("Packet capture already running")
            return False

        try:
            self.packet_callback = callback
            self.running = True
            self.stop_event.clear()
            self.start_time = time.time()
            self.stats['start_time'] = time.time()

            # Start capture in separate thread
            self.capture_thread = threading.Thread(target=self._capture_loop)
            self.capture_thread.daemon = True
            self.capture_thread.start()

            self.logger.info("Packet capture started successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start packet capture: {e}")
            self.running = False
            return False

    def stop_capture(self):
        """Stop packet capture."""
        if not self.running:
            return

        self.logger.info("Stopping packet capture...")
        self.running = False
        self.stop_event.set()

        # Wait for capture thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5.0)

        self.stats['end_time'] = time.time()
        self.logger.info("Packet capture stopped")

    def is_running(self) -> bool:
        """Check if packet capture is running."""
        return self.running

    def get_statistics(self) -> dict:
        """Get capture statistics."""
        stats = self.stats.copy()
        if self.start_time:
            stats['uptime'] = time.time() - self.start_time
            stats['packets_per_second'] = (self.packet_count / max(stats['uptime'], 1))
        return stats

    def _capture_loop(self):
        """Main capture loop running in separate thread."""
        try:
            # Configure scapy for the interface
            conf.iface = self.interface

            # Start sniffing
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self._process_packet,
                store=0,  # Don't store packets in memory
                stop_filter=self._should_stop,
                timeout=None
            )

        except Exception as e:
            self.logger.error(f"Error in capture loop: {e}")
            self.running = False

    def _process_packet(self, packet):
        """Process a captured packet."""
        try:
            if self.stop_event.is_set():
                return

            # Update statistics
            self._update_stats(packet)

            # Call callback if provided
            if self.packet_callback:
                self.packet_callback(packet)

            # Check packet limit
            if self.max_packets > 0 and self.packet_count >= self.max_packets:
                self.logger.info(f"Packet limit reached: {self.max_packets}")
                self.stop_capture()

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def _should_stop(self, packet) -> bool:
        """Determine if capture should stop."""
        return self.stop_event.is_set()

    def _update_stats(self, packet):
        """Update capture statistics."""
        self.packet_count += 1
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += len(packet)

        # Protocol-specific counting
        if TCP in packet:
            self.stats['tcp_packets'] += 1
        elif UDP in packet:
            self.stats['udp_packets'] += 1
        elif ICMP in packet:
            self.stats['icmp_packets'] += 1
        else:
            self.stats['other_packets'] += 1

    def _auto_detect_interface(self) -> Optional[str]:
        """Auto-detect suitable network interface."""
        try:
            interfaces = get_if_list()

            # Filter out loopback and down interfaces
            suitable_interfaces = []
            for iface in interfaces:
                if iface.startswith('lo') or iface.startswith('docker'):
                    continue

                try:
                    addr = get_if_addr(iface)
                    if addr and addr != '0.0.0.0':
                        suitable_interfaces.append(iface)
                except:
                    continue

            if suitable_interfaces:
                # Prefer wired interfaces over wireless
                for iface in suitable_interfaces:
                    if iface.startswith('eth') or iface.startswith('en'):
                        return iface

                # Return first suitable interface
                return suitable_interfaces[0]

            return None

        except Exception as e:
            self.logger.error(f"Error auto-detecting interface: {e}")
            return None

    def _verify_interface(self, interface: str) -> bool:
        """Verify that the specified interface exists and is accessible."""
        try:
            interfaces = get_if_list()
            if interface not in interfaces:
                return False

            # Try to get interface address
            addr = get_if_addr(interface)
            return addr is not None

        except Exception as e:
            self.logger.error(f"Error verifying interface {interface}: {e}")
            return False

    @staticmethod
    def get_available_interfaces() -> List[str]:
        """Get list of available network interfaces."""
        try:
            return get_if_list()
        except Exception as e:
            logging.error(f"Error getting interfaces: {e}")
            return []

    @staticmethod
    def get_interface_description(interface: str) -> str:
        """Get description of the specified interface."""
        try:
            addr = get_if_addr(interface)
            if addr:
                return f"IP: {addr}"
            return ""
        except Exception:
            return ""

    def reset(self):
        """Reset capture state and statistics."""
        self.stop_capture()
        self.packet_count = 0
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'start_time': None,
            'end_time': None
        }
        self.start_time = None
        self.packet_callback = None


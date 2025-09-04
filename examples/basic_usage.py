#!/usr/bin/env python3
"""
Basic Usage Example - Network Security Analyzer
Spring 2024 Security Software Development

This example demonstrates basic usage of the Network Security Analyzer
for network traffic monitoring and security analysis.
"""

import time
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python', 'src'))

from network_analyzer import NetworkAnalyzer, AnalysisConfig


def basic_monitoring_example():
    """Basic network monitoring example."""
    print("=== Basic Network Security Analysis Example ===\n")
    
    # Create configuration
    config = AnalysisConfig(
        interface="auto",  # Auto-detect interface
        timeout=30,        # Run for 30 seconds
        verbose=True,      # Enable verbose output
        anomaly_threshold=2.0,
        threat_threshold=0.8,
        enable_ml=True     # Enable machine learning analysis
    )
    
    # Create analyzer
    analyzer = NetworkAnalyzer(config)
    
    try:
        # Initialize the analyzer
        print("Initializing Network Security Analyzer...")
        if not analyzer.initialize():
            print("Failed to initialize analyzer")
            return False
        
        print("Analyzer initialized successfully!")
        print(f"Interface: {config.interface}")
        print(f"Timeout: {config.timeout} seconds")
        print(f"Anomaly threshold: {config.anomaly_threshold}")
        print(f"Threat threshold: {config.threat_threshold}")
        print(f"ML analysis: {'enabled' if config.enable_ml else 'disabled'}")
        print()
        
        # Start monitoring
        print("Starting network monitoring...")
        if not analyzer.start_monitoring():
            print("Failed to start monitoring")
            return False
        
        print("Monitoring started! Capturing network traffic...")
        print("Press Ctrl+C to stop early\n")
        
        # Monitor for the specified timeout
        start_time = time.time()
        while time.time() - start_time < config.timeout and analyzer.running:
            time.sleep(1)
            
            # Display periodic updates
            elapsed = int(time.time() - start_time)
            if elapsed % 10 == 0:  # Every 10 seconds
                status = analyzer.get_status()
                print(f"[{elapsed}s] Captured {status['packet_count']} packets, "
                      f"{status['byte_count']} bytes")
        
        # Stop monitoring
        print("\nStopping monitoring...")
        analyzer.stop()
        
        # Display results
        print("\n=== Analysis Results ===")
        latest_results = analyzer.get_latest_results(1)
        if latest_results:
            result = latest_results[0]
            print(f"Total packets captured: {result.total_packets}")
            print(f"Total bytes processed: {result.total_bytes}")
            print(f"Anomalies detected: {len(result.anomalies)}")
            print(f"Threats detected: {len(result.threats)}")
            
            if result.anomalies:
                print("\nDetected Anomalies:")
                for i, anomaly in enumerate(result.anomalies, 1):
                    print(f"  {i}. {anomaly.get('type', 'Unknown')}: {anomaly.get('description', '')}")
            
            if result.threats:
                print("\nDetected Threats:")
                for i, threat in enumerate(result.threats, 1):
                    print(f"  {i}. {threat.get('level', 'Unknown')} {threat.get('type', 'Unknown')}: "
                          f"{threat.get('description', '')}")
            
            if result.top_talkers:
                print("\nTop Talkers:")
                for ip, count in list(result.top_talkers.items())[:5]:
                    print(f"  {ip}: {count} packets")
        
        print("\n=== End Results ===")
        return True
        
    except KeyboardInterrupt:
        print("\n\nReceived interrupt signal, stopping...")
        analyzer.stop()
        return True
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        return False


def interface_listing_example():
    """Example of listing available network interfaces."""
    print("=== Network Interface Listing Example ===\n")
    
    try:
        from utils import NetworkUtils
        
        interfaces = NetworkUtils.get_available_interfaces()
        if interfaces:
            print("Available network interfaces:")
            for interface in interfaces:
                print(f"  {interface}")
        else:
            print("No network interfaces found")
            
    except Exception as e:
        print(f"Error listing interfaces: {e}")


def configuration_example():
    """Example of different configuration options."""
    print("=== Configuration Examples ===\n")
    
    # Example 1: Basic monitoring
    basic_config = AnalysisConfig(
        interface="eth0",
        timeout=60,
        verbose=False
    )
    print("Basic Configuration:")
    print(f"  Interface: {basic_config.interface}")
    print(f"  Timeout: {basic_config.timeout}s")
    print(f"  Verbose: {basic_config.verbose}")
    print()
    
    # Example 2: Advanced monitoring with filters
    advanced_config = AnalysisConfig(
        interface="wlan0",
        filter="port 80 or port 443",  # HTTP/HTTPS traffic only
        timeout=300,                   # 5 minutes
        verbose=True,
        anomaly_threshold=1.5,         # More sensitive
        threat_threshold=0.6,          # More sensitive
        enable_ml=True,
        save_packets=True
    )
    print("Advanced Configuration:")
    print(f"  Interface: {advanced_config.interface}")
    print(f"  Filter: {advanced_config.filter}")
    print(f"  Timeout: {advanced_config.timeout}s")
    print(f"  Anomaly threshold: {advanced_config.anomaly_threshold}")
    print(f"  Threat threshold: {advanced_config.threat_threshold}")
    print(f"  ML analysis: {advanced_config.enable_ml}")
    print(f"  Save packets: {advanced_config.save_packets}")
    print()
    
    # Example 3: High-performance monitoring
    perf_config = AnalysisConfig(
        interface="auto",
        timeout=0,                     # Run indefinitely
        verbose=False,
        buffer_size=131072,            # Larger buffer
        analysis_interval=0.5,         # Faster analysis
        enable_realtime=True
    )
    print("High-Performance Configuration:")
    print(f"  Interface: {perf_config.interface}")
    print(f"  Timeout: {'infinite' if perf_config.timeout == 0 else perf_config.timeout}")
    print(f"  Buffer size: {perf_config.buffer_size} bytes")
    print(f"  Analysis interval: {perf_config.analysis_interval}s")
    print(f"  Real-time: {perf_config.enable_realtime}")


def main():
    """Main function demonstrating various examples."""
    print("Network Security Analyzer - Usage Examples")
    print("Spring 2024 Security Software Development\n")
    
    while True:
        print("Select an example to run:")
        print("1. Basic network monitoring (30 seconds)")
        print("2. List available network interfaces")
        print("3. Show configuration examples")
        print("4. Exit")
        
        try:
            choice = input("\nEnter your choice (1-4): ").strip()
            
            if choice == "1":
                print("\n" + "="*50)
                basic_monitoring_example()
                print("="*50 + "\n")
                
            elif choice == "2":
                print("\n" + "="*50)
                interface_listing_example()
                print("="*50 + "\n")
                
            elif choice == "3":
                print("\n" + "="*50)
                configuration_example()
                print("="*50 + "\n")
                
            elif choice == "4":
                print("Exiting...")
                break
                
            else:
                print("Invalid choice. Please enter 1-4.")
                
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()


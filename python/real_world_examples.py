#!/usr/bin/env python3
"""
Real-World Network Security Analyzer Usage Examples
Spring 2024 Security Software Development

This script demonstrates practical usage scenarios for the Network Security Analyzer.
"""

import sys
import time
import argparse
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from network_analyzer import NetworkAnalyzer, AnalysisConfig

def example_1_basic_monitoring():
    """Example 1: Basic network monitoring with real-time alerts"""
    print("🔍 Example 1: Basic Network Monitoring")
    print("=" * 50)
    
    # Configure the analyzer
    config = AnalysisConfig(
        interface="en0",  # Your network interface
        timeout=60,  # Monitor for 60 seconds
        anomaly_threshold=2.0,
        threat_threshold=0.8,
        enable_ml=True,
        verbose=True
    )
    
    # Create and start the analyzer
    analyzer = NetworkAnalyzer()
    analyzer.initialize(config)
    
    try:
        print(f"Starting monitoring on interface: {config.interface}")
        print("Monitoring for suspicious activity...")
        
        # Start monitoring
        analyzer.start_monitoring()
        
        # Monitor for the specified duration
        start_time = time.time()
        while time.time() - start_time < config.timeout:
            # Get real-time status
            status = analyzer.get_status()
            if status['running']:  # Fixed: access dictionary key instead of attribute
                # Get current results from analyzer instance variables
                threats = analyzer.threats
                anomalies = analyzer.anomalies
                statistics = analyzer.statistics
                
                # Check for alerts
                if anomalies:
                    print(f"🚨 ANOMALY DETECTED: {len(anomalies)} anomalies found!")
                    for anomaly in anomalies:
                        print(f"   - {anomaly.get('type', 'Unknown')} from {anomaly.get('source_ip', 'Unknown')} (confidence: {anomaly.get('confidence', 0):.1%})")
                
                if threats:
                    print(f"⚠️  THREAT DETECTED: {len(threats)} threats found!")
                    for threat in threats:
                        print(f"   - {threat.get('level', 'Unknown')} {threat.get('type', 'Unknown')} from {threat.get('source_ip', 'Unknown')}")
                
                # Show basic stats every 10 seconds
                if int(time.time() - start_time) % 10 == 0:
                    total_packets = statistics.get('total_packets', 0)
                    total_bytes = statistics.get('total_bytes', 0)
                    print(f"📊 Packets: {total_packets}, Bytes: {total_bytes:,}")
            
            time.sleep(1)
        
        # Stop monitoring
        analyzer.stop_monitoring()
        
        # Generate comprehensive report
        report_path = "security_report_basic.html"
        analyzer.generate_report(report_path)
        print(f"📄 Report generated: {report_path}")
        
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user")
        analyzer.stop_monitoring()
    except Exception as e:
        print(f"❌ Error: {e}")
        analyzer.stop_monitoring()

def example_2_ddos_detection():
    """Example 2: DDoS attack detection and mitigation"""
    print("\n🛡️ Example 2: DDoS Detection")
    print("=" * 50)
    
    config = AnalysisConfig(
        interface="en0",
        timeout=120,  # Monitor for 2 minutes
        anomaly_threshold=1.5,  # Lower threshold for DDoS detection
        threat_threshold=0.7,
        enable_ml=True,
        verbose=True
    )
    
    analyzer = NetworkAnalyzer()
    analyzer.initialize(config)
    
    try:
        print("Monitoring for DDoS attacks...")
        analyzer.start_monitoring()
        
        start_time = time.time()
        while time.time() - start_time < config.timeout:
            # Get current results from analyzer instance variables
            threats = analyzer.threats
            anomalies = analyzer.anomalies
            statistics = analyzer.statistics
            
            # Check for DDoS indicators
            for anomaly in anomalies:
                if anomaly.get('type') == "VOLUME_SPIKE":
                    print(f"🚨 DDoS ALERT: Volume spike detected from {anomaly.get('source_ip', 'Unknown')}")
                    print(f"   Confidence: {anomaly.get('confidence', 0):.1%}")
                    # Here you could trigger automated mitigation
                    # e.g., block IP, rate limiting, etc.
            
            for threat in threats:
                if threat.get('type') == "DDoS_ATTACK":
                    print(f"⚠️  DDoS THREAT: {threat.get('level', 'Unknown')} level attack from {threat.get('source_ip', 'Unknown')}")
                    print(f"   Evidence: {threat.get('evidence', 'Unknown')}")
            
            time.sleep(2)
        
        analyzer.stop_monitoring()
        
        # Generate DDoS-specific report
        report_path = "ddos_analysis_report.html"
        analyzer.generate_report(report_path)
        print(f"📄 DDoS report generated: {report_path}")
        
    except KeyboardInterrupt:
        print("\n🛑 DDoS monitoring stopped")
        analyzer.stop_monitoring()

def example_3_port_scan_detection():
    """Example 3: Port scanning detection"""
    print("\n🔍 Example 3: Port Scan Detection")
    print("=" * 50)
    
    config = AnalysisConfig(
        interface="en0",
        timeout=90,
        anomaly_threshold=2.0,
        threat_threshold=0.6,  # Lower threshold for port scans
        enable_ml=True,
        verbose=True
    )
    
    analyzer = NetworkAnalyzer()
    analyzer.initialize(config)
    
    try:
        print("Monitoring for port scanning activity...")
        analyzer.start_monitoring()
        
        start_time = time.time()
        while time.time() - start_time < config.timeout:
            # Get current results from analyzer instance variables
            threats = analyzer.threats
            anomalies = analyzer.anomalies
            statistics = analyzer.statistics
            
            # Check for port scanning
            for anomaly in anomalies:
                if anomaly.get('type') == "PORT_SCAN":
                    print(f"🚨 PORT SCAN DETECTED: {anomaly.get('source_ip', 'Unknown')}")
                    print(f"   Confidence: {anomaly.get('confidence', 0):.1%}")
                    # Could trigger firewall rules, logging, etc.
            
            for threat in threats:
                if threat.get('type') == "PORT_SCAN":
                    print(f"⚠️  PORT SCAN THREAT: {threat.get('level', 'Unknown')} level from {threat.get('source_ip', 'Unknown')}")
                    print(f"   Scanned ports: {threat.get('evidence', {}).get('ports', 'Unknown')}")
            
            time.sleep(3)
        
        analyzer.stop_monitoring()
        
        # Generate port scan report
        report_path = "port_scan_report.html"
        analyzer.generate_report(report_path)
        print(f"📄 Port scan report generated: {report_path}")
        
    except KeyboardInterrupt:
        print("\n🛑 Port scan monitoring stopped")
        analyzer.stop_monitoring()

def example_4_continuous_monitoring():
    """Example 4: Continuous monitoring with periodic reports"""
    print("\n🔄 Example 4: Continuous Monitoring")
    print("=" * 50)
    
    config = AnalysisConfig(
        interface="en0",
        timeout=0,  # Run indefinitely
        anomaly_threshold=2.0,
        threat_threshold=0.8,
        enable_ml=True,
        verbose=False  # Less verbose for continuous monitoring
    )
    
    analyzer = NetworkAnalyzer()
    analyzer.initialize(config)
    
    try:
        print("Starting continuous monitoring...")
        print("Press Ctrl+C to stop")
        
        analyzer.start_monitoring()
        
        report_counter = 1
        last_report_time = time.time()
        
        while True:
            current_time = time.time()
            # Get current results from analyzer instance variables
            threats = analyzer.threats
            anomalies = analyzer.anomalies
            statistics = analyzer.statistics
            
            # Generate periodic reports (every 5 minutes)
            if current_time - last_report_time >= 300:  # 5 minutes
                report_path = f"continuous_report_{report_counter}.html"
                analyzer.generate_report(report_path)
                print(f"📄 Periodic report generated: {report_path}")
                
                # Show summary
                total_packets = statistics.get('total_packets', 0)
                total_bytes = statistics.get('total_bytes', 0)
                print(f"📊 Summary: {total_packets} packets, {total_bytes:,} bytes")
                print(f"   Anomalies: {len(anomalies)}, Threats: {len(threats)}")
                
                last_report_time = current_time
                report_counter += 1
            
            # Check for critical alerts
            for threat in threats:
                if threat.get('level') in ["HIGH", "CRITICAL"]:
                    print(f"🚨 CRITICAL ALERT: {threat.get('level', 'Unknown')} {threat.get('type', 'Unknown')} from {threat.get('source_ip', 'Unknown')}")
            
            time.sleep(5)  # Check every 5 seconds
        
    except KeyboardInterrupt:
        print("\n🛑 Continuous monitoring stopped")
        analyzer.stop_monitoring()
        
        # Generate final report
        final_report = "final_continuous_report.html"
        analyzer.generate_report(final_report)
        print(f"📄 Final report generated: {final_report}")

def example_5_custom_filtering():
    """Example 5: Custom packet filtering for specific analysis"""
    print("\n🎯 Example 5: Custom Filtering")
    print("=" * 50)
    
    # Example: Monitor only HTTP/HTTPS traffic
    config = AnalysisConfig(
        interface="en0",
        timeout=60,
        filter="port 80 or port 443",  # Only HTTP/HTTPS
        anomaly_threshold=2.0,
        threat_threshold=0.8,
        enable_ml=True,
        verbose=True
    )
    
    analyzer = NetworkAnalyzer()
    analyzer.initialize(config)
    
    try:
        print("Monitoring HTTP/HTTPS traffic only...")
        analyzer.start_monitoring()
        
        start_time = time.time()
        while time.time() - start_time < config.timeout:
            # Get current results from analyzer instance variables
            threats = analyzer.threats
            anomalies = analyzer.anomalies
            statistics = analyzer.statistics
            
            # Analyze web traffic patterns
            total_packets = statistics.get('total_packets', 0)
            if total_packets > 0:
                print(f"🌐 Web traffic: {total_packets} packets")
                
                # Check for suspicious web activity
                for threat in threats:
                    if threat.get('type') in ["MALWARE_TRAFFIC", "DATA_EXFILTRATION"]:
                        print(f"🚨 Suspicious web activity: {threat.get('type', 'Unknown')} from {threat.get('source_ip', 'Unknown')}")
            
            time.sleep(2)
        
        analyzer.stop_monitoring()
        
        # Generate web traffic report
        report_path = "web_traffic_analysis.html"
        analyzer.generate_report(report_path)
        print(f"📄 Web traffic report generated: {report_path}")
        
    except KeyboardInterrupt:
        print("\n🛑 Web traffic monitoring stopped")
        analyzer.stop_monitoring()

def main():
    """Main function to run examples"""
    parser = argparse.ArgumentParser(description="Network Security Analyzer Examples")
    parser.add_argument("--example", type=int, choices=[1, 2, 3, 4, 5], 
                       help="Example to run (1-5)")
    parser.add_argument("--interface", default="en0", 
                       help="Network interface to monitor")
    
    args = parser.parse_args()
    
    # Update interface in all examples
    if args.interface != "en0":
        print(f"Using interface: {args.interface}")
    
    if args.example:
        # Run specific example
        examples = {
            1: example_1_basic_monitoring,
            2: example_2_ddos_detection,
            3: example_3_port_scan_detection,
            4: example_4_continuous_monitoring,
            5: example_5_custom_filtering
        }
        examples[args.example]()
    else:
        # Run all examples
        print("🚀 Network Security Analyzer - Real-World Examples")
        print("=" * 60)
        
        example_1_basic_monitoring()
        example_2_ddos_detection()
        example_3_port_scan_detection()
        example_4_continuous_monitoring()
        example_5_custom_filtering()
        
        print("\n✅ All examples completed!")
        print("\n📚 Next Steps:")
        print("1. Review generated reports in the current directory")
        print("2. Customize configurations for your network")
        print("3. Integrate with your security infrastructure")
        print("4. Set up automated monitoring and alerting")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Network Security Analyzer - Main Module
Spring 2024 Security Software Development

Main orchestrator for network security analysis.
"""

import sys
import time
import threading
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

# Import components
try:
    from packet_capture import PacketCapture
    from packet_analyzer import PacketAnalyzer
    from anomaly_detector import AnomalyDetector
    from threat_detector import ThreatDetector
    from statistical_analyzer import StatisticalAnalyzer
    from report_generator import ReportGenerator
    from utils import NetworkUtils
except ImportError:
    # Fallback for when running as module
    from .packet_capture import PacketCapture
    from .packet_analyzer import PacketAnalyzer
    from .anomaly_detector import AnomalyDetector
    from .threat_detector import ThreatDetector
    from .statistical_analyzer import StatisticalAnalyzer
    from .report_generator import ReportGenerator
    from .utils import NetworkUtils

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AnalysisConfig:
    """Configuration for network analysis."""
    interface: str = "auto"
    filter: str = ""
    timeout: int = 0
    max_packets: int = 0
    verbose: bool = False
    save_packets: bool = False
    output_file: str = ""
    anomaly_threshold: float = 2.0
    threat_threshold: float = 0.8
    buffer_size: int = 65536
    analysis_interval: float = 1.0
    enable_ml: bool = True
    enable_realtime: bool = True


@dataclass
class AnalysisResult:
    """Results from network analysis."""
    start_time: datetime
    end_time: datetime
    total_packets: int
    total_bytes: int
    threats_detected: List[Dict[str, Any]]
    anomalies_detected: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    report_path: str = ""


class NetworkAnalyzer:
    """
    Main network security analyzer.
    
    Orchestrates packet capture, analysis, threat detection,
    anomaly detection, and reporting.
    """
    
    def __init__(self):
        """Initialize the network analyzer."""
        self.config = None
        self.running = False
        self.analysis_thread = None
        
        # Initialize components
        self.packet_capture = PacketCapture()
        self.packet_analyzer = PacketAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.threat_detector = ThreatDetector()
        self.statistical_analyzer = StatisticalAnalyzer()
        self.report_generator = ReportGenerator()
        
        # Analysis state
        self.start_time = None
        self.end_time = None
        self.packets_processed = 0
        self.bytes_processed = 0
        
        # Results storage
        self.threats = []
        self.anomalies = []
        self.statistics = {}
        
        # ML models
        self.ml_models = {}
        self.scaler = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def initialize(self, config: AnalysisConfig) -> bool:
        """Initialize the analyzer with configuration."""
        try:
            self.config = config
            
            # Initialize components
            self.packet_capture.initialize(config)
            self.packet_analyzer.initialize(config)
            self.anomaly_detector.initialize(config)
            self.threat_detector.initialize(config)
            self.statistical_analyzer.initialize(config)
            self.report_generator.initialize(config)
            
            # Initialize ML models if enabled
            if config.enable_ml:
                self._initialize_ml_models()
            
            self.logger.info("Network analyzer initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize network analyzer: {e}")
            return False
    
    def start_monitoring(self) -> bool:
        """Start network monitoring."""
        if self.running:
            self.logger.warning("Monitoring already running")
            return True
        
        try:
            self.running = True
            self.start_time = datetime.now()
            
            # Start packet capture
            if not self.packet_capture.start_capture(self._process_packet):
                raise Exception("Failed to start packet capture")
            
            # Start analysis thread
            self.analysis_thread = threading.Thread(target=self._analysis_loop)
            self.analysis_thread.daemon = True
            self.analysis_thread.start()
            
            self.logger.info("Network monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            self.running = False
            return False
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        if not self.running:
            return
        
        self.logger.info("Stopping network monitoring...")
        self.running = False
        
        # Stop packet capture
        self.packet_capture.stop_capture()
        
        # Wait for analysis thread
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5.0)
        
        self.end_time = datetime.now()
        self.logger.info("Network monitoring stopped")
    
    def _process_packet(self, packet) -> None:
        """Process a captured packet."""
        try:
            # Update packet count
            self.packets_processed += 1
            self.bytes_processed += len(packet)
            
            # Analyze packet
            analysis = self.packet_analyzer.analyze_packet(packet)
            
            # Detect anomalies
            self.anomaly_detector.process_packet(packet)
            
            # Detect threats
            self.threat_detector.process_packet(packet)
            
            # Update statistics
            self.statistical_analyzer.process_packet(packet)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _analysis_loop(self):
        """Main analysis loop."""
        try:
            while self.running:
                # Perform periodic analysis
                self._perform_periodic_analysis()
                
                # Sleep for analysis interval
                time.sleep(self.config.analysis_interval)
                
        except Exception as e:
            self.logger.error(f"Error in analysis loop: {e}")
    
    def _perform_periodic_analysis(self):
        """Perform periodic analysis tasks."""
        try:
            # Get latest results
            self.threats = self.threat_detector.get_threats()
            self.anomalies = self.anomaly_detector.get_anomalies()
            self.statistics = self.statistical_analyzer.get_statistics()
            
            # Perform ML analysis if enabled
            if self.config.enable_ml:
                ml_anomalies = self._perform_ml_analysis(self.statistics)
                self.anomalies.extend(ml_anomalies)
            
            # Generate alerts
            self._generate_alerts()
            
        except Exception as e:
            self.logger.error(f"Error in periodic analysis: {e}")
    
    def _initialize_ml_models(self):
        """Initialize machine learning models."""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            
            # Initialize models
            self.ml_models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            self.scaler = StandardScaler()
            
            self.logger.info("ML models initialized")
            
        except ImportError:
            self.logger.warning("scikit-learn not available, ML analysis disabled")
            self.config.enable_ml = False
        except Exception as e:
            self.logger.error(f"Error initializing ML models: {e}")
            self.config.enable_ml = False
    
    def _perform_ml_analysis(self, stats: Dict) -> List[Dict]:
        """Perform machine learning-based anomaly detection."""
        try:
            features = self._extract_ml_features(stats)
            
            if not features or len(features) < 10:
                return []
            
            features_scaled = self.scaler.fit_transform(features)
            predictions = self.ml_models['isolation_forest'].fit_predict(features_scaled)
            
            anomalies = []
            for i, pred in enumerate(predictions):
                if pred == -1:  # Anomaly detected
                    anomaly = {
                        'type': 'ML_DETECTED',
                        'confidence': 0.8,
                        'description': 'Machine learning detected anomaly',
                        'features': features[i].tolist(),
                        'timestamp': datetime.now().isoformat()
                    }
                    anomalies.append(anomaly)
            return anomalies
        except Exception as e:
            self.logger.error(f"Error in ML analysis: {e}")
            return []
    
    def _extract_ml_features(self, stats: Dict) -> List[List[float]]:
        """Extract features for ML analysis."""
        try:
            features = []
            
            # Basic statistical features
            if 'total_packets' in stats:
                features.append([
                    stats.get('total_packets', 0),
                    stats.get('total_bytes', 0),
                    stats.get('packets_per_second', 0),
                    stats.get('bytes_per_second', 0),
                    stats.get('avg_packet_size', 0)
                ])
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting ML features: {e}")
            return []
    
    def _generate_alerts(self):
        """Generate alerts for detected threats and anomalies."""
        try:
            # Check for high-priority threats
            high_threats = [t for t in self.threats if t.get('level') == 'high']
            if high_threats:
                self.logger.warning(f"High-priority threats detected: {len(high_threats)}")
            
            # Check for high-confidence anomalies
            high_anomalies = [a for a in self.anomalies if a.get('confidence', 0) > 0.8]
            if high_anomalies:
                self.logger.warning(f"High-confidence anomalies detected: {len(high_anomalies)}")
                
        except Exception as e:
            self.logger.error(f"Error generating alerts: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the analyzer."""
        return {
            'running': self.running,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'packets_processed': self.packets_processed,
            'bytes_processed': self.bytes_processed,
            'threats_detected': len(self.threats),
            'anomalies_detected': len(self.anomalies)
        }
    
    def generate_report(self, output_path: str = None) -> str:
        """Generate analysis report."""
        try:
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"security_report_{timestamp}.html"
            
            # Prepare report data
            report_data = {
                'threats': self.threats,
                'anomalies': self.anomalies,
                'statistics': self.statistics,
                'start_time': self.start_time,
                'end_time': self.end_time or datetime.now(),
                'config': self.config
            }
            
            # Generate report
            report_content = self.report_generator.generate_comprehensive_report(
                report_data, format='html'
            )
            
            # Save report
            self.report_generator.save_report(report_content, output_path)
            
            self.logger.info(f"Report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return ""
    
    def export_data(self, output_path: str) -> bool:
        """Export analysis data."""
        try:
            import json
            
            data = {
                'threats': self.threats,
                'anomalies': self.anomalies,
                'statistics': self.statistics,
                'status': self.get_status(),
                'export_time': datetime.now().isoformat()
            }
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            self.logger.info(f"Data exported: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
            return False
    
    def reset(self):
        """Reset the analyzer."""
        self.stop_monitoring()
        
        # Reset components
        self.packet_capture.reset()
        self.packet_analyzer.reset()
        self.anomaly_detector.reset()
        self.threat_detector.reset()
        self.statistical_analyzer.reset()
        self.report_generator.reset()
        
        # Reset state
        self.start_time = None
        self.end_time = None
        self.packets_processed = 0
        self.bytes_processed = 0
        self.threats = []
        self.anomalies = []
        self.statistics = {}
        
        self.logger.info("Network analyzer reset")


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Security Analyzer")
    parser.add_argument("-i", "--interface", default="auto", help="Network interface")
    parser.add_argument("-f", "--filter", default="", help="BPF filter")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Capture timeout (seconds)")
    parser.add_argument("-m", "--max-packets", type=int, default=0, help="Maximum packets to capture")
    parser.add_argument("-o", "--output", default="", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Create configuration
    config = AnalysisConfig(
        interface=args.interface,
        filter=args.filter,
        timeout=args.timeout,
        max_packets=args.max_packets,
        verbose=args.verbose,
        output_file=args.output
    )
    
    # Create and run analyzer
    analyzer = NetworkAnalyzer()
    
    if not analyzer.initialize(config):
        print("Failed to initialize analyzer")
        return 1
    
    try:
        if not analyzer.start_monitoring():
            print("Failed to start monitoring")
            return 1
        
        print(f"Monitoring started on interface: {config.interface}")
        print("Press Ctrl+C to stop...")
        
        # Wait for completion or interruption
        while analyzer.running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
    finally:
        analyzer.stop_monitoring()
        
        # Generate report
        if args.output:
            report_path = analyzer.generate_report(args.output)
            print(f"Report saved: {report_path}")
        
        # Display summary
        status = analyzer.get_status()
        print(f"\nSummary:")
        print(f"  Packets processed: {status['packets_processed']:,}")
        print(f"  Bytes processed: {status['bytes_processed']:,}")
        print(f"  Threats detected: {status['threats_detected']}")
        print(f"  Anomalies detected: {status['anomalies_detected']}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())


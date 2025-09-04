#!/usr/bin/env python3
"""
Report Generator Module - Network Security Analyzer
Spring 2024 Security Software Development

Generates comprehensive security reports in multiple formats.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class ReportSection:
    """Represents a section in a security report."""
    title: str
    content: str
    level: int = 1
    subsections: List['ReportSection'] = None


class ReportGenerator:
    """
    Comprehensive security report generation.
    
    Generates detailed security reports in multiple formats including
    HTML, JSON, XML, and plain text.
    """
    
    def __init__(self):
        """Initialize the report generator."""
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.default_format = "html"
        self.include_timestamps = True
        self.include_charts = True
        self.include_recommendations = True
        
        # Report templates
        self.html_template = self._get_html_template()
        self.text_template = self._get_text_template()
        
        # Report metadata
        self.report_metadata = {
            'title': 'Network Security Analysis Report',
            'version': '1.0.0',
            'generator': 'Network Security Analyzer',
            'timestamp': datetime.now().isoformat()
        }
    
    def initialize(self, config) -> None:
        """Initialize the report generator with configuration."""
        self.default_format = getattr(config, 'report_format', 'html')
        self.include_timestamps = getattr(config, 'include_timestamps', True)
        self.include_charts = getattr(config, 'include_charts', True)
        self.include_recommendations = getattr(config, 'include_recommendations', True)
        
        self.logger.info("Report generator initialized")
    
    def generate_comprehensive_report(self, data: Dict[str, Any], format: str = None) -> str:
        """Generate a comprehensive security report."""
        try:
            if format is None:
                format = self.default_format
            
            # Prepare report data
            report_data = self._prepare_report_data(data)
            
            # Generate report based on format
            if format.lower() == "html":
                return self._generate_html_report(report_data)
            elif format.lower() == "json":
                return self._generate_json_report(report_data)
            elif format.lower() == "xml":
                return self._generate_xml_report(report_data)
            elif format.lower() == "txt":
                return self._generate_text_report(report_data)
            else:
                self.logger.error(f"Unsupported report format: {format}")
                return ""
                
        except Exception as e:
            self.logger.error(f"Error generating comprehensive report: {e}")
            return ""
    
    def generate_threat_report(self, threats: List[Dict[str, Any]], format: str = None) -> str:
        """Generate a threat-specific report."""
        try:
            if format is None:
                format = self.default_format
            
            # Prepare threat report data
            report_data = {
                'report_type': 'Threat Report',
                'threats': threats,
                'threat_summary': self._generate_threat_summary(threats),
                'risk_assessment': self._assess_risk_level(threats),
                'recommendations': self._generate_threat_recommendations(threats)
            }
            
            # Generate report based on format
            if format.lower() == "html":
                return self._generate_html_report(report_data)
            elif format.lower() == "json":
                return self._generate_json_report(report_data)
            elif format.lower() == "xml":
                return self._generate_xml_report(report_data)
            elif format.lower() == "txt":
                return self._generate_text_report(report_data)
            else:
                self.logger.error(f"Unsupported report format: {format}")
                return ""
                
        except Exception as e:
            self.logger.error(f"Error generating threat report: {e}")
            return ""
    
    def generate_anomaly_report(self, anomalies: List[Dict[str, Any]], format: str = None) -> str:
        """Generate an anomaly-specific report."""
        try:
            if format is None:
                format = self.default_format
            
            # Prepare anomaly report data
            report_data = {
                'report_type': 'Anomaly Report',
                'anomalies': anomalies,
                'anomaly_summary': self._generate_anomaly_summary(anomalies),
                'pattern_analysis': self._analyze_anomaly_patterns(anomalies),
                'recommendations': self._generate_anomaly_recommendations(anomalies)
            }
            
            # Generate report based on format
            if format.lower() == "html":
                return self._generate_html_report(report_data)
            elif format.lower() == "json":
                return self._generate_json_report(report_data)
            elif format.lower() == "xml":
                return self._generate_xml_report(report_data)
            elif format.lower() == "txt":
                return self._generate_text_report(report_data)
            else:
                self.logger.error(f"Unsupported report format: {format}")
                return ""
                
        except Exception as e:
            self.logger.error(f"Error generating anomaly report: {e}")
            return ""
    
    def generate_statistical_report(self, statistics: Dict[str, Any], format: str = None) -> str:
        """Generate a statistical report."""
        try:
            if format is None:
                format = self.default_format
            
            # Prepare statistical report data
            report_data = {
                'report_type': 'Statistical Report',
                'statistics': statistics,
                'statistical_summary': self._generate_statistical_summary(statistics),
                'trend_analysis': self._analyze_trends(statistics),
                'insights': self._generate_statistical_insights(statistics)
            }
            
            # Generate report based on format
            if format.lower() == "html":
                return self._generate_html_report(report_data)
            elif format.lower() == "json":
                return self._generate_json_report(report_data)
            elif format.lower() == "xml":
                return self._generate_xml_report(report_data)
            elif format.lower() == "txt":
                return self._generate_text_report(report_data)
            else:
                self.logger.error(f"Unsupported report format: {format}")
                return ""
                
        except Exception as e:
            self.logger.error(f"Error generating statistical report: {e}")
            return ""
    
    def _prepare_report_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for report generation."""
        try:
            report_data = {
                'report_type': 'Comprehensive Security Report',
                'metadata': self.report_metadata.copy(),
                'executive_summary': self._generate_executive_summary(data),
                'detailed_analysis': self._generate_detailed_analysis(data),
                'threat_analysis': self._analyze_threats(data),
                'anomaly_analysis': self._analyze_anomalies(data),
                'statistical_analysis': self._analyze_statistics(data),
                'risk_assessment': self._assess_overall_risk(data),
                'recommendations': self._generate_recommendations(data),
                'appendix': self._generate_appendix(data)
            }
            
            # Update timestamp
            report_data['metadata']['timestamp'] = datetime.now().isoformat()
            
            return report_data
            
        except Exception as e:
            self.logger.error(f"Error preparing report data: {e}")
            return {}
    
    def _generate_executive_summary(self, data: Dict[str, Any]) -> str:
        """Generate executive summary."""
        try:
            summary = []
            summary.append("EXECUTIVE SUMMARY")
            summary.append("=" * 50)
            summary.append("")
            
            # Add key findings
            if 'threats' in data and data['threats']:
                threat_count = len(data['threats'])
                high_threats = len([t for t in data['threats'] if t.get('level') == 'high'])
                summary.append(f"Key Findings:")
                summary.append(f"- {threat_count} security threats detected")
                summary.append(f"- {high_threats} high-severity threats identified")
                summary.append("")
            
            if 'anomalies' in data and data['anomalies']:
                anomaly_count = len(data['anomalies'])
                summary.append(f"- {anomaly_count} network anomalies detected")
                summary.append("")
            
            if 'statistics' in data:
                stats = data['statistics']
                if 'total_packets' in stats:
                    summary.append(f"Network Activity:")
                    summary.append(f"- {stats['total_packets']:,} packets analyzed")
                    if 'total_bytes' in stats:
                        summary.append(f"- {stats['total_bytes']:,} bytes processed")
                    summary.append("")
            
            summary.append("This report provides a comprehensive analysis of network security")
            summary.append("threats, anomalies, and statistical patterns identified during")
            summary.append("network monitoring and analysis.")
            
            return "\n".join(summary)
            
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {e}")
            return "Error generating executive summary"
    
    def _generate_detailed_analysis(self, data: Dict[str, Any]) -> str:
        """Generate detailed analysis section."""
        try:
            analysis = []
            analysis.append("DETAILED ANALYSIS")
            analysis.append("=" * 50)
            analysis.append("")
            
            # Add analysis sections
            if 'threats' in data and data['threats']:
                analysis.append("1. THREAT ANALYSIS")
                analysis.append("-" * 20)
                for threat in data['threats'][:5]:  # Show first 5 threats
                    analysis.append(f"Threat: {threat.get('type', 'Unknown')}")
                    analysis.append(f"Level: {threat.get('level', 'Unknown')}")
                    analysis.append(f"Description: {threat.get('description', 'No description')}")
                    analysis.append("")
                analysis.append("")
            
            if 'anomalies' in data and data['anomalies']:
                analysis.append("2. ANOMALY ANALYSIS")
                analysis.append("-" * 20)
                for anomaly in data['anomalies'][:5]:  # Show first 5 anomalies
                    analysis.append(f"Type: {anomaly.get('type', 'Unknown')}")
                    analysis.append(f"Confidence: {anomaly.get('confidence', 0.0):.2f}")
                    analysis.append(f"Description: {anomaly.get('description', 'No description')}")
                    analysis.append("")
                analysis.append("")
            
            if 'statistics' in data:
                analysis.append("3. STATISTICAL ANALYSIS")
                analysis.append("-" * 20)
                stats = data['statistics']
                if 'protocol_breakdown' in stats:
                    analysis.append("Protocol Breakdown:")
                    for protocol, count in list(stats['protocol_breakdown'].items())[:5]:
                        analysis.append(f"  {protocol}: {count:,} packets")
                analysis.append("")
            
            return "\n".join(analysis)
            
        except Exception as e:
            self.logger.error(f"Error generating detailed analysis: {e}")
            return "Error generating detailed analysis"
    
    def _analyze_threats(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threats for reporting."""
        try:
            threats = data.get('threats', [])
            if not threats:
                return {'threat_count': 0, 'risk_level': 'low'}
            
            # Count threats by level
            threat_counts = {'high': 0, 'medium': 0, 'low': 0}
            for threat in threats:
                level = threat.get('level', 'medium')
                threat_counts[level] += 1
            
            # Determine overall risk level
            if threat_counts['high'] > 0:
                risk_level = 'high'
            elif threat_counts['medium'] > 0:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            return {
                'threat_count': len(threats),
                'threat_counts': threat_counts,
                'risk_level': risk_level,
                'top_threats': threats[:5]
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing threats: {e}")
            return {'threat_count': 0, 'risk_level': 'low'}
    
    def _analyze_anomalies(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze anomalies for reporting."""
        try:
            anomalies = data.get('anomalies', [])
            if not anomalies:
                return {'anomaly_count': 0, 'severity': 'low'}
            
            # Count anomalies by type
            anomaly_types = {}
            for anomaly in anomalies:
                anomaly_type = anomaly.get('type', 'Unknown')
                anomaly_types[anomaly_type] = anomaly_types.get(anomaly_type, 0) + 1
            
            # Calculate average confidence
            confidences = [anomaly.get('confidence', 0.0) for anomaly in anomalies]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
            
            # Determine severity
            if avg_confidence > 0.8:
                severity = 'high'
            elif avg_confidence > 0.5:
                severity = 'medium'
            else:
                severity = 'low'
            
            return {
                'anomaly_count': len(anomalies),
                'anomaly_types': anomaly_types,
                'avg_confidence': avg_confidence,
                'severity': severity,
                'top_anomalies': anomalies[:5]
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing anomalies: {e}")
            return {'anomaly_count': 0, 'severity': 'low'}
    
    def _analyze_statistics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze statistics for reporting."""
        try:
            stats = data.get('statistics', {})
            if not stats:
                return {'data_available': False}
            
            analysis = {
                'data_available': True,
                'total_packets': stats.get('total_packets', 0),
                'total_bytes': stats.get('total_bytes', 0),
                'protocols': stats.get('protocol_breakdown', {}),
                'top_ips': stats.get('ip_frequencies', {}),
                'top_ports': stats.get('port_frequencies', {})
            }
            
            # Calculate rates if time information is available
            if 'start_time' in stats and stats['start_time']:
                try:
                    start_time = datetime.fromisoformat(stats['start_time'])
                    elapsed_time = (datetime.now() - start_time).total_seconds()
                    if elapsed_time > 0:
                        analysis['packets_per_second'] = stats.get('total_packets', 0) / elapsed_time
                        analysis['bytes_per_second'] = stats.get('total_bytes', 0) / elapsed_time
                except:
                    pass
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing statistics: {e}")
            return {'data_available': False}
    
    def _assess_overall_risk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk level."""
        try:
            threat_analysis = self._analyze_threats(data)
            anomaly_analysis = self._analyze_anomalies(data)
            
            # Determine overall risk level
            threat_risk = threat_analysis.get('risk_level', 'low')
            anomaly_severity = anomaly_analysis.get('severity', 'low')
            
            # Risk mapping
            risk_mapping = {'low': 1, 'medium': 2, 'high': 3}
            threat_score = risk_mapping.get(threat_risk, 1)
            anomaly_score = risk_mapping.get(anomaly_severity, 1)
            
            overall_score = max(threat_score, anomaly_score)
            if overall_score == 3:
                overall_risk = 'high'
            elif overall_score == 2:
                overall_risk = 'medium'
            else:
                overall_risk = 'low'
            
            return {
                'overall_risk': overall_risk,
                'threat_risk': threat_risk,
                'anomaly_severity': anomaly_severity,
                'risk_factors': self._identify_risk_factors(data)
            }
            
        except Exception as e:
            self.logger.error(f"Error assessing overall risk: {e}")
            return {'overall_risk': 'unknown'}
    
    def _identify_risk_factors(self, data: Dict[str, Any]) -> List[str]:
        """Identify key risk factors."""
        try:
            risk_factors = []
            
            # Check for high-severity threats
            threats = data.get('threats', [])
            high_threats = [t for t in threats if t.get('level') == 'high']
            if high_threats:
                risk_factors.append(f"{len(high_threats)} high-severity threats detected")
            
            # Check for high-confidence anomalies
            anomalies = data.get('anomalies', [])
            high_confidence_anomalies = [a for a in anomalies if a.get('confidence', 0) > 0.8]
            if high_confidence_anomalies:
                risk_factors.append(f"{len(high_confidence_anomalies)} high-confidence anomalies")
            
            # Check for unusual traffic patterns
            stats = data.get('statistics', {})
            if stats.get('total_packets', 0) > 10000:
                risk_factors.append("High volume of network traffic")
            
            return risk_factors
            
        except Exception as e:
            self.logger.error(f"Error identifying risk factors: {e}")
            return []
    
    def _generate_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Generate security recommendations."""
        try:
            recommendations = []
            
            # Threat-based recommendations
            threat_analysis = self._analyze_threats(data)
            if threat_analysis['risk_level'] == 'high':
                recommendations.append("Immediate action required: Investigate and mitigate high-severity threats")
                recommendations.append("Implement additional security controls and monitoring")
            
            # Anomaly-based recommendations
            anomaly_analysis = self._analyze_anomalies(data)
            if anomaly_analysis['severity'] == 'high':
                recommendations.append("Review and investigate high-confidence anomalies")
                recommendations.append("Consider adjusting anomaly detection thresholds")
            
            # General recommendations
            recommendations.append("Implement regular security assessments and penetration testing")
            recommendations.append("Ensure security monitoring and alerting systems are properly configured")
            recommendations.append("Maintain up-to-date security policies and procedures")
            recommendations.append("Provide regular security awareness training to staff")
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            return ["Error generating recommendations"]
    
    def _generate_appendix(self, data: Dict[str, Any]) -> str:
        """Generate report appendix."""
        try:
            appendix = []
            appendix.append("APPENDIX")
            appendix.append("=" * 50)
            appendix.append("")
            
            # Add technical details
            appendix.append("Technical Details:")
            appendix.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            appendix.append(f"Data source: Network Security Analyzer")
            appendix.append("")
            
            # Add data summary
            if 'statistics' in data:
                stats = data['statistics']
                appendix.append("Data Summary:")
                appendix.append(f"Total packets: {stats.get('total_packets', 0):,}")
                appendix.append(f"Total bytes: {stats.get('total_bytes', 0):,}")
                appendix.append("")
            
            return "\n".join(appendix)
            
        except Exception as e:
            self.logger.error(f"Error generating appendix: {e}")
            return "Error generating appendix"
    
    def _generate_threat_summary(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate threat summary for threat reports."""
        try:
            if not threats:
                return {'count': 0, 'levels': {}, 'types': {}}
            
            # Count by level and type
            levels = {}
            types = {}
            
            for threat in threats:
                level = threat.get('level', 'unknown')
                threat_type = threat.get('type', 'unknown')
                
                levels[level] = levels.get(level, 0) + 1
                types[threat_type] = types.get(threat_type, 0) + 1
            
            return {
                'count': len(threats),
                'levels': levels,
                'types': types,
                'high_priority': [t for t in threats if t.get('level') == 'high']
            }
            
        except Exception as e:
            self.logger.error(f"Error generating threat summary: {e}")
            return {'count': 0, 'levels': {}, 'types': {}}
    
    def _assess_risk_level(self, threats: List[Dict[str, Any]]) -> str:
        """Assess risk level based on threats."""
        try:
            if not threats:
                return 'low'
            
            high_threats = len([t for t in threats if t.get('level') == 'high'])
            if high_threats > 0:
                return 'high'
            elif len(threats) > 5:
                return 'medium'
            else:
                return 'low'
                
        except Exception as e:
            self.logger.error(f"Error assessing risk level: {e}")
            return 'unknown'
    
    def _generate_threat_recommendations(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on threats."""
        try:
            recommendations = []
            
            # Analyze threat types
            threat_types = [t.get('type') for t in threats]
            
            if 'DDoS_ATTACK' in threat_types:
                recommendations.append("Implement DDoS protection and mitigation strategies")
                recommendations.append("Configure rate limiting and traffic filtering")
            
            if 'PORT_SCAN' in threat_types:
                recommendations.append("Implement intrusion detection and prevention systems")
                recommendations.append("Configure firewall rules to block scanning attempts")
            
            if 'MALWARE_TRAFFIC' in threat_types:
                recommendations.append("Deploy advanced malware detection and prevention")
                recommendations.append("Implement network segmentation and access controls")
            
            # General recommendations
            recommendations.append("Regular security assessments and penetration testing")
            recommendations.append("Implement comprehensive logging and monitoring")
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating threat recommendations: {e}")
            return ["Error generating recommendations"]
    
    def _generate_anomaly_summary(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate anomaly summary for anomaly reports."""
        try:
            if not anomalies:
                return {'count': 0, 'types': {}, 'avg_confidence': 0.0}
            
            # Count by type
            types = {}
            confidences = []
            
            for anomaly in anomalies:
                anomaly_type = anomaly.get('type', 'unknown')
                types[anomaly_type] = types.get(anomaly_type, 0) + 1
                
                confidence = anomaly.get('confidence', 0.0)
                confidences.append(confidence)
            
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
            
            return {
                'count': len(anomalies),
                'types': types,
                'avg_confidence': avg_confidence,
                'high_confidence': [a for a in anomalies if a.get('confidence', 0) > 0.8]
            }
            
        except Exception as e:
            self.logger.error(f"Error generating anomaly summary: {e}")
            return {'count': 0, 'types': {}, 'avg_confidence': 0.0}
    
    def _analyze_anomaly_patterns(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns in anomalies."""
        try:
            if not anomalies:
                return {'patterns': [], 'trends': []}
            
            # This is a placeholder for pattern analysis
            # Could implement more sophisticated pattern recognition
            return {
                'patterns': [],
                'trends': []
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing anomaly patterns: {e}")
            return {'patterns': [], 'trends': []}
    
    def _generate_anomaly_recommendations(self, anomalies: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on anomalies."""
        try:
            recommendations = []
            
            # Analyze anomaly types
            anomaly_types = [a.get('type') for a in anomalies]
            
            if 'VOLUME_SPIKE' in anomaly_types:
                recommendations.append("Investigate unusual traffic volume patterns")
                recommendations.append("Implement traffic monitoring and alerting")
            
            if 'FREQUENCY_ANOMALY' in anomaly_types:
                recommendations.append("Review traffic frequency patterns")
                recommendations.append("Adjust anomaly detection thresholds if needed")
            
            # General recommendations
            recommendations.append("Regular review of anomaly detection rules")
            recommendations.append("Implement baseline traffic analysis")
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating anomaly recommendations: {e}")
            return ["Error generating recommendations"]
    
    def _generate_statistical_summary(self, statistics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate statistical summary for statistical reports."""
        try:
            if not statistics:
                return {'data_available': False}
            
            return {
                'data_available': True,
                'total_packets': statistics.get('total_packets', 0),
                'total_bytes': statistics.get('total_bytes', 0),
                'protocols': statistics.get('protocol_breakdown', {}),
                'top_ips': statistics.get('ip_frequencies', {}),
                'top_ports': statistics.get('port_frequencies', {})
            }
            
        except Exception as e:
            self.logger.error(f"Error generating statistical summary: {e}")
            return {'data_available': False}
    
    def _analyze_trends(self, statistics: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze trends in statistics."""
        try:
            # This is a placeholder for trend analysis
            # Could implement time series analysis and trend detection
            return {
                'trends': [],
                'patterns': []
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing trends: {e}")
            return {'trends': [], 'patterns': []}
    
    def _generate_statistical_insights(self, statistics: Dict[str, Any]) -> List[str]:
        """Generate insights from statistics."""
        try:
            insights = []
            
            if not statistics:
                return ["No statistical data available"]
            
            # Generate basic insights
            total_packets = statistics.get('total_packets', 0)
            if total_packets > 10000:
                insights.append("High volume of network traffic detected")
            
            protocols = statistics.get('protocol_breakdown', {})
            if protocols:
                top_protocol = max(protocols.items(), key=lambda x: x[1])
                insights.append(f"Primary protocol: {top_protocol[0]} ({top_protocol[1]:,} packets)")
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Error generating statistical insights: {e}")
            return ["Error generating insights"]
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report."""
        try:
            # Use the HTML template
            html_content = self.html_template
            
            # Replace placeholders with actual data
            html_content = html_content.replace('{{TITLE}}', report_data.get('report_type', 'Security Report'))
            html_content = html_content.replace('{{TIMESTAMP}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            # Add executive summary
            if 'executive_summary' in report_data:
                html_content = html_content.replace('{{EXECUTIVE_SUMMARY}}', 
                                                 report_data['executive_summary'].replace('\n', '<br>'))
            
            # Add detailed analysis
            if 'detailed_analysis' in report_data:
                html_content = html_content.replace('{{DETAILED_ANALYSIS}}', 
                                                 report_data['detailed_analysis'].replace('\n', '<br>'))
            
            return html_content
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            return f"<html><body><h1>Error generating report: {e}</h1></body></html>"
    
    def _generate_json_report(self, report_data: Dict[str, Any]) -> str:
        """Generate JSON report."""
        try:
            return json.dumps(report_data, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")
            return json.dumps({'error': str(e)})
    
    def _generate_xml_report(self, report_data: Dict[str, Any]) -> str:
        """Generate XML report."""
        try:
            # Simple XML generation
            xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
            xml_lines.append('<security_report>')
            
            # Add metadata
            xml_lines.append('  <metadata>')
            xml_lines.append(f'    <title>{report_data.get("report_type", "Security Report")}</title>')
            xml_lines.append(f'    <timestamp>{datetime.now().isoformat()}</timestamp>')
            xml_lines.append('  </metadata>')
            
            # Add content sections
            if 'executive_summary' in report_data:
                xml_lines.append('  <executive_summary>')
                xml_lines.append(f'    {report_data["executive_summary"]}')
                xml_lines.append('  </executive_summary>')
            
            xml_lines.append('</security_report>')
            
            return '\n'.join(xml_lines)
            
        except Exception as e:
            self.logger.error(f"Error generating XML report: {e}")
            return f'<?xml version="1.0" encoding="UTF-8"?><error>{e}</error>'
    
    def _generate_text_report(self, report_data: Dict[str, Any]) -> str:
        """Generate plain text report."""
        try:
            # Use the text template
            text_content = self.text_template
            
            # Replace placeholders with actual data
            text_content = text_content.replace('{{TITLE}}', report_data.get('report_type', 'Security Report'))
            text_content = text_content.replace('{{TIMESTAMP}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            # Add executive summary
            if 'executive_summary' in report_data:
                text_content = text_content.replace('{{EXECUTIVE_SUMMARY}}', report_data['executive_summary'])
            
            # Add detailed analysis
            if 'detailed_analysis' in report_data:
                text_content = text_content.replace('{{DETAILED_ANALYSIS}}', report_data['detailed_analysis'])
            
            return text_content
            
        except Exception as e:
            self.logger.error(f"Error generating text report: {e}")
            return f"Error generating report: {e}"
    
    def _get_html_template(self) -> str:
        """Get HTML template for reports."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        h3 { color: #7f8c8d; }
        .timestamp { color: #95a5a6; font-style: italic; margin-bottom: 20px; }
        .section { margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 4px solid #3498db; }
        .summary { background-color: #e8f5e8; border-left-color: #27ae60; }
        .analysis { background-color: #fff3cd; border-left-color: #f39c12; }
        .recommendations { background-color: #f8d7da; border-left-color: #e74c3c; }
    </style>
</head>
<body>
    <h1>{{TITLE}}</h1>
    <div class="timestamp">Generated: {{TIMESTAMP}}</div>
    
    <div class="section summary">
        <h2>Executive Summary</h2>
        {{EXECUTIVE_SUMMARY}}
    </div>
    
    <div class="section analysis">
        <h2>Detailed Analysis</h2>
        {{DETAILED_ANALYSIS}}
    </div>
    
    <div class="section recommendations">
        <h2>Recommendations</h2>
        <p>Based on the analysis, the following recommendations are provided:</p>
        <ul>
            <li>Implement comprehensive security monitoring</li>
            <li>Regular security assessments and testing</li>
            <li>Update security policies and procedures</li>
            <li>Provide security awareness training</li>
        </ul>
    </div>
</body>
</html>"""
    
    def _get_text_template(self) -> str:
        """Get text template for reports."""
        return """{{TITLE}}
Generated: {{TIMESTAMP}}

EXECUTIVE SUMMARY
================
{{EXECUTIVE_SUMMARY}}

DETAILED ANALYSIS
=================
{{DETAILED_ANALYSIS}}

RECOMMENDATIONS
===============
Based on the analysis, the following recommendations are provided:

1. Implement comprehensive security monitoring
2. Regular security assessments and testing
3. Update security policies and procedures
4. Provide security awareness training
5. Implement incident response procedures

---
Report generated by Network Security Analyzer
For more information, contact your security team"""
    
    def save_report(self, report_content: str, filename: str, format: str = None) -> bool:
        """Save report to file."""
        try:
            if format is None:
                format = self.default_format
            
            # Ensure proper file extension
            if not filename.endswith(f'.{format}'):
                filename = f"{filename}.{format}"
            
            # Write report to file
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            self.logger.info(f"Report saved to: {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")
            return False
    
    def reset(self) -> None:
        """Reset the report generator."""
        self.logger.info("Report generator reset")


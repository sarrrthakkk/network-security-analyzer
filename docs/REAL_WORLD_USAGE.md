# Real-World Usage Guide - Network Security Analyzer

A comprehensive guide for using the Network Security Analyzer in real-world scenarios with enhanced HTTP threat detection capabilities.

## 🎯 Use Cases

### 1. Web Application Security Monitoring
Monitor web applications for common attacks and vulnerabilities.

### 2. Network Intrusion Detection
Detect unauthorized access attempts and malicious activities.

### 3. DDoS Attack Detection
Identify and respond to distributed denial-of-service attacks.

### 4. Port Scanning Detection
Detect network reconnaissance activities.

### 5. Data Exfiltration Monitoring
Monitor for unusual data transfer patterns.

## 🚀 Quick Start Scenarios

### Scenario 1: Basic Network Monitoring
```bash
cd python
sudo python3 real_world_examples.py --example 1
```
**What it does:**
- Monitors all network traffic
- Detects basic threats and anomalies
- Provides real-time alerts
- Generates comprehensive reports

### Scenario 2: DDoS Attack Detection
```bash
cd python
sudo python3 real_world_examples.py --example 2
```
**What it does:**
- Monitors for high-volume traffic spikes
- Detects UDP flood attacks
- Identifies SYN flood attacks
- Provides attack source information

### Scenario 3: Port Scanning Detection
```bash
cd python
sudo python3 real_world_examples.py --example 3
```
**What it does:**
- Detects rapid port scanning
- Identifies scanning tools
- Monitors connection patterns
- Alerts on suspicious activities

### Scenario 4: Continuous Monitoring
```bash
cd python
sudo python3 real_world_examples.py --example 4
```
**What it does:**
- Runs continuous monitoring
- Generates periodic reports
- Maintains historical data
- Provides trend analysis

### Scenario 5: Custom Filtering
```bash
cd python
sudo python3 real_world_examples.py --example 5
```
**What it does:**
- Filters specific traffic types
- Focuses on web traffic
- Detects web-specific threats
- Provides targeted analysis

## 🔍 HTTP Threat Detection in Real-World

### Web Application Security

#### 1. E-commerce Site Monitoring
```python
from src.network_analyzer import NetworkAnalyzer, AnalysisConfig

# Monitor e-commerce site
config = AnalysisConfig(
    interface="en0",
    filter="tcp port 80 or tcp port 443",
    timeout=3600,  # 1 hour
    http_detection=True,
    anomaly_threshold=2.0,
    threat_threshold=0.8,
    verbose=True
)

analyzer = NetworkAnalyzer()
analyzer.initialize(config)
analyzer.start_monitoring()
```

**Detects:**
- SQL injection attempts on login forms
- XSS attacks in search queries
- Directory traversal attempts
- Scanning tool activities

#### 2. API Security Monitoring
```python
# Monitor API endpoints
config = AnalysisConfig(
    interface="en0",
    filter="tcp port 443",  # HTTPS only
    timeout=0,
    http_detection=True,
    anomaly_threshold=1.5,
    threat_threshold=0.7
)
```

**Detects:**
- Command injection in API calls
- Malicious payloads in requests
- Unusual request patterns
- Authentication bypass attempts

#### 3. Content Management System Monitoring
```python
# Monitor CMS applications
config = AnalysisConfig(
    interface="en0",
    filter="tcp port 80 or tcp port 443",
    timeout=0,
    http_detection=True,
    anomaly_threshold=2.0,
    threat_threshold=0.8
)
```

**Detects:**
- WordPress admin attacks
- PHPMyAdmin access attempts
- Configuration file access
- Plugin vulnerability exploitation

### Real-World Attack Examples

#### Example 1: SQL Injection Attack
```
GET /login.php?id=1' OR '1'='1'--
```
**Detection:**
- Pattern: `' OR '1'='1`
- Type: SQL_INJECTION
- Level: high
- Confidence: 0.9

#### Example 2: XSS Attack
```
GET /search?q=<script>alert('XSS')</script>
```
**Detection:**
- Pattern: `<script>`
- Type: XSS_ATTACK
- Level: high
- Confidence: 0.9

#### Example 3: Command Injection
```
GET /admin?cmd=; cat /etc/passwd
```
**Detection:**
- Pattern: `; cat`
- Type: COMMAND_INJECTION
- Level: high
- Confidence: 0.9

#### Example 4: Directory Traversal
```
GET /files/../../../etc/passwd
```
**Detection:**
- Pattern: `../`
- Type: DIRECTORY_TRAVERSAL
- Level: medium
- Confidence: 0.8

#### Example 5: Scanning Tool Detection
```
User-Agent: sqlmap/1.0
```
**Detection:**
- Pattern: `sqlmap`
- Type: SCANNING_TOOL
- Level: medium
- Confidence: 0.7

## 🏢 Enterprise Integration

### 1. Security Operations Center (SOC)

#### Real-time Monitoring Dashboard
```python
import time
from src.network_analyzer import NetworkAnalyzer, AnalysisConfig

# SOC monitoring configuration
config = AnalysisConfig(
    interface="en0",
    filter="tcp or udp",
    timeout=0,
    http_detection=True,
    anomaly_threshold=1.5,
    threat_threshold=0.7,
    verbose=True
)

analyzer = NetworkAnalyzer()
analyzer.initialize(config)
analyzer.start_monitoring()

# Real-time dashboard
while True:
    status = analyzer.get_status()
    threats = analyzer.threats
    anomalies = analyzer.anomalies
    
    # Update dashboard
    update_dashboard(status, threats, anomalies)
    
    # Generate alerts
    if threats:
        send_alert(threats)
    
    time.sleep(30)  # Update every 30 seconds
```

#### Automated Response
```python
def automated_response(threat):
    if threat['type'] == 'DDoS_ATTACK':
        # Block source IP
        block_ip(threat['source_ip'])
        # Send alert to SOC
        send_soc_alert(threat)
        # Update firewall rules
        update_firewall(threat['source_ip'])
    
    elif threat['type'] == 'XSS_ATTACK':
        # Log attack details
        log_attack(threat)
        # Send security alert
        send_security_alert(threat)
        # Update WAF rules
        update_waf_rules(threat)
```

### 2. Incident Response

#### Threat Investigation
```python
def investigate_threat(threat_id):
    # Get threat details
    threat = get_threat_details(threat_id)
    
    # Analyze threat context
    context = analyze_threat_context(threat)
    
    # Generate investigation report
    report = generate_investigation_report(threat, context)
    
    # Update incident tracking
    update_incident_tracking(threat, report)
    
    return report
```

#### Forensics Analysis
```python
def forensic_analysis(threat):
    # Extract packet data
    packets = extract_packets(threat['timestamp'])
    
    # Analyze payload
    payload_analysis = analyze_payload(packets)
    
    # Identify attack vector
    attack_vector = identify_attack_vector(payload_analysis)
    
    # Generate forensic report
    forensic_report = generate_forensic_report(threat, payload_analysis, attack_vector)
    
    return forensic_report
```

### 3. Compliance and Reporting

#### Security Compliance Reports
```python
def generate_compliance_report():
    # Collect security metrics
    metrics = collect_security_metrics()
    
    # Generate compliance report
    report = {
        'timestamp': datetime.now(),
        'total_threats': len(analyzer.threats),
        'threat_types': categorize_threats(analyzer.threats),
        'anomalies': len(analyzer.anomalies),
        'compliance_score': calculate_compliance_score(metrics),
        'recommendations': generate_recommendations(metrics)
    }
    
    return report
```

#### Executive Summary
```python
def generate_executive_summary():
    summary = {
        'period': 'Last 30 days',
        'total_incidents': len(analyzer.threats),
        'critical_threats': count_critical_threats(analyzer.threats),
        'web_attacks': count_web_attacks(analyzer.threats),
        'risk_level': calculate_risk_level(analyzer.threats),
        'trends': analyze_trends(analyzer.threats)
    }
    
    return summary
```

## 🔧 Customization and Integration

### 1. Custom Threat Detection

#### Adding Custom Patterns
```python
from src.threat_detector import ThreatDetector

detector = ThreatDetector()

# Add custom patterns for your organization
detector.http_threat_patterns['custom'] = [
    rb'your_custom_pattern',
    rb'organization_specific_pattern',
    rb'application_specific_pattern'
]
```

#### Custom Alert Rules
```python
def custom_alert_rules(threat):
    # Organization-specific rules
    if threat['source_ip'] in whitelist:
        return False  # Ignore whitelisted IPs
    
    if threat['type'] == 'XSS_ATTACK' and threat['confidence'] > 0.8:
        # High-confidence XSS attack
        send_urgent_alert(threat)
        block_ip(threat['source_ip'])
    
    if threat['type'] == 'SQL_INJECTION':
        # SQL injection attempt
        log_security_event(threat)
        update_security_score(threat)
```

### 2. Integration with Security Tools

#### SIEM Integration
```python
def send_to_siem(threat):
    siem_data = {
        'timestamp': threat['timestamp'],
        'source_ip': threat['source_ip'],
        'dest_ip': threat['dest_ip'],
        'threat_type': threat['type'],
        'confidence': threat['confidence'],
        'evidence': threat['evidence']
    }
    
    # Send to SIEM
    siem_client.send_event(siem_data)
```

#### Firewall Integration
```python
def update_firewall(threat):
    if threat['type'] in ['DDoS_ATTACK', 'PORT_SCAN']:
        # Add IP to firewall block list
        firewall.add_block_rule(threat['source_ip'])
        
        # Log firewall action
        log_firewall_action(threat['source_ip'], 'blocked')
```

#### WAF Integration
```python
def update_waf(threat):
    if threat['type'] == 'XSS_ATTACK':
        # Add XSS pattern to WAF
        waf.add_xss_rule(threat['evidence']['pattern'])
        
        # Log WAF update
        log_waf_update(threat['evidence']['pattern'])
```

### 3. Custom Reporting

#### Custom Report Templates
```python
def generate_custom_report(template_name):
    if template_name == 'executive':
        return generate_executive_report()
    elif template_name == 'technical':
        return generate_technical_report()
    elif template_name == 'compliance':
        return generate_compliance_report()
    else:
        return generate_standard_report()
```

#### Automated Report Distribution
```python
def distribute_reports():
    # Generate reports
    executive_report = generate_executive_report()
    technical_report = generate_technical_report()
    
    # Send to stakeholders
    send_email('executives@company.com', executive_report)
    send_email('security@company.com', technical_report)
    
    # Upload to dashboard
    upload_to_dashboard(executive_report)
    upload_to_dashboard(technical_report)
```

## 📊 Performance Optimization

### 1. High-Volume Environments

#### Load Balancing
```python
# Distribute analysis across multiple instances
def distribute_analysis(traffic_volume):
    if traffic_volume > 10000:  # packets per second
        # Use multiple analyzers
        analyzers = create_analyzer_pool(4)
        distribute_traffic(analyzers)
    else:
        # Use single analyzer
        use_single_analyzer()
```

#### Performance Tuning
```python
# Optimize for high performance
config = AnalysisConfig(
    interface="en0",
    filter="tcp",  # Reduce filter complexity
    timeout=0,
    anomaly_threshold=3.0,  # Less sensitive
    threat_threshold=0.9,   # Less sensitive
    verbose=False,          # Reduce logging
    http_detection=True
)
```

### 2. Resource Management

#### Memory Optimization
```python
def optimize_memory():
    # Clear old data periodically
    if len(analyzer.threats) > 1000:
        analyzer.threats = analyzer.threats[-500:]  # Keep recent threats
    
    # Clear old anomalies
    if len(analyzer.anomalies) > 1000:
        analyzer.anomalies = analyzer.anomalies[-500:]
```

#### CPU Optimization
```python
def optimize_cpu():
    # Use multiprocessing for heavy analysis
    from multiprocessing import Pool
    
    with Pool(4) as pool:
        results = pool.map(analyze_packet_batch, packet_batches)
```

## 🛡️ Security Best Practices

### 1. Authorization and Compliance

#### Legal Requirements
- **Always obtain proper authorization** before monitoring
- **Comply with local laws** and regulations
- **Respect privacy** and data protection requirements
- **Document all monitoring activities**

#### Data Protection
```python
def protect_sensitive_data():
    # Anonymize IP addresses
    anonymize_ips(analyzer.threats)
    
    # Encrypt stored data
    encrypt_data(analyzer.threats)
    
    # Implement data retention
    implement_retention_policy(analyzer.threats)
```

### 2. Network Security

#### Secure Deployment
```python
def secure_deployment():
    # Use dedicated monitoring network
    use_monitoring_network()
    
    # Implement access controls
    implement_access_controls()
    
    # Regular security updates
    schedule_security_updates()
```

#### Monitoring Security
```python
def monitor_security():
    # Self-monitoring
    monitor_analyzer_health()
    
    # Detect tampering
    detect_tampering()
    
    # Alert on security events
    alert_on_security_events()
```

## 📈 Scaling and Growth

### 1. Horizontal Scaling

#### Multiple Analyzers
```python
def deploy_multiple_analyzers():
    # Deploy analyzers on multiple servers
    analyzers = []
    for server in servers:
        analyzer = deploy_analyzer(server)
        analyzers.append(analyzer)
    
    # Load balance traffic
    load_balance_traffic(analyzers)
```

#### Distributed Analysis
```python
def distributed_analysis():
    # Distribute analysis tasks
    tasks = distribute_tasks(analysis_tasks)
    
    # Process in parallel
    results = process_parallel(tasks)
    
    # Aggregate results
    aggregated_results = aggregate_results(results)
```

### 2. Cloud Integration

#### Cloud Deployment
```python
def cloud_deployment():
    # Deploy to cloud
    cloud_analyzer = deploy_to_cloud()
    
    # Configure auto-scaling
    configure_auto_scaling(cloud_analyzer)
    
    # Monitor cloud costs
    monitor_cloud_costs(cloud_analyzer)
```

#### Hybrid Deployment
```python
def hybrid_deployment():
    # On-premises for sensitive data
    on_prem_analyzer = deploy_on_premises()
    
    # Cloud for public data
    cloud_analyzer = deploy_to_cloud()
    
    # Synchronize results
    synchronize_results(on_prem_analyzer, cloud_analyzer)
```

## 📞 Support and Maintenance

### 1. Troubleshooting

#### Common Issues
```python
def troubleshoot_common_issues():
    # Check permissions
    if not has_permissions():
        print("Run with sudo for packet capture")
    
    # Check interface
    if not interface_exists():
        print("Check network interface configuration")
    
    # Check dependencies
    if not dependencies_installed():
        print("Install required dependencies")
```

#### Performance Issues
```python
def troubleshoot_performance():
    # Check CPU usage
    if cpu_usage > 80:
        print("Consider reducing sensitivity or using multiple analyzers")
    
    # Check memory usage
    if memory_usage > 80:
        print("Consider clearing old data or increasing memory")
    
    # Check network bandwidth
    if bandwidth_usage > 80:
        print("Consider filtering traffic or using multiple interfaces")
```

### 2. Maintenance

#### Regular Maintenance
```python
def regular_maintenance():
    # Update threat patterns
    update_threat_patterns()
    
    # Clear old data
    clear_old_data()
    
    # Update software
    update_software()
    
    # Backup configuration
    backup_configuration()
```

#### Monitoring Health
```python
def monitor_health():
    # Check analyzer status
    status = analyzer.get_status()
    
    # Monitor resource usage
    monitor_resources()
    
    # Check for errors
    check_for_errors()
    
    # Generate health report
    generate_health_report()
```

---

**Network Security Analyzer** - Spring 2024 Security Software Development Project

For technical details, see `docs/IMPLEMENTATION_DETAILS.md`.
For basic usage, see `HOW_TO_USE.md`.

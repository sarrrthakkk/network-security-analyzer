# How to Use Network Security Analyzer

A comprehensive guide for using the Network Security Analyzer with enhanced HTTP threat detection capabilities.

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+** or **C++17+**
- **Root/Administrator privileges** (for packet capture)
- **Network interface** with active traffic

### Installation
```bash
# Clone the repository
git clone https://github.com/sarrrthakkk/network-security-analyzer.git
cd network-security-analyzer

# Install Python dependencies
cd python
pip install -r requirements.txt

# Test the installation
python3 demo.py
```

## 📋 Help Commands - Quick Reference

### 🆘 Getting Help
```bash
# Show all available commands and options
python3 src/network_analyzer.py --help

# Show C++ usage guide (interactive menu)
./cpp_usage_guide.sh

# Run demo without root (safe test)
python3 demo.py

# List available network interfaces
python3 -c "from src.utils import NetworkUtils; print(NetworkUtils.get_available_interfaces())"
```

### 🚀 Essential Commands

#### **Python (Recommended)**
```bash
# Basic monitoring (60 seconds, generates report)
sudo python3 src/network_analyzer.py -i en0 -t 60 -o security_report.html -v

# Continuous monitoring (until Ctrl+C)
sudo python3 src/network_analyzer.py -i en0 -t 0 -v

# Monitor specific traffic (HTTP/HTTPS only)
sudo python3 src/network_analyzer.py -i en0 -f "port 80 or port 443" -t 300 -v

# Use pre-built scenarios
sudo python3 real_world_examples.py --example 1  # Basic monitoring
sudo python3 real_world_examples.py --example 2  # DDoS detection
sudo python3 real_world_examples.py --example 3  # Port scan detection
sudo python3 real_world_examples.py --example 4  # Continuous monitoring
sudo python3 real_world_examples.py --example 5  # Custom filtering
```

#### **C++ Alternative**
```bash
# Build and run
cd cpp
make
sudo ./bin/network_analyzer

# Interactive guide with examples
./cpp_usage_guide.sh
```

### 🔧 Troubleshooting Commands

#### **Permission Issues**
```bash
# Always use sudo for packet capture
sudo python3 src/network_analyzer.py -i en0 -t 30

# Check if you have packet capture permissions
sudo python3 -c "import scapy; print('Packet capture available')"
```

#### **Interface Issues**
```bash
# Find your network interface
ifconfig | grep -E "^[a-z]|inet "

# List interfaces programmatically
python3 -c "from src.utils import NetworkUtils; print(NetworkUtils.get_available_interfaces())"

# Common interfaces:
# macOS: en0, en1, en2
# Linux: eth0, wlan0, ens33
# Windows: Ethernet, Wi-Fi
```

#### **Dependency Issues**
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install C++ dependencies (macOS)
brew install libpcap openssl

# Install C++ dependencies (Ubuntu/Debian)
sudo apt-get install libpcap-dev libssl-dev

# Test installation
python3 demo.py
```

### 📊 Output and Reports

#### **View Results**
```bash
# Open generated HTML report
open security_report.html

# View in terminal
cat security_report.html

# Export data as JSON
python3 -c "
from src.network_analyzer import NetworkAnalyzer, AnalysisConfig
analyzer = NetworkAnalyzer()
analyzer.initialize(AnalysisConfig(interface='en0', timeout=10))
analyzer.start_monitoring()
analyzer.export_data('analysis_data.json')
"
```

#### **Monitor in Real-time**
```bash
# Watch live output with timestamps
sudo python3 src/network_analyzer.py -i en0 -t 0 -v | while read line; do echo "$(date): $line"; done

# Save live output to file
sudo python3 src/network_analyzer.py -i en0 -t 0 -v > live_monitor.log 2>&1 &
tail -f live_monitor.log
```

### 🎯 Common Use Cases

#### **Web Application Security**
```bash
# Monitor web traffic for attacks
sudo python3 src/network_analyzer.py -i en0 -f "port 80 or port 443" -t 3600 -o web_security_report.html -v
```

#### **DDoS Detection**
```bash
# Monitor for DDoS attacks
sudo python3 real_world_examples.py --example 2
```

#### **Port Scan Detection**
```bash
# Detect port scanning
sudo python3 real_world_examples.py --example 3
```

#### **Custom Analysis**
```bash
# Monitor specific IP range
sudo python3 src/network_analyzer.py -i en0 -f "net 192.168.1.0/24" -t 300 -v

# Monitor specific protocol
sudo python3 src/network_analyzer.py -i en0 -f "tcp" -t 300 -v
```

### 🔍 Advanced Usage

#### **Programmatic Usage**
```python
from src.network_analyzer import NetworkAnalyzer, AnalysisConfig

# Create configuration
config = AnalysisConfig(
    interface="en0",
    timeout=60,
    filter="tcp port 80 or tcp port 443",
    anomaly_threshold=2.0,
    threat_threshold=0.8,
    verbose=True
)

# Initialize and run
analyzer = NetworkAnalyzer()
analyzer.initialize(config)
analyzer.start_monitoring()

# Get results
status = analyzer.get_status()
print(f"Captured {status['packets_processed']} packets")

# Generate report
analyzer.generate_report("custom_report.html")
```

#### **Batch Processing**
```bash
# Run multiple analysis sessions
for i in {1..5}; do
    echo "Running session $i..."
    sudo python3 src/network_analyzer.py -i en0 -t 60 -o "report_$i.html"
    sleep 10
done
```

### 📚 Additional Resources

#### **Documentation**
```bash
# Read comprehensive usage guide
open docs/REAL_WORLD_USAGE.md

# Read implementation details
open docs/IMPLEMENTATION_DETAILS.md

# Read this file
open docs/HOW_TO_USE.md
```

#### **Examples and Tests**
```bash
# Run all examples
python3 real_world_examples.py --example 1
python3 real_world_examples.py --example 2
python3 real_world_examples.py --example 3
python3 real_world_examples.py --example 4
python3 real_world_examples.py --example 5

# Run build tests
./test_build.sh

# Run C++ examples
./cpp_usage_guide.sh
```

### ⚠️ Important Notes

1. **Always use sudo** for packet capture
2. **Replace en0** with your actual network interface
3. **Check permissions** before running
4. **Monitor disk space** for large captures
5. **Respect privacy** and legal requirements
6. **Use appropriate filters** to reduce noise

### 🆘 Still Need Help?

1. **Check the demo**: `python3 demo.py`
2. **Run tests**: `./test_build.sh`
3. **Read docs**: `docs/REAL_WORLD_USAGE.md`
4. **Try examples**: `python3 real_world_examples.py --example 1`
5. **Use help flag**: `python3 src/network_analyzer.py --help`
## 📋 Basic Usage

### Python Version (Recommended)

#### 1. Basic Demo
```bash
cd python
python3 demo.py
```
This runs a comprehensive demo showing all components and capabilities.

#### 2. Real-world Examples
```bash
# Basic monitoring (requires sudo)
sudo python3 real_world_examples.py --example 1

# DDoS detection
sudo python3 real_world_examples.py --example 2

# Port scan detection
sudo python3 real_world_examples.py --example 3

# Continuous monitoring
sudo python3 real_world_examples.py --example 4

# Custom filtering
sudo python3 real_world_examples.py --example 5
```

#### 3. Programmatic Usage
```python
from src.network_analyzer import NetworkAnalyzer, AnalysisConfig

# Create configuration
config = AnalysisConfig(
    interface="en0",  # Your network interface
    timeout=30,      # Capture for 30 seconds
    filter="tcp",    # Only TCP traffic
    sensitivity="medium"
)

# Initialize analyzer
analyzer = NetworkAnalyzer()
analyzer.initialize(config)

# Start monitoring
analyzer.start_monitoring()

# Get results
results = analyzer.get_status()
print(f"Captured {results['packets_captured']} packets")

# Generate report
analyzer.generate_report("security_report.html")
```

### C++ Version

#### 1. Build and Run
```bash
cd cpp
make
./bin/network_analyzer
```

#### 2. Interactive Guide
```bash
./cpp_usage_guide.sh
```

## 🔍 HTTP Threat Detection

The analyzer includes comprehensive HTTP threat detection capabilities:

### Detected Threats

#### 1. Cross-Site Scripting (XSS)
- **Patterns**: `<script>`, `javascript:`, `onload=`, `onclick=`, `<iframe>`
- **Example**: `GET /search?q=<script>alert('XSS')</script>`

#### 2. SQL Injection
- **Patterns**: `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`
- **Example**: `POST /login?id=1' OR '1'='1'--`

#### 3. Command Injection
- **Patterns**: `cmd.exe`, `powershell`, `; ls`, `; cat`
- **Example**: `GET /admin?cmd=; cat /etc/passwd`

#### 4. Directory Traversal
- **Patterns**: `../`, `..\`, `/etc/passwd`, `c:\windows`
- **Example**: `GET /files/../../../etc/passwd`

#### 5. Scanning Tools
- **Tools**: `sqlmap`, `nikto`, `nmap`, `burp`, `zap`
- **Detection**: User-Agent and payload analysis

### HTTP Analysis Features

#### Header Analysis
```python
# The analyzer extracts and analyzes:
- Host headers
- User-Agent strings
- Content-Type
- Content-Length
- Custom headers
```

#### Path Analysis
```python
# Suspicious paths are flagged:
- /admin
- /login
- /wp-admin
- /phpmyadmin
- /config
- /.env
```

#### Query Parameter Analysis
```python
# Query parameters are analyzed for:
- Injection attempts
- Suspicious patterns
- Malicious payloads
```

## 📊 Advanced Usage

### Custom Configuration

#### AnalysisConfig Options
```python
@dataclass
class AnalysisConfig:
    interface: str = "auto"           # Network interface
    filter: str = ""                  # BPF filter
    timeout: int = 0                  # Capture timeout (0 = infinite)
    verbose: bool = False             # Verbose output
    anomaly_threshold: float = 2.0    # Anomaly detection sensitivity
    threat_threshold: float = 0.8     # Threat detection sensitivity
    enable_ml: bool = True            # Enable machine learning
    http_detection: bool = True        # Enable HTTP threat detection
```

#### Example Configurations

**High Security Mode**
```python
config = AnalysisConfig(
    interface="en0",
    filter="tcp port 80 or tcp port 443",
    timeout=300,
    anomaly_threshold=1.5,  # More sensitive
    threat_threshold=0.7,   # More sensitive
    verbose=True
)
```

**Performance Mode**
```python
config = AnalysisConfig(
    interface="en0",
    filter="tcp",
    timeout=0,
    anomaly_threshold=3.0,  # Less sensitive
    threat_threshold=0.9,   # Less sensitive
    verbose=False
)
```

**HTTP-Only Mode**
```python
config = AnalysisConfig(
    interface="en0",
    filter="tcp port 80 or tcp port 443",
    timeout=60,
    http_detection=True,
    anomaly_threshold=2.0,
    threat_threshold=0.8
)
```

### Custom Threat Detection

#### Adding Custom Patterns
```python
from src.threat_detector import ThreatDetector

detector = ThreatDetector()

# Add custom patterns
detector.http_threat_patterns['custom'] = [
    rb'your_custom_pattern',
    rb'another_pattern'
]
```

#### Custom Alert Handling
```python
def custom_alert_handler(threat):
    if threat['type'] == 'XSS_ATTACK':
        print(f"🚨 XSS Attack from {threat['source_ip']}")
        # Add custom response logic
        block_ip(threat['source_ip'])
```

## 📈 Monitoring and Reporting

### Real-time Monitoring
```python
# Monitor in real-time
analyzer.start_monitoring()

while True:
    status = analyzer.get_status()
    if status['running']:
        threats = analyzer.threats
        anomalies = analyzer.anomalies
        
        if threats:
            print(f"🚨 {len(threats)} threats detected!")
        
        if anomalies:
            print(f"⚠️ {len(anomalies)} anomalies detected!")
    
    time.sleep(5)
```

### Report Generation
```python
# Generate comprehensive report
analyzer.generate_report("security_report.html")

# Export data
analyzer.export_data("analysis_data.json")
```

### Report Types

#### HTML Reports
- **Interactive**: Clickable elements and navigation
- **Comprehensive**: All threats, anomalies, and statistics
- **Visual**: Charts and graphs
- **Exportable**: Can be saved and shared

#### JSON Export
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "total_packets": 15000,
  "threats": [
    {
      "type": "XSS_ATTACK",
      "level": "high",
      "source_ip": "192.168.1.100",
      "confidence": 0.9
    }
  ],
  "anomalies": [
    {
      "type": "VOLUME_SPIKE",
      "confidence": 0.85
    }
  ]
}
```

## 🔧 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Solution: Run with sudo
sudo python3 real_world_examples.py --example 1
```

#### No Network Interface Found
```bash
# List available interfaces
python3 -c "from src.utils import NetworkUtils; print(NetworkUtils.get_available_interfaces())"
```

#### No HTTP Traffic Detected
```bash
# Check if filtering HTTP traffic
config = AnalysisConfig(
    filter="tcp port 80 or tcp port 443"
)
```

#### High CPU Usage
```bash
# Reduce sensitivity
config = AnalysisConfig(
    anomaly_threshold=3.0,
    threat_threshold=0.9,
    verbose=False
)
```

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Run with debug output
analyzer = NetworkAnalyzer()
analyzer.initialize(config)
analyzer.start_monitoring()
```

## 📚 Examples

### Web Application Monitoring
```python
# Monitor web application traffic
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

### DDoS Detection
```python
# Monitor for DDoS attacks
config = AnalysisConfig(
    interface="en0",
    filter="udp or tcp",
    timeout=0,
    anomaly_threshold=1.5,
    threat_threshold=0.7
)

analyzer = NetworkAnalyzer()
analyzer.initialize(config)
analyzer.start_monitoring()
```

### Port Scan Detection
```python
# Monitor for port scanning
config = AnalysisConfig(
    interface="en0",
    filter="tcp",
    timeout=0,
    anomaly_threshold=2.0,
    threat_threshold=0.8
)

analyzer = NetworkAnalyzer()
analyzer.initialize(config)
analyzer.start_monitoring()
```

## 🛡️ Security Best Practices

### Authorization
- **Always obtain proper authorization** before monitoring network traffic
- **Respect privacy** and data protection regulations
- **Use for educational and authorized security testing only**

### Data Handling
- **Secure storage**: Encrypt sensitive data
- **Data retention**: Implement appropriate retention policies
- **Access control**: Limit access to analysis results

### Network Security
- **Isolated monitoring**: Use dedicated monitoring network
- **Secure management**: Secure access to management interfaces
- **Regular updates**: Keep software updated

## 📞 Support

### Getting Help
1. **Check the demo**: `python3 demo.py`
2. **Run tests**: `./test_build.sh`
3. **Read documentation**: `docs/IMPLEMENTATION_DETAILS.md`
4. **Check examples**: `python/real_world_examples.py`

### Common Commands
```bash
# Test installation
./test_build.sh

# Run demo
cd python && python3 demo.py

# Run examples
cd python && sudo python3 real_world_examples.py --example 1

# Build C++ version
cd cpp && make

# Interactive C++ guide
./cpp_usage_guide.sh
```

---

**Network Security Analyzer** - Spring 2024 Security Software Development Project

For more detailed information, see `docs/IMPLEMENTATION_DETAILS.md`.

# Network Security Analyzer

A comprehensive network security analysis tool developed in C++ and Python for detecting security vulnerabilities, anomalous traffic patterns, and HTTP-based attacks.

## 🚀 Features

### **Core Capabilities**
- **Deep Packet Inspection**: Custom algorithms for analyzing packet contents at multiple layers
- **Statistical Anomaly Detection**: Machine learning-based detection of unusual network behavior
- **Real-time Monitoring**: Live network traffic analysis with configurable thresholds
- **Cross-platform Support**: Works on Windows, macOS, and Linux
- **Dual Implementation**: Core functionality in C++ with Python bindings and utilities

### **Security Detection**
- **HTTP Threat Detection**: XSS, SQL injection, command injection, directory traversal
- **Network Threats**: DDoS attacks, port scanning, malware traffic detection
- **Anomaly Detection**: Volume spikes, unusual source ports, burst patterns
- **Behavioral Analysis**: User behavior profiling and anomaly detection
- **Comprehensive Reporting**: Detailed security reports and alerts

## 📁 Project Structure

```
network-security-analyzer/
├── cpp/                    # C++ implementation
│   ├── src/               # Source files
│   │   ├── main.cpp      # Main application
│   │   ├── packet_capture.cpp
│   │   └── test_main.cpp  # Test application
│   ├── include/           # Header files
│   │   ├── common.h
│   │   ├── packet_capture.h
│   │   ├── packet_analyzer.h
│   │   ├── anomaly_detector.h
│   │   ├── threat_detector.h
│   │   ├── statistical_analyzer.h
│   │   ├── report_generator.h
│   │   └── utils.h
│   ├── CMakeLists.txt     # CMake build configuration
│   └── Makefile          # Make build configuration
├── python/                # Python implementation
│   ├── src/               # Source files
│   │   ├── network_analyzer.py    # Main analyzer class
│   │   ├── packet_capture.py      # Packet capture functionality
│   │   ├── packet_analyzer.py     # Packet analysis with HTTP detection
│   │   ├── anomaly_detector.py    # Anomaly detection
│   │   ├── threat_detector.py     # Threat detection
│   │   ├── statistical_analyzer.py # Statistical analysis
│   │   ├── report_generator.py    # Report generation
│   │   ├── utils.py               # Utility functions
│   │   └── __init__.py
│   ├── demo.py            # Demo script
│   ├── real_world_examples.py # Real-world usage examples
│   └── requirements.txt   # Python dependencies
├── docs/                  # Documentation
│   └── IMPLEMENTATION_DETAILS.md
├── examples/              # Usage examples
│   └── basic_usage.py
├── scripts/               # Utility scripts
│   └── build.sh
├── README.md              # This file
├── REAL_WORLD_USAGE.md    # Comprehensive usage guide
├── HOW_TO_USE.md          # How-to guide
├── test_build.sh          # Build test script
├── cpp_usage_guide.sh     # C++ usage guide
├── setup.py               # Python package setup
└── LICENSE                # MIT License
```

## 🔧 Requirements

### **C++ Requirements**
- C++17 or later
- CMake 3.16+
- libpcap-dev
- OpenSSL 3.0+
- macOS: Homebrew (`brew install libpcap openssl`)

### **Python Requirements**
- Python 3.8+
- scapy (for packet capture)
- numpy (for numerical operations)
- pandas (for data analysis)
- scikit-learn (for machine learning)
- loguru (for logging)

## 🛠️ Installation

### **Quick Start**
```bash
# Clone the repository
git clone https://github.com/sarrrthakkk/network-security-analyzer.git
cd network-security-analyzer

# Run the build test
./test_build.sh
```

### **C++ Build**
```bash
cd cpp
mkdir build && cd build
cmake ..
make
```

### **Python Setup**
```bash
cd python
pip install -r requirements.txt
```

## 🚀 Usage

### **Python Version (Recommended)**

**Basic Demo:**
```bash
cd python
python3 demo.py
```

**Real-world Examples:**
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

**Programmatic Usage:**
```python
from src.network_analyzer import NetworkAnalyzer, AnalysisConfig

# Create configuration
config = AnalysisConfig(
    interface="en0",
    timeout=30,
    filter="tcp",
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
```

### **C++ Version**

**Build and Run:**
```bash
cd cpp
make
./bin/network_analyzer
```

**Interactive Guide:**
```bash
./cpp_usage_guide.sh
```

## 🔍 HTTP Threat Detection

The analyzer includes comprehensive HTTP threat detection capabilities:

### **Detected Threats**
- **XSS Attacks**: `<script>`, `javascript:`, `onload=`, `onclick=`, etc.
- **SQL Injection**: `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`, etc.
- **Command Injection**: `cmd.exe`, `powershell`, `; ls`, `; cat`, etc.
- **Directory Traversal**: `../`, `..\`, `/etc/passwd`, etc.
- **Scanning Tools**: `sqlmap`, `nikto`, `nmap`, `burp`, etc.

### **Example Detection**
```python
# The analyzer automatically detects HTTP threats like:
# GET /admin?id=1' OR '1'='1 HTTP/1.1
# POST /login HTTP/1.1
# <script>alert('XSS')</script>
```

## 📊 Security Features

### **Protocol Analysis**
- **HTTP/HTTPS**: Deep inspection with threat detection
- **DNS**: Query analysis and suspicious domain detection
- **TCP/UDP**: Port scanning and connection analysis
- **ICMP**: Ping flood and network scanning detection

### **Threat Detection**
- **DDoS Attacks**: Volume-based and rate-based detection
- **Port Scanning**: Multiple port access pattern detection
- **Malware Traffic**: Known malicious pattern detection
- **Data Exfiltration**: Large data transfer detection

### **Anomaly Detection**
- **Volume Spikes**: Unusual traffic volume detection
- **Burst Patterns**: Rapid packet sequence detection
- **Unusual Ports**: Non-standard port usage detection
- **Behavioral Changes**: Machine learning-based anomaly detection

### **Reporting**
- **HTML Reports**: Interactive security reports
- **JSON Export**: Structured data export
- **Real-time Alerts**: Live threat notifications
- **Statistical Analysis**: Traffic pattern analysis

## 🧪 Testing

### **Build Test**
```bash
./test_build.sh
```

### **Python Tests**
```bash
cd python
python3 demo.py
```

### **C++ Tests**
```bash
cd cpp
make test
```

## 📚 Documentation

- **[HELP_COMMANDS.md](HELP_COMMANDS.md)**: 🆘 **Quick reference for all commands and troubleshooting**
- **[REAL_WORLD_USAGE.md](REAL_WORLD_USAGE.md)**: Comprehensive usage guide with real-world scenarios
- **[HOW_TO_USE.md](HOW_TO_USE.md)**: Step-by-step how-to guide
- **[docs/IMPLEMENTATION_DETAILS.md](docs/IMPLEMENTATION_DETAILS.md)**: Technical implementation details

## 🤝 Contributing

This project was developed for Spring 2024 Security Software Development course. Contributions are welcome!

### **Development Setup**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `./test_build.sh`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before monitoring network traffic. The authors are not responsible for any misuse of this software.

---

**Network Security Analyzer** - Spring 2024 Security Software Development Project
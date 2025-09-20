# 🆘 Network Security Analyzer - Help Commands

**Quick reference for all commands and troubleshooting**

## 🚀 Get Started (Copy-Paste Ready)

### 1. Clone and Setup
```bash
git clone https://github.com/sarrrthakkk/network-security-analyzer.git
cd network-security-analyzer/python
pip install -r requirements.txt
```

### 2. Find Your Network Interface
```bash
# macOS/Linux
ifconfig | grep -E "^[a-z]|inet "

# Or programmatically
python3 -c "from src.utils import NetworkUtils; print(NetworkUtils.get_available_interfaces())"
```

### 3. Run Basic Monitoring
```bash
# Replace 'en0' with your interface
sudo python3 src/network_analyzer.py -i en0 -t 60 -o security_report.html -v
```

## 📋 Essential Commands

### Help Commands
```bash
# Show all options
python3 src/network_analyzer.py --help

# Safe demo (no root needed)
python3 demo.py

# Interactive C++ guide
./cpp_usage_guide.sh
```

### Python Monitoring Commands
```bash
# Basic monitoring (60s with report)
sudo python3 src/network_analyzer.py -i en0 -t 60 -o security_report.html -v

# Continuous monitoring (until Ctrl+C)
sudo python3 src/network_analyzer.py -i en0 -t 0 -v

# HTTP/HTTPS traffic only
sudo python3 src/network_analyzer.py -i en0 -f "port 80 or port 443" -t 300 -v

# Specific IP range
sudo python3 src/network_analyzer.py -i en0 -f "net 192.168.1.0/24" -t 300 -v
```

### Pre-built Scenarios
```bash
# Example 1: Basic monitoring
sudo python3 real_world_examples.py --example 1

# Example 2: DDoS detection
sudo python3 real_world_examples.py --example 2

# Example 3: Port scan detection
sudo python3 real_world_examples.py --example 3

# Example 4: Continuous monitoring
sudo python3 real_world_examples.py --example 4

# Example 5: Custom filtering
sudo python3 real_world_examples.py --example 5
```

### C++ Commands
```bash
# Build and run
cd ../cpp
make
sudo ./bin/network_analyzer

# Interactive examples
./cpp_usage_guide.sh
```

## 🔧 Troubleshooting

### Permission Issues
```bash
# Always use sudo for packet capture
sudo python3 src/network_analyzer.py -i en0 -t 30

# Test packet capture capability
sudo python3 -c "import scapy; print('Packet capture available')"
```

### Interface Issues
```bash
# Common interfaces by OS:
# macOS: en0, en1, en2
# Linux: eth0, wlan0, ens33
# Windows: Ethernet, Wi-Fi

# Find your interface
ifconfig | grep -E "^[a-z]|inet "
```

### Dependency Issues
```bash
# Python dependencies
pip install -r requirements.txt

# C++ dependencies (macOS)
brew install libpcap openssl

# C++ dependencies (Ubuntu/Debian)
sudo apt-get install libpcap-dev libssl-dev

# Test installation
python3 demo.py
```

## 📊 Viewing Results

### Reports
```bash
# Open HTML report
open security_report.html

# View in terminal
cat security_report.html

# Export as JSON
python3 -c "
from src.network_analyzer import NetworkAnalyzer, AnalysisConfig
analyzer = NetworkAnalyzer()
analyzer.initialize(AnalysisConfig(interface='en0', timeout=10))
analyzer.start_monitoring()
analyzer.export_data('analysis_data.json')
"
```

### Real-time Monitoring
```bash
# Live output with timestamps
sudo python3 src/network_analyzer.py -i en0 -t 0 -v | while read line; do echo "$(date): $line"; done

# Save to file and watch
sudo python3 src/network_analyzer.py -i en0 -t 0 -v > live_monitor.log 2>&1 &
tail -f live_monitor.log
```

## 🎯 Common Use Cases

### Web Security
```bash
# Monitor web traffic for attacks
sudo python3 src/network_analyzer.py -i en0 -f "port 80 or port 443" -t 3600 -o web_security_report.html -v
```

### DDoS Detection
```bash
sudo python3 real_world_examples.py --example 2
```

### Port Scanning Detection
```bash
sudo python3 real_world_examples.py --example 3
```

### Custom Analysis
```bash
# TCP traffic only
sudo python3 src/network_analyzer.py -i en0 -f "tcp" -t 300 -v

# UDP traffic only
sudo python3 src/network_analyzer.py -i en0 -f "udp" -t 300 -v

# Specific port
sudo python3 src/network_analyzer.py -i en0 -f "port 22" -t 300 -v
```

## 🔍 Advanced Usage

### Programmatic Usage
```python
from src.network_analyzer import NetworkAnalyzer, AnalysisConfig

config = AnalysisConfig(
    interface="en0",
    timeout=60,
    filter="tcp port 80 or tcp port 443",
    anomaly_threshold=2.0,
    threat_threshold=0.8,
    verbose=True
)

analyzer = NetworkAnalyzer()
analyzer.initialize(config)
analyzer.start_monitoring()

status = analyzer.get_status()
print(f"Captured {status['packets_processed']} packets")

analyzer.generate_report("custom_report.html")
```

### Batch Processing
```bash
# Run multiple sessions
for i in {1..5}; do
    echo "Running session $i..."
    sudo python3 src/network_analyzer.py -i en0 -t 60 -o "report_$i.html"
    sleep 10
done
```

## 📚 Documentation

### Read Documentation
```bash
# Comprehensive usage guide
open docs/REAL_WORLD_USAGE.md

# Implementation details
open docs/IMPLEMENTATION_DETAILS.md

# This help file
open HELP_COMMANDS.md
```

### Run Tests
```bash
# Build tests
./test_build.sh

# Python demo
python3 demo.py

# C++ examples
./cpp_usage_guide.sh
```

## ⚠️ Important Notes

1. **Always use sudo** for packet capture
2. **Replace en0** with your actual network interface
3. **Check permissions** before running
4. **Monitor disk space** for large captures
5. **Respect privacy** and legal requirements
6. **Use appropriate filters** to reduce noise

## 🆘 Still Need Help?

1. **Check the demo**: `python3 demo.py`
2. **Run tests**: `./test_build.sh`
3. **Read docs**: `docs/REAL_WORLD_USAGE.md`
4. **Try examples**: `python3 real_world_examples.py --example 1`
5. **Use help flag**: `python3 src/network_analyzer.py --help`

---

**Network Security Analyzer** - Spring 2024 Security Software Development Project

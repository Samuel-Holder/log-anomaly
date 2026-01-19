# Log Anomaly Detector

A Python-based security tool for detecting anomalies, threats, and suspicious patterns in log files. Designed for SOC analysts, security engineers, and system administrators.

## Features

- **Multi-Format Parser** - Supports Apache, Nginx, Syslog, JSON, Windows Event logs
- **Pattern Detection** - Regex-based detection for known attack signatures
- **Statistical Anomaly Detection** - Identifies unusual traffic spikes, failed logins, error rates
- **IP Intelligence** - Tracks suspicious IPs, geo-location, reputation scoring
- **Real-time Monitoring** - Tail and analyze logs in real-time
- **Alert System** - Configurable severity levels and thresholds
- **Reporting** - JSON, CSV, and HTML report generation

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/log-anomaly-detector.git
cd log-anomaly-detector

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## Quick Start

```bash
# Analyze a log file
logdetector analyze /var/log/auth.log

# Analyze with specific parser
logdetector analyze /var/log/apache2/access.log --parser apache

# Real-time monitoring
logdetector watch /var/log/syslog

# Generate HTML report
logdetector analyze /var/log/auth.log -o report.html --format html

# Scan multiple files
logdetector analyze /var/log/*.log --recursive
```

## Project Structure

```
log-anomaly-detector/
├── src/
│   └── logdetector/
│       ├── __init__.py
│       ├── __main__.py        # CLI entry point
│       ├── parsers.py         # Log format parsers
│       ├── detectors.py       # Anomaly detection engines
│       ├── patterns.py        # Attack signature patterns
│       ├── analyzer.py        # Main analysis orchestrator
│       ├── alerts.py          # Alert generation & management
│       ├── reporters.py       # Report generation
│       └── utils.py           # Helper utilities
├── tests/
│   ├── test_parsers.py
│   ├── test_detectors.py
│   └── test_patterns.py
├── docs/
│   ├── USAGE.md
│   └── PATTERNS.md
├── examples/
│   └── example_analysis.py
├── sample_logs/
│   └── sample_auth.log
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── LICENSE
└── README.md
```

## Detection Capabilities

### Attack Signatures
- SQL Injection attempts
- XSS (Cross-Site Scripting)
- Path traversal attacks
- Shell injection
- Brute force login attempts
- Port scanning indicators
- Web shell access
- Command injection

### Anomaly Detection
- Unusual request rates
- Failed authentication spikes
- Off-hours activity
- New IP addresses
- Geographic anomalies
- Error rate spikes
- Large response sizes

### Threat Intelligence
- Known malicious IP detection
- User-agent analysis
- Suspicious endpoint access
- Privilege escalation patterns

## Usage Examples

### Python API

```python
from logdetector import LogAnalyzer, ApacheParser

# Initialize analyzer
analyzer = LogAnalyzer()

# Analyze Apache logs
results = analyzer.analyze_file(
    "/var/log/apache2/access.log",
    parser=ApacheParser()
)

# Check findings
for alert in results.alerts:
    print(f"[{alert.severity}] {alert.message}")

# Get statistics
print(f"Total entries: {results.stats.total_entries}")
print(f"Anomalies found: {results.stats.anomaly_count}")
```

### Command Line

```bash
# Basic analysis
logdetector analyze auth.log

# Verbose output with specific detectors
logdetector analyze access.log --detectors bruteforce,sqli,xss -v

# Export alerts only
logdetector analyze syslog --alerts-only -o alerts.json

# Watch mode with custom threshold
logdetector watch /var/log/auth.log --threshold 10
```

## Configuration

Create `config.yaml` for custom settings:

```yaml
detection:
  bruteforce_threshold: 5
  time_window: 300  # seconds
  
alerts:
  min_severity: medium
  
parsers:
  default_timezone: UTC
  
whitelist:
  ips:
    - 192.168.1.0/24
    - 10.0.0.0/8
```

## Legal Disclaimer

⚠️ **This tool is intended for authorized security monitoring and analysis only.**

- Only analyze logs from systems you own or have explicit permission to monitor
- Respect privacy regulations (GDPR, HIPAA, etc.)
- The author assumes no liability for misuse of this software

## Technical Skills Demonstrated

- **Log Parsing** - Regex patterns, format detection, multi-format support
- **Security Analysis** - Attack signature matching, threat detection
- **Statistical Analysis** - Anomaly detection, baseline comparison
- **Data Processing** - Efficient file handling, streaming analysis
- **Python Best Practices** - Type hints, dataclasses, clean architecture

## Contributing

Contributions welcome! Please read the contributing guidelines and submit pull requests.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Author

Built as a portfolio project demonstrating cybersecurity and Python development skills.

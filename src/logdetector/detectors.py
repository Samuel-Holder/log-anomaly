"""
Anomaly Detectors Module

Provides various detection engines for identifying security threats,
anomalies, and suspicious patterns in log data.
"""

import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set, Any
from statistics import mean, stdev

from .parsers import LogEntry
from .patterns import AttackPatterns, AttackPattern, check_for_attacks, ThreatCategory
from .alerts import Alert, AlertSeverity

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of a detection check."""
    
    detected: bool
    detector_name: str
    severity: AlertSeverity
    message: str
    entry: LogEntry
    matched_patterns: List[AttackPattern] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_alert(self) -> Alert:
        """Convert to Alert object."""
        return Alert(
            severity=self.severity,
            message=self.message,
            source=self.entry.source_ip,
            timestamp=self.entry.timestamp or datetime.now(),
            detector=self.detector_name,
            log_entry=self.entry,
            context=self.context,
        )


class BaseDetector(ABC):
    """Abstract base class for detectors."""
    
    name: str = "base"
    description: str = "Base detector"
    
    @abstractmethod
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """
        Analyze a log entry for threats.
        
        Args:
            entry: Parsed log entry
            
        Returns:
            DetectionResult if threat detected, None otherwise
        """
        pass
    
    def detect_batch(self, entries: List[LogEntry]) -> List[DetectionResult]:
        """
        Analyze multiple entries.
        
        Args:
            entries: List of log entries
            
        Returns:
            List of detection results
        """
        results = []
        for entry in entries:
            result = self.detect(entry)
            if result:
                results.append(result)
        return results
    
    def reset(self):
        """Reset detector state."""
        pass


class SQLInjectionDetector(BaseDetector):
    """Detects SQL injection attempts."""
    
    name = "sqli"
    description = "SQL Injection Detector"
    
    def __init__(self):
        self.patterns = AttackPatterns.SQL_INJECTION
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Check for SQL injection patterns."""
        # Check path and user agent
        text_to_check = f"{entry.path or ''} {entry.user_agent or ''}"
        
        matches = check_for_attacks(text_to_check, self.patterns)
        
        if matches:
            return DetectionResult(
                detected=True,
                detector_name=self.name,
                severity=AlertSeverity.HIGH,
                message=f"SQL Injection attempt detected: {matches[0].name}",
                entry=entry,
                matched_patterns=matches,
                context={
                    "attack_type": "SQL Injection",
                    "patterns_matched": [m.name for m in matches],
                    "path": entry.path,
                }
            )
        
        return None


class XSSDetector(BaseDetector):
    """Detects Cross-Site Scripting attempts."""
    
    name = "xss"
    description = "XSS Detector"
    
    def __init__(self):
        self.patterns = AttackPatterns.XSS_PATTERNS
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Check for XSS patterns."""
        text_to_check = f"{entry.path or ''} {entry.user_agent or ''} {entry.referer or ''}"
        
        matches = check_for_attacks(text_to_check, self.patterns)
        
        if matches:
            return DetectionResult(
                detected=True,
                detector_name=self.name,
                severity=AlertSeverity.HIGH,
                message=f"XSS attempt detected: {matches[0].name}",
                entry=entry,
                matched_patterns=matches,
                context={
                    "attack_type": "Cross-Site Scripting",
                    "patterns_matched": [m.name for m in matches],
                }
            )
        
        return None


class PathTraversalDetector(BaseDetector):
    """Detects path/directory traversal attempts."""
    
    name = "traversal"
    description = "Path Traversal Detector"
    
    def __init__(self):
        self.patterns = AttackPatterns.PATH_TRAVERSAL
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Check for path traversal patterns."""
        if not entry.path:
            return None
        
        matches = check_for_attacks(entry.path, self.patterns)
        
        if matches:
            severity = AlertSeverity.CRITICAL if any(
                m.severity == "critical" for m in matches
            ) else AlertSeverity.HIGH
            
            return DetectionResult(
                detected=True,
                detector_name=self.name,
                severity=severity,
                message=f"Path traversal attempt: {matches[0].name}",
                entry=entry,
                matched_patterns=matches,
                context={
                    "attack_type": "Path Traversal",
                    "attempted_path": entry.path,
                }
            )
        
        return None


class CommandInjectionDetector(BaseDetector):
    """Detects command injection attempts."""
    
    name = "cmdi"
    description = "Command Injection Detector"
    
    def __init__(self):
        self.patterns = AttackPatterns.COMMAND_INJECTION
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Check for command injection patterns."""
        text_to_check = f"{entry.path or ''} {entry.message or ''}"
        
        matches = check_for_attacks(text_to_check, self.patterns)
        
        if matches:
            return DetectionResult(
                detected=True,
                detector_name=self.name,
                severity=AlertSeverity.CRITICAL,
                message=f"Command injection attempt: {matches[0].name}",
                entry=entry,
                matched_patterns=matches,
                context={
                    "attack_type": "Command Injection",
                    "patterns_matched": [m.name for m in matches],
                }
            )
        
        return None


class BruteForceDetector(BaseDetector):
    """
    Detects brute force login attempts.
    
    Tracks failed authentication attempts per IP/user and alerts
    when thresholds are exceeded.
    """
    
    name = "bruteforce"
    description = "Brute Force Detector"
    
    def __init__(
        self,
        threshold: int = 5,
        time_window: int = 300,  # seconds
    ):
        """
        Initialize brute force detector.
        
        Args:
            threshold: Number of failures before alerting
            time_window: Time window in seconds
        """
        self.threshold = threshold
        self.time_window = timedelta(seconds=time_window)
        
        # Track failures: ip -> [(timestamp, user), ...]
        self.ip_failures: Dict[str, List[tuple]] = defaultdict(list)
        self.user_failures: Dict[str, List[tuple]] = defaultdict(list)
        
        # Already alerted combinations
        self.alerted: Set[str] = set()
        
        # Failure keywords
        self.failure_keywords = [
            'failed', 'failure', 'invalid', 'denied', 
            'rejected', 'error', 'bad password'
        ]
    
    def _is_auth_failure(self, entry: LogEntry) -> bool:
        """Check if entry represents an auth failure."""
        message = (entry.message or '').lower()
        return any(kw in message for kw in self.failure_keywords)
    
    def _cleanup_old_entries(self, entries: List[tuple], cutoff: datetime) -> List[tuple]:
        """Remove entries older than cutoff."""
        return [(ts, user) for ts, user in entries if ts > cutoff]
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Check for brute force patterns."""
        if not self._is_auth_failure(entry):
            return None
        
        timestamp = entry.timestamp or datetime.now()
        ip = entry.source_ip or "unknown"
        user = entry.user or "unknown"
        
        cutoff = timestamp - self.time_window
        
        # Track this failure
        self.ip_failures[ip].append((timestamp, user))
        self.user_failures[user].append((timestamp, ip))
        
        # Cleanup old entries
        self.ip_failures[ip] = self._cleanup_old_entries(
            self.ip_failures[ip], cutoff
        )
        self.user_failures[user] = self._cleanup_old_entries(
            self.user_failures[user], cutoff
        )
        
        # Check thresholds
        ip_count = len(self.ip_failures[ip])
        user_count = len(self.user_failures[user])
        
        alert_key = f"{ip}:{user}"
        
        if ip_count >= self.threshold and alert_key not in self.alerted:
            self.alerted.add(alert_key)
            
            # Get targeted users
            targeted_users = set(u for _, u in self.ip_failures[ip])
            
            return DetectionResult(
                detected=True,
                detector_name=self.name,
                severity=AlertSeverity.HIGH,
                message=f"Brute force attack from {ip}: {ip_count} failures in {self.time_window.seconds}s",
                entry=entry,
                context={
                    "attack_type": "Brute Force",
                    "source_ip": ip,
                    "failure_count": ip_count,
                    "targeted_users": list(targeted_users),
                    "time_window": self.time_window.seconds,
                }
            )
        
        return None
    
    def reset(self):
        """Reset detector state."""
        self.ip_failures.clear()
        self.user_failures.clear()
        self.alerted.clear()


class AnomalyDetector(BaseDetector):
    """
    Statistical anomaly detector.
    
    Builds baseline statistics and detects deviations.
    """
    
    name = "anomaly"
    description = "Statistical Anomaly Detector"
    
    def __init__(
        self,
        baseline_size: int = 1000,
        std_threshold: float = 3.0,
    ):
        """
        Initialize anomaly detector.
        
        Args:
            baseline_size: Number of entries for baseline
            std_threshold: Standard deviations for anomaly
        """
        self.baseline_size = baseline_size
        self.std_threshold = std_threshold
        
        # Tracking metrics
        self.request_counts: Dict[str, List[int]] = defaultdict(list)  # ip -> counts per minute
        self.error_rates: List[float] = []
        self.response_sizes: List[int] = []
        
        # Time-based tracking
        self.minute_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.hourly_patterns: Dict[int, int] = defaultdict(int)  # hour -> count
        
        # Baseline stats
        self.baseline_computed = False
        self.baseline_error_rate: float = 0.0
        self.baseline_error_std: float = 0.0
        self.baseline_size_mean: float = 0.0
        self.baseline_size_std: float = 0.0
        
        self.entries_seen = 0
    
    def _compute_baseline(self):
        """Compute baseline statistics."""
        if len(self.error_rates) >= 100:
            self.baseline_error_rate = mean(self.error_rates)
            self.baseline_error_std = stdev(self.error_rates) if len(self.error_rates) > 1 else 0
        
        if len(self.response_sizes) >= 100:
            self.baseline_size_mean = mean(self.response_sizes)
            self.baseline_size_std = stdev(self.response_sizes) if len(self.response_sizes) > 1 else 0
        
        self.baseline_computed = True
        logger.info(f"Baseline computed: error_rate={self.baseline_error_rate:.2%}")
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Detect statistical anomalies."""
        self.entries_seen += 1
        
        # Track metrics
        if entry.status_code:
            is_error = entry.status_code >= 400
            self.error_rates.append(1.0 if is_error else 0.0)
            # Keep last N entries
            if len(self.error_rates) > self.baseline_size * 2:
                self.error_rates = self.error_rates[-self.baseline_size:]
        
        if entry.size:
            self.response_sizes.append(entry.size)
            if len(self.response_sizes) > self.baseline_size * 2:
                self.response_sizes = self.response_sizes[-self.baseline_size:]
        
        # Track IP request frequency
        if entry.source_ip and entry.timestamp:
            minute_key = entry.timestamp.strftime("%Y%m%d%H%M")
            self.minute_counts[entry.source_ip][minute_key] += 1
        
        # Track hourly patterns
        if entry.timestamp:
            self.hourly_patterns[entry.timestamp.hour] += 1
        
        # Compute baseline after enough data
        if self.entries_seen >= self.baseline_size and not self.baseline_computed:
            self._compute_baseline()
        
        # Detect anomalies only after baseline
        if not self.baseline_computed:
            return None
        
        anomalies = []
        
        # Check for unusual response size
        if entry.size and self.baseline_size_std > 0:
            z_score = abs(entry.size - self.baseline_size_mean) / self.baseline_size_std
            if z_score > self.std_threshold:
                anomalies.append(f"Unusual response size: {entry.size} bytes (z={z_score:.1f})")
        
        # Check for high request rate from IP
        if entry.source_ip and entry.timestamp:
            minute_key = entry.timestamp.strftime("%Y%m%d%H%M")
            ip_count = self.minute_counts[entry.source_ip][minute_key]
            
            if ip_count > 100:  # More than 100 requests per minute
                anomalies.append(f"High request rate: {ip_count} requests/minute from {entry.source_ip}")
        
        # Check for off-hours activity
        if entry.timestamp:
            hour = entry.timestamp.hour
            if hour < 6 or hour > 22:  # Outside business hours
                if entry.extra.get('auth_event') == 'accepted':
                    anomalies.append(f"Off-hours authentication at {hour}:00")
        
        if anomalies:
            return DetectionResult(
                detected=True,
                detector_name=self.name,
                severity=AlertSeverity.MEDIUM,
                message="; ".join(anomalies),
                entry=entry,
                context={
                    "anomaly_type": "statistical",
                    "anomalies": anomalies,
                }
            )
        
        return None
    
    def reset(self):
        """Reset detector state."""
        self.request_counts.clear()
        self.error_rates.clear()
        self.response_sizes.clear()
        self.minute_counts.clear()
        self.hourly_patterns.clear()
        self.baseline_computed = False
        self.entries_seen = 0


class WebShellDetector(BaseDetector):
    """Detects web shell access attempts."""
    
    name = "webshell"
    description = "Web Shell Detector"
    
    def __init__(self):
        self.patterns = AttackPatterns.WEB_SHELL
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Check for web shell indicators."""
        text_to_check = f"{entry.path or ''}"
        
        matches = check_for_attacks(text_to_check, self.patterns)
        
        if matches:
            return DetectionResult(
                detected=True,
                detector_name=self.name,
                severity=AlertSeverity.CRITICAL,
                message=f"Web shell detected: {matches[0].name}",
                entry=entry,
                matched_patterns=matches,
                context={
                    "attack_type": "Web Shell",
                    "path": entry.path,
                }
            )
        
        return None


class ScannerDetector(BaseDetector):
    """Detects security scanner activity."""
    
    name = "scanner"
    description = "Security Scanner Detector"
    
    def __init__(self):
        self.patterns = AttackPatterns.RECONNAISSANCE
        self.known_scanners = {
            'nikto', 'nmap', 'sqlmap', 'dirb', 'dirbuster',
            'gobuster', 'wfuzz', 'burp', 'zap', 'acunetix',
            'nessus', 'openvas', 'masscan', 'w3af', 'arachni'
        }
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Check for scanner signatures."""
        user_agent = (entry.user_agent or '').lower()
        
        # Check user agent for known scanners
        for scanner in self.known_scanners:
            if scanner in user_agent:
                return DetectionResult(
                    detected=True,
                    detector_name=self.name,
                    severity=AlertSeverity.MEDIUM,
                    message=f"Security scanner detected: {scanner}",
                    entry=entry,
                    context={
                        "scanner": scanner,
                        "user_agent": entry.user_agent,
                    }
                )
        
        # Check path patterns
        matches = check_for_attacks(entry.path or '', self.patterns)
        if matches:
            return DetectionResult(
                detected=True,
                detector_name=self.name,
                severity=AlertSeverity.LOW,
                message=f"Reconnaissance detected: {matches[0].name}",
                entry=entry,
                matched_patterns=matches,
            )
        
        return None


class CompositeDetector(BaseDetector):
    """Combines multiple detectors."""
    
    name = "composite"
    description = "Composite Detector"
    
    def __init__(self, detectors: List[BaseDetector] = None):
        """
        Initialize with list of detectors.
        
        Args:
            detectors: List of detector instances
        """
        if detectors is None:
            detectors = [
                SQLInjectionDetector(),
                XSSDetector(),
                PathTraversalDetector(),
                CommandInjectionDetector(),
                BruteForceDetector(),
                WebShellDetector(),
                ScannerDetector(),
                AnomalyDetector(),
            ]
        
        self.detectors = detectors
    
    def detect(self, entry: LogEntry) -> Optional[DetectionResult]:
        """Run all detectors and return highest severity result."""
        results = []
        
        for detector in self.detectors:
            result = detector.detect(entry)
            if result:
                results.append(result)
        
        if not results:
            return None
        
        # Return highest severity
        severity_order = [
            AlertSeverity.CRITICAL,
            AlertSeverity.HIGH,
            AlertSeverity.MEDIUM,
            AlertSeverity.LOW,
            AlertSeverity.INFO,
        ]
        
        for severity in severity_order:
            for result in results:
                if result.severity == severity:
                    # Combine all matches
                    result.context['all_detections'] = [
                        {"detector": r.detector_name, "message": r.message}
                        for r in results
                    ]
                    return result
        
        return results[0]
    
    def detect_batch(self, entries: List[LogEntry]) -> List[DetectionResult]:
        """Run all detectors on batch."""
        results = []
        for entry in entries:
            result = self.detect(entry)
            if result:
                results.append(result)
        return results
    
    def reset(self):
        """Reset all detectors."""
        for detector in self.detectors:
            detector.reset()


def get_detector(name: str) -> BaseDetector:
    """Get detector by name."""
    detectors = {
        'sqli': SQLInjectionDetector,
        'xss': XSSDetector,
        'traversal': PathTraversalDetector,
        'cmdi': CommandInjectionDetector,
        'bruteforce': BruteForceDetector,
        'webshell': WebShellDetector,
        'scanner': ScannerDetector,
        'anomaly': AnomalyDetector,
        'all': CompositeDetector,
    }
    
    detector_class = detectors.get(name.lower())
    if not detector_class:
        raise ValueError(f"Unknown detector: {name}")
    
    return detector_class()


if __name__ == "__main__":
    # Test detectors
    from .parsers import ApacheParser, AuthLogParser
    
    logging.basicConfig(level=logging.DEBUG)
    
    # Test SQL injection
    detector = SQLInjectionDetector()
    parser = ApacheParser()
    
    test_line = '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /page?id=1\' UNION SELECT * FROM users-- HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    entry = parser.parse_line(test_line)
    
    result = detector.detect(entry)
    if result:
        print(f"SQLi Detection: {result.message}")
    
    # Test brute force
    bf_detector = BruteForceDetector(threshold=3)
    auth_parser = AuthLogParser()
    
    for i in range(5):
        auth_line = f'Jan 10 12:34:{56+i} server sshd[1234]: Failed password for admin from 192.168.1.100 port 22'
        entry = auth_parser.parse_line(auth_line)
        result = bf_detector.detect(entry)
        if result:
            print(f"Brute Force Detection: {result.message}")

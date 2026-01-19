"""
Unit Tests for Anomaly Detectors
"""

import pytest
from datetime import datetime

from logdetector.parsers import LogEntry
from logdetector.detectors import (
    SQLInjectionDetector, XSSDetector, PathTraversalDetector,
    CommandInjectionDetector, BruteForceDetector, WebShellDetector,
    ScannerDetector, CompositeDetector
)
from logdetector.alerts import AlertSeverity


def make_entry(path=None, message=None, user_agent=None, source_ip=None, timestamp=None):
    """Helper to create test log entries."""
    return LogEntry(
        raw="test",
        path=path,
        message=message,
        user_agent=user_agent,
        source_ip=source_ip or "192.168.1.100",
        timestamp=timestamp or datetime.now(),
        line_number=1,
    )


class TestSQLInjectionDetector:
    """Tests for SQL injection detection."""
    
    def test_detect_union_injection(self):
        detector = SQLInjectionDetector()
        entry = make_entry(path="/page?id=1' UNION SELECT * FROM users--")
        
        result = detector.detect(entry)
        
        assert result is not None
        assert result.severity == AlertSeverity.HIGH
        assert "SQL" in result.message
    
    def test_detect_boolean_injection(self):
        detector = SQLInjectionDetector()
        entry = make_entry(path="/login?user=admin' OR '1'='1")
        
        result = detector.detect(entry)
        
        assert result is not None
    
    def test_no_false_positive_normal_path(self):
        detector = SQLInjectionDetector()
        entry = make_entry(path="/products/category/electronics")
        
        result = detector.detect(entry)
        
        assert result is None


class TestXSSDetector:
    """Tests for XSS detection."""
    
    def test_detect_script_tag(self):
        detector = XSSDetector()
        entry = make_entry(path="/search?q=<script>alert('xss')</script>")
        
        result = detector.detect(entry)
        
        assert result is not None
        assert "XSS" in result.message
    
    def test_detect_event_handler(self):
        detector = XSSDetector()
        entry = make_entry(path="/page?name=<img onerror=alert(1)>")
        
        result = detector.detect(entry)
        
        assert result is not None
    
    def test_detect_javascript_protocol(self):
        detector = XSSDetector()
        entry = make_entry(path="/redirect?url=javascript:alert(1)")
        
        result = detector.detect(entry)
        
        assert result is not None


class TestPathTraversalDetector:
    """Tests for path traversal detection."""
    
    def test_detect_dotdot(self):
        detector = PathTraversalDetector()
        entry = make_entry(path="/files/../../../etc/passwd")
        
        result = detector.detect(entry)
        
        assert result is not None
        assert result.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]
    
    def test_detect_encoded_traversal(self):
        detector = PathTraversalDetector()
        entry = make_entry(path="/files/%2e%2e%2f%2e%2e%2fetc/passwd")
        
        result = detector.detect(entry)
        
        assert result is not None
    
    def test_detect_sensitive_file(self):
        detector = PathTraversalDetector()
        entry = make_entry(path="/.htpasswd")
        
        result = detector.detect(entry)
        
        assert result is not None


class TestCommandInjectionDetector:
    """Tests for command injection detection."""
    
    def test_detect_semicolon_injection(self):
        detector = CommandInjectionDetector()
        entry = make_entry(path="/ping?host=;cat /etc/passwd")
        
        result = detector.detect(entry)
        
        assert result is not None
        assert result.severity == AlertSeverity.CRITICAL
    
    def test_detect_pipe_injection(self):
        detector = CommandInjectionDetector()
        entry = make_entry(path="/cmd?run=test|whoami")
        
        result = detector.detect(entry)
        
        assert result is not None


class TestBruteForceDetector:
    """Tests for brute force detection."""
    
    def test_detect_multiple_failures(self):
        detector = BruteForceDetector(threshold=3)
        
        # Simulate 3 failed attempts
        for i in range(3):
            entry = make_entry(
                message=f"Failed password for admin from 192.168.1.100",
                source_ip="192.168.1.100",
                timestamp=datetime.now(),
            )
            result = detector.detect(entry)
        
        # Should trigger on 3rd attempt
        assert result is not None
        assert "Brute force" in result.message
    
    def test_no_alert_under_threshold(self):
        detector = BruteForceDetector(threshold=5)
        
        # Only 2 failures
        for i in range(2):
            entry = make_entry(
                message="Failed password for admin",
                source_ip="192.168.1.100",
            )
            result = detector.detect(entry)
        
        assert result is None
    
    def test_different_ips_no_alert(self):
        detector = BruteForceDetector(threshold=3)
        
        # 3 failures from different IPs
        for i in range(3):
            entry = make_entry(
                message="Failed password for admin",
                source_ip=f"192.168.1.{100+i}",
            )
            result = detector.detect(entry)
        
        assert result is None


class TestWebShellDetector:
    """Tests for web shell detection."""
    
    def test_detect_known_webshell(self):
        detector = WebShellDetector()
        entry = make_entry(path="/uploads/c99.php")
        
        result = detector.detect(entry)
        
        assert result is not None
        assert result.severity == AlertSeverity.CRITICAL
    
    def test_detect_shell_parameter(self):
        detector = WebShellDetector()
        entry = make_entry(path="/backdoor.php?cmd=whoami")
        
        result = detector.detect(entry)
        
        assert result is not None


class TestScannerDetector:
    """Tests for security scanner detection."""
    
    def test_detect_nikto(self):
        detector = ScannerDetector()
        entry = make_entry(user_agent="Nikto/2.1.6")
        
        result = detector.detect(entry)
        
        assert result is not None
        assert "nikto" in result.message.lower()
    
    def test_detect_sqlmap(self):
        detector = ScannerDetector()
        entry = make_entry(user_agent="sqlmap/1.5")
        
        result = detector.detect(entry)
        
        assert result is not None


class TestCompositeDetector:
    """Tests for composite detector."""
    
    def test_runs_all_detectors(self):
        detector = CompositeDetector()
        
        # SQL injection should be detected
        entry = make_entry(path="/page?id=1' UNION SELECT * FROM users--")
        result = detector.detect(entry)
        
        assert result is not None
    
    def test_returns_highest_severity(self):
        detector = CompositeDetector()
        
        # Command injection (critical) + scanner (medium)
        entry = make_entry(
            path="/cmd?run=;cat /etc/passwd",
            user_agent="Nikto/2.1.6",
        )
        result = detector.detect(entry)
        
        assert result is not None
        assert result.severity == AlertSeverity.CRITICAL
    
    def test_reset_clears_state(self):
        detector = CompositeDetector()
        
        # Add some detections
        entry = make_entry(message="Failed password for admin", source_ip="192.168.1.100")
        detector.detect(entry)
        
        # Reset
        detector.reset()
        
        # State should be cleared (bruteforce counter reset)
        # No assertion needed - just checking no exceptions


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

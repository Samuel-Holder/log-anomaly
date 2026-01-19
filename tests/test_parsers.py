"""
Unit Tests for Log Parsers
"""

import pytest
from datetime import datetime

from logdetector.parsers import (
    ApacheParser, NginxParser, SyslogParser,
    AuthLogParser, JSONLogParser, AutoParser, LogEntry
)


class TestApacheParser:
    """Tests for Apache log parser."""
    
    def test_parse_standard_line(self):
        parser = ApacheParser()
        line = '192.168.1.100 - admin [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
        
        entry = parser.parse_line(line)
        
        assert entry.source_ip == "192.168.1.100"
        assert entry.user == "admin"
        assert entry.method == "GET"
        assert entry.path == "/index.html"
        assert entry.status_code == 200
        assert entry.size == 2326
        assert "Mozilla" in entry.user_agent
    
    def test_parse_no_user(self):
        parser = ApacheParser()
        line = '10.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/7.64.1"'
        
        entry = parser.parse_line(line)
        
        assert entry.source_ip == "10.0.0.1"
        assert entry.user is None
        assert entry.method == "POST"
        assert entry.status_code == 401
    
    def test_parse_with_referer(self):
        parser = ApacheParser()
        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /page HTTP/1.1" 200 1234 "https://google.com" "Mozilla/5.0"'
        
        entry = parser.parse_line(line)
        
        assert entry.referer == "https://google.com"
    
    def test_parse_invalid_line(self):
        parser = ApacheParser()
        line = "This is not a valid Apache log line"
        
        entry = parser.parse_line(line)
        
        assert entry.parse_error is not None


class TestSyslogParser:
    """Tests for Syslog parser."""
    
    def test_parse_standard_syslog(self):
        parser = SyslogParser()
        line = "Jan 10 12:34:56 myserver sshd[1234]: Connection from 192.168.1.100"
        
        entry = parser.parse_line(line)
        
        assert entry.hostname == "myserver"
        assert entry.service == "sshd"
        assert entry.pid == 1234
        assert "Connection from" in entry.message
    
    def test_parse_without_pid(self):
        parser = SyslogParser()
        line = "Jan 10 12:34:56 server kernel: Some kernel message"
        
        entry = parser.parse_line(line)
        
        assert entry.service == "kernel"
        assert entry.pid is None


class TestAuthLogParser:
    """Tests for auth log parser."""
    
    def test_parse_failed_password(self):
        parser = AuthLogParser()
        line = "Jan 10 12:34:56 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2"
        
        entry = parser.parse_line(line)
        
        assert entry.source_ip == "192.168.1.100"
        assert entry.user == "admin"
        assert entry.extra.get('auth_event') == 'failed'
        assert entry.level == 'WARNING'
    
    def test_parse_accepted_password(self):
        parser = AuthLogParser()
        line = "Jan 10 12:34:56 server sshd[1234]: Accepted password for user1 from 10.0.0.5 port 22 ssh2"
        
        entry = parser.parse_line(line)
        
        assert entry.source_ip == "10.0.0.5"
        assert entry.user == "user1"
        assert entry.extra.get('auth_event') == 'accepted'
        assert entry.level == 'INFO'
    
    def test_parse_invalid_user(self):
        parser = AuthLogParser()
        line = "Jan 10 12:34:56 server sshd[1234]: Invalid user hacker from 192.168.1.100"
        
        entry = parser.parse_line(line)
        
        assert entry.extra.get('auth_event') == 'invalid_user'
        assert entry.level == 'WARNING'


class TestJSONLogParser:
    """Tests for JSON log parser."""
    
    def test_parse_standard_json(self):
        parser = JSONLogParser()
        line = '{"timestamp": "2023-10-10T13:55:36Z", "source_ip": "192.168.1.1", "method": "GET", "path": "/api/users", "status": 200}'
        
        entry = parser.parse_line(line)
        
        assert entry.source_ip == "192.168.1.1"
        assert entry.method == "GET"
        assert entry.path == "/api/users"
        assert entry.status_code == 200
    
    def test_parse_with_message(self):
        parser = JSONLogParser()
        line = '{"level": "ERROR", "message": "Database connection failed", "timestamp": "2023-10-10T13:55:36Z"}'
        
        entry = parser.parse_line(line)
        
        assert entry.level == "ERROR"
        assert "Database" in entry.message
    
    def test_parse_invalid_json(self):
        parser = JSONLogParser()
        line = "This is not JSON"
        
        entry = parser.parse_line(line)
        
        assert entry.parse_error is not None


class TestAutoParser:
    """Tests for auto-detecting parser."""
    
    def test_detect_apache_format(self):
        parser = AutoParser()
        lines = [
            '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
            '192.168.1.2 - - [10/Oct/2023:13:55:37 +0000] "GET /page HTTP/1.1" 200 5678 "-" "Mozilla/5.0"',
        ]
        
        detected = parser.detect_format(lines)
        
        assert detected.name in ['apache', 'nginx']
    
    def test_detect_json_format(self):
        parser = AutoParser()
        lines = [
            '{"timestamp": "2023-10-10T13:55:36Z", "message": "test"}',
            '{"timestamp": "2023-10-10T13:55:37Z", "message": "test2"}',
        ]
        
        detected = parser.detect_format(lines)
        
        assert detected.name == 'json'


class TestLogEntry:
    """Tests for LogEntry dataclass."""
    
    def test_to_dict(self):
        entry = LogEntry(
            raw="test line",
            source_ip="192.168.1.1",
            method="GET",
            path="/test",
            status_code=200,
            line_number=1,
        )
        
        data = entry.to_dict()
        
        assert data['source_ip'] == "192.168.1.1"
        assert data['method'] == "GET"
        assert data['status_code'] == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

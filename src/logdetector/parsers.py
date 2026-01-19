"""
Log Parsers Module

Provides parsers for various log formats including Apache, Nginx,
Syslog, auth logs, and JSON structured logs.
"""

import re
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List, Any, Iterator, Type
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Represents a parsed log entry."""
    
    raw: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    size: Optional[int] = None
    user_agent: Optional[str] = None
    referer: Optional[str] = None
    message: Optional[str] = None
    level: Optional[str] = None
    hostname: Optional[str] = None
    service: Optional[str] = None
    pid: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    line_number: int = 0
    parse_error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "user": self.user,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "size": self.size,
            "user_agent": self.user_agent,
            "message": self.message,
            "level": self.level,
            "hostname": self.hostname,
            "service": self.service,
            "line_number": self.line_number,
            "extra": self.extra,
        }


class BaseParser(ABC):
    """Abstract base class for log parsers."""
    
    name: str = "base"
    
    @abstractmethod
    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        """Parse a single log line."""
        pass
    
    def parse_file(self, filepath: str) -> Iterator[LogEntry]:
        """Parse all lines in a file."""
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    yield self.parse_line(line, line_num)
    
    def parse_lines(self, lines: List[str]) -> Iterator[LogEntry]:
        """Parse a list of log lines."""
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line:
                yield self.parse_line(line, line_num)


class ApacheParser(BaseParser):
    """
    Parser for Apache Combined Log Format.
    
    Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
    Example: 192.168.1.1 - user [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
    """
    
    name = "apache"
    
    # Apache combined log format regex
    PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'                              # IP address
        r'(?P<ident>\S+)\s+'                            # Ident
        r'(?P<user>\S+)\s+'                             # User
        r'\[(?P<timestamp>[^\]]+)\]\s+'                 # Timestamp
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'   # Request
        r'(?P<status>\d+)\s+'                           # Status code
        r'(?P<size>\S+)'                                # Size
        r'(?:\s+"(?P<referer>[^"]*)"\s+'                # Referer (optional)
        r'"(?P<user_agent>[^"]*)")?'                    # User-agent (optional)
    )
    
    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        """Parse Apache log line."""
        match = self.PATTERN.match(line)
        
        if not match:
            return LogEntry(
                raw=line,
                line_number=line_number,
                parse_error="Failed to parse Apache log format"
            )
        
        data = match.groupdict()
        
        # Parse timestamp
        timestamp = None
        try:
            ts_str = data['timestamp']
            timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except (ValueError, TypeError):
            try:
                timestamp = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            except:
                pass
        
        # Parse size
        size = None
        if data['size'] and data['size'] != '-':
            try:
                size = int(data['size'])
            except ValueError:
                pass
        
        return LogEntry(
            raw=line,
            timestamp=timestamp,
            source_ip=data['ip'],
            user=data['user'] if data['user'] != '-' else None,
            method=data['method'],
            path=data['path'],
            status_code=int(data['status']),
            size=size,
            referer=data.get('referer'),
            user_agent=data.get('user_agent'),
            line_number=line_number,
        )


class NginxParser(BaseParser):
    """
    Parser for Nginx default log format.
    
    Similar to Apache combined but with slight variations.
    """
    
    name = "nginx"
    
    PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+-\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
        r'(?:\s+"(?P<forwarded>[^"]*)")?'
    )
    
    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        """Parse Nginx log line."""
        match = self.PATTERN.match(line)
        
        if not match:
            # Fall back to Apache parser
            apache = ApacheParser()
            return apache.parse_line(line, line_number)
        
        data = match.groupdict()
        
        # Parse timestamp
        timestamp = None
        try:
            timestamp = datetime.strptime(
                data['timestamp'].split()[0], 
                "%d/%b/%Y:%H:%M:%S"
            )
        except (ValueError, TypeError):
            pass
        
        return LogEntry(
            raw=line,
            timestamp=timestamp,
            source_ip=data['ip'],
            user=data['user'] if data['user'] != '-' else None,
            method=data['method'],
            path=data['path'],
            status_code=int(data['status']),
            size=int(data['size']) if data['size'] else None,
            referer=data['referer'] if data['referer'] != '-' else None,
            user_agent=data['user_agent'],
            line_number=line_number,
            extra={'forwarded_for': data.get('forwarded')},
        )


class SyslogParser(BaseParser):
    """
    Parser for standard Syslog format (RFC 3164).
    
    Format: <priority>timestamp hostname service[pid]: message
    Example: Jan 10 12:34:56 server sshd[1234]: Accepted password for user
    """
    
    name = "syslog"
    
    PATTERN = re.compile(
        r'^(?:(<\d+>))?'                                 # Priority (optional)
        r'(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'   # Timestamp
        r'(?P<hostname>\S+)\s+'                          # Hostname
        r'(?P<service>[\w\-\.]+)'                        # Service
        r'(?:\[(?P<pid>\d+)\])?'                         # PID (optional)
        r':\s*'                                          # Separator
        r'(?P<message>.*)$'                              # Message
    )
    
    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        """Parse Syslog line."""
        match = self.PATTERN.match(line)
        
        if not match:
            return LogEntry(
                raw=line,
                message=line,
                line_number=line_number,
                parse_error="Failed to parse Syslog format"
            )
        
        data = match.groupdict()
        
        # Parse timestamp (add current year)
        timestamp = None
        try:
            ts_str = data['timestamp']
            current_year = datetime.now().year
            timestamp = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
        except (ValueError, TypeError):
            pass
        
        return LogEntry(
            raw=line,
            timestamp=timestamp,
            hostname=data['hostname'],
            service=data['service'],
            pid=int(data['pid']) if data['pid'] else None,
            message=data['message'],
            line_number=line_number,
        )


class AuthLogParser(BaseParser):
    """
    Parser for authentication logs (auth.log, secure).
    
    Extends Syslog parser with auth-specific extraction.
    """
    
    name = "authlog"
    
    # Patterns for extracting auth-specific info
    IP_PATTERN = re.compile(r'(?:from|rhost=)\s*(\d+\.\d+\.\d+\.\d+)')
    USER_PATTERN = re.compile(r'(?:for|user=?|user)\s+(\S+)')
    AUTH_PATTERNS = {
        'accepted': re.compile(r'Accepted\s+(\w+)\s+for\s+(\S+)', re.I),
        'failed': re.compile(r'Failed\s+(\w+)\s+for\s+(?:invalid user\s+)?(\S+)', re.I),
        'invalid_user': re.compile(r'Invalid user\s+(\S+)', re.I),
        'disconnect': re.compile(r'Disconnected from\s+(\S+)', re.I),
        'sudo': re.compile(r'(\S+)\s*:\s*.*COMMAND=(.+)$', re.I),
    }
    
    def __init__(self):
        self.syslog_parser = SyslogParser()
    
    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        """Parse auth log line."""
        # First parse as syslog
        entry = self.syslog_parser.parse_line(line, line_number)
        
        if entry.message:
            # Extract IP
            ip_match = self.IP_PATTERN.search(entry.message)
            if ip_match:
                entry.source_ip = ip_match.group(1)
            
            # Extract user
            user_match = self.USER_PATTERN.search(entry.message)
            if user_match:
                entry.user = user_match.group(1)
            
            # Determine auth event type
            for event_type, pattern in self.AUTH_PATTERNS.items():
                match = pattern.search(entry.message)
                if match:
                    entry.extra['auth_event'] = event_type
                    entry.extra['auth_details'] = match.groups()
                    break
            
            # Set level based on message content
            if 'failed' in entry.message.lower() or 'invalid' in entry.message.lower():
                entry.level = 'WARNING'
            elif 'accepted' in entry.message.lower():
                entry.level = 'INFO'
            elif 'error' in entry.message.lower():
                entry.level = 'ERROR'
        
        return entry


class JSONLogParser(BaseParser):
    """
    Parser for JSON-structured logs.
    
    Handles logs where each line is a JSON object.
    """
    
    name = "json"
    
    # Common field mappings
    FIELD_MAPPINGS = {
        'timestamp': ['timestamp', '@timestamp', 'time', 'datetime', 'date', 'ts'],
        'source_ip': ['source_ip', 'client_ip', 'ip', 'remote_addr', 'clientip', 'src_ip'],
        'user': ['user', 'username', 'user_name', 'userid'],
        'method': ['method', 'http_method', 'request_method'],
        'path': ['path', 'url', 'uri', 'request_uri', 'request_path'],
        'status_code': ['status', 'status_code', 'http_status', 'response_code'],
        'message': ['message', 'msg', 'log', 'text'],
        'level': ['level', 'severity', 'log_level', 'loglevel'],
        'hostname': ['hostname', 'host', 'server', 'node'],
        'service': ['service', 'application', 'app', 'program'],
    }
    
    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        """Parse JSON log line."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            return LogEntry(
                raw=line,
                line_number=line_number,
                parse_error=f"Invalid JSON: {e}"
            )
        
        # Extract known fields
        extracted = {}
        remaining = dict(data)
        
        for field, aliases in self.FIELD_MAPPINGS.items():
            for alias in aliases:
                if alias in data:
                    extracted[field] = data[alias]
                    remaining.pop(alias, None)
                    break
        
        # Parse timestamp
        timestamp = None
        if extracted.get('timestamp'):
            timestamp = self._parse_timestamp(extracted['timestamp'])
        
        return LogEntry(
            raw=line,
            timestamp=timestamp,
            source_ip=extracted.get('source_ip'),
            user=extracted.get('user'),
            method=extracted.get('method'),
            path=extracted.get('path'),
            status_code=self._safe_int(extracted.get('status_code')),
            message=extracted.get('message'),
            level=extracted.get('level'),
            hostname=extracted.get('hostname'),
            service=extracted.get('service'),
            line_number=line_number,
            extra=remaining,
        )
    
    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        """Parse various timestamp formats."""
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value)
            except:
                return datetime.fromtimestamp(value / 1000)  # milliseconds
        
        if isinstance(value, str):
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
        
        return None
    
    def _safe_int(self, value: Any) -> Optional[int]:
        """Safely convert to int."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None


class AutoParser(BaseParser):
    """
    Auto-detecting parser that identifies log format.
    
    Analyzes sample lines to determine the appropriate parser.
    """
    
    name = "auto"
    
    PARSERS: List[Type[BaseParser]] = [
        JSONLogParser,
        ApacheParser,
        NginxParser,
        AuthLogParser,
        SyslogParser,
    ]
    
    def __init__(self):
        self._detected_parser: Optional[BaseParser] = None
    
    def detect_format(self, sample_lines: List[str]) -> BaseParser:
        """Detect log format from sample lines."""
        scores = {parser: 0 for parser in self.PARSERS}
        
        for line in sample_lines[:20]:  # Check first 20 lines
            line = line.strip()
            if not line:
                continue
            
            for parser_class in self.PARSERS:
                parser = parser_class()
                entry = parser.parse_line(line)
                
                if not entry.parse_error:
                    scores[parser_class] += 1
                    
                    # Bonus for extracted fields
                    if entry.timestamp:
                        scores[parser_class] += 1
                    if entry.source_ip:
                        scores[parser_class] += 1
        
        # Return parser with highest score
        best_parser = max(scores, key=scores.get)
        logger.info(f"Auto-detected format: {best_parser.name}")
        return best_parser()
    
    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        """Parse line using detected or fallback parser."""
        if self._detected_parser:
            return self._detected_parser.parse_line(line, line_number)
        
        # Try each parser
        for parser_class in self.PARSERS:
            parser = parser_class()
            entry = parser.parse_line(line, line_number)
            if not entry.parse_error:
                return entry
        
        # Return unparsed entry
        return LogEntry(
            raw=line,
            message=line,
            line_number=line_number,
        )
    
    def parse_file(self, filepath: str) -> Iterator[LogEntry]:
        """Parse file with auto-detection."""
        path = Path(filepath)
        
        # Read sample for detection
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            sample = [f.readline() for _ in range(20)]
        
        self._detected_parser = self.detect_format(sample)
        
        # Now parse full file
        yield from self._detected_parser.parse_file(filepath)


def get_parser(name: str) -> BaseParser:
    """Get parser by name."""
    parsers = {
        'apache': ApacheParser,
        'nginx': NginxParser,
        'syslog': SyslogParser,
        'auth': AuthLogParser,
        'authlog': AuthLogParser,
        'json': JSONLogParser,
        'auto': AutoParser,
    }
    
    parser_class = parsers.get(name.lower())
    if not parser_class:
        raise ValueError(f"Unknown parser: {name}")
    
    return parser_class()


if __name__ == "__main__":
    # Demo parsing
    logging.basicConfig(level=logging.DEBUG)
    
    # Test Apache log
    apache_line = '192.168.1.1 - admin [10/Oct/2023:13:55:36 +0000] "GET /admin.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    parser = ApacheParser()
    entry = parser.parse_line(apache_line)
    print(f"Apache: IP={entry.source_ip}, Path={entry.path}, Status={entry.status_code}")
    
    # Test auth log
    auth_line = 'Jan 10 12:34:56 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2'
    parser = AuthLogParser()
    entry = parser.parse_line(auth_line)
    print(f"Auth: IP={entry.source_ip}, User={entry.user}, Event={entry.extra.get('auth_event')}")

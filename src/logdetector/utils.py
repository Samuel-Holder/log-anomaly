"""
Utility Functions

Helper utilities for log analysis operations.
"""

import re
import logging
import ipaddress
from typing import Optional, List, Dict, Set
from datetime import datetime

logger = logging.getLogger(__name__)


# === IP Address Utilities ===

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_ip_in_network(ip: str, network: str) -> bool:
    """Check if IP is in a network range."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


# === Whitelist/Blacklist ===

class IPFilter:
    """IP address whitelist/blacklist filter."""
    
    def __init__(
        self,
        whitelist: List[str] = None,
        blacklist: List[str] = None,
    ):
        self.whitelist_ips: Set[str] = set()
        self.whitelist_networks: List[ipaddress.IPv4Network] = []
        self.blacklist_ips: Set[str] = set()
        self.blacklist_networks: List[ipaddress.IPv4Network] = []
        
        if whitelist:
            for item in whitelist:
                if '/' in item:
                    self.whitelist_networks.append(ipaddress.ip_network(item, strict=False))
                else:
                    self.whitelist_ips.add(item)
        
        if blacklist:
            for item in blacklist:
                if '/' in item:
                    self.blacklist_networks.append(ipaddress.ip_network(item, strict=False))
                else:
                    self.blacklist_ips.add(item)
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        if not self.whitelist_ips and not self.whitelist_networks:
            return False
        
        if ip in self.whitelist_ips:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in self.whitelist_networks)
        except ValueError:
            return False
    
    def is_blacklisted(self, ip: str) -> bool:
        """Check if IP is blacklisted."""
        if ip in self.blacklist_ips:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in self.blacklist_networks)
        except ValueError:
            return False


# === Text Processing ===

def decode_url(url: str) -> str:
    """URL decode a string."""
    from urllib.parse import unquote
    # Double decode to catch double-encoded attacks
    decoded = unquote(unquote(url))
    return decoded


def normalize_path(path: str) -> str:
    """Normalize a URL path."""
    if not path:
        return path
    
    # Decode URL encoding
    path = decode_url(path)
    
    # Remove query string for normalization
    if '?' in path:
        path = path.split('?')[0]
    
    # Collapse multiple slashes
    path = re.sub(r'/+', '/', path)
    
    return path


def extract_ips(text: str) -> List[str]:
    """Extract all IP addresses from text."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, text)


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text."""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)


# === Time Utilities ===

def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse various timestamp formats."""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue
    
    return None


def is_off_hours(timestamp: datetime, start_hour: int = 6, end_hour: int = 22) -> bool:
    """Check if timestamp is outside business hours."""
    return timestamp.hour < start_hour or timestamp.hour >= end_hour


def is_weekend(timestamp: datetime) -> bool:
    """Check if timestamp is on a weekend."""
    return timestamp.weekday() >= 5


# === HTTP Utilities ===

HTTP_STATUS_MESSAGES = {
    200: "OK",
    201: "Created",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


def is_error_status(status_code: int) -> bool:
    """Check if HTTP status indicates an error."""
    return status_code >= 400


def is_client_error(status_code: int) -> bool:
    """Check if HTTP status is a client error (4xx)."""
    return 400 <= status_code < 500


def is_server_error(status_code: int) -> bool:
    """Check if HTTP status is a server error (5xx)."""
    return status_code >= 500


# === Logging Setup ===

def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    format_str: str = None,
):
    """Configure logging for the application."""
    if format_str is None:
        format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler()]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=handlers,
    )


# === File Utilities ===

def guess_log_type(filepath: str) -> str:
    """Guess log type from filename."""
    filepath_lower = filepath.lower()
    
    if 'access' in filepath_lower or 'apache' in filepath_lower:
        return 'apache'
    elif 'nginx' in filepath_lower:
        return 'nginx'
    elif 'auth' in filepath_lower or 'secure' in filepath_lower:
        return 'authlog'
    elif 'syslog' in filepath_lower or 'messages' in filepath_lower:
        return 'syslog'
    elif filepath_lower.endswith('.json') or filepath_lower.endswith('.jsonl'):
        return 'json'
    
    return 'auto'


def count_lines(filepath: str) -> int:
    """Count lines in a file efficiently."""
    count = 0
    with open(filepath, 'rb') as f:
        for _ in f:
            count += 1
    return count


if __name__ == "__main__":
    # Test utilities
    print("=== IP Tests ===")
    print(f"Valid IP: {is_valid_ip('192.168.1.1')}")
    print(f"Private IP: {is_private_ip('192.168.1.1')}")
    print(f"Public IP: {is_private_ip('8.8.8.8')}")
    
    print("\n=== IP Filter ===")
    ip_filter = IPFilter(
        whitelist=["192.168.1.0/24", "10.0.0.1"],
        blacklist=["192.168.1.100"]
    )
    print(f"192.168.1.50 whitelisted: {ip_filter.is_whitelisted('192.168.1.50')}")
    print(f"192.168.1.100 blacklisted: {ip_filter.is_blacklisted('192.168.1.100')}")
    
    print("\n=== Text Extraction ===")
    text = "Connection from 192.168.1.1 and 10.0.0.5, email: admin@example.com"
    print(f"IPs: {extract_ips(text)}")
    print(f"Emails: {extract_emails(text)}")

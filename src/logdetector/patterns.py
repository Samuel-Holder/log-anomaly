"""
Attack Patterns Module

Contains regex patterns and signatures for detecting various
security threats and attack attempts in log files.
"""

import re
from dataclasses import dataclass
from typing import List, Pattern, Optional, Dict
from enum import Enum


class ThreatCategory(Enum):
    """Categories of security threats."""
    INJECTION = "injection"
    XSS = "xss"
    TRAVERSAL = "traversal"
    BRUTE_FORCE = "brute_force"
    RECONNAISSANCE = "reconnaissance"
    MALWARE = "malware"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    DOS = "denial_of_service"
    WEB_ATTACK = "web_attack"


@dataclass
class AttackPattern:
    """Represents an attack signature pattern."""
    
    name: str
    pattern: Pattern
    category: ThreatCategory
    severity: str  # critical, high, medium, low
    description: str
    cve: Optional[str] = None
    mitre_id: Optional[str] = None
    
    def match(self, text: str) -> bool:
        """Check if pattern matches text."""
        return bool(self.pattern.search(text))
    
    def find_all(self, text: str) -> List[str]:
        """Find all matches in text."""
        return self.pattern.findall(text)


class AttackPatterns:
    """Collection of attack detection patterns."""
    
    # === SQL Injection Patterns ===
    SQL_INJECTION = [
        AttackPattern(
            name="SQL Union Injection",
            pattern=re.compile(
                r"(?:union\s+(?:all\s+)?select|select\s+.*\s+from\s+.*\s+where)",
                re.IGNORECASE
            ),
            category=ThreatCategory.INJECTION,
            severity="high",
            description="SQL UNION-based injection attempt",
            mitre_id="T1190",
        ),
        AttackPattern(
            name="SQL Comment Injection",
            pattern=re.compile(
                r"(?:--|#|\/\*|\*\/|;)\s*(?:select|insert|update|delete|drop|union|exec)",
                re.IGNORECASE
            ),
            category=ThreatCategory.INJECTION,
            severity="high",
            description="SQL comment-based injection attempt",
        ),
        AttackPattern(
            name="SQL Boolean Injection",
            pattern=re.compile(
                r"(?:'\s*(?:or|and)\s*'?\d*'?\s*[=<>]|(?:or|and)\s+\d+\s*[=<>]\s*\d+)",
                re.IGNORECASE
            ),
            category=ThreatCategory.INJECTION,
            severity="high",
            description="SQL boolean-based blind injection attempt",
        ),
        AttackPattern(
            name="SQL Time-based Injection",
            pattern=re.compile(
                r"(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep)",
                re.IGNORECASE
            ),
            category=ThreatCategory.INJECTION,
            severity="high",
            description="SQL time-based blind injection attempt",
        ),
        AttackPattern(
            name="SQL Stacked Queries",
            pattern=re.compile(
                r";\s*(?:select|insert|update|delete|drop|create|alter|exec|execute)",
                re.IGNORECASE
            ),
            category=ThreatCategory.INJECTION,
            severity="high",
            description="SQL stacked query injection attempt",
        ),
    ]
    
    # === XSS Patterns ===
    XSS_PATTERNS = [
        AttackPattern(
            name="Script Tag XSS",
            pattern=re.compile(
                r"<\s*script[^>]*>|<\s*/\s*script\s*>",
                re.IGNORECASE
            ),
            category=ThreatCategory.XSS,
            severity="high",
            description="Script tag injection attempt",
            mitre_id="T1059.007",
        ),
        AttackPattern(
            name="Event Handler XSS",
            pattern=re.compile(
                r"(?:on(?:load|error|click|mouse|focus|blur|change|submit|key|touch)\s*=)",
                re.IGNORECASE
            ),
            category=ThreatCategory.XSS,
            severity="high",
            description="Event handler injection attempt",
        ),
        AttackPattern(
            name="JavaScript Protocol XSS",
            pattern=re.compile(
                r"javascript\s*:|vbscript\s*:|data\s*:[^,]*;base64",
                re.IGNORECASE
            ),
            category=ThreatCategory.XSS,
            severity="high",
            description="JavaScript protocol injection attempt",
        ),
        AttackPattern(
            name="SVG XSS",
            pattern=re.compile(
                r"<\s*svg[^>]*(?:onload|onerror)\s*=",
                re.IGNORECASE
            ),
            category=ThreatCategory.XSS,
            severity="medium",
            description="SVG-based XSS attempt",
        ),
        AttackPattern(
            name="IMG Tag XSS",
            pattern=re.compile(
                r"<\s*img[^>]*(?:onerror|onload)\s*=",
                re.IGNORECASE
            ),
            category=ThreatCategory.XSS,
            severity="medium",
            description="IMG tag event handler XSS attempt",
        ),
    ]
    
    # === Path Traversal Patterns ===
    PATH_TRAVERSAL = [
        AttackPattern(
            name="Directory Traversal",
            pattern=re.compile(
                r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./){2,}",
                re.IGNORECASE
            ),
            category=ThreatCategory.TRAVERSAL,
            severity="high",
            description="Directory traversal attempt",
            mitre_id="T1083",
        ),
        AttackPattern(
            name="Null Byte Injection",
            pattern=re.compile(
                r"%00|\\x00|\\0",
                re.IGNORECASE
            ),
            category=ThreatCategory.TRAVERSAL,
            severity="high",
            description="Null byte injection attempt",
        ),
        AttackPattern(
            name="Sensitive File Access",
            pattern=re.compile(
                r"(?:/etc/(?:passwd|shadow|hosts|sudoers)|"
                r"(?:c:|C:)\\\\(?:windows|winnt)\\\\system32|"
                r"\.(?:htaccess|htpasswd|git|svn|env))",
                re.IGNORECASE
            ),
            category=ThreatCategory.TRAVERSAL,
            severity="critical",
            description="Attempt to access sensitive system files",
        ),
    ]
    
    # === Command Injection Patterns ===
    COMMAND_INJECTION = [
        AttackPattern(
            name="Shell Command Injection",
            pattern=re.compile(
                r"(?:;|\||`|\$\(|\$\{)\s*(?:cat|ls|id|whoami|pwd|uname|wget|curl|nc|bash|sh|perl|python|php|ruby)",
                re.IGNORECASE
            ),
            category=ThreatCategory.INJECTION,
            severity="critical",
            description="Shell command injection attempt",
            mitre_id="T1059",
        ),
        AttackPattern(
            name="Reverse Shell",
            pattern=re.compile(
                r"(?:bash\s+-i|nc\s+-e|python\s+-c.*socket|perl\s+-e.*socket|/dev/tcp/)",
                re.IGNORECASE
            ),
            category=ThreatCategory.INJECTION,
            severity="critical",
            description="Reverse shell attempt",
        ),
        AttackPattern(
            name="Command Substitution",
            pattern=re.compile(
                r"`[^`]+`|\$\([^)]+\)",
            ),
            category=ThreatCategory.INJECTION,
            severity="high",
            description="Command substitution attempt",
        ),
    ]
    
    # === Web Shell Patterns ===
    WEB_SHELL = [
        AttackPattern(
            name="PHP Web Shell",
            pattern=re.compile(
                r"(?:c99|r57|wso|b374k|weevely|phpspy|alfa|shell)\.php",
                re.IGNORECASE
            ),
            category=ThreatCategory.MALWARE,
            severity="critical",
            description="Known web shell access attempt",
            mitre_id="T1505.003",
        ),
        AttackPattern(
            name="Web Shell Parameters",
            pattern=re.compile(
                r"(?:cmd|command|exec|execute|shell|run)=",
                re.IGNORECASE
            ),
            category=ThreatCategory.MALWARE,
            severity="high",
            description="Potential web shell command parameter",
        ),
    ]
    
    # === Reconnaissance Patterns ===
    RECONNAISSANCE = [
        AttackPattern(
            name="Scanner User Agent",
            pattern=re.compile(
                r"(?:nikto|nmap|sqlmap|dirb|dirbuster|gobuster|wfuzz|burp|masscan|zap|acunetix|nessus|openvas)",
                re.IGNORECASE
            ),
            category=ThreatCategory.RECONNAISSANCE,
            severity="medium",
            description="Security scanner detected",
            mitre_id="T1595",
        ),
        AttackPattern(
            name="Admin Path Enumeration",
            pattern=re.compile(
                r"/(?:admin|administrator|wp-admin|phpmyadmin|manager|cpanel|webadmin|siteadmin|panel)",
                re.IGNORECASE
            ),
            category=ThreatCategory.RECONNAISSANCE,
            severity="low",
            description="Administrative path enumeration",
        ),
        AttackPattern(
            name="Backup File Discovery",
            pattern=re.compile(
                r"\.(?:bak|backup|old|orig|copy|tmp|temp|swp|sav)(?:\?|$|#)",
                re.IGNORECASE
            ),
            category=ThreatCategory.RECONNAISSANCE,
            severity="medium",
            description="Backup file discovery attempt",
        ),
    ]
    
    # === Authentication Attacks ===
    AUTH_ATTACKS = [
        AttackPattern(
            name="Failed SSH Login",
            pattern=re.compile(
                r"(?:Failed password|authentication failure|Invalid user|Bad protocol)",
                re.IGNORECASE
            ),
            category=ThreatCategory.BRUTE_FORCE,
            severity="medium",
            description="Failed authentication attempt",
            mitre_id="T1110",
        ),
        AttackPattern(
            name="Root Login Attempt",
            pattern=re.compile(
                r"(?:user=?root|for root|ROOT LOGIN)",
                re.IGNORECASE
            ),
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            severity="high",
            description="Root/administrator login attempt",
        ),
        AttackPattern(
            name="Sudo Abuse",
            pattern=re.compile(
                r"sudo:.*COMMAND=(?:/bin/(?:bash|sh)|.*(?:passwd|shadow|sudoers))",
                re.IGNORECASE
            ),
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            severity="high",
            description="Suspicious sudo command execution",
        ),
    ]
    
    # === Log Tampering ===
    LOG_TAMPERING = [
        AttackPattern(
            name="Log Injection",
            pattern=re.compile(
                r"(?:\r\n|\n|\r).*(?:INFO|WARN|ERROR|DEBUG|CRITICAL)",
                re.IGNORECASE
            ),
            category=ThreatCategory.DATA_EXFILTRATION,
            severity="medium",
            description="Potential log injection attempt",
        ),
    ]
    
    @classmethod
    def get_all_patterns(cls) -> List[AttackPattern]:
        """Get all attack patterns."""
        all_patterns = []
        all_patterns.extend(cls.SQL_INJECTION)
        all_patterns.extend(cls.XSS_PATTERNS)
        all_patterns.extend(cls.PATH_TRAVERSAL)
        all_patterns.extend(cls.COMMAND_INJECTION)
        all_patterns.extend(cls.WEB_SHELL)
        all_patterns.extend(cls.RECONNAISSANCE)
        all_patterns.extend(cls.AUTH_ATTACKS)
        all_patterns.extend(cls.LOG_TAMPERING)
        return all_patterns
    
    @classmethod
    def get_patterns_by_category(cls, category: ThreatCategory) -> List[AttackPattern]:
        """Get patterns for a specific category."""
        return [p for p in cls.get_all_patterns() if p.category == category]
    
    @classmethod
    def get_patterns_by_severity(cls, severity: str) -> List[AttackPattern]:
        """Get patterns of a specific severity."""
        return [p for p in cls.get_all_patterns() if p.severity == severity]


# Pre-compiled pattern sets for quick matching
CRITICAL_PATTERNS = AttackPatterns.get_patterns_by_severity("critical")
HIGH_PATTERNS = AttackPatterns.get_patterns_by_severity("high")
INJECTION_PATTERNS = AttackPatterns.get_patterns_by_category(ThreatCategory.INJECTION)
XSS_DETECTION_PATTERNS = AttackPatterns.get_patterns_by_category(ThreatCategory.XSS)


def check_for_attacks(text: str, patterns: List[AttackPattern] = None) -> List[AttackPattern]:
    """
    Check text against attack patterns.
    
    Args:
        text: Text to check
        patterns: Specific patterns to check (default: all)
        
    Returns:
        List of matched attack patterns
    """
    if patterns is None:
        patterns = AttackPatterns.get_all_patterns()
    
    matches = []
    for pattern in patterns:
        if pattern.match(text):
            matches.append(pattern)
    
    return matches


def get_threat_score(matches: List[AttackPattern]) -> int:
    """
    Calculate threat score based on matched patterns.
    
    Args:
        matches: List of matched patterns
        
    Returns:
        Threat score (0-100)
    """
    if not matches:
        return 0
    
    severity_scores = {
        'critical': 40,
        'high': 25,
        'medium': 15,
        'low': 5,
    }
    
    score = sum(severity_scores.get(m.severity, 5) for m in matches)
    return min(100, score)


if __name__ == "__main__":
    # Test patterns
    test_cases = [
        "GET /admin.php?id=1' UNION SELECT * FROM users-- HTTP/1.1",
        "GET /page?name=<script>alert('xss')</script> HTTP/1.1",
        "GET /files/../../../etc/passwd HTTP/1.1",
        "GET /cmd?exec=;cat /etc/shadow HTTP/1.1",
        "GET /shell.php?cmd=whoami HTTP/1.1",
        "Failed password for invalid user admin from 192.168.1.1",
    ]
    
    print("Testing attack patterns:\n")
    for test in test_cases:
        matches = check_for_attacks(test)
        score = get_threat_score(matches)
        print(f"Input: {test[:60]}...")
        print(f"  Matches: {[m.name for m in matches]}")
        print(f"  Threat Score: {score}")
        print()

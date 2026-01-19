"""
Alerts Module

Provides alert generation, management, and filtering capabilities.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def numeric(self) -> int:
        """Get numeric value for comparison."""
        values = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        return values[self.value]
    
    def __lt__(self, other):
        return self.numeric < other.numeric
    
    def __le__(self, other):
        return self.numeric <= other.numeric
    
    def __gt__(self, other):
        return self.numeric > other.numeric
    
    def __ge__(self, other):
        return self.numeric >= other.numeric


@dataclass
class Alert:
    """Represents a security alert."""
    
    severity: AlertSeverity
    message: str
    source: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    detector: Optional[str] = None
    log_entry: Any = None
    context: Dict[str, Any] = field(default_factory=dict)
    alert_id: str = field(default="")
    acknowledged: bool = False
    false_positive: bool = False
    notes: str = ""
    
    def __post_init__(self):
        if not self.alert_id:
            self.alert_id = f"{self.timestamp.strftime('%Y%m%d%H%M%S')}-{id(self)}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "severity": self.severity.value,
            "message": self.message,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "detector": self.detector,
            "context": self.context,
            "acknowledged": self.acknowledged,
            "false_positive": self.false_positive,
            "notes": self.notes,
            "log_line": self.log_entry.line_number if self.log_entry else None,
        }
    
    def acknowledge(self, notes: str = ""):
        """Mark alert as acknowledged."""
        self.acknowledged = True
        self.notes = notes
    
    def mark_false_positive(self, notes: str = ""):
        """Mark alert as false positive."""
        self.false_positive = True
        self.notes = notes


class AlertManager:
    """
    Manages alerts, deduplication, and filtering.
    """
    
    def __init__(
        self,
        min_severity: AlertSeverity = AlertSeverity.LOW,
        dedup_window: int = 300,  # seconds
        max_alerts: int = 10000,
    ):
        """
        Initialize alert manager.
        
        Args:
            min_severity: Minimum severity to track
            dedup_window: Window for deduplication in seconds
            max_alerts: Maximum alerts to store
        """
        self.min_severity = min_severity
        self.dedup_window = dedup_window
        self.max_alerts = max_alerts
        
        self.alerts: List[Alert] = []
        self.alert_counts: Dict[str, int] = defaultdict(int)
        
        # Deduplication tracking
        self._seen_hashes: Dict[str, datetime] = {}
        
        # Callbacks
        self.on_alert: Optional[Callable[[Alert], None]] = None
        self.on_critical: Optional[Callable[[Alert], None]] = None
    
    def _get_dedup_hash(self, alert: Alert) -> str:
        """Generate hash for deduplication."""
        return f"{alert.detector}:{alert.source}:{alert.message[:50]}"
    
    def _is_duplicate(self, alert: Alert) -> bool:
        """Check if alert is a duplicate."""
        hash_key = self._get_dedup_hash(alert)
        
        if hash_key in self._seen_hashes:
            last_seen = self._seen_hashes[hash_key]
            if (alert.timestamp - last_seen).total_seconds() < self.dedup_window:
                return True
        
        self._seen_hashes[hash_key] = alert.timestamp
        return False
    
    def add_alert(self, alert: Alert) -> bool:
        """
        Add alert to manager.
        
        Args:
            alert: Alert to add
            
        Returns:
            True if alert was added, False if filtered/deduplicated
        """
        # Check severity threshold
        if alert.severity < self.min_severity:
            return False
        
        # Check for duplicates
        if self._is_duplicate(alert):
            logger.debug(f"Duplicate alert filtered: {alert.message[:50]}")
            return False
        
        # Add alert
        self.alerts.append(alert)
        self.alert_counts[alert.severity.value] += 1
        
        # Trim if needed
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]
        
        # Trigger callbacks
        if self.on_alert:
            self.on_alert(alert)
        
        if alert.severity == AlertSeverity.CRITICAL and self.on_critical:
            self.on_critical(alert)
        
        logger.info(f"Alert added: [{alert.severity.value}] {alert.message[:60]}")
        return True
    
    def get_alerts(
        self,
        severity: AlertSeverity = None,
        detector: str = None,
        source: str = None,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = None,
    ) -> List[Alert]:
        """
        Get filtered alerts.
        
        Args:
            severity: Filter by minimum severity
            detector: Filter by detector name
            source: Filter by source IP
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum alerts to return
            
        Returns:
            Filtered list of alerts
        """
        filtered = self.alerts
        
        if severity:
            filtered = [a for a in filtered if a.severity >= severity]
        
        if detector:
            filtered = [a for a in filtered if a.detector == detector]
        
        if source:
            filtered = [a for a in filtered if a.source == source]
        
        if start_time:
            filtered = [a for a in filtered if a.timestamp >= start_time]
        
        if end_time:
            filtered = [a for a in filtered if a.timestamp <= end_time]
        
        if limit:
            filtered = filtered[-limit:]
        
        return filtered
    
    def get_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics."""
        severity_counts = defaultdict(int)
        source_counts = defaultdict(int)
        detector_counts = defaultdict(int)
        
        for alert in self.alerts:
            severity_counts[alert.severity.value] += 1
            if alert.source:
                source_counts[alert.source] += 1
            if alert.detector:
                detector_counts[alert.detector] += 1
        
        # Top sources
        top_sources = sorted(
            source_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "total_alerts": len(self.alerts),
            "by_severity": dict(severity_counts),
            "by_detector": dict(detector_counts),
            "top_sources": top_sources,
            "acknowledged": sum(1 for a in self.alerts if a.acknowledged),
            "false_positives": sum(1 for a in self.alerts if a.false_positive),
        }
    
    def get_critical_alerts(self) -> List[Alert]:
        """Get all critical alerts."""
        return [a for a in self.alerts if a.severity == AlertSeverity.CRITICAL]
    
    def get_unacknowledged(self) -> List[Alert]:
        """Get all unacknowledged alerts."""
        return [a for a in self.alerts if not a.acknowledged and not a.false_positive]
    
    def acknowledge_all(self, notes: str = ""):
        """Acknowledge all alerts."""
        for alert in self.alerts:
            alert.acknowledge(notes)
    
    def clear(self):
        """Clear all alerts."""
        self.alerts.clear()
        self.alert_counts.clear()
        self._seen_hashes.clear()
    
    def export_alerts(self) -> List[Dict]:
        """Export all alerts as dictionaries."""
        return [alert.to_dict() for alert in self.alerts]


class AlertFormatter:
    """Formats alerts for display."""
    
    SEVERITY_COLORS = {
        AlertSeverity.CRITICAL: "\033[91m",  # Red
        AlertSeverity.HIGH: "\033[93m",      # Yellow
        AlertSeverity.MEDIUM: "\033[94m",    # Blue
        AlertSeverity.LOW: "\033[96m",       # Cyan
        AlertSeverity.INFO: "\033[97m",      # White
    }
    RESET = "\033[0m"
    
    @classmethod
    def format_console(cls, alert: Alert, use_colors: bool = True) -> str:
        """Format alert for console output."""
        if use_colors:
            color = cls.SEVERITY_COLORS.get(alert.severity, "")
            severity_str = f"{color}[{alert.severity.value.upper()}]{cls.RESET}"
        else:
            severity_str = f"[{alert.severity.value.upper()}]"
        
        timestamp = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        source = alert.source or "unknown"
        
        return f"{timestamp} {severity_str} {source}: {alert.message}"
    
    @classmethod
    def format_short(cls, alert: Alert) -> str:
        """Short format for summaries."""
        return f"[{alert.severity.value.upper()}] {alert.message[:50]}"


if __name__ == "__main__":
    # Test alert management
    manager = AlertManager()
    
    # Add some test alerts
    manager.add_alert(Alert(
        severity=AlertSeverity.HIGH,
        message="SQL Injection attempt detected",
        source="192.168.1.100",
        detector="sqli"
    ))
    
    manager.add_alert(Alert(
        severity=AlertSeverity.CRITICAL,
        message="Web shell access detected",
        source="10.0.0.50",
        detector="webshell"
    ))
    
    manager.add_alert(Alert(
        severity=AlertSeverity.MEDIUM,
        message="Brute force detected",
        source="192.168.1.100",
        detector="bruteforce"
    ))
    
    # Get summary
    summary = manager.get_summary()
    print("Alert Summary:")
    print(f"  Total: {summary['total_alerts']}")
    print(f"  By Severity: {summary['by_severity']}")
    
    # Print alerts
    print("\nAlerts:")
    for alert in manager.alerts:
        print(f"  {AlertFormatter.format_console(alert)}")

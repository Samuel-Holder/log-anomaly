"""
Log Anomaly Detector

A security tool for detecting anomalies, threats, and suspicious
patterns in log files.
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__license__ = "MIT"

from .parsers import (
    BaseParser,
    ApacheParser,
    NginxParser,
    SyslogParser,
    AuthLogParser,
    JSONLogParser,
    AutoParser,
)
from .detectors import (
    BaseDetector,
    BruteForceDetector,
    SQLInjectionDetector,
    XSSDetector,
    PathTraversalDetector,
    AnomalyDetector,
)
from .analyzer import LogAnalyzer, AnalysisResult
from .alerts import Alert, AlertSeverity, AlertManager
from .reporters import Reporter, JSONReporter, HTMLReporter, CSVReporter

__all__ = [
    # Parsers
    "BaseParser",
    "ApacheParser",
    "NginxParser",
    "SyslogParser",
    "AuthLogParser",
    "JSONLogParser",
    "AutoParser",
    # Detectors
    "BaseDetector",
    "BruteForceDetector",
    "SQLInjectionDetector",
    "XSSDetector",
    "PathTraversalDetector",
    "AnomalyDetector",
    # Core
    "LogAnalyzer",
    "AnalysisResult",
    # Alerts
    "Alert",
    "AlertSeverity",
    "AlertManager",
    # Reporters
    "Reporter",
    "JSONReporter",
    "HTMLReporter",
    "CSVReporter",
]

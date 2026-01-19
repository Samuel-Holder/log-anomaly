"""
Log Analyzer Module

Main orchestrator for log analysis, combining parsers, detectors,
and output generation.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator
import glob

from .parsers import BaseParser, AutoParser, LogEntry, get_parser
from .detectors import BaseDetector, CompositeDetector, DetectionResult, get_detector
from .alerts import Alert, AlertManager, AlertSeverity

logger = logging.getLogger(__name__)


@dataclass
class AnalysisStats:
    """Statistics from log analysis."""
    
    total_entries: int = 0
    parsed_entries: int = 0
    parse_errors: int = 0
    anomaly_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    top_sources: Dict[str, int] = field(default_factory=dict)
    by_detector: Dict[str, int] = field(default_factory=dict)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status_codes: Dict[int, int] = field(default_factory=dict)
    methods: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_entries": self.total_entries,
            "parsed_entries": self.parsed_entries,
            "parse_errors": self.parse_errors,
            "anomaly_count": self.anomaly_count,
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "top_sources": dict(sorted(
                self.top_sources.items(), key=lambda x: x[1], reverse=True
            )[:20]),
            "by_detector": self.by_detector,
            "time_range": {
                "start": self.start_time.isoformat() if self.start_time else None,
                "end": self.end_time.isoformat() if self.end_time else None,
            },
            "status_codes": self.status_codes,
            "methods": self.methods,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result."""
    
    filepath: str
    stats: AnalysisStats
    alerts: List[Alert]
    start_time: datetime
    end_time: datetime
    parser_used: str
    detectors_used: List[str]
    
    @property
    def duration(self) -> float:
        return (self.end_time - self.start_time).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "filepath": self.filepath,
            "stats": self.stats.to_dict(),
            "alerts": [a.to_dict() for a in self.alerts],
            "analysis_time": {
                "start": self.start_time.isoformat(),
                "end": self.end_time.isoformat(),
                "duration_seconds": self.duration,
            },
            "parser": self.parser_used,
            "detectors": self.detectors_used,
        }
    
    def get_critical_alerts(self) -> List[Alert]:
        return [a for a in self.alerts if a.severity == AlertSeverity.CRITICAL]
    
    def get_high_alerts(self) -> List[Alert]:
        return [a for a in self.alerts if a.severity == AlertSeverity.HIGH]


class LogAnalyzer:
    """
    Main log analysis orchestrator.
    
    Example:
        >>> analyzer = LogAnalyzer()
        >>> result = analyzer.analyze_file("/var/log/auth.log")
        >>> print(f"Found {result.stats.anomaly_count} anomalies")
    """
    
    def __init__(
        self,
        parser: BaseParser = None,
        detector: BaseDetector = None,
        min_severity: AlertSeverity = AlertSeverity.LOW,
    ):
        self.parser = parser or AutoParser()
        self.detector = detector or CompositeDetector()
        self.alert_manager = AlertManager(min_severity=min_severity)
        logger.info(f"LogAnalyzer initialized with {self.parser.name} parser")
    
    def _update_stats(self, stats: AnalysisStats, entry: LogEntry, result: Optional[DetectionResult]):
        stats.total_entries += 1
        
        if entry.parse_error:
            stats.parse_errors += 1
        else:
            stats.parsed_entries += 1
        
        if entry.timestamp:
            if not stats.start_time or entry.timestamp < stats.start_time:
                stats.start_time = entry.timestamp
            if not stats.end_time or entry.timestamp > stats.end_time:
                stats.end_time = entry.timestamp
        
        if entry.source_ip:
            stats.top_sources[entry.source_ip] = stats.top_sources.get(entry.source_ip, 0) + 1
        
        if entry.status_code:
            stats.status_codes[entry.status_code] = stats.status_codes.get(entry.status_code, 0) + 1
        
        if entry.method:
            stats.methods[entry.method] = stats.methods.get(entry.method, 0) + 1
        
        if result:
            stats.anomaly_count += 1
            if result.severity == AlertSeverity.CRITICAL:
                stats.critical_count += 1
            elif result.severity == AlertSeverity.HIGH:
                stats.high_count += 1
            elif result.severity == AlertSeverity.MEDIUM:
                stats.medium_count += 1
            elif result.severity == AlertSeverity.LOW:
                stats.low_count += 1
            stats.by_detector[result.detector_name] = stats.by_detector.get(result.detector_name, 0) + 1
    
    def analyze_entry(self, entry: LogEntry) -> Optional[Alert]:
        result = self.detector.detect(entry)
        if result:
            alert = result.to_alert()
            self.alert_manager.add_alert(alert)
            return alert
        return None
    
    def analyze_file(self, filepath: str, parser: BaseParser = None, progress_callback=None) -> AnalysisResult:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        current_parser = parser or self.parser
        start_time = datetime.now()
        stats = AnalysisStats()
        
        self.alert_manager.clear()
        self.detector.reset()
        
        logger.info(f"Starting analysis of {filepath}")
        
        total_lines = sum(1 for _ in open(filepath, 'rb'))
        
        for entry in current_parser.parse_file(filepath):
            result = self.detector.detect(entry)
            self._update_stats(stats, entry, result)
            
            if result:
                alert = result.to_alert()
                self.alert_manager.add_alert(alert)
            
            if progress_callback and stats.total_entries % 1000 == 0:
                progress_callback(stats.total_entries, total_lines)
        
        end_time = datetime.now()
        
        logger.info(f"Analysis complete: {stats.total_entries} entries, {stats.anomaly_count} anomalies")
        
        return AnalysisResult(
            filepath=str(filepath),
            stats=stats,
            alerts=self.alert_manager.alerts.copy(),
            start_time=start_time,
            end_time=end_time,
            parser_used=current_parser.name,
            detectors_used=[d.name for d in getattr(self.detector, 'detectors', [self.detector])],
        )
    
    def analyze_files(self, pattern: str, recursive: bool = False) -> List[AnalysisResult]:
        files = glob.glob(pattern, recursive=recursive)
        results = []
        for filepath in files:
            try:
                result = self.analyze_file(filepath)
                results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing {filepath}: {e}")
        return results
    
    def analyze_stream(self, lines: Iterator[str]) -> Iterator[Alert]:
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            entry = self.parser.parse_line(line, line_num)
            result = self.detector.detect(entry)
            if result:
                alert = result.to_alert()
                if self.alert_manager.add_alert(alert):
                    yield alert
    
    def watch_file(self, filepath: str, callback=None, poll_interval: float = 1.0):
        """Watch log file for new entries (tail -f style)."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        logger.info(f"Watching {filepath}")
        
        with open(filepath, 'r') as f:
            f.seek(0, 2)  # Seek to end
            line_num = 0
            
            while True:
                line = f.readline()
                if line:
                    line_num += 1
                    line = line.strip()
                    if line:
                        entry = self.parser.parse_line(line, line_num)
                        result = self.detector.detect(entry)
                        if result:
                            alert = result.to_alert()
                            if self.alert_manager.add_alert(alert):
                                if callback:
                                    callback(alert)
                                else:
                                    print(f"[{alert.severity.value.upper()}] {alert.message}")
                else:
                    time.sleep(poll_interval)


def quick_analyze(filepath: str) -> AnalysisResult:
    """Convenience function for quick analysis."""
    analyzer = LogAnalyzer()
    return analyzer.analyze_file(filepath)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1:
        result = quick_analyze(sys.argv[1])
        print(f"\nAnalysis Results for {result.filepath}")
        print(f"  Total entries: {result.stats.total_entries}")
        print(f"  Anomalies: {result.stats.anomaly_count}")
        print(f"  Critical: {result.stats.critical_count}")
        print(f"  High: {result.stats.high_count}")
    else:
        print("Usage: python -m logdetector.analyzer <logfile>")

"""
Reporters Module

Generates reports in various formats (JSON, CSV, HTML).
"""

import json
import csv
import io
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from .analyzer import AnalysisResult
from .alerts import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class Reporter(ABC):
    """Abstract base class for reporters."""
    
    @abstractmethod
    def generate(self, result: AnalysisResult) -> str:
        """Generate report content."""
        pass
    
    def save(self, result: AnalysisResult, filepath: str):
        """Save report to file."""
        content = self.generate(result)
        Path(filepath).write_text(content)
        logger.info(f"Report saved to {filepath}")


class JSONReporter(Reporter):
    """Generates JSON reports."""
    
    def generate(self, result: AnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2, default=str)


class CSVReporter(Reporter):
    """Generates CSV reports of alerts."""
    
    def generate(self, result: AnalysisResult) -> str:
        output = io.StringIO()
        
        if not result.alerts:
            return "No alerts found"
        
        fieldnames = [
            'timestamp', 'severity', 'source', 'detector', 
            'message', 'log_line', 'acknowledged'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for alert in result.alerts:
            writer.writerow({
                'timestamp': alert.timestamp.isoformat(),
                'severity': alert.severity.value,
                'source': alert.source,
                'detector': alert.detector,
                'message': alert.message,
                'log_line': alert.log_entry.line_number if alert.log_entry else None,
                'acknowledged': alert.acknowledged,
            })
        
        return output.getvalue()


class HTMLReporter(Reporter):
    """Generates HTML reports."""
    
    SEVERITY_COLORS = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#17a2b8',
        'info': '#6c757d',
    }
    
    def generate(self, result: AnalysisResult) -> str:
        stats = result.stats
        
        # Generate alert rows
        alert_rows = ""
        for alert in result.alerts:
            color = self.SEVERITY_COLORS.get(alert.severity.value, '#6c757d')
            alert_rows += f"""
            <tr>
                <td>{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td><span class="badge" style="background-color: {color}">{alert.severity.value.upper()}</span></td>
                <td>{alert.source or 'N/A'}</td>
                <td>{alert.detector or 'N/A'}</td>
                <td>{alert.message}</td>
            </tr>
            """
        
        # Generate top sources
        top_sources_html = ""
        for ip, count in sorted(stats.top_sources.items(), key=lambda x: x[1], reverse=True)[:10]:
            top_sources_html += f"<tr><td>{ip}</td><td>{count}</td></tr>"
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analysis Report - {Path(result.filepath).name}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }}
        h1 {{ color: #333; margin-bottom: 10px; }}
        h2 {{ color: #555; margin-bottom: 15px; font-size: 1.3em; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #333; }}
        .stat-label {{ color: #666; font-size: 0.9em; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; font-weight: 600; }}
        .meta {{ color: #666; font-size: 0.9em; margin-bottom: 20px; }}
        .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 768px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🔍 Log Analysis Report</h1>
            <p class="meta">
                <strong>File:</strong> {result.filepath}<br>
                <strong>Analyzed:</strong> {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}<br>
                <strong>Duration:</strong> {result.duration:.2f} seconds<br>
                <strong>Parser:</strong> {result.parser_used}
            </p>
        </div>
        
        <div class="card">
            <h2>📊 Summary Statistics</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{stats.total_entries:,}</div>
                    <div class="stat-label">Total Entries</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{stats.anomaly_count:,}</div>
                    <div class="stat-label">Anomalies</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value critical">{stats.critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value high">{stats.high_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value medium">{stats.medium_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value low">{stats.low_count}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>
        
        <div class="two-col">
            <div class="card">
                <h2>🌐 Top Source IPs</h2>
                <table>
                    <thead><tr><th>IP Address</th><th>Requests</th></tr></thead>
                    <tbody>{top_sources_html if top_sources_html else '<tr><td colspan="2">No data</td></tr>'}</tbody>
                </table>
            </div>
            <div class="card">
                <h2>🔧 Detection Breakdown</h2>
                <table>
                    <thead><tr><th>Detector</th><th>Alerts</th></tr></thead>
                    <tbody>
                        {''.join(f'<tr><td>{d}</td><td>{c}</td></tr>' for d, c in stats.by_detector.items()) or '<tr><td colspan="2">No detections</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="card">
            <h2>🚨 Alerts ({len(result.alerts)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Source</th>
                        <th>Detector</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    {alert_rows if alert_rows else '<tr><td colspan="5">No alerts generated</td></tr>'}
                </tbody>
            </table>
        </div>
        
        <div class="card" style="text-align: center; color: #666;">
            <p>Generated by Log Anomaly Detector v1.0.0</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html


class ConsoleReporter(Reporter):
    """Generates console-friendly output."""
    
    COLORS = {
        'critical': '\033[91m',
        'high': '\033[93m',
        'medium': '\033[94m',
        'low': '\033[96m',
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    
    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors
    
    def _color(self, text: str, color: str) -> str:
        if not self.use_colors:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"
    
    def generate(self, result: AnalysisResult) -> str:
        stats = result.stats
        lines = []
        
        lines.append("")
        lines.append(self._color("=" * 60, 'bold'))
        lines.append(self._color(f"  LOG ANALYSIS REPORT", 'bold'))
        lines.append(self._color("=" * 60, 'bold'))
        lines.append("")
        lines.append(f"  File: {result.filepath}")
        lines.append(f"  Parser: {result.parser_used}")
        lines.append(f"  Duration: {result.duration:.2f}s")
        lines.append("")
        
        lines.append(self._color("  STATISTICS", 'bold'))
        lines.append("-" * 40)
        lines.append(f"  Total Entries:    {stats.total_entries:,}")
        lines.append(f"  Parse Errors:     {stats.parse_errors:,}")
        lines.append(f"  Anomalies Found:  {stats.anomaly_count:,}")
        lines.append("")
        
        lines.append(self._color("  SEVERITY BREAKDOWN", 'bold'))
        lines.append("-" * 40)
        lines.append(f"  {self._color('Critical:', 'critical')} {stats.critical_count}")
        lines.append(f"  {self._color('High:', 'high')} {stats.high_count}")
        lines.append(f"  {self._color('Medium:', 'medium')} {stats.medium_count}")
        lines.append(f"  {self._color('Low:', 'low')} {stats.low_count}")
        lines.append("")
        
        if result.alerts:
            lines.append(self._color("  ALERTS", 'bold'))
            lines.append("-" * 40)
            for alert in result.alerts[:20]:
                severity_color = alert.severity.value
                severity = self._color(f"[{alert.severity.value.upper()}]", severity_color)
                lines.append(f"  {severity} {alert.message[:50]}")
            
            if len(result.alerts) > 20:
                lines.append(f"  ... and {len(result.alerts) - 20} more alerts")
        
        lines.append("")
        
        return "\n".join(lines)


def get_reporter(format: str) -> Reporter:
    """Get reporter by format name."""
    reporters = {
        'json': JSONReporter,
        'csv': CSVReporter,
        'html': HTMLReporter,
        'console': ConsoleReporter,
    }
    
    reporter_class = reporters.get(format.lower())
    if not reporter_class:
        raise ValueError(f"Unknown format: {format}")
    
    return reporter_class()


if __name__ == "__main__":
    # Demo with mock data
    from .alerts import Alert, AlertSeverity
    from .analyzer import AnalysisResult, AnalysisStats
    
    stats = AnalysisStats(
        total_entries=10000,
        parsed_entries=9950,
        parse_errors=50,
        anomaly_count=25,
        critical_count=2,
        high_count=8,
        medium_count=10,
        low_count=5,
        top_sources={"192.168.1.100": 500, "10.0.0.50": 300},
        by_detector={"sqli": 5, "xss": 3, "bruteforce": 10},
    )
    
    alerts = [
        Alert(severity=AlertSeverity.CRITICAL, message="SQL Injection detected", source="192.168.1.100"),
        Alert(severity=AlertSeverity.HIGH, message="XSS attempt blocked", source="10.0.0.50"),
    ]
    
    result = AnalysisResult(
        filepath="/var/log/apache2/access.log",
        stats=stats,
        alerts=alerts,
        start_time=datetime.now(),
        end_time=datetime.now(),
        parser_used="apache",
        detectors_used=["sqli", "xss", "bruteforce"],
    )
    
    # Test reporters
    for format in ['console', 'json']:
        reporter = get_reporter(format)
        print(f"\n=== {format.upper()} Report ===")
        print(reporter.generate(result)[:500])

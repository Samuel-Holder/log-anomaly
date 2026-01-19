"""
Log Anomaly Detector CLI

Command-line interface for log analysis and threat detection.
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import Optional

from .analyzer import LogAnalyzer, quick_analyze
from .parsers import get_parser
from .detectors import get_detector, CompositeDetector
from .reporters import get_reporter
from .alerts import AlertSeverity
from .utils import setup_logging, guess_log_type


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="logdetector",
        description="Log Anomaly Detector - Security threat and anomaly detection in log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  logdetector analyze /var/log/auth.log
  logdetector analyze /var/log/apache2/access.log --parser apache
  logdetector analyze logs/*.log --recursive -o report.html --format html
  logdetector watch /var/log/syslog
  logdetector analyze auth.log --detectors bruteforce,sqli -v

⚠️  Only analyze logs you have authorization to access.
        """
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)"
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help="Disable colored output"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # === Analyze Command ===
    analyze = subparsers.add_parser('analyze', help='Analyze log file(s)')
    
    analyze.add_argument(
        'files',
        nargs='+',
        help="Log file(s) to analyze (supports glob patterns)"
    )
    
    analyze.add_argument(
        '-p', '--parser',
        choices=['auto', 'apache', 'nginx', 'syslog', 'auth', 'json'],
        default='auto',
        help="Log parser to use (default: auto-detect)"
    )
    
    analyze.add_argument(
        '-d', '--detectors',
        help="Comma-separated list of detectors (sqli,xss,traversal,cmdi,bruteforce,webshell,scanner,anomaly)"
    )
    
    analyze.add_argument(
        '-s', '--severity',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default='low',
        help="Minimum severity level to report (default: low)"
    )
    
    analyze.add_argument(
        '-o', '--output',
        help="Output file path"
    )
    
    analyze.add_argument(
        '-f', '--format',
        choices=['json', 'csv', 'html', 'console'],
        default='console',
        help="Output format (default: console)"
    )
    
    analyze.add_argument(
        '--recursive',
        action='store_true',
        help="Search for files recursively"
    )
    
    analyze.add_argument(
        '--alerts-only',
        action='store_true',
        help="Only output alerts, skip statistics"
    )
    
    # === Watch Command ===
    watch = subparsers.add_parser('watch', help='Watch log file in real-time')
    
    watch.add_argument(
        'file',
        help="Log file to watch"
    )
    
    watch.add_argument(
        '-p', '--parser',
        choices=['auto', 'apache', 'nginx', 'syslog', 'auth', 'json'],
        default='auto',
        help="Log parser to use"
    )
    
    watch.add_argument(
        '-s', '--severity',
        choices=['critical', 'high', 'medium', 'low'],
        default='medium',
        help="Minimum severity to alert on"
    )
    
    watch.add_argument(
        '-i', '--interval',
        type=float,
        default=1.0,
        help="Poll interval in seconds (default: 1.0)"
    )
    
    # === Stats Command ===
    stats = subparsers.add_parser('stats', help='Show log statistics without detection')
    
    stats.add_argument(
        'file',
        help="Log file to analyze"
    )
    
    stats.add_argument(
        '-p', '--parser',
        default='auto',
        help="Log parser to use"
    )
    
    return parser


def get_severity(name: str) -> AlertSeverity:
    """Convert severity name to enum."""
    return {
        'critical': AlertSeverity.CRITICAL,
        'high': AlertSeverity.HIGH,
        'medium': AlertSeverity.MEDIUM,
        'low': AlertSeverity.LOW,
        'info': AlertSeverity.INFO,
    }[name.lower()]


def run_analyze(args) -> int:
    """Run analyze command."""
    import glob
    
    # Collect files
    all_files = []
    for pattern in args.files:
        if args.recursive:
            matches = glob.glob(pattern, recursive=True)
        else:
            matches = glob.glob(pattern)
        all_files.extend(matches)
    
    if not all_files:
        print(f"Error: No files found matching patterns: {args.files}")
        return 1
    
    # Setup parser
    parser = get_parser(args.parser)
    
    # Setup detectors
    if args.detectors:
        detector_names = args.detectors.split(',')
        detectors = [get_detector(name) for name in detector_names]
        detector = CompositeDetector(detectors)
    else:
        detector = CompositeDetector()
    
    # Setup analyzer
    min_severity = get_severity(args.severity)
    analyzer = LogAnalyzer(
        parser=parser,
        detector=detector,
        min_severity=min_severity,
    )
    
    # Analyze files
    all_results = []
    for filepath in all_files:
        print(f"Analyzing: {filepath}")
        try:
            result = analyzer.analyze_file(filepath)
            all_results.append(result)
        except Exception as e:
            print(f"Error analyzing {filepath}: {e}")
    
    if not all_results:
        print("No files were successfully analyzed")
        return 1
    
    # Use first result for single file, or combine for multiple
    if len(all_results) == 1:
        result = all_results[0]
    else:
        # Combine results for multiple files
        from .analyzer import AnalysisResult, AnalysisStats
        combined_stats = AnalysisStats()
        combined_alerts = []
        
        for r in all_results:
            combined_stats.total_entries += r.stats.total_entries
            combined_stats.anomaly_count += r.stats.anomaly_count
            combined_stats.critical_count += r.stats.critical_count
            combined_stats.high_count += r.stats.high_count
            combined_stats.medium_count += r.stats.medium_count
            combined_stats.low_count += r.stats.low_count
            combined_alerts.extend(r.alerts)
        
        result = AnalysisResult(
            filepath=f"{len(all_files)} files",
            stats=combined_stats,
            alerts=combined_alerts,
            start_time=all_results[0].start_time,
            end_time=all_results[-1].end_time,
            parser_used=args.parser,
            detectors_used=result.detectors_used,
        )
    
    # Generate output
    reporter = get_reporter(args.format)
    output = reporter.generate(result)
    
    if args.output:
        Path(args.output).write_text(output)
        print(f"\nReport saved to: {args.output}")
    else:
        print(output)
    
    # Return exit code based on findings
    if result.stats.critical_count > 0:
        return 2  # Critical findings
    elif result.stats.high_count > 0:
        return 1  # High findings
    return 0


def run_watch(args) -> int:
    """Run watch command."""
    filepath = args.file
    
    if not Path(filepath).exists():
        print(f"Error: File not found: {filepath}")
        return 1
    
    parser = get_parser(args.parser)
    detector = CompositeDetector()
    min_severity = get_severity(args.severity)
    
    analyzer = LogAnalyzer(
        parser=parser,
        detector=detector,
        min_severity=min_severity,
    )
    
    print(f"Watching {filepath} (Ctrl+C to stop)")
    print(f"Minimum severity: {args.severity}")
    print("-" * 50)
    
    try:
        analyzer.watch_file(
            filepath,
            poll_interval=args.interval,
        )
    except KeyboardInterrupt:
        print("\nStopped watching")
    
    return 0


def run_stats(args) -> int:
    """Run stats command."""
    filepath = args.file
    
    if not Path(filepath).exists():
        print(f"Error: File not found: {filepath}")
        return 1
    
    parser = get_parser(args.parser)
    
    print(f"Parsing {filepath}...")
    
    # Simple stats without detection
    stats = {
        'total_lines': 0,
        'parsed': 0,
        'errors': 0,
        'ips': set(),
        'status_codes': {},
        'methods': {},
    }
    
    for entry in parser.parse_file(filepath):
        stats['total_lines'] += 1
        
        if entry.parse_error:
            stats['errors'] += 1
        else:
            stats['parsed'] += 1
        
        if entry.source_ip:
            stats['ips'].add(entry.source_ip)
        
        if entry.status_code:
            stats['status_codes'][entry.status_code] = stats['status_codes'].get(
                entry.status_code, 0
            ) + 1
        
        if entry.method:
            stats['methods'][entry.method] = stats['methods'].get(
                entry.method, 0
            ) + 1
    
    print(f"\n=== Log Statistics ===")
    print(f"Total lines: {stats['total_lines']:,}")
    print(f"Parsed: {stats['parsed']:,}")
    print(f"Parse errors: {stats['errors']:,}")
    print(f"Unique IPs: {len(stats['ips'])}")
    
    if stats['status_codes']:
        print(f"\nStatus Codes:")
        for code, count in sorted(stats['status_codes'].items()):
            print(f"  {code}: {count:,}")
    
    if stats['methods']:
        print(f"\nHTTP Methods:")
        for method, count in sorted(stats['methods'].items(), key=lambda x: -x[1]):
            print(f"  {method}: {count:,}")
    
    return 0


def main(argv=None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)
    
    # Setup logging
    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    
    setup_logging(log_level)
    
    # Run command
    if args.command == 'analyze':
        return run_analyze(args)
    elif args.command == 'watch':
        return run_watch(args)
    elif args.command == 'stats':
        return run_stats(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())

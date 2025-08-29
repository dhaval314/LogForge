"""
Main entry point for the Forensic AI Log Analyzer.
This module provides both CLI and programmatic interfaces.
"""
import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from loguru import logger

from config import Config
from agents import ForensicOrchestrator
from data_models import ForensicReport
from dashboard import main as dashboard_main

def setup_logging(log_level: str = None):
    """Configure logging for the application."""
    level = log_level or Config.LOG_LEVEL
    
    # Remove default logger
    logger.remove()
    
    # Add console logger with conditional colorization
    console_format = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    if not Config.DEBUG_MODE:
        console_format = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
    
    logger.add(
        sys.stderr,
        level=level,
        format=console_format,
        colorize=Config.DEBUG_MODE
    )
    
    # Add file logger with better rotation settings
    log_file = Path("logs") / "forensic_analyzer.log"
    log_file.parent.mkdir(exist_ok=True)
    
    logger.add(
        str(log_file),
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="50 MB",
        retention="30 days",
        compression="zip"
    )
    
    # Add error log file for critical errors
    error_log_file = Path("logs") / "errors.log"
    logger.add(
        str(error_log_file),
        level="ERROR",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="10 MB",
        retention="90 days",
        compression="zip"
    )
    
    logger.info(f"Logging configured at level: {level}")
    logger.info(f"Debug mode: {Config.DEBUG_MODE}")

class ForensicAnalyzerCLI:
    """Command-line interface for the Forensic AI Log Analyzer."""
    
    def __init__(self):
        self.orchestrator = ForensicOrchestrator()
    
    def analyze_files(self, log_files: List[str], case_id: Optional[str] = None, 
                     output_dir: Optional[str] = None) -> ForensicReport:
        """
        Analyze log files and return forensic report.
        
        Args:
            log_files: List of log file paths
            case_id: Optional case identifier
            output_dir: Optional output directory for reports
            
        Returns:
            ForensicReport object
        """
        logger.info(f"Starting CLI analysis of {len(log_files)} files")
        
        try:
            # Validate input files
            valid_files = []
            for file_path in log_files:
                path = Path(file_path)
                if path.exists() and path.is_file():
                    valid_files.append(str(path.absolute()))
                    logger.info(f"Added file: {path}")
                else:
                    logger.warning(f"File not found or not a file: {file_path}")
            
            if not valid_files:
                raise ValueError("No valid log files provided")
            
            # Run investigation
            logger.info("Running forensic investigation...")
            report = self.orchestrator.investigate(valid_files, case_id)
            
            # Save reports if output directory specified
            if output_dir:
                self._save_reports(report, output_dir)
            
            logger.info(f"Analysis completed successfully. Case ID: {report.case_id}")
            return report
            
        except Exception as e:
            logger.error(f"CLI analysis failed: {e}")
            raise
    
    def _save_reports(self, report: ForensicReport, output_dir: str):
        """Save reports to specified directory."""
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Save JSON report
            json_file = output_path / f"forensic_report_{report.case_id}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                f.write(report.model_dump_json(indent=2))
            
            logger.info(f"JSON report saved: {json_file}")
            
            # Save Word report if possible
            try:
                from dashboard import ReportGenerator
                generator = ReportGenerator()
                doc_buffer = generator.generate_word_report(report)
                
                if doc_buffer:
                    word_file = output_path / f"forensic_report_{report.case_id}.docx"
                    with open(word_file, 'wb') as f:
                        f.write(doc_buffer.getvalue())
                    logger.info(f"Word report saved: {word_file}")
                
            except Exception as e:
                logger.warning(f"Could not save Word report: {e}")
            
            # Save timeline CSV
            if report.timeline:
                import pandas as pd
                timeline_file = output_path / f"timeline_{report.case_id}.csv"
                df_timeline = pd.DataFrame(report.timeline)
                df_timeline.to_csv(timeline_file, index=False)
                logger.info(f"Timeline CSV saved: {timeline_file}")
            
        except Exception as e:
            logger.error(f"Error saving reports: {e}")

def create_arg_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Forensic AI Log Analyzer - Automated security log analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze log files with CLI
  python main.py analyze file1.log file2.csv --case-id INCIDENT_001 --output reports/
  
  # Run web dashboard
  python main.py dashboard
  
  # Check configuration
  python main.py config --check
        """
    )
    
    # Global options
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Set logging level')
    parser.add_argument('--config-file', help='Path to configuration file')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze log files')
    analyze_parser.add_argument('files', nargs='+', help='Log files to analyze')
    analyze_parser.add_argument('--case-id', help='Case identifier')
    analyze_parser.add_argument('--output', '-o', help='Output directory for reports')
    analyze_parser.add_argument('--format', choices=['json', 'word', 'both'], 
                                default='both', help='Output format')
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Launch web dashboard')
    dashboard_parser.add_argument('--port', type=int, default=8501, help='Dashboard port')
    dashboard_parser.add_argument('--host', default='localhost', help='Dashboard host')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('--check', action='store_true', help='Check configuration')
    config_parser.add_argument('--validate', action='store_true', help='Validate all services')
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run with demo data')
    demo_parser.add_argument('--scenario', choices=['malware', 'breach', 'insider'], 
                            default='malware', help='Demo scenario')
    
    return parser

def handle_analyze_command(args) -> int:
    """Handle the analyze command."""
    try:
        cli = ForensicAnalyzerCLI()
        report = cli.analyze_files(
            log_files=args.files,
            case_id=args.case_id,
            output_dir=args.output
        )
        
        # Print summary
        print("\n" + "="*60)
        print("FORENSIC ANALYSIS SUMMARY")
        print("="*60)
        print(f"Case ID: {report.case_id}")
        print(f"Total Events: {report.total_events:,}")
        print(f"Severity: {report.analysis.initial_analysis.severity.value.upper()}")
        print(f"IOCs Found: {len(report.analysis.initial_analysis.iocs)}")
        print(f"MITRE Mappings: {len(report.analysis.initial_analysis.mitre_mappings)}")
        print(f"Confidence: {report.analysis.initial_analysis.confidence:.1%}")
        print("\nExecutive Summary:")
        print(report.executive_summary)
        
        if report.analysis.recommendations:
            print("\nTop Recommendations:")
            for i, rec in enumerate(report.analysis.recommendations[:5], 1):
                print(f"{i}. {rec}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        print(f"\nError: {e}", file=sys.stderr)
        return 1

def handle_dashboard_command(args) -> int:
    """Handle the dashboard command."""
    try:
        import os
        os.environ['STREAMLIT_SERVER_PORT'] = str(args.port)
        os.environ['STREAMLIT_SERVER_ADDRESS'] = args.host
        
        print(f"Starting dashboard at http://{args.host}:{args.port}")
        print("Press Ctrl+C to stop the dashboard")
        
        # Launch Streamlit dashboard
        dashboard_main()
        return 0
        
    except KeyboardInterrupt:
        print("\nDashboard stopped by user")
        return 0
    except Exception as e:
        logger.error(f"Dashboard failed to start: {e}")
        print(f"\nError: {e}", file=sys.stderr)
        return 1

def handle_config_command(args) -> int:
    """Handle the config command."""
    try:
        if args.check or args.validate:
            print("Configuration Status:")
            print("="*40)
            
            config_status = Config.validate_config()
            for service, status in config_status.items():
                status_icon = "✓" if status else "✗"
                service_name = service.replace("_", " ").title()
                print(f"{status_icon} {service_name}")
            
            if args.validate:
                # Additional validation tests
                print("\nDetailed Validation:")
                print("-"*40)
                
                # Test IBM Watson connection
                if config_status.get("ibm_configured"):
                    try:
                        from llm_analysis import GraniteAnalyzer
                        analyzer = GraniteAnalyzer()
                        if analyzer.client:
                            print("IBM Watson ML connection successful")
                        else:
                            print("IBM Watson ML connection failed")
                    except Exception as e:
                        print(f"IBM Watson ML validation error: {e}")
                
                # Test AWS connection
                if config_status.get("aws_configured"):
                    try:
                        import boto3
                        session = boto3.Session(
                            aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
                            aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY,
                            region_name=Config.AWS_DEFAULT_REGION
                        )
                        sts = session.client('sts')
                        sts.get_caller_identity()
                        print("AWS credentials valid")
                    except Exception as e:
                        print(f"AWS validation error: {e}")
                
                # Test VirusTotal connection
                if config_status.get("vt_configured"):
                    try:
                        from utilities import VirusTotalEnricher
                        vt = VirusTotalEnricher()
                        if vt.client:
                            print("VirusTotal API key configured")
                        else:
                            print("VirusTotal API connection failed")
                    except Exception as e:
                        print(f"VirusTotal validation error: {e}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Config check failed: {e}")
        print(f"\nError: {e}", file=sys.stderr)
        return 1

def handle_demo_command(args) -> int:
    """Handle the demo command."""
    try:
        print(f"Running demo scenario: {args.scenario}")
        
        # Create demo data directory
        demo_dir = Path("demo_data")
        demo_dir.mkdir(exist_ok=True)
        
        # Generate demo log files based on scenario
        demo_files = create_demo_data(args.scenario, demo_dir)
        
        if demo_files:
            # Run analysis on demo files
            cli = ForensicAnalyzerCLI()
            report = cli.analyze_files(
                log_files=demo_files,
                case_id=f"DEMO_{args.scenario.upper()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                output_dir=str(demo_dir / "reports")
            )
            
            print(f"\nDemo analysis completed! Reports saved to: {demo_dir / 'reports'}")
            print("Run 'python main.py dashboard' to view results in the web interface")
            
        return 0
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        print(f"\nError: {e}", file=sys.stderr)
        return 1

def create_demo_data(scenario: str, output_dir: Path) -> List[str]:
    """Create demo log data for specified scenario."""
    demo_files = []
    
    try:
        if scenario == "malware":
            # Create malware infection scenario logs
            demo_files.append(create_malware_demo_logs(output_dir))
        elif scenario == "breach":
            # Create data breach scenario logs
            demo_files.append(create_breach_demo_logs(output_dir))
        elif scenario == "insider":
            # Create insider threat scenario logs
            demo_files.append(create_insider_demo_logs(output_dir))
        
        logger.info(f"Created {len(demo_files)} demo files for scenario: {scenario}")
        return demo_files
        
    except Exception as e:
        logger.error(f"Error creating demo data: {e}")
        return []

def create_malware_demo_logs(output_dir: Path) -> str:
    """Create demo logs for malware scenario."""
    import json
    from datetime import datetime, timedelta
    
    demo_file = output_dir / "malware_demo.json"
    
    # Generate demo log entries
    base_time = datetime.now() - timedelta(hours=2)
    demo_logs = []
    
    # Initial compromise
    demo_logs.append({
        "timestamp": (base_time + timedelta(minutes=0)).isoformat(),
        "source": "email_security",
        "event_type": "email_threat",
        "message": "Suspicious attachment detected: invoice_malware.exe (MD5: 5d41402abc4b2a76b9719d911017c592)",
        "severity": "high"
    })
    
    # Malware execution
    demo_logs.append({
        "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
        "source": "endpoint_security",
        "event_type": "process_execution",
        "message": "Suspicious process executed: C:\\temp\\invoice_malware.exe with parent process: outlook.exe",
        "severity": "critical"
    })
    
    # Network communication
    demo_logs.append({
        "timestamp": (base_time + timedelta(minutes=20)).isoformat(),
        "source": "firewall",
        "event_type": "network_connection",
        "message": "Outbound connection to suspicious IP: 185.220.101.182:4444 from internal host 192.168.1.105",
        "severity": "high"
    })
    
    # Registry modification
    demo_logs.append({
        "timestamp": (base_time + timedelta(minutes=25)).isoformat(),
        "source": "windows_events",
        "event_id": "13",
        "event_type": "registry_modification",
        "message": "Registry value modified: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate = C:\\temp\\persistent.exe",
        "severity": "medium"
    })
    
    # Save demo file
    with open(demo_file, 'w') as f:
        json.dump(demo_logs, f, indent=2)
    
    return str(demo_file)

def create_breach_demo_logs(output_dir: Path) -> str:
    """Create demo logs for data breach scenario."""
    import json
    from datetime import datetime, timedelta
    
    demo_file = output_dir / "breach_demo.json"
    
    # Generate demo log entries
    base_time = datetime.now() - timedelta(hours=4)
    demo_logs = []
    
    # Initial access attempt
    demo_logs.append({
        "timestamp": (base_time + timedelta(minutes=0)).isoformat(),
        "source": "authentication_server",
        "event_type": "login_attempt",
        "message": "Multiple failed login attempts for admin account from IP: 203.0.113.45",
        "severity": "medium"
    })
    
    # Successful compromise
    demo_logs.append({
        "timestamp": (base_time + timedelta(minutes=30)).isoformat(),
        "source": "authentication_server",
        "event_type": "successful_login",
        "message": "Admin account successfully authenticated from IP: 203.0.113.45 at unusual hour",
        "severity": "high"
    })
    
    # Privilege escalation
    demo_logs.append({
        "timestamp": (base_time + timedelta(minutes=45)).isoformat(),
        "source": "domain_controller",
        "event_type": "privilege_escalation",
        "message": "User admin added to Domain Admins group by admin account",
        "severity": "critical"
    })
    
    # Database access
    demo_logs.append({
        "timestamp": (base_time + timedelta(hours=1)).isoformat(),
        "source": "database_server",
        "event_type": "database_access",
        "message": "Large data export operation initiated: customer_data table (500,000 records)",
        "severity": "critical"
    })
    
    # Data exfiltration
    demo_logs.append({
        "timestamp": (base_time + timedelta(hours=1, minutes=30)).isoformat(),
        "source": "network_monitor",
        "event_type": "data_transfer",
        "message": "Large outbound transfer detected: 2.5GB to external IP 198.51.100.23:443",
        "severity": "critical"
    })
    
    # Cleanup attempt
    demo_logs.append({
        "timestamp": (base_time + timedelta(hours=2)).isoformat(),
        "source": "windows_events",
        "event_id": "1102",
        "event_type": "log_clearing",
        "message": "Security log cleared by admin account",
        "severity": "high"
    })
    
    with open(demo_file, 'w') as f:
        json.dump(demo_logs, f, indent=2)
    
    return str(demo_file)

def create_insider_demo_logs(output_dir: Path) -> str:
    """Create demo logs for insider threat scenario."""
    import json
    from datetime import datetime, timedelta
    
    demo_file = output_dir / "insider_demo.json"
    
    # Generate demo log entries
    base_time = datetime.now() - timedelta(days=1)
    demo_logs = []
    
    # After-hours access
    demo_logs.append({
        "timestamp": (base_time + timedelta(hours=22)).isoformat(),
        "source": "badge_access",
        "event_type": "facility_access",
        "message": "Employee John.Doe (ID: EMP001) accessed server room at 22:15 (outside normal hours)",
        "severity": "medium"
    })
    
    # Unusual file access
    demo_logs.append({
        "timestamp": (base_time + timedelta(hours=22, minutes=30)).isoformat(),
        "source": "file_server",
        "event_type": "file_access",
        "message": "User John.Doe accessed sensitive directory: \\\\fileserver\\confidential\\financial_reports\\",
        "severity": "medium"
    })
    
    # Mass file copying
    demo_logs.append({
        "timestamp": (base_time + timedelta(hours=23)).isoformat(),
        "source": "endpoint_dlp",
        "event_type": "data_copy",
        "message": "Large volume of files copied to USB device by user John.Doe (250 files, 1.2GB)",
        "severity": "high"
    })
    
    # Email forwarding
    demo_logs.append({
        "timestamp": (base_time + timedelta(hours=23, minutes=15)).isoformat(),
        "source": "email_server",
        "event_type": "email_forward",
        "message": "User John.Doe forwarded 15 emails to external address: personal@gmail.com",
        "severity": "high"
    })
    
    # VPN access from unusual location
    demo_logs.append({
        "timestamp": (base_time + timedelta(days=1, hours=8)).isoformat(),
        "source": "vpn_server",
        "event_type": "vpn_connection",
        "message": "User John.Doe connected via VPN from unusual location: Country=Unknown, IP=tor-exit-node.com",
        "severity": "high"
    })
    
    with open(demo_file, 'w') as f:
        json.dump(demo_logs, f, indent=2)
    
    return str(demo_file)

def main():
    """Main entry point for the application."""
    parser = create_arg_parser()
    args = parser.parse_args()
    
    # Set up logging
    setup_logging(args.log_level)
    
    # Handle different commands
    if args.command == 'analyze':
        return handle_analyze_command(args)
    elif args.command == 'dashboard':
        return handle_dashboard_command(args)
    elif args.command == 'config':
        return handle_config_command(args)
    elif args.command == 'demo':
        return handle_demo_command(args)
    else:
        # No command specified, show help
        parser.print_help()
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.exception("Unexpected error occurred")
        print(f"\nUnexpected error: {e}", file=sys.stderr)
        sys.exit(1)
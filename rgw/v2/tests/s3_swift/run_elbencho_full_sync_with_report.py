#!/usr/bin/env python3
"""
Test Runner with HTML Report Generation for Elbencho Full Sync Tests

This script runs the multisite full sync test and optionally generates:
1. Individual log files for each scenario
2. Master log file with all output
3. HTML report with test duration, status, and log links

Report generation can be controlled via:
- Config file: Set 'generate_report: true/false' in test_ops section
- Command line: Use '--no-report' flag to disable (overrides config)

Usage:
    # With report generation (default)
    python run_elbencho_full_sync_with_report.py \
        -c multisite_configs/test_elbencho_full_sync_all_scenarios.yaml \
        -o /path/to/output/directory

    # Without report generation (console output only)
    python run_elbencho_full_sync_with_report.py \
        -c multisite_configs/test_elbencho_full_sync_all_scenarios.yaml \
        --no-report

When report generation is enabled, the script will create:
    output_dir/
        ├── test_report.html              # Main HTML report
        ├── master_log.txt                # Complete test output
        ├── scenario1_log.txt             # Scenario 1 specific logs
        ├── scenario2_log.txt             # Scenario 2 specific logs
        ├── scenario3_log.txt             # Scenario 3 specific logs
        ├── scenario4_log.txt             # Scenario 4 specific logs
        ├── scenario5_log.txt             # Scenario 5 specific logs
        └── sanity_check_log.txt          # Sanity check logs (if run)
"""

import argparse
import datetime
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import yaml


class ScenarioTracker:
    """Tracks individual scenario execution details."""

    def __init__(self, name, scenario_id):
        self.name = name
        self.scenario_id = scenario_id
        self.status = "NOT_RUN"
        self.start_time = None
        self.end_time = None
        self.duration_seconds = 0
        self.log_file = None
        self.error_message = None
        self.step_logs = []

    def start(self):
        self.start_time = datetime.datetime.now()
        self.status = "RUNNING"

    def complete(self, success=True, error_msg=None):
        self.end_time = datetime.datetime.now()
        if self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()
        self.status = "PASSED" if success else "FAILED"
        self.error_message = error_msg

    def get_duration_formatted(self):
        if self.duration_seconds == 0:
            return "N/A"
        hours = int(self.duration_seconds // 3600)
        minutes = int((self.duration_seconds % 3600) // 60)
        seconds = int(self.duration_seconds % 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


class TestRunner:
    """Main test runner that executes tests and generates reports."""

    def __init__(self, config_file, output_dir, log_level="info", generate_report=True):
        self.config_file = config_file
        self.output_dir = Path(output_dir)
        self.log_level = log_level
        self.generate_report = generate_report

        # Create output directory only if generating reports
        if self.generate_report:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        # Test tracking
        self.test_start_time = None
        self.test_end_time = None
        self.overall_status = "NOT_STARTED"

        # Scenario tracking
        self.scenarios = {
            "sanity": ScenarioTracker("Sanity Check", "sanity"),
            "scenario1": ScenarioTracker(
                "Scenario 1: 1 bucket, 1.3M objects", "scenario1"
            ),
            "scenario2": ScenarioTracker(
                "Scenario 2: 5 buckets, 1.3M objects each", "scenario2"
            ),
            "scenario3": ScenarioTracker(
                "Scenario 3: 5 versioned buckets, 10 versions", "scenario3"
            ),
            "scenario4": ScenarioTracker(
                "Scenario 4: LC DELETE with 10 versions", "scenario4"
            ),
            "scenario5": ScenarioTracker(
                "Scenario 5: 1 bucket with special characters", "scenario5"
            ),
        }

        # File paths
        self.master_log_file = self.output_dir / "master_log.txt"
        self.html_report_file = self.output_dir / "test_report.html"

        # Current scenario being tracked
        self.current_scenario = None
        self.master_log_handle = None

    def parse_log_line(self, line):
        """Parse log line to detect scenario transitions and status."""
        line_stripped = line.strip()

        # Detect sanity check
        if "STARTING SANITY CHECK" in line_stripped:
            self.current_scenario = "sanity"
            self.scenarios["sanity"].start()
        elif "SANITY CHECK PASSED" in line_stripped:
            if self.current_scenario == "sanity":
                self.scenarios["sanity"].complete(success=True)
        elif "SANITY CHECK FAILED" in line_stripped:
            if self.current_scenario == "sanity":
                self.scenarios["sanity"].complete(success=False)

        # Detect scenario starts
        elif "SCENARIO 1: Full sync with 1 bucket" in line_stripped:
            self.current_scenario = "scenario1"
            self.scenarios["scenario1"].start()
        elif "SCENARIO 2: Full sync with 5 buckets" in line_stripped:
            self.current_scenario = "scenario2"
            self.scenarios["scenario2"].start()
        elif "SCENARIO 3: Full sync with 5 versioned buckets" in line_stripped:
            self.current_scenario = "scenario3"
            self.scenarios["scenario3"].start()
        elif "SCENARIO 4: LC DELETE" in line_stripped:
            self.current_scenario = "scenario4"
            self.scenarios["scenario4"].start()
        elif (
            "SCENARIO 5: Full sync with 1 bucket and special character" in line_stripped
        ):
            self.current_scenario = "scenario5"
            self.scenarios["scenario5"].start()

        # Detect scenario completions
        elif "SCENARIO 1 COMPLETED SUCCESSFULLY" in line_stripped:
            self.scenarios["scenario1"].complete(success=True)
        elif "SCENARIO 2 COMPLETED SUCCESSFULLY" in line_stripped:
            self.scenarios["scenario2"].complete(success=True)
        elif "SCENARIO 3 COMPLETED SUCCESSFULLY" in line_stripped:
            self.scenarios["scenario3"].complete(success=True)
        elif "SCENARIO 4 COMPLETED SUCCESSFULLY" in line_stripped:
            self.scenarios["scenario4"].complete(success=True)
        elif "SCENARIO 5 COMPLETED SUCCESSFULLY" in line_stripped:
            self.scenarios["scenario5"].complete(success=True)

        # Log to current scenario
        if self.current_scenario and self.current_scenario in self.scenarios:
            self.scenarios[self.current_scenario].step_logs.append(line)

    def run_test(self):
        """Execute the test and capture output."""
        print(f"\n{'='*80}")
        print("MULTISITE ELBENCHO FULL SYNC TEST RUNNER")
        print(f"{'='*80}\n")
        print(f"Config file: {self.config_file}")
        if self.generate_report:
            print(f"Output directory: {self.output_dir}")
            print(f"Report generation: ENABLED")
        else:
            print(f"Report generation: DISABLED")
        print(f"Log level: {self.log_level}")
        print(
            f"\nTest started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print(f"\n{'='*80}\n")

        self.test_start_time = datetime.datetime.now()
        self.overall_status = "RUNNING"

        # Prepare command
        test_script = "rgw/v2/tests/s3_swift/test_multisite_elbencho_full_sync.py"
        cmd = [
            "python",
            test_script,
            "-c",
            self.config_file,
            "-log_level",
            self.log_level,
        ]

        print(f"Running command: {' '.join(cmd)}\n")

        # Conditionally open master log file
        if self.generate_report:
            master_log = open(self.master_log_file, "w")
            self.master_log_handle = master_log

            # Write header to master log
            master_log.write(f"{'='*80}\n")
            master_log.write(f"MULTISITE ELBENCHO FULL SYNC TEST\n")
            master_log.write(f"{'='*80}\n")
            master_log.write(
                f"Started: {self.test_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            master_log.write(f"Config: {self.config_file}\n")
            master_log.write(f"Command: {' '.join(cmd)}\n")
            master_log.write(f"{'='*80}\n\n")
            master_log.flush()
        else:
            master_log = None

        try:
            # Run test process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )

            # Read output line by line
            for line in process.stdout:
                # Write to master log if enabled
                if master_log:
                    master_log.write(line)
                    master_log.flush()

                # Print to console
                print(line, end="")
                sys.stdout.flush()

                # Parse for scenario tracking only if generating reports
                if self.generate_report:
                    self.parse_log_line(line)

            # Wait for process to complete
            return_code = process.wait()

            self.test_end_time = datetime.datetime.now()

            if return_code == 0:
                self.overall_status = "PASSED"
                print(f"\n{'='*80}")
                print("✅ TEST PASSED")
                print(f"{'='*80}\n")
            else:
                self.overall_status = "FAILED"
                print(f"\n{'='*80}")
                print(f"❌ TEST FAILED (exit code: {return_code})")
                print(f"{'='*80}\n")

                # Mark any running scenarios as failed (only if generating reports)
                if self.generate_report:
                    for scenario in self.scenarios.values():
                        if scenario.status == "RUNNING":
                            scenario.complete(
                                success=False,
                                error_msg=f"Test terminated with exit code {return_code}",
                            )

        except Exception as e:
            self.test_end_time = datetime.datetime.now()
            self.overall_status = "FAILED"
            error_msg = f"Exception during test execution: {str(e)}"
            print(f"\n{'='*80}")
            print(f"❌ {error_msg}")
            print(f"{'='*80}\n")
            if master_log:
                master_log.write(f"\n{error_msg}\n")

            # Mark any running scenarios as failed (only if generating reports)
            if self.generate_report:
                for scenario in self.scenarios.values():
                    if scenario.status == "RUNNING":
                        scenario.complete(success=False, error_msg=error_msg)

        finally:
            # Close master log file if it was opened
            if master_log:
                master_log.close()

        # Generate reports only if enabled
        if self.generate_report:
            # Write individual scenario logs
            self.write_scenario_logs()

            # Generate HTML report
            self.generate_html_report()

            print(
                f"Test completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            print(f"\nLogs and report saved to: {self.output_dir}")
            print(f"  - HTML Report: {self.html_report_file}")
            print(f"  - Master Log: {self.master_log_file}\n")
        else:
            print(
                f"Test completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            print(f"\nReport generation was disabled in config.\n")

    def write_scenario_logs(self):
        """Write individual log files for each scenario."""
        for scenario_id, scenario in self.scenarios.items():
            if scenario.step_logs:
                log_file = self.output_dir / f"{scenario_id}_log.txt"
                scenario.log_file = log_file.name

                with open(log_file, "w") as f:
                    f.write(f"{'='*80}\n")
                    f.write(f"{scenario.name}\n")
                    f.write(f"{'='*80}\n")
                    f.write(f"Status: {scenario.status}\n")
                    f.write(f"Duration: {scenario.get_duration_formatted()}\n")
                    if scenario.start_time:
                        f.write(
                            f"Started: {scenario.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                        )
                    if scenario.end_time:
                        f.write(
                            f"Completed: {scenario.end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                        )
                    f.write(f"{'='*80}\n\n")

                    for log_line in scenario.step_logs:
                        f.write(log_line)

    def generate_html_report(self):
        """Generate comprehensive HTML report."""
        total_duration = 0
        if self.test_start_time and self.test_end_time:
            total_duration = (self.test_end_time - self.test_start_time).total_seconds()

        # Count passed/failed scenarios
        total_scenarios = sum(
            1 for s in self.scenarios.values() if s.status in ["PASSED", "FAILED"]
        )
        passed_scenarios = sum(
            1 for s in self.scenarios.values() if s.status == "PASSED"
        )
        failed_scenarios = sum(
            1 for s in self.scenarios.values() if s.status == "FAILED"
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multisite Elbencho Full Sync Test Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 28px;
            margin-bottom: 10px;
        }}

        .header p {{
            opacity: 0.9;
            font-size: 14px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #e0e0e0;
        }}

        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            text-align: center;
        }}

        .summary-card h3 {{
            font-size: 14px;
            color: #666;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }}

        .summary-card.passed .value {{
            color: #28a745;
        }}

        .summary-card.failed .value {{
            color: #dc3545;
        }}

        .summary-card.duration .value {{
            color: #007bff;
        }}

        .scenarios {{
            padding: 30px;
        }}

        .scenarios h2 {{
            font-size: 22px;
            margin-bottom: 20px;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}

        .scenario-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        .scenario-table th {{
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #555;
            border-bottom: 2px solid #e0e0e0;
        }}

        .scenario-table td {{
            padding: 15px;
            border-bottom: 1px solid #e0e0e0;
        }}

        .scenario-table tr:hover {{
            background: #f8f9fa;
        }}

        .status-badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .status-passed {{
            background: #d4edda;
            color: #155724;
        }}

        .status-failed {{
            background: #f8d7da;
            color: #721c24;
        }}

        .status-not-run {{
            background: #e2e3e5;
            color: #383d41;
        }}

        .status-running {{
            background: #d1ecf1;
            color: #0c5460;
        }}

        .log-link {{
            color: #007bff;
            text-decoration: none;
            font-weight: 500;
        }}

        .log-link:hover {{
            text-decoration: underline;
        }}

        .footer {{
            padding: 20px 30px;
            background: #f8f9fa;
            border-top: 1px solid #e0e0e0;
            text-align: center;
            color: #666;
            font-size: 14px;
        }}

        .timestamp {{
            color: #888;
            font-size: 13px;
        }}

        .overall-status {{
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 16px;
            font-weight: bold;
            margin-top: 10px;
        }}

        .overall-passed {{
            background: #28a745;
            color: white;
        }}

        .overall-failed {{
            background: #dc3545;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Multisite Elbencho Full Sync Test Report</h1>
            <p>RGW Full Sync Validation - 5 Scenario Test Suite</p>
            <div class="overall-status {'overall-passed' if self.overall_status == 'PASSED' else 'overall-failed'}">
                {'✅ ALL TESTS PASSED' if self.overall_status == 'PASSED' else '❌ TESTS FAILED'}
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Scenarios</h3>
                <div class="value">{total_scenarios}</div>
            </div>
            <div class="summary-card passed">
                <h3>Passed</h3>
                <div class="value">{passed_scenarios}</div>
            </div>
            <div class="summary-card failed">
                <h3>Failed</h3>
                <div class="value">{failed_scenarios}</div>
            </div>
            <div class="summary-card duration">
                <h3>Total Duration</h3>
                <div class="value" style="font-size: 20px;">{self._format_duration(total_duration)}</div>
            </div>
        </div>

        <div class="scenarios">
            <h2>📋 Test Scenarios</h2>

            <table class="scenario-table">
                <thead>
                    <tr>
                        <th>Scenario</th>
                        <th>Status</th>
                        <th>Duration</th>
                        <th>Started</th>
                        <th>Completed</th>
                        <th>Logs</th>
                    </tr>
                </thead>
                <tbody>
"""

        # Add scenario rows
        for scenario_id, scenario in self.scenarios.items():
            if scenario.status == "NOT_RUN":
                continue

            status_class = {
                "PASSED": "status-passed",
                "FAILED": "status-failed",
                "RUNNING": "status-running",
                "NOT_RUN": "status-not-run",
            }.get(scenario.status, "status-not-run")

            start_time_str = (
                scenario.start_time.strftime("%H:%M:%S")
                if scenario.start_time
                else "N/A"
            )
            end_time_str = (
                scenario.end_time.strftime("%H:%M:%S") if scenario.end_time else "N/A"
            )

            log_link = (
                f'<a href="{scenario.log_file}" class="log-link">View Log</a>'
                if scenario.log_file
                else "N/A"
            )

            html_content += f"""
                    <tr>
                        <td><strong>{scenario.name}</strong></td>
                        <td><span class="status-badge {status_class}">{scenario.status}</span></td>
                        <td>{scenario.get_duration_formatted()}</td>
                        <td class="timestamp">{start_time_str}</td>
                        <td class="timestamp">{end_time_str}</td>
                        <td>{log_link}</td>
                    </tr>
"""

        html_content += f"""
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p><strong>Test Information</strong></p>
            <p class="timestamp">Started: {self.test_start_time.strftime('%Y-%m-%d %H:%M:%S') if self.test_start_time else 'N/A'}</p>
            <p class="timestamp">Completed: {self.test_end_time.strftime('%Y-%m-%d %H:%M:%S') if self.test_end_time else 'N/A'}</p>
            <p class="timestamp">Config: {self.config_file}</p>
            <p style="margin-top: 15px;">
                <a href="master_log.txt" class="log-link">📄 View Master Log</a>
            </p>
        </div>
    </div>
</body>
</html>
"""

        # Write HTML file
        with open(self.html_report_file, "w") as f:
            f.write(html_content)

    def _format_duration(self, seconds):
        """Format duration in human-readable format."""
        if seconds == 0:
            return "N/A"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"


def main():
    parser = argparse.ArgumentParser(
        description="Run Multisite Elbencho Full Sync Test with HTML Report Generation"
    )
    parser.add_argument(
        "-c", "--config", required=True, help="Path to test configuration YAML file"
    )
    parser.add_argument(
        "-o",
        "--output",
        default=f"test_reports/elbencho_full_sync_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Output directory for logs and reports (default: test_reports/elbencho_full_sync_<timestamp>)",
    )
    parser.add_argument(
        "-log_level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Log level for the test (default: info)",
    )
    parser.add_argument(
        "--no-report",
        dest="no_report",
        action="store_true",
        help="Disable HTML report generation (overrides config setting)",
    )

    args = parser.parse_args()

    # Read config to check generate_report setting
    generate_report = True  # Default to True
    try:
        with open(args.config, "r") as f:
            config_data = yaml.safe_load(f)
            if config_data and "config" in config_data:
                test_ops = config_data["config"].get("test_ops", {})
                # Get generate_report from config (default True if not specified)
                generate_report = test_ops.get("generate_report", True)
    except Exception as e:
        print(f"Warning: Could not read generate_report from config: {e}")
        print("Defaulting to generate_report=True")

    # Command line --no-report overrides config setting
    if args.no_report:
        generate_report = False
        print("Report generation disabled via --no-report flag")

    # Create and run test
    runner = TestRunner(
        config_file=args.config,
        output_dir=args.output,
        log_level=args.log_level,
        generate_report=generate_report,
    )

    runner.run_test()

    # Print summary
    print(f"\n{'='*80}")
    print("TEST EXECUTION SUMMARY")
    print(f"{'='*80}")
    print(f"Overall Status: {runner.overall_status}")
    if runner.generate_report:
        print(f"HTML Report: {runner.html_report_file}")
        print(f"Master Log: {runner.master_log_file}")
        print(f"\nScenario Results:")
        for scenario_id, scenario in runner.scenarios.items():
            if scenario.status != "NOT_RUN":
                print(
                    f"  {scenario.name}: {scenario.status} ({scenario.get_duration_formatted()})"
                )
    else:
        print(f"Report Generation: DISABLED")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()

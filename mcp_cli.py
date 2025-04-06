#!/usr/bin/env python3
"""
MCP Server CLI - A simple command-line interface for the MCP Server
Usage:
    mcp_cli.py scan [--scan-type=<type>] [--concurrent=<n>] [--output=<format>] [--risk-level=<level>] [--timeout=<seconds>] DOMAINS...
    mcp_cli.py scan -f <file> [--scan-type=<type>] [--concurrent=<n>] [--output=<format>] [--risk-level=<level>] [--timeout=<seconds>]
    mcp_cli.py fullscan [--output=<format>] [--risk-level=<level>] [--timeout=<seconds>] DOMAINS...
    mcp_cli.py fullscan -f <file> [--output=<format>] [--risk-level=<level>] [--timeout=<seconds>]
    mcp_cli.py status [<scan_id>]
    mcp_cli.py report <scan_id> [--output=<format>]
    mcp_cli.py (-h | --help)

Options:
    -h --help               Show this help message
    --scan-type=<type>      Type of scan to perform (spider, active) [default: spider]
    --concurrent=<n>        Number of concurrent scans [default: 2]
    --output=<format>       Output format (text, json, html) [default: text]
    --risk-level=<level>    Minimum risk level to report (info, low, medium, high) [default: low]
    --timeout=<seconds>     Scan timeout in seconds [default: 3600]
    -f <file>               Read domains from file (one per line)
"""
import asyncio
import sys
import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional
from docopt import docopt
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('MCP-CLI')

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mcp_client import MCPClient

console = Console()

class MCPScanner:
    def __init__(self, concurrent_scans: int = 2, output_format: str = 'text',
                 risk_level: str = 'low', timeout: int = 3600, scan_type: str = 'spider'):
        self.client = MCPClient()
        self.concurrent_scans = concurrent_scans
        self.output_format = output_format
        self.risk_level = risk_level
        self.timeout = timeout
        self.scan_type = scan_type
        self.risk_levels = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
        
    async def scan_domain(self, domain: str, progress: Progress, task_id: TaskID) -> Dict:
        """Scan a single domain with progress tracking."""
        try:
            if not domain.startswith(('http://', 'https://')):
                domain = f'https://{domain}'
                
            progress.update(task_id, description=f"Scanning {domain} ({self.scan_type} scan)")
            
            async with self.client as client:
                # Start scan
                start_time = datetime.now()
                
                if self.scan_type == 'full':
                    # Perform full scan (spider + active)
                    console.print(f"[bold blue]Starting full scan of {domain}[/bold blue]")
                    console.print("[blue]Phase 1: Spider scan to discover content[/blue]")
                    scan_id = await client.full_scan(domain)
                    console.print("[blue]Phase 2: Active scan to find vulnerabilities[/blue]")
                else:
                    # Regular single scan (spider or active)
                    scan_id = await client.start_scan(domain, self.scan_type)
                
                # Monitor progress
                while True:
                    try:
                        status = await client.get_status(scan_id)
                        current_progress = status.get("progress", 0)
                        progress.update(task_id, completed=current_progress)
                        
                        if status.get("is_complete", False):
                            break
                            
                        if (datetime.now() - start_time).seconds > self.timeout:
                            raise TimeoutError(f"Scan timeout after {self.timeout} seconds")
                            
                        await asyncio.sleep(2)
                    except Exception as e:
                        logger.error(f"Error monitoring scan: {str(e)}")
                        raise
                
                # Get results
                alerts = await client.get_alerts(scan_id)
                scan_duration = datetime.now() - start_time
                
                return {
                    'domain': domain,
                    'scan_id': scan_id,
                    'scan_type': self.scan_type,
                    'status': 'success',
                    'duration': str(scan_duration),
                    'alerts': self._filter_alerts(alerts)
                }
                
        except Exception as e:
            logger.error(f"Error scanning {domain}: {str(e)}")
            return {
                'domain': domain,
                'scan_type': self.scan_type,
                'status': 'error',
                'error': str(e)
            }
            
    def _filter_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Filter alerts based on minimum risk level."""
        min_level = self.risk_levels[self.risk_level.lower()]
        return [
            alert for alert in alerts
            if self.risk_levels[alert['risk'].lower()] >= min_level
        ]
            
    async def scan_domains(self, domains: List[str]) -> Dict[str, Dict]:
        """Scan multiple domains concurrently with progress tracking."""
        results = {}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            # Create tasks for each domain
            tasks = {
                domain: progress.add_task(f"Waiting to scan {domain}", total=100)
                for domain in domains
            }
            
            # Process domains in batches
            for i in range(0, len(domains), self.concurrent_scans):
                batch = domains[i:i + self.concurrent_scans]
                batch_results = await asyncio.gather(*[
                    self.scan_domain(domain, progress, tasks[domain])
                    for domain in batch
                ])
                
                for result in batch_results:
                    results[result['domain']] = result
                    
        return results
        
    def output_results(self, results: Dict[str, Dict]):
        """Output results in the specified format."""
        if self.output_format == 'json':
            console.print(json.dumps(results, indent=2))
            
        elif self.output_format == 'html':
            self._generate_html_report(results)
            
        else:  # text format
            table = Table(show_header=True)
            table.add_column("Domain")
            table.add_column("Scan Type")
            table.add_column("Status")
            table.add_column("Findings")
            table.add_column("Duration")
            
            for domain, result in results.items():
                if result['status'] == 'success':
                    alerts_by_risk = {}
                    for alert in result['alerts']:
                        risk = alert['risk']
                        alerts_by_risk[risk] = alerts_by_risk.get(risk, 0) + 1
                        
                    findings = ', '.join(
                        f"{risk}: {count}" 
                        for risk, count in alerts_by_risk.items()
                    )
                    
                    scan_type = result.get('scan_type', 'spider').title()
                    
                    table.add_row(
                        domain,
                        f"[cyan]{scan_type}[/cyan]",
                        "[green]Success[/green]",
                        findings or "No issues found",
                        result['duration']
                    )
                else:
                    scan_type = result.get('scan_type', 'spider').title()
                    
                    table.add_row(
                        domain,
                        f"[cyan]{scan_type}[/cyan]",
                        "[red]Error[/red]",
                        result['error'],
                        ""
                    )
                    
            console.print(table)
            
    def _generate_html_report(self, results: Dict[str, Dict]):
        """Generate detailed HTML report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mcp_scan_report_{timestamp}.html"
        
        html = f"""
        <html>
        <head>
            <title>MCP Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .success {{ color: green; }}
                .error {{ color: red; }}
                .high {{ color: red; }}
                .medium {{ color: orange; }}
                .low {{ color: blue; }}
                .info {{ color: gray; }}
                .spider {{ color: purple; }}
                .active {{ color: teal; }}
                .full {{ color: darkblue; }}
                .domain-section {{ margin: 20px 0; padding: 10px; border: 1px solid #ccc; }}
                .finding {{ margin: 10px 0; padding: 10px; background: #f5f5f5; }}
                .summary {{ background-color: #f0f0f0; padding: 10px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <h1>MCP Security Scan Report</h1>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <p>Total domains scanned: {len(results)}</p>
                <p>Scan type: {self.scan_type.upper()}</p>
            </div>
        """
        
        for domain, result in results.items():
            scan_type = result.get('scan_type', 'spider').title()
            
            html += f"""
            <div class='domain-section'>
                <h2>Domain: {domain}</h2>
                <p>Scan Type: <span class='{scan_type.lower()}'>{scan_type}</span></p>
                <p>Status: <span class='{result["status"]}'>{result["status"].upper()}</span></p>
            """
            
            if result['status'] == 'success':
                html += f"<p>Duration: {result['duration']}</p>"
                
                if result['alerts']:
                    html += "<h3>Security Findings</h3>"
                    
                    # Group findings by risk level
                    findings_by_risk = {}
                    for alert in result['alerts']:
                        risk = alert['risk']
                        if risk not in findings_by_risk:
                            findings_by_risk[risk] = []
                        findings_by_risk[risk].append(alert)
                    
                    # Summary of findings by risk level
                    html += "<div class='risk-summary'><h4>Risk Summary:</h4><ul>"
                    for risk in ['High', 'Medium', 'Low', 'Info']:
                        count = len(findings_by_risk.get(risk, []))
                        if count > 0:
                            html += f"<li><span class='{risk.lower()}'>{risk}</span>: {count}</li>"
                    html += "</ul></div>"
                    
                    # Detailed findings
                    for risk in ['High', 'Medium', 'Low', 'Info']:
                        if risk in findings_by_risk:
                            html += f"<h4 class='{risk.lower()}'>{risk} Risk Findings:</h4>"
                            for alert in findings_by_risk[risk]:
                                html += f"""
                                <div class='finding'>
                                    <h4 class='{alert["risk"].lower()}'>{alert["name"]}</h4>
                                    <p><strong>URL:</strong> {alert["url"]}</p>
                                    <p><strong>Description:</strong> {alert["description"]}</p>
                                    <p><strong>Solution:</strong> {alert.get("solution", "N/A")}</p>
                                </div>
                                """
                else:
                    html += "<p>No security issues found.</p>"
            else:
                html += f"<p>Error: {result['error']}</p>"
                
            html += "</div>"
            
        html += "</body></html>"
        
        with open(filename, 'w') as f:
            f.write(html)
            
        console.print(f"HTML report generated: {filename}")

    async def start_scan(self, target_url: str) -> str:
        """Start a new security scan and return scan ID."""
        response = await self._send_command("start_scan", {
            "config": {
                "target_url": target_url,
                "scan_type": "spider"
            }
        })
        
        if response.get("status") == "success" and "data" in response:
            return response["data"].get("scan_id")
        raise Exception(f"Failed to start scan: {response.get('message', 'Unknown error')}")

async def main():
    args = docopt(__doc__)
    
    # Set scan type based on command
    scan_type = 'spider'  # default
    if args['--scan-type']:
        scan_type = args['--scan-type']
    if args['fullscan']:
        scan_type = 'full'
    
    scanner = MCPScanner(
        concurrent_scans=int(args['--concurrent']) if args['--concurrent'] else 2,
        output_format=args['--output'],
        risk_level=args['--risk-level'],
        timeout=int(args['--timeout']) if args['--timeout'] else 3600,
        scan_type=scan_type
    )
    
    if args['scan'] or args['fullscan']:
        # Get domains from command line or file
        if args['-f']:
            with open(args['<file>'], 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        else:
            domains = args['DOMAINS']
            
        # Show scan type information
        if scan_type == 'full':
            console.print(f"[bold]Starting full security scan (spider + active) on {len(domains)} domain(s)[/bold]")
            console.print("[yellow]Note: Full scans may take significantly longer to complete[/yellow]")
        else:
            console.print(f"[bold]Starting {scan_type} scan on {len(domains)} domain(s)[/bold]")
            
        # Run scans
        results = await scanner.scan_domains(domains)
        scanner.output_results(results)
        
    elif args['status']:
        # TODO: Implement scan status checking
        pass
        
    elif args['report']:
        # TODO: Implement report generation for existing scan
        pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1) 
"""
Example implementation of batch scanning multiple domains using the MCP Server.
"""
import asyncio
from typing import List, Dict
import sys
import os

# Add parent directory to path to import mcp_client
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp_client import MCPClient
from datetime import datetime

class ProgressBar:
    def __init__(self, total: int, prefix: str = '', length: int = 50):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.current = 0

    def update(self, current: int):
        self.current = current
        percentage = (current / self.total) * 100
        filled = int(self.length * current // self.total)
        bar = '█' * filled + '-' * (self.length - filled)
        sys.stdout.write(f'\r{self.prefix} |{bar}| {percentage:.1f}%')
        if current == self.total:
            sys.stdout.write('\n')
        sys.stdout.flush()

class BatchScanner:
    def __init__(self, concurrent_scans: int = 5):
        """Initialize batch scanner with concurrency limit."""
        self.concurrent_scans = concurrent_scans
        self.client = MCPClient()
        self.progress_bars = {}

    async def scan_domains(self, domains: List[str]) -> Dict[str, Dict]:
        """
        Scan multiple domains concurrently and return results.
        
        Args:
            domains: List of domain names to scan
            
        Returns:
            Dictionary mapping domains to their scan results
        """
        print(f"\nStarting batch scan of {len(domains)} domains at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Running {self.concurrent_scans} concurrent scans\n")

        async with self.client as client:
            results = {}
            for i in range(0, len(domains), self.concurrent_scans):
                batch = domains[i:i + self.concurrent_scans]
                print(f"\nProcessing batch {(i//self.concurrent_scans)+1}:")
                tasks = [self.scan_single_domain(client, domain) for domain in batch]
                batch_results = await asyncio.gather(*tasks)
                
                for domain, result in zip(batch, batch_results):
                    results[domain] = result
                    
                print(f"\nBatch {(i//self.concurrent_scans)+1} complete!")
            
            return results

    async def scan_single_domain(self, client: MCPClient, domain: str) -> Dict:
        """
        Scan a single domain and return its results.
        
        Args:
            client: MCPClient instance
            domain: Domain name to scan
            
        Returns:
            Dictionary containing scan results and metadata
        """
        start_time = datetime.now()
        result = {
            'status': 'failed',
            'alerts': [],
            'start_time': start_time.isoformat(),
            'end_time': None,
            'duration': None,
            'error': None
        }

        try:
            # Initialize progress bar
            progress_bar = ProgressBar(total=100, prefix=f'{domain:30}')
            self.progress_bars[domain] = progress_bar
            progress_bar.update(0)

            # Start scan
            scan_id = await client.start_scan(f"https://{domain}")
            
            # Monitor progress
            while True:
                status = await client.get_status(scan_id)
                progress_bar.update(status.progress)
                if status.is_complete:
                    break
                await asyncio.sleep(2)
            
            # Get results
            alerts = await client.get_alerts(scan_id)
            
            # Update result
            end_time = datetime.now()
            result.update({
                'status': 'success',
                'alerts': alerts,
                'end_time': end_time.isoformat(),
                'duration': str(end_time - start_time)
            })
            
        except Exception as e:
            result['error'] = str(e)
            print(f"\nError scanning {domain}: {e}")
        
        return result

async def main():
    """Example usage of BatchScanner."""
    domains = [
        "example.com",
        "test.com",
        "demo.com",
        "staging.example.com",
        "dev.example.com"
    ]
    
    scanner = BatchScanner(concurrent_scans=2)
    results = await scanner.scan_domains(domains)
    
    # Print summary
    print("\nScan Summary:")
    print("-" * 80)
    for domain, result in results.items():
        status = "✅" if result['status'] == 'success' else "❌"
        alerts_count = len(result['alerts']) if result['status'] == 'success' else 'N/A'
        duration = result['duration'] if result['duration'] else 'N/A'
        print(f"{status} {domain:30} | Alerts: {alerts_count:4} | Duration: {duration}")
        
        if result['error']:
            print(f"   Error: {result['error']}")
        elif result['status'] == 'success':
            risk_levels = {}
            for alert in result['alerts']:
                risk_levels[alert['risk']] = risk_levels.get(alert['risk'], 0) + 1
            print("   Risk Levels:", ", ".join(f"{k}: {v}" for k, v in risk_levels.items()))

if __name__ == "__main__":
    asyncio.run(main()) 
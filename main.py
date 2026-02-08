import time
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.engine import Scanner
from core.lookup import VulnLookup
from utils.data_handler import DataHandler

console = Console()

def run_watcher(target):
    # Initialize
    scanner = Scanner()
    lookup = VulnLookup()
    handler = DataHandler()
    
    console.print(Panel(f"[bold blue]The Watcher[/bold blue]\n[white]Starting reconnaissance on: {target}[/white]"), justify="center")

    # 1. Scanning Phase
    with console.status("[bold green]Scanning network...") as status:
        raw_results = scanner.scan(target)
    
    if not raw_results:
        console.print("[bold red]No hosts found or scan failed.[/bold red]")
        return

    # 2. Enrichment Phase
    # We will build a table to show results in real-time
    table = Table(title="Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("IP Address", style="dim")
    table.add_column("Port/Proto")
    table.add_column("Service")
    table.add_column("Top CVE")
    table.add_column("CVSS", justify="center")

    enriched_data = raw_results
    
    console.print(f"[*] Found {len(raw_results)} hosts. Checking vulnerabilities...")

    # Traverse your nested dictionary structure
    for host_index, host_dict in enumerate(enriched_data):
        ip = list(host_dict.keys())[0]
        for proto in host_dict[ip].keys():
            for port in host_dict[ip][proto].keys():
                service_item = host_dict[ip][proto][port]
                
                # Fetch Vulns
                cpe = service_item.get('cpe')
                vulns = lookup.check_vulnerabilities(cpe)
                service_item['vulnerabilities'] = vulns
                
                # Table Formatting logic
                cve_display = "None"
                cvss_display = "-"
                
                if vulns:
                    top_vuln = vulns[0]
                    cve_display = top_vuln['id']
                    score = top_vuln['cvss']
                    cvss_display = f"[bold red]{score}[/bold red]" if score and score >= 7 else str(score)

                table.add_row(
                    ip, 
                    f"{port}/{proto}", 
                    f"{service_item['product']} {service_item['version']}",
                    cve_display,
                    cvss_display
                )
                
                # Uncomment the 6s delay here to avoid NIST's NVD rate limiting
                # time.sleep(6) 

    console.print(table)

    # 3. Save Phase
    report_path = handler.save_results(target.replace('/', '_'), enriched_data)
    console.print(f"\n[bold green]✔ Done![/bold green] Report saved to [italic]{report_path}[/italic]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The Watcher: Network Scanner & Vuln Mapper")
    parser.add_argument("--target", help="Target IP or CIDR (e.g., 192.168.1.0/24)", required=True)
    
    args = parser.parse_args()
    run_watcher(args.target)
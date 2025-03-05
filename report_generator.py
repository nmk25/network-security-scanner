# Generates scan reports

import datetime

def generate_report(scan_results, filename = "scan_report.txt"):
    with open(filename, "w") as f:
        f.write(f"Network Scan Report\n")
        f.write(f"Generated on: {datetime.now()}\n\n")

        for host, ports in scan_results.items():
            f.write(f"Host: {host}\n")

            for port, state in ports.items():
                f.write(f"Port: {port}\tState: {state}\n\n")
            
            f.write("\n")
    
    print(f"Report saved to {filename}")
    
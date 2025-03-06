# Network Security Scanner
# Nate Kadlec

import nmap
import argparse
from report_generator import generate_report

def scan_network(ip_range, ports):
    nm = nmap.PortScanner()
    print(f"Scanning {ip_range}...")
    nm.scan(hosts = ip_range, arguments = '-sn')    # Scan to find live hosts in IP range

    scan_results = {}

    for host in nm.all_hosts():
        host = str(host)

        # Check if host exists and has a state to avoid KeyError
        if host in nm and 'status' in nm[host] and nm[host]['status']['state'] == 'up':
            print(f"\nScanning ports on {host}...")
            nm.scan(hosts = host, arguments = f'-p {ports}')

            ports_dict = {}

            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()

                for port in ports:
                    state = nm[host][proto][port]['state']
                    ports_dict[port] = state
                    print(f"Port: {port}\tState: {state}")

            scan_results[host] = ports_dict

if __name__ == "__main__":
    #ip_range = "172.18.0.0/24"      # Docker's default network range
    #ports = "22,80,443"             # SSH, HTTP, HTTPS
    #scan_network(ip_range, ports)

    parser = argparse.ArgumentParser(description = "Network Security Scanner")
    parser.add_argument("--ip", default = "172.18.0.0/24", help = "IP range to scan")
    parser.add_argument("--ports", default = "22,80,443", help = "Ports to scan")
    args = parser.parse_args()

    results = scan_network(args.ip, args.ports)
    generate_report((results))
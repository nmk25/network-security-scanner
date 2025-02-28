# Network Security Scanner
# Nate Kadlec

import nmap

def scan_network(ip_range):
    nm = nmap.PortScanner()
    print(f"Scanning {ip_range}...")
    nm.scan(hosts = ip_range, arguments = '-sn')    # Scan to find live hosts in IP range

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f"\nScanning ports on {host}...")
            nm.scan(hosts = host, arguments = '-p 22,80,443')     # SSH, HTTP, HTTPS
            print(f"Host: {host}")

            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()

                for port in ports:
                    state = nm[host][proto][port]['state']
                    print(f"Port: {port}\tState: {state}")

if __name__ == "__main__":
    ip_range = "172.18.0.0/24"      # Docker's default network range
    scan_network(ip_range)

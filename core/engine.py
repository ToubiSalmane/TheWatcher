import nmap
# We'll wrap this in a try/except in case someone deletes the utils folder
try:
    from utils.localIP import getLocalIP
except ImportError:
    getLocalIP = None

class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        try:
            self.local = getLocalIP()
        except Exception as e:
            print(e)
            self.local = ''

    def scan(self, target):
        """Scans for live systems, then scans each of them for services."""
        print(f"[*] Scanning {target} for running hosts...")
        # Ping scan to find live hosts
        self.nm.scan(target, arguments='-sn')

        hosts = self.nm.all_hosts()
        try:
            hosts.remove(self.local)
        except ValueError:
            print("Your machine is outside of scope.")

        if not hosts:
            print("[-] No live hosts found.")
            return []
        
        for host in hosts:
            print(f'[+] Host found: {host}')
        
        # Initialize a list for results
        scan_results = []
        # Initialize a counter to keep track of the host
        counter = 0

        print(f"[*] Deep scanning {len(hosts)} hosts...")
        for host in hosts:
            print(f'    > Scanning services on {host}...')
            # -sV: Version detection, -T4: Faster timing, --version-intensity 5: Balanced
            self.nm.scan(host, arguments='-sV -T4')
            scan_results.append({host:{}})
            try:
                # Iterate through all protocols (tcp/udp)
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()

                    scan_results[counter][host][proto] = {}
                    for port in ports:
                        service = self.nm[host][proto][port]

                        if service['cpe']:
                            cpe_string = service['cpe']
                        else:
                            continue

                        # Create a clean, flat dictionary object
                        service_data = {
                            "name": service.get('name', 'unknown'),
                            "product": service.get('product', 'unknown'),
                            "version": service.get('version', ''),
                            "cpe": cpe_string,
                            "conf": service.get('conf', 0)
                        }
                        scan_results[counter][host][proto][port] = service_data
                        # Print as we find them (Feedback for user)
                        print(f"      Found open port {port}: {service_data['product']} {service_data['version']}")

                counter += 1
            except KeyError as e:
                print(f"[!] Error parsing data for {host}: {e}")
                continue

        return scan_results
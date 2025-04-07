from scapy.all import sniff, DNSQR, DNS
import socket
import os # os for executing system commands (Windows firewall rules)

# Domains substring  (match by substring)
BLOCKLIST = ["facebook", "youtube", "reddit", "pinterest"]
blocked_ips = set()  # Track already blocked IPs to avoid duplicates

# Function to block an IP address using Windows Firewall
def block_ip(ip):
    if ip not in blocked_ips:  # Check if this IP hasn't been blocked already
        cmd = f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=out action=block remoteip={ip}'# Command to create Windows Firewall outbound block rule
        os.system(cmd)
        blocked_ips.add(ip) # Add IP to our tracking set
        print(f"\n BLOCKED NEW IP: {ip}")
        print(f" Added Windows Firewall rule for {ip}")
# Function to process each captured network packet
def process_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:# Check if packet has DNS layer and is a query (not response
        domain = packet[DNSQR].qname.decode().rstrip(".").lower()

        # Skip spoofed or local domains
        if domain.endswith(".ac.in") or domain.endswith(".nitw.ac.in"):
            return

        for blocked in BLOCKLIST:
            if blocked in domain:
                try:
                    ip = socket.gethostbyname(domain) #to resolve the domain into an IP address.
                    print(f"\n BLOCKED DOMAIN DETECTED: {domain}")
                    print(f" Resolved to IP: {ip}")
                    block_ip(ip) #add the firewall rule.
                    break  # No need to check other blocklist entries
                except Exception as e:
                    print(f"\n Failed to block {domain}: {str(e)}")
                    break

print("\n Starting DNS monitor (Press Ctrl+C to stop)...")
print(f" Blocklist: {', '.join(BLOCKLIST)}")
print(" Only showing alerts for blocked domains\n")
sniff(filter="udp port 53", store=False, prn=process_packet) 


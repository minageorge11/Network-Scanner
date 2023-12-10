import scapy.all as scapy
import argparse
import csv

def scan(ip):
    # Creating an ARP request packet
    arp_request = scapy.ARP(pdst=ip)
    
    # Creating an Ethernet frame to encapsulate the ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the Ethernet frame and ARP request packet
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and receive the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # Create a list of dictionaries to store the scan results
    clients_list = []
    
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        
    return clients_list

def scan_ports(ip, ports):
    # Creating a TCP SYN packet for port scanning
    try:
        target_ip = scapy.IP(dst=ip)
        target_ports = ports.split(",")
        port_scan = scapy.TCP(dport=target_ports, flags="S")
        packet = target_ip / port_scan
        answered, unanswered = scapy.sr(packet, timeout=1, verbose=False)
        
        # Create a list of dictionaries to store the port scan results
        open_ports_list = []
        
        for element in answered:
            port_dict = {"port": element[1].dport, "status": "open"}
            open_ports_list.append(port_dict)
        
        return open_ports_list
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return []

def save_to_csv(data, filename):
    # Save scan results to a CSV file
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

def main():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("-t", "--target", dest="target", help="Target IP address or IP range")
    parser.add_argument("-p", "--ports", dest="ports", help="Ports to scan (comma-separated)")
    parser.add_argument("-o", "--output", dest="output", help="Output filename for scan results (CSV)")

    args = parser.parse_args()

    if not args.target:
        parser.error("[-] Please specify a target IP address or IP range. Use the -t option.")
    
    if not args.ports:
        parser.error("[-] Please specify ports to scan. Use the -p option.")
    
    target_ip = args.target
    target_ports = args.ports
    output_filename = args.output if args.output else "scan_results.csv"

    print("[+] Scanning the network...")
    scan_results = scan(target_ip)
    print("[+] Network scan complete.")
    
    print("[+] Scanning open ports...")
    port_results = scan_ports(target_ip, target_ports)
    print("[+] Port scan complete.")
    
    # Combine results and generate a report
    full_results = {
        "network_scan": scan_results,
        "port_scan": port_results
    }

    # Save results to CSV file
    save_to_csv(full_results["network_scan"], output_filename)
    print(f"[+] Results saved to {output_filename}")

if __name__ == "__main__":
    main()

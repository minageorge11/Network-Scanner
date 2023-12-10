# Network-Scanner
This network scanner tool uses Scapy for packet manipulation and network scanning.

This script uses Scapy to send ARP requests to discover devices on the network and performs a TCP SYN scan on specified ports to identify open ports. The results are then saved to a CSV file. 

To run the script, use the following command:

python network_scanner.py -t <target_ip> -p <port_range> -o <output_filename>

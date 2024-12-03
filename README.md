# **ARP Spoofer & Network Scanner**

A Python-based tool designed for network scanning and ARP spoofing. This project allows users to perform network scans, conduct ARP poisoning attacks, and manage port forwarding for packet redirection. It is intended for **educational and ethical purposes only**.

---

## **Features**

- **Network Scanning**:  
  Discover live hosts on a network and retrieve their IP and MAC addresses.
- **ARP Poisoning**:  
  Perform ARP spoofing to redirect network traffic and conduct man-in-the-middle (MITM) attacks.
- **Port Forwarding**:  
  Dynamically enable or disable port forwarding during attacks.
- **Threaded Execution**:  
  Execute ARP poisoning in a separate thread for efficient operation.
- **Logging**:  
  Informative, color-coded logs for a better user experience.
- **Save Scan Results**:  
  Automatically save scanned results to a `scan_results.txt` file.

---

## **Requirements**

1. **Python 3.10.10** installed on your system.
2. **Root Privileges**: This script requires administrative permissions.
3. **Dependencies**: Install required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

### Dependencies:
- `scapy`: Install using `pip install scapy`.

---

## **Usage**

### **1. Clone the Repository**
```bash
git clone https://github.com/ssam246/ARP-Spoofer-Network-Scanner
cd arp-spoofer
```

### **2. Install Dependencies**
```bash
pip install -r requirements.txt
```

### **3. Run the Script**

#### **General Command**:
```bash
sudo python3 arp_spoofer.py [options]
```

#### **Options**:
| Option                        | Description                                           |
|-------------------------------|-------------------------------------------------------|
| `-s {ip_range}`, `--scan`     | Scan the network for live hosts.                     |
| `-i {interface}`, `--interface` | Specify the network interface (e.g., `wlan0`).       |
| `-t {target_ip}`, `--target`  | Specify the target IP for ARP poisoning.             |
| `-g {gateway_ip}`, `--gateway`| Specify the gateway IP for ARP poisoning.            |

---

### **Examples**

#### **Scan a Network**:
Discover live hosts on a specific network range:
```bash
sudo python3 arp_spoofer.py --scan 192.168.0.0/24
```

#### **Perform ARP Poisoning**:
Redirect traffic between a target device and the gateway:
```bash
sudo python3 arp_spoofer.py -i wlan0 -t 192.168.1.2 -g 192.168.1.1
```

---

## **How It Works**

### **1. Network Scanning**:
- Sends ARP requests to all devices in the specified network range.
- Discovers live devices and logs their IP and MAC addresses.
- Saves results to `scan_results.txt`.

### **2. ARP Poisoning**:
- Sends forged ARP packets to the target and gateway, tricking them into routing traffic through the attacker.
- Creates a man-in-the-middle (MITM) scenario for packet interception and analysis.

### **3. Port Forwarding**:
- Dynamically enables IP forwarding during attacks for smooth packet redirection.
- Automatically resets port forwarding after stopping the script.

### **4. Logging**:
- Color-coded logs provide detailed feedback during execution.
- Logs include information about discovered devices, ARP spoofing status, and error messages.

---

## **File Structure**
```
├── arp_spoofer.py       # Main script
├── requirements.txt     # Python dependencies
├── scan_results.txt     # Output file for scan results (generated)
├── README.md            # Documentation
```

---

## **Notes**

1. **Wireshark Integration**:  
   Use Wireshark to monitor network packets. Apply a filter such as `ip.addr == <target_ip>` for focused analysis.

2. **Stopping the Script**:  
   Use `Ctrl+C` to terminate the script. Port forwarding will automatically reset.

3. **Educational Use Only**:  
   Ensure you have permission before using this tool on any network.

---

## **Future Enhancements**
- Add support for custom packet capture filters.
- Include a GUI for easier operation.
- Add detection and prevention features for ARP spoofing.

---

## **Disclaimer**
This tool is designed for **educational purposes only**.  
The author does not condone the use of this tool for illegal or malicious activities.  
Always ensure proper authorization before running this script on any network.

---

### **Made with 💻 and 🛡️ by Stephen Sam**


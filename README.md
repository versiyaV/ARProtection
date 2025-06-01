# ARP Spoofing Detection and Mitigation System

## Core Functionality

### Detection Phase
- Continuously monitors ARP packets on specified interface (`eth0`, `wlan0`, etc.)
- Validates ARP responses by:
  - Checking packet structure (OP code 2 for responses)
  - Comparing advertised vs known MAC addresses
  - Verifying sender IP-MAC consistency

### Mitigation Phase
- When attack detected:
  ```bash
  # Linux
  ifconfig [interface] down
  
  # Windows 
  netsh interface set interface [interface] disable
  ```
- Logs attack details:
  - Timestamp
  - Spoofed IP/MAC
  ```bash
  [Timestamp] - WARNING - ARP Spoofing detected! 192.168.1.0 is claiming to be aa:bb:cc:dd:ee:ff but really is e8:2a:44:23:81:30
  ```
### Install
#### Warning: Must be run under super-user
```bash
git clone https://github.com/versiyaV/ARProtection.git
cd ARProtection
python3 -m pip install --upgrade pip
pip install pytest scapy
python3 arp_protection.py -i [interface] -v
```

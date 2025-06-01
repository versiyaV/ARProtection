#!/usr/bin/env python
import scapy.all as scapy
import subprocess
import argparse
import platform
import logging
from threading import Timer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='arp_protection.log'
)
logger = logging.getLogger(__name__)

ATTACK_DETECTED = False
INTERFACE = ""
OS_NAME = ""
BLOCK_DURATION = 15  # seconds
BROADCAST_IP = "255.255.255.255"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofing Detection and Protection Tool")
    parser.add_argument("-i", "--interface", dest="interface", required=True,
                        help="Network interface to monitor (e.g., eth0, wlan0)")
    parser.add_argument("-d", "--duration", dest="duration", type=int, default=15,
                        help="Duration to disable interface when attack detected (default: 15s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    global BLOCK_DURATION
    BLOCK_DURATION = args.duration
    
    return args

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst=BROADCAST_MAC)
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1][scapy.ARP].hwsrc
        return None
    except Exception as e:
        logger.error(f"Error getting MAC for {ip}: {e}")
        return None

def validate_arp_packet(packet):
    if not packet.haslayer(scapy.ARP):
        return False

    if packet[scapy.ARP].op != 2:
        return False

    if packet[scapy.ARP].pdst == BROADCAST_IP:
        return False
        
    return True

def process_sniffed_packet(packet):
    global ATTACK_DETECTED
    
    if not validate_arp_packet(packet):
        return
    
    try:
        sender_ip = packet[scapy.ARP].psrc
        sender_mac = packet[scapy.ARP].hwsrc
        
        real_mac = get_mac(sender_ip)
        
        if real_mac and sender_mac.lower() != real_mac.lower():
            logger.warning(f"ARP Spoofing detected! {sender_ip} is claiming to be {sender_mac} but really is {real_mac}")
            print("\n[!] WARNING: ARP Spoofing Attack Detected!")
            print(f"    {sender_ip} is claiming to be {sender_mac} but really is {real_mac}")
            
            if not ATTACK_DETECTED:
                ATTACK_DETECTED = True
                protect_action()
                
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def protect_action():
    logger.info("Taking protective actions...")
    print("[!] Taking protective actions...")

    disable_network()

    t = Timer(BLOCK_DURATION, restore_network)
    t.start()

def disable_network():
    try:
        if OS_NAME == "Linux":
            subprocess.run(["ip link set dev ", INTERFACE, "down"], check=True)
        elif OS_NAME == "Windows":
            subprocess.run(["netsh", "interface", "set", "interface", INTERFACE, "disable"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to disable interface: {e}")

def restore_network():
    try:
        if OS_NAME == "Linux":
            subprocess.run(["ip link set dev ", INTERFACE, "up"], check=True)
        elif OS_NAME == "Windows":
            subprocess.run(["netsh", "interface", "set", "interface", INTERFACE, "enable"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to restore interface: {e}")

def get_platform():
    os_name = platform.system()
    logger.info(f"Detected OS: {os_name}")
    return os_name

def main():
    global INTERFACE, OS_NAME
    
    args = get_arguments()
    INTERFACE = args.interface
    OS_NAME = get_platform()
    
    print(f"[*] Starting ARP Spoofing Protection on interface {INTERFACE}")
    print(f"[*] OS detected: {OS_NAME}")
    print("[*] Monitoring network... Press Ctrl+C to stop")
    
    try:
        scapy.sniff(iface=INTERFACE, store=False, prn=process_sniffed_packet)
    except KeyboardInterrupt:
        print("\n[*] Stopping ARP protection...")
        logger.info("ARP protection stopped by user")
    except Exception as e:
        logger.error(f"Error in sniffing: {e}")
        print("[!] Error occurred. Check logs for details.")

if __name__ == "__main__":
    main()
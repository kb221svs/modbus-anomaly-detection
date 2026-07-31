from scapy.all import load_contrib, bind_layers, rdpcap, sniff, wrpcap
load_contrib('modbus')
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
from scapy.layers.inet import IP, TCP
import os
import time
import subprocess

# Centralized file list
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES = {
    '1': os.path.join(BASE_DIR, 'modbus.pcap'),
    '2': os.path.join(BASE_DIR, 'ssh_modbus_eth0.pcap'),
    '3': os.path.join(BASE_DIR, 'modbus_eth0.pcap'),
    '4': os.path.join(BASE_DIR, 'modbus_lo.pcap'),
    '5': os.path.join(BASE_DIR, 'live_attacks_captured.pcap'),
    '6': os.path.join(BASE_DIR, 'modbus_enp0s3.pcap'
}

# Layer binding configuration
bind_layers(TCP, ModbusADURequest, dport=502)
bind_layers(TCP, ModbusADUResponse, sport=502)

time_window = 1.0
threshold = 20
packet_history = {}
blocked_ips = set()
def is_rate_limit_exceeded(ip):
    current_time = time.time()
    if ip not in packet_history:
        packet_history[ip] = []
    packet_history[ip].append(current_time)
    packet_history[ip] = [t for t in packet_history[ip] if current_time - t < time_window]
    return len(packet_history[ip]) > threshold

def write_log(message):
    with open("alerts.log", "a") as log:
        log.write(f"[{time.ctime()}] {message}\n")

def block_attacker_ip(ip):
    try:
        subprocess.run(f'sudo iptables -I INPUT -s {ip} -j DROP', shell=True, check=True)
        subprocess.run(f"sudo iptables -I FORWARD -s {ip} -j DROP",shell=True,check=True)
        print(f'[***]IPS ACTION: Successfully blocked IP {ip} via iptables.')
    except subprocess.CalledProcessError as e:
        print(f'[-]Failed to block IP: {e}')

def classify_source(src_ip):
    if src_ip == "192.41.15.2":
        return "SCADA"
    elif src_ip == "192.41.15.3":
        return "Kali-Attacker"
    elif src_ip == "192.41.15.1":
        return "PLC"
    else:
        return "Unknown"

def get_file_choice():
    """Universal file selection function for all modules"""
    print('\n--- Available PCAP Files ---')
    for key, path in FILES.items():
        print(f"{key} - {path}")
    
    choice = input('Choose a file number (or "q" to cancel): ').strip()
    return FILES.get(choice)

def analyze_pcap():
    """Module for detailed manual packet analysis"""
    file_path = get_file_choice()
    if not file_path: return
    
    try:
        print(f"[*] Loading {file_path}...")
        d = rdpcap(file_path)
        print(f'[+] Success. Number of packets: {len(d)}')
        
        while True:
            cmd = input('\nEnter a row number (or "q" to back to menu): ').strip()
            if cmd.lower() == 'q': break
            
            try:
                a = int(cmd)
                if 0 <= a < len(d):
                    print('\n1 - Structured (Summary)\n2 - Hierarchical (Detailed)')
                    mode = input('Your choice: ').strip()
                    
                    print("-" * 50)
                    if mode == '1':
                        print(d[a].summary())
                    else:
                        d[a].show()
                    print("-" * 50)
                else:
                    print(f'[!] Error: Packet #{a} not found. Max index: {len(d)-1}')
            except ValueError:
                print("[!] Please enter a numeric value!")
    except Exception as e:
        print(f"[!] Error reading file: {e}")

def detect_attacks():
    """Module for automated attack detection (IDS)"""
    file_path = get_file_choice()
    if not file_path: return
    
    try:
        print(f"[*] Analyzing {file_path} for attacks...")
        packets = rdpcap(file_path)
        suspicious_count = 0
        
        for pkt in packets:
            # Modbus check
            if pkt.haslayer("ModbusADURequest") or pkt.haslayer("ModbusPDU"):
                layer = pkt.getlayer("ModbusADURequest") or pkt.getlayer("ModbusPDU")
                
                if hasattr(layer, 'funcCode'):
                    f_code = layer.funcCode
                    # Detecting critical function codes (Write/Control)
                    if f_code in [1, 5, 6, 15, 16]: 
                        print(f"[!] Write command detected! Function Code: {f_code}")
                        suspicious_count += 1
                
                # IP spoofing/Suspicious source check
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    source = classify_source(src_ip)
                    if src_ip not in ['192.41.15.2', '192.41.15.1', '127.0.0.1']:
                        print(f'[!] WARNING! Suspicious IP detected: {source} {src_ip}')

        print(f'\n[+] Analysis complete. Total incidents detected: {suspicious_count}')
    except Exception as e:
        print(f"[!] Analysis error: {e}")

def live_capture_ids():
    print("\n[*] Starting LIVE capture mode...")
    print("[*] Listening for SSH & Modbus (30 sec capture)...")    
    captured_data = []
    def process_packet(pkt):
        if not pkt.haslayer(IP):
            return
        src_ip = pkt[IP].src
        source = classify_source(src_ip)
        is_bad = False
        if src_ip not in ['192.41.15.2', '192.41.15.1', '127.0.0.1']:
            print(f"[!] LIVE ALERT: Unauthorized IP {source} ({src_ip})!")
            write_log(f"[!] LIVE ALERT: Unauthorized IP {source}({src_ip})!")
            is_bad = True
        if src_ip != '192.41.15.1' and is_rate_limit_exceeded(src_ip):
            print(f"[!!!] DDOS ALERT: from {source}({src_ip}) sends too many packets!")
            write_log(f"[!!!] DDOS ALERT: from {source}({src_ip}) sends too many packets!")
            if src_ip not in blocked_ips:
                block_attacker_ip(src_ip)
                blocked_ips.add(src_ip)
            is_bad = True
        if pkt.haslayer("ModbusADURequest") or pkt.haslayer("ModbusPDU"):
            layer = pkt.getlayer("ModbusADURequest") or pkt.getlayer("ModbusPDU")
            if hasattr(layer, 'funcCode') and layer.funcCode in [1, 5, 6, 15, 16]:
                print(f"[!] LIVE ALERT: Critical Modbus Function {layer.funcCode} detected from {source}({src_ip})!")
                write_log(f"[!] LIVE ALERT: Critical Modbus Function {layer.funcCode} detected from {source}({src_ip})!")
                is_bad = True
                
        if is_bad:
            captured_data.append(pkt)

    try:
        sniff(
            iface="enp0s3",   
            prn=process_packet,
            filter="tcp port 22 or tcp port 502", 
            timeout=30       
        )
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")

    print(f"\n[*] Captured suspicious packets: {len(captured_data)}")

    if captured_data:
        output_file = "live_attacks_captured.pcap"
        wrpcap(output_file, captured_data)
        print(f"[+] Saved {len(captured_data)} packets to {output_file}")
    else:
        print("[!] No suspicious packets captured.")

while True:
    print('\n========== MAIN MENU ==========')
    print('1. Detailed PCAP Analysis')
    print('2. Automated Attack Detection')
    print('3. LIVE Capture & IDS Mode (Sniffing)')
    print('4. Exit program')
    print('===============================')
    
    choice = input('Make your choice: ').strip()
    
    if choice == '1':
        analyze_pcap()
    elif choice == '2':
        detect_attacks()
    elif choice == '3':
        live_capture_ids()
    elif choice == '4':
        print('Exiting... Good bye!')
        break
    else:
        print('[!] Invalid choice. Please try again.')

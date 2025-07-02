import os
import argparse
from scapy.all import *
from colorama import Fore, Style
from datetime import datetime
import threading

def banner():
    print(Fore.GREEN + r"""
  ██████╗  █████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
  ██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██████╔╝███████║██║   ██║██████╔╝███████║███████╗█████╗  
  ██╔═══╝ ██╔══██║██║   ██║██╔═══╝ ██╔══██║╚════██║██╔══╝  
  ██║     ██║  ██║╚██████╔╝██║     ██║  ██║███████║███████╗
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
        [ Bypass Banner - Firewall Evasion Tool ]
""" + Style.RESET_ALL)

def log(message):
    with open("logs.txt", "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

# -----------------------------------
# 🔍 Live Packet Sniffer (Sniff replies)
# -----------------------------------
sniffed_packets = []

def start_sniffer(target):
    def packet_callback(pkt):
        if IP in pkt and pkt[IP].src == target:
            sniffed_packets.append(pkt)
    sniff(filter=f"ip host {target}", prn=packet_callback, timeout=20, store=0)

# -----------------------------------
# 🧪 Individual Tests
# -----------------------------------
def icmp_bypass(target):
    print(Fore.YELLOW + "[1] ICMP Fragmented Packet Test..." + Style.RESET_ALL)
    pkt = IP(dst=target, ttl=1)/ICMP()/("X"*600)
    send(pkt, verbose=False)
    log(f"ICMP fragmented sent to {target}")

def tcp_frag_bypass(target):
    print(Fore.YELLOW + "[2] TCP Fragmentation Scan..." + Style.RESET_ALL)
    os.system(f"nmap -f {target} -Pn -T4 > nmap_tcp_frag.txt")
    log(f"TCP Fragmentation scan sent to {target}")

def source_port_53(target):
    print(Fore.YELLOW + "[3] Source Port Spoof (53) Scan..." + Style.RESET_ALL)
    os.system(f"nmap --source-port 53 {target} -Pn -T4 > nmap_dns.txt")
    log(f"Source Port 53 spoof scan to {target}")

def decoy_scan(target):
    print(Fore.YELLOW + "[4] Decoy IP Scan..." + Style.RESET_ALL)
    os.system(f"nmap -D RND:10 {target} -Pn -T4 > nmap_decoy.txt")
    log(f"Decoy scan to {target}")

def dns_tunnel_emulation(target):
    print(Fore.YELLOW + "[5] DNS Tunnel Emulation..." + Style.RESET_ALL)
    pkt = IP(dst=target)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname="secretdata.lab"))
    send(pkt, verbose=False)
    log(f"DNS tunnel sent to {target}")

def custom_scapy_tcp(target):
    print(Fore.YELLOW + "[6] Custom Raw TCP Packet..." + Style.RESET_ALL)
    pkt = IP(dst=target)/TCP(dport=80, flags="S", window=2048, options=[('MSS',1460)])
    send(pkt, verbose=False)
    log(f"Custom raw TCP sent to {target}")

# -----------------------------------
# 🧠 Auto Analysis (Firewall Behavior Detection)
# -----------------------------------
def analyze_firewall_behavior():
    print(Fore.MAGENTA + "\n🔍 Auto Analysis of Firewall Behavior:" + Style.RESET_ALL)
    responses = [p.summary() for p in sniffed_packets]
    if any("ICMP" in r for r in responses):
        print(Fore.GREEN + "✓ ICMP reply received – ICMP likely ALLOWED" + Style.RESET_ALL)
    else:
        print(Fore.RED + "✗ No ICMP reply – ICMP may be BLOCKED" + Style.RESET_ALL)

    if os.path.exists("nmap_tcp_frag.txt"):
        with open("nmap_tcp_frag.txt") as f:
            content = f.read()
            if "open" in content:
                print(Fore.GREEN + "✓ TCP fragmentation succeeded – Firewall allowed fragments" + Style.RESET_ALL)
            else:
                print(Fore.RED + "✗ TCP fragmentation likely blocked" + Style.RESET_ALL)

    if os.path.exists("nmap_dns.txt"):
        with open("nmap_dns.txt") as f:
            content = f.read()
            if "open" in content:
                print(Fore.GREEN + "✓ Source port 53 scan succeeded – DNS spoofing not blocked" + Style.RESET_ALL)
            else:
                print(Fore.RED + "✗ Source port spoofing blocked" + Style.RESET_ALL)

    if os.path.exists("nmap_decoy.txt"):
        with open("nmap_decoy.txt") as f:
            content = f.read()
            if "open" in content:
                print(Fore.GREEN + "✓ Decoy scan worked – No IP filtering or tracking detected" + Style.RESET_ALL)
            else:
                print(Fore.RED + "✗ Decoy scan ineffective or blocked" + Style.RESET_ALL)

# -----------------------------------
# 🚀 Main Execution Flow
# -----------------------------------
def full_auto_bypass(target):
    print(Fore.MAGENTA + f"\n🔥 Starting firewall evasion test on {target}...\n" + Style.RESET_ALL)

    sniffer_thread = threading.Thread(target=start_sniffer, args=(target,))
    sniffer_thread.start()

    icmp_bypass(target)
    tcp_frag_bypass(target)
    source_port_53(target)
    decoy_scan(target)
    dns_tunnel_emulation(target)
    custom_scapy_tcp(target)

    sniffer_thread.join()

    analyze_firewall_behavior()
    print(Fore.CYAN + "\n✅ All tests completed. Check 'logs.txt' and nmap_*.txt files.\n" + Style.RESET_ALL)

def main():
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Target IP Address for Bypass Test")
    args = parser.parse_args()
    full_auto_bypass(args.target)

if __name__ == "__main__":
    main()
"""
Controlled Lab Attack Simulator for Advance NIDS System Validation
Generates sequential Port Scans, TCP SYN Floods, and ICMP Floods.
Aligned strictly with Review 1 project specifications.
Authors: Yashveer Singh & Atharva Gupta | Guide: Dr. Priya M
"""

import time
import sys
import socket
from scapy.all import send
from scapy.layers.inet import IP, TCP, ICMP

DEFAULT_TARGET = "127.0.0.1"


def get_local_ip():
    """Returns local active host IP if available."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def dispatch(packets, label):
    """Dispatches raw packets reliably and fast within the 5.0-second sliding window."""
    print(f"[+] Dispatching {len(packets)} {label} packets...")
    try:
        send(packets, verbose=False)
    except Exception as e:
        print(f"[!] Bulk dispatch note ({e}). Falling back to rapid iterative dispatch...")
        for pkt in packets:
            send(pkt, verbose=False)


def simulate_port_scan(target):
    print(f"\n[1/3] Generating Port Scan on {target} (Ports 20 to 45)...")
    # 26 packets hitting unique ports in under a second (Threshold is > 15)
    packets = [IP(dst=target)/TCP(dport=port, flags="S") for port in range(20, 46)]
    dispatch(packets, "port scan probe")
    print("[+] 26 port probe packets dispatched (Rule: >15 unique ports in 5s).")


def simulate_syn_flood(target):
    print(f"\n[2/3] Generating TCP SYN Flood on {target}:80 (45 SYN packets)...")
    # 45 SYN-only packets to port 80 (Threshold is > 30)
    packets = [IP(dst=target)/TCP(dport=80, sport=3000+i, flags="S") for i in range(45)]
    dispatch(packets, "TCP SYN-only")
    print("[+] 45 TCP SYN packets dispatched (Rule: >30 SYNs in 5s).")


def simulate_icmp_flood(target):
    print(f"\n[3/3] Generating ICMP Ping Flood on {target} (35 ICMP packets)...")
    # 35 Echo requests (Threshold is > 25)
    packets = [IP(dst=target)/ICMP() for _ in range(35)]
    dispatch(packets, "ICMP Echo")
    print("[+] 35 ICMP packets dispatched (Rule: >25 ICMPs in 5s).")


if __name__ == "__main__":
    local_ip = get_local_ip()
    print("==================================================================")
    print("    ADVANCE NIDS SYSTEM - CONTROLLED LAB ATTACK GENERATOR         ")
    print("==================================================================")
    print(f"[*] Loopback Target (Recommended): {DEFAULT_TARGET}")
    print(f"[*] Local Host Interface Target:   {local_ip}")
    print("------------------------------------------------------------------")
    target = input(f"Enter Target IP [Press Enter for {DEFAULT_TARGET}]: ").strip()
    if not target:
        target = DEFAULT_TARGET

    print(f"\n[*] Commencing automated intrusion sequence against {target}...")
    simulate_port_scan(target)
    time.sleep(2.0)
    simulate_syn_flood(target)
    time.sleep(2.0)
    simulate_icmp_flood(target)
    print("\n[✓] All 3 attack batches successfully dispatched!")
    print("[✓] Check your live dashboard: http://127.0.0.1:5050")
    print("[✓] Offending Wireshark PCAPs are saved under the 'pcaps/' folder.\n")
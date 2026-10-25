"""
Lightweight and Computationally Efficient Network Intrusion Detection System (NIDS)
Backend Application: SOC Matrix Edition
Project: Review 1 NIDS Specifications
Authors: Yashveer Singh & Atharva Gupta
Guide: Dr. Priya M

Features:
- Dual Ingestion: Live sniffing (en0 + lo0) and Offline PCAP Upload/Analysis.
- Strict Review 1 Heuristics:
  1. Port Scanning: > 15 unique destination ports in 5.0s window.
  2. TCP SYN Flood: > 30 TCP SYN-only packets ('S') in 5.0s window.
  3. ICMP Ping Flood: > 25 ICMP packets in 5.0s window.
- Real-Time psutil CPU/RAM Telemetry & Microsecond Detection Latency.
- Automated Wireshark Libpcap Buffer Dumps (pcaps/*.pcap).
- WebSocket Real-Time Telemetry and Deep Packet Stream.
"""

import os
import sys
import time
import threading
from collections import deque, defaultdict
from datetime import datetime

from flask import Flask, render_template, send_from_directory, request, jsonify
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename
import psutil

# Scapy layer imports
from scapy.utils import wrpcap, rdpcap
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# ---------------------------------------------------------
# Project Specification Metadata
# ---------------------------------------------------------
PROJECT_METADATA = {
    "system_name": "Advance NIDS System",
    "subtitle": "Lightweight Heuristic Intrusion Detection Engine",
    "authors": "Yashveer Singh & Atharva Gupta",
    "guide": "Dr. Priya M",
    "specification": "Review 1 Approved Specification",
    "version": "2.5.0-SOC"
}

# ---------------------------------------------------------
# App Configuration
# ---------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids_soc_matrix_review1_secret_key'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64 MB maximum PCAP upload
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

PCAP_DIR = "pcaps"
UPLOAD_DIR = os.path.join(PCAP_DIR, "uploads")
os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------
# Detection & Buffering Parameters (Strict Review 1 Rules)
# ---------------------------------------------------------
WINDOW_DELTA = 5.0          # 5-second sliding window
ALERT_COOLDOWN = 4.0        # 4-second alert cooldown per (src_ip, attack_type)

PORT_SCAN_THRESHOLD = 15    # > 15 unique destination ports / 5s
SYN_FLOOD_THRESHOLD = 30    # > 30 TCP SYN-only packets ('S') / 5s
ICMP_FLOOD_THRESHOLD = 25   # > 25 ICMP packets / 5s

# Rolling in-memory packet buffer for live PCAP export (300 packets)
packet_buffer = deque(maxlen=300)
buffer_lock = threading.Lock()

# Sliding-window trackers per source IP
# Maps src_ip -> deque of (timestamp, dport)
port_scan_tracker = defaultdict(deque)
# Maps src_ip -> deque of timestamps
syn_flood_tracker = defaultdict(deque)
icmp_flood_tracker = defaultdict(deque)

# Cooldown tracking: (src_ip, attack_type) -> float last_alert_time
last_alert_time = {}
alert_lock = threading.Lock()

# Global statistics & metrics
stats = {
    'total_packets': 0,
    'suspicious_packets': 0,
    'threats_count': 0
}
stats_lock = threading.Lock()

attack_counts = {
    'port_scan': 0,
    'syn_flood': 0,
    'icmp_flood': 0
}
counts_lock = threading.Lock()

# Hostile Origin Vectors: src_ip -> dict metadata
hostile_origins = {}
origins_lock = threading.Lock()

# Confirmed Security Incidents Ring Buffer (for persistent dashboard log)
confirmed_incidents = deque(maxlen=100)
incidents_lock = threading.Lock()

# Live Packet Stream buffer (last 50 packets for SOC deep inspection table)
recent_packets = deque(maxlen=50)
recent_lock = threading.Lock()

# Traffic Timeline Buckets (rolling 5-second buckets for Chart.js)
traffic_timeline = deque(maxlen=24)
timeline_lock = threading.Lock()
current_bucket = {
    'start_time': time.time(),
    'total': 0,
    'suspicious': 0
}
bucket_lock = threading.Lock()

# Sniffer state control
sniffer_active = True
sniffer_lock = threading.Lock()


# ---------------------------------------------------------
# Helper Functions & Algorithmic Sliding Window
# ---------------------------------------------------------
def clean_sliding_window(d_queue, current_time, window_size=WINDOW_DELTA):
    """
    Purges entries older than (current_time - window_size) from a deque in O(1) amortized time.
    Handles both float timestamps and (timestamp, dport) tuples.
    """
    cutoff = current_time - window_size
    while d_queue:
        item = d_queue[0]
        timestamp = item[0] if isinstance(item, tuple) else item
        if timestamp < cutoff:
            d_queue.popleft()
        else:
            break


def is_on_cooldown(src_ip, attack_type, current_time):
    """
    Checks and updates the 4-second alert cooldown per (src_ip, attack_type).
    Returns True if still on cooldown; False if an alert can be triggered.
    """
    with alert_lock:
        last_time = last_alert_time.get((src_ip, attack_type), 0.0)
        if current_time - last_time < ALERT_COOLDOWN:
            return True
        last_alert_time[(src_ip, attack_type)] = current_time
        return False


def dump_pcap(attack_type, src_ip, custom_buffer=None):
    """
    Exports a snapshot of the offending 300-packet buffer to a .pcap file
    named: pcaps/<attack_type>_<src_ip>_<timestamp>.pcap
    """
    clean_attack = attack_type.lower().replace(" ", "_")
    clean_ip = src_ip.replace(":", "_").replace("/", "_")
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{clean_attack}_{clean_ip}_{timestamp_str}.pcap"
    filepath = os.path.join(PCAP_DIR, filename)

    if custom_buffer is not None:
        packets_snapshot = list(custom_buffer)
    else:
        with buffer_lock:
            packets_snapshot = list(packet_buffer)

    if packets_snapshot:
        try:
            # Ensure uniform linktype (e.g. Ethernet vs Loopback) to prevent libpcap format errors
            last_class = packets_snapshot[-1].__class__
            consistent_pkts = [p for p in packets_snapshot if p.__class__ == last_class]
            wrpcap(filepath, consistent_pkts)
        except Exception as e:
            print(f"[!] Error exporting PCAP to {filepath}: {e}")
            return "export_failed.pcap"
    return filename


def record_hostile_origin(src_ip, attack_type, dst_ip):
    """
    Records and updates the ranked hostile origin entry for the SIEM origin vectors panel.
    """
    with origins_lock:
        if src_ip not in hostile_origins:
            hostile_origins[src_ip] = {
                'ip': src_ip,
                'target': dst_ip,
                'incidents': 0,
                'attacks': set(),
                'severity': 'Medium',
                'last_seen': datetime.now().strftime("%H:%M:%S")
            }
        origin = hostile_origins[src_ip]
        origin['incidents'] += 1
        origin['attacks'].add(attack_type)
        origin['target'] = dst_ip
        origin['last_seen'] = datetime.now().strftime("%H:%M:%S")
        # Elevate to High if flood attack or more than 2 incidents
        if "Flood" in attack_type or origin['incidents'] >= 2:
            origin['severity'] = 'High'


def get_current_posture():
    """
    Computes DEFCON threat posture level:
    - DEFCON 2 (High Alert): Active Volumetric SYN/ICMP Floods
    - DEFCON 3 (Elevated): Port Scanning Probe detected
    - DEFCON 5 (Normal): Clean Traffic Profile
    """
    with counts_lock:
        syns = attack_counts['syn_flood']
        icmps = attack_counts['icmp_flood']
        scans = attack_counts['port_scan']

    if syns > 0 or icmps > 0:
        return {
            'level': 'DEFCON 2',
            'status': 'HIGH ALERT',
            'badge': 'bg-rose-500/20 text-rose-400 border border-rose-500/40',
            'description': 'Active Volumetric Flood Detected (Immediate Defense)'
        }
    elif scans > 0:
        return {
            'level': 'DEFCON 3',
            'status': 'ELEVATED',
            'badge': 'bg-amber-500/20 text-amber-400 border border-amber-500/40',
            'description': 'Reconnaissance Probe Detected (Port Scanning Active)'
        }
    else:
        return {
            'level': 'DEFCON 5',
            'status': 'NORMAL',
            'badge': 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40',
            'description': 'All Enclaves Monitored &bull; No Active Anomalies'
        }


def trigger_alert(src_ip, dst_ip, attack_type, attack_key, reason, t_start, custom_buffer=None, pcap_timestamp=None):
    """
    Triggers an intrusion alert: enforces cooldown, dumps forensic PCAP,
    calculates microsecond latency, updates SIEM metrics, and broadcasts alert via Socket.IO.
    """
    now = time.time()
    if is_on_cooldown(src_ip, attack_type, now):
        return None

    # Export Wireshark PCAP
    pcap_filename = dump_pcap(attack_type, src_ip, custom_buffer=custom_buffer)

    latency_ms = round((time.perf_counter() - t_start) * 1000, 3)
    timestamp_str = datetime.now().strftime("%H:%M:%S") if not pcap_timestamp else pcap_timestamp

    with stats_lock:
        stats['threats_count'] += 1

    with counts_lock:
        if attack_key in attack_counts:
            attack_counts[attack_key] += 1
        current_counts = dict(attack_counts)

    # Record hostile IP
    record_hostile_origin(src_ip, attack_type, dst_ip)

    threshold_val = (
        PORT_SCAN_THRESHOLD if attack_key == "port_scan"
        else (SYN_FLOOD_THRESHOLD if attack_key == "syn_flood" else ICMP_FLOOD_THRESHOLD)
    )

    alert_payload = {
        "timestamp": timestamp_str,
        "type": attack_type,
        "attack_key": attack_key,
        "src": src_ip,
        "dst": dst_ip,
        "reason": reason,
        "latency": f"{latency_ms:.3f} ms",
        "pcap": pcap_filename,
        "counts": current_counts,
        "details": {
            "window": f"{WINDOW_DELTA}s",
            "threshold": threshold_val
        }
    }

    with incidents_lock:
        confirmed_incidents.append(alert_payload)

    print(f"\033[91m[!] SOC ALERT: {attack_type} | {src_ip} -> {dst_ip} | {reason} | Latency: {latency_ms} ms | PCAP: {pcap_filename}\033[0m")
    socketio.emit('new_alert', alert_payload)
    return alert_payload


# ---------------------------------------------------------
# Packet Processing Callback (Live & Offline)
# ---------------------------------------------------------
def process_packet(packet, is_offline=False, pkt_time=None):
    """
    Core inspection engine for Scapy packets.
    Executes sliding-window rules, records telemetry buckets, and extracts socket metadata.
    """
    t_start = time.perf_counter()
    now = pkt_time if (is_offline and pkt_time is not None) else time.time()

    with sniffer_lock:
        if not is_offline and not sniffer_active:
            return

    # Update overall packet count
    with stats_lock:
        stats['total_packets'] += 1

    with bucket_lock:
        current_bucket['total'] += 1

    # Buffer packet for PCAP export
    with buffer_lock:
        packet_buffer.append(packet)

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    is_threat_pkt = False

    dport = None
    sport = None
    proto_str = "IP"
    flags_str = "-"

    if packet.haslayer(TCP):
        proto_str = "TCP"
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        flags = packet[TCP].flags
        flags_str = str(flags).strip() or f"0x{int(flags):02x}"
    elif packet.haslayer(UDP):
        proto_str = "UDP"
        dport = packet[UDP].dport
        sport = packet[UDP].sport
    elif packet.haslayer(ICMP):
        proto_str = "ICMP"
        sport = packet[ICMP].type
        dport = packet[ICMP].code

    # -----------------------------------------------------
    # 1. Rule: Port Scanning Detection (> 15 unique ports / 5s)
    # -----------------------------------------------------
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        transport_dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        queue = port_scan_tracker[src_ip]
        queue.append((now, transport_dport))
        clean_sliding_window(queue, now)
        unique_ports = len(set(port for _, port in queue))
        if unique_ports > PORT_SCAN_THRESHOLD:
            is_threat_pkt = True
            reason = f"Contacted {unique_ports} unique ports within {WINDOW_DELTA}s (threshold > {PORT_SCAN_THRESHOLD})"
            trigger_alert(src_ip, dst_ip, "Port Scan", "port_scan", reason, t_start)

    # -----------------------------------------------------
    # 2. Rule: TCP SYN Flood Detection (> 30 SYN pkts / 5s)
    # -----------------------------------------------------
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == 0x02 or str(flags).strip() == 'S':
            syn_queue = syn_flood_tracker[src_ip]
            syn_queue.append(now)
            clean_sliding_window(syn_queue, now)
            syn_count = len(syn_queue)
            if syn_count > SYN_FLOOD_THRESHOLD:
                is_threat_pkt = True
                reason = f"Sent {syn_count} TCP SYN packets within {WINDOW_DELTA}s (threshold > {SYN_FLOOD_THRESHOLD})"
                trigger_alert(src_ip, dst_ip, "TCP SYN Flood", "syn_flood", reason, t_start)

    # -----------------------------------------------------
    # 3. Rule: ICMP Flood Detection (> 25 ICMP pkts / 5s)
    # -----------------------------------------------------
    if packet.haslayer(ICMP):
        icmp_queue = icmp_flood_tracker[src_ip]
        icmp_queue.append(now)
        clean_sliding_window(icmp_queue, now)
        icmp_count = len(icmp_queue)
        if icmp_count > ICMP_FLOOD_THRESHOLD:
            is_threat_pkt = True
            reason = f"Sent {icmp_count} ICMP packets within {WINDOW_DELTA}s (threshold > {ICMP_FLOOD_THRESHOLD})"
            trigger_alert(src_ip, dst_ip, "ICMP Flood", "icmp_flood", reason, t_start)

    if is_threat_pkt:
        with stats_lock:
            stats['suspicious_packets'] += 1
        with bucket_lock:
            current_bucket['suspicious'] += 1

    # Record recent packet sample for live SOC deep inspection stream
    pkt_sample = {
        'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:12],
        'proto': proto_str,
        'src': f"{src_ip}:{sport}" if sport is not None else src_ip,
        'dst': f"{dst_ip}:{dport}" if dport is not None else dst_ip,
        'length': len(packet),
        'flags': flags_str,
        'is_threat': is_threat_pkt
    }

    with recent_lock:
        recent_packets.append(pkt_sample)

    # Emit packet sample live over WebSockets (throttled during live stream)
    if not is_offline:
        socketio.emit('packet_sample', pkt_sample)


# ---------------------------------------------------------
# Offline PCAP Analysis Engine
# ---------------------------------------------------------
def analyze_pcap_file(filepath):
    """
    Parses an uploaded .pcap or .pcapng file via Scapy's rdpcap and applies
    the exact same 3 Review 1 sliding-window rules.
    """
    print(f"[*] Starting offline PCAP analysis on {filepath}...")
    packets = rdpcap(filepath)
    total_pkts = len(packets)
    alerts_generated = []

    # Localized sliding window state for this specific PCAP run
    pcap_port_tracker = defaultdict(deque)
    pcap_syn_tracker = defaultdict(deque)
    pcap_icmp_tracker = defaultdict(deque)
    pcap_last_alert = {}
    pcap_stats = {'total': total_pkts, 'suspicious': 0, 'threats': 0}
    pcap_counts = {'port_scan': 0, 'syn_flood': 0, 'icmp_flood': 0}

    for pkt in packets:
        t_start = time.perf_counter()
        pkt_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()

        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        is_threat = False

        # Port Scan check
        dport = None
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport

        if dport is not None:
            queue = pcap_port_tracker[src_ip]
            queue.append((pkt_time, dport))
            clean_sliding_window(queue, pkt_time)
            unique_ports = len(set(port for _, port in queue))
            if unique_ports > PORT_SCAN_THRESHOLD:
                if pkt_time - pcap_last_alert.get((src_ip, 'Port Scan'), 0.0) >= ALERT_COOLDOWN:
                    pcap_last_alert[(src_ip, 'Port Scan')] = pkt_time
                    is_threat = True
                    pcap_counts['port_scan'] += 1
                    pcap_stats['threats'] += 1
                    latency_ms = round((time.perf_counter() - t_start) * 1000, 3)
                    time_str = datetime.fromtimestamp(pkt_time).strftime("%H:%M:%S")
                    reason = f"Contacted {unique_ports} unique ports within {WINDOW_DELTA}s"
                    alert_item = {
                        'timestamp': time_str,
                        'type': "Port Scan",
                        'src': src_ip,
                        'dst': dst_ip,
                        'reason': reason,
                        'latency': f"{latency_ms:.3f} ms",
                        'pcap': os.path.basename(filepath)
                    }
                    alerts_generated.append(alert_item)
                    socketio.emit('new_alert', {**alert_item, 'counts': pcap_counts})

        # TCP SYN Flood check
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags == 0x02 or str(flags).strip() == 'S':
                syn_queue = pcap_syn_tracker[src_ip]
                syn_queue.append(pkt_time)
                clean_sliding_window(syn_queue, pkt_time)
                syn_count = len(syn_queue)
                if syn_count > SYN_FLOOD_THRESHOLD:
                    if pkt_time - pcap_last_alert.get((src_ip, 'TCP SYN Flood'), 0.0) >= ALERT_COOLDOWN:
                        pcap_last_alert[(src_ip, 'TCP SYN Flood')] = pkt_time
                        is_threat = True
                        pcap_counts['syn_flood'] += 1
                        pcap_stats['threats'] += 1
                        latency_ms = round((time.perf_counter() - t_start) * 1000, 3)
                        time_str = datetime.fromtimestamp(pkt_time).strftime("%H:%M:%S")
                        reason = f"Sent {syn_count} TCP SYN packets within {WINDOW_DELTA}s"
                        alert_item = {
                            'timestamp': time_str,
                            'type': "TCP SYN Flood",
                            'src': src_ip,
                            'dst': dst_ip,
                            'reason': reason,
                            'latency': f"{latency_ms:.3f} ms",
                            'pcap': os.path.basename(filepath)
                        }
                        alerts_generated.append(alert_item)
                        socketio.emit('new_alert', {**alert_item, 'counts': pcap_counts})

        # ICMP Flood check
        if pkt.haslayer(ICMP):
            icmp_queue = pcap_icmp_tracker[src_ip]
            icmp_queue.append(pkt_time)
            clean_sliding_window(icmp_queue, pkt_time)
            icmp_count = len(icmp_queue)
            if icmp_count > ICMP_FLOOD_THRESHOLD:
                if pkt_time - pcap_last_alert.get((src_ip, 'ICMP Flood'), 0.0) >= ALERT_COOLDOWN:
                    pcap_last_alert[(src_ip, 'ICMP Flood')] = pkt_time
                    is_threat = True
                    pcap_counts['icmp_flood'] += 1
                    pcap_stats['threats'] += 1
                    latency_ms = round((time.perf_counter() - t_start) * 1000, 3)
                    time_str = datetime.fromtimestamp(pkt_time).strftime("%H:%M:%S")
                    reason = f"Sent {icmp_count} ICMP packets within {WINDOW_DELTA}s"
                    alert_item = {
                        'timestamp': time_str,
                        'type': "ICMP Flood",
                        'src': src_ip,
                        'dst': dst_ip,
                        'reason': reason,
                        'latency': f"{latency_ms:.3f} ms",
                        'pcap': os.path.basename(filepath)
                    }
                    alerts_generated.append(alert_item)
                    socketio.emit('new_alert', {**alert_item, 'counts': pcap_counts})

        if is_threat:
            pcap_stats['suspicious'] += 1

    # Merge pcap stats into global stats
    with stats_lock:
        stats['total_packets'] += pcap_stats['total']
        stats['suspicious_packets'] += pcap_stats['suspicious']
        stats['threats_count'] += pcap_stats['threats']

    with counts_lock:
        for k in attack_counts:
            attack_counts[k] += pcap_counts[k]

    with incidents_lock:
        for alert_item in alerts_generated:
            confirmed_incidents.append(alert_item)

    return {
        'total_packets': total_pkts,
        'suspicious_packets': pcap_stats['suspicious'],
        'threats_count': pcap_stats['threats'],
        'counts': pcap_counts,
        'alerts': alerts_generated
    }


# ---------------------------------------------------------
# Background Worker Threads
# ---------------------------------------------------------
def start_sniffing_workers():
    """
    Spawns dedicated sniffer workers for macOS / BSD / Linux:
    - Dedicated loopback worker ('lo0' on macOS, 'lo' on Linux)
    - Dedicated primary external worker ('en0', 'eth0', or default)
    Separate BPF sockets prevent BSD link-layer DLT_NULL / DLT_EN10MB drop conflicts.
    """
    from scapy.all import get_if_list
    try:
        available_ifaces = set(get_if_list())
    except Exception:
        available_ifaces = set()

    def _worker(iface_name):
        desc = iface_name if iface_name else "default interface"
        print(f"[*] Live Sniffer Worker active on {desc} (filter='ip', store=False)...")
        try:
            if iface_name:
                sniff(iface=iface_name, filter="ip", store=False, prn=process_packet)
            else:
                sniff(filter="ip", store=False, prn=process_packet)
        except PermissionError:
            print(f"\n[!] CRITICAL ERROR: Live packet sniffing on {desc} requires root privileges (sudo).\n")
        except Exception as e:
            print(f"[*] Sniffer worker on {desc} encountered: {e}. Retrying with default interface...")
            try:
                sniff(filter="ip", store=False, prn=process_packet)
            except Exception as err:
                print(f"[!] Sniffer fallback stopped: {err}")

    # Determine loopback interface
    lo_iface = 'lo0' if 'lo0' in available_ifaces else ('lo' if 'lo' in available_ifaces else None)
    if lo_iface:
        t_lo = threading.Thread(target=_worker, args=(lo_iface,), daemon=True)
        t_lo.start()

    # Determine primary external interface
    ext_iface = 'en0' if 'en0' in available_ifaces else ('eth0' if 'eth0' in available_ifaces else None)
    t_ext = threading.Thread(target=_worker, args=(ext_iface,), daemon=True)
    t_ext.start()


def telemetry_thread():
    """
    Background worker sampling CPU (%) and RSS Memory (MB) every 1.0 second.
    Rolls 5-second traffic buckets and emits telemetry_update to WebSocket clients.
    """
    process = psutil.Process(os.getpid())
    process.cpu_percent(interval=None)

    while True:
        time.sleep(1.0)
        try:
            cpu_usage = round(process.cpu_percent(interval=None), 1)
            mem_rss_mb = round(process.memory_info().rss / (1024 * 1024), 2)

            now_t = time.time()
            with bucket_lock:
                if now_t - current_bucket['start_time'] >= 5.0:
                    time_label = datetime.now().strftime("%H:%M:%S")
                    with timeline_lock:
                        traffic_timeline.append({
                            'time': time_label,
                            'total': current_bucket['total'],
                            'suspicious': current_bucket['suspicious']
                        })
                    current_bucket['start_time'] = now_t
                    current_bucket['total'] = 0
                    current_bucket['suspicious'] = 0

            with stats_lock:
                total_pkts = stats['total_packets']
                suspicious_pkts = stats['suspicious_packets']
                threats = stats['threats_count']

            with counts_lock:
                current_counts = dict(attack_counts)

            with buffer_lock:
                buf_size = len(packet_buffer)

            with origins_lock:
                # Top 5 ranked hostile origin vectors
                raw_origins = list(hostile_origins.values())
                raw_origins.sort(key=lambda x: x['incidents'], reverse=True)
                top_origins = []
                for idx, o in enumerate(raw_origins[:5], start=1):
                    top_origins.append({
                        'rank': idx,
                        'ip': o['ip'],
                        'target': o['target'],
                        'incidents': o['incidents'],
                        'attacks': list(o['attacks']),
                        'severity': o['severity'],
                        'last_seen': o['last_seen']
                    })

            with timeline_lock:
                timeline_data = list(traffic_timeline)

            with sniffer_lock:
                is_active = sniffer_active

            contagion_pct = round((suspicious_pkts / max(total_pkts, 1)) * 100, 2)
            rules_correlated = sum(1 for c in current_counts.values() if c > 0)
            posture = get_current_posture()

            telemetry_payload = {
                'cpu_percent': f"{cpu_usage}%",
                'cpu_val': cpu_usage,
                'ram_mb': f"{mem_rss_mb} MB",
                'ram_val': mem_rss_mb,
                'total_packets': total_pkts,
                'suspicious_packets': suspicious_pkts,
                'threats_count': threats,
                'contagion_pct': contagion_pct,
                'rules_correlated': rules_correlated,
                'posture': posture,
                'counts': current_counts,
                'buffer_size': buf_size,
                'top_origins': top_origins,
                'timeline': timeline_data,
                'sniffer_active': is_active,
                'active_window_seconds': WINDOW_DELTA
            }

            socketio.emit('telemetry_update', telemetry_payload)
        except Exception as e:
            print(f"[!] Telemetry sampling error: {e}")


# ---------------------------------------------------------
# Flask Routes & REST Endpoints
# ---------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html', meta=PROJECT_METADATA)


@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    """
    Offline PCAP Ingestion Endpoint: accepts uploaded .pcap or .pcapng,
    runs offline heuristic analysis, and returns JSON report.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved_name = f"upload_{timestamp_str}_{filename}"
    filepath = os.path.join(UPLOAD_DIR, saved_name)
    file.save(filepath)

    try:
        analysis_result = analyze_pcap_file(filepath)
        return jsonify({
            'success': True,
            'filename': saved_name,
            'original_name': filename,
            **analysis_result
        })
    except Exception as e:
        return jsonify({'error': f"Failed to analyze PCAP: {str(e)}"}), 500


@app.route('/api/pcaps')
def list_pcaps():
    """
    Returns list of all available forensic PCAPs in the pcaps/ directory.
    """
    files_list = []
    try:
        for f in os.listdir(PCAP_DIR):
            fp = os.path.join(PCAP_DIR, f)
            if os.path.isfile(fp) and f.endswith(('.pcap', '.pcapng')):
                stat = os.stat(fp)
                # Infer attack type from name
                attack_tag = "Anomaly"
                if "port_scan" in f:
                    attack_tag = "Port Scan"
                elif "syn_flood" in f:
                    attack_tag = "TCP SYN Flood"
                elif "icmp_flood" in f:
                    attack_tag = "ICMP Flood"

                files_list.append({
                    'filename': f,
                    'size_kb': round(stat.st_size / 1024, 2),
                    'created': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    'tag': attack_tag
                })
        files_list.sort(key=lambda x: x['created'], reverse=True)
    except Exception as e:
        print(f"[!] Error listing pcaps: {e}")
    return jsonify({'pcaps': files_list})


@app.route('/download/<path:filename>')
def download_pcap(filename):
    """
    Allows downloading forensic PCAPs directly from pcaps/ or pcaps/uploads/.
    """
    # Check if file is in uploads subdirectory
    if filename.startswith("uploads/"):
        subfile = filename.replace("uploads/", "")
        return send_from_directory(UPLOAD_DIR, subfile, as_attachment=True)
    return send_from_directory(PCAP_DIR, filename, as_attachment=True)


@app.route('/api/sniffer/toggle', methods=['POST', 'GET'])
def toggle_sniffer():
    """
    Toggles the active state of live packet sniffing.
    """
    global sniffer_active
    with sniffer_lock:
        sniffer_active = not sniffer_active
        status = sniffer_active
    socketio.emit('sniffer_status', {'active': status})
    return jsonify({'active': status})


@app.route('/api/reset_stats', methods=['POST'])
def reset_stats():
    """
    Resets accumulated counters and hostile origins for a clean test run.
    """
    with stats_lock:
        stats['total_packets'] = 0
        stats['suspicious_packets'] = 0
        stats['threats_count'] = 0

    with counts_lock:
        for k in attack_counts:
            attack_counts[k] = 0

    with origins_lock:
        hostile_origins.clear()

    with buffer_lock:
        packet_buffer.clear()

    with recent_lock:
        recent_packets.clear()

    with incidents_lock:
        confirmed_incidents.clear()

    socketio.emit('stats_reset', {'success': True})
    return jsonify({'success': True})


@app.route('/api/incidents')
def get_incidents():
    """
    Returns recent confirmed security incidents for SIEM console rendering.
    """
    with incidents_lock:
        incidents_list = list(confirmed_incidents)
    return jsonify({'incidents': incidents_list})


# ---------------------------------------------------------
# SocketIO Handlers
# ---------------------------------------------------------
@socketio.on('connect')
def handle_connect():
    print("[*] Advance NIDS System client connected.")
    process = psutil.Process(os.getpid())
    with stats_lock:
        tot = stats['total_packets']
        susp = stats['suspicious_packets']
        threats = stats['threats_count']
    with counts_lock:
        c = dict(attack_counts)
    with sniffer_lock:
        act = sniffer_active

    with origins_lock:
        raw_origins = list(hostile_origins.values())
        raw_origins.sort(key=lambda x: x['incidents'], reverse=True)
        top_origins = []
        for idx, o in enumerate(raw_origins[:5], start=1):
            top_origins.append({
                'rank': idx,
                'ip': o['ip'],
                'target': o['target'],
                'incidents': o['incidents'],
                'attacks': list(o['attacks']),
                'severity': o['severity'],
                'last_seen': o['last_seen']
            })

    with incidents_lock:
        incidents_list = list(confirmed_incidents)

    socketio.emit('telemetry_update', {
        'cpu_percent': f"{round(process.cpu_percent(interval=None), 1)}%",
        'cpu_val': round(process.cpu_percent(interval=None), 1),
        'ram_mb': f"{round(process.memory_info().rss / (1024 * 1024), 2)} MB",
        'ram_val': round(process.memory_info().rss / (1024 * 1024), 2),
        'total_packets': tot,
        'suspicious_packets': susp,
        'threats_count': threats,
        'contagion_pct': round((susp / max(tot, 1)) * 100, 2),
        'rules_correlated': sum(1 for val in c.values() if val > 0),
        'posture': get_current_posture(),
        'counts': c,
        'buffer_size': len(packet_buffer),
        'top_origins': top_origins,
        'timeline': list(traffic_timeline),
        'sniffer_active': act,
        'active_window_seconds': WINDOW_DELTA
    })
    socketio.emit('initial_incidents', {'incidents': incidents_list})


@socketio.on('toggle_sniffer')
def handle_toggle_sniffer():
    global sniffer_active
    with sniffer_lock:
        sniffer_active = not sniffer_active
        status = sniffer_active
    socketio.emit('sniffer_status', {'active': status})


# ---------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------
if __name__ == '__main__':
    # Launch packet sniffer workers (dedicated loopback and external threads)
    start_sniffing_workers()

    # Launch telemetry daemon thread
    telemetry_t = threading.Thread(target=telemetry_thread, daemon=True)
    telemetry_t.start()

    print("==================================================================")
    print("      ADVANCE NIDS SYSTEM - REAL-TIME HEURISTIC ENGINE            ")
    print(f"      Authors: {PROJECT_METADATA['authors']} | Guide: {PROJECT_METADATA['guide']}")
    print(f"      Rules: Port Scan (>15), TCP SYN (>30), ICMP Flood (>25)")
    print("==================================================================")
    print("[*] Advance NIDS System running at http://127.0.0.1:5050")
    print("[*] Sliding window: 5.0s | Cooldown: 4.0s | Forensic Ring Buffer: 300 pkts")
    socketio.run(app, host='0.0.0.0', port=5050, debug=False, allow_unsafe_werkzeug=True)
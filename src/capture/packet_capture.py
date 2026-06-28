"""
Live packet capture using Scapy. Feeds real network traffic into the
FlowTracker, runs predictions on finished flows, and logs results.

Run this with: python -m src.capture.packet_capture
Requires: Administrator/root privileges + Npcap (Windows) installed.
"""

from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP
from src.preprocessing.flow_tracker import FlowTracker
from src.detection.realtime_detector import predict_flow
from src.alerts.alert_manager import log_result
import threading

tracker = FlowTracker()


def get_tcp_flags(pkt) -> str:
    """Convert Scapy's numeric TCP flags into the letter-based format flow_tracker expects."""
    if not pkt.haslayer(TCP):
        return ""
    flags = pkt[TCP].flags
    flag_str = ""
    if flags & 0x02: flag_str += "S"   # SYN
    if flags & 0x10: flag_str += "A"   # ACK
    if flags & 0x01: flag_str += "F"   # FIN
    if flags & 0x04: flag_str += "R"   # RST
    return flag_str


def handle_packet(pkt):
    """Called by Scapy for every captured packet, on any interface."""
    if not pkt.haslayer(IP):
        return  # skip non-IP traffic (ARP, etc.)

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    timestamp = float(pkt.time)
    payload_len = len(pkt[IP].payload)

    if pkt.haslayer(TCP):
        protocol = "tcp"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = get_tcp_flags(pkt)
    elif pkt.haslayer(UDP):
        protocol = "udp"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        flags = ""
    elif pkt.haslayer(ICMP):
        protocol = "icmp"
        src_port = 0
        dst_port = 0
        flags = ""
    else:
        return  # skip other protocols for now

    tracker.process_packet(src_ip, dst_ip, src_port, dst_port, protocol,
                            payload_len, flags, timestamp)

    for flow in tracker.get_finished_flows():
        result = predict_flow(flow)
        log_result(result)
        marker = "🚨" if result["prediction"] == "attack" else "  "
        print(f"{marker} {result['protocol']:5s} {result['src_ip']:15s} -> "
              f"{result['dst_ip']:15s} [{result['service']:10s}] "
              f"{result['prediction']:7s} ({result['confidence']:.0%})")


def sniff_interface(iface):
    """Runs a sniffer on one interface. Used as a thread target."""
    try:
        sniff(iface=iface, prn=handle_packet, store=False)
    except Exception as e:
        print(f"⚠️  Could not sniff on {iface}: {e}")


def start_capture():
    """
    Starts live sniffing on ALL available interfaces simultaneously
    (so loopback traffic like 127.0.0.1 scans are caught too, not just
    your main WiFi/Ethernet adapter).
    """
    interfaces = get_if_list()
    print(f"🛡️  IDS started — capturing on {len(interfaces)} interfaces. Press Ctrl+C to stop.\n")

    threads = []
    for iface in interfaces:
        t = threading.Thread(target=sniff_interface, args=(iface,), daemon=True)
        t.start()
        threads.append(t)

    try:
        # Keep main thread alive so daemon sniffer threads keep running
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n🛑 Stopping IDS...")


if __name__ == "__main__":
    start_capture()
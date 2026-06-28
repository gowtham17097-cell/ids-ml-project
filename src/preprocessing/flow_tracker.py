"""
Core flow-tracking engine for the IDS.
Groups packets into flows (connections) and computes NSL-KDD-style features:
- Basic features: computed directly from the flow
- Traffic features: computed from a rolling window of recent connections
- Content features: defaulted to 0 (documented limitation — see README)
  Exception: logged_in is approximated from TCP flag (SF = established = 1)
"""

import time
from collections import deque
from src.preprocessing.service_lookup import get_service

FLOW_TIMEOUT = 5    # seconds of inactivity before a flow is considered finished
TIME_WINDOW = 2     # seconds, for 'count'/'srv_count' style features
HOST_WINDOW = 100   # number of past connections, for 'dst_host_*' features


class Flow:
    """Represents a single network connection being tracked."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, timestamp):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol  # "tcp", "udp", "icmp"

        self.start_time = timestamp
        self.last_seen = timestamp

        self.src_bytes = 0
        self.dst_bytes = 0

        self.syn_seen = False
        self.ack_seen = False
        self.fin_seen = False
        self.rst_seen = False

        self.service = get_service(dst_port, protocol)

    def add_packet(self, payload_len, direction, flags, timestamp):
        """direction: 'out' (src->dst) or 'in' (dst->src)"""
        self.last_seen = timestamp

        if direction == "out":
            self.src_bytes += payload_len
        else:
            self.dst_bytes += payload_len

        if "S" in flags and "A" not in flags:
            self.syn_seen = True
        if "A" in flags:
            self.ack_seen = True
        if "F" in flags:
            self.fin_seen = True
        if "R" in flags:
            self.rst_seen = True

    def get_duration(self):
        return round(self.last_seen - self.start_time, 4)

    def get_flag(self):
        """Approximates NSL-KDD's connection status flags."""
        if self.rst_seen:
            return "RSTO" if self.ack_seen else "RSTR"
        if self.syn_seen and not self.ack_seen:
            return "S0"
        if self.fin_seen and self.ack_seen:
            return "SF"
        if self.syn_seen and self.ack_seen:
            return "S1"
        return "SF"  # default: completed normally

    def is_expired(self, now):
        return (now - self.last_seen) > FLOW_TIMEOUT


class FlowTracker:
    """Manages all active flows and computes rolling-window traffic features."""

    def __init__(self):
        self.active_flows = {}
        # recent_connections stores: (dst_ip, service, flag, timestamp)
        self.recent_connections = deque()
        # host_history stores: (dst_ip, service, flag, src_port)  ← src_port added
        self.host_history = deque(maxlen=HOST_WINDOW)
        self.finished_flows = deque()

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def process_packet(self, src_ip, dst_ip, src_port, dst_port, protocol,
                        payload_len, flags, timestamp):
        """Call this once per captured packet."""
        fwd_key = self._flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        rev_key = self._flow_key(dst_ip, src_ip, dst_port, src_port, protocol)

        if fwd_key in self.active_flows:
            flow = self.active_flows[fwd_key]
            flow.add_packet(payload_len, "out", flags, timestamp)
            active_key = fwd_key
        elif rev_key in self.active_flows:
            flow = self.active_flows[rev_key]
            flow.add_packet(payload_len, "in", flags, timestamp)
            active_key = rev_key
        else:
            flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
            flow.add_packet(payload_len, "out", flags, timestamp)
            self.active_flows[fwd_key] = flow
            active_key = fwd_key

        # If this packet finished the connection, finalize immediately
        if flow.fin_seen or flow.rst_seen:
            self.finished_flows.append(self._finalize_flow(flow, timestamp))
            del self.active_flows[active_key]

        # Sweep for any flows that timed out from inactivity
        self._expire_timed_out_flows(timestamp)

    def _expire_timed_out_flows(self, now):
        """Move inactive flows into finished_flows."""
        for key, flow in list(self.active_flows.items()):
            if flow.is_expired(now):
                self.finished_flows.append(self._finalize_flow(flow, now))
                del self.active_flows[key]

    def get_finished_flows(self):
        """Pop and return all finished flows accumulated so far."""
        results = list(self.finished_flows)
        self.finished_flows.clear()
        return results

    def _finalize_flow(self, flow, now):
        """Compute the full 41-feature dict for a completed flow."""

        # --- Update rolling windows FIRST ---
        # recent_connections: (dst_ip, service, flag, timestamp)
        self.recent_connections.append(
            (flow.dst_ip, flow.service, flow.get_flag(), now)
        )
        # host_history: (dst_ip, service, flag, src_port)  ← src_port stored here
        self.host_history.append(
            (flow.dst_ip, flow.service, flow.get_flag(), flow.src_port)
        )

        # Drop entries older than TIME_WINDOW from recent_connections
        while self.recent_connections and (now - self.recent_connections[0][3]) > TIME_WINDOW:
            self.recent_connections.popleft()

        # --- TIME_WINDOW based features (last 2 seconds) ---
        same_host = [c for c in self.recent_connections if c[0] == flow.dst_ip]
        same_srv  = [c for c in self.recent_connections if c[1] == flow.service]

        count     = len(same_host)
        srv_count = len(same_srv)

        def error_rate(conns):
            if not conns:
                return 0.0
            errors = sum(1 for c in conns if c[2] in ("S0", "S1", "S2", "S3"))
            return round(errors / len(conns), 3)

        def rej_rate(conns):
            if not conns:
                return 0.0
            rejects = sum(1 for c in conns if c[2] == "REJ")
            return round(rejects / len(conns), 3)

        serror_rate     = error_rate(same_host)
        srv_serror_rate = error_rate(same_srv)
        rerror_rate     = rej_rate(same_host)
        srv_rerror_rate = rej_rate(same_srv)

        same_srv_rate = (
            round(len([c for c in same_host if c[1] == flow.service]) / count, 3)
            if count else 0.0
        )
        diff_srv_rate     = round(1 - same_srv_rate, 3) if count else 0.0
        srv_diff_host_rate = (
            round(len(set(c[0] for c in same_srv)) / srv_count, 3)
            if srv_count else 0.0
        )

        # --- dst_host_* features (last 100 connections to same dst_ip) ---
        host_conns = [c for c in self.host_history if c[0] == flow.dst_ip]
        dst_host_count     = len(host_conns)
        dst_host_srv_count = len([c for c in host_conns if c[1] == flow.service])

        dst_host_same_srv_rate = (
            round(dst_host_srv_count / dst_host_count, 3) if dst_host_count else 0.0
        )
        dst_host_diff_srv_rate = (
            round(1 - dst_host_same_srv_rate, 3) if dst_host_count else 0.0
        )
        dst_host_serror_rate = error_rate(host_conns)
        dst_host_rerror_rate = rej_rate(host_conns)

        # FIX 2a: dst_host_same_src_port_rate
        # "Of all connections to this dst_ip, what % used the same src_port as this flow?"
        # A port scanner reuses the same src ports → this rate spikes during scans
        same_src_port = len([c for c in host_conns if c[3] == flow.src_port])
        dst_host_same_src_port_rate = (
            round(same_src_port / dst_host_count, 3) if dst_host_count else 0.0
        )

        # FIX 2b: dst_host_srv_diff_host_rate
        # "Of connections using the same service, how many went to DIFFERENT dst hosts?"
        # Helps catch horizontal scans (same service, many targets)
        same_srv_all = [c for c in self.host_history if c[1] == flow.service]
        unique_hosts_for_srv = len(set(c[0] for c in same_srv_all))
        dst_host_srv_diff_host_rate = (
            round(unique_hosts_for_srv / len(same_srv_all), 3)
            if same_srv_all else 0.0
        )

        # --- logged_in approximation (FIX 1) ---
        # SF flag = clean SYN→SYN-ACK→FIN-ACK = successfully established session
        logged_in = 1 if flow.get_flag() == "SF" else 0

        return {
            # Basic (9)
            "duration":       flow.get_duration(),
            "protocol_type":  flow.protocol,
            "service":        flow.service,
            "flag":           flow.get_flag(),
            "src_bytes":      flow.src_bytes,
            "dst_bytes":      flow.dst_bytes,
            "land":           int(flow.src_ip == flow.dst_ip and
                                  flow.src_port == flow.dst_port),
            "wrong_fragment": 0,
            "urgent":         0,

            # Content (13) — defaulted except logged_in
            "hot":               0,
            "num_failed_logins": 0,
            "logged_in":         logged_in,   # ✅ FIX 1
            "num_compromised":   0,
            "root_shell":        0,
            "su_attempted":      0,
            "num_root":          0,
            "num_file_creations":0,
            "num_shells":        0,
            "num_access_files":  0,
            "num_outbound_cmds": 0,
            "is_host_login":     0,
            "is_guest_login":    0,

            # Traffic — 2-sec window (9)
            "count":            count,
            "srv_count":        srv_count,
            "serror_rate":      serror_rate,
            "srv_serror_rate":  srv_serror_rate,
            "rerror_rate":      rerror_rate,
            "srv_rerror_rate":  srv_rerror_rate,
            "same_srv_rate":    same_srv_rate,
            "diff_srv_rate":    diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,

            # dst_host_* — 100-connection window (10)
            "dst_host_count":              dst_host_count,
            "dst_host_srv_count":          dst_host_srv_count,
            "dst_host_same_srv_rate":      dst_host_same_srv_rate,
            "dst_host_diff_srv_rate":      dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate,  # ✅ FIX 2a
            "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,  # ✅ FIX 2b
            "dst_host_serror_rate":        dst_host_serror_rate,
            "dst_host_srv_serror_rate":    dst_host_serror_rate,
            "dst_host_rerror_rate":        dst_host_rerror_rate,
            "dst_host_srv_rerror_rate":    dst_host_rerror_rate,

            # Kept for alert logging — dropped before model prediction
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
        }
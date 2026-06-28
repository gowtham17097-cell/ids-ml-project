"""
Unit tests for the IDS core logic.
Tests FlowTracker, feature_mapper, service_lookup, and realtime_detector
using fake packet data — no live network capture needed.

Run with:
    python -m pytest tests/ -v
"""

import os
import sys
import time

import pytest

# Make sure project root is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.preprocessing.service_lookup import get_service
from src.preprocessing.flow_tracker import Flow, FlowTracker
from src.preprocessing.feature_mapper import flow_to_model_row


class TestServiceLookup:
    def test_http(self):
        assert get_service(80) == "http"

    def test_https(self):
        assert get_service(443) == "http_443"

    def test_ftp(self):
        assert get_service(21) == "ftp"

    def test_ftp_data(self):
        assert get_service(20) == "ftp_data"

    def test_telnet(self):
        assert get_service(23) == "telnet"

    def test_dns(self):
        assert get_service(53) == "domain"

    def test_ssh(self):
        assert get_service(22) == "ssh"

    def test_smtp(self):
        assert get_service(25) == "smtp"

    def test_unknown_high_port(self):
        assert get_service(54321) == "private"

    def test_unknown_low_port(self):
        assert get_service(7) == "other"

    def test_icmp_returns_eco_i(self):
        assert get_service(0, protocol="icmp") == "eco_i"

    def test_icmp_overrides_port(self):
        assert get_service(80, protocol="icmp") == "eco_i"

    def test_no_duplicate_port_443(self):
        result = get_service(443)
        assert result == "http_443"
        assert result != "http"


class TestFlow:
    def _make_flow(self, src="10.0.0.1", dst="10.0.0.2", sport=51000, dport=80, proto="tcp"):
        return Flow(src, dst, sport, dport, proto, time.time())

    def test_service_assigned_from_port(self):
        f = self._make_flow(dport=80)
        assert f.service == "http"

    def test_service_https(self):
        f = self._make_flow(dport=443)
        assert f.service == "http_443"

    def test_src_bytes_count(self):
        f = self._make_flow()
        f.add_packet(500, "out", "S", time.time())
        f.add_packet(200, "out", "FA", time.time())
        assert f.src_bytes == 700

    def test_dst_bytes_count(self):
        f = self._make_flow()
        f.add_packet(0, "in", "SA", time.time())
        f.add_packet(1200, "in", "FA", time.time())
        assert f.dst_bytes == 1200

    def test_flag_sf_clean_connection(self):
        f = self._make_flow()
        f.add_packet(100, "out", "S", time.time())
        f.add_packet(0, "in", "SA", time.time())
        f.add_packet(200, "out", "FA", time.time())
        assert f.get_flag() == "SF"

    def test_flag_s0_no_reply(self):
        f = self._make_flow()
        f.add_packet(100, "out", "S", time.time())
        assert f.get_flag() == "S0"

    def test_flag_rsto_reset_with_ack(self):
        f = self._make_flow()
        f.add_packet(100, "out", "S", time.time())
        f.add_packet(0, "in", "SA", time.time())
        f.add_packet(0, "in", "RA", time.time())
        assert f.get_flag() == "RSTO"

    def test_flag_rstr_reset_no_ack(self):
        f = self._make_flow()
        f.add_packet(100, "out", "S", time.time())
        f.add_packet(0, "in", "R", time.time())
        assert f.get_flag() == "RSTR"

    def test_duration_increases(self):
        now = time.time()
        f = self._make_flow()
        f.start_time = now
        f.last_seen = now + 0.5
        assert f.get_duration() == pytest.approx(0.5, abs=0.01)

    def test_land_same_ip_and_port(self):
        f = Flow("10.0.0.1", "10.0.0.1", 80, 80, "tcp", time.time())
        assert f.src_ip == f.dst_ip
        assert f.src_port == f.dst_port

    def test_is_expired(self):
        f = self._make_flow()
        f.last_seen = time.time() - 10
        assert f.is_expired(time.time()) is True

    def test_not_expired_fresh(self):
        f = self._make_flow()
        assert f.is_expired(time.time()) is False


class TestFlowTracker:
    def _simulate_http(self, tracker=None, offset=0):
        if tracker is None:
            tracker = FlowTracker()
        now = time.time() + offset
        tracker.process_packet("10.0.0.1", "93.184.216.34", 51000, 80, "tcp", 500, "S", now)
        tracker.process_packet("93.184.216.34", "10.0.0.1", 80, 51000, "tcp", 0, "SA", now + 0.01)
        tracker.process_packet("10.0.0.1", "93.184.216.34", 51000, 80, "tcp", 200, "FA", now + 0.02)
        return list(tracker.finished_flows)

    def test_single_flow_finalized(self):
        flows = self._simulate_http()
        assert len(flows) == 1

    def test_flow_has_expected_keys(self):
        flows = self._simulate_http()
        expected = {"duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "count", "serror_rate", "dst_host_count", "logged_in"}
        assert expected.issubset(flows[0].keys())

    def test_flow_service_http(self):
        flows = self._simulate_http()
        assert flows[0]["service"] == "http"

    def test_flow_flag_sf(self):
        flows = self._simulate_http()
        assert flows[0]["flag"] == "SF"

    def test_flow_src_bytes(self):
        flows = self._simulate_http()
        assert flows[0]["src_bytes"] == 700

    def test_flow_dst_bytes(self):
        flows = self._simulate_http()
        assert flows[0]["dst_bytes"] == 0

    def test_logged_in_sf_connection(self):
        flows = self._simulate_http()
        assert flows[0]["logged_in"] == 1

    def test_logged_in_s0_connection(self):
        tracker = FlowTracker()
        now = time.time()
        tracker.process_packet("10.0.0.1", "10.0.0.2", 51000, 9999, "tcp", 60, "S", now)
        tracker.process_packet("10.0.0.1", "10.0.0.2", 51000, 9999, "tcp", 0, "R", now + 0.1)
        flows = tracker.get_finished_flows()
        assert len(flows) == 1
        assert flows[0]["logged_in"] == 0

    def test_count_increases_with_same_host(self):
        tracker = FlowTracker()
        self._simulate_http(tracker, offset=0)
        flows2 = self._simulate_http(tracker, offset=0.1)
        assert flows2[0]["count"] >= 1

    def test_src_ip_in_output(self):
        flows = self._simulate_http()
        assert flows[0]["src_ip"] == "10.0.0.1"

    def test_dst_ip_in_output(self):
        flows = self._simulate_http()
        assert flows[0]["dst_ip"] == "93.184.216.34"

    def test_protocol_type_tcp(self):
        flows = self._simulate_http()
        assert flows[0]["protocol_type"] == "tcp"

    def test_udp_flow(self):
        tracker = FlowTracker()
        now = time.time()
        tracker.process_packet("10.0.0.1", "8.8.8.8", 54321, 53, "udp", 64, "", now)
        tracker._expire_timed_out_flows(now + 10)
        flows = tracker.get_finished_flows()
        assert len(flows) == 1
        assert flows[0]["protocol_type"] == "udp"
        assert flows[0]["service"] == "domain"

    def test_finished_flows_cleared_after_get(self):
        tracker = FlowTracker()
        self._simulate_http(tracker)
        flows1 = tracker.get_finished_flows()
        flows2 = tracker.get_finished_flows()
        assert len(flows1) == 1
        assert len(flows2) == 0

    def test_dst_host_same_src_port_rate_computed(self):
        flows = self._simulate_http()
        assert "dst_host_same_src_port_rate" in flows[0]
        assert 0.0 <= flows[0]["dst_host_same_src_port_rate"] <= 1.0

    def test_land_flag_detected(self):
        tracker = FlowTracker()
        now = time.time()
        tracker.process_packet("10.0.0.1", "10.0.0.1", 80, 80, "tcp", 100, "S", now)
        tracker.process_packet("10.0.0.1", "10.0.0.1", 80, 80, "tcp", 0, "R", now + 0.1)
        flows = tracker.get_finished_flows()
        assert flows[0]["land"] == 1

    def test_content_features_defaulted_to_zero(self):
        flows = self._simulate_http()
        for feat in [
            "hot",
            "num_failed_logins",
            "root_shell",
            "su_attempted",
            "num_root",
            "num_file_creations",
            "num_shells",
            "num_access_files",
            "num_outbound_cmds",
            "is_host_login",
            "is_guest_login",
        ]:
            assert flows[0][feat] == 0, f"{feat} should default to 0"


class TestFeatureMapper:
    def _get_flow(self):
        tracker = FlowTracker()
        now = time.time()
        tracker.process_packet("10.0.0.1", "93.184.216.34", 51000, 80, "tcp", 500, "S", now)
        tracker.process_packet("93.184.216.34", "10.0.0.1", 80, 51000, "tcp", 0, "SA", now + 0.01)
        tracker.process_packet("10.0.0.1", "93.184.216.34", 51000, 80, "tcp", 200, "FA", now + 0.02)
        return tracker.get_finished_flows()[0]

    def test_output_shape_122_columns(self):
        row = flow_to_model_row(self._get_flow())
        assert row.shape == (1, 122), f"Expected (1, 122) but got {row.shape}"

    def test_no_missing_values(self):
        row = flow_to_model_row(self._get_flow())
        assert row.isnull().sum().sum() == 0

    def test_src_ip_not_in_model_row(self):
        row = flow_to_model_row(self._get_flow())
        assert "src_ip" not in row.columns

    def test_dst_ip_not_in_model_row(self):
        row = flow_to_model_row(self._get_flow())
        assert "dst_ip" not in row.columns

    def test_binary_label_not_in_model_row(self):
        row = flow_to_model_row(self._get_flow())
        assert "binary_label" not in row.columns

    def test_src_bytes_preserved(self):
        row = flow_to_model_row(self._get_flow())
        assert row["src_bytes"].iloc[0] == 700

    def test_protocol_type_tcp_encoded(self):
        row = flow_to_model_row(self._get_flow())
        assert "protocol_type_tcp" in row.columns
        assert row["protocol_type_tcp"].iloc[0] == 1

    def test_service_http_encoded(self):
        row = flow_to_model_row(self._get_flow())
        assert "service_http" in row.columns
        assert row["service_http"].iloc[0] == 1

    def test_flag_sf_encoded(self):
        row = flow_to_model_row(self._get_flow())
        assert "flag_SF" in row.columns
        assert row["flag_SF"].iloc[0] == 1

    def test_all_values_numeric(self):
        import numpy as np

        row = flow_to_model_row(self._get_flow())
        for col in row.columns:
            assert np.issubdtype(row[col].dtype, np.number) or row[col].dtype == bool, f"Column {col} is not numeric"

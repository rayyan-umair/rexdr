"""
rexdr - Network Flow Intelligence Engine
capture.py - Packet capture layer

Author  : Rayyan Umair
Date    : 2026-06-17
Purpose : Captures live network traffic or replays from a PCAP file,
          aggregates packets into flow records, and yields completed
          flows for inspection. Uses scapy for packet parsing. Tracks
          active flows in memory and closes them after flow_timeout_seconds
          of inactivity. This is the only module that touches raw packets.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Silence the noise, strike the signal."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import threading
import logging
import time
import uuid
from datetime import datetime, timezone

# -- Third Party -------------------------------------------------------------
from scapy.all import sniff, rdpcap, IP, TCP, UDP, Packet

# -- Internal ----------------------------------------------------------------
from network_flow.config import settings

# ============================================================================

logger = logging.getLogger(__name__)

# Private IP ranges used to determine internal vs external traffic
PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
]


def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3])


def is_private_ip(ip: str) -> bool:
    """Returns True if the IP falls within a private RFC 1918 range."""
    try:
        ip_int = _ip_to_int(ip)
        for start, end in PRIVATE_RANGES:
            if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
                return True
        return False
    except Exception:
        return False


class FlowKey:
    """Identifies a unique bidirectional flow between two endpoints."""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

    def key(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"


class ActiveFlow:
    """Tracks an in-progress flow's accumulated state."""

    def __init__(self, flow_key: FlowKey):
        self.flow_id        = str(uuid.uuid4())
        self.flow_key       = flow_key
        self.start_time     = datetime.now(timezone.utc)
        self.last_seen      = time.time()
        self.packet_count   = 0
        self.bytes_sent     = 0
        self.bytes_received = 0
        self.flags: set[str] = set()

    def to_dict(self) -> dict:
        is_external = not is_private_ip(self.flow_key.dst_ip)
        return {
            "flow_id":        self.flow_id,
            "src_ip":         self.flow_key.src_ip,
            "dst_ip":         self.flow_key.dst_ip,
            "src_port":       self.flow_key.src_port,
            "dst_port":       self.flow_key.dst_port,
            "protocol":       self.flow_key.protocol,
            "start_time":     self.start_time,
            "end_time":       datetime.now(timezone.utc),
            "packet_count":   self.packet_count,
            "bytes_sent":     self.bytes_sent,
            "bytes_received": self.bytes_received,
            "flags":          ",".join(sorted(self.flags)),
            "is_external":    is_external,
        }


class PacketCapture:
    """
    Live or replay packet capture with flow aggregation.

    Usage:
        capture = PacketCapture()
        for flow in capture.run():
            process_flow(flow)
    """

    def __init__(self) -> None:
        self.active_flows: dict[str, ActiveFlow] = {}

    def run(self, flow_callback) -> None:
        """
        Starts capture and calls flow_callback(flow_dict) for every
        completed flow. Runs in live capture mode unless
        pcap_replay_path is configured. This is no longer a generator -
        sniff() blocks indefinitely in live mode, so completed flows
        must be pushed out via callback from a parallel timer thread
        rather than yielded after sniff() returns, since sniff() with
        no count/timeout never returns on its own.
        """
        if settings.pcap_replay_path and settings.pcap_replay_path.exists():
            self._run_replay(flow_callback)
        else:
            self._run_live(flow_callback)

    # -------------------------------------------------------------------------
    # Live capture
    # -------------------------------------------------------------------------

    def _run_live(self, flow_callback) -> None:
        logger.info(
            "Starting live capture - interface=%s filter=%s",
            settings.capture_interface,
            settings.capture_filter or "(none)",
        )

        def handle_packet(pkt: Packet):
            self._process_packet(pkt)

        expiry_thread = threading.Thread(
            target=self._expiry_loop,
            args=(flow_callback,),
            daemon=True,
        )
        expiry_thread.start()

        sniff(
            iface  = settings.capture_interface,
            filter = settings.capture_filter or None,
            prn    = handle_packet,
            store  = False,
        )

    def _expiry_loop(self, flow_callback) -> None:
        """
        Runs continuously on its own thread while sniff() blocks on the
        main capture thread. Checks for expired flows every few seconds
        and pushes each one out via flow_callback as it expires.
        """
        while True:
            time.sleep(5)
            for flow in self._drain_expired_flows():
                flow_callback(flow)

    # -------------------------------------------------------------------------
    # Replay mode
    # -------------------------------------------------------------------------

    def _run_replay(self, flow_callback) -> None:
        logger.info(
            "Starting PCAP replay - path=%s",
            settings.pcap_replay_path,
        )

        packets = rdpcap(str(settings.pcap_replay_path))
        for pkt in packets:
            self._process_packet(pkt)

        # Flush all flows at end of replay
        for flow in self.active_flows.values():
            flow_callback(flow.to_dict())
        self.active_flows.clear()

    # -------------------------------------------------------------------------
    # Packet processing
    # -------------------------------------------------------------------------

    def _process_packet(self, pkt: Packet) -> None:
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        size   = len(pkt)

        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        flags    = ""

        if TCP in pkt:
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = str(pkt[TCP].flags)
        elif UDP in pkt:
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        flow_key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
        key = flow_key.key()

        if key not in self.active_flows:
            self.active_flows[key] = ActiveFlow(flow_key)

        flow = self.active_flows[key]
        flow.packet_count += 1
        flow.bytes_sent += size
        flow.last_seen = time.time()
        if flags:
            flow.flags.add(flags)

    def _drain_expired_flows(self):
        """Yield and remove flows that have exceeded the idle timeout."""
        now = time.time()
        expired_keys = [
            k for k, f in self.active_flows.items()
            if now - f.last_seen > settings.flow_timeout_seconds
        ]
        for k in expired_keys:
            flow = self.active_flows.pop(k)
            yield flow.to_dict()
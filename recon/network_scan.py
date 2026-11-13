import ipaddress
from scapy.all import ARP, Ether, srp, conf


def get_interface_subnet(iface: str) -> str | None:
    iface_obj = conf.ifaces.dev_from_name(iface)   
    target_inf = iface_obj.network_name           
  
    best_network = None
    max_prefix_len = -1
    for route in conf.route.routes:
      net, mask, gw, inf, addr, metric = route
      if (
          inf == target_inf
          and addr != "0.0.0.0"
          and net != "0.0.0.0"
          and mask != 4294967295
      ):
        try:
          prefix_len = bin(mask & 0xFFFFFFFF).count("1")
          network = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
          if network.is_multicast or network.is_loopback:
            continue
          if network.prefixlen > max_prefix_len:
            max_prefix_len = network.prefixlen
            best_network = str(network)
        except ValueError:
          continue
    return best_network


def scan_subnet(iface, subnet_str=None, timeout=3) -> list[dict]:
  if not subnet_str:
    subnet_str = get_interface_subnet(iface)
    if not subnet_str:
      print(f"[-] Could not auto-detect subnet for interface {iface}")
      return []
    print(f"[*] Auto-detected subnet: {subnet_str}")

  packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet_str)
  answered, _ = srp(packet, timeout=timeout, iface=iface, verbose=False)

  devices = []
  for sent, rcv in answered:
    devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc})

  return devices
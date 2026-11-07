import random


def random_mac(oui=None):
    """oui: optional 3-byte prefix like '00:50:56' to mimic a real vendor"""
    prefix = oui if oui else "02:00:00"
    return "%s:%02x:%02x:%02x" % (
        prefix,
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )


def random_xid():
    return random.randint(1, 0xFFFFFFFF)


def mac_str_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))

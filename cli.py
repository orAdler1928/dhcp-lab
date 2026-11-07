#!/usr/bin/env python3
import argparse
import logging

from common.logging_config import setup_logging
from attacks.starvation import StarvationAttack

ATTACKS = {
    "starvation": StarvationAttack,
}


def build_parser():
    parser = argparse.ArgumentParser(description="DHCP Attack Lab CLI")
    subparsers = parser.add_subparsers(dest="attack", required=True)

    for name, attack_cls in ATTACKS.items():
        sub = subparsers.add_parser(name, help=f"{name} attack")
        sub.add_argument("-i", "--iface", required=True, help="Network interface to use")
        sub.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
        attack_cls.configure_parser(sub)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO)

    attack_cls = ATTACKS[args.attack]
    attack = attack_cls.from_args(args)

    try:
        attack.run()
    except KeyboardInterrupt:
        attack.stop()


if __name__ == "__main__":
    main()

# DHCP Attack Lab

CLI framework for practicing DHCP protocol attacks and defenses in an isolated
lab environment (host-only / internal network VMs only — **never run against
a real network you don't own**).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Scapy's raw-socket operations require root:

```bash
sudo .venv/bin/python3 cli.py <attack> -i <iface> [options]
```

## Usage

```bash
python3 cli.py --help                 # list available attacks
python3 cli.py starvation --help      # per-attack arguments
```

### starvation

DHCP pool exhaustion via full DORA completion (not just DISCOVER flooding —
sniffs OFFERs and completes REQUEST so the server actually commits each lease
via ACK).

```bash
sudo .venv/bin/python3 cli.py starvation -i eth0 --rate 0.1 --max-leases 50 -v
```

| Flag | Meaning | Default |
|---|---|---|
| `-i / --iface` | Network interface to attack on | required |
| `-v / --verbose` | Enable debug-level logging | off |
| `--rate` | Seconds between DISCOVER packets | `0.1` |
| `--max-leases` | Stop after this many confirmed ACKs | unlimited |

## Project structure

```
dhcp-lab/
├── cli.py                  # single entry point, argparse subcommands
├── attacks/
│   ├── base.py              # BaseAttack — shared interface (run/stop/stats)
│   └── starvation.py        # Exercise 2: DHCP Starvation
├── common/
│   ├── packet_utils.py      # random_mac, random_xid, mac_str_to_bytes
│   └── logging_config.py    # unified logging setup
└── requirements.txt
```

## Adding a new attack

1. Create `attacks/<name>.py`, subclass `BaseAttack`.
2. Implement `run()`.
3. Override `configure_parser(cls, parser)` to add attack-specific CLI args.
4. Override `from_args(cls, args)` to build the instance from parsed args.
5. Register it in `cli.py`'s `ATTACKS` dict.

Each attack owns only its own CLI arguments — `--help` on one attack never
shows flags belonging to another.

## Lab context

Built as part of a structured DHCP lab: baseline DORA → starvation →
decline/release spoofing → rogue DHCP/MITM → option abuse (WPAD, DNS hijack,
NTP spoofing, PXE/TFTP hijack, TunnelVision/CVE-2024-3661, and more) →
DHCP Snooping defense on a virtual switch (GNS3/EVE-NG).

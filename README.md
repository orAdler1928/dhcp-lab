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

## תרגיל 3 — DECLINE Flood: ממצאים

### התנהגות ISC dhcp-server (abandon-lease-time)
- `abandon-lease-time` **לא** קובע מתי dhcpd מתחיל להציע כתובות abandoned כ-last-resort —
  זה קורה כמעט מיידית (תוך ~1 שניה) ברגע שאין כתובות "free" רגילות, בלי קשר לערך
  (נבדק עם 60 ו-120 — אותה התנהגות בדיוק).
- המשמעות: `--exhaustion-timeout` הוא תנאי עצירה לא אמין נגד שרת עם abandon-lease-time
  מוגדר, כי "שקט אמיתי" (0 OFFERs) כמעט לא קורה — יש תמיד מה למחזר.
- `--max-leases` (לפי `decline_sent`) הוא כרגע התנאי העצירה האמין היחיד.

### Snipe של OFFER לקורבן אמיתי — לא עובד ברשת מבוססת-switch
- ציפייה ראשונית: הסניפר שלנו (`sniff` בלי סינון MAC/xid) יתפוס גם OFFER שנשלח ללקוח
  אמיתי, ונוכל לשלוח DECLINE בשמו לפני שהוא משלים DORA.
- בפועל (מאומת ב-VM2): **לא קורה.** `isc-dhclient` מודרני לא מדליק את ה-BROADCAST flag
  בבקשת DISCOVER שלו, ולכן dhcpd עונה לו ב-unicast ישירות ל-MAC שלו. ברשת host-only
  של VirtualBox (מתנהגת כמו switch, לא hub), פריים unicast כזה פשוט לא מגיע פיזית
  לממשק הרשת של התוקף.
- ה-DISCOVER/OFFER **שלנו** כן נראים לנו כי אנחנו מכריחים `flags=0x8000` (BROADCAST)
  בכוונה, כדי שנוכל לקבל תשובה בלי כתובת IP אמיתית.
- מסקנה: ה-snipe הזה יעיל רק נגד לקוחות שמדליקים את ה-broadcast flag (מימושים ישנים/
  חריגים), לא נגד isc-dhclient סטנדרטי על Linux מודרני.

### המסקנה הכוללת: DECLINE flood הוא DoS חלש/לא-מתמשך מול ISC dhcpd
- בניגוד ל-STARVATION (DORA מלא עד ACK, תרגיל 2) — ששם lease אמיתי נשמר ל-lease_time
  המלא ולא ניתן למחזור מוקדם — DECLINE רק מסמן "abandoned", וההתאוששות (last-resort
  reclaim) כמעט מיידית.
- המשמעות: אין כאן מצב "pool חסום" ממושך. ברגע שעוצרים את ה-flood, לקוח הבא (ישן או
  חדש) מקבל שירות תוך כדי שבריר שניה.
- STARVATION נשאר מנגנון ה-DoS ה"אמיתי" מבין השניים, מכיוון שהוא תלוי ב-lease_time
  ולא ב-abandon-lease-time.
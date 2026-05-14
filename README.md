# mdns-detect

Fast validator for the **mDNS Detection (Remote Network)** class of finding.

Per RFC 6762/6763, mDNS responders should only answer link-local multicast queries. When a host answers a **unicast** DNS-SD query from off-link, it leaks hostnames, advertised services, ports, and often device-model / OS / firmware metadata.

This script confirms the issue on a list of targets and prints screenshot-worthy terminal evidence of what was disclosed.

## Install

```sh
git clone https://github.com/alecoad/mdns-detect.git
cd mdns-detect
chmod +x mdns-detect.py
```

Python 3.10+. **No dependencies** — drop the single file on a test box and run it. Color/box-drawing output uses plain ANSI escapes; auto-disabled when stdout isn't a TTY.

## Usage

```
mdns-detect.py [targets...] [-f targets.txt]
               [--basic | --full]                # default: --full
               [--timeout 2.0] [--concurrency 64]
               [--plain | --json | --concise]    # default: color
               [-v]                              # record raw response packets
```

Target format: `host:port`, `ip:port`, `[ipv6]:port`, or bare `host` / `ip` (defaults to 5353). In a `-f` file, `#` comments and blank lines are ignored.

### Typical workflow

**1. Triage a large list with `--concise`:**

```sh
python3 mdns-detect.py -f targets.txt --concise --timeout 2
```

```
[VULN] 10.0.0.42:5353         Office-Printer.local         7 services  (ipp,http,printer,...)
[VULN] 10.0.0.51:5353         apple-tv.local               3 services  (airplay,raop,companion)
[ ok ] 10.0.0.77:5353         no response
[ERR ] bogus.example:5353     resolve: [Errno 8] ...
Scanned 161 | Vulnerable 23 | Clean 134 | Errors 4 | 14.2s
```

**2. Re-run the vulnerable subset with the default color output to capture per-host screenshots:**

```sh
python3 mdns-detect.py 10.0.0.42 10.0.0.51 -v
```

Per-target output shows verdict, RTT, resolved `.local` hostname, and a table of advertised services with ports and TXT key/value metadata.

**3. Export structured results:**

```sh
python3 mdns-detect.py -f targets.txt --json > results.json
jq '.results[] | select(.status=="vulnerable")' results.json
```

## Modes

- **`--full`** *(default)* — three-stage DNS-SD walk:
  1. `PTR _services._dns-sd._udp.local` → service types
  2. `PTR <service-type>` → instance names
  3. `ANY <instance>` → SRV (host/port) + TXT (metadata)
  Then resolves any `.local` hostnames referenced by SRV records.
- **`--basic`** — one PTR query; flags responding on any answer. Faster on huge lists, no service-level disclosure.

## Exit codes

- `0` — no targets responded
- `1` — at least one target responded
- `130` — interrupted (Ctrl-C)

## References

- RFC 6762 (mDNS)
- RFC 6763 (DNS-SD) §4, §9 — service-type enumeration meta-query
- Cross-check a single host with: `nmap -sU -p 5353 --script=dns-service-discovery <ip>`

## Disclaimer

For authorized security testing only. Run this against hosts/networks you own or have written permission to test.

## Credits

Written with [Claude Code](https://claude.com/claude-code) (Opus 4.7).

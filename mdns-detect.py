#!/usr/bin/env python3
"""
mdns-detect — validator for Tenable Nessus plugin "mDNS Detection (Remote Network)".

Sends unicast DNS-SD queries (UDP/5353) to each target and reports whether the host
answers — and what it discloses. Per RFC 6762/6763, mDNS responders should only
answer link-local multicast queries; answering off-link unicast = the Nessus finding.

Stdlib only — drop the file on a test box and run it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import shutil
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Any


# ─── DNS wire format (RFC 1035) ──────────────────────────────────────────────

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_ANY = 255
CLASS_IN = 1

TYPE_NAMES = {TYPE_A: "A", TYPE_PTR: "PTR", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA", TYPE_SRV: "SRV"}

SERVICE_TYPE_ENUM = "_services._dns-sd._udp.local"


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        b = label.encode("utf-8")
        if len(b) > 63:
            raise ValueError("label too long")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def pack_query(qname: str, qtype: int, qid: int | None = None) -> tuple[int, bytes]:
    if qid is None:
        qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0000, 1, 0, 0, 0)
    body = encode_name(qname) + struct.pack(">HH", qtype, CLASS_IN)
    return qid, header + body


def decode_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, offset_after).
    For compressed pointers, offset_after is past the pointer in the original stream."""
    labels: list[str] = []
    jumped = False
    original_offset = offset
    safety = 0
    while True:
        if safety > 256:
            raise ValueError("name decode loop")
        safety += 1
        if offset >= len(buf):
            raise ValueError("name truncated")
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("pointer truncated")
            ptr = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(buf[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), (original_offset if jumped else offset)


@dataclass
class RR:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: Any  # decoded form depending on type

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, str(self.rtype))


def parse_response(buf: bytes) -> tuple[int, list[RR], list[RR]]:
    """Return (qid, answers, additionals)."""
    if len(buf) < 12:
        raise ValueError("response too short")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    offset = 12
    # skip questions
    for _ in range(qd):
        _, offset = decode_name(buf, offset)
        offset += 4
    answers = []
    for _ in range(an):
        rr, offset = _parse_rr(buf, offset)
        answers.append(rr)
    # skip authority
    for _ in range(ns):
        _, offset = decode_name(buf, offset)
        if offset + 10 > len(buf):
            break
        rdlen = struct.unpack(">H", buf[offset + 8:offset + 10])[0]
        offset += 10 + rdlen
    additionals = []
    for _ in range(ar):
        if offset >= len(buf):
            break
        try:
            rr, offset = _parse_rr(buf, offset)
        except Exception:
            break
        additionals.append(rr)
    return qid, answers, additionals


def _parse_rr(buf: bytes, offset: int) -> tuple[RR, int]:
    name, offset = decode_name(buf, offset)
    if offset + 10 > len(buf):
        raise ValueError("rr header truncated")
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[offset:offset + 10])
    offset += 10
    rdata_end = offset + rdlen
    if rdata_end > len(buf):
        raise ValueError("rdata truncated")
    # mDNS sets top bit of class for cache-flush; mask it off
    rclass &= 0x7FFF
    rdata: Any
    if rtype == TYPE_A and rdlen == 4:
        rdata = socket.inet_ntop(socket.AF_INET, buf[offset:offset + 4])
    elif rtype == TYPE_AAAA and rdlen == 16:
        rdata = socket.inet_ntop(socket.AF_INET6, buf[offset:offset + 16])
    elif rtype == TYPE_PTR:
        rdata, _ = decode_name(buf, offset)
    elif rtype == TYPE_SRV:
        priority, weight, port = struct.unpack(">HHH", buf[offset:offset + 6])
        target, _ = decode_name(buf, offset + 6)
        rdata = {"priority": priority, "weight": weight, "port": port, "target": target}
    elif rtype == TYPE_TXT:
        items: dict[str, str | bool] = {}
        i = offset
        while i < rdata_end:
            ln = buf[i]
            i += 1
            chunk = buf[i:i + ln].decode("utf-8", errors="replace")
            i += ln
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                items[k] = v
            elif chunk:
                items[chunk] = True
        rdata = items
    else:
        rdata = buf[offset:rdata_end].hex()
    return RR(name, rtype, rclass, ttl, rdata), rdata_end


# ─── Probe ───────────────────────────────────────────────────────────────────

@dataclass
class Service:
    service_type: str
    instance: str
    port: int | None = None
    target: str | None = None
    txt: dict[str, str | bool] = field(default_factory=dict)


@dataclass
class ProbeResult:
    host: str
    port: int
    status: str            # "vulnerable" | "clean" | "error"
    rtt_ms: float | None = None
    error: str | None = None
    hostnames: dict[str, str] = field(default_factory=dict)  # name -> first addr
    services: list[Service] = field(default_factory=list)
    raw_answers: list[RR] = field(default_factory=list)
    raw_packets: list[bytes] = field(default_factory=list)

    @property
    def target_str(self) -> str:
        return f"{self.host}:{self.port}"


class _UDPProto(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        self.queue.put_nowait(data)

    def error_received(self, exc: Exception) -> None:
        # ICMP unreachable etc — surface by closing queue
        self.queue.put_nowait(b"")


async def _send_and_collect(proto: _UDPProto, transport: asyncio.DatagramTransport,
                            qname: str, qtype: int, timeout: float,
                            raw_store: list[bytes] | None) -> list[RR]:
    qid, pkt = pack_query(qname, qtype)
    transport.sendto(pkt)
    answers: list[RR] = []
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            data = await asyncio.wait_for(proto.queue.get(), timeout=remaining)
        except asyncio.TimeoutError:
            break
        if not data:
            continue
        if raw_store is not None:
            raw_store.append(data)
        try:
            rqid, ans, addl = parse_response(data)
        except Exception:
            continue
        # mDNS responses often use qid=0; accept anything that arrived on this socket
        answers.extend(ans)
        answers.extend(addl)
        # Don't break — multiple packets may follow within the window
    return answers


async def probe(host: str, port: int, *, mode: str, timeout: float,
                verbose: bool) -> ProbeResult:
    result = ProbeResult(host=host, port=port, status="clean")
    raw_store = result.raw_packets if verbose else None
    loop = asyncio.get_event_loop()

    try:
        # Resolve hostname → IP up front (asyncio.create_datagram_endpoint with
        # remote_addr does it, but we want to surface DNS errors clearly).
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        if not infos:
            raise OSError("no address")
        family, _, _, _, sockaddr = infos[0]
    except Exception as e:  # noqa: BLE001
        result.status = "error"
        result.error = f"resolve: {e}"
        return result

    try:
        transport, proto = await loop.create_datagram_endpoint(
            _UDPProto, family=family, remote_addr=sockaddr[:2] if family == socket.AF_INET else sockaddr,
        )
    except Exception as e:  # noqa: BLE001
        result.status = "error"
        result.error = f"socket: {e}"
        return result

    try:
        t0 = time.perf_counter()
        # Stage 1: service-type enumeration
        ans1 = await _send_and_collect(proto, transport, SERVICE_TYPE_ENUM,
                                       TYPE_PTR, timeout, raw_store)
        result.raw_answers.extend(ans1)

        # Any answer at all = vulnerable
        if not ans1:
            return result  # status=clean, no rtt
        result.rtt_ms = (time.perf_counter() - t0) * 1000.0
        result.status = "vulnerable"

        service_types: list[str] = []
        for rr in ans1:
            if rr.rtype == TYPE_PTR and isinstance(rr.rdata, str):
                if rr.rdata not in service_types:
                    service_types.append(rr.rdata)

        if mode == "basic" or not service_types:
            return result

        # Stage 2: enumerate instances per service type
        instances: list[tuple[str, str]] = []  # (service_type, instance_fqdn)
        for stype in service_types:
            ans = await _send_and_collect(proto, transport, stype, TYPE_PTR,
                                          timeout, raw_store)
            result.raw_answers.extend(ans)
            for rr in ans:
                if rr.rtype == TYPE_PTR and isinstance(rr.rdata, str):
                    instances.append((stype, rr.rdata))
                # Sometimes SRV/TXT come along for free in additional section
                if rr.rtype == TYPE_SRV:
                    pass  # handled in stage 3 lookup

        # Stage 3: SRV + TXT per instance (single ANY query keeps it fast)
        seen: dict[str, Service] = {}
        for stype, instance in instances:
            ans = await _send_and_collect(proto, transport, instance, TYPE_ANY,
                                          timeout / 2, raw_store)
            result.raw_answers.extend(ans)
            svc = seen.get(instance) or Service(service_type=stype,
                                                instance=_instance_label(instance, stype))
            for rr in ans:
                if rr.rtype == TYPE_SRV and isinstance(rr.rdata, dict):
                    svc.port = rr.rdata["port"]
                    svc.target = rr.rdata["target"]
                elif rr.rtype == TYPE_TXT and isinstance(rr.rdata, dict):
                    svc.txt.update(rr.rdata)
            seen[instance] = svc

        result.services = list(seen.values())

        # Stage 4: resolve any .local hostnames referenced by SRV targets
        hostnames = {s.target for s in result.services if s.target}
        for hn in hostnames:
            ans = await _send_and_collect(proto, transport, hn, TYPE_A,
                                          timeout / 2, raw_store)
            for rr in ans:
                if rr.rtype == TYPE_A and isinstance(rr.rdata, str):
                    result.hostnames.setdefault(hn, rr.rdata)
                    break
    finally:
        transport.close()

    return result


def _instance_label(instance_fqdn: str, service_type: str) -> str:
    """`Office Printer._ipp._tcp.local` + `_ipp._tcp.local` → `Office Printer`."""
    suffix = "." + service_type
    if instance_fqdn.endswith(suffix):
        return instance_fqdn[:-len(suffix)]
    return instance_fqdn


# ─── Renderers ──────────────────────────────────────────────────────────────

def _short_service_name(stype: str) -> str:
    # `_ipp._tcp.local` → `ipp`
    s = stype.split(".")[0]
    return s.lstrip("_")


def _ansi(code: str, use_color: bool) -> str:
    return f"\033[{code}m" if use_color else ""


class ColorRenderer:
    """ANSI-colored per-host output with a box-drawn service table. Stdlib only."""

    def __init__(self) -> None:
        self.use_color = sys.stdout.isatty()
        self.width = shutil.get_terminal_size((100, 24)).columns

    def _c(self, s: str, code: str) -> str:
        return f"{_ansi(code, self.use_color)}{s}{_ansi('0', self.use_color)}"

    def per_target(self, r: ProbeResult, verbose: bool) -> None:
        rule_char = "━"
        header = f" {r.target_str} "
        bar = rule_char * max(4, (self.width - len(header)) // 2)
        print(self._c(f"{bar}{header}{bar}", "1;36"))

        if r.status == "vulnerable":
            verdict = self._c("VULNERABLE", "1;31") + "  responded to off-link mDNS query"
        elif r.status == "clean":
            verdict = self._c("not vulnerable", "32") + self._c("  (no response within timeout)", "2")
        else:
            verdict = self._c(f"ERROR  {r.error}", "1;33")
        print(f"  Status:    {verdict}")
        if r.rtt_ms is not None:
            print(f"  RTT:       {self._c(f'{r.rtt_ms:.1f} ms', '2')}")
        for hn, addr in r.hostnames.items():
            print(f"  Hostname:  {self._c(hn, '1')} -> {addr}")

        if r.services:
            services = sorted(r.services, key=lambda s: s.service_type)
            rows = []
            for svc in services:
                txt = ", ".join(
                    (k if v is True else f"{k}={v}")
                    for k, v in list(svc.txt.items())[:6]
                )
                rows.append((svc.service_type, svc.instance,
                             str(svc.port) if svc.port else "-", txt))
            headers = ("Service", "Instance", "Port", "TXT details")
            widths = [
                max(len(headers[i]), max((len(row[i]) for row in rows), default=0))
                for i in range(4)
            ]
            # Cap the TXT column so wide TXT doesn't blow up the table.
            max_txt = max(20, self.width - sum(widths[:3]) - 12)
            widths[3] = min(widths[3], max_txt)

            def fmt_row(cols, bold=False):
                cells = []
                for i, c in enumerate(cols):
                    if i == 3 and len(c) > widths[3]:
                        c = c[: widths[3] - 1] + "…"
                    pad = c.ljust(widths[i]) if i != 2 else c.rjust(widths[i])
                    cells.append(self._c(pad, "1") if bold else pad)
                return "  " + "  ".join(cells)

            print(self._c("  Services:", "1"))
            print(fmt_row(headers, bold=True))
            print("  " + self._c("─" * (sum(widths) + 6), "2"))
            for row in rows:
                print(fmt_row(row))

        if verbose and r.raw_packets:
            total = sum(len(p) for p in r.raw_packets)
            print(self._c(f"  raw packets: {len(r.raw_packets)} ({total} bytes)", "2"))
        print()

    def summary(self, results: list[ProbeResult], elapsed: float) -> None:
        vuln = sum(1 for r in results if r.status == "vulnerable")
        clean = sum(1 for r in results if r.status == "clean")
        err = sum(1 for r in results if r.status == "error")
        print(
            f"{self._c('Scanned', '1')} {len(results)}  "
            f"{self._c('Vulnerable', '31')} {vuln}  "
            f"{self._c('Clean', '32')} {clean}  "
            f"{self._c('Errors', '33')} {err}  "
            f"{self._c(f'{elapsed:.1f}s', '2')}"
        )


class ConciseRenderer:
    """Streams one row per host as probes complete, with header up front and a
    summary after. Hosts with >2 services wrap to multiple lines (2 per line)
    aligned under the DETAIL column."""

    # Column widths matched to the format strings in _format_row.
    _W_TAG = 6      # "[VULN]"
    _W_TARGET = 22
    _W_HOST = 28
    _SERVICES_PER_LINE = 2

    def __init__(self) -> None:
        self.use_color = sys.stdout.isatty()
        self._header_printed = False

    def _c(self, s: str, code: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.use_color else s

    @property
    def _detail_col(self) -> int:
        return self._W_TAG + 1 + self._W_TARGET + 1 + self._W_HOST + 1

    def _print_header(self) -> None:
        print()  # blank line separating from the command prompt
        header = (
            f"{'STATUS':<{self._W_TAG}} "
            f"{'TARGET':<{self._W_TARGET}} "
            f"{'HOSTNAME':<{self._W_HOST}} "
            f"DETAIL"
        )
        rule_w = self._detail_col + 30
        print(self._c(header, "1"))
        print(self._c("─" * rule_w, "2"))
        self._header_printed = True

    def per_target(self, r: ProbeResult, verbose: bool) -> None:
        if not self._header_printed:
            self._print_header()
        if r.status == "vulnerable":
            tag = self._c("[VULN]", "1;31")
            hn = next(iter(r.hostnames), "")
            count = len(r.services)
            names = [_short_service_name(s.service_type) for s in r.services]
            noun = "service" if count == 1 else "services"
            if not names:
                detail_lines = ["responded"]
            elif len(names) <= 2:
                detail_lines = [f"{count} {noun}  ({', '.join(names)})"]
            else:
                # Force a real multi-line wrap: header line + N service lines
                detail_lines = [f"{count} {noun}:"]
                for i in range(0, len(names), self._SERVICES_PER_LINE):
                    chunk = names[i:i + self._SERVICES_PER_LINE]
                    detail_lines.append(", ".join(chunk))
            first = f"{tag} {r.target_str:<{self._W_TARGET}} {hn:<{self._W_HOST}} {detail_lines[0]}"
            print(first)
            indent = " " * self._detail_col
            for line in detail_lines[1:]:
                print(indent + line)
        elif r.status == "clean":
            print(f"{self._c('[ ok ]', '32')} {r.target_str:<{self._W_TARGET}} "
                  f"{'':<{self._W_HOST}} no response")
        else:
            print(f"{self._c('[ERR ]', '1;33')} {r.target_str:<{self._W_TARGET}} "
                  f"{'':<{self._W_HOST}} {r.error}")
        sys.stdout.flush()

    def summary(self, results: list[ProbeResult], elapsed: float) -> None:
        print()  # blank line before the summary
        vuln = sum(1 for r in results if r.status == "vulnerable")
        clean = sum(1 for r in results if r.status == "clean")
        err = sum(1 for r in results if r.status == "error")
        print(f"Scanned {len(results)} | Vulnerable {vuln} | Clean {clean} "
              f"| Errors {err} | {elapsed:.1f}s")


class PlainRenderer:
    def per_target(self, r: ProbeResult, verbose: bool) -> None:
        print(f"=== {r.target_str} ===")
        print(f"  status: {r.status}" + (f"  ({r.error})" if r.error else ""))
        if r.rtt_ms is not None:
            print(f"  rtt: {r.rtt_ms:.1f} ms")
        for hn, addr in r.hostnames.items():
            print(f"  hostname: {hn} -> {addr}")
        for svc in sorted(r.services, key=lambda s: s.service_type):
            line = f"  {svc.service_type}  {svc.instance}"
            if svc.port:
                line += f"  port={svc.port}"
            if svc.target:
                line += f"  target={svc.target}"
            print(line)
            for k, v in svc.txt.items():
                print(f"      {k}={v}")
        print()

    def summary(self, results: list[ProbeResult], elapsed: float) -> None:
        vuln = sum(1 for r in results if r.status == "vulnerable")
        clean = sum(1 for r in results if r.status == "clean")
        err = sum(1 for r in results if r.status == "error")
        print(f"scanned={len(results)} vulnerable={vuln} clean={clean} "
              f"errors={err} elapsed={elapsed:.1f}s")


class JsonRenderer:
    def __init__(self) -> None:
        self._items: list[dict] = []

    def per_target(self, r: ProbeResult, verbose: bool) -> None:
        self._items.append({
            "target": r.target_str,
            "host": r.host,
            "port": r.port,
            "status": r.status,
            "error": r.error,
            "rtt_ms": r.rtt_ms,
            "hostnames": r.hostnames,
            "services": [
                {
                    "type": s.service_type,
                    "instance": s.instance,
                    "port": s.port,
                    "target": s.target,
                    "txt": s.txt,
                } for s in r.services
            ],
        })

    def summary(self, results: list[ProbeResult], elapsed: float) -> None:
        out = {
            "results": self._items,
            "summary": {
                "scanned": len(results),
                "vulnerable": sum(1 for r in results if r.status == "vulnerable"),
                "clean": sum(1 for r in results if r.status == "clean"),
                "errors": sum(1 for r in results if r.status == "error"),
                "elapsed_s": round(elapsed, 2),
            },
        }
        print(json.dumps(out, indent=2, default=str))


# ─── CLI ────────────────────────────────────────────────────────────────────

def parse_target(s: str) -> tuple[str, int]:
    s = s.strip()
    # IPv6 with brackets: [::1]:5353
    if s.startswith("["):
        end = s.index("]")
        host = s[1:end]
        rest = s[end + 1:]
        port = int(rest.lstrip(":")) if rest else 5353
        return host, port
    if ":" in s and s.count(":") == 1:
        host, _, port_s = s.partition(":")
        return host, int(port_s)
    return s, 5353


def load_targets(args: argparse.Namespace) -> list[tuple[str, int]]:
    raws: list[str] = list(args.targets or [])
    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    raws.append(line)
    targets = []
    seen = set()
    for r in raws:
        try:
            t = parse_target(r)
        except Exception as e:  # noqa: BLE001
            print(f"warn: bad target {r!r}: {e}", file=sys.stderr)
            continue
        if t not in seen:
            seen.add(t)
            targets.append(t)
    return targets


async def run(targets: list[tuple[str, int]], args: argparse.Namespace, renderer) -> int:
    sem = asyncio.Semaphore(args.concurrency)
    results: list[ProbeResult] = [None] * len(targets)  # type: ignore[list-item]
    stream = not isinstance(renderer, JsonRenderer)
    lock = asyncio.Lock()

    async def one(i: int, host: str, port: int) -> None:
        async with sem:
            r = await probe(host, port, mode=args.mode, timeout=args.timeout,
                            verbose=args.verbose)
        results[i] = r
        if stream:
            async with lock:
                renderer.per_target(r, args.verbose)

    t0 = time.perf_counter()
    await asyncio.gather(*(one(i, h, p) for i, (h, p) in enumerate(targets)))
    elapsed = time.perf_counter() - t0

    if not stream:
        for r in results:
            renderer.per_target(r, args.verbose)
    renderer.summary(results, elapsed)

    return 1 if any(r.status == "vulnerable" for r in results) else 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Validate Nessus 'mDNS Detection (Remote Network)' findings.",
    )
    p.add_argument("targets", nargs="*", help="host[:port] or ip[:port] (default port 5353)")
    p.add_argument("-f", "--file", help="file of targets, one per line (# for comments)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--basic", dest="mode", action="store_const", const="basic",
                      help="one PTR query, no service walk")
    mode.add_argument("--full", dest="mode", action="store_const", const="full",
                      help="full DNS-SD service walk (default)")
    p.set_defaults(mode="full")
    p.add_argument("--timeout", type=float, default=2.0, help="per-stage timeout seconds (default 2.0)")
    p.add_argument("--concurrency", type=int, default=64, help="parallel probes (default 64)")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--plain", dest="output", action="store_const", const="plain")
    out.add_argument("--json", dest="output", action="store_const", const="json")
    out.add_argument("--concise", dest="output", action="store_const", const="concise")
    p.set_defaults(output="color")
    p.add_argument("-v", "--verbose", action="store_true", help="record raw response packets")
    args = p.parse_args()

    targets = load_targets(args)
    if not targets:
        p.error("no targets given (positional or -f)")

    renderer: Any
    if args.output == "color":
        renderer = ColorRenderer()
    elif args.output == "concise":
        renderer = ConciseRenderer()
    elif args.output == "json":
        renderer = JsonRenderer()
    else:
        renderer = PlainRenderer()

    try:
        return asyncio.run(run(targets, args, renderer))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

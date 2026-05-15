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
import os
import random
import re
import shutil
import socket
import struct
import sys
import textwrap
import time
from dataclasses import dataclass, field
from typing import Any, TextIO


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

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _short_service_name(stype: str) -> str:
    # `_ipp._tcp.local` → `ipp`
    s = stype.split(".")[0]
    return s.lstrip("_")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _vlen(s: str) -> int:
    return len(_strip_ansi(s))


def _truncate(s: str, width: int) -> str:
    if _vlen(s) <= width:
        return s
    plain = _strip_ansi(s)
    if width <= 3:
        return plain[:width]
    return plain[:width - 3] + "..."


def _short_error(msg: str | None) -> str:
    if not msg:
        return "unreachable"
    m = msg.lower()
    if "nodename nor servname" in m or "name resolution" in m:
        return "DNS resolution failed"
    if "name or service not known" in m:
        return "DNS resolution failed"
    if "temporary failure in name resolution" in m:
        return "DNS resolution failed"
    if "timed out" in m or "timeout" in m:
        return "timeout"
    if "connection refused" in m:
        return "connection refused"
    if "no route to host" in m:
        return "no route to host"
    if "network is unreachable" in m:
        return "network unreachable"
    if "host is down" in m:
        return "host is down"
    return msg.split(":", 1)[-1].strip()[:60] or "error"


class TerminalRenderer:
    """Default client-facing terminal report."""

    _MAX_SERVICES = 3
    _HEADER_EVERY = 30
    _HOST_PREFIX = "    Hostname: "
    _EVIDENCE_PREFIX = "    Evidence: "
    _DETAILS_PREFIX = "    Details: "

    def __init__(self, *, mode: str, timeout: float, concurrency: int,
                 stream: TextIO = sys.stdout) -> None:
        self.mode = mode
        self.timeout = timeout
        self.concurrency = concurrency
        self.stream = stream
        self.use_color = (
            bool(getattr(stream, "isatty", lambda: False)())
            and not os.environ.get("NO_COLOR")
        )
        self.width = shutil.get_terminal_size((100, 24)).columns
        self._W_EVIDENCE = max(44, min(96, self.width - len(self._EVIDENCE_PREFIX)))
        self._rule_w = max(72, min(100, self.width))

    def _c(self, s: str, code: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.use_color else s

    def _rule(self) -> str:
        return self._c("─" * self._rule_w, "2")

    def _status(self, r: ProbeResult) -> str:
        if r.status == "vulnerable":
            return self._c("VULNERABLE", "1;31")
        if r.status == "error":
            return self._c("ERROR", "1;33")
        return self._c("OK", "32")

    def _target(self, r: ProbeResult) -> str:
        return self._c(_truncate(r.target_str, 48), "1;34")

    def _primary_hostname(self, r: ProbeResult) -> str:
        return next(iter(sorted(r.hostnames)), "-")

    def _service_names(self, r: ProbeResult) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for svc in sorted(r.services, key=lambda s: _short_service_name(s.service_type)):
            name = _short_service_name(svc.service_type)
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(name)
        return names

    def _service_summary(self, r: ProbeResult) -> str:
        names = self._service_names(r)
        count = len(names)
        if count == 0:
            return "no service details"
        shown = names[:self._MAX_SERVICES]
        more = count - len(shown)
        summary = f"services disclosed: {', '.join(shown)}"
        if more:
            summary += f" (+{more})"
        return summary

    def _evidence(self, r: ProbeResult, verbose: bool) -> str:
        if r.status == "error":
            return _short_error(r.error)
        if r.status == "clean":
            return "no response"

        return "; ".join(("off-link mDNS response", self._service_summary(r)))

    def _details(self, r: ProbeResult, verbose: bool) -> str | None:
        if not verbose or r.status != "vulnerable":
            return None
        parts = []
        if verbose and r.rtt_ms is not None:
            parts.append(f"RTT {r.rtt_ms:.1f} ms")
        if verbose and r.raw_packets:
            total = sum(len(p) for p in r.raw_packets)
            noun = "pkt" if len(r.raw_packets) == 1 else "pkts"
            parts.append(f"raw {len(r.raw_packets)} {noun}, {total} B")
        return "; ".join(parts) if parts else None

    def _wrap(self, text: str) -> list[str]:
        return textwrap.wrap(text, width=self._W_EVIDENCE) or [""]

    def _print_wrapped(self, prefix: str, text: str) -> None:
        lines = self._wrap(text)
        print(f"{prefix}{lines[0]}", file=self.stream)
        indent = " " * len(prefix)
        for line in lines[1:]:
            print(f"{indent}{line}", file=self.stream)

    def _print_row(self, r: ProbeResult, verbose: bool) -> None:
        status = self._status(r)
        host = _truncate(self._primary_hostname(r), 48)

        print(f"[*] {self._target(r)} - {status}", file=self.stream)
        print(f"{self._HOST_PREFIX}{host}", file=self.stream)
        self._print_wrapped(self._EVIDENCE_PREFIX, self._evidence(r, verbose))
        details = self._details(r, verbose)
        if details:
            self._print_wrapped(self._DETAILS_PREFIX, details)
        print(file=self.stream)

    def _ordered(self, results: list[ProbeResult]) -> list[ProbeResult]:
        rank = {"vulnerable": 0, "error": 1, "clean": 2}
        return sorted(results, key=lambda r: (rank.get(r.status, 3), r.target_str))

    def _print_continued_header(self) -> None:
        print(self._rule(), file=self.stream)
        print(self._c("mDNS Detection (continued)", "1"), file=self.stream)
        print(file=self.stream)

    def render(self, results: list[ProbeResult], elapsed: float, verbose: bool) -> None:
        print(file=self.stream)
        print(self._c("mDNS Detection (Remote Network)", "1;36"), file=self.stream)
        print(
            self._c(
                f"mode={self.mode}  timeout={self.timeout:.1f}s  "
                f"concurrency={self.concurrency}",
                "2",
            ),
            file=self.stream,
        )
        print(file=self.stream)
        ordered = self._ordered(results)
        for i, r in enumerate(ordered):
            if i > 0 and i % self._HEADER_EVERY == 0:
                self._print_continued_header()
            self._print_row(r, verbose)
        print(self._rule(), file=self.stream)

        vuln = sum(1 for r in results if r.status == "vulnerable")
        clean = sum(1 for r in results if r.status == "clean")
        err = sum(1 for r in results if r.status == "error")
        summary = (
            f"Scanned {len(results)} | "
            f"Vulnerable {vuln} | OK {clean} | Errors {err} | {elapsed:.1f}s"
        )
        print(self._c(summary, "1"), file=self.stream)
        print(file=self.stream)


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


async def run(targets: list[tuple[str, int]], args: argparse.Namespace,
              renderer: TerminalRenderer) -> int:
    sem = asyncio.Semaphore(args.concurrency)
    results: list[ProbeResult] = [None] * len(targets)  # type: ignore[list-item]

    async def one(i: int, host: str, port: int) -> None:
        async with sem:
            r = await probe(host, port, mode=args.mode, timeout=args.timeout,
                            verbose=args.verbose)
        results[i] = r

    t0 = time.perf_counter()
    await asyncio.gather(*(one(i, h, p) for i, (h, p) in enumerate(targets)))
    elapsed = time.perf_counter() - t0

    renderer.render(results, elapsed, args.verbose)

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
    p.add_argument("-v", "--verbose", action="store_true",
                   help="include raw response packet counts in the report")
    args = p.parse_args()

    targets = load_targets(args)
    if not targets:
        p.error("no targets given (positional or -f)")

    renderer = TerminalRenderer(
        mode=args.mode,
        timeout=args.timeout,
        concurrency=args.concurrency,
    )

    try:
        return asyncio.run(run(targets, args, renderer))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

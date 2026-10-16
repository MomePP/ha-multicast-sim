#!/usr/bin/env python3
"""Reproduce Home Assistant + ESPHome multicast load on a workshop Wi-Fi VLAN.

Modes
  sim     model H Home Assistant VMs and D ESPHome devices sharing one VLAN:
          zeroconf restart bursts, ESPHome discovery answers, known-answer
          lists, SSDP scans.
  flood   send a fixed or stepped multicast rate to find the breaking point.
  listen  count mDNS/SSDP/broadcast arriving at this host (run on a second
          client to confirm the AP delivers the flood, and to measure the
          real workshop).

Where to run the sender
  Best: a wired host on an access port of the VLAN under test. The AP
  re-transmits every group frame once per BSS of that VLAN at the basic rate,
  which is the cost this reproduces. From a Wi-Fi client each frame also costs
  one uplink transmission at the client's data rate.

Not reproduced: association/DHCP load of 300 real clients, per-device
retries, VirtualBox bridged-MAC behaviour, IPv6 RS/MLD.

The airtime columns estimate the share of one channel spent on these frames
(group frames are never ACKed or retried). Values over 100% mean the offered
load exceeds what the channel can carry.

Run only on a network you operate.
"""
from __future__ import annotations

import argparse
import heapq
import itertools
import math
import random
import re
import selectors
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter

MDNS = ("224.0.0.251", 5353)
SSDP = ("239.255.255.250", 1900)
BCAST = ("255.255.255.255", 1900)
MAX_MSG = 1460  # python-zeroconf _MAX_MSG_TYPICAL
T_A, T_PTR, T_TXT, T_SRV, T_ANY = 1, 12, 16, 33, 255
UDP_OVER_WIFI = 24 + 8 + 20 + 8 + 16 + 4  # MAC header, LLC/SNAP, IPv4, UDP, CCMP, FCS
DSSS_RATES = (1.0, 2.0, 5.5, 11.0)
BEACONS_PER_S = 1 / 0.1024
MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 4\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def airtime_us(mpdu: int, rate: float) -> float:
    """One group-addressed transmission: preamble + payload + DIFS + mean backoff, no ACK."""
    if rate in DSSS_RATES:
        return 192 + mpdu * 8 / rate + 50 + 15.5 * 20
    symbols = math.ceil((16 + 8 * mpdu + 6) / (rate * 4))
    return 20 + 4 * symbols + 34 + 7.5 * 9


# --- DNS wire format -------------------------------------------------------


class Msg:
    def __init__(self, flags: int):
        self.flags = flags
        self.buf = bytearray(12)
        self.ptrs: dict[str, int] = {}
        self.qd = self.an = 0

    def name(self, name: str) -> None:
        labels = name.rstrip(".").split(".")
        for i, label in enumerate(labels):
            suffix = ".".join(labels[i:])
            if suffix in self.ptrs:
                self.buf += struct.pack("!H", 0xC000 | self.ptrs[suffix])
                return
            self.ptrs[suffix] = len(self.buf)
            raw = label.encode()
            self.buf += bytes([len(raw)]) + raw
        self.buf.append(0)

    def question(self, name: str, qtype: int, unicast: bool = False) -> None:
        self.name(name)
        self.buf += struct.pack("!HH", qtype, 0x8001 if unicast else 1)
        self.qd += 1

    def record(self, name: str, rtype: int, ttl: int, rdata, flush: bool = False) -> None:
        self.name(name)
        self.buf += struct.pack("!HHIH", rtype, 0x8001 if flush else 1, ttl, 0)
        start = len(self.buf)
        rdata(self)
        struct.pack_into("!H", self.buf, start - 2, len(self.buf) - start)
        self.an += 1

    def wire(self) -> bytes:
        struct.pack_into("!HHHHHH", self.buf, 0, 0, self.flags, self.qd, self.an, 0, 0)
        return bytes(self.buf)


def rd_name(target: str):
    return lambda m: m.name(target)


def rd_raw(data: bytes):
    return lambda m: m.buf.extend(data)


def rd_srv(port: int, target: str):
    def write(m: Msg) -> None:
        m.buf += struct.pack("!HHH", 0, 0, port)
        m.name(target)

    return write


def txt(pairs) -> bytes:
    return b"".join(bytes([len(s)]) + s for s in (f"{k}={v}".encode() for k, v in pairs))


def pack(flags: int, questions=(), answers=()) -> list[bytes]:
    """Split into <=1460-byte messages like python-zeroconf; TC set when more follow."""

    def build(qs, ans, more):
        m = Msg(flags | (0x0200 if more else 0))
        for q in qs:
            m.question(*q)
        for r in ans:
            m.record(*r)
        return m.wire()

    out, qs, ans = [], [], []
    for is_q, item in [(True, q) for q in questions] + [(False, r) for r in answers]:
        nq, na = (qs + [item], ans) if is_q else (qs, ans + [item])
        if (qs or ans) and len(build(nq, na, False)) > MAX_MSG:
            out.append(build(qs, ans, True))
            qs, ans = ([item], []) if is_q else ([], [item])
        else:
            qs, ans = nq, na
    out.append(build(qs, ans, False))
    return out


# --- simulated devices -----------------------------------------------------


class Names:
    def __init__(self, real: bool):
        self.esp = "_esphomelib._tcp.local." if real else "_simtest-esphome._tcp.local."
        self.ha = "_home-assistant._tcp.local." if real else "_simtest-hass._tcp.local."


def esp_records(i: int, n: Names) -> list[tuple]:
    rng = random.Random(i)
    host = f"simtest-esp-{i:03d}"
    inst, target = f"{host}.{n.esp}", f"{host}.local."
    meta = txt([
        ("friendly_name", f"Group {i // 2 + 1:03d} Sensor {i % 2 + 1}"),
        ("version", "2025.9.3"),
        ("mac", "".join(f"{rng.randrange(256):02X}" for _ in range(6))),
        ("platform", "ESP32"),
        ("board", "esp32dev"),
        ("network", "wifi"),
        ("api_encryption", "Noise_NNpsk0_25519_ChaChaPoly_SHA256"),
    ])
    ip = bytes([192, 0, 2, i % 254 + 1])  # TEST-NET-1, nothing answers there
    return [
        (n.esp, T_PTR, 4500, rd_name(inst)),
        (inst, T_SRV, 120, rd_srv(6053, target), True),
        (inst, T_TXT, 4500, rd_raw(meta), True),
        (target, T_A, 120, rd_raw(ip), True),
    ]


def ha_records(h: int, n: Names) -> list[tuple]:
    rng = random.Random(10_000 + h)
    host = f"simtest-hass-{h:03d}"
    inst, target = f"{host}.{n.ha}", f"{host}.local."
    url = f"http://192.0.2.{h % 254 + 1}:8123"
    meta = txt([
        ("location_name", f"Group {h + 1:03d}"),
        ("uuid", f"{rng.getrandbits(128):032x}"),
        ("version", "2025.10.2"),
        ("external_url", ""),
        ("internal_url", url),
        ("base_url", url),
        ("requires_api_password", "True"),
    ])
    return [
        (n.ha, T_PTR, 4500, rd_name(inst)),
        (inst, T_SRV, 120, rd_srv(8123, target), True),
        (inst, T_TXT, 4500, rd_raw(meta), True),
        (target, T_A, 120, rd_raw(bytes([192, 0, 2, h % 254 + 1])), True),
    ]


def browse_types(count: int, n: Names) -> list[str]:
    rng = random.Random(0)
    types = [n.esp]
    while len(types) < count:
        types.append(f"_sim{len(types):03d}{'x' * rng.randint(0, 10)}._tcp.local.")
    return types


# --- measurement -----------------------------------------------------------


class Window:
    def __init__(self):
        self.kinds: Counter = Counter()
        self.srcs: Counter = Counter()
        self.errors: Counter = Counter()
        self.pkts = self.bytes = 0
        self.air1 = self.air = self.lag = 0.0


class Meter:
    def __init__(self, rate: float):
        self.rate = rate
        self.w = Window()

    def add(self, kind: str, size: int, src: str | None = None) -> None:
        w = self.w
        w.kinds[kind] += 1
        w.pkts += 1
        w.bytes += size
        w.air1 += airtime_us(size + UDP_OVER_WIFI, 1.0)
        w.air += airtime_us(size + UDP_OVER_WIFI, self.rate)
        if src:
            w.srcs[src] += 1

    def take(self) -> Window:
        w, self.w = self.w, Window()
        return w


class Pinger:
    RTT = re.compile(r"time[=<]([\d.]+) ?ms")
    LOST = re.compile(r"Request timeout|no answer yet")

    def __init__(self, host: str, interval: float):
        cmd = ["ping", "-i", str(interval), host]
        if sys.platform.startswith("linux"):
            cmd.insert(1, "-O")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.lock = threading.Lock()
        self.rtts: list[float] = []
        self.lost = 0
        self.other: list[str] = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for line in self.proc.stdout:
            with self.lock:
                if m := self.RTT.search(line):
                    self.rtts.append(float(m.group(1)))
                elif self.LOST.search(line):
                    self.lost += 1
                elif not line.startswith("PING"):
                    self.other.append(line.strip())

    def take(self) -> tuple[list[float], int]:
        with self.lock:
            out = (self.rtts, self.lost)
            self.rtts, self.lost = [], 0
            if self.proc.poll() is not None and self.other:
                print("ping exited:", " | ".join(self.other), file=sys.stderr)
                self.other = []
        return out

    def stop(self) -> None:
        self.proc.terminate()


def pct(xs: list[float], p: float) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, int(p * len(s)))]


def fmt_ping(rtts: list[float], lost: int) -> str:
    sent = len(rtts) + lost
    if not sent:
        return f"{'-':>4} {'-':>5} {'-':>17}"
    loss = 100 * lost / sent
    if not rtts:
        return f"{sent:4d} {loss:4.0f}% {'-':>17}"
    return f"{sent:4d} {loss:4.0f}% {pct(rtts, .5):5.1f}/{pct(rtts, .95):5.1f}/{max(rtts):5.1f}"


class Report:
    def __init__(self, a, meter: Meter, pinger: Pinger | None, show_srcs: bool):
        self.every, self.aps, self.meter, self.pinger, self.show_srcs = a.report, a.aps_same_channel, meter, pinger, show_srcs
        self.start = self.last = time.monotonic()
        self.next = self.start + self.every
        self.label = ""
        self.pkts = self.bytes = 0
        self.peak1 = self.peak = 0.0
        self.rtts: list[float] = []
        self.lost = 0
        print(f"{'time':>7} {'step':>8} {'pps':>6} {'kbps':>7} {'air@1M':>7} {f'air@{meter.rate:g}M':>8} | "
              f"{'ping':>4} {'loss':>5} {'p50/p95/max ms':>17} | per second by kind")

    def tick(self, now: float, force: bool = False) -> None:
        if now < self.next and not force:
            return
        w = self.meter.take()
        self.pkts += w.pkts
        self.bytes += w.bytes
        rtts, lost = self.pinger.take() if self.pinger else ([], 0)
        self.rtts += rtts
        self.lost += lost
        if now - self.last < 0.5:
            self.last = now  # sliver after a forced tick: in the totals, not worth a row
            return
        dt = now - self.last
        scale = self.aps * 100 / (dt * 1e6)
        air1, air = w.air1 * scale, w.air * scale
        self.peak1, self.peak = max(self.peak1, air1), max(self.peak, air)
        ping = fmt_ping(rtts, lost) if self.pinger else ""
        extra = " ".join(f"{k}={v / dt:.0f}" for k, v in w.kinds.most_common(4))
        if self.show_srcs and w.srcs:
            top, cnt = w.srcs.most_common(1)[0]
            extra += f" srcs={len(w.srcs)} top={top}@{cnt / dt:.0f}"
        if w.lag > 0.2:
            extra += f" LAG={w.lag:.1f}s"
        if w.errors:
            extra += " ERR " + " ".join(f"{k}x{v}" for k, v in w.errors.items())
        print(f"{now - self.start:6.0f}s {self.label:>8} {w.pkts / dt:6.0f} {w.bytes * 8 / dt / 1000:7.0f} "
              f"{air1:6.1f}% {air:7.1f}% | {ping:>28} | {extra}", flush=True)
        self.last, self.next = now, now + self.every

    def summary(self) -> None:
        self.tick(time.monotonic(), force=True)
        dur = time.monotonic() - self.start
        print(f"\n{dur:.0f}s: {self.pkts} pkts, {self.bytes / 1e6:.2f} MB, avg {self.pkts / dur:.0f} pps; "
              f"peak airtime {self.peak1:.1f}% @1M, {self.peak:.1f}% @{self.meter.rate:g}M "
              f"(x{self.aps} APs on channel)")
        if self.pinger:
            print("ping overall:", fmt_ping(self.rtts, self.lost).strip())


# --- sending ---------------------------------------------------------------


class Tx:
    def __init__(self, iface_ip: str, loop: bool, meter: Meter):
        self.meter = meter
        self.mdns = self._sock(iface_ip, loop, 255)
        try:
            self.mdns.bind(("", 5353))  # real mDNS speakers send from 5353; others get legacy unicast replies
            self.legacy = False
        except OSError:
            self.mdns.bind((iface_ip, 0))
            self.legacy = True
        self.ssdp = self._sock(iface_ip, loop, 2)
        self.ssdp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.ssdp.bind((iface_ip, 0))

    @staticmethod
    def _sock(iface_ip: str, loop: bool, ttl: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", ttl))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, struct.pack("B", int(loop)))
        return s

    def send(self, kind: str, data: bytes, dst: tuple[str, int]) -> None:
        sock = self.ssdp if dst[1] == 1900 else self.mdns
        try:
            sock.sendto(data, dst)
        except OSError as e:
            self.meter.w.errors[f"{kind}:{e.strerror}"] += 1
            return
        self.meter.add(kind, len(data))


class Clock:
    def __init__(self):
        self.heap: list = []
        self.seq = itertools.count()

    def at(self, t: float, fn, *args) -> None:
        heapq.heappush(self.heap, (t, next(self.seq), fn, args))

    def run(self, report: Report, end: float) -> None:
        while True:
            now = time.monotonic()
            report.tick(now)
            if now >= end:
                return
            if self.heap and self.heap[0][0] <= now:
                t, _, fn, args = heapq.heappop(self.heap)
                report.meter.w.lag = max(report.meter.w.lag, now - t)
                fn(*args)
                continue
            nxt = min(self.heap[0][0] if self.heap else end, report.next, end)
            time.sleep(max(0.0, nxt - now))


def run_sim(a, tx: Tx, report: Report, end: float) -> None:
    rng = random.Random(a.seed)
    n = Names(a.real_names)
    types = browse_types(a.ha_types, n)
    known = [esp_records(i, n)[0] for i in range(a.esp)]
    # python-zeroconf: 4 startup rounds at +0, +1, +5, +14 s; round 0 asks for unicast (QU) replies,
    # rounds 2-3 carry the ESPHome PTRs learned in round 1 as known answers.
    browse = [
        pack(0, [(t, T_PTR, True) for t in types]),
        pack(0, [(t, T_PTR) for t in types]),
        pack(0, [(t, T_PTR) for t in types], known),
        pack(0, [(t, T_PTR) for t in types], known),
    ]
    esp_pkt = [pack(0x8400, answers=esp_records(i, n))[0] for i in range(a.esp)]
    ha_probe = [pack(0, [(f"simtest-hass-{h:03d}.{n.ha}", T_ANY, True)])[0] for h in range(a.ha)]
    ha_ann = [pack(0x8400, answers=ha_records(h, n))[0] for h in range(a.ha)]
    copies = 2 if a.ha_ipv6 else 1
    print(f"model: {a.ha} HA x {a.ha_types} browse types, {a.esp} ESPHome; HA restart mean "
          f"{a.restart_mean or 'off'} s, cold start over {a.stagger or 'off'} s; HA mDNS sent x{copies}")
    print(f"  browse rounds {[len(p) for p in browse]} pkts / {[sum(map(len, p)) for p in browse]} B, "
          f"ESP answer {len(esp_pkt[0])} B, HA announce {len(ha_ann[0])} B")

    clock = Clock()
    gen = [0] * a.ha
    last_answer = [-1e9] * a.esp

    def ha_mdns(kind: str, pkts: list[bytes]) -> None:
        for p in pkts:
            for _ in range(copies):
                tx.send(kind, p, MDNS)

    def esp_answer(d: int, kind: str) -> None:
        tx.send(kind, esp_pkt[d], MDNS)

    def ha_event(h: int, g: int, what: str, k: int = 0) -> None:
        if gen[h] != g:
            return  # instance restarted since this was scheduled
        now = time.monotonic()
        if what == "probe":
            ha_mdns("ha-probe", [ha_probe[h]])
        elif what == "announce":
            ha_mdns("ha-announce", [ha_ann[h]])
        elif what == "browse":
            ha_mdns("ha-query", browse[k])
            if k == 1:
                for d in range(a.esp):
                    if now - last_answer[d] >= 1.0:  # RFC 6762 s6: one multicast per record per second
                        t = now + rng.uniform(0.02, 0.12)
                        last_answer[d] = t
                        clock.at(t, esp_answer, d, "esp-answer")
        elif what == "ssdp":
            tx.send("ssdp", MSEARCH, SSDP)
            tx.send("ssdp", MSEARCH, BCAST)
            clock.at(now + 600, ha_event, h, g, "ssdp")

    def ha_restart(h: int) -> None:
        gen[h] += 1
        g, now = gen[h], time.monotonic()
        for dt in (0, 0.25, 0.5):
            clock.at(now + dt, ha_event, h, g, "probe")
        for dt in (0.75, 0.975, 1.2):
            clock.at(now + dt, ha_event, h, g, "announce")
        first = now + rng.uniform(0.02, 0.12)
        for k, dt in enumerate((0, 1, 5, 14)):
            clock.at(first + dt, ha_event, h, g, "browse", k)
        if a.ssdp:
            clock.at(first, ha_event, h, g, "ssdp")
        if a.restart_mean > 0:
            clock.at(now + rng.expovariate(1 / a.restart_mean), ha_restart, h)

    def esp_reconnect(d: int) -> None:
        now = time.monotonic()
        last_answer[d] = now
        esp_answer(d, "esp-announce")
        clock.at(now + 1, esp_answer, d, "esp-announce")
        clock.at(now + rng.expovariate(1 / a.esp_reconnect_mean), esp_reconnect, d)

    t0 = time.monotonic()
    for h in range(a.ha):
        if a.stagger > 0:
            clock.at(t0 + rng.uniform(0, a.stagger), ha_restart, h)
        elif a.restart_mean > 0:
            clock.at(t0 + rng.expovariate(1 / a.restart_mean), ha_restart, h)
    if a.esp_reconnect_mean > 0:
        for d in range(a.esp):
            clock.at(t0 + rng.expovariate(1 / a.esp_reconnect_mean), esp_reconnect, d)
    clock.run(report, end)


def flood_packet(dst: str, size: int, n: Names) -> bytes:
    if dst == "mdns":
        recs = esp_records(0, n)
        m = Msg(0x8400)
        for r in recs:
            m.record(*r)
        extra = size - len(m.buf) - 12  # one more TXT record with a compressed owner name
        chunks = []
        while extra > 1:
            k = min(255, extra - 1)
            chunks.append(b"x" * k)
            extra -= k + 1
        if chunks:
            m.record(recs[1][0], T_TXT, 4500, rd_raw(b"".join(bytes([len(c)]) + c for c in chunks)), True)
        return m.wire()
    head = MSEARCH[:-2]
    pad = max(0, size - len(head) - len(b"X-PAD: \r\n\r\n"))
    return head + b"X-PAD: " + b"x" * pad + b"\r\n\r\n"


def run_flood(a, tx: Tx, report: Report, end: float) -> None:
    pkt = flood_packet(a.dst, a.size, Names(a.real_names))
    dst = {"mdns": MDNS, "ssdp": SSDP, "broadcast": BCAST}[a.dst]
    steps = [int(x) for x in a.ramp.split(",")] if a.ramp else [a.pps]
    print(f"flood: {len(pkt)} B UDP payload -> {dst[0]}:{dst[1]}, steps {steps} pps"
          + (f", {a.step:g} s each" if a.ramp else ""))
    for pps in steps:
        pps = min(pps, a.max_pps)
        report.label = f"{pps}pps"
        step_end = min(end, time.monotonic() + a.step) if a.ramp else end
        gap = 1 / pps if pps else math.inf
        due = time.monotonic() if pps else math.inf
        while (now := time.monotonic()) < step_end:
            report.tick(now)
            if now >= due:
                tx.send("flood", pkt, dst)
                due += gap
                if now - due > 0.5:
                    due = now  # sender stalled (e.g. ENOBUFS); don't burst to catch up
            else:
                time.sleep(max(0.0, min(due, report.next, step_end) - now))
        report.tick(time.monotonic(), force=True)  # one row per step ends at the step boundary
        if step_end >= end:
            return


def run_listen(a, meter: Meter, report: Report, end: float) -> None:
    sel = selectors.DefaultSelector()
    for group, port, kind in ((MDNS[0], 5353, "mdns"), (SSDP[0], 1900, "ssdp/bcast")):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(("", port))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group) + socket.inet_aton(a.iface_ip))
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, kind)
    while (now := time.monotonic()) < end:
        report.tick(now)
        for key, _ in sel.select(timeout=max(0.0, min(report.next, end) - now)):
            while True:
                try:
                    data, src = key.fileobj.recvfrom(9000)
                except BlockingIOError:
                    break
                meter.add(key.data, len(data), src[0])


def route_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(MDNS)
        return s.getsockname()[0]


def main() -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--iface-ip", help="local IPv4 on the VLAN under test (default: source address toward 224.0.0.251)")
    common.add_argument("--duration", type=float, default=0, help="seconds, 0 = until Ctrl-C (default 0)")
    common.add_argument("--report", type=float, default=5, help="report interval seconds (default 5)")
    common.add_argument("--basic-rate", type=float, default=12, help="Mbps for the second airtime column (default 12)")
    common.add_argument("--aps-same-channel", type=int, default=1,
                        help="APs on one channel that each re-broadcast this VLAN (multiplies airtime, default 1)")
    common.add_argument("--ssids-per-radio", type=int, default=0, help="print beacon airtime for this many SSIDs per radio")
    common.add_argument("--beacon-bytes", type=int, default=300, help="beacon frame size for --ssids-per-radio (default 300)")
    common.add_argument("--ping", metavar="HOST", help="run ping alongside and report loss/latency per interval")
    common.add_argument("--ping-interval", type=float, default=0.2, help="seconds; short interval keeps macOS Wi-Fi awake (default 0.2)")
    common.add_argument("--real-names", action="store_true",
                        help="use _esphomelib._tcp / _home-assistant._tcp so real HA and ESPHome react; "
                             "real HA will list the fake simtest-esp-* devices as discovered")
    common.add_argument("--loop", action="store_true", help="deliver own multicast locally (loopback tests)")
    common.add_argument("--seed", type=int, default=1)

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("sim", parents=[common], help="model Home Assistant + ESPHome discovery traffic")
    s.add_argument("--ha", type=int, default=33, help="Home Assistant instances on this VLAN (default 33)")
    s.add_argument("--esp", type=int, default=66, help="ESPHome devices on this VLAN (default 66)")
    s.add_argument("--ha-types", type=int, default=110, help="zeroconf service types each HA browses (default 110)")
    s.add_argument("--restart-mean", type=float, default=180, help="mean seconds between restarts per HA, 0 = never (default 180)")
    s.add_argument("--stagger", type=float, default=60, help="cold start: all HA boot within this many seconds, 0 = skip (default 60)")
    s.add_argument("--esp-reconnect-mean", type=float, default=0, help="mean seconds between Wi-Fi reconnects per ESP, 0 = never")
    s.add_argument("--no-ha-ipv6", dest="ha_ipv6", action="store_false",
                   help="HA mDNS once per packet instead of twice (default doubles it, emulating the IPv6 copy)")
    s.add_argument("--no-ssdp", dest="ssdp", action="store_false", help="skip SSDP M-SEARCH (multicast + 255.255.255.255)")
    f = sub.add_parser("flood", parents=[common], help="fixed or stepped multicast rate")
    f.add_argument("--pps", type=int, default=100, help="packets per second (default 100)")
    f.add_argument("--size", type=int, default=400, help="UDP payload bytes, 100-1400 (default 400)")
    f.add_argument("--dst", choices=("mdns", "ssdp", "broadcast"), default="mdns")
    f.add_argument("--ramp", help="comma list of pps steps, e.g. 0,25,50,100,200,400")
    f.add_argument("--step", type=float, default=30, help="seconds per ramp step (default 30)")
    f.add_argument("--max-pps", type=int, default=3000, help="hard cap (default 3000)")
    sub.add_parser("listen", parents=[common], help="count multicast/broadcast arriving here")
    a = p.parse_args()
    if a.mode == "flood" and not 100 <= a.size <= 1400:
        p.error("--size must be 100-1400")

    a.iface_ip = a.iface_ip or route_ip()
    meter = Meter(a.basic_rate)
    print(f"{a.mode} on {a.iface_ip}")
    if a.ssids_per_radio:
        load = [airtime_us(a.beacon_bytes, r) * BEACONS_PER_S / 1e4 * a.ssids_per_radio * a.aps_same_channel
                for r in (1.0, a.basic_rate)]
        print(f"beacons alone: {load[0]:.1f}% @1M, {load[1]:.1f}% @{a.basic_rate:g}M "
              f"({a.ssids_per_radio} SSIDs x {a.aps_same_channel} APs, {a.beacon_bytes} B)")
    tx = None
    if a.mode != "listen":
        tx = Tx(a.iface_ip, a.loop, meter)
        if tx.legacy:
            print("warning: UDP 5353 busy; sending from an ephemeral port, so real responders reply unicast")
    pinger = Pinger(a.ping, a.ping_interval) if a.ping else None
    report = Report(a, meter, pinger, show_srcs=a.mode == "listen")
    end = time.monotonic() + a.duration if a.duration else math.inf
    try:
        if a.mode == "sim":
            run_sim(a, tx, report, end)
        elif a.mode == "flood":
            run_flood(a, tx, report, end)
        else:
            run_listen(a, meter, report, end)
    except KeyboardInterrupt:
        pass
    finally:
        if pinger:
            pinger.stop()
        report.summary()


if __name__ == "__main__":
    main()

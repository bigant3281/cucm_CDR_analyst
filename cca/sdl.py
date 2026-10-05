"""Extract SIP messages from Cisco CallManager SDL trace files.

SDL lines look like:
  00123456.001 |10:15:22.123 |AppInfo  |SIPTcp - wait_SdlReadRsp: Incoming SIP TCP message from 10.1.1.20 on port 5060 index 12 with 1234 bytes:
  [5678,NET]
  INVITE sip:2001@10.1.1.10:5060 SIP/2.0
  ...
and for UDP:
  ... |SIPUdp - wait_SdlReadRsp: Incoming SIP UDP message size 812 from 10.1.1.20:[5060]:
  ... |SIPUdp - wait_SdlSPISignal: Outgoing SIP UDP message to 10.1.1.20:[5060]:

Lines only carry a time of day in the server's local timezone, so each file
is dated from an anchor (the file's modified time): a line later than the
anchor time belongs to the previous day.
"""
from __future__ import annotations

import gzip
import io
import re
import zipfile
from datetime import datetime, time, timedelta, timezone, tzinfo

LINE_RE = re.compile(r"^(?:\d{8}\.\d{3} )?\|?\s*(?:(\d{2}/\d{2}/\d{4}) )?(\d{2}):(\d{2}):(\d{2})\.(\d{3})\s*\|")
SIP_HDR_RE = re.compile(
    r"(Incoming|Outgoing) SIP (TCP|UDP|TLS) message(?: size \d+)?\s+(?:from|to)\s+"
    r"\[?([0-9a-fA-F\.:]+?)\]?(?:\s+on port\s+|:\[|:)(\d+)", re.I)
TAG_LINE_RE = re.compile(r"^\[\d+,\w+\]\s*$")
SIP_START_RE = re.compile(r"^(?:[A-Z]+ \S+ SIP/2\.0|SIP/2\.0 \d{3})")

US_TZ = {"EST": -5, "EDT": -4, "CST": -6, "CDT": -5, "MST": -7, "MDT": -6, "PST": -8, "PDT": -7,
         "AKST": -9, "AKDT": -8, "HST": -10, "UTC": 0, "GMT": 0, "BST": 1, "CET": 1, "CEST": 2,
         "IST": 5.5, "AEST": 10, "AEDT": 11, "JST": 9, "SGT": 8}


def parse_modified(s: str, fallback_tz: tzinfo) -> datetime | None:
    """'Fri Jul 22 15:11:52 PDT 2022' -> aware datetime."""
    m = re.match(r"\w{3} (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) (\d{4})", (s or "").strip())
    if not m:
        return None
    mon, day, hh, mm, ss, tzs, yr = m.groups()
    dt = datetime.strptime(f"{mon} {day} {yr} {hh}:{mm}:{ss}", "%b %d %Y %H:%M:%S")
    if tzs in US_TZ:
        return dt.replace(tzinfo=timezone(timedelta(hours=US_TZ[tzs])))
    return dt.replace(tzinfo=fallback_tz)


def read_maybe_gz(name: str, data: bytes) -> str:
    if name.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8", "replace")


def iter_archive(name: str, data: bytes):
    """Yield (member_name, bytes, mtime|None) for a zip (RTMT collection) or a single file."""
    if name.lower().endswith(".zip") or data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                mt = datetime(*info.date_time)
                yield info.filename, z.read(info), mt
    else:
        yield name, data, None


def node_from_path(path: str) -> str:
    """RTMT collections look like <node>/cm/trace/ccm/sdl/SDL001_100_000123.txt.gz"""
    parts = [p for p in re.split(r"[\\/]", path) if p]
    for i, p in enumerate(parts):
        if p == "cm" and i > 0:
            return parts[i - 1]
    return ""


def parse_sdl_text(text: str, anchor: datetime, node: str = "", source: str = "") -> list[dict]:
    """Return SIP message dicts: ts (UTC), node, direction, transport, remote_ip,
    remote_port, raw, line_no, source."""
    lines = text.splitlines()
    out = []
    a_local = anchor
    a_date = a_local.date()
    tz = a_local.tzinfo
    i, n = 0, len(lines)
    while i < n:
        ln = lines[i]
        hm = SIP_HDR_RE.search(ln)
        lm = LINE_RE.match(ln) if hm else None
        if not hm or not lm:
            i += 1
            continue
        date_s, hh, mi, ss, ms = lm.groups()
        t = time(int(hh), int(mi), int(ss), int(ms) * 1000)
        if date_s:
            d = datetime.strptime(date_s, "%m/%d/%Y").date()
            ts = datetime.combine(d, t, tz)
        else:
            ts = datetime.combine(a_date, t, tz)
            if ts > a_local + timedelta(minutes=5):
                ts -= timedelta(days=1)
        direction = "in" if hm.group(1).lower() == "incoming" else "out"
        body: list[str] = []
        j = i + 1
        # skip the [nnnn,NET] tag and anything before the start line
        while j < n and not LINE_RE.match(lines[j]) and not SIP_START_RE.match(lines[j].strip()):
            j += 1
        while j < n and not LINE_RE.match(lines[j]):
            if not TAG_LINE_RE.match(lines[j]):
                body.append(lines[j].rstrip("\r"))
            j += 1
        while body and not body[-1].strip():
            body.pop()
        raw = "\n".join(body)
        if SIP_START_RE.match(raw):
            out.append({"ts": ts.astimezone(timezone.utc), "node": node, "direction": direction,
                        "transport": hm.group(2).upper(), "remote_ip": hm.group(3),
                        "remote_port": int(hm.group(4)), "raw": raw, "line_no": i + 1,
                        "source": source})
        i = j
    return out

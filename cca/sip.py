"""SIP message + SDP parsing (enough for ladders and call analysis)."""
from __future__ import annotations

import re

COMPACT = {"i": "call-id", "f": "from", "t": "to", "v": "via", "m": "contact", "l": "content-length",
           "c": "content-type", "k": "supported", "s": "subject", "e": "content-encoding",
           "o": "event", "r": "refer-to", "b": "referred-by", "x": "session-expires", "u": "allow-events"}

REQ_RE = re.compile(r"^([A-Z]+) (\S+) SIP/2\.0\s*$")
RESP_RE = re.compile(r"^SIP/2\.0 (\d{3})(?: (.*))?$")
USER_RE = re.compile(r"<?(?:sips?|tel):([^@;>]+)", re.I)
TAG_RE = re.compile(r";\s*tag=([^;>\s]+)", re.I)
BRANCH_RE = re.compile(r";\s*branch=([^;\s,]+)", re.I)
DEVNAME_RE = re.compile(r'devicename\.ccm\.cisco\.com="?([^";>]+)', re.I)
VIA_HOST_RE = re.compile(r"SIP/2\.0/\w+\s+\[?([0-9a-fA-F\.:]+?)\]?(?::(\d+))?(?:;|\s|$)")


def _user(v: str) -> str:
    m = USER_RE.search(v or "")
    return m.group(1) if m else ""


def digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def parse_sdp(body: str) -> dict | None:
    if not body or "v=0" not in body:
        return None
    sess = {"c": "", "dir": "", "o": "", "media": []}
    cur = None
    for raw in body.splitlines():
        line = raw.strip()
        if len(line) < 2 or line[1] != "=":
            continue
        k, v = line[0], line[2:]
        if k == "o" and cur is None:
            sess["o"] = v
        elif k == "c":
            ip = v.split()[-1] if v.split() else ""
            (cur if cur is not None else sess)["c"] = ip
        elif k == "m":
            parts = v.split()
            cur = {"type": parts[0] if parts else "", "port": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                   "proto": parts[2] if len(parts) > 2 else "", "fmts": parts[3:], "rtpmap": {},
                   "dir": "", "c": "", "crypto": False, "ptime": ""}
            sess["media"].append(cur)
        elif k == "a":
            name, _, val = v.partition(":")
            if name in ("sendrecv", "sendonly", "recvonly", "inactive"):
                (cur if cur is not None else sess)["dir"] = name
            elif name == "rtpmap" and cur is not None:
                pt, _, enc = val.partition(" ")
                cur["rtpmap"][pt] = enc
            elif name == "crypto" and cur is not None:
                cur["crypto"] = True
            elif name == "ptime" and cur is not None:
                cur["ptime"] = val
    for m in sess["media"]:
        m["c"] = m["c"] or sess["c"]
        m["dir"] = m["dir"] or sess["dir"] or "sendrecv"
        names = []
        for f in m["fmts"]:
            enc = m["rtpmap"].get(f) or {"0": "PCMU/8000", "8": "PCMA/8000", "9": "G722/8000",
                                         "18": "G729/8000", "4": "G723/8000", "13": "CN/8000"}.get(f, f)
            names.append(enc.split("/")[0])
        m["codecs"] = names
    return sess


def sdp_summary(sdp: dict | None) -> str:
    if not sdp:
        return ""
    out = []
    for m in sdp["media"]:
        if m["type"] != "audio" and m["port"] == 0:
            continue
        codecs = [c for c in m["codecs"] if c.lower() not in ("telephone-event", "cn")]
        bits = [m["type"], "/".join(codecs[:3]) or "-"]
        if "telephone-event" in [c.lower() for c in m["codecs"]]:
            bits.append("2833")
        if m["dir"] != "sendrecv":
            bits.append(m["dir"])
        if m["c"] in ("0.0.0.0", "::") or m["port"] == 0:
            bits.append("hold/disabled")
        if m["crypto"] or "SAVP" in m["proto"]:
            bits.append("SRTP")
        out.append(" ".join(bits))
    return "; ".join(out)


def parse_sip(raw: str) -> dict:
    text = raw.replace("\r\n", "\n")
    head, sep, body = text.partition("\n\n")
    lines = head.split("\n")
    first = lines[0].strip() if lines else ""
    msg = {"first_line": first, "is_request": False, "method": "", "ruri": "", "status": 0,
           "reason_phrase": "", "headers": [], "body": body if sep else ""}
    m = REQ_RE.match(first)
    if m:
        msg.update(is_request=True, method=m.group(1), ruri=m.group(2))
    else:
        m = RESP_RE.match(first)
        if m:
            msg.update(status=int(m.group(1)), reason_phrase=(m.group(2) or "").strip())
    hdrs: list[tuple[str, str]] = []
    for ln in lines[1:]:
        if ln[:1] in (" ", "\t") and hdrs:  # folded header
            hdrs[-1] = (hdrs[-1][0], hdrs[-1][1] + " " + ln.strip())
            continue
        name, colon, val = ln.partition(":")
        if not colon:
            continue
        hdrs.append((name.strip(), val.strip()))
    msg["headers"] = hdrs

    def h(name: str) -> str:
        n = name.lower()
        for k, v in hdrs:
            kl = k.lower()
            if kl == n or COMPACT.get(kl) == n:
                return v
        return ""

    def h_all(name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in hdrs if k.lower() == n or COMPACT.get(k.lower()) == n]

    cseq = h("cseq").split()
    vias = h_all("via")
    top_via = vias[0] if vias else ""
    vm = VIA_HOST_RE.search(top_via)
    msg.update(
        call_id=h("call-id"),
        cseq_num=int(cseq[0]) if cseq and cseq[0].isdigit() else 0,
        cseq_method=cseq[1] if len(cseq) > 1 else "",
        from_=h("from"), to=h("to"),
        from_user=_user(h("from")), to_user=_user(h("to")),
        from_tag=(TAG_RE.search(h("from")) or [None, ""])[1],
        to_tag=(TAG_RE.search(h("to")) or [None, ""])[1],
        ruri_user=_user(msg["ruri"]),
        pai_user=_user(h("p-asserted-identity")),
        diversion_user=_user(h("diversion")),
        via_branch=(BRANCH_RE.search(top_via) or [None, ""])[1],
        via_host=vm.group(1) if vm else "",
        contact=h("contact"),
        device_name=(DEVNAME_RE.search(h("contact")) or [None, ""])[1],
        user_agent=h("user-agent") or h("server"),
        reason=h("reason"), warning=h("warning"),
        replaces=h("replaces"), refer_to=h("refer-to"),
        content_type=h("content-type"),
    )
    msg["sdp"] = parse_sdp(msg["body"]) if "sdp" in msg["content_type"].lower() or "v=0" in msg["body"][:20] else None
    if msg["sdp"] is None and "multipart" in msg["content_type"].lower() and "v=0" in msg["body"]:
        msg["sdp"] = parse_sdp(msg["body"][msg["body"].index("v=0"):])
    msg["label"] = label(msg)
    return msg


def label(msg: dict) -> str:
    if msg["is_request"]:
        s = msg["method"]
    elif msg["status"]:
        s = f"{msg['status']} {msg['reason_phrase']}".strip()
    else:
        s = msg["first_line"][:40]
    if msg.get("sdp"):
        s += " (SDP)"
    return s


def numbers_in(msg: dict) -> set[str]:
    return {digits(x) for x in (msg["from_user"], msg["to_user"], msg["ruri_user"],
                                msg["pai_user"], msg["diversion_user"]) if digits(x)}


def num_match(a: str, b: str, min_len: int = 4) -> bool:
    a, b = digits(a), digits(b)
    if not a or not b:
        return False
    if a == b:
        return True
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    return len(short) >= min_len and long_.endswith(short)


def q850_from_reason(reason: str) -> int | None:
    m = re.search(r"Q\.850\s*;\s*cause\s*=\s*(\d+)", reason or "", re.I)
    return int(m.group(1)) if m else None

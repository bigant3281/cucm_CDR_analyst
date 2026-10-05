"""Tie SIP dialogs from SDL traces to a CDR call and build the ladder model.

Matching (per SIP Call-ID found in the call's time window):
  * strong  - Call-ID equals the CDR's Incoming/OutgoingProtocolCallRef (SIP trunks)
  * strong  - Contact devicename (SIP phones) is a device in the CDR, close to a leg start
  * strong  - initial INVITE carries both a calling and a called number of the call
  * weak    - initial INVITE carries one of the call's numbers, close to a leg start
  * weak    - signaling IP of a CDR device, close to a leg start
Dialogs referenced by Replaces / Refer-To from a selected dialog are pulled in.
Score >= 2 is selected by default; weaker candidates are listed but unchecked.
"""
from __future__ import annotations

import re
from collections import defaultdict

from . import cdr as C
from .sip import digits, num_match, numbers_in, parse_sip, sdp_summary

PALETTE_SIZE = 8


def _call_numbers(cdrs: list[dict]) -> tuple[set[str], set[str]]:
    calling, called = set(), set()
    for r in cdrs:
        for f in ("callingPartyNumber", "outpulsedCallingPartyNumber", "callingPartyNumber_uri"):
            v = digits(C.ci_get(r, f).split("@")[0])
            if v:
                calling.add(v)
        for f in ("originalCalledPartyNumber", "finalCalledPartyNumber", "lastRedirectDn",
                  "outpulsedCalledPartyNumber", "huntPilotDN", "finalCalledPartyNumber_uri"):
            v = digits(C.ci_get(r, f).split("@")[0])
            if v:
                called.add(v)
    return calling, called


def window(cdrs: list[dict], pad_before: int, pad_after: int) -> tuple[float, float]:
    starts = [C.to_int(C.ci_get(r, "dateTimeOrigination")) for r in cdrs]
    ends = [max(C.to_int(C.ci_get(r, "dateTimeDisconnect")), C.to_int(C.ci_get(r, "dateTimeConnect")),
                C.to_int(C.ci_get(r, "dateTimeOrigination"))) for r in cdrs]
    starts = [s for s in starts if s] or [0]
    ends = [e for e in ends if e] or starts
    return min(starts) - pad_before, max(ends) + pad_after


def _ua_kind(ua: str, dev: str) -> str:
    u = (ua or "").lower()
    d = (dev or "").upper()
    if d.startswith(("SEP", "CSF", "BOT", "TCT", "TAB", "ATA", "AN")) or "cisco-cp" in u or "cisco-tsp" in u:
        return "phone"
    if "sipgateway" in u or "cube" in u or "ios" in u:
        return "gateway"
    if "cucm" in u or "ccm" in u:
        return "cucm"
    if "cisco-cuc" in u or "unity" in u:
        return "voicemail"
    if "expressway" in u or "tandberg" in u or "vcs" in u:
        return "expressway"
    return "endpoint" if (ua or dev) else "unknown"


def build(cdrs: list[dict], store, node_ips: dict[str, str], pad_before=60, pad_after=60) -> dict:
    start, end = window(cdrs, pad_before, pad_after)
    rows = store.sip_window(start, end)
    calling, called = _call_numbers(cdrs)
    leg_starts = sorted({C.to_int(C.ci_get(r, "dateTimeOrigination")) for r in cdrs} - {0})
    devices = {C.ci_get(r, f).upper() for r in cdrs for f in ("origDeviceName", "destDeviceName")} - {""}
    cdr_ips: dict[str, str] = {}
    for r in cdrs:
        for side in ("orig", "dest"):
            ip, dev = C.cdr_ip(r, side), C.ci_get(r, f"{side}DeviceName")
            if ip and dev:
                cdr_ips[ip] = dev
    refs = set()
    for r in cdrs:
        for p in ("Incoming", "Outgoing"):
            if C.to_int(C.ci_get(r, f"{p}ProtocolID")) == 1 and C.ci_get(r, f"{p}ProtocolCallRef"):
                refs.add(C.ci_get(r, f"{p}ProtocolCallRef").strip())

    def near_leg(ts: float, slack: float = 15) -> bool:
        return any(s - slack <= ts <= s + slack for s in leg_starts)

    # ------------------------------------------------------------ parse + score
    msgs = []
    for r in rows:
        p = parse_sip(r["raw"])
        r["p"] = p
        msgs.append(r)

    # learn node IPs from our own top Via on outgoing requests
    learned = dict(node_ips)
    ip_to_node = {ip: n for n, ip in learned.items() if ip}
    for m in msgs:
        if m["direction"] == "out" and m["p"]["is_request"] and m["p"]["via_host"] and m["node"]:
            if m["node"] not in learned or not learned[m["node"]]:
                learned[m["node"]] = m["p"]["via_host"]
            ip_to_node.setdefault(m["p"]["via_host"], m["node"])

    by_cid: dict[str, list[dict]] = defaultdict(list)
    for m in msgs:
        if m["p"]["call_id"]:
            by_cid[m["p"]["call_id"]].append(m)

    dialogs = {}
    for cid, ms in by_cid.items():
        score, why = 0, []
        base = cid.split("@")[0]
        if any(cid.startswith(ref) or ref.startswith(cid) or base == ref.split("@")[0] for ref in refs):
            score += 3; why.append("Call-ID matches CDR ProtocolCallRef")
        inv = [m for m in ms if m["p"]["method"] == "INVITE" and not m["p"]["to_tag"]]
        first = inv[0] if inv else ms[0]
        nums = set()
        for m in inv or ms[:1]:
            nums |= numbers_in(m["p"])
        hit_calling = any(num_match(a, b) for a in nums for b in calling)
        hit_called = any(num_match(a, b) for a in nums for b in called)
        close = near_leg(first["ts"])
        if hit_calling and hit_called:
            score += 2 if close else 1; why.append("INVITE carries calling and called numbers")
        elif (hit_calling or hit_called) and close:
            score += 1; why.append("INVITE carries " + ("calling" if hit_calling else "called") + " number")
        devs = {m["p"]["device_name"].upper() for m in ms if m["direction"] == "in" and m["p"]["device_name"]}
        if devs & devices and close:
            score += 2; why.append("Contact devicename " + ", ".join(sorted(devs & devices)))
        if close and any(m["remote_ip"] in cdr_ips for m in inv):
            score += 1; why.append("signaling IP of " + ", ".join(sorted({cdr_ips[m['remote_ip']] for m in inv if m['remote_ip'] in cdr_ips})))
        if score:
            dialogs[cid] = {"call_id": cid, "score": score, "why": why}

    # pull in dialogs joined by Replaces / Refer-To
    for _ in range(3):
        added = False
        for cid, ms in by_cid.items():
            if cid in dialogs:
                continue
            for m in ms:
                ref = m["p"]["replaces"] or ""
                rt = m["p"]["refer_to"] or ""
                ref_cid = ref.split(";")[0].strip()
                hit = [d for d in dialogs if d == ref_cid or (d and d in rt.replace("%40", "@"))]
                if hit and dialogs[hit[0]]["score"] >= 2:
                    dialogs[cid] = {"call_id": cid, "score": 2, "why": [f"Replaces/Refer-To dialog {hit[0][:24]}…"]}
                    added = True
                    break
        if not added:
            break

    # ------------------------------------------------------------ messages
    keep = [m for m in msgs if m["p"]["call_id"] in dialogs]
    keep.sort(key=lambda m: (m["ts"], m["id"]))
    # inter-node duplicates: node A 'out' to node B == node B 'in' from node A
    seen_out = {}
    for m in keep:
        p = m["p"]
        if m["direction"] == "out" and m["remote_ip"] in ip_to_node:
            seen_out[(p["call_id"], p["first_line"], p["cseq_num"], p["cseq_method"], ip_to_node[m["remote_ip"]])] = m["ts"]
    deduped = []
    for m in keep:
        p = m["p"]
        if m["direction"] == "in" and m["remote_ip"] in ip_to_node:
            k = (p["call_id"], p["first_line"], p["cseq_num"], p["cseq_method"], m["node"])
            t = seen_out.get(k)
            if t is not None and abs(t - m["ts"]) < 3:
                continue
        deduped.append(m)
    # retransmissions
    last_seen = {}
    for m in deduped:
        p = m["p"]
        k = (m["node"], m["direction"], m["remote_ip"], p["call_id"], p["first_line"], p["cseq_num"],
             p["cseq_method"], p["via_branch"] if p["is_request"] else p["to_tag"])
        prev = last_seen.get(k)
        m["retrans"] = prev is not None and m["ts"] - prev < 33
        last_seen[k] = m["ts"]

    # ------------------------------------------------------------ participants
    parts: dict[str, dict] = {}

    def part(key, **kw):
        if key not in parts:
            parts[key] = {"key": key, "name": "", "ip": "", "port": "", "kind": "", "ua": "", "device": ""}
        for k, v in kw.items():
            if v and not parts[key].get(k):
                parts[key][k] = v
        return key

    out_msgs = []
    cid_order = []
    for m in deduped:
        p = m["p"]
        node_key = part(f"node:{m['node'] or 'CUCM'}", name=m["node"] or "CUCM", kind="cucm-node",
                        ip=learned.get(m["node"], ""))
        if m["remote_ip"] in ip_to_node:
            rk = part(f"node:{ip_to_node[m['remote_ip']]}", name=ip_to_node[m["remote_ip"]],
                      kind="cucm-node", ip=m["remote_ip"])
        else:
            rk = part(f"ip:{m['remote_ip']}", ip=m["remote_ip"], port=str(m["remote_port"]))
            if m["direction"] == "in":
                dev = p["device_name"] or ""
                part(rk, device=dev, ua=p["user_agent"])
            if m["remote_ip"] in cdr_ips:
                part(rk, device=cdr_ips[m["remote_ip"]])
        if p["call_id"] not in cid_order:
            cid_order.append(p["call_id"])
        src, dst = (rk, node_key) if m["direction"] == "in" else (node_key, rk)
        out_msgs.append({
            "id": m["id"], "ts": m["ts"], "node": m["node"], "direction": m["direction"],
            "transport": m["transport"], "remote": f"{m['remote_ip']}:{m['remote_port']}",
            "from": src, "to": dst, "call_id": p["call_id"], "label": p["label"],
            "cseq": f"{p['cseq_num']} {p['cseq_method']}", "is_request": p["is_request"],
            "status": p["status"], "method": p["method"], "sdp": sdp_summary(p["sdp"]),
            "retrans": m["retrans"], "raw": m["raw"], "line_no": m["line_no"],
            "reason": p["reason"], "warning": p["warning"],
        })
    for k, v in parts.items():
        if v["kind"] != "cucm-node":
            v["kind"] = _ua_kind(v["ua"], v["device"])
            v["name"] = v["device"] or _short_ua(v["ua"]) or v["ip"]

    dlist = []
    for i, cid in enumerate(cid_order):
        d = dialogs[cid]
        ms = [m for m in out_msgs if m["call_id"] == cid]
        inv = next((m for m in ms if m["method"] == "INVITE"), None)
        pr = parse_sip(inv["raw"]) if inv else parse_sip(ms[0]["raw"])
        finals = [m for m in ms if not m["is_request"] and m["status"] >= 200 and m["cseq"].endswith("INVITE")]
        dlist.append({**d, "color": i % PALETTE_SIZE, "selected": d["score"] >= 2,
                      "first_ts": ms[0]["ts"], "method": inv["method"] if inv else ms[0]["label"],
                      "from_user": pr["from_user"], "to_user": pr["to_user"] or pr["ruri_user"],
                      "final": finals[0]["label"] if finals else "", "count": len(ms),
                      "path": f"{parts[ms[0]['from']]['name']} → {parts[ms[0]['to']]['name']}"})
    # weaker candidates appear but unchecked; if nothing scored >=2, select the best ones
    if dlist and not any(d["selected"] for d in dlist):
        best = max(d["score"] for d in dlist)
        for d in dlist:
            d["selected"] = d["score"] == best

    return {"window": [start, end], "participants": parts, "messages": out_msgs,
            "dialogs": dlist, "sip_in_window": len(rows), "node_ips": learned,
            "has_traces": bool(rows)}


def _short_ua(ua: str) -> str:
    if not ua:
        return ""
    return re.split(r"\s", ua.strip())[0][:28]

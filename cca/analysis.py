"""Call summary and findings from CDR/CMR + SIP."""
from __future__ import annotations

from . import cdr as C
from .sip import parse_sip, q850_from_reason

SIP_HINTS = {
    400: "Malformed request (often a header/SDP the far end can't parse)",
    401: "Authentication challenge", 403: "Forbidden: check CSS/trunk ACL, calling-number screening or provider rejection",
    404: "Number not found: check digit manipulation, route pattern or far-end dial plan",
    407: "Proxy authentication challenge",
    408: "Request timeout: far end never answered the request (reachability, OPTIONS ping, firewall)",
    415: "Unsupported media type", 480: "Temporarily unavailable (endpoint unregistered or DND)",
    481: "Call/transaction does not exist (dialog mismatch, often after failover or a stale re-INVITE)",
    483: "Too many hops (routing loop)", 484: "Address incomplete: digits missing / interdigit timeout",
    486: "Busy here", 487: "Request terminated (caller hung up or CANCEL before answer)",
    488: "Not acceptable here: no common codec / SRTP or media mismatch (check region, codec preference, MTP/transcoder)",
    491: "Request pending (re-INVITE glare)", 500: "Server internal error",
    502: "Bad gateway", 503: "Service unavailable: route list exhausted, trunk down, or no resources",
    504: "Server timeout", 580: "Precondition failure", 600: "Busy everywhere", 603: "Declined",
    604: "Does not exist anywhere", 606: "Not acceptable",
}


def _f(level: str, title: str, detail: str = "") -> dict:
    return {"level": level, "title": title, "detail": detail}


def legs(cdrs: list[dict], cmrs: list[dict]) -> list[dict]:
    out = []
    for r in cdrs:
        s = C.summarize(r)
        leg_ids = {s["orig_leg"], s["dest_leg"]}
        q = []
        for m in cmrs:
            if C.ci_get(m, "callIdentifier") in leg_ids:
                vq = C.parse_vq(C.ci_get(m, "varVQMetrics"))
                side = "orig" if C.ci_get(m, "callIdentifier") == s["orig_leg"] else "dest"
                q.append({
                    "side": side, "device": C.ci_get(m, "deviceName"), "dn": C.ci_get(m, "directoryNum"),
                    "sent": C.to_int(C.ci_get(m, "numberPacketsSent")),
                    "received": C.to_int(C.ci_get(m, "numberPacketsReceived")),
                    "lost": C.to_int(C.ci_get(m, "numberPacketsLost")),
                    "jitter": C.to_int(C.ci_get(m, "jitter")), "latency": C.to_int(C.ci_get(m, "latency")),
                    "mos": vq.get("MLQK"), "mos_min": vq.get("MLQKmn"), "mos_avg": vq.get("MLQKav"),
                    "ccr": vq.get("CCR"), "icr_max": vq.get("ICRmx"), "cs": vq.get("CS"), "scs": vq.get("SCS"),
                    "vq": C.ci_get(m, "varVQMetrics"),
                })
        out.append({
            "pkid": s["pkid"], "orig_ts": s["orig_ts"], "connect_ts": s["connect_ts"],
            "disconnect_ts": s["disconnect_ts"], "duration": s["duration"],
            "calling": s["calling"], "orig_called": s["orig_called"], "final_called": s["final_called"],
            "last_redirect": s["last_redirect"],
            "redirect_reason": C.decode("lastRedirectRedirectReason", C.ci_get(r, "lastRedirectRedirectReason")),
            "orig_device": s["orig_device"], "dest_device": s["dest_device"],
            "orig_ip": C.cdr_ip(r, "orig"), "dest_ip": C.cdr_ip(r, "dest"),
            "orig_cause": s["orig_cause"], "orig_cause_text": C.cause_text(s["orig_cause"]),
            "dest_cause": s["dest_cause"], "dest_cause_text": C.cause_text(s["dest_cause"]),
            "orig_codec": C.decode("origMediaCap_payloadCapability", C.ci_get(r, "origMediaCap_payloadCapability")),
            "dest_codec": C.decode("destMediaCap_payloadCapability", C.ci_get(r, "destMediaCap_payloadCapability")),
            "orig_media": f"{C.media_ip(r, 'orig')}:{C.ci_get(r, 'origMediaTransportAddress_Port')}".strip(":"),
            "dest_media": f"{C.media_ip(r, 'dest')}:{C.ci_get(r, 'destMediaTransportAddress_Port')}".strip(":"),
            "orig_term": C.decode("origCallTerminationOnBehalfOf", C.ci_get(r, "origCallTerminationOnBehalfOf")),
            "dest_term": C.decode("destCallTerminationOnBehalfOf", C.ci_get(r, "destCallTerminationOnBehalfOf")),
            "secured": C.decode("callSecuredStatus", C.ci_get(r, "callSecuredStatus")),
            "quality": q, "fields": C.decorate(r),
        })
    return out


def findings(leg_list: list[dict], ladder: dict | None, selected: set | None = None) -> list[dict]:
    out: list[dict] = []
    # ------------------------------------------------------------ CDR
    for i, L in enumerate(leg_list, 1):
        tag = f"Leg {i} ({L['calling'] or '?'} → {L['final_called'] or L['orig_called'] or '?'})"
        for side in ("orig", "dest"):
            c = L[f"{side}_cause"]
            if c and c not in C.NORMAL_CAUSES:
                lvl = "warn" if c in (17, 19, 21) else "error"
                who = "calling side" if side == "orig" else "called side"
                out.append(_f(lvl, f"{tag}: {who} cleared with cause {c}", L[f"{side}_cause_text"]))
        if L["duration"] == 0 and not L["connect_ts"]:
            out.append(_f("warn", f"{tag}: never connected (duration 0)",
                          "The call was released before answer. Check the termination causes and the SIP final response."))
        if L["redirect_reason"] and L["last_redirect"]:
            out.append(_f("info", f"{tag}: redirected by {L['last_redirect']}", L["redirect_reason"]))
        if L["orig_codec"] and L["dest_codec"] and L["orig_codec"] != L["dest_codec"]:
            out.append(_f("info", f"{tag}: codec differs per side ({L['orig_codec']} / {L['dest_codec']})",
                          "A transcoder or MTP was likely inserted between the parties."))
        for q in L["quality"]:
            who = f"{q['device'] or q['side']}"
            if L["duration"] >= 5 and q["sent"] and not q["received"]:
                out.append(_f("error", f"{tag}: {who} received no RTP packets",
                              "One-way audio: check the media path / NAT / firewall / ACL toward this device."))
            elif L["duration"] >= 5 and not q["sent"] and q["received"]:
                out.append(_f("error", f"{tag}: {who} sent no RTP packets", "One-way audio from this device."))
            tot = (q["received"] or 0) + (q["lost"] or 0)
            if tot and q["lost"] / tot > 0.01:
                out.append(_f("warn", f"{tag}: {who} lost {q['lost']} packets ({q['lost'] / tot:.1%})"))
            if q["jitter"] and q["jitter"] > 30:
                out.append(_f("warn", f"{tag}: {who} jitter {q['jitter']} ms"))
            if q["latency"] and q["latency"] > 150:
                out.append(_f("warn", f"{tag}: {who} latency {q['latency']} ms"))
            if isinstance(q["mos"], float) and 0 < q["mos"] < 3.6:
                out.append(_f("warn", f"{tag}: {who} MOS-LQK {q['mos']:.2f}",
                              f"min {q['mos_min']}, avg {q['mos_avg']}, conceal ratio {q['ccr']}"))
    # ------------------------------------------------------------ SIP
    if not ladder or not ladder.get("messages"):
        return out
    sel = selected if selected is not None else {d["call_id"] for d in ladder["dialogs"] if d["selected"]}
    msgs = [m for m in ladder["messages"] if m["call_id"] in sel]
    parts = ladder["participants"]
    name = lambda k: parts.get(k, {}).get("name", k)  # noqa: E731
    by_cid: dict[str, list[dict]] = {}
    for m in msgs:
        by_cid.setdefault(m["call_id"], []).append(m)
    retrans = [m for m in msgs if m["retrans"]]
    if retrans:
        tgts = sorted({name(m["to"]) for m in retrans})
        out.append(_f("warn", f"{len(retrans)} SIP retransmission(s)",
                      "Toward " + ", ".join(tgts) + ". Packet loss or a far end that is slow to respond."))
    for cid, ms in by_cid.items():
        inv = next((m for m in ms if m["method"] == "INVITE"), None)
        if not inv:
            continue
        path = f"{name(inv['from'])} → {name(inv['to'])}"
        pinv = parse_sip(inv["raw"])
        if not pinv["sdp"]:
            out.append(_f("info", f"Delayed offer on {path}", "Initial INVITE has no SDP; the offer comes in the 200 OK and the answer in the ACK."))
        first_cseq = inv["cseq"]
        resps = [m for m in ms if not m["is_request"] and m["cseq"] == first_cseq]
        prov = next((m for m in resps if 180 <= m["status"] < 200 and m["from"] == inv["to"]), None)
        final = next((m for m in resps if m["status"] >= 200 and m["from"] == inv["to"]), None)
        if prov:
            pdd = prov["ts"] - inv["ts"]
            lvl = "warn" if pdd > 5 else "info"
            out.append(_f(lvl, f"Post-dial delay {pdd:.2f}s on {path}", f"INVITE → {prov['label']}"))
            if prov["status"] == 183 and prov["sdp"]:
                out.append(_f("info", f"Early media on {path}", f"183 with SDP: {prov['sdp']}"))
        if final and final["status"] >= 300:
            h = SIP_HINTS.get(final["status"], "")
            extra = []
            if final.get("reason"):
                q = q850_from_reason(final["reason"])
                extra.append(f"Reason: {final['reason']}" + (f" ({C.cause_text(q)})" if q is not None else ""))
            if final.get("warning"):
                extra.append(f"Warning: {final['warning']}")
            lvl = "warn" if final["status"] in (486, 487, 600, 603) else "error"
            out.append(_f(lvl, f"{final['label']} from {name(final['from'])} on {path}",
                          " ".join([h] + extra).strip()))
        elif final and final["status"] < 300:
            out.append(_f("info", f"Answered on {path} after {final['ts'] - inv['ts']:.2f}s",
                          f"SDP: {final['sdp']}" if final["sdp"] else ""))
            acks = [m for m in ms if m["method"] == "ACK" and m["from"] == inv["from"]]
            if not acks:
                out.append(_f("error", f"No ACK seen for 200 OK on {path}",
                              "The 200 OK was not acknowledged: check routing of the ACK (Record-Route/Contact, NAT, TLS)."))
        elif not final:
            out.append(_f("warn", f"No final response to INVITE on {path}", "Trace may be incomplete, or the far end never answered."))
        # codec negotiation
        offer = pinv["sdp"]
        ans = parse_sip(final["raw"])["sdp"] if final and final["status"] < 300 else None
        if offer and ans:
            o = {c.lower() for mm in offer["media"] if mm["type"] == "audio" for c in mm["codecs"]}
            a = [c for mm in ans["media"] if mm["type"] == "audio" for c in mm["codecs"]
                 if c.lower() not in ("telephone-event", "cn")]
            if a and a[0].lower() not in o:
                out.append(_f("warn", f"Answer codec {a[0]} was not in the offer on {path}"))
            if "telephone-event" in o and not any(c.lower() == "telephone-event" for mm in ans["media"] for c in mm["codecs"]):
                out.append(_f("warn", f"RFC 2833 offered but not answered on {path}",
                              "DTMF may fall back to KPML/OOB or need an MTP."))
        held = False
        for m in ms:
            if m["method"] in ("INVITE", "UPDATE") and m is not inv and m["sdp"]:
                if any(x in m["sdp"] for x in ("sendonly", "inactive", "hold")):
                    held = True
                    out.append(_f("info", f"Hold at {_t(m['ts'])} on {path}", f"{m['label']} from {name(m['from'])}: {m['sdp']}"))
                elif held:
                    held = False
                    out.append(_f("info", f"Resume at {_t(m['ts'])} on {path}", f"{m['label']} from {name(m['from'])}: {m['sdp']}"))
            if m["method"] in ("BYE", "CANCEL") and m.get("reason"):
                q = q850_from_reason(m["reason"])
                out.append(_f("info", f"{m['method']} from {name(m['from'])} carries Reason",
                              m["reason"] + (f" ({C.cause_text(q)})" if q is not None else "")))
    # who ended the call: the first BYE/CANCEL that did not originate at a CUCM node
    ends = sorted((m for m in msgs if m["method"] in ("BYE", "CANCEL") and not m["retrans"]), key=lambda m: m["ts"])
    ext = [m for m in ends if parts.get(m["from"], {}).get("kind") != "cucm-node"]
    first_end = (ext or ends or [None])[0]
    if first_end:
        who = parts[first_end["from"]]
        out.append(_f("info", f"Call ended by {name(first_end['from'])}" + (f" ({who['ip']})" if who.get("ip") and who["kind"] != "cucm-node" else ""),
                      f"{first_end['method']} at {_t(first_end['ts'])}; later BYEs in other dialogs are CUCM relaying it."))
    return out


def _t(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"

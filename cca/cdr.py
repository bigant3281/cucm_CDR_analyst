"""CDR / CMR flat-file parsing and field decoding."""
from __future__ import annotations

import csv
import io
import socket
import struct
from datetime import datetime, timezone

# --------------------------------------------------------------- lookups
Q850 = {
    0: "No error", 1: "Unallocated (unassigned) number", 2: "No route to specified transit network",
    3: "No route to destination", 4: "Send special information tone", 5: "Misdialed trunk prefix",
    6: "Channel unacceptable", 7: "Call awarded and being delivered in an established channel",
    8: "Preemption", 9: "Preemption - circuit reserved for reuse", 16: "Normal call clearing",
    17: "User busy", 18: "No user responding", 19: "No answer from user (user alerted)",
    20: "Subscriber absent", 21: "Call rejected", 22: "Number changed", 26: "Non-selected user clearing",
    27: "Destination out of order", 28: "Invalid number format (address incomplete)",
    29: "Facility rejected", 30: "Response to STATUS ENQUIRY", 31: "Normal, unspecified",
    34: "No circuit/channel available", 38: "Network out of order",
    39: "Permanent frame mode connection out of service", 40: "Permanent frame mode connection operational",
    41: "Temporary failure", 42: "Switching equipment congestion", 43: "Access information discarded",
    44: "Requested circuit/channel not available", 46: "Precedence call blocked",
    47: "Resource unavailable, unspecified", 49: "Quality of service not available",
    50: "Requested facility not subscribed", 53: "Outgoing calls barred within CUG",
    54: "Incoming calls barred", 55: "Incoming calls barred within CUG",
    57: "Bearer capability not authorized", 58: "Bearer capability not presently available",
    62: "Inconsistency in outgoing information element", 63: "Service or option not available, unspecified",
    65: "Bearer capability not implemented", 66: "Channel type not implemented",
    69: "Requested facility not implemented", 70: "Only restricted digital information bearer capability is available",
    79: "Service or option not implemented, unspecified", 81: "Invalid call reference value",
    82: "Identified channel does not exist", 83: "A suspended call exists, but this call identity does not",
    84: "Call identity in use", 85: "No call suspended", 86: "Call having the requested call identity has been cleared",
    87: "User not member of CUG", 88: "Incompatible destination", 90: "Destination number missing and DC not subscribed",
    91: "Invalid transit network selection", 95: "Invalid message, unspecified",
    96: "Mandatory information element is missing", 97: "Message type non-existent or not implemented",
    98: "Message not compatible with call state or message type non-existent",
    99: "Information element non-existent or not implemented", 100: "Invalid information element contents",
    101: "Message not compatible with call state", 102: "Recovery on timer expiry",
    103: "Parameter non-existent or not implemented - passed on", 110: "Message with unrecognized parameter discarded",
    111: "Protocol error, unspecified", 122: "Precedence level exceeded",
    123: "Device not preemptable", 125: "Out of bandwidth (Cisco specific)", 126: "Call split (Cisco specific)",
    127: "Interworking, unspecified", 129: "Precedence out of bandwidth",
    # Cisco-specific CDR termination causes
    262144: "Conference full (Cisco)", 393216: "Call split - transfer/consult completed (Cisco)",
    458752: "Conference drop any party / drop last party (Cisco)",
}
NORMAL_CAUSES = {0, 16, 31, 393216, 458752}

CODECS = {
    0: "None", 1: "NonStandard", 2: "G.711 A-law 64k", 3: "G.711 A-law 56k", 4: "G.711 u-law 64k",
    5: "G.711 u-law 56k", 6: "G.722 64k", 7: "G.722 56k", 8: "G.722 48k", 9: "G.723.1", 10: "G.728",
    11: "G.729", 12: "G.729 Annex A", 15: "G.729 Annex B", 16: "G.729 Annex A+B",
    18: "GSM Full Rate", 19: "GSM Half Rate", 20: "GSM Enhanced Full Rate", 25: "Wideband 256k",
    32: "Data 64k", 33: "Data 56k", 40: "G.722.1 32k", 41: "G.722.1 24k",
    100: "H.261", 101: "H.263", 103: "H.264",
}

REDIRECT_REASONS = {
    0: "Unknown", 1: "Call Forward Busy", 2: "Call Forward No Answer", 4: "Call Transfer",
    5: "Call Pickup", 7: "Call Park", 8: "Call Park Pickup", 9: "CPE Out of Order",
    10: "Call Forward", 11: "Call Park Reversion", 15: "Call Forward All", 18: "Call Deflection",
    34: "Blind Transfer", 50: "Call Immediate Divert", 66: "Call Forward Alternate Party",
    82: "Call Forward on Failure", 98: "Conference", 114: "Barge", 129: "AAR", 130: "Refer",
    146: "Replaces", 162: "Redirection (3xx)",
}

ON_BEHALF_OF = {
    0: "Unknown", 1: "CTI/JTAPI line", 2: "Unicast shared resource", 3: "Call Park", 4: "Conference",
    5: "Call Forward", 6: "Meet-Me Conference", 7: "Meet-Me Conference Intercepts", 8: "Message Waiting",
    9: "Multicast shared resource", 10: "Transfer", 11: "SSAPI Manager", 12: "Device",
    13: "Call Control", 14: "Immediate Divert", 15: "Barge", 16: "Pickup", 17: "Refer",
    18: "Replaces", 19: "Redirection", 20: "Callback", 21: "Path Replacement", 22: "FAC/CMC Manager",
    23: "Malicious Call", 24: "Mobility", 25: "AAR", 26: "Directed Call Park", 27: "Recording",
    28: "Monitor",
}

PROTOCOL_IDS = {0: "Unknown", 1: "SIP", 2: "H.323", 3: "CTI/JTAPI", 4: "Q.931"}
SECURED = {0: "Non-secure", 1: "Authenticated", 2: "Encrypted"}

# Fields shown on the call page, grouped. Anything else lands in "All fields".
GROUPS = [
    ("Identity", ["globalCallID_callManagerId", "globalCallID_callId", "globalCallId_ClusterID",
                   "origLegCallIdentifier", "destLegIdentifier", "pkid", "origConversationId",
                   "IncomingProtocolID", "IncomingProtocolCallRef", "OutgoingProtocolID",
                   "OutgoingProtocolCallRef"]),
    ("Parties", ["callingPartyNumber", "callingPartyNumberPartition", "callingPartyUnicodeLoginUserID",
                 "originalCalledPartyNumber", "originalCalledPartyNumberPartition",
                 "finalCalledPartyNumber", "finalCalledPartyNumberPartition", "lastRedirectDn",
                 "lastRedirectDnPartition", "lastRedirectRedirectReason", "huntPilotDN",
                 "outpulsedCallingPartyNumber", "outpulsedCalledPartyNumber",
                 "callingPartyNumber_uri", "finalCalledPartyNumber_uri",
                 "originalCalledPartyPattern", "finalCalledPartyPattern", "calledPartyPatternUsage"]),
    ("Devices", ["origDeviceName", "origDeviceType", "origIpv4v6Addr", "origIpAddr", "origNodeId",
                 "destDeviceName", "destDeviceType", "destIpv4v6Addr", "destIpAddr", "destNodeId"]),
    ("Timing", ["dateTimeOrigination", "dateTimeConnect", "dateTimeDisconnect", "duration",
                "wasCallQueued", "totalWaitTimeInQueue"]),
    ("Termination", ["origCause_value", "origCause_location", "destCause_value", "destCause_location",
                     "origCallTerminationOnBehalfOf", "destCallTerminationOnBehalfOf",
                     "origCalledPartyRedirectOnBehalfOf", "lastRedirectRedirectOnBehalfOf",
                     "joinOnBehalfOf", "comment"]),
    ("Media", ["origMediaTransportAddress_IP", "origMediaTransportAddress_Port",
               "origMediaCap_payloadCapability", "origMediaCap_maxFramesPerPacket", "origMediaCap_Bandwidth",
               "destMediaTransportAddress_IP", "destMediaTransportAddress_Port",
               "destMediaCap_payloadCapability", "destMediaCap_maxFramesPerPacket", "destMediaCap_Bandwidth",
               "origVideoCap_Codec", "destVideoCap_Codec", "origDTMFMethod", "destDTMFMethod",
               "callSecuredStatus"]),
]

TIME_FIELDS = {"dateTimeOrigination", "dateTimeConnect", "dateTimeDisconnect", "dateTimeStamp"}
IP_INT_FIELDS = {"origIpAddr", "destIpAddr", "origMediaTransportAddress_IP",
                 "destMediaTransportAddress_IP", "origVideoTransportAddress_IP",
                 "destVideoTransportAddress_IP", "origVideoTransportAddress_IP_Channel2",
                 "destVideoTransportAddress_IP_Channel2"}


# --------------------------------------------------------------- helpers
def int_ip(v) -> str:
    """CDR stores IPv4 as a signed 32-bit int in network-reversed order."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return str(v or "")
    if n == 0:
        return ""
    try:
        return socket.inet_ntoa(struct.pack("<i", n))
    except struct.error:
        return socket.inet_ntoa(struct.pack("<I", n & 0xFFFFFFFF))


def epoch(v) -> datetime | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(n, tz=timezone.utc) if n > 0 else None


def to_int(v, default=0) -> int:
    try:
        return int(str(v).strip() or default)
    except ValueError:
        return default


def cause_text(v) -> str:
    n = to_int(v, -1)
    if n < 0:
        return ""
    return Q850.get(n, f"Cisco-specific cause {n} (see CDR Admin Guide)" if n > 127 else f"Cause {n}")


def decode(field: str, value) -> str:
    """Human-readable form of a CDR/CMR field ('' when same as raw)."""
    if value in (None, ""):
        return ""
    if field in TIME_FIELDS:
        d = epoch(value)
        return d.isoformat() if d else ""
    if field in IP_INT_FIELDS:
        ip = int_ip(value)
        return ip if ip != str(value) else ""
    if field.endswith("Cause_value"):
        return cause_text(value)
    if field.endswith("payloadCapability"):
        n = to_int(value, -1)
        return CODECS.get(n, f"codec id {n}") if n > 0 else ""
    if field.endswith("VideoCap_Codec"):
        n = to_int(value, -1)
        return CODECS.get(n, f"codec id {n}") if n > 0 else ""
    if field == "lastRedirectRedirectReason" or field.endswith("RedirectReason"):
        n = to_int(value, -1)
        return REDIRECT_REASONS.get(n, "") if n >= 0 else ""
    if field.endswith("OnBehalfOf"):
        n = to_int(value, -1)
        return ON_BEHALF_OF.get(n, "") if n >= 0 else ""
    if field.endswith("ProtocolID"):
        return PROTOCOL_IDS.get(to_int(value, -1), "")
    if field == "callSecuredStatus":
        return SECURED.get(to_int(value, -1), "")
    if field == "duration":
        n = to_int(value)
        return f"{n // 3600:d}:{n % 3600 // 60:02d}:{n % 60:02d}"
    return ""


def parse_vq(s: str) -> dict:
    """'MLQK=4.5000;MLQKav=4.4;CCR=0.0;...' -> {'MLQK': 4.5, ...}"""
    out = {}
    for part in (s or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            try:
                out[k.strip()] = float(v)
            except ValueError:
                out[k.strip()] = v.strip()
    return out


# --------------------------------------------------------------- parsing
def sniff_kind(header: list[str]) -> str | None:
    h = {c.strip().strip('"').lower() for c in header}
    if "dateTimeOrigination".lower() in h:
        return "cdr"
    if "numberPacketsSent".lower() in h or "varvqmetrics" in h:
        return "cmr"
    return None


def parse_file(data: bytes) -> tuple[str | None, list[dict]]:
    """Parse a CDR or CMR flat file. Returns (kind, records)."""
    text = data.decode("utf-8", "replace").lstrip("﻿")
    rdr = csv.reader(io.StringIO(text))
    rows = list(rdr)
    if not rows:
        return None, []
    header = [c.strip() for c in rows[0]]
    kind = sniff_kind(header)
    if not kind:
        return None, []
    start = 1
    # second row lists column types: INTEGER, VARCHAR(50), UNIQUEIDENTIFIER ...
    if len(rows) > 1 and rows[1] and all(c.strip().upper().split("(")[0] in
                                         ("INTEGER", "VARCHAR", "UNIQUEIDENTIFIER", "TEXT", "CHAR", "")
                                         for c in rows[1]):
        start = 2
    recs = []
    for row in rows[start:]:
        if not row or all(not c.strip() for c in row):
            continue
        rec = {header[i]: (row[i].strip() if i < len(row) else "") for i in range(len(header))}
        rt = rec.get("cdrRecordType", "")
        if kind == "cdr" and rt not in ("1", ""):
            continue
        recs.append(rec)
    return kind, recs


def ci_get(rec: dict, key: str, default=""):
    if key in rec:
        return rec[key]
    lk = key.lower()
    for k, v in rec.items():
        if k.lower() == lk:
            return v
    return default


def cdr_ip(rec: dict, side: str) -> str:
    """Signaling IP of orig/dest device (newer field first)."""
    v = ci_get(rec, f"{side}Ipv4v6Addr")
    if v:
        return v
    return int_ip(ci_get(rec, f"{side}IpAddr"))


def media_ip(rec: dict, side: str) -> str:
    return int_ip(ci_get(rec, f"{side}MediaTransportAddress_IP"))


def call_key(rec: dict) -> str:
    return f"{ci_get(rec, 'globalCallId_ClusterID') or ci_get(rec, 'globalCallID_callManagerId')}:" \
           f"{ci_get(rec, 'globalCallID_callId')}"


def summarize(rec: dict) -> dict:
    """Flat columns used for indexing/search."""
    return {
        "call_key": call_key(rec),
        "pkid": ci_get(rec, "pkid"),
        "orig_ts": to_int(ci_get(rec, "dateTimeOrigination")),
        "connect_ts": to_int(ci_get(rec, "dateTimeConnect")),
        "disconnect_ts": to_int(ci_get(rec, "dateTimeDisconnect")),
        "duration": to_int(ci_get(rec, "duration")),
        "calling": ci_get(rec, "callingPartyNumber"),
        "orig_called": ci_get(rec, "originalCalledPartyNumber"),
        "final_called": ci_get(rec, "finalCalledPartyNumber"),
        "last_redirect": ci_get(rec, "lastRedirectDn"),
        "orig_device": ci_get(rec, "origDeviceName"),
        "dest_device": ci_get(rec, "destDeviceName"),
        "orig_cause": to_int(ci_get(rec, "origCause_value")),
        "dest_cause": to_int(ci_get(rec, "destCause_value")),
        "orig_leg": ci_get(rec, "origLegCallIdentifier"),
        "dest_leg": ci_get(rec, "destLegIdentifier") or ci_get(rec, "destLegCallIdentifier"),
    }


def decorate(rec: dict) -> dict:
    """Grouped, decoded view of one CDR for the UI."""
    used = set()
    groups = []
    for title, fields in GROUPS:
        rows = []
        for f in fields:
            k = next((k for k in rec if k.lower() == f.lower()), None)
            if k is None:
                continue
            used.add(k)
            v = rec[k]
            if v in ("", "0") and f not in ("duration", "origCause_value", "destCause_value"):
                continue
            rows.append({"field": k, "value": v, "decoded": decode(k, v)})
        groups.append({"title": title, "rows": rows})
    all_rows = [{"field": k, "value": v, "decoded": decode(k, v)} for k, v in rec.items()]
    return {"groups": groups, "all": all_rows}

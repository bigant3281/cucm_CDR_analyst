"""Synthetic CUCM data: CDR + CMR flat files and a CallManager SDL trace.

Cluster: CUCM-PUB 10.1.1.10 (publisher). Phone SEP001122334455 (DN 2001) at 10.1.1.50,
phone SEP00AABBCCDDEE (DN 2002) at 10.1.1.51, CUBE 10.1.1.200 (SIP trunk "CUBE-TRUNK").

Call 1  2001 -> 9 1 555 123 4567 via CUBE: answered, hold/resume, remote BYE, retransmitted INVITE
Call 2  2002 -> 9 555 999 9999 via CUBE: 404 Not Found (Reason Q.850 cause 1)
Call 3  2001 -> 2002 internal, answered, CDR/CMR only (no SDL for it)
"""
from __future__ import annotations

import socket
import struct
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

NY = ZoneInfo("America/New_York")
BASE = datetime(2026, 10, 5, 19, 30, 0, tzinfo=timezone.utc)   # 15:30:00 EDT
PUB_IP, PH1_IP, PH2_IP, CUBE_IP = "10.1.1.10", "10.1.1.50", "10.1.1.51", "10.1.1.200"


def ip_int(ip: str) -> int:
    return struct.unpack("<i", socket.inet_aton(ip))[0]


def epoch(dt: datetime) -> int:
    return int(dt.timestamp())


# --------------------------------------------------------------------- CDR/CMR
CDR_COLS = [
    "cdrRecordType", "globalCallID_callManagerId", "globalCallID_callId", "origLegCallIdentifier",
    "dateTimeOrigination", "origNodeId", "origIpAddr", "callingPartyNumber", "origCause_location",
    "origCause_value", "origMediaTransportAddress_IP", "origMediaTransportAddress_Port",
    "origMediaCap_payloadCapability", "destLegIdentifier", "destNodeId", "destIpAddr",
    "originalCalledPartyNumber", "finalCalledPartyNumber", "destCause_location", "destCause_value",
    "destMediaTransportAddress_IP", "destMediaTransportAddress_Port", "destMediaCap_payloadCapability",
    "dateTimeConnect", "dateTimeDisconnect", "lastRedirectDn", "pkid", "origDeviceName", "destDeviceName",
    "origCallTerminationOnBehalfOf", "destCallTerminationOnBehalfOf", "duration", "origIpv4v6Addr",
    "destIpv4v6Addr", "IncomingProtocolID", "IncomingProtocolCallRef", "OutgoingProtocolID",
    "OutgoingProtocolCallRef", "callSecuredStatus", "globalCallId_ClusterID",
    "callingPartyNumberPartition", "originalCalledPartyNumberPartition", "finalCalledPartyNumberPartition",
]
CDR_TYPES = ["INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "VARCHAR(50)",
             "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER",
             "VARCHAR(50)", "VARCHAR(50)", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER",
             "INTEGER", "INTEGER", "VARCHAR(50)", "UNIQUEIDENTIFIER", "VARCHAR(129)", "VARCHAR(129)",
             "INTEGER", "INTEGER", "INTEGER", "VARCHAR(64)", "VARCHAR(64)", "INTEGER", "VARCHAR(32)",
             "INTEGER", "VARCHAR(32)", "INTEGER", "VARCHAR(50)", "VARCHAR(50)", "VARCHAR(50)", "VARCHAR(50)"]

CMR_COLS = ["cdrRecordType", "globalCallID_callManagerId", "globalCallID_callId", "nodeId", "directoryNum",
            "callIdentifier", "dateTimeStamp", "numberPacketsSent", "numberOctetsSent", "numberPacketsReceived",
            "numberOctetsReceived", "numberPacketsLost", "jitter", "latency", "pkid", "directoryNumPartition",
            "globalCallId_ClusterID", "deviceName", "varVQMetrics"]
CMR_TYPES = ["INTEGER", "INTEGER", "INTEGER", "INTEGER", "VARCHAR(50)", "INTEGER", "INTEGER", "INTEGER",
             "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "UNIQUEIDENTIFIER",
             "VARCHAR(50)", "VARCHAR(50)", "VARCHAR(129)", "VARCHAR(600)"]


def _csv(cols, types, rows) -> bytes:
    def q(v):
        s = str(v)
        return f'"{s}"' if "," in s or '"' in s else s
    lines = [",".join(cols), ",".join(types)]
    for r in rows:
        lines.append(",".join(q(r.get(c, "")) for c in cols))
    return ("\n".join(lines) + "\n").encode()


def _cdr(**kw) -> dict:
    d = {c: "" for c in CDR_COLS}
    d.update({"cdrRecordType": 1, "globalCallID_callManagerId": 1, "origNodeId": 1, "destNodeId": 1,
              "globalCallId_ClusterID": "StandAloneCluster", "origCause_location": 0, "destCause_location": 0,
              "origMediaCap_payloadCapability": 4, "destMediaCap_payloadCapability": 4,
              "callSecuredStatus": 0, "origCallTerminationOnBehalfOf": 12, "destCallTerminationOnBehalfOf": 12,
              "callingPartyNumberPartition": "Internal-PT", "originalCalledPartyNumberPartition": "PSTN-PT",
              "finalCalledPartyNumberPartition": "PSTN-PT"})
    d.update(kw)
    return d


def build_cdr_cmr():
    t1 = BASE + timedelta(seconds=0.1)
    c1_conn, c1_end = t1 + timedelta(seconds=5.2), t1 + timedelta(seconds=62.3)
    t2 = BASE + timedelta(minutes=4, seconds=10)
    t3 = BASE + timedelta(minutes=8)
    cdrs = [
        _cdr(globalCallID_callId=5000123, origLegCallIdentifier=30100001, destLegIdentifier=30100002,
             dateTimeOrigination=epoch(t1), origIpAddr=ip_int(PH1_IP), destIpAddr=ip_int(CUBE_IP),
             callingPartyNumber="2001", originalCalledPartyNumber="915551234567", finalCalledPartyNumber="15551234567",
             origCause_value=16, destCause_value=16, origMediaTransportAddress_IP=ip_int(PH1_IP),
             origMediaTransportAddress_Port=24576, destMediaTransportAddress_IP=ip_int(CUBE_IP),
             destMediaTransportAddress_Port=16384, dateTimeConnect=epoch(c1_conn), dateTimeDisconnect=epoch(c1_end),
             pkid="11111111-aaaa-4bbb-8ccc-000000000001", origDeviceName="SEP001122334455", destDeviceName="CUBE-TRUNK",
             origCallTerminationOnBehalfOf=12, destCallTerminationOnBehalfOf=12, duration=57,
             origIpv4v6Addr=PH1_IP, destIpv4v6Addr=CUBE_IP, IncomingProtocolID=1,
             IncomingProtocolCallRef="e1f2a3b4-0001-4c11-9a22-000000000001@10.1.1.50", OutgoingProtocolID=1,
             OutgoingProtocolCallRef="a8b7c6d5-0002-4e33-8f44-000000000002@10.1.1.10"),
        _cdr(globalCallID_callId=5000140, origLegCallIdentifier=30100021, destLegIdentifier=30100022,
             dateTimeOrigination=epoch(t2), origIpAddr=ip_int(PH2_IP), destIpAddr=ip_int(CUBE_IP),
             callingPartyNumber="2002", originalCalledPartyNumber="95559999999", finalCalledPartyNumber="5559999999",
             origCause_value=1, destCause_value=1, dateTimeConnect=0, dateTimeDisconnect=epoch(t2 + timedelta(seconds=1.4)),
             pkid="11111111-aaaa-4bbb-8ccc-000000000002", origDeviceName="SEP00AABBCCDDEE", destDeviceName="CUBE-TRUNK",
             origCallTerminationOnBehalfOf=12, destCallTerminationOnBehalfOf=12, duration=0,
             origIpv4v6Addr=PH2_IP, destIpv4v6Addr=CUBE_IP, IncomingProtocolID=1,
             IncomingProtocolCallRef="c9d8e7f6-0003-4a55-9b66-000000000003@10.1.1.51", OutgoingProtocolID=1,
             OutgoingProtocolCallRef="d4c3b2a1-0004-4d77-8a88-000000000004@10.1.1.10"),
        _cdr(globalCallID_callId=5000177, origLegCallIdentifier=30100041, destLegIdentifier=30100042,
             dateTimeOrigination=epoch(t3), origIpAddr=ip_int(PH1_IP), destIpAddr=ip_int(PH2_IP),
             callingPartyNumber="2001", originalCalledPartyNumber="2002", finalCalledPartyNumber="2002",
             origCause_value=16, destCause_value=0, origMediaTransportAddress_IP=ip_int(PH1_IP),
             origMediaTransportAddress_Port=24580, destMediaTransportAddress_IP=ip_int(PH2_IP),
             destMediaTransportAddress_Port=24590, origMediaCap_payloadCapability=6, destMediaCap_payloadCapability=6,
             dateTimeConnect=epoch(t3 + timedelta(seconds=3)), dateTimeDisconnect=epoch(t3 + timedelta(seconds=33)),
             pkid="11111111-aaaa-4bbb-8ccc-000000000003", origDeviceName="SEP001122334455", destDeviceName="SEP00AABBCCDDEE",
             origCallTerminationOnBehalfOf=12, destCallTerminationOnBehalfOf=12, duration=30,
             origIpv4v6Addr=PH1_IP, destIpv4v6Addr=PH2_IP, IncomingProtocolID=1, OutgoingProtocolID=1,
             originalCalledPartyNumberPartition="Internal-PT", finalCalledPartyNumberPartition="Internal-PT"),
    ]

    def cmr(call_id, leg, dn, dev, sent, rcv, lost, jit, lat, vq, ts, n):
        return {"cdrRecordType": 0, "globalCallID_callManagerId": 1, "globalCallID_callId": call_id, "nodeId": 1,
                "directoryNum": dn, "callIdentifier": leg, "dateTimeStamp": epoch(ts), "numberPacketsSent": sent,
                "numberOctetsSent": sent * 160, "numberPacketsReceived": rcv, "numberOctetsReceived": rcv * 160,
                "numberPacketsLost": lost, "jitter": jit, "latency": lat,
                "pkid": f"22222222-bbbb-4ccc-8ddd-{n:012d}", "directoryNumPartition": "Internal-PT",
                "globalCallId_ClusterID": "StandAloneCluster", "deviceName": dev, "varVQMetrics": vq}
    cmrs = [
        cmr(5000123, 30100001, "2001", "SEP001122334455", 2850, 2791, 59, 38, 0,
            "MLQK=3.4000;MLQKmn=2.9000;MLQKmx=4.5000;MLQKav=3.7000;MLQKvr=3.5000;CCR=0.0412;ICR=0.0300;ICRmx=0.1200;CS=4;SCS=2", c1_end, 1),
        cmr(5000123, 30100002, "2001", "CUBE-TRUNK", 2791, 2850, 0, 6, 0,
            "MLQK=4.4000;MLQKmn=4.3000;MLQKmx=4.5000;MLQKav=4.4000;MLQKvr=4.4000;CCR=0.0000;ICR=0.0000;ICRmx=0.0000;CS=0;SCS=0", c1_end, 2),
        cmr(5000177, 30100041, "2001", "SEP001122334455", 1500, 0, 0, 2, 1,
            "MLQK=0.0000;CCR=0.0000;ICR=0.0000;CS=0;SCS=0", t3 + timedelta(seconds=33), 3),
        cmr(5000177, 30100042, "2002", "SEP00AABBCCDDEE", 1480, 1500, 0, 3, 1,
            "MLQK=4.5000;MLQKmn=4.5000;MLQKmx=4.5000;MLQKav=4.5000;CCR=0.0000;CS=0;SCS=0", t3 + timedelta(seconds=33), 4),
    ]
    cdr_name = "cdr_StandAloneCluster_01_202610051930_0"
    cmr_name = "cmr_StandAloneCluster_01_202610051930_1"
    return (cdr_name, _csv(CDR_COLS, CDR_TYPES, cdrs)), (cmr_name, _csv(CMR_COLS, CMR_TYPES, cmrs))


# --------------------------------------------------------------------- SDL
_seq = [0]


def _sdl_entry(ts_utc: datetime, direction: str, remote_ip: str, port: int, sip: str, tcp=True) -> str:
    _seq[0] += 1
    local = ts_utc.astimezone(NY)
    stamp = local.strftime("%H:%M:%S.") + f"{local.microsecond // 1000:03d}"
    n = len(sip)
    if tcp:
        head = (f"{_seq[0]:08d}.001 |{stamp} |AppInfo  |SIPTcp - wait_SdlReadRsp: Incoming SIP TCP message from {remote_ip} on port {port} index 7 with {n} bytes:"
                if direction == "in" else
                f"{_seq[0]:08d}.001 |{stamp} |AppInfo  |SIPTcp - wait_SdlSPISignal: Outgoing SIP TCP message to {remote_ip} on port {port} index 7")
    else:
        head = (f"{_seq[0]:08d}.001 |{stamp} |AppInfo  |SIPUdp - wait_SdlReadRsp: Incoming SIP UDP message size {n} from {remote_ip}:[{port}]:"
                if direction == "in" else
                f"{_seq[0]:08d}.001 |{stamp} |AppInfo  |SIPUdp - wait_SdlSPISignal: Outgoing SIP UDP message to {remote_ip}:[{port}]:")
    noise = f"{_seq[0] + 1:08d}.001 |{stamp} |SdlSig  |CcSetupReq   |wait |CC(1,100,200,1) |SIPCdpc(1,100,19)"
    return f"{head}\n[{_seq[0] + 5000},NET]\n{sip}\n{noise}\n"


def _sdp(ip: str, port: int, codecs=("0 PCMU/8000", "8 PCMA/8000"), direction="sendrecv", ev=True) -> str:
    pts = [c.split()[0] for c in codecs] + (["101"] if ev else [])
    s = (f"v=0\r\no=CiscoSystemsCCM-SIP 2000 1 IN IP4 {ip}\r\ns=SIP Call\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
         f"m=audio {port} RTP/AVP {' '.join(pts)}\r\n")
    for c in codecs:
        s += f"a=rtpmap:{c}\r\n"
    if ev:
        s += "a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n"
    s += f"a={direction}\r\n"
    return s


def _msg(first: str, headers: list[tuple[str, str]], body: str = "") -> str:
    h = "\r\n".join(f"{k}: {v}" for k, v in headers)
    h += f"\r\nContent-Length: {len(body)}"
    if body:
        h += "\r\nContent-Type: application/sdp"
    return f"{first}\r\n{h}\r\n\r\n{body}"


def build_sdl():
    out: list[tuple[datetime, str]] = []

    def add(t, direction, ip, port, sip, tcp=True):
        out.append((t, _sdl_entry(t, direction, ip, port, sip, tcp)))

    # ================= call 1 =================
    cidA = "e1f2a3b4-0001-4c11-9a22-000000000001@10.1.1.50"       # phone <-> CUCM
    cidB = "a8b7c6d5-0002-4e33-8f44-000000000002@10.1.1.10"       # CUCM <-> CUBE
    fromA = '"Anthony Lab" <sip:2001@10.1.1.10>;tag=0011223344550001'
    toA_nt = "<sip:915551234567@10.1.1.10>"
    dev = '+u.sip!devicename.ccm.cisco.com="SEP001122334455"'
    t = BASE + timedelta(seconds=0.1)
    inv = _msg("INVITE sip:915551234567@10.1.1.10;user=phone SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.50:51234;branch=z9hG4bK0a1b2c3d"), ("From", fromA), ("To", toA_nt),
        ("Call-ID", cidA), ("CSeq", "101 INVITE"), ("Contact", f"<sip:a1b2c3d4-5e6f@10.1.1.50:51234;transport=tcp>;{dev}"),
        ("User-Agent", "Cisco-CP8845/14.2.1"), ("Max-Forwards", "70"), ("Allow", "ACK,BYE,CANCEL,INVITE,NOTIFY,OPTIONS,REFER,REGISTER,UPDATE,SUBSCRIBE,INFO"),
        ("Supported", "replaces,join,norefersub")], _sdp("10.1.1.50", 24576))
    add(t, "in", PH1_IP, 51234, inv)
    toA = toA_nt + ";tag=cucm-8841"
    add(t + timedelta(milliseconds=12), "out", PH1_IP, 51234, _msg("SIP/2.0 100 Trying", [
        ("Via", "SIP/2.0/TCP 10.1.1.50:51234;branch=z9hG4bK0a1b2c3d"), ("From", fromA), ("To", toA_nt),
        ("Call-ID", cidA), ("CSeq", "101 INVITE")]))
    fromB = '<sip:2001@10.1.1.10>;tag=cucm-9001'
    toB = "<sip:15551234567@10.1.1.200>"
    invB = _msg("INVITE sip:15551234567@10.1.1.200:5060 SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc11dd22"), ("From", '"Anthony Lab" ' + fromB), ("To", toB),
        ("Call-ID", cidB), ("CSeq", "101 INVITE"), ("Contact", "<sip:2001@10.1.1.10:5060;transport=tcp>"),
        ("P-Asserted-Identity", '"Anthony Lab" <sip:2001@10.1.1.10>'), ("User-Agent", "Cisco-CUCM14"),
        ("Max-Forwards", "69"), ("Supported", "timer,resource-priority,replaces"),
        ("Session-Expires", "1800"), ("Min-SE", "1800")], _sdp("10.1.1.50", 24576))
    add(t + timedelta(milliseconds=45), "out", CUBE_IP, 5060, invB)
    add(t + timedelta(milliseconds=545), "out", CUBE_IP, 5060, invB)                       # retransmission (T1)
    add(t + timedelta(milliseconds=600), "in", CUBE_IP, 5060, _msg("SIP/2.0 100 Trying", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc11dd22"), ("From", '"Anthony Lab" ' + fromB), ("To", toB),
        ("Call-ID", cidB), ("CSeq", "101 INVITE"), ("Server", "Cisco-SIPGateway/IOS-17.9.4")]))
    toBt = toB + ";tag=3A7B1F-2C4D"
    ring = lambda to, cid, via, frm, cs, srv=None: _msg("SIP/2.0 180 Ringing", [  # noqa: E731
        ("Via", via), ("From", frm), ("To", to), ("Call-ID", cid), ("CSeq", cs),
        ("Contact", "<sip:15551234567@10.1.1.200:5060;transport=tcp>")] + ([("Server", srv)] if srv else []))
    add(t + timedelta(milliseconds=1900), "in", CUBE_IP, 5060, ring(toBt, cidB, "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc11dd22", '"Anthony Lab" ' + fromB, "101 INVITE", "Cisco-SIPGateway/IOS-17.9.4"))
    add(t + timedelta(milliseconds=1920), "out", PH1_IP, 51234, ring(toA, cidA, "SIP/2.0/TCP 10.1.1.50:51234;branch=z9hG4bK0a1b2c3d", fromA, "101 INVITE"))
    ok = lambda to, cid, via, frm, cs, sdp, contact: _msg("SIP/2.0 200 OK", [  # noqa: E731
        ("Via", via), ("From", frm), ("To", to), ("Call-ID", cid), ("CSeq", cs), ("Contact", contact),
        ("Supported", "replaces")], sdp)
    t200 = t + timedelta(seconds=5.2)
    add(t200, "in", CUBE_IP, 5060, ok(toBt, cidB, "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc11dd22", '"Anthony Lab" ' + fromB, "101 INVITE",
                                       _sdp("10.1.1.200", 16384, ("0 PCMU/8000",)), "<sip:15551234567@10.1.1.200:5060;transport=tcp>"))
    add(t200 + timedelta(milliseconds=15), "out", PH1_IP, 51234, ok(toA, cidA, "SIP/2.0/TCP 10.1.1.50:51234;branch=z9hG4bK0a1b2c3d", fromA, "101 INVITE",
                                       _sdp("10.1.1.200", 16384, ("0 PCMU/8000",)), "<sip:915551234567@10.1.1.10:5060;transport=tcp>"))
    ack = lambda first, via, frm, to, cid, cs, extra=(): _msg(first, [("Via", via), ("From", frm), ("To", to), ("Call-ID", cid), ("CSeq", cs), ("Max-Forwards", "70")] + list(extra))  # noqa: E731
    add(t200 + timedelta(milliseconds=60), "in", PH1_IP, 51234, ack("ACK sip:915551234567@10.1.1.10:5060;transport=tcp SIP/2.0", "SIP/2.0/TCP 10.1.1.50:51234;branch=z9hG4bK0a1b2c3e", fromA, toA, cidA, "101 ACK"))
    add(t200 + timedelta(milliseconds=75), "out", CUBE_IP, 5060, ack("ACK sip:15551234567@10.1.1.200:5060;transport=tcp SIP/2.0", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc11dd33", '"Anthony Lab" ' + fromB, toBt, cidB, "101 ACK"))

    # hold (re-INVITE sendonly) and resume
    def reinvite(tt, n, direction_attr, port_phone=24576):
        invA = _msg("INVITE sip:915551234567@10.1.1.10:5060;transport=tcp SIP/2.0", [
            ("Via", f"SIP/2.0/TCP 10.1.1.50:51234;branch=z9hG4bK0a1b2c{n}0"), ("From", fromA), ("To", toA), ("Call-ID", cidA),
            ("CSeq", f"{101 + n} INVITE"), ("Contact", f"<sip:a1b2c3d4-5e6f@10.1.1.50:51234;transport=tcp>;{dev}")], _sdp("10.1.1.50", port_phone, direction=direction_attr))
        add(tt, "in", PH1_IP, 51234, invA)
        invB2 = _msg("INVITE sip:15551234567@10.1.1.200:5060;transport=tcp SIP/2.0", [
            ("Via", f"SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc11e{n}"), ("From", '"Anthony Lab" ' + fromB), ("To", toBt), ("Call-ID", cidB),
            ("CSeq", f"{101 + n} INVITE"), ("Contact", "<sip:2001@10.1.1.10:5060;transport=tcp>")], _sdp("10.1.1.50", port_phone, direction=direction_attr))
        add(tt + timedelta(milliseconds=20), "out", CUBE_IP, 5060, invB2)
        rd = "recvonly" if direction_attr == "sendonly" else "sendrecv"
        add(tt + timedelta(milliseconds=70), "in", CUBE_IP, 5060, ok(toBt, cidB, f"SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc11e{n}", '"Anthony Lab" ' + fromB,
                                                                       f"{101 + n} INVITE", _sdp("10.1.1.200", 16384, ("0 PCMU/8000",), direction=rd), "<sip:15551234567@10.1.1.200:5060;transport=tcp>"))
        add(tt + timedelta(milliseconds=90), "out", PH1_IP, 51234, ok(toA, cidA, f"SIP/2.0/TCP 10.1.1.50:51234;branch=z9hG4bK0a1b2c{n}0", fromA,
                                                                        f"{101 + n} INVITE", _sdp("10.1.1.200", 16384, ("0 PCMU/8000",), direction=rd), "<sip:915551234567@10.1.1.10:5060;transport=tcp>"))
        add(tt + timedelta(milliseconds=130), "in", PH1_IP, 51234, ack("ACK sip:915551234567@10.1.1.10:5060 SIP/2.0", f"SIP/2.0/TCP 10.1.1.50:51234;branch=z9hG4bK0a1b2c{n}1", fromA, toA, cidA, f"{101 + n} ACK"))
        add(tt + timedelta(milliseconds=145), "out", CUBE_IP, 5060, ack("ACK sip:15551234567@10.1.1.200:5060 SIP/2.0", f"SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc11f{n}", '"Anthony Lab" ' + fromB, toBt, cidB, f"{101 + n} ACK"))
    reinvite(t + timedelta(seconds=20.4), 1, "sendonly")
    reinvite(t + timedelta(seconds=34.9), 2, "sendrecv")

    # remote BYE
    tb = t + timedelta(seconds=62.3)
    add(tb, "in", CUBE_IP, 5060, _msg("BYE sip:2001@10.1.1.10:5060;transport=tcp SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.200:5060;branch=z9hG4bKb7e1"), ("From", toBt), ("To", '"Anthony Lab" ' + fromB), ("Call-ID", cidB),
        ("CSeq", "2 BYE"), ("Reason", "Q.850;cause=16"), ("Max-Forwards", "70")]))
    add(tb + timedelta(milliseconds=8), "out", PH1_IP, 51234, _msg("BYE sip:a1b2c3d4-5e6f@10.1.1.50:51234;transport=tcp SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc9988"), ("From", toA), ("To", fromA), ("Call-ID", cidA), ("CSeq", "101 BYE"), ("Max-Forwards", "69")]))
    add(tb + timedelta(milliseconds=40), "in", PH1_IP, 51234, _msg("SIP/2.0 200 OK", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK00cc9988"), ("From", toA), ("To", fromA), ("Call-ID", cidA), ("CSeq", "101 BYE")]))
    add(tb + timedelta(milliseconds=52), "out", CUBE_IP, 5060, _msg("SIP/2.0 200 OK", [
        ("Via", "SIP/2.0/TCP 10.1.1.200:5060;branch=z9hG4bKb7e1"), ("From", toBt), ("To", '"Anthony Lab" ' + fromB), ("Call-ID", cidB), ("CSeq", "2 BYE")]))

    # background noise on the trunk: OPTIONS ping (must be ignored by matching)
    to = BASE + timedelta(seconds=30.0)
    add(to, "out", CUBE_IP, 5060, _msg("OPTIONS sip:10.1.1.200:5060 SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK5555"), ("From", "<sip:10.1.1.10>;tag=opt1"), ("To", "<sip:10.1.1.200>"),
        ("Call-ID", "opt-ping-1@10.1.1.10"), ("CSeq", "101 OPTIONS"), ("Max-Forwards", "0")]))
    add(to + timedelta(milliseconds=9), "in", CUBE_IP, 5060, _msg("SIP/2.0 200 OK", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK5555"), ("From", "<sip:10.1.1.10>;tag=opt1"), ("To", "<sip:10.1.1.200>;tag=zz"),
        ("Call-ID", "opt-ping-1@10.1.1.10"), ("CSeq", "101 OPTIONS")]))

    # ================= call 2 : 404 =================
    cidC = "c9d8e7f6-0003-4a55-9b66-000000000003@10.1.1.51"
    cidD = "d4c3b2a1-0004-4d77-8a88-000000000004@10.1.1.10"
    t2 = BASE + timedelta(minutes=4, seconds=10)
    fromC = '"Lab Two" <sip:2002@10.1.1.10>;tag=00AABBCCDDEE0002'
    toC = "<sip:95559999999@10.1.1.10>"
    devC = '+u.sip!devicename.ccm.cisco.com="SEP00AABBCCDDEE"'
    add(t2, "in", PH2_IP, 50500, _msg("INVITE sip:95559999999@10.1.1.10;user=phone SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.51:50500;branch=z9hG4bK77aa88bb"), ("From", fromC), ("To", toC), ("Call-ID", cidC), ("CSeq", "101 INVITE"),
        ("Contact", f"<sip:77aa88bb-0000@10.1.1.51:50500;transport=tcp>;{devC}"), ("User-Agent", "Cisco-CP8845/14.2.1")], _sdp("10.1.1.51", 24600)))
    add(t2 + timedelta(milliseconds=10), "out", PH2_IP, 50500, _msg("SIP/2.0 100 Trying", [
        ("Via", "SIP/2.0/TCP 10.1.1.51:50500;branch=z9hG4bK77aa88bb"), ("From", fromC), ("To", toC), ("Call-ID", cidC), ("CSeq", "101 INVITE")]))
    fromD = "<sip:2002@10.1.1.10>;tag=cucm-9100"
    toD = "<sip:5559999999@10.1.1.200>"
    add(t2 + timedelta(milliseconds=40), "out", CUBE_IP, 5060, _msg("INVITE sip:5559999999@10.1.1.200:5060 SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK12ab34cd"), ("From", '"Lab Two" ' + fromD), ("To", toD), ("Call-ID", cidD), ("CSeq", "101 INVITE"),
        ("Contact", "<sip:2002@10.1.1.10:5060;transport=tcp>"), ("User-Agent", "Cisco-CUCM14")], _sdp("10.1.1.51", 24600)))
    add(t2 + timedelta(milliseconds=95), "in", CUBE_IP, 5060, _msg("SIP/2.0 100 Trying", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK12ab34cd"), ("From", '"Lab Two" ' + fromD), ("To", toD), ("Call-ID", cidD), ("CSeq", "101 INVITE")]))
    toDt = toD + ";tag=4F9E2A-91"
    add(t2 + timedelta(milliseconds=1380), "in", CUBE_IP, 5060, _msg("SIP/2.0 404 Not Found", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK12ab34cd"), ("From", '"Lab Two" ' + fromD), ("To", toDt), ("Call-ID", cidD), ("CSeq", "101 INVITE"),
        ("Server", "Cisco-SIPGateway/IOS-17.9.4"), ("Reason", "Q.850;cause=1;text=\"Unallocated number\""), ("Warning", '399 10.1.1.200 "Unassigned number"')]))
    add(t2 + timedelta(milliseconds=1395), "out", CUBE_IP, 5060, _msg("ACK sip:5559999999@10.1.1.200:5060 SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.10:5060;branch=z9hG4bK12ab34cd"), ("From", '"Lab Two" ' + fromD), ("To", toDt), ("Call-ID", cidD), ("CSeq", "101 ACK")]))
    add(t2 + timedelta(milliseconds=1410), "out", PH2_IP, 50500, _msg("SIP/2.0 404 Not Found", [
        ("Via", "SIP/2.0/TCP 10.1.1.51:50500;branch=z9hG4bK77aa88bb"), ("From", fromC), ("To", toC + ";tag=cucm-9101"), ("Call-ID", cidC), ("CSeq", "101 INVITE"),
        ("Reason", "Q.850;cause=1")]))
    add(t2 + timedelta(milliseconds=1450), "in", PH2_IP, 50500, _msg("ACK sip:95559999999@10.1.1.10 SIP/2.0", [
        ("Via", "SIP/2.0/TCP 10.1.1.51:50500;branch=z9hG4bK77aa88bb"), ("From", fromC), ("To", toC + ";tag=cucm-9101"), ("Call-ID", cidC), ("CSeq", "101 ACK")]))

    out.sort(key=lambda x: x[0])
    header = f"{0:08d}.000 |{BASE.astimezone(NY).strftime('%H:%M:%S.000')} |AppInfo  |CCM SDL trace start (synthetic)\n"
    return header + "".join(e for _, e in out)


def sdl_file_info():
    end = (BASE + timedelta(minutes=12)).astimezone(NY)
    return {"name": "SDL001_200_000042.txt", "path": "/var/log/active/cm/trace/ccm/sdl/SDL001_200_000042.txt",
            "modified": end.strftime("%a %b %d %H:%M:%S ") + ("EDT" if end.dst() else "EST") + end.strftime(" %Y")}

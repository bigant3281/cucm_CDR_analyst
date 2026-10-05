#!/usr/bin/env python3
"""Unit tests for parsers not covered by the mock CUCM run. Run: python tests/test_units.py"""
import struct, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cca import cdr, sdl, sip, soap

def eq(a, b, msg):
    ok = a == b
    print(("PASS " if ok else "FAIL ") + msg + ("" if ok else f"  got {a!r} expected {b!r}"))
    if not ok: sys.exit(1)

# CDR decoding
eq(cdr.int_ip(struct.unpack("<i", bytes([10, 1, 1, 50]))[0]), "10.1.1.50", "IPv4 little-endian int decoded")
eq(cdr.int_ip(0), "", "zero IP is blank")
eq(cdr.cause_text(16), "Normal call clearing", "Q.850 16")
eq(cdr.cause_text(393216).startswith("Call split"), True, "Cisco-specific cause")
eq(cdr.decode("duration", 3725), "1:02:05", "duration")
eq(cdr.decode("origMediaCap_payloadCapability", 11), "G.729", "codec id")
eq(cdr.parse_vq("MLQK=4.5;CCR=0.1;x=y")["CCR"], 0.1, "VQ metrics")
k, recs = cdr.parse_file(b'cdrRecordType,dateTimeOrigination,pkid\nINTEGER,INTEGER,UNIQUEIDENTIFIER\n1,1700000000,abc\n')
eq((k, len(recs)), ("cdr", 1), "CDR file parse skips type row")

# SIP
raw = ("INVITE sip:1001@10.0.0.1 SIP/2.0\r\nv: SIP/2.0/UDP 10.0.0.9;branch=z9hG4bKx\r\nf: <sip:2002@10.0.0.9>;tag=a\r\nt: <sip:1001@10.0.0.1>\r\n"
       "i: abc@10.0.0.9\r\nCSeq: 1 INVITE\r\nm: <sip:2002@10.0.0.9>\r\nContent-Type: application/sdp\r\n\r\n"
       "v=0\r\no=- 1 1 IN IP4 10.0.0.9\r\ns=-\r\nc=IN IP4 10.0.0.9\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0 18 101\r\na=rtpmap:101 telephone-event/8000\r\na=sendonly\r\n")
m = sip.parse_sip(raw)
eq((m["call_id"], m["from_user"], m["to_user"], m["method"]), ("abc@10.0.0.9", "2002", "1001", "INVITE"), "compact headers")
eq(sip.sdp_summary(m["sdp"]), "audio PCMU/G729 2833 sendonly", "SDP summary")
eq(sip.parse_sip("SIP/2.0 486 Busy Here\r\nCSeq: 1 INVITE\r\n\r\n")["label"], "486 Busy Here", "response label")
eq(sip.num_match("12125551234", "5551234"), True, "number suffix match")
eq(sip.q850_from_reason('Q.850;cause=17;text="busy"'), 17, "Reason cause")

# SDL: UDP form + date rollover (line later than anchor => previous day)
text = ("00000010.001 |23:59:58.500 |AppInfo  |SIPUdp - wait_SdlReadRsp: Incoming SIP UDP message size 120 from 10.0.0.9:[5060]:\n[1,NET]\n"
        "OPTIONS sip:10.0.0.1 SIP/2.0\r\nCall-ID: u1\r\nCSeq: 1 OPTIONS\r\n\r\n\n"
        "00000011.001 |00:00:01.250 |AppInfo  |SIPUdp - wait_SdlSPISignal: Outgoing SIP UDP message to 10.0.0.9:[5060]:\n[2,NET]\n"
        "SIP/2.0 200 OK\r\nCall-ID: u1\r\nCSeq: 1 OPTIONS\r\n\r\n\n")
tz = timezone(timedelta(hours=-4))
msgs = sdl.parse_sdl_text(text, datetime(2026, 10, 6, 0, 5, tzinfo=tz), "n1")
eq(len(msgs), 2, "UDP-format SDL messages found")
eq((msgs[0]["direction"], msgs[0]["transport"], msgs[0]["remote_port"]), ("in", "UDP", 5060), "UDP incoming parsed")
eq(msgs[0]["ts"].isoformat(), "2026-10-06T03:59:58.500000+00:00", "23:59:58 belongs to the previous day (anchor 00:05)")
eq(msgs[1]["ts"].isoformat(), "2026-10-06T04:00:01.250000+00:00", "after-midnight line stays on anchor day")
eq(sdl.parse_modified("Fri Jul 22 15:11:52 PDT 2022", timezone.utc).isoformat(), "2022-07-22T15:11:52-07:00", "modifiedDate parsed")
eq(sdl.node_from_path("cucm-sub1/cm/trace/ccm/sdl/SDL001_1.txt.gz"), "cucm-sub1", "node from RTMT zip path")

# Legacy DIME
def rec(flags, data, typ=b"", id_=b""):
    p = lambda n: (-n) % 4
    return (bytes([flags, 0]) + struct.pack(">HHH", 0, len(id_), len(typ)) + struct.pack(">I", len(data))
            + id_ + b"\0" * p(len(id_)) + typ + b"\0" * p(len(typ)) + data + b"\0" * p(len(data)))
dime = rec(0b00001000 | 0b100, b"<soap/>", b"text/xml") + rec(0b00000010, b"HELLO LOG FILE", b"application/octet-stream")
eq(soap.extract_attachment("application/dime", dime), b"HELLO LOG FILE", "DIME attachment extracted")
print("\nALL UNIT CHECKS PASSED")

#!/usr/bin/env python3
"""End-to-end: mock CUCM + app (real HTTP, real SFTP push) -> assert the analysis."""
import json, sys, tempfile, threading, time
from pathlib import Path
import requests, uvicorn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tests"))
import mock_cucm, app as appmod  # noqa: E402

PUB, SUB, SFTP, WEB = 9443, 9444, 2222, 8765
mock_cucm.serve(PUB, SFTP, "pub"); mock_cucm.serve(SUB, SFTP, "sub")
data = tempfile.mkdtemp(prefix="cca_e2e_")
app = appmod.create_app(data)
srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=WEB, log_level="error"))
threading.Thread(target=srv.run, daemon=True).start()
time.sleep(1.2)
B = f"http://127.0.0.1:{WEB}"
ok_count = 0
def check(cond, msg):
    global ok_count
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: sys.exit(1)
    ok_count += 1
def job(j):
    while True:
        v = requests.get(f"{B}/api/jobs/{j['id']}").json()
        if v["state"] != "running": return v
        time.sleep(0.3)

# settings
r = requests.post(f"{B}/api/settings", json={
    "cucm": {"host": f"127.0.0.1:{PUB}", "user": "axluser", "server_tz": "America/New_York",
             "node_addresses": {"cucm-pub": f"127.0.0.1:{PUB}", "cucm-sub1": f"127.0.0.1:{SUB}"}},
    "cdr_delivery": {"mode": "embedded", "listen_port": SFTP, "advertise_host": "127.0.0.1", "username": "cdrpush"},
    "secrets": {"cucm_password": "secret", "sftp_password": "pushpw"}}).json()
check(r["receiver"]["running"], "embedded SFTP receiver running")
t = requests.post(f"{B}/api/test").json()
check(t["cdr_on_demand"].startswith("OK"), "CDR on Demand reachable: " + t["cdr_on_demand"])
check(t["log_collection"].startswith("OK"), "Log Collection reachable: " + t["log_collection"])

# CDR pull
j = requests.post(f"{B}/api/cdr/fetch", json={"start": "2026-10-05T19:00:00Z", "end": "2026-10-05T20:00:00Z"}).json()
v = job(j); print("\n".join(v["log"]))
check(v["state"] == "done" and v["result"]["files"] == 2, "CDR+CMR files pulled over SOAP+SFTP")
st = requests.get(f"{B}/api/status").json()["stats"]
check(st["cdr"] == 3 and st["cmr"] == 4, f"3 CDRs / 4 CMRs indexed ({st['cdr']}/{st['cmr']})")
calls = requests.get(f"{B}/api/calls").json()["calls"]
check(len(calls) == 3, "3 calls listed")
check(len(requests.get(f"{B}/api/calls", params={"number": "5551234567"}).json()["calls"]) == 1, "number search")
check(len(requests.get(f"{B}/api/calls", params={"failed": "true"}).json()["calls"]) == 1, "failed filter (only call 2 is abnormal in the CDR)")
k1 = [c for c in calls if c["calling"] == "2001" and c["final_called"] == "15551234567"][0]["call_key"]
k2 = [c for c in calls if c["calling"] == "2002"][0]["call_key"]
k3 = [c for c in calls if c["final_called"] == "2002" and c["calling"] == "2001"][0]["call_key"]

# before SDL: no ladder
d = requests.get(f"{B}/api/call", params={"key": k1}).json()
check(not d["ladder"]["has_traces"], "no traces yet")

# SDL pull
j = requests.post(f"{B}/api/call/sdl", json={"key": k1}).json()
v = job(j); print("\n".join(v["log"]))
check(v["state"] == "done" and v["result"]["sip_added"] > 30, f"SDL pulled, {v['result']['sip_added']} SIP messages")

# call 1
d = requests.get(f"{B}/api/call", params={"key": k1}).json()
L = d["ladder"]
sel = [x for x in L["dialogs"] if x["selected"]]
check(len(sel) == 2, f"call 1: both dialogs (phone leg + trunk leg) auto-selected ({len(sel)}); all={[(x['call_id'][:8], x['score'], x['why']) for x in L['dialogs']]}")
check(not any("opt-ping" in x["call_id"] for x in L["dialogs"]), "OPTIONS ping not matched")
ms = [m for m in L["messages"] if m["call_id"] in {x["call_id"] for x in sel}]
check(any(m["retrans"] for m in ms), "retransmitted INVITE detected")
check([m["label"] for m in ms if m["method"] in ("INVITE", "BYE") and not m["retrans"]][:2] == ["INVITE (SDP)", "INVITE (SDP)"], "INVITE order")
check(any(m["label"] == "180 Ringing" for m in ms) and any(m["label"].startswith("200 OK") for m in ms), "ringing + answer present")
titles = " | ".join(f["title"] for f in d["findings"])
print("\n".join(f"  [{f['level']}] {f['title']}  {f['detail']}" for f in d["findings"]))
check("retransmission" in titles.lower(), "finding: retransmission")
check("Post-dial delay" in titles, "finding: PDD")
check("Hold" in titles, "finding: hold detected")
check("lost 59 packets" in titles, "finding: packet loss from CMR")
check("MOS-LQK 3.40" in titles, "finding: MOS")
check("Call ended by CUBE-TRUNK" in titles, "finding: call ended by the far end (CUBE)")
check("Resume at" in titles, "finding: resume after hold")
parts = {p["name"] for p in L["participants"].values()}
check({"SEP001122334455", "cucm-pub"} <= parts, f"participants named from Contact devicename/CDR: {sorted(parts)}")

# call 2
d2 = requests.get(f"{B}/api/call", params={"key": k2}).json()
t2 = " | ".join(f["title"] + " " + f["detail"] for f in d2["findings"])
print("\n".join(f"  [{f['level']}] {f['title']}  {f['detail']}" for f in d2["findings"]))
check("404 Not Found" in t2 and "Unallocated" in t2, "call 2: 404 with Q.850 cause 1 explained")
check(len([x for x in d2["ladder"]["dialogs"] if x["selected"]]) == 2, "call 2: both dialogs matched")

# call 3 (internal): CDR/CMR only; one-way audio from CMR
d3 = requests.get(f"{B}/api/call", params={"key": k3}).json()
t3 = " | ".join(f["title"] for f in d3["findings"])
check("received no RTP" in t3, "call 3: one-way audio from CMR")

# export, dialog toggle, upload
html = requests.get(f"{B}/api/call/export", params={"key": k1}).text
check("renderCall" in html and "svg" in html.lower() and len(html) > 30000, "HTML export is self-contained")
d1b = requests.get(f"{B}/api/call", params={"key": k1, "dialogs": sel[0]["call_id"]}).json()
check(sum(x["selected"] for x in d1b["ladder"]["dialogs"]) == 1, "dialog selection honoured")
# window pull: CDR + SDL together (SDL stored raw on disk, survives CUCM rotation)
import os
requests.post(f"{B}/api/clear", json={"what": "sip"})
check(requests.get(f"{B}/api/status").json()["stats"]["sip"] == 0, "SIP data cleared")
j = requests.post(f"{B}/api/cdr/fetch", json={"start": "2026-10-05T19:00:00Z", "end": "2026-10-05T20:00:00Z", "sdl": True}).json()
v = job(j); print("\n".join(v["log"]))
check(v["state"] == "done" and v["result"].get("sip_added", 0) > 30, f"window pull fetched SDL with the CDR step ({v['result']})")
check(v["log"][0].startswith(tuple("0123456789")) and "Step 1/2: SDL" in " ".join(v["log"][:2]), "SDL pulled first")
check(requests.get(f"{B}/api/status").json()["stats"]["cdr"] == 3, "CDRs not duplicated on re-fetch")
sdl_files = [p for p in Path(data, "sdl").rglob("*.txt")]
check(len(sdl_files) >= 1, f"raw SDL file kept on disk: {sdl_files[0].relative_to(data) if sdl_files else None}")
d = requests.get(f"{B}/api/call", params={"key": k1}).json()
check(len([x for x in d["ladder"]["dialogs"] if x["selected"]]) == 2, "ladder ready without a per-call pull")
j = requests.post(f"{B}/api/call/sdl", json={"key": k1}).json(); v = job(j)
check(v["state"] == "done" and v["result"]["sip_added"] == 0, "per-call pull is a no-op once the window was pulled")
# SDL failure must not block the CDR step
j = requests.post(f"{B}/api/settings", json={"cucm": {"node_addresses": {"cucm-pub": "127.0.0.1:1", "cucm-sub1": "127.0.0.1:1"}}})
requests.post(f"{B}/api/clear", json={"what": "cdr"})
j = requests.post(f"{B}/api/cdr/fetch", json={"start": "2026-10-05T19:00:00Z", "end": "2026-10-05T20:00:00Z", "sdl": True}).json(); v = job(j)
check(requests.get(f"{B}/api/status").json()["stats"]["cdr"] == 3, "CDRs still loaded when SDL nodes are unreachable")
up = requests.post(f"{B}/api/upload", files=[("files", ("sdl.txt", (ROOT / "tests" / "out" / "SDL.txt").read_bytes()))],
                   data={"node": "uploaded-node", "trace_date": "2026-10-05"}).json() if (ROOT / "tests" / "out" / "SDL.txt").exists() else None
print(f"\nALL {ok_count} CHECKS PASSED")
if "--serve" in sys.argv:
    print("serving on", B, flush=True); import threading as _t; _t.Event().wait()

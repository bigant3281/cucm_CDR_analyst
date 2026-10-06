# CUCM Call Analyzer

A local web app that pulls **CDR/CMR** and **CallManager SDL traces** from Cisco Unified CM and shows any call as:

* decoded CDR details (parties, devices, IPs, codecs, Q.850 / Cisco termination causes, redirect reason, who hung up)
* CMR voice quality per leg (loss, jitter, latency, MOS-LQK)
* an interactive **SIP ladder diagram** (click a message for the full SIP + SDP)
* plain-language **findings** (404/486/503 explained, post-dial delay, retransmissions, hold/resume, codec mismatch, one-way audio, missing ACK, who ended the call)
* a self-contained **HTML report** you can attach to a ticket

Read-only against CUCM: it only lists and downloads.

## Quick start

```bash
pip install -r requirements.txt
python app.py                       # http://127.0.0.1:8080
```

1. **Settings** → publisher host, application user, password, server timezone → *Save & test connection*.
2. **Data** → pick a time window → *Fetch files* (or drop CDR/CMR/SDL files onto the upload box).
3. **Calls** → search by number / device / time → open a call.
4. On the call page → *Pull SDL traces from CUCM* → the ladder appears.

Passwords are kept in memory only (or set `CUCM_PASSWORD`, `CCA_SFTP_PASSWORD`, `CCA_EXT_SFTP_PASSWORD`). Everything else lives in `data/` (settings, SQLite index, downloaded files).

## CUCM requirements

| Need | Detail |
|---|---|
| Application user | Roles **Standard CCM Admin Users** and **Standard RealtimeAndTraceCollection** |
| CDR | CDR Repository Manager + CDR on Demand service running (Serviceability). CDRs enabled (service parameters *CDR Enabled Flag* and *CDR Log Calls With Zero Duration Flag* = True; CMRs: *Call Diagnostics Enabled* = Enabled) |
| SDL SIP messages | Trace Configuration → Cisco CallManager → Debug Trace Level ≥ **Detailed**, *SIP Call Processing Trace* on |
| Network | HTTPS 8443 from this machine to every CUCM node; SFTP from the publisher back to this machine (see below) |

## How the data gets here

**CDR on Demand cannot return file contents in the SOAP reply.** `get_file` makes CUCM open an SFTP connection *to you* and upload the file. So the app has two modes (Settings → *How CUCM delivers CDR files*):

* **Built-in SFTP receiver** (default): the app runs a small single-user SFTP server. CUCM always connects to **port 22**, so either run with rights to listen on 22, or forward 22 → the listen port. Set *Address CUCM uses to reach this app* to this machine's IP as the publisher sees it.
* **Your own SFTP server**: enter its host/user/password/dir. If it writes to a folder this machine can read, give that path; otherwise the app downloads the file over SFTP.

**SDL traces** use the Log Collection API (`selectLogFiles` with `DownloadtoClient`, then `GetOneFile`) against every node: it lists SDL files modified in the call window and downloads only those. Node names that don't resolve in DNS can be mapped under *Node addresses*.

SDL lines carry a time of day only, so each file is dated from its modified time (an entry later than that time is placed on the previous day). Set *Server timezone* correctly or ladders will be offset from the CDR.

**SFTP host key:** CUCM's SFTP client negotiates the legacy SHA-1 `ssh-rsa` host key, which current paramiko releases no longer offer. The built-in receiver re-enables it (see `cca/sftp_receiver.py`), so `Incompatible ssh peer (no acceptable host key)` should not occur. If you see a *kex* or *cipher* error instead, send the log line; those can be re-enabled the same way.

## Matching SIP dialogs to a call

SDL traces contain every SIP dialog on the node. A dialog is tied to the CDR call when:

* its Call-ID equals the CDR `IncomingProtocolCallRef` / `OutgoingProtocolCallRef` (SIP trunks and SIP phones), or
* the INVITE carries the call's calling **and** called number, or
* a SIP phone's `devicename` Contact parameter / signaling IP matches a CDR device and the INVITE is within 15 s of a leg start,
* plus any dialog joined by `Replaces` / `Refer-To`.

Each dialog shows *why* it matched; tick or untick dialogs to redraw the ladder and findings. Weak matches are listed but unticked.

## Tests

```bash
python tests/test_units.py     # parsers
python tests/e2e.py            # mock CUCM (SOAP + real SFTP push) -> full analysis, 28 checks
python tests/e2e.py --serve    # same, then leave the UI running on :8765 with sample data
python tests/mock_cucm.py      # just the mock CUCM (pub :9443, sub :9444; user axluser / secret)
```

To point the app at the mock: host `127.0.0.1:9443`, user `axluser`, password `secret`, SFTP receiver port 2222 (`--sftp-port`), node addresses `cucm-pub=127.0.0.1:9443`, `cucm-sub1=127.0.0.1:9444`.

## Layout

```
app.py              FastAPI app + CLI
cca/soap.py         CDRonDemand, LogCollection, DimeGetFile clients (raw XML, retries on throttling)
cca/sftp_receiver.py  built-in SFTP server (paramiko)
cca/cdr.py          CDR/CMR parsing and decoding tables
cca/sdl.py          SIP message extraction from SDL traces
cca/sip.py          SIP/SDP parser
cca/correlate.py    dialog <-> call matching and ladder model
cca/analysis.py     findings
cca/store.py        SQLite index
cca/service.py      background jobs (CDR pull, SDL pull, uploads)
static/             UI (callview.js draws the SVG ladder; shared with the HTML export)
tests/              sample data generator, mock CUCM, tests
```

## Known limits

* SIP only (SCCP/MGCP/H.323 signaling is not drawn; their CDR/CMR data still appears).
* CDR on Demand allows 1 h per request and ~10 `get_file` per minute; large windows are paced automatically.
* Written against the documented CUCM 12.5-15 Serviceability SOAP formats and tested against a mock, **not yet against a live cluster**. If a SOAP call fails on yours, the job log shows CUCM's fault string.

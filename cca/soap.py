"""Read-only CUCM Serviceability SOAP clients.

* CDRonDemand  : get_file_list / get_file   (CDR Repository node = publisher)
* LogCollection: listNodeServiceLogs / selectLogFiles (JobType=DownloadtoClient only)
* DimeGetFile  : GetOneFile (file returned as MIME/XOP or legacy DIME attachment)

Envelopes are sent as raw XML (no WSDL needed). Throttling faults and HTTP
503/429 are retried with backoff.
"""
from __future__ import annotations

import email
import email.policy
import logging
import re
import struct
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import requests
import urllib3

log = logging.getLogger("cca.soap")
NS = "http://schemas.cisco.com/ast/soap"

CDR_PATH = "/CDRonDemandService2/services/CDRonDemandService"
LOG_PATH = "/logcollectionservice2/services/LogCollectionPortTypeService"
DIME_PATH = "/logcollectionservice/services/DimeGetFileService"

THROTTLE_HINTS = ("exceeded", "rate", "too many", "throttl", "maximum", "try again")
DISPATCH_HINTS = ("epr", "operation not found", "no such operation", "no handler",
                  "soapaction", "unable to find", "dispatch")


class SoapError(Exception):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _envelope(body: str) -> str:
    return ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:soap="{NS}"><soapenv:Header/><soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>')


def _fault(xml_text: str) -> str | None:
    m = re.search(r"<(?:\w+:)?faultstring[^>]*>(.*?)</(?:\w+:)?faultstring>", xml_text, re.S)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return None


class CucmSoap:
    def __init__(self, host: str, user: str, password: str, verify=False,
                 timeout: int = 90, port: int = 8443):
        if not host or not user:
            raise SoapError("CUCM host and user are required (Settings)")
        if not password:
            raise SoapError("CUCM password is not set (Settings or CUCM_PASSWORD)")
        self.host, self.port, self.timeout = host, port, timeout
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.verify = verify
        if verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def url(self, path: str, host: str | None = None) -> str:
        h = host or self.host
        if h.count(":") == 1:          # "host:port" override (lab / port-forwarded CUCM)
            return f"https://{h}{path}"
        if ":" in h and not h.startswith("["):   # bare IPv6
            h = f"[{h}]"
        return f"https://{h}:{self.port}{path}"

    # ------------------------------------------------------------------
    def _post(self, url: str, body: str, op: str, svc: str, raw: bool = False,
              retries: int = 5):
        """POST a SOAP body. Tries a few SOAPAction spellings because CUCM
        releases (Axis1 vs Axis2) dispatch differently."""
        actions = [op, f"http://schemas.cisco.com/ast/soap/action/#{svc}#{op}", '""']
        data = _envelope(body).encode()
        delay = 4.0
        ai = 0
        last = ""
        for attempt in range(retries + len(actions)):
            hdr = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": actions[ai],
                   "Accept": ("text/xml, multipart/related, application/dime, */*" if raw
                              else "text/xml, application/soap+xml")}
            try:
                r = self.s.post(url, data=data, headers=hdr, timeout=self.timeout, verify=self.s.verify)
            except requests.exceptions.SSLError as e:
                raise SoapError(f"TLS error talking to {url}: {e}. Set verify_tls to false or give a CA bundle.")
            except requests.RequestException as e:
                last = f"{type(e).__name__}: {e}"
                # Connection refused / unreachable is not throttling: retry once quickly, then fail.
                if attempt < 1:
                    time.sleep(2)
                    continue
                raise SoapError(f"cannot reach {url}: {last}")
            if r.status_code == 401:
                raise SoapError("authentication failed (401). Check the application user and its roles.")
            if r.status_code == 403:
                raise SoapError("access denied (403). The user needs Standard CCM Admin Users + Standard Serviceability.")
            if r.status_code == 404:
                raise SoapError(f"{url} returned 404 (service not available on this node/version)")
            ctype = r.headers.get("Content-Type", "")
            text = _soap_text(ctype, r.content, r.text) if not raw else (
                "" if ("multipart" in ctype or "dime" in ctype) else r.text)
            flt = _fault(text) if text else None
            if r.status_code in (429, 503) or (flt and any(h in flt.lower() for h in THROTTLE_HINTS)):
                last = flt or f"HTTP {r.status_code}"
                log.warning("throttled by %s (%s); retrying in %.0fs", self.host, last, delay)
                time.sleep(delay); delay = min(delay * 2, 60)
                continue
            if flt and any(h in flt.lower() for h in DISPATCH_HINTS) and ai < len(actions) - 1:
                ai += 1
                continue
            if flt:
                raise SoapError(flt)
            if r.status_code >= 400:
                raise SoapError(f"HTTP {r.status_code}: {r.text[:300]}")
            return r if raw else text
        raise SoapError(f"gave up after retries: {last}")

    # ---------------------------------------------------------------- CDR
    def cdr_get_file_list(self, start_utc: datetime, end_utc: datetime,
                          include_sent: bool = True) -> list[str]:
        """List CDR/CMR files between two UTC datetimes (any span; split into
        <=1h requests, and continued when a request hits the 1300-file cap)."""
        out: list[str] = []
        cur = start_utc
        while cur < end_utc:
            nxt = min(cur.replace(second=0, microsecond=0) + _HOUR, end_utc)
            if nxt <= cur:
                nxt = cur + _MINUTE
            body = (f"<soap:get_file_list><soap:in0>{_ymdhm(cur)}</soap:in0>"
                    f"<soap:in1>{_ymdhm(nxt)}</soap:in1>"
                    f"<soap:in2>{'True' if include_sent else 'False'}</soap:in2></soap:get_file_list>")
            try:
                text = self._post(self.url(CDR_PATH), body, "get_file_list", "CDRonDemand")
            except SoapError as e:
                if "no file" in str(e).lower():
                    cur = nxt
                    continue
                raise
            names = [n for n in re.findall(r"<(?:\w+:)?FileName[^>]*>([^<]+)<", text)]
            out.extend(names)
            if len(names) >= 1300:  # continue from the last returned file's time
                ts = _file_ts(names[-1])
                cur = ts if ts and ts > cur else nxt
            else:
                cur = nxt
        seen, uniq = set(), []
        for n in out:
            if n not in seen:
                seen.add(n); uniq.append(n)
        return uniq

    def cdr_get_file(self, filename: str, host: str, user: str, password: str,
                     remote_dir: str, sftp: bool = True) -> None:
        body = ("<soap:get_file>"
                f"<soap:in0>{escape(host)}</soap:in0><soap:in1>{escape(user)}</soap:in1>"
                f"<soap:in2>{escape(password)}</soap:in2><soap:in3>{escape(remote_dir)}</soap:in3>"
                f"<soap:in4>{escape(filename)}</soap:in4><soap:in5>{'True' if sftp else 'False'}</soap:in5>"
                "</soap:get_file>")
        self._post(self.url(CDR_PATH), body, "get_file", "CDRonDemand")

    # --------------------------------------------------------- Log collection
    def list_node_service_logs(self) -> dict[str, list[str]]:
        body = "<soap:listNodeServiceLogs><soap:ListRequest></soap:ListRequest></soap:listNodeServiceLogs>"
        text = self._post(self.url(LOG_PATH), body, "listNodeServiceLogs", "LogCollectionPort")
        root = _xml(text, "listNodeServiceLogs")
        out: dict[str, list[str]] = {}
        for el in root.iter():
            if _local(el.tag) == "listNodeServiceLogsReturn":
                name, items = "", []
                for ch in el:
                    if _local(ch.tag) == "name":
                        name = (ch.text or "").strip()
                    elif _local(ch.tag) == "ServiceLog":
                        items = [(i.text or "").strip() for i in ch if (i.text or "").strip()]
                if name:
                    out[name] = items
        return out

    def select_log_files(self, node_host: str, services: list[str],
                         from_utc: datetime, to_utc: datetime) -> list[dict]:
        """List log files on ONE node whose time falls in the window (GMT)."""
        items = "".join(f"<soap:item>{escape(s)}</soap:item>" for s in services)
        body = ("<soap:selectLogFiles><soap:FileSelectionCriteria>"
                f"<soap:ServiceLogs>{items}</soap:ServiceLogs><soap:SystemLogs/>"
                "<soap:SearchStr></soap:SearchStr><soap:Frequency>OnDemand</soap:Frequency>"
                "<soap:JobType>DownloadtoClient</soap:JobType>"
                f"<soap:ToDate>{_gmt(to_utc)}</soap:ToDate><soap:FromDate>{_gmt(from_utc)}</soap:FromDate>"
                "<soap:TimeZone>Client: (GMT+0:0)Greenwich Mean Time-Europe/London</soap:TimeZone>"
                "<soap:RelText>None</soap:RelText><soap:RelTime>0</soap:RelTime>"
                "<soap:Port></soap:Port><soap:IPAddress></soap:IPAddress><soap:UserName></soap:UserName>"
                "<soap:Password></soap:Password><soap:ZipInfo>false</soap:ZipInfo>"
                "<soap:RemoteFolder></soap:RemoteFolder>"
                "</soap:FileSelectionCriteria></soap:selectLogFiles>")
        text = self._post(self.url(LOG_PATH, node_host), body, "selectLogFiles", "LogCollectionPort")
        root = _xml(text, "selectLogFiles")
        files = []
        for el in root.iter():
            if _local(el.tag) == "File":
                d = {_local(c.tag): (c.text or "").strip() for c in el}
                if d.get("absolutepath"):
                    files.append({"name": d.get("name", ""), "path": d["absolutepath"],
                                  "size": int(d.get("filesize") or 0),
                                  "modified": d.get("modifiedDate", "")})
        return files

    def get_one_file(self, node_host: str, abs_path: str) -> bytes:
        body = f"<soap:FileName>{escape(abs_path)}</soap:FileName>"
        r = self._post(self.url(DIME_PATH, node_host), body, "GetOneFile", "LogCollectionPort", raw=True)
        return extract_attachment(r.headers.get("Content-Type", ""), r.content)


# ---------------------------------------------------------------------------
from datetime import timedelta  # noqa: E402

_HOUR = timedelta(hours=1)
_MINUTE = timedelta(minutes=1)


def _ymdhm(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y%m%d%H%M")


def _gmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%m/%d/%y %I:%M %p")


def _file_ts(name: str) -> datetime | None:
    """cdr_StandAloneCluster_01_202207112241_0 -> 2022-07-11 22:41 UTC"""
    m = re.search(r"_(\d{12})_", name)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y%m%d%H%M").replace(tzinfo=timezone.utc)


def _soap_text(content_type: str, content: bytes, text: str) -> str:
    """XML of a SOAP reply, unwrapping a multipart/MTOM envelope if CUCM sent one."""
    if "multipart" not in content_type.lower():
        return text
    try:
        msg = email.message_from_bytes(b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + content,
                                       policy=email.policy.HTTP)
        for part in msg.walk():
            if not part.is_multipart() and "xml" in part.get_content_type():
                return part.get_payload(decode=True).decode("utf-8", "replace")
    except Exception:
        pass
    return text


def _xml(text: str, op: str):
    if not (text or "").strip():
        raise SoapError(f"{op}: CUCM returned an empty reply (HTTP 200 with no body). "
                        "Check the user has the Standard RealtimeAndTraceCollection role and that the "
                        "Cisco Log Partition Monitoring / Cisco Trace Collection services are running on the node.")
    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        snippet = re.sub(r"\s+", " ", text[:300])
        raise SoapError(f"{op}: reply was not valid XML ({e}). Start of reply: {snippet}")


def extract_attachment(content_type: str, payload: bytes) -> bytes:
    """Pull the binary file out of a GetOneFile response (MIME/XOP, or DIME)."""
    ct = content_type.lower()
    if "multipart" in ct:
        msg = email.message_from_bytes(b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + payload,
                                       policy=email.policy.HTTP)
        parts = [p for p in msg.walk() if not p.is_multipart()]
        bins = [p for p in parts if "xml" not in p.get_content_type()]
        if bins:
            return bins[0].get_payload(decode=True) or b""
        raise SoapError("GetOneFile: no attachment in MIME response")
    if "dime" in ct or (payload[:1] and (payload[0] >> 3) == 1 and len(payload) > 12):
        recs = _dime_records(payload)
        if len(recs) >= 2:
            return recs[1]
        if recs:
            return recs[0]
    flt = _fault(payload.decode("utf-8", "replace"))
    if flt:
        raise SoapError(flt)
    raise SoapError(f"GetOneFile: unexpected response type {content_type!r}")


def _dime_records(buf: bytes) -> list[bytes]:
    """Legacy DIME: concatenate chunked records; first record is the SOAP part."""
    out, cur, i = [], b"", 0
    while i + 12 <= len(buf):
        b0 = buf[i]
        cf = bool(b0 & 0x01)
        me = bool(b0 & 0x02)
        opt_len, id_len, type_len = struct.unpack(">HHH", buf[i + 2:i + 8])
        data_len = struct.unpack(">I", buf[i + 8:i + 12])[0]
        p = i + 12
        pad = lambda n: (n + 3) & ~3  # noqa: E731
        p += pad(opt_len) + pad(id_len) + pad(type_len)
        cur += buf[p:p + data_len]
        p += pad(data_len)
        if not cf:
            out.append(cur); cur = b""
        i = p
        if me and not cf:
            break
    return out

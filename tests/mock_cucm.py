#!/usr/bin/env python3
"""A tiny fake CUCM serving the Serviceability SOAP formats the app uses.

  python tests/mock_cucm.py --port 9443 --sftp-port 2222

CDR get_file really pushes the file to the SFTP server named in the request
(like CUCM does, except CUCM always uses port 22; --sftp-port overrides).
"""
import argparse, os, re, ssl, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import base64

sys.path.insert(0, str(Path(__file__).parent))
import sample_data as SD  # noqa: E402

NS = "http://schemas.cisco.com/ast/soap"
USER, PASS = "axluser", "secret"
STATE = {"sftp_port": 22, "hits": []}
(CDR_NAME, CDR_DATA), (CMR_NAME, CMR_DATA) = SD.build_cdr_cmr()
SDL_TEXT = SD.build_sdl().encode()
SDL_INFO = SD.sdl_file_info()
FILES = {CDR_NAME: CDR_DATA, CMR_NAME: CMR_DATA}


def env(body, ns=True):
    return (f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>').encode()


def fault(msg):
    return env(f"<soapenv:Fault><faultcode>soapenv:Server</faultcode><faultstring>{msg}</faultstring></soapenv:Fault>")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def _send(self, code, data, ctype="text/xml; charset=utf-8"):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode()
        auth = self.headers.get("Authorization", "")
        ok = auth.startswith("Basic ") and base64.b64decode(auth[6:]).decode() == f"{USER}:{PASS}"
        if not ok:
            return self._send(401, b"unauthorized", "text/plain")
        STATE["hits"].append((self.path, re.search(r"<soap:(\w+)", body).group(1) if re.search(r"<soap:(\w+)", body) else "?"))
        p = self.path
        if "CDRonDemand" in p:
            if "<soap:get_file_list>" in body:
                a = re.search(r"<soap:in0>(\d+)</soap:in0><soap:in1>(\d+)</soap:in1>", body)
                lo, hi = a.group(1), a.group(2)
                names = [f for f in FILES if lo <= re.search(r"_(\d{12})_", f).group(1) < hi]
                if not names:
                    return self._send(500, fault("No file found within the specified time range"))
                items = "".join(f"<ns1:FileName>{f}</ns1:FileName>" for f in names)
                return self._send(200, env(f'<ns1:get_file_listResponse xmlns:ns1="{NS}"><ns1:get_file_listReturn>{items}</ns1:get_file_listReturn></ns1:get_file_listResponse>'))
            if "<soap:get_file>" in body:
                g = lambda k: re.search(rf"<soap:in{k}>(.*?)</soap:in{k}>", body).group(1)
                host, user, pw, rdir, name = g(0), g(1), g(2), g(3), g(4)
                if name not in FILES:
                    return self._send(500, fault("file not found"))
                import paramiko
                try:
                    t = paramiko.Transport((host, STATE["sftp_port"])); t.connect(username=user, password=pw)
                    sf = paramiko.SFTPClient.from_transport(t)
                    with sf.open(rdir.rstrip("/") + "/" + name, "wb") as f:
                        f.write(FILES[name])
                    t.close()
                except Exception as e:
                    return self._send(500, fault(f"The FTP or SFTP connection to the remote node is not established: {e}"))
                return self._send(200, env(f'<ns1:get_fileResponse xmlns:ns1="{NS}"/>'))
        if "logcollectionservice2" in p:
            if "<soap:listNodeServiceLogs>" in body:
                def node(n): return f'<ns1:listNodeServiceLogsReturn><ns1:name>{n}</ns1:name><ns1:ServiceLog><ns1:item>Cisco CallManager</ns1:item><ns1:item>Cisco CTIManager</ns1:item></ns1:ServiceLog></ns1:listNodeServiceLogsReturn>'
                return self._send(200, env(f'<ns1:listNodeServiceLogsResponse xmlns:ns1="{NS}">{node("cucm-pub")}{node("cucm-sub1")}</ns1:listNodeServiceLogsResponse>'))
            if "<soap:selectLogFiles>" in body:
                if "DownloadtoClient" not in body:
                    return self._send(500, fault("mock only supports DownloadtoClient"))
                # only the publisher has traces; mimic CUCM answering for the node it is addressed as
                files = (f'<ns1:File><ns1:name>{SDL_INFO["name"]}</ns1:name><ns1:absolutepath>{SDL_INFO["path"]}</ns1:absolutepath>'
                         f'<ns1:filesize>{len(SDL_TEXT)}</ns1:filesize><ns1:modifiedDate>{SDL_INFO["modified"]}</ns1:modifiedDate></ns1:File>')
                if STATE.get("node_of", {}).get(self.server.server_port) == "sub":
                    files = ""
                return self._send(200, env(f'<ns1:selectLogFilesResponse xmlns:ns1="{NS}"><ns1:ResultSet><ns1:SchemaFileSelectionResult><ns1:Node><ns1:name/><ns1:ServiceList><ns1:ServiceLogs><ns1:SetOfFiles>{files}</ns1:SetOfFiles></ns1:ServiceLogs></ns1:ServiceList></ns1:Node></ns1:SchemaFileSelectionResult></ns1:ResultSet></ns1:selectLogFilesResponse>'))
        if "DimeGetFileService" in p:
            if "<soap:GetOneFile>" not in body:   # Axis dispatches on the first Body element
                first = re.search(r"<soap:Body>\s*<soap:(\w+)|<soapenv:Body>\s*<soap:(\w+)", body)
                return self._send(500, fault(f"No such operation '{(first.group(1) or first.group(2)) if first else '?'}'"))
            fn = re.search(r"<soap:FileName>(.*?)</soap:FileName>", body).group(1)
            if fn != SDL_INFO["path"]:
                return self._send(500, fault("File not found: " + fn))
            b = "MIMEBoundaryurn_uuid_TEST"
            soap = (f'<?xml version=\'1.0\' encoding=\'UTF-8\'?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
                    f'<ns1:GetOneFileReturn xmlns:ns1="{NS}"><xop:Include href="cid:1.urn:uuid:T@apache.org" xmlns:xop="http://www.w3.org/2004/08/xop/include"/></ns1:GetOneFileReturn></soapenv:Body></soapenv:Envelope>')
            payload = (f'--{b}\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-Transfer-Encoding: binary\r\nContent-ID: <0.urn:uuid:T@apache.org>\r\n\r\n{soap}\r\n'
                       f'--{b}\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\nContent-ID: <1.urn:uuid:T@apache.org>\r\n\r\n').encode() + SDL_TEXT + f'\r\n--{b}--\r\n'.encode()
            return self._send(200, payload, f'multipart/related; boundary={b}; type="application/xop+xml"; start="<0.urn:uuid:T@apache.org>"; start-info="text/xml"')
        self._send(404, b"not found", "text/plain")


def serve(port, sftp_port, node_kind=None):
    STATE["sftp_port"] = sftp_port
    d = Path(tempfile.gettempdir()) / "mockcucm"; d.mkdir(exist_ok=True)
    crt, key = d / "c.pem", d / "k.pem"
    if not crt.exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                        "-days", "30", "-subj", "/CN=mock-cucm"], check=True, capture_output=True)
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    STATE.setdefault("node_of", {})[port] = node_kind
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, default=9443); ap.add_argument("--sftp-port", type=int, default=22)
    ap.add_argument("--sub-port", type=int, default=9444)
    a = ap.parse_args()
    serve(a.port, a.sftp_port, "pub"); serve(a.sub_port, a.sftp_port, "sub")
    print(f"mock CUCM pub on https://127.0.0.1:{a.port}  sub on :{a.sub_port}  (user {USER}/{PASS})")
    threading.Event().wait()

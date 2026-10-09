"""Orchestration: background jobs for CDR / SDL collection, uploads, node addressing."""
from __future__ import annotations

import logging
import shutil
import socket
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import analysis, correlate
from . import sdl as S
from .config import Config
from .soap import CucmSoap, SoapError
from .store import Store

log = logging.getLogger("cca.service")


class Job:
    def __init__(self, kind: str, title: str):
        self.id = uuid.uuid4().hex[:10]
        self.kind, self.title = kind, title
        self.state = "running"   # running | done | error
        self.progress = 0.0
        self.lines: list[str] = []
        self.result: dict = {}
        self.started = time.time()
        self.finished: float | None = None
        self._base, self._span = 0.0, 1.0

    def phase(self, base: float, span: float):
        self._base, self._span = base, span

    def prog(self, frac: float):
        self.progress = self._base + self._span * max(0.0, min(1.0, frac))

    def log(self, msg: str, level=logging.INFO):
        stamp = datetime.now().strftime("%H:%M:%S")
        self.lines.append(f"{stamp} {msg}")
        log.log(level, "[%s] %s", self.kind, msg)

    def view(self) -> dict:
        return {"id": self.id, "kind": self.kind, "title": self.title, "state": self.state,
                "progress": round(self.progress, 3), "log": self.lines[-200:], "result": self.result,
                "started": self.started, "finished": self.finished}


class Service:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.store = Store(cfg.db_path)
        self.jobs: dict[str, Job] = {}
        self.receiver = None
        self._inbox_events: dict[str, threading.Event] = {}

    # ------------------------------------------------------------------ infra
    def server_tz(self):
        try:
            return ZoneInfo(self.cfg.get("cucm", "server_tz") or "UTC")
        except Exception:
            return timezone.utc

    def soap(self) -> CucmSoap:
        c = self.cfg.settings["cucm"]
        return CucmSoap(c["host"], c["user"], self.cfg.secrets.get("cucm_password", ""), verify=c["verify_tls"])

    def start_receiver(self) -> str:
        d = self.cfg.settings["cdr_delivery"]
        if self.receiver:
            self.receiver.stop()
            self.receiver = None
        if d["mode"] != "embedded":
            return ""
        from .sftp_receiver import SftpReceiver
        self.receiver = SftpReceiver(self.cfg.inbox_dir, self.cfg.data_dir / "sftp_host_rsa.key",
                                     d["username"], lambda: self.cfg.secrets.get("sftp_password", ""),
                                     port=int(d["listen_port"]), on_file=self._on_inbox_file)
        self.receiver.start()
        return self.receiver.error

    def receiver_status(self) -> dict:
        d = self.cfg.settings["cdr_delivery"]
        if d["mode"] != "embedded":
            return {"mode": "external"}
        r = self.receiver
        return {"mode": "embedded", "running": bool(r and r.running), "error": r.error if r else "",
                "port": d["listen_port"], "advertise_host": d["advertise_host"] or _guess_ip(self.cfg.settings["cucm"]["host"])}

    def _on_inbox_file(self, path: Path):
        ev = self._inbox_events.get(path.name)
        if ev:
            ev.set()

    def run_job(self, kind: str, title: str, fn, *args) -> Job:
        job = Job(kind, title)
        self.jobs[job.id] = job

        def runner():
            try:
                fn(job, *args)
                job.state = "done"
            except SoapError as e:
                job.state = "error"; job.log(f"ERROR: {e}", logging.ERROR)
            except Exception as e:  # pragma: no cover
                job.state = "error"; job.log(f"ERROR: {type(e).__name__}: {e}", logging.ERROR)
                log.debug(traceback.format_exc())
            job.progress = 1.0
            job.finished = time.time()

        threading.Thread(target=runner, daemon=True).start()
        return job

    # ------------------------------------------------------------ nodes
    def discover_nodes(self) -> list[str]:
        nodes = sorted(self.soap().list_node_service_logs().keys())
        if nodes:
            self.cfg.update({"cucm": {"nodes": nodes}})
        return nodes

    def resolve_node(self, name: str) -> str | None:
        c = self.cfg.settings["cucm"]
        if name in c["node_addresses"]:
            return c["node_addresses"][name]
        host = c["host"]
        if name.lower() == host.lower() or name.split(".")[0].lower() == host.split(".")[0].lower():
            return host
        for cand in [name] + ([f"{name}.{c['domain']}"] if c["domain"] else []) + \
                ([f"{name}.{host.split('.', 1)[1]}"] if "." in host and not _is_ip(host) else []):
            try:
                socket.getaddrinfo(cand, 8443)
                return cand
            except OSError:
                continue
        return None

    # ------------------------------------------------------------ CDR
    def fetch_cdrs(self, job: Job, start_utc: datetime, end_utc: datetime):
        soap = self.soap()
        d = self.cfg.settings["cdr_delivery"]
        job.log(f"Listing CDR/CMR files {start_utc:%Y-%m-%d %H:%M} → {end_utc:%Y-%m-%d %H:%M} UTC")
        names = soap.cdr_get_file_list(start_utc, end_utc)
        have = {f["name"] for f in self.store.files()}
        todo = [n for n in names if n not in have]
        job.log(f"{len(names)} files on the CDR Repository, {len(todo)} not loaded yet")
        if not todo:
            job.result = {**job.result, "files": 0, "records": 0}
            return
        if d["mode"] == "embedded":
            st = self.receiver_status()
            if not st.get("running"):
                raise SoapError("embedded SFTP receiver is not running: " + (st.get("error") or "check Settings"))
            host, user = st["advertise_host"], d["username"]
            pw, rdir = self.cfg.secrets["sftp_password"], "/"
            if not host:
                raise SoapError("set 'Address CUCM uses to reach this app' in Settings")
        else:
            host, user, rdir = d["external_host"], d["external_user"], d["external_dir"] or "/"
            pw = self.cfg.secrets.get("external_sftp_password", "")
            if not (host and user and pw):
                raise SoapError("external SFTP host/user/password are not set")
        total_recs = 0
        last_call = 0.0
        for i, name in enumerate(todo, 1):
            # CDRonDemand allows ~10 get_file per minute by default; pace when needed
            if len(todo) > 10:
                wait = 6.2 - (time.time() - last_call)
                if wait > 0:
                    time.sleep(wait)
            ev = threading.Event()
            self._inbox_events[name] = ev
            last_call = time.time()
            try:
                soap.cdr_get_file(name, host, user, pw, rdir, sftp=True)
                data = self._collect_pushed(name, ev)
            except SoapError as e:
                job.log(f"{name}: {e}", logging.WARNING)
                continue
            finally:
                self._inbox_events.pop(name, None)
            kind, n = self.store.load_cdr_file(name, data)
            (self.cfg.cdr_dir / name).write_bytes(data)
            total_recs += n
            job.log(f"{name}: {kind or 'not a CDR/CMR file'}, {n} records")
            job.prog(i / len(todo))
        job.result = {**job.result, "files": len(todo), "records": total_recs}

    def _collect_pushed(self, name: str, ev: threading.Event) -> bytes:
        d = self.cfg.settings["cdr_delivery"]
        if d["mode"] == "embedded":
            p = self.cfg.inbox_dir / name
            if not p.exists():
                ev.wait(60)
            for _ in range(50):
                if p.exists():
                    break
                time.sleep(0.2)
            if not p.exists():
                raise SoapError("CUCM reported success but the file never arrived at the SFTP receiver")
            data = p.read_bytes()
            p.unlink(missing_ok=True)
            return data
        if d["external_local_path"]:
            p = Path(d["external_local_path"]) / name
            for _ in range(150):
                if p.exists():
                    return p.read_bytes()
                time.sleep(0.2)
            raise SoapError(f"{p} did not appear (check external_local_path)")
        import paramiko
        t = paramiko.Transport((d["external_host"], int(d["external_port"] or 22)))
        try:
            t.connect(username=d["external_user"], password=self.cfg.secrets.get("external_sftp_password", ""))
            sf = paramiko.SFTPClient.from_transport(t)
            rpath = (d["external_dir"].rstrip("/") or "") + "/" + name
            with sf.open(rpath, "rb") as f:
                return f.read()
        finally:
            t.close()

    # ------------------------------------------------------------ SDL
    def fetch_sdl(self, job: Job, call_key: str, nodes: list[str] | None = None):
        """SDL traces around one call (its CDR window plus the configured padding)."""
        cdrs, _ = self.store.call(call_key)
        if not cdrs:
            raise SoapError("call not found")
        sd = self.cfg.settings["sdl"]
        start, end = correlate.window(cdrs, sd["pad_before_s"], sd["pad_after_s"])
        self.pull_sdl_window(job, datetime.fromtimestamp(start, tz=timezone.utc),
                             datetime.fromtimestamp(end, tz=timezone.utc), nodes, int(sd["max_files_per_node"]))

    def pull_sdl_window(self, job: Job, s_dt: datetime, e_dt: datetime,
                        nodes: list[str] | None, cap: int) -> int:
        """List, download and index CallManager SDL files covering [s_dt, e_dt] on every node.
        Raw files are kept under data/sdl/<node>/ so they survive CUCM trace rotation."""
        sd = self.cfg.settings["sdl"]
        soap = self.soap()
        nodes = nodes or self.cfg.settings["cucm"]["nodes"] or self.discover_nodes()
        tz = self.server_tz()
        job.log(f"Window {s_dt:%H:%M:%S} → {e_dt:%H:%M:%S} UTC on {len(nodes)} node(s)")
        total = 0
        for ni, node in enumerate(nodes):
            addr = self.resolve_node(node)
            if not addr:
                job.log(f"{node}: cannot resolve. Add it under Node addresses in Settings.", logging.WARNING)
                continue
            try:
                files = soap.select_log_files(addr, [sd["service"]], s_dt - timedelta(minutes=2),
                                              e_dt + timedelta(minutes=60))
            except SoapError as e:
                job.log(f"{node}: selectLogFiles failed: {e}", logging.WARNING)
                continue
            sdl_files = [f for f in files if "/sdl/" in f["path"].lower() or f["name"].upper().startswith("SDL")] or files
            for f in sdl_files:
                f["mdt"] = S.parse_modified(f["modified"], tz)
            dated = sorted([f for f in sdl_files if f["mdt"]], key=lambda f: f["mdt"])
            pick = []
            for f in dated:
                if f["mdt"] < s_dt:
                    continue
                pick.append(f)
                if f["mdt"] > e_dt:
                    break
            pick += [f for f in sdl_files if not f["mdt"]][:2]
            if len(pick) > cap:
                last = pick[cap - 1]["mdt"]
                job.log(f"{node}: {len(pick)} trace files cover the window; keeping the first {cap}"
                        + (f" (up to {last.astimezone(timezone.utc):%H:%M:%S} UTC)" if last else "")
                        + ". Raise the limit in Settings or use a shorter window.", logging.WARNING)
                pick = pick[:cap]
            job.log(f"{node}: {len(sdl_files)} SDL files listed, {len(pick)} cover the window")
            for fi, f in enumerate(pick):
                key = f"sdl:{node}:{f['path']}:{f['size']}:{f['modified']}"
                if self.store.has_file(key):
                    continue
                try:
                    data = soap.get_one_file(addr, f["path"])
                except SoapError as e:
                    job.log(f"{node}: {f['name']}: {e}", logging.WARNING)
                    continue
                (self.cfg.sdl_dir / node).mkdir(parents=True, exist_ok=True)
                (self.cfg.sdl_dir / node / f["name"]).write_bytes(data)
                text = S.read_maybe_gz(f["name"], data)
                anchor = (f["mdt"] or e_dt).astimezone(tz)
                msgs = S.parse_sdl_text(text, anchor, node=node, source=f["name"])
                added = self.store.load_sip(key, f["name"], node, len(data), msgs, {"path": f["path"]})
                total += added
                job.log(f"{node}: {f['name']} → {len(msgs)} SIP messages")
                job.prog((ni + (fi + 1) / max(len(pick), 1)) / len(nodes))
        job.result = {**job.result, "sip_added": total}
        return total

    # ------------------------------------------------------------ CDR + SDL together
    def fetch_window(self, job: Job, start_utc: datetime, end_utc: datetime, with_sdl: bool = True):
        """CDR/CMR for a window and, optionally, the SDL traces for the same window.
        SDL goes first: CUCM rotates trace files quickly on busy clusters, while the CDR
        repository keeps its files far longer. A failure in one half does not stop the other."""
        errors = []
        if with_sdl:
            sd = self.cfg.settings["sdl"]
            pad_b, pad_a = timedelta(seconds=int(sd["pad_before_s"])), timedelta(seconds=int(sd["pad_after_s"]))
            job.log("Step 1/2: SDL traces for the window (pulled first, they rotate fastest)")
            job.phase(0.0, 0.6)
            try:
                self.pull_sdl_window(job, start_utc - pad_b, end_utc + pad_a, None,
                                     int(sd.get("max_window_files_per_node", 400)))
            except SoapError as e:
                errors.append(f"SDL: {e}"); job.log(f"SDL pull failed: {e}", logging.ERROR)
            job.log("Step 2/2: CDR/CMR files")
            job.phase(0.6, 0.4)
        try:
            self.fetch_cdrs(job, start_utc, end_utc)
        except SoapError as e:
            errors.append(f"CDR: {e}"); job.log(f"CDR pull failed: {e}", logging.ERROR)
        if errors:
            raise SoapError("; ".join(errors))

    # ------------------------------------------------------------ uploads
    def ingest_upload(self, name: str, data: bytes, node: str = "", trace_date: str = "") -> list[dict]:
        tz = self.server_tz()
        out = []
        for member, blob, mtime in S.iter_archive(name, data):
            base = Path(member).name
            res = {"file": member, "kind": "", "records": 0, "note": ""}
            try:
                raw = blob
                if base.endswith(".gz") or raw[:2] == b"\x1f\x8b":
                    import gzip
                    raw = gzip.decompress(raw)
                head = raw[:4000].decode("utf-8", "replace")
                if "dateTimeOrigination" in head or "numberPacketsSent" in head or "varVQMetrics" in head:
                    kind, n = self.store.load_cdr_file(base, raw)
                    res.update(kind=kind or "", records=n, note="already loaded" if kind == "dup" else "")
                    if kind and kind != "dup":
                        (self.cfg.cdr_dir / base).write_bytes(raw)
                elif S.SIP_HDR_RE.search(raw.decode("utf-8", "replace")) or "|AppInfo" in head:
                    text = raw.decode("utf-8", "replace")
                    nd = node or S.node_from_path(member) or "uploaded"
                    if mtime:
                        anchor = mtime.replace(tzinfo=tz)
                    elif trace_date:
                        anchor = datetime.strptime(trace_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=tz)
                    else:
                        anchor = datetime.now(tz)
                    msgs = S.parse_sdl_text(text, anchor, node=nd, source=base)
                    import hashlib
                    key = "sdl:upload:" + hashlib.sha1(blob).hexdigest()
                    added = self.store.load_sip(key, base, nd, len(blob), msgs)
                    res.update(kind="sdl", records=len(msgs), note=f"node {nd}, {added} new")
                else:
                    res["note"] = "skipped (not a CDR/CMR or SDL trace)"
            except Exception as e:
                res["note"] = f"error: {e}"
            out.append(res)
        return out

    # ------------------------------------------------------------ call view
    def call_view(self, call_key: str, selected: set | None = None) -> dict:
        cdrs, cmrs = self.store.call(call_key)
        if not cdrs:
            return {}
        sd = self.cfg.settings["sdl"]
        node_ips = {k: v for k, v in self.cfg.settings["cucm"]["node_addresses"].items() if _is_ip(v)}
        ladder = correlate.build(cdrs, self.store, node_ips, sd["pad_before_s"], sd["pad_after_s"])
        if selected is not None:
            for d in ladder["dialogs"]:
                d["selected"] = d["call_id"] in selected
        L = analysis.legs(cdrs, cmrs)
        return {"call_key": call_key, "legs": L, "ladder": ladder,
                "findings": analysis.findings(L, ladder), "server_tz": self.cfg.get("cucm", "server_tz"),
                "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    def clear(self, what: str):
        self.store.clear(what)
        if what in ("cdr", "all"):
            shutil.rmtree(self.cfg.cdr_dir, ignore_errors=True); self.cfg.cdr_dir.mkdir(exist_ok=True)
        if what in ("sip", "all"):
            shutil.rmtree(self.cfg.sdl_dir, ignore_errors=True); self.cfg.sdl_dir.mkdir(exist_ok=True)


def _is_ip(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, s)
            return True
        except OSError:
            return False


def _guess_ip(toward: str) -> str:
    """Local IP used to reach CUCM (no packets are sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((toward or "8.8.8.8", 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return ""

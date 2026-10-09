#!/usr/bin/env python3
"""CUCM Call Analyzer - local web app.

    python app.py                      # http://127.0.0.1:8080
    python app.py --port 9000 --data ./data --bind 0.0.0.0

Pulls CDR/CMR files (CDR on Demand) and Cisco CallManager SDL traces
(LogCollection + DimeGetFile) from CUCM, or takes uploaded files, and shows
each call with decoded CDR details, CMR voice quality, findings and a SIP
ladder diagram.
"""
from __future__ import annotations

import argparse
import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import Body, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cca.config import Config
from cca.service import Service
from cca.soap import SoapError

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
VERSION = "1.0.0"


def create_app(data_dir: str | Path) -> FastAPI:
    cfg = Config(data_dir)
    svc = Service(cfg)
    svc.start_receiver()
    app = FastAPI(title="CUCM Call Analyzer", version=VERSION)
    app.state.svc = svc
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    def _dt(v) -> datetime:
        """Accept epoch seconds or ISO 8601 (naive = UTC)."""
        if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
            return datetime.fromtimestamp(int(v), tz=timezone.utc)
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

    @app.exception_handler(SoapError)
    async def soap_err(_, exc: SoapError):
        return JSONResponse({"error": str(exc)}, status_code=502)

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    # ------------------------------------------------------------ settings
    @app.get("/api/settings")
    def get_settings():
        return cfg.public()

    @app.post("/api/settings")
    def set_settings(body: dict = Body(...)):
        before = json.dumps(cfg.settings["cdr_delivery"], sort_keys=True)
        cfg.update(body)
        if json.dumps(cfg.settings["cdr_delivery"], sort_keys=True) != before or \
                "sftp_password" in (body.get("secrets") or {}):
            svc.start_receiver()
        return {"ok": True, "settings": cfg.public(), "receiver": svc.receiver_status()}

    @app.get("/api/status")
    def status():
        return {"version": VERSION, "stats": svc.store.stats(), "receiver": svc.receiver_status(),
                "nodes": cfg.settings["cucm"]["nodes"], "files": svc.store.files()[:300],
                "configured": bool(cfg.settings["cucm"]["host"] and cfg.settings["cucm"]["user"]
                                   and cfg.secrets.get("cucm_password"))}

    @app.post("/api/test")
    def test():
        out = {}
        soap = svc.soap()
        now = datetime.now(timezone.utc)
        try:
            from datetime import timedelta
            files = soap.cdr_get_file_list(now - timedelta(minutes=59), now)
            out["cdr_on_demand"] = f"OK, {len(files)} file(s) in the last hour"
        except SoapError as e:
            out["cdr_on_demand"] = f"FAILED: {e}"
        try:
            nodes = svc.discover_nodes()
            out["log_collection"] = f"OK, nodes: {', '.join(nodes)}"
            out["node_addresses"] = {n: svc.resolve_node(n) or "UNRESOLVED (set it in Node addresses)" for n in nodes}
        except SoapError as e:
            out["log_collection"] = f"FAILED: {e}"
        out["receiver"] = svc.receiver_status()
        return out

    @app.post("/api/nodes/discover")
    def discover():
        return {"nodes": svc.discover_nodes()}

    # ------------------------------------------------------------ data in
    @app.post("/api/cdr/fetch")
    def cdr_fetch(body: dict = Body(...)):
        s, e = _dt(body["start"]), _dt(body["end"])
        if e <= s:
            raise HTTPException(400, "end must be after start")
        if (e - s).total_seconds() > 7 * 86400:
            raise HTTPException(400, "window is limited to 7 days per fetch")
        with_sdl = bool(body.get("sdl", False))
        job = svc.run_job("cdr", f"CDRs{' + SDL' if with_sdl else ''} {s:%m/%d %H:%M}–{e:%H:%M} UTC",
                          svc.fetch_window, s, e, with_sdl)
        return job.view()

    @app.post("/api/upload")
    async def upload(files: list[UploadFile] = File(...), node: str = Form(""), trace_date: str = Form("")):
        results = []
        for f in files:
            data = await f.read()
            results += svc.ingest_upload(f.filename or "upload", data, node.strip(), trace_date.strip())
        return {"results": results, "stats": svc.store.stats()}

    @app.post("/api/clear")
    def clear(body: dict = Body(...)):
        what = body.get("what", "")
        if what not in ("cdr", "sip", "all"):
            raise HTTPException(400, "what must be cdr, sip or all")
        svc.clear(what)
        return {"ok": True, "stats": svc.store.stats()}

    # ------------------------------------------------------------ calls
    @app.get("/api/calls")
    def calls(number: str = "", calling: str = "", called: str = "", device: str = "",
              call_id: str = "", start: str = "", end: str = "", failed: bool = False, limit: int = 500):
        q = {"number": number, "calling": calling, "called": called, "device": device,
             "call_id": call_id, "failed": failed, "limit": min(limit, 5000)}
        if start:
            q["start"] = int(_dt(start).timestamp())
        if end:
            q["end"] = int(_dt(end).timestamp())
        return {"calls": svc.store.search(q)}

    def _sel(dialogs: str | None):
        return None if dialogs is None else {d for d in dialogs.split("\n") if d}

    @app.get("/api/call")
    def call(key: str = Query(...), dialogs: str | None = None):
        v = svc.call_view(key, _sel(dialogs))
        if not v:
            raise HTTPException(404, "call not found")
        return v

    @app.post("/api/call/findings")
    def call_findings(body: dict = Body(...)):
        v = svc.call_view(body["key"], set(body.get("dialogs") or []))
        if not v:
            raise HTTPException(404, "call not found")
        from cca import analysis
        return {"findings": analysis.findings(v["legs"], v["ladder"], set(body.get("dialogs") or []))}

    @app.post("/api/call/sdl")
    def call_sdl(body: dict = Body(...)):
        job = svc.run_job("sdl", f"SDL traces for {body['key']}", svc.fetch_sdl, body["key"], body.get("nodes") or None)
        return job.view()

    @app.get("/api/call/export", response_class=HTMLResponse)
    def export(key: str = Query(...), dialogs: str | None = None):
        sel = _sel(dialogs)
        v = svc.call_view(key, sel)
        if not v:
            raise HTTPException(404, "call not found")
        if sel is not None:
            from cca import analysis
            v["findings"] = analysis.findings(v["legs"], v["ladder"], sel)
        css = (STATIC / "app.css").read_text()
        js = (STATIC / "callview.js").read_text()
        data = json.dumps(v).replace("</", "<\\/")
        title = html.escape(f"Call {key}")
        page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>{css}</style></head><body class="report"><main id="call"></main>
<script>{js}</script><script>const DATA={data};renderCall(document.getElementById('call'),DATA,{{static:true}});</script>
</body></html>"""
        fn = "call_" + "".join(ch if ch.isalnum() else "_" for ch in key) + ".html"
        return HTMLResponse(page, headers={"Content-Disposition": f'attachment; filename="{fn}"'})

    # ------------------------------------------------------------ jobs
    @app.get("/api/jobs")
    def jobs():
        return {"jobs": [j.view() for j in sorted(svc.jobs.values(), key=lambda j: -j.started)][:20]}

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str):
        j = svc.jobs.get(job_id)
        if not j:
            raise HTTPException(404, "no such job")
        return j.view()

    return app


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="127.0.0.1", help="web UI address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="web UI port (default 8080)")
    ap.add_argument("--data", default=str(HERE / "data"), help="data folder (CDRs, traces, index, settings)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    app = create_app(a.data)
    print(f"CUCM Call Analyzer {VERSION} → http://{a.bind}:{a.port}")
    uvicorn.run(app, host=a.bind, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()

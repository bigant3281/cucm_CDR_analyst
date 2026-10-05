"""SQLite index of CDRs, CMRs and SIP messages pulled from SDL traces."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import cdr as cdrmod
from .sip import parse_sip

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
  key TEXT PRIMARY KEY, kind TEXT, name TEXT, node TEXT, size INTEGER,
  records INTEGER, loaded_at TEXT, info TEXT);
CREATE TABLE IF NOT EXISTS cdr (
  pkid TEXT PRIMARY KEY, call_key TEXT, orig_ts INTEGER, connect_ts INTEGER,
  disconnect_ts INTEGER, duration INTEGER, calling TEXT, orig_called TEXT,
  final_called TEXT, last_redirect TEXT, orig_device TEXT, dest_device TEXT,
  orig_cause INTEGER, dest_cause INTEGER, orig_leg TEXT, dest_leg TEXT,
  file TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS cdr_ts ON cdr(orig_ts);
CREATE INDEX IF NOT EXISTS cdr_call ON cdr(call_key);
CREATE TABLE IF NOT EXISTS cmr (
  pkid TEXT PRIMARY KEY, call_key TEXT, call_identifier TEXT, device TEXT,
  ts INTEGER, file TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS cmr_call ON cmr(call_key);
CREATE TABLE IF NOT EXISTS sip (
  id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT UNIQUE, file_key TEXT, node TEXT,
  ts REAL, direction TEXT, transport TEXT, remote_ip TEXT, remote_port INTEGER,
  call_id TEXT, cseq TEXT, first_line TEXT, line_no INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS sip_ts ON sip(ts);
CREATE INDEX IF NOT EXISTS sip_cid ON sip(call_id);
"""


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ------------------------------------------------------------ files
    def has_file(self, key: str) -> bool:
        with self.lock:
            return self.db.execute("SELECT 1 FROM files WHERE key=?", (key,)).fetchone() is not None

    def files(self) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(
                "SELECT key,kind,name,node,size,records,loaded_at FROM files ORDER BY loaded_at DESC")]

    def _mark(self, key, kind, name, node, size, records, info=None):
        self.db.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?,?,?,?,?)",
                        (key, kind, name, node, size, records,
                         datetime.now(timezone.utc).isoformat(timespec="seconds"),
                         json.dumps(info or {})))

    # ------------------------------------------------------------ CDR/CMR
    def load_cdr_file(self, name: str, data: bytes) -> tuple[str | None, int]:
        key = "cdr:" + hashlib.sha1(data).hexdigest()
        if self.has_file(key):
            return "dup", 0
        kind, recs = cdrmod.parse_file(data)
        if not kind:
            return None, 0
        with self.lock:
            if kind == "cdr":
                for r in recs:
                    s = cdrmod.summarize(r)
                    pk = s["pkid"] or hashlib.sha1(json.dumps(r, sort_keys=True).encode()).hexdigest()
                    self.db.execute(
                        "INSERT OR REPLACE INTO cdr VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (pk, s["call_key"], s["orig_ts"], s["connect_ts"], s["disconnect_ts"],
                         s["duration"], s["calling"], s["orig_called"], s["final_called"],
                         s["last_redirect"], s["orig_device"], s["dest_device"], s["orig_cause"],
                         s["dest_cause"], s["orig_leg"], s["dest_leg"], name, json.dumps(r)))
            else:
                for r in recs:
                    pk = cdrmod.ci_get(r, "pkid") or hashlib.sha1(json.dumps(r, sort_keys=True).encode()).hexdigest()
                    self.db.execute("INSERT OR REPLACE INTO cmr VALUES (?,?,?,?,?,?,?)",
                                    (pk, cdrmod.call_key(r), cdrmod.ci_get(r, "callIdentifier"),
                                     cdrmod.ci_get(r, "deviceName"),
                                     cdrmod.to_int(cdrmod.ci_get(r, "dateTimeStamp")), name, json.dumps(r)))
            self._mark(key, kind, name, "", len(data), len(recs))
            self.db.commit()
        return kind, len(recs)

    def search(self, q: dict) -> list[dict]:
        where, args = [], []
        if q.get("start"):
            where.append("orig_ts >= ?"); args.append(int(q["start"]))
        if q.get("end"):
            where.append("orig_ts <= ?"); args.append(int(q["end"]))
        num = "".join(ch for ch in (q.get("number") or "") if ch.isalnum() or ch in "+*#")
        if num:
            like = f"%{num}%"
            where.append("(calling LIKE ? OR orig_called LIKE ? OR final_called LIKE ? OR last_redirect LIKE ?)")
            args += [like] * 4
        if q.get("calling"):
            where.append("calling LIKE ?"); args.append(f"%{q['calling']}%")
        if q.get("called"):
            where.append("(orig_called LIKE ? OR final_called LIKE ?)"); args += [f"%{q['called']}%"] * 2
        if q.get("device"):
            where.append("(orig_device LIKE ? OR dest_device LIKE ?)"); args += [f"%{q['device']}%"] * 2
        if q.get("call_id"):
            where.append("call_key LIKE ?"); args.append(f"%{q['call_id']}%")
        if q.get("failed"):
            where.append("(duration = 0 OR orig_cause NOT IN (0,16,31,393216,458752) "
                         "OR dest_cause NOT IN (0,16,31,393216,458752))")
        sql = ("SELECT pkid,call_key,orig_ts,connect_ts,disconnect_ts,duration,calling,orig_called,"
               "final_called,last_redirect,orig_device,dest_device,orig_cause,dest_cause FROM cdr")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY orig_ts DESC LIMIT ?"
        args.append(int(q.get("limit") or 500))
        with self.lock:
            rows = [dict(r) for r in self.db.execute(sql, args)]
        # one row per call (globalCallID), keeping every leg count
        calls: dict[str, dict] = {}
        for r in rows:
            c = calls.get(r["call_key"])
            if c is None:
                r["legs"] = 1
                calls[r["call_key"]] = r
            else:
                c["legs"] += 1
                if r["orig_ts"] < c["orig_ts"]:
                    r["legs"] = c["legs"]
                    calls[r["call_key"]] = r
        return list(calls.values())

    def call(self, call_key: str) -> tuple[list[dict], list[dict]]:
        with self.lock:
            cdrs = [json.loads(r["raw"]) for r in self.db.execute(
                "SELECT raw FROM cdr WHERE call_key=? ORDER BY orig_ts, pkid", (call_key,))]
            cmrs = [json.loads(r["raw"]) for r in self.db.execute(
                "SELECT raw FROM cmr WHERE call_key=? ORDER BY ts", (call_key,))]
        return cdrs, cmrs

    def stats(self) -> dict:
        with self.lock:
            one = lambda s: self.db.execute(s).fetchone()[0]  # noqa: E731
            return {"cdr": one("SELECT COUNT(*) FROM cdr"), "cmr": one("SELECT COUNT(*) FROM cmr"),
                    "sip": one("SELECT COUNT(*) FROM sip"),
                    "first": one("SELECT MIN(orig_ts) FROM cdr"), "last": one("SELECT MAX(orig_ts) FROM cdr"),
                    "sip_first": one("SELECT MIN(ts) FROM sip"), "sip_last": one("SELECT MAX(ts) FROM sip")}

    # ------------------------------------------------------------ SIP
    def load_sip(self, file_key: str, name: str, node: str, size: int, msgs: list[dict], info=None) -> int:
        added = 0
        with self.lock:
            for m in msgs:
                p = parse_sip(m["raw"])
                uid = hashlib.sha1(f"{m['node']}|{m['ts'].isoformat()}|{m['direction']}|{m['remote_ip']}|"
                                   f"{m['remote_port']}|{m['raw']}".encode()).hexdigest()
                cur = self.db.execute(
                    "INSERT OR IGNORE INTO sip (uid,file_key,node,ts,direction,transport,remote_ip,remote_port,"
                    "call_id,cseq,first_line,line_no,raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (uid, file_key, m["node"], m["ts"].timestamp(), m["direction"], m["transport"],
                     m["remote_ip"], m["remote_port"], p["call_id"],
                     f"{p['cseq_num']} {p['cseq_method']}", p["first_line"], m["line_no"], m["raw"]))
                added += cur.rowcount
            self._mark(file_key, "sdl", name, node, size, len(msgs), info)
            self.db.commit()
        return added

    def sip_window(self, start: float, end: float) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM sip WHERE ts BETWEEN ? AND ? ORDER BY ts, id", (start, end))]

    def sip_by_callids(self, call_ids: list[str], start: float, end: float) -> list[dict]:
        if not call_ids:
            return []
        q = ",".join("?" * len(call_ids))
        with self.lock:
            return [dict(r) for r in self.db.execute(
                f"SELECT * FROM sip WHERE call_id IN ({q}) AND ts BETWEEN ? AND ? ORDER BY ts, id",
                (*call_ids, start, end))]

    def clear(self, what: str) -> None:
        with self.lock:
            if what in ("cdr", "all"):
                self.db.execute("DELETE FROM cdr"); self.db.execute("DELETE FROM cmr")
                self.db.execute("DELETE FROM files WHERE kind IN ('cdr','cmr')")
            if what in ("sip", "all"):
                self.db.execute("DELETE FROM sip"); self.db.execute("DELETE FROM files WHERE kind='sdl'")
            self.db.commit()

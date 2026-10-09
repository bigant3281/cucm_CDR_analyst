"""Settings, secrets and data-directory layout.

Settings live in <data>/config.json (no passwords). Passwords come from
environment variables or are entered in the UI and kept in memory only.
"""
from __future__ import annotations

import copy
import json
import os
import secrets
import threading
from pathlib import Path

DEFAULTS = {
    "cucm": {
        "host": "",              # publisher (CDR Repository node) FQDN or IP
        "user": "",              # application user
        "verify_tls": False,     # True, False or a path to a CA bundle
        "domain": "",            # appended to short node names that don't resolve
        "node_addresses": {},    # {"CUCM-SUB1": "10.1.1.11"}
        "server_tz": "America/New_York",  # timezone the CUCM servers run in (SDL timestamps)
        "nodes": [],             # discovered with listNodeServiceLogs; editable
    },
    "cdr_delivery": {
        # embedded: this app runs an SFTP server and CUCM pushes CDR files to it
        # external: CUCM pushes to an SFTP server you already have
        "mode": "embedded",
        "listen_port": 22,
        "advertise_host": "",    # IP of THIS machine as CUCM sees it
        "username": "cdrpush",
        "external_host": "",
        "external_port": 22,
        "external_user": "",
        "external_dir": "",
        "external_local_path": "",  # if the external SFTP server writes to a folder this app can read
    },
    "sdl": {
        "max_files_per_node": 40,          # per-call pull
        "max_window_files_per_node": 400,  # window pull alongside CDRs
        "pad_before_s": 60,
        "pad_after_s": 60,
        "service": "Cisco CallManager",
    },
}

ENV_SECRETS = {
    "cucm_password": "CUCM_PASSWORD",
    "sftp_password": "CCA_SFTP_PASSWORD",        # embedded receiver password
    "external_sftp_password": "CCA_EXT_SFTP_PASSWORD",
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir).resolve()
        self.lock = threading.RLock()
        for sub in ("cdr", "sdl", "uploads", "cdr_inbox", "exports"):
            (self.data_dir / sub).mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "config.json"
        self.settings = copy.deepcopy(DEFAULTS)
        if self.path.exists():
            try:
                self.settings = _merge(DEFAULTS, json.loads(self.path.read_text()))
            except Exception:
                pass
        self.secrets: dict[str, str] = {}
        for key, env in ENV_SECRETS.items():
            if os.environ.get(env):
                self.secrets[key] = os.environ[env]
        if "sftp_password" not in self.secrets:
            self.secrets["sftp_password"] = secrets.token_urlsafe(12)

    # ------------------------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.data_dir / "cca.sqlite"

    @property
    def cdr_dir(self) -> Path:
        return self.data_dir / "cdr"

    @property
    def sdl_dir(self) -> Path:
        return self.data_dir / "sdl"

    @property
    def inbox_dir(self) -> Path:
        return self.data_dir / "cdr_inbox"

    def save(self) -> None:
        with self.lock:
            self.path.write_text(json.dumps(self.settings, indent=2))

    def update(self, new: dict) -> None:
        with self.lock:
            pw = (new or {}).pop("secrets", None) or {}
            na = ((new or {}).get("cucm") or {}).get("node_addresses")
            self.settings = _merge(self.settings, new or {})
            if na is not None:
                self.settings["cucm"]["node_addresses"] = dict(na)
            for k, v in pw.items():
                if k in ENV_SECRETS and v:
                    self.secrets[k] = v
            self.save()

    def public(self) -> dict:
        """Settings for the UI: never return passwords, only whether they're set."""
        with self.lock:
            out = copy.deepcopy(self.settings)
            out["secrets_set"] = {k: bool(self.secrets.get(k)) for k in ENV_SECRETS}
            return out

    def get(self, section: str, key: str, default=None):
        return self.settings.get(section, {}).get(key, default)

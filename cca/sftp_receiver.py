"""Minimal embedded SFTP server so CUCM's CDRonDemand get_file can push
CDR/CMR files straight to this app. Single user, password auth, writes are
confined to one folder. Uses an RSA host key (CUCM 14+ negotiates ssh-rsa).
"""
from __future__ import annotations

import logging
import os
import socket
import threading
from pathlib import Path

import paramiko
from paramiko.sftp import SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_OK, SFTP_PERMISSION_DENIED

log = logging.getLogger("cca.sftp")


class _Server(paramiko.ServerInterface):
    def __init__(self, user: str, password_fn):
        self.user, self.password_fn = user, password_fn

    def check_auth_password(self, username, password):
        if username == self.user and password == self.password_fn():
            return paramiko.AUTH_SUCCESSFUL
        log.warning("SFTP login rejected for %r", username)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        return name == "sftp" and super().check_channel_subsystem_request(channel, name)


class _Handle(paramiko.SFTPHandle):
    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno() if hasattr(self, "readfile") else self.writefile.fileno()))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        return SFTP_OK


def _make_sftp_interface(root: Path, on_file):
    class _SFTP(paramiko.SFTPServerInterface):
        ROOT = root

        def _real(self, path: str) -> Path:
            # Every client path maps into ROOT by its file name / relative parts.
            rel = Path(*[p for p in self.canonicalize(path).split("/") if p not in ("", ".", "..")])
            real = (self.ROOT / rel).resolve()
            if self.ROOT not in real.parents and real != self.ROOT:
                raise PermissionError(path)
            return real

        def canonicalize(self, path):
            import posixpath
            return posixpath.normpath("/" + (path or "").replace("\\", "/").lstrip("/"))

        def list_folder(self, path):
            try:
                real = self._real(path)
                out = []
                for f in real.iterdir():
                    a = paramiko.SFTPAttributes.from_stat(f.stat())
                    a.filename = f.name
                    out.append(a)
                return out
            except OSError as e:
                return paramiko.SFTPServer.convert_errno(e.errno)

        def stat(self, path):
            try:
                real = self._real(path)
                if not real.exists():  # pretend every directory CUCM asks about exists
                    if not Path(path).suffix:
                        real = self.ROOT
                    else:
                        return SFTP_NO_SUCH_FILE
                return paramiko.SFTPAttributes.from_stat(real.stat())
            except PermissionError:
                return SFTP_PERMISSION_DENIED
            except OSError as e:
                return paramiko.SFTPServer.convert_errno(e.errno)

        lstat = stat

        def open(self, path, flags, attr):
            try:
                real = self._real(path)
            except PermissionError:
                return SFTP_PERMISSION_DENIED
            real.parent.mkdir(parents=True, exist_ok=True)
            writing = bool(flags & (os.O_WRONLY | os.O_RDWR))
            try:
                if writing:
                    fd = os.open(real, flags | getattr(os, "O_BINARY", 0), 0o644)
                    f = os.fdopen(fd, "wb" if not flags & os.O_RDWR else "r+b")
                else:
                    f = open(real, "rb")
            except OSError as e:
                return paramiko.SFTPServer.convert_errno(e.errno)
            h = _Handle(flags)
            h.filename = str(real)
            if writing:
                h.writefile = f
                orig_close = h.close

                def _close():
                    orig_close()
                    try:
                        on_file(real)
                    except Exception:  # pragma: no cover
                        log.exception("on_file callback failed for %s", real)
                h.close = _close
            else:
                h.readfile = f
            return h

        def remove(self, path):
            return SFTP_PERMISSION_DENIED

        def rename(self, old, new):
            try:
                self._real(old).rename(self._real(new))
                return SFTP_OK
            except Exception:
                return SFTP_FAILURE

        def mkdir(self, path, attr):
            try:
                self._real(path).mkdir(parents=True, exist_ok=True)
                return SFTP_OK
            except Exception:
                return SFTP_FAILURE

        def rmdir(self, path):
            return SFTP_PERMISSION_DENIED

        def chattr(self, path, attr):
            return SFTP_OK

    return _SFTP


class SftpReceiver:
    def __init__(self, root: Path, key_path: Path, user: str, password_fn,
                 port: int = 22, on_file=None, bind: str = "0.0.0.0"):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.user, self.password_fn, self.port, self.bind = user, password_fn, port, bind
        self.on_file = on_file or (lambda p: None)
        if key_path.exists():
            self.key = paramiko.RSAKey(filename=str(key_path))
        else:
            self.key = paramiko.RSAKey.generate(2048)
            self.key.write_private_key_file(str(key_path))
        self.sock: socket.socket | None = None
        self.error: str = ""
        self.running = False

    def start(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.bind, self.port))
            s.listen(16)
        except OSError as e:
            self.error = (f"cannot listen on port {self.port}: {e}. Port 22 needs admin/root rights; "
                          "CUCM's get_file always connects on port 22, so run elevated, "
                          "forward 22 to this port, or use an external SFTP server.")
            log.error(self.error)
            return False
        self.sock = s
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        log.info("embedded SFTP receiver listening on %s:%d (user %s)", self.bind, self.port, self.user)
        return True

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _accept_loop(self):
        iface = _make_sftp_interface(self.root, self.on_file)
        while self.running:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn, addr, iface), daemon=True).start()

    def _serve(self, conn, addr, iface):
        t = paramiko.Transport(conn)
        try:
            t.add_server_key(self.key)
            t.set_subsystem_handler("sftp", paramiko.SFTPServer, iface)
            t.start_server(server=_Server(self.user, self.password_fn))
            ch = t.accept(60)
            if ch is None:
                return
            while t.is_active():
                t.join(1)
        except Exception as e:
            log.warning("SFTP session from %s ended: %s", addr[0], e)
        finally:
            t.close()

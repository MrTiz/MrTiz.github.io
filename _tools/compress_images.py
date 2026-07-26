"""
Lossless PNG recompression via oxipng + Zopfli. Rewrites every .png under
assets/img/ in place with a smaller DEFLATE stream and non-critical
metadata stripped. Pixels are byte-identical to the input.

Typical savings on a mixed set of screenshots + diagrams: ~40-50%.

No manual install required. On first run the script resolves the latest
oxipng release on GitHub, downloads it into _tools/.bin/oxipng-<version>/,
and caches it there. Nothing is pinned: whichever version is latest at
first-install time on this machine is what you get. Cached versions are
reused; delete _tools/.bin/ to force a refresh.

Works on Windows, macOS (x86_64/ARM64) and Linux (x86_64/ARM64).

Usage:
    python _tools/compress_images.py                 # default: assets/img/
    python _tools/compress_images.py path/to/dir     # any dir tree
    python _tools/compress_images.py file1.png ...   # specific files

The Zopfli pass (`-Z`) is slow (minutes to tens of minutes on a fresh
tree) but only rewrites files that shrink -- re-running on an already
compressed tree is fast because most files can't be improved further.
"""

import io
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BIN_ROOT = Path(__file__).resolve().parent / ".bin"
DEFAULT_TARGET = REPO / "assets" / "img"

# -o max     -> try every filter/strategy combination for smallest output
# -Z         -> use Zopfli as the DEFLATE backend (slow, best ratio)
# --strip safe -> drop non-critical chunks (timestamps, editor metadata)
#                 while keeping colorspace (iCCP/sRGB), pHYs, APNG frames
OXIPNG_ARGS = ["-o", "max", "-Z", "--strip", "safe", "--recursive"]


def platform_asset(version):
    """Return (release_asset_name, member_path_in_archive, is_zip) for the
    given version and current platform. The member path is the file to
    extract from inside the archive."""
    sys_name = platform.system()
    machine = platform.machine().lower()

    if sys_name == "Windows":
        # Windows ships only x86_64 in oxipng releases
        return (
            f"oxipng-{version}-x86_64-pc-windows-msvc.zip",
            "oxipng.exe",
            True,
        )

    if sys_name == "Darwin":
        arch = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
        return (
            f"oxipng-{version}-{arch}-apple-darwin.tar.gz",
            "oxipng",
            False,
        )

    if sys_name == "Linux":
        arch = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
        return (
            f"oxipng-{version}-{arch}-unknown-linux-musl.tar.gz",
            "oxipng",
            False,
        )

    sys.exit(f"ERROR: unsupported platform {sys_name} {machine}")


def latest_oxipng_version():
    """Query GitHub for the latest oxipng release tag and return it
    stripped of any leading 'v'."""
    api = "https://api.github.com/repos/oxipng/oxipng/releases/latest"
    req = urllib.request.Request(api, headers={"User-Agent": "compress_images.py"})

    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)

    tag = data.get("tag_name") or ""
    return tag.lstrip("v")


def ensure_oxipng():
    """Return the path to an oxipng executable. Prefer one in PATH; else
    resolve the latest upstream release and download it into a versioned
    cache dir under _tools/.bin/. Cached versions are reused; nothing is
    pinned in the script."""
    onpath = shutil.which("oxipng")

    if onpath:
        return onpath

    version = latest_oxipng_version()

    if not version:
        sys.exit("ERROR: could not resolve latest oxipng release from GitHub")

    exe_name = "oxipng.exe" if platform.system() == "Windows" else "oxipng"
    bin_dir = BIN_ROOT / f"oxipng-{version}"
    cached = bin_dir / exe_name

    if cached.exists():
        return str(cached)

    asset, member, is_zip = platform_asset(version)
    url = (f"https://github.com/oxipng/oxipng/releases/download/"
           f"v{version}/{asset}")

    print(f"oxipng not in PATH -> downloading latest (v{version}) for this platform")
    print(f"  {url}")

    bin_dir.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "compress_images.py"})

    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()

    if is_zip:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            # Release zips nest the binary inside a folder. Find it by suffix.
            match = next(
                (n for n in z.namelist() if n.endswith("/" + member) or n == member),
                None,
            )

            if not match:
                sys.exit(f"ERROR: could not find {member} inside {asset}")

            cached.write_bytes(z.read(match))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            match = next(
                (m for m in t.getmembers()
                 if m.name.endswith("/" + member) or m.name == member),
                None,
            )

            if not match:
                sys.exit(f"ERROR: could not find {member} inside {asset}")

            src = t.extractfile(match)

            if src is None:
                sys.exit(f"ERROR: {member} inside {asset} is not a regular file")

            cached.write_bytes(src.read())

    if platform.system() != "Windows":
        cached.chmod(cached.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"  cached at {cached}")
    return str(cached)


def main():
    exe = ensure_oxipng()
    targets = [Path(a) for a in sys.argv[1:]] or [DEFAULT_TARGET]

    for t in targets:
        if not t.exists():
            print(f"skip: {t} does not exist")

    cmd = [exe, *OXIPNG_ARGS, *[str(t) for t in targets if t.exists()]]
    print(f"\n$ {shutil.which(exe) or exe} {' '.join(OXIPNG_ARGS)} ...\n")
    r = subprocess.run(cmd)
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extract_kb2999226.py -- extract the private UCRT file set from the
KB2999226 (Universal C Runtime) .msu without installing anything.

The .msu is a CAB archive containing a nested CAB; ``expand.exe`` (ships
with every Windows since forever, works on Win7 too) does both layers:

    expand -F:* Windows6.1-KB2999226-x64.msu  <stage1>
    expand -F:* Windows6.1-KB2999226-x64.cab  <stage2>

stage2 then contains per-component directories named e.g.
``amd64_microsoft-windows-ucrt_31bf3856ad364e35_..._none_...`` holding
``ucrtbase.dll``, plus the api-ms-win-* forwarders.  This script copies
``ucrtbase.dll`` and every ``api-ms-win-*.dll`` into
``assets/kb2999226/{amd64,x86}`` (layout consumed by build_pack.py).

Usage:
    python tools\\extract_kb2999226.py [path-to-msu]
        (default: assets\\kb2999226\\Windows6.1-KB2999226-x64.msu)

The target machine never installs KB2999226; these files are deployed
privately next to python314.dll (application directory wins the DLL
search order).
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PYW7 = os.path.normpath(os.path.join(HERE, ".."))
DEFAULT_MSU = os.path.join(PYW7, "assets", "kb2999226",
                           "Windows6.1-KB2999226-x64.msu")
OUT_ROOT = os.path.join(PYW7, "assets", "kb2999226")

WANTED = ("ucrtbase.dll",)          # plus every api-ms-win-*.dll


def expand(src, dst):
    os.makedirs(dst, exist_ok=True)
    subprocess.run(["expand.exe", "-F:*", src, dst], check=True,
                   capture_output=True)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    msu = os.path.abspath(argv[0]) if argv else DEFAULT_MSU
    if not os.path.isfile(msu):
        print("error: msu not found: " + msu)
        return 2

    work = tempfile.mkdtemp(prefix="kb2999226_")
    try:
        stage1 = os.path.join(work, "s1")
        expand(msu, stage1)
        cabs = [os.path.join(stage1, f) for f in os.listdir(stage1)
                if f.lower().endswith(".cab")]
        if not cabs:
            print("error: no inner cab found in msu")
            return 1
        stage2 = os.path.join(work, "s2")
        expand(cabs[0], stage2)

        counts = {"amd64": 0, "x86": 0}
        for dirpath, _dirs, files in os.walk(stage2):
            base = os.path.basename(dirpath).lower()
            arch = "amd64" if base.startswith("amd64_") else \
                   "x86" if base.startswith("x86_") else None
            if arch is None:
                continue
            outdir = os.path.join(OUT_ROOT, arch)
            os.makedirs(outdir, exist_ok=True)
            for fn in files:
                low = fn.lower()
                if low in WANTED or (low.startswith("api-ms-win-")
                                     and low.endswith(".dll")):
                    shutil.copy2(os.path.join(dirpath, fn),
                                 os.path.join(outdir, fn))
                    counts[arch] += 1
        for arch, n in sorted(counts.items()):
            print("%s: %d DLLs -> %s" %
                  (arch, n, os.path.join(OUT_ROOT, arch)))
        if counts["amd64"] == 0:
            print("error: nothing extracted (unexpected msu layout)")
            return 1
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

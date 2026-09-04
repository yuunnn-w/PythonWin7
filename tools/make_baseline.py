#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_baseline.py -- convert a YY-Thunks analyzer Config txt database
(e.g. tools/Config/x64/6.1.7600.txt) into the compact JSON baseline that
pywin7gate ships inside the Python tree (usable on the bare Win7 target,
where the tools\\Config directory does not exist).

Usage:
    make_baseline.py [--config-root DIR] [--arch x64] [--target 6.1.7600]
                     [--out PATH]

Default output: <PythonWin7>/src/pywin7gate/baseline_<target>.json
"""
import argparse
import json
import os
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config-root", default=None)
    ap.add_argument("--arch", default="x64")
    ap.add_argument("--target", default="6.1.7600")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.normpath(os.path.join(here, ".."))           # PythonWin7
    config_root = args.config_root or os.path.join(
        root, "assets", "baseline")                             # vendored
    src = os.path.join(config_root, args.arch, args.target + ".txt")
    if not os.path.isfile(src):                                 # repo fallback
        config_root = os.path.normpath(
            os.path.join(root, "..", "..", "tools", "Config"))
        src = os.path.join(config_root, args.arch, args.target + ".txt")
    if not os.path.isfile(src):
        print("error: baseline txt not found:", src)
        return 2

    db = {}
    cur = None
    with open(src, "r", encoding="ascii", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                cur = line[1:-1].lower()
                db.setdefault(cur, [])
            elif cur is not None and "=" in line:
                _o, _e, name = line.partition("=")
                name = name.strip().lower()
                if name and name not in db[cur]:
                    db[cur].append(name)

    out = args.out or os.path.join(
        root, "src", "pywin7gate", "baseline_" +
        args.target.replace(".", "_") + ".json")
    outdir = os.path.dirname(out)
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    payload = {
        "format": 1,
        "arch": args.arch,
        "target": args.target,
        "source": os.path.basename(src),
        "dlls": {k: sorted(v) for k, v in sorted(db.items())},
    }
    with open(out, "w", encoding="ascii") as f:
        json.dump(payload, f, separators=(",", ":"))
    size = os.path.getsize(out)
    print("wrote %s (%d bytes, %d DLLs, %d symbols)" %
          (out, size, len(db), sum(len(v) for v in db.values())))
    return 0


if __name__ == "__main__":
    sys.exit(main())

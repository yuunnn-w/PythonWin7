# -*- coding: utf-8 -*-
"""pywin7gate CLI.

  python -m pywin7gate scan <paths...>    report Win7 blockers (no changes)
  python -m pywin7gate fix  <paths...>    scan + auto-fix + manifest
  python -m pywin7gate fix-all            fix all of Lib\\site-packages
  python -m pywin7gate flatten            flatten every *.libs vendored dir
  python -m pywin7gate pip <args...>      run pip, then auto fix-all
                                          (this is what local-pip.bat calls)
  python -m pywin7gate verify             verify manifest hashes
  python -m pywin7gate restore <path>     roll back fixes for one file
  python -m pywin7gate status             summary
"""
import os
import sys

from . import fixers, gate
from .iatpatch import restore as iat_restore, is_patched


def _cmd_scan(paths, fix=False):
    ctx = gate.GateContext()
    rep = gate.gate_paths(paths, fix=fix, ctx=ctx)
    print("---")
    print("ok=%d fixed=%d fixable=%d rejected=%d error=%d" % tuple(
        len(rep.get(k, [])) for k in ("ok", "fixed", "fixable",
                                      "rejected", "error")))
    return 1 if rep.get("rejected") or rep.get("error") else 0


def _cmd_pip(args):
    from pip._internal.cli.main import main as pip_main
    rc = pip_main(args)
    if rc == 0 and args and args[0] in ("install", "wheel"):
        print("[pywin7gate] pip done; gating site-packages...")
        _cmd_scan([gate.site_packages()], fix=True)
    return rc


def _cmd_flatten():
    sp = gate.site_packages()
    for libs in fixers.find_vendored_libs(sp):
        acts = fixers.flatten_vendored(sp, libs)
        for dll, dirs in acts:
            print("flattened %s -> %d dir(s)" % (dll, len(dirs)))
    return 0


def _cmd_verify():
    m = gate.load_manifest()
    bad = 0
    for rel, rec in sorted(m["files"].items()):
        p = os.path.join(gate.site_packages(), rel)
        if not os.path.exists(p):
            print("MISSING:", rel)
            bad += 1
            continue
        st = gate.file_stamp(p)
        if st["sha256"] != rec["stamp"]["sha256"]:
            print("CHANGED:", rel)
            bad += 1
    print("verify: %d entries, %d problems" % (len(m["files"]), bad))
    return 1 if bad else 0


def _cmd_restore(path):
    sp = gate.site_packages()
    m = gate.load_manifest(sp)
    rel = os.path.relpath(path, sp)
    rec = m["files"].get(rel)
    if not rec:
        print("no manifest entry for", rel)
        return 1
    for art in rec.get("artifacts", []):
        if art.lower().endswith(".pyw7bak"):
            if os.path.exists(art):
                iat_restore(path[:-len(".pyw7bak")] if False else path)
                print("restored IAT backup for", rel)
        elif os.path.exists(art):
            os.remove(art)
            print("removed artifact", art)
    rec["status"] = "restored"
    gate.save_manifest(m, sp)
    return 0


def _cmd_status():
    m = gate.load_manifest()
    by = {}
    for rec in m["files"].values():
        by[rec.get("status", "?")] = by.get(rec.get("status", "?"), 0) + 1
    print("manifest:", gate.manifest_path())
    for k, v in sorted(by.items()):
        print("  %-10s %d" % (k, v))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "scan" and rest:
        return _cmd_scan(rest, fix=False)
    if cmd == "fix" and rest:
        return _cmd_scan(rest, fix=True)
    if cmd == "fix-all":
        return _cmd_scan([gate.site_packages()], fix=True)
    if cmd == "flatten":
        return _cmd_flatten()
    if cmd == "pip":
        return _cmd_pip(rest)
    if cmd == "verify":
        return _cmd_verify()
    if cmd == "restore" and rest:
        return _cmd_restore(rest[0])
    if cmd == "status":
        return _cmd_status()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

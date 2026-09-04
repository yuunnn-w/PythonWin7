#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""iat_patch.py -- CLI for surgical IAT redirection (engine: pywin7gate.iatpatch).

Examples:
  # redirect two kernel32 imports of python314.dll to KxBase.dll
  iat_patch.py D:\\...\\python314.dll ^
      KERNEL32.dll!AddDllDirectory=KxBase.dll ^
      KERNEL32.dll!RemoveDllDirectory=KxBase.dll

  # with explicit donor (source-dll symbol used as placeholder, must exist
  # on the target OS; default: auto-picked, e.g. Sleep for short victims)
  iat_patch.py foo.pyd KERNEL32.dll!GetThreadDescription=KxBase.dll --donor GetLastError

  iat_patch.py --restore D:\\...\\python314.dll
  iat_patch.py --show    D:\\...\\python314.dll

Creates <file>.pyw7bak backup (once) before modifying.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "src"))

# A patched tree's interpreter preloads pywin7gate (sitecustomize audit
# hook) from its own Lib\; evict it so this checkout's code is used.
for _m in [m for m in list(sys.modules)
           if m == "pywin7gate" or m.startswith("pywin7gate.")]:
    del sys.modules[_m]

from pywin7gate.iatpatch import (IATPatcher, PatchError, is_patched,
                                 list_redirects, restore, sha256_of)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="surgical IAT redirection (see module docstring)")
    ap.add_argument("file", help="PE file to patch (.dll/.pyd/.exe)")
    ap.add_argument("specs", nargs="*",
                    help="SRC.DLL!Func=DST.DLL[!Func2] entries")
    ap.add_argument("--donor", default=None,
                    help="placeholder symbol that must exist in SRC.DLL on "
                         "the target OS (default: auto-picked per source DLL "
                         "from pywin7gate.iatpatch.DONOR_CANDIDATES)")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--no-backup", action="store_true")
    args = ap.parse_args(argv)

    if args.restore:
        restore(args.file)
        print("restored:", args.file)
        return 0
    if args.show:
        print("patched:", is_patched(args.file))
        for r in list_redirects(args.file):
            print("  %s: %s (iat %s)" % (r["dll"], ", ".join(r["funcs"]),
                                         r["iat_rva"]))
        return 0
    if not args.specs:
        ap.error("nothing to do (no specs given)")

    p = IATPatcher(args.file)
    for spec in args.specs:
        lhs, _eq, rhs = spec.partition("=")
        if not _eq:
            ap.error("bad spec: " + spec)
        src_dll, _b, func = lhs.partition("!")
        dst_dll, _b2, dst_func = rhs.partition("!")
        if not (src_dll and func and dst_dll):
            ap.error("bad spec: " + spec)
        p.redirect(src_dll, func, dst_dll, dst_func or func, args.donor)
    rec = p.commit(backup=not args.no_backup)
    print("patched:", rec["file"])
    print("sha256:", rec["sha256_after"])
    for r in rec["redirects"]:
        print("  %s -> %s   (donor %s, slot %s)" %
              (r["src"], r["dst"], r["donor"], r["iat_slot_rva"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PatchError as e:
        print("patch error:", e, file=sys.stderr)
        sys.exit(1)

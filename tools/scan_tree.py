#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_tree.py -- whole-tree static Win7 acceptance scan.

Walks a Python tree (or any directory) and checks every .exe/.dll/.pyd
against the bare-Win7 SP1 (6.1.7600) API baseline, using the vendored
pywin7gate PE parser and the JSON baseline.  Each binary's own directory,
the tree root and ``DLLs/`` count as privately-deployed DLL dirs (this
models how the Windows loader actually resolves siblings).

Additionally reports (as warnings, not failures) images whose PE header
declares OS/subsystem version > 6.1: they would trip the CreateProcessInternalW
subsystem-version check on Win7 -- acceptable when KxBase.dll is deployed
(it patches that check), fatal otherwise.

Usage:
    python scan_tree.py [TREE] [--json OUT.json] [--quiet]
                        [--max-report N] [--no-version-warn]

Exit code: 0 = clean, 1 = unresolvable imports found, 2 = usage error.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

# A patched tree's interpreter preloads pywin7gate (sitecustomize audit
# hook) from its own Lib\; evict it so this checkout's code is used.
for _m in [m for m in list(sys.modules)
           if m == "pywin7gate" or m.startswith("pywin7gate.")]:
    del sys.modules[_m]

from pywin7gate import pe as pemod                            # noqa: E402

BIN_EXT = (".exe", ".dll", ".pyd")


def iter_binaries(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.lower().endswith(BIN_EXT):
                yield os.path.join(dirpath, fn)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tree", nargs="?",
                    default=os.path.normpath(os.path.join(
                        HERE, "..", "..", "..", "Python", "Python314")))
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--max-report", type=int, default=200)
    ap.add_argument("--no-version-warn", action="store_true")
    args = ap.parse_args(argv)

    tree = os.path.normpath(args.tree)
    if not os.path.isdir(tree):
        print("error: not a directory: " + tree, file=sys.stderr)
        return 2

    baseline = pemod.load_baseline()
    extra = pemod.ExtraDllIndex([tree, os.path.join(tree, "DLLs")])

    scanned = 0
    skipped_non_x64 = []
    errors = []
    files_with_missing = []
    version_warnings = []
    for path in iter_binaries(tree):
        extra.add_dir(os.path.dirname(path))
        try:
            r = pemod.scan_file(path, baseline, extra)
        except (pemod.PEError, OSError) as e:
            errors.append({"file": path, "error": str(e)})
            continue
        if r["machine"] != "x64":
            # this pack is amd64-only; x86/arm images (e.g. pip's vendored
            # distlib stub templates) can never be judged by the x64
            # baseline and are never executed by the deployment
            skipped_non_x64.append({"file": path, "machine": r["machine"]})
            continue
        scanned += 1
        if r["missing"]:
            files_with_missing.append(r)
        # PE-version check matters only for EXE images (CreateProcess' CPIW
        # subsystem-version check); DLLs are not version-checked on load
        if not args.no_version_warn and path.lower().endswith(".exe"):
            mj, mn = (int(x) for x in r["os_version"].split("."))
            smj, smn = (int(x) for x in r["subsystem_version"].split("."))
            if (mj, mn) > (6, 1) or (smj, smn) > (6, 1):
                version_warnings.append(
                    {"file": path, "os_version": r["os_version"],
                     "subsystem_version": r["subsystem_version"]})

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"tree": tree, "scanned": scanned,
                       "files_with_missing": files_with_missing,
                       "version_warnings": version_warnings,
                       "skipped_non_x64": skipped_non_x64,
                       "errors": errors}, f, indent=1, ensure_ascii=False)

    if not args.quiet:
        print("tree:    ", tree)
        print("scanned: ", scanned, "binaries")
        if files_with_missing:
            print("\nUNRESOLVABLE ON BARE WIN7 SP1:")
            for r in files_with_missing[:args.max_report]:
                rel = os.path.relpath(r["file"], tree)
                by_dll = {}
                for mrec in r["missing"]:
                    by_dll.setdefault(mrec["dll"], set()).add(mrec["func"])
                for dll, funcs in sorted(by_dll.items()):
                    print("  %s: %s!%s" % (rel, dll, "/".join(sorted(funcs))))
            if len(files_with_missing) > args.max_report:
                print("  ... and %d more files" %
                      (len(files_with_missing) - args.max_report))
        if version_warnings:
            print("\nPE version warnings (>6.1; need KxBase CPIW bypass):")
            for w in version_warnings[:args.max_report]:
                print("  %s (os=%s subsystem=%s)" %
                      (os.path.relpath(w["file"], tree),
                       w["os_version"], w["subsystem_version"]))
        if errors:
            print("\nunparseable files:")
            for e in errors[:args.max_report]:
                print("  %s: %s" % (os.path.relpath(e["file"], tree),
                                    e["error"]))
        if skipped_non_x64:
            print("\nskipped non-x64 images (pack is amd64-only): %d" %
                  len(skipped_non_x64))
            for s in skipped_non_x64[:10]:
                print("  %s (%s)" % (os.path.relpath(s["file"], tree),
                                     s["machine"]))
    print("summary: scanned=%d missing=%d version-warn=%d "
          "skipped-non-x64=%d errors=%d" %
          (scanned, len(files_with_missing), len(version_warnings),
           len(skipped_non_x64), len(errors)))
    return 1 if files_with_missing else 0


if __name__ == "__main__":
    sys.exit(main())

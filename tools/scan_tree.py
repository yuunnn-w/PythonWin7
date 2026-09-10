#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_tree.py -- whole-tree static Win7 acceptance scan.

Walks a Python tree (or any directory) and checks every .exe/.dll/.pyd
against the bare-Win7 SP1 (6.1.7600) API baseline, using the vendored
pywin7gate PE parser and the JSON baseline.  Each binary's own directory,
the tree root and ``DLLs/`` count as privately-deployed DLL dirs (this
models how the Windows loader actually resolves siblings).

Imports that cannot resolve statically are then classified:

  * runtime-covered  -- PyKexBoot's load-time import rewrite (KxBase.dll +
    PyKexBoot.dll present in the tree root) substitutes the descriptor at
    load time; verified against the tree's real Kx*.dll export tables.
    Pass --static-only to disable this model.
  * optional-absent  -- the provider DLL is an optional vendor runtime
    (MPI, MATLAB engine, solver SDKs, debug CRT, Qt5 add-ons the PyQt5
    wheel never shipped, ...) that is absent everywhere; the feature is
    dead on stock Windows too, so it is not a Win7 defect.
  * bootstrap        -- the provider DLL exists elsewhere in the tree and
    is loaded by the package's own ctypes/add_dll_directory bootstrap
    (e.g. shapely.libs), invisible to the OS loader's static view.

Only imports failing all of the above count as failures.

Additionally reports (as warnings, not failures) images whose PE header
declares OS/subsystem version > 6.1: they would trip the CreateProcessInternalW
subsystem-version check on Win7 -- acceptable when KxBase.dll is deployed
(it patches that check), fatal otherwise.

Usage:
    python scan_tree.py TREE [--json OUT.json] [--quiet]
                        [--max-report N] [--no-version-warn] [--static-only]
    (TREE may also be set via the PYW7_TREE environment variable)

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
from pywin7gate import fixers                                 # noqa: E402

BIN_EXT = (".exe", ".dll", ".pyd")

# Optional third-party provider DLLs that are legitimately absent from the
# tree: the importing module is an optional backend/plugin that is equally
# dead on a stock Windows box without the vendor runtime (MPI redists,
# MATLAB engine, commercial solver SDKs, debug CRTs, Qt5 add-on modules the
# PyQt5 wheel itself does not ship, numba's optional TBB pool, ...).
OPTIONAL_PROVIDERS = {
    "impi.dll", "msmpi.dll", "msmpires.dll",
    "libmx.dll", "libmat.dll", "libeng.dll",
    "libmad.dll",
    "msvcr120.dll", "msvcr120d.dll", "msvcp120.dll",
    "vcruntime140d.dll", "vcruntime140_1d.dll", "ucrtbased.dll",
    "msvcp140d.dll", "concrt140d.dll",
    "tbb12.dll", "tbbmalloc.dll", "tbbmalloc_proxy.dll",
    "libxprs.dll", "knitro.dll", "worhp.dll", "snopt7.dll", "cpoptimizer.dll",
    "libhsl.dll",                                   # casadi 的 HSL MA27 插件（商业许可求解器）
    "qt53drender.dll", "qt53dcore.dll", "qt53dextras.dll", "qt53dinput.dll",
    "qt53dlogic.dll", "qt53dquick.dll", "qt53dquickrender.dll",
    "qt53danimation.dll", "qt53dquickscene2d.dll",
    "qt5webengine.dll", "qt5webenginecore.dll", "qt5webenginewidgets.dll",
    "qt5multimediaquick.dll",
    # netCDF4 的 HDF5 滤镜插件引用的宿主/压缩库（delvewheel 漏改名的上游
    # 缺陷，插件在原生 Windows 上同样加载不到；缺了只是对应滤镜不可用）
    "netcdf.dll", "hdf5.dll", "hdf5_hl.dll", "szip.dll",
    "snappy.dll", "libbz2.dll", "zlib-ng2.dll",
    # winpty 附带的 Win10+ ConPTY 宿主（Win7 走管道后端，从不用它）
    "icu.dll",
    # magika.exe 的 DirectML 推理后端（Win10 1903+；Python API 走 onnxruntime CPU）
    "dxcore.dll", "directml.dll",
}

# 整族可选提供方（版本化命名，逐版本枚举不现实）：VTK —— pythonocc 的
# TKIVtk 桥接模块专用，未装 VTK 时该模块在任何 OS 上都不可用。
OPTIONAL_PROVIDER_PREFIXES = ("vtk",)


def runtime_cover_checker(tree):
    """Return a predicate import_rec -> bool telling whether the runtime
    layer (PyKexBoot load-time import rewrite) resolves an import that the
    static file layer cannot.  Active only when the tree actually carries
    KxBase.dll + PyKexBoot.dll; otherwise everything is 'not covered'."""
    have = (os.path.isfile(os.path.join(tree, "KxBase.dll")) and
            os.path.isfile(os.path.join(tree, "PyKexBoot.dll")))
    if not have:
        return None
    kx_index = fixers.build_kx_index(tree)

    def covers(mrec):
        tgt = fixers.find_runtime_redirect(mrec["dll"])
        if not tgt:
            return False
        func = (mrec.get("func") or "").lower()
        if not func or func.startswith("#"):
            return True                    # ordinal import: name unknown
        exports = kx_index.get(tgt.lower())
        if exports is None:
            return True                    # plain Win7 system dll target
        return func in exports

    return covers


def iter_binaries(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.lower().endswith(BIN_EXT):
                yield os.path.join(dirpath, fn)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tree", nargs="?",
                    default=os.environ.get("PYW7_TREE"),
                    help="Python tree (or any directory) to scan; may also "
                         "be set via the PYW7_TREE environment variable")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--max-report", type=int, default=200)
    ap.add_argument("--no-version-warn", action="store_true")
    ap.add_argument("--static-only", action="store_true",
                    help="do not model the runtime layer (PyKexBoot import "
                         "rewrite); every import must resolve statically")
    args = ap.parse_args(argv)

    if not args.tree:
        print("error: no tree given; pass TREE or set PYW7_TREE",
              file=sys.stderr)
        return 2
    tree = os.path.normpath(args.tree)
    if not os.path.isdir(tree):
        print("error: not a directory: " + tree, file=sys.stderr)
        return 2

    baseline = pemod.load_baseline()
    extra = pemod.ExtraDllIndex([tree, os.path.join(tree, "DLLs")])
    covers = None if args.static_only else runtime_cover_checker(tree)
    # global binary-name index: a provider DLL that exists somewhere in the
    # tree but is imported from elsewhere is loaded by the package's own
    # bootstrap (ctypes / add_dll_directory), not by the OS loader -- the
    # shapely.libs case.  Reported separately, not a failure.
    all_names = {os.path.basename(p).lower() for p in iter_binaries(tree)}

    scanned = 0
    skipped_non_x64 = []
    errors = []
    files_with_missing = []
    version_warnings = []
    runtime_covered = 0
    optional_absent = []
    bootstrap_resolved = []
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
            keep = []
            for mrec in r["missing"]:
                low = mrec["dll"].lower()
                if covers and covers(mrec):
                    runtime_covered += 1
                elif (low in OPTIONAL_PROVIDERS or
                        low.startswith(OPTIONAL_PROVIDER_PREFIXES)) and \
                        low not in all_names:
                    optional_absent.append({"file": path, **mrec})
                elif low not in baseline and low in all_names:
                    bootstrap_resolved.append({"file": path, **mrec})
                else:
                    keep.append(mrec)
            r["missing"] = keep
            if keep:
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
                       "runtime_covered_imports": runtime_covered,
                       "optional_absent_imports": optional_absent,
                       "bootstrap_resolved_imports": bootstrap_resolved,
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
        if runtime_covered:
            print("\nruntime-covered imports (PyKexBoot rewrites them at "
                  "load): %d" % runtime_covered)
        if optional_absent:
            print("\noptional providers absent (feature equally dead on "
                  "stock Windows; not a Win7 defect): %d" %
                  len(optional_absent))
            by = {}
            for o in optional_absent:
                by.setdefault(o["dll"].lower(), set()).add(o["file"])
            for dll, fs in sorted(by.items()):
                print("  %s  <- %d file(s), e.g. %s" %
                      (dll, len(fs),
                       os.path.relpath(sorted(fs)[0], tree)))
        if bootstrap_resolved:
            print("\npackage-bootstrap resolved (provider ships elsewhere "
                  "in tree, loaded via ctypes/add_dll_directory): %d" %
                  len(bootstrap_resolved))
            by = {}
            for o in bootstrap_resolved:
                by.setdefault(o["dll"].lower(), set()).add(o["file"])
            for dll, fs in sorted(by.items()):
                print("  %s  <- %d file(s), e.g. %s" %
                      (dll, len(fs),
                       os.path.relpath(sorted(fs)[0], tree)))
    print("summary: scanned=%d missing=%d runtime-covered=%d "
          "optional-absent=%d bootstrap=%d version-warn=%d "
          "skipped-non-x64=%d errors=%d" %
          (scanned, len(files_with_missing), runtime_covered,
           len(optional_absent), len(bootstrap_resolved),
           len(version_warnings), len(skipped_non_x64), len(errors)))
    return 1 if files_with_missing or errors else 0


if __name__ == "__main__":
    sys.exit(main())

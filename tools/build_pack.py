#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_pack.py -- one-shot assembly of a Win7-compatible Python tree.

Works on any official CPython 3.9+ x64 install/embeddable tree (3.9-3.14+
verified by design; the version-specific bits are discovered by scanning the
tree, not hardcoded).  Run on the dev machine.  Idempotent.

    python tools\\build_pack.py --target <PYTHON_DIR> --dry-run
    python tools\\build_pack.py --target <PYTHON_DIR>
    python tools\\build_pack.py --target <PYTHON_DIR> --restore

IMPORTANT: run it with a DIFFERENT interpreter than the target tree's own
python.exe.  Patching rewrites the tree's core python3XX.dll in place, and
Windows keeps that DLL locked while it is loaded by the very process doing
the work.  build_pack detects this and refuses (exit 2).  Any other 3.9+
interpreter (a second tree, a system Python) will do.  --dry-run is exempt.

Steps performed (each recorded in <tree>\\pywin7-pack-manifest.json):
  1. copy the KB2999226 UCRT file set (ucrtbase.dll + 23 api-ms-*.dll) from
     assets\\kb2999226\\amd64 into the tree root;
  2. copy the VxKex binaries (KexDll.dll + 12 Kx*.dll; KxDw.dll deliberately
     excluded) into the tree root.  Skipped with --no-vxkex (pure-shim
     fallback route);
  3. copy msvcp140.dll / msvcp140_1.dll / msvcp140_2.dll /
     vcruntime140_threads.dll from
     assets\\msvc-redist (override with --msvcp-dir);
  4. scan the core DLLs (python3XX.dll / python3XXt.dll, auto-detected)
     against the bare-Win7 baseline and IAT-patch every import that has no
     file resolution: system-DLL Win8+ functions are redirected to the Kx*.dll
     that exports them (3.14: KERNEL32!AddDllDirectory/RemoveDllDirectory ->
     KxBase.dll; most older versions need zero patches), api-set names with
     no target-OS file are retargeted wholesale.  This is the bootstrap the
     runtime layer needs to reach injection; originals kept as *.pyw7bak;
  5. install pywin7gate into Lib\\pywin7gate and Lib\\sitecustomize.py
     (embeddable trees: <python3XX>._pth is extended with Lib /
     Lib\\site-packages / "import site" so the gate loads);
  6. flatten vendored *.libs in site-packages (numpy.libs etc.) and gate
     every binary already in site-packages;
  7. install the runtime layer (default; disable with --no-launcher):
     the entry-point exes (python.exe, pythonw.exe, pythonX.Yt.exe,
     pythonwX.Yt.exe -- whatever the tree actually contains) are renamed to
     their versioned names and replaced by the PyKexLdr launcher variants;
     PyKexBoot.dll goes into the tree root.  The launcher injects
     KexDll.dll + PyKexBoot.dll into every interpreter process, which then
     rewrites imports of later-loaded modules in memory and propagates into
     every child process.  Command lines pass through verbatim, so venv
     keeps working;
  8. relocatable Scripts shims: copy the CRT-free PyKexExe stubs
     (PyKexExe.exe / PyKexExeW.exe) into the tree root and rewrite every
     python console script in Scripts to the PyKexExe layout
     ([stub]["#!pyw7-relocatable"][zip payload]).  The stub finds
     python[w].exe RELATIVE TO ITS OWN PATH, so the packed tree runs from
     any directory, after any move/copy/rename, with zero commands and zero
     hardcoded paths.  Originals are kept in Scripts\\pyw7bak\\;
     Scripts\\.pyw7loc records the pack-time root so sitecustomize can
     repair legacy (never-converted) shims silently after a move;
  9. patch jupyterlab's node/yarn probe (site-patch): wrap _yarn_config /
     _node_check in SetErrorMode so a Win8+-only node.exe found on PATH
     cannot pop a modal loader dialog; skipped when jupyterlab is absent;
 10. write the manifest and re-scan the core DLLs: anything still
     unresolvable on bare Win7 SP1 is reported (nonzero exit).

Undo everything with --restore.
"""
import argparse
import datetime
import glob
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PYW7 = os.path.normpath(os.path.join(HERE, ".."))              # PythonWin7 repo
sys.path.insert(0, os.path.join(PYW7, "src"))

# When run under a *patched* tree's interpreter, that tree's sitecustomize
# has already imported pywin7gate (the audit hook) from its own Lib\ -- an
# installed copy that may be older than this checkout.  Evict preloaded
# copies so the repo's current code is what the tool actually uses.
for _m in [m for m in list(sys.modules)
           if m == "pywin7gate" or m.startswith("pywin7gate.")]:
    del sys.modules[_m]

from pywin7gate import fixers, gate, shims as shimod            # noqa: E402
from pywin7gate import pe as pemod                          # noqa: E402
from pywin7gate.iatpatch import (IATPatcher, PatchError,      # noqa: E402
                                 is_patched, restore as iat_restore,
                                 sha256_of)

KB_DIR = os.path.join(PYW7, "assets", "kb2999226", "amd64")
KEX_REL = os.path.join(PYW7, "third_party", "vxkex")
KEX_CORE64 = os.path.join(KEX_REL, "Core64")
KEX_KEX64 = os.path.join(KEX_REL, "Kex64")
MSVCP_BUNDLED = os.path.join(PYW7, "assets", "msvc-redist")
RUNTIME = os.path.join(PYW7, "runtime")

# KxDw.dll is deliberately NOT deployed: it imports dwrw10.dll!
# DWriteCoreCreateFactory, which is unresolvable on bare Win7 (dwrw10 cannot
# be backported).  DirectWrite is only needed by Chromium-family apps, not
# by CPython.  (The file stays vendored in third_party/vxkex for reference.)
KX_FILES = ["KxAdvapi.dll", "KxBase.dll", "KxCom.dll", "KxCrt.dll",
            "KxCryp.dll", "KxDx.dll", "KxMi.dll", "KxNet.dll",
            "KxNt.dll", "KxSChanl.dll", "KxUia.dll", "KxUser.dll"]
MSVCP_FILES = ["msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
               "vcruntime140_threads.dll"]

MANIFEST = "pywin7-pack-manifest.json"

# entry-point exe names we know how to shim: python.exe, pythonw.exe,
# python3.exe, pythonX.Y.exe, pythonX.Yt.exe, pythonwX.Y.exe, ...
ENTRY_EXE_RE = re.compile(r"^python(w)?(\d+(\.\d+)*t?)?\.exe$",
                          re.IGNORECASE)


def detect_version_stems(tree):
    """Scan the tree root for python3*.dll (excluding the python3.dll
    stable-ABI shim).  Returns stems like ['314', '314t']."""
    stems = []
    for fn in sorted(os.listdir(tree)):
        low = fn.lower()
        m = re.match(r"^python(3\d+t?)\.dll$", low)
        if m:
            stems.append(m.group(1))
    return stems


def pick_stem(stems, want_t):
    non_t = [s for s in stems if not s.endswith("t")]
    t = [s for s in stems if s.endswith("t")]
    if want_t:
        return (t or non_t or [None])[0]
    return (non_t or t or [None])[0]


def launcher_entries(tree, stems):
    """(orig_name, renamed_name, launcher_binary) for every entry-point exe
    actually present in the tree root."""
    entries = []
    try:
        root_files = os.listdir(tree)
    except OSError:
        return entries
    for fn in sorted(root_files):
        if not ENTRY_EXE_RE.match(fn):
            continue
        low = fn.lower()
        gui = low.startswith("pythonw")
        want_t = low.endswith("t.exe")
        stem = pick_stem(stems, want_t)
        if not stem:
            continue
        renamed = ("pythonw" if gui else "python") + stem + ".exe"
        ldr = "PyKexLdrW.exe" if gui else "PyKexLdr.exe"
        entries.append((fn, renamed, ldr))
    # deterministic order: plain python.exe / pythonw.exe first
    entries.sort(key=lambda e: (0 if e[0].lower() in ("python.exe",
                                                      "pythonw.exe")
                                else 1, e[0].lower()))
    return entries


def find_msvcp_dir():
    if all(os.path.isfile(os.path.join(MSVCP_BUNDLED, f))
           for f in MSVCP_FILES):
        return MSVCP_BUNDLED
    pats = [
        r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Redist\MSVC\*"
        r"\x64\Microsoft.VC143.CRT",
        r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Redist\MSVC\*"
        r"\x64\Microsoft.VC143.CRT",
    ]
    cands = []
    for pat in pats:
        cands += glob.glob(pat)
    for c in sorted(cands, reverse=True):
        if all(os.path.isfile(os.path.join(c, f)) for f in MSVCP_FILES):
            return c
    return None


def interpreter_inside_tree(tree):
    """Return the executable path if the *running* interpreter lives in the
    target tree.  Patching from inside the target tree fails on Windows:
    the core python3XX.dll is already loaded by this very process and the
    loader keeps it locked against in-place rewrite (and --restore needs
    the same write access)."""
    t = os.path.normcase(os.path.normpath(tree))
    for attr in ("executable", "base_executable", "_base_executable"):
        exe = getattr(sys, attr, None)
        if not exe:
            continue
        try:
            d = os.path.normcase(os.path.normpath(
                os.path.dirname(os.path.realpath(exe))))
        except OSError:
            continue
        if d == t or d.startswith(t + os.sep):
            return exe
    return None


def copy_set(files, src_dir, dst_dir, actions, dry_run, log):
    for f in files:
        src = os.path.join(src_dir, f)
        dst = os.path.join(dst_dir, f)
        if not os.path.isfile(src):
            raise SystemExit("missing source file: " + src)
        if os.path.exists(dst):
            log("  exists:  %s" % f)
            continue
        if not dry_run:
            shutil.copy2(src, dst)
        actions.append({"action": "copy", "file": f,
                        "sha256": sha256_of(src) if not dry_run else None})
        log("  copied:  %s" % f)


def install_launchers(tree, entries, actions, dry_run, log):
    """Rename entry exes and install PyKexLdr under the original names."""
    ldr = os.path.join(RUNTIME, "PyKexLdr")
    boot = os.path.join(RUNTIME, "PyKexBoot", "PyKexBoot.dll")
    for _, _, lname in entries:
        if not os.path.isfile(os.path.join(ldr, lname)):
            raise SystemExit(
                "launcher binary missing: %s -- build it first with "
                "runtime\\PyKexLdr\\build.bat" % os.path.join(ldr, lname))
    if not os.path.isfile(boot):
        raise SystemExit("PyKexBoot.dll missing -- build it first with "
                         "runtime\\PyKexBoot\\build.bat")
    for orig, renamed, lname in entries:
        p_orig = os.path.join(tree, orig)
        p_ren = os.path.join(tree, renamed)
        if os.path.normcase(orig) == os.path.normcase(renamed):
            continue
        if not os.path.isfile(p_orig):
            log("  skip (absent): %s" % orig)
            continue
        if is_launcher_installed(p_orig):
            src = os.path.join(ldr, lname)
            if not dry_run and sha256_of(p_orig) != sha256_of(src):
                shutil.copy2(src, p_orig)     # stale launcher build: refresh
                actions.append({"action": "copy", "file": orig,
                                "sha256": sha256_of(src)})
                log("  launcher refreshed (new build): %s" % orig)
            else:
                log("  already installed: %s" % orig)
            continue
        if not dry_run:
            if os.path.normcase(p_orig) != os.path.normcase(p_ren) and \
                    not os.path.isfile(p_ren):
                os.rename(p_orig, p_ren)
                actions.append({"action": "rename",
                                "from": orig, "to": renamed})
            shutil.copy2(os.path.join(ldr, lname), p_orig)
        actions.append({"action": "copy", "file": orig,
                        "sha256": sha256_of(os.path.join(ldr, lname))
                        if not dry_run else None})
        log("  launcher:  %s (real -> %s)" % (orig, renamed))
    dst = os.path.join(tree, "PyKexBoot.dll")
    if not os.path.exists(dst):
        if not dry_run:
            shutil.copy2(boot, dst)
        actions.append({"action": "copy", "file": "PyKexBoot.dll",
                        "sha256": sha256_of(boot) if not dry_run else None})
        log("  copied:  PyKexBoot.dll")


def is_launcher_installed(path):
    """Heuristic: the file is one of our CRT-free launchers (imports only
    kernel32, tiny)."""
    try:
        pe = pemod.PEFile(path)
        imps = pe.imports()
        dlls = {dll.lower() for dll, _f, _i in imps}
        return dlls == {"kernel32.dll"} and len(pe.data) < 64 * 1024
    except (pemod.PEError, OSError):
        return False


# Python 3.13+ ships venv redirector exes under Lib\venv\scripts\nt\ which
# venv copies into <venv>\Scripts as python.exe/pythonw.exe.  The stock
# redirectors import api-ms-win-core-path-l1-1-0.dll (PathCch*), which does
# not exist on a bare Win7 -- every venv interpreter then fails to start
# with STATUS_DLL_NOT_FOUND.  Replace them with PyKexLdr builds (kernel32
# only); the launcher's pyvenv.cfg fallback handles the venv case.
VENV_REDIRECTORS = (
    ("venvlauncher.exe", "PyKexLdr.exe"),
    ("venvlaunchert.exe", "PyKexLdr.exe"),
    ("venvwlauncher.exe", "PyKexLdrW.exe"),
    ("venvwlaunchert.exe", "PyKexLdrW.exe"),
)


def replace_venv_redirectors(tree, actions, dry_run, log):
    """Swap the 3.13+ venv redirector exes for PyKexLdr variants.
    Originals move to Lib\\venv\\pyw7bak\\ (NOT kept in scripts\\nt: venv
    copies every file it finds there into new venvs)."""
    nt_dir = os.path.join(tree, "Lib", "venv", "scripts", "nt")
    if not os.path.isdir(nt_dir):
        return
    bak_dir = os.path.join(tree, "Lib", "venv", "pyw7bak")
    ldr_dir = os.path.join(RUNTIME, "PyKexLdr")
    for name, lname in VENV_REDIRECTORS:
        p = os.path.join(nt_dir, name)
        if not os.path.isfile(p):
            continue                       # pre-3.13 tree: nothing to do
        if is_launcher_installed(p):
            src = os.path.join(ldr_dir, lname)
            if not dry_run and sha256_of(p) != sha256_of(src):
                shutil.copy2(src, p)
                actions.append({"action": "copy", "file":
                                os.path.relpath(p, tree),
                                "sha256": sha256_of(src)})
                log("  venv redirector refreshed (new build): %s" % name)
            else:
                log("  venv redirector already ours: %s" % name)
            continue
        rel = os.path.relpath(p, tree)
        bak = os.path.join(bak_dir, name)
        if not dry_run and not os.path.isfile(bak):
            os.makedirs(bak_dir, exist_ok=True)
            os.rename(p, bak)
            actions.append({"action": "rename",
                            "from": rel,
                            "to": os.path.relpath(bak, tree)})
        if not dry_run:
            shutil.copy2(os.path.join(ldr_dir, lname), p)
        actions.append({"action": "copy", "file": rel,
                        "sha256": sha256_of(os.path.join(ldr_dir, lname))
                        if not dry_run else None})
        log("  venv redirector: %s -> %s (orig -> Lib\\venv\\pyw7bak\\)"
            % (name, lname))


def convert_script_shims(tree, actions, dry_run, log):
    """Rewrite every python console script in Scripts to the relocatable
    PyKexExe layout: [CRT-free stub]["#!pyw7-relocatable"][zip payload].
    The stub resolves python[w].exe relative to its own path (venv Scripts
    -> sibling; tree Scripts -> parent), so a moved/copied tree needs zero
    commands.  Original stubs are kept in Scripts\\pyw7bak\\."""
    scripts = os.path.join(tree, "Scripts")
    if not os.path.isdir(scripts):
        log("  no Scripts dir; nothing to convert")
        return
    if dry_run:
        n = 0
        for fn in sorted(os.listdir(scripts)):
            if not fn.lower().endswith(".exe"):
                continue
            info = shimod.read_shim(os.path.join(scripts, fn))
            if info and not info["converted"]:
                n += 1
        log("  would convert %d shim(s) to PyKexExe stubs" % n)
        return

    def on_convert(rel, bak_rel):
        actions.append({"action": "shim-convert", "file": rel,
                        "backup": bak_rel})

    counts = shimod.convert_tree(tree, log=log, on_convert=on_convert)
    log("  shims: %d converted, %d stub-refreshed, %d already relocatable, "
        "%d skipped"
        % (counts["converted"], counts["updated"], counts["ok"],
           counts["skip"]))


def write_relocation_stamp(tree, actions, dry_run, log):
    """Scripts\\.pyw7loc records the pack-time tree root.  sitecustomize
    compares it at every interpreter start and silently rewrites LEGACY
    (never PyKexExe-converted) shim shebangs when the tree was moved."""
    scripts = os.path.join(tree, "Scripts")
    if not os.path.isdir(scripts):
        return
    stamp = os.path.join(scripts, ".pyw7loc")
    rel = os.path.relpath(stamp, tree)
    if os.path.isfile(stamp):
        log("  stamp exists: %s" % rel)
        return
    log("  stamp: %s" % rel)
    if not dry_run:
        with open(stamp, "w", encoding="utf-8") as f:
            f.write(os.path.normpath(tree))
    actions.append({"action": "write-file", "file": rel})


def fix_pth_files(tree, stems, actions, dry_run, log):
    """Embeddable trees carry python3XX._pth files that disable site (and
    with it sitecustomize + site-packages).  Append the lines the gate
    needs.  Original content is recorded in the manifest for --restore."""
    for stem in stems:
        name = "python%s._pth" % stem
        p = os.path.join(tree, name)
        if not os.path.isfile(p):
            continue
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        have = {ln.strip().lower() for ln in lines}
        add = [ln for ln in ("Lib", "Lib\\site-packages", "import site")
               if ln.lower() not in have]
        if not add:
            log("  ._pth ok: %s" % name)
            continue
        log("  ._pth += %s: %s" % (", ".join(add), name))
        if not dry_run:
            with open(p, "a", encoding="ascii") as f:
                f.write("\r\n# added by PythonWin7 build_pack:\r\n")
                for ln in add:
                    f.write(ln + "\r\n")
        actions.append({"action": "pth-append", "file": name,
                        "original": lines})


def patch_core_dlls(tree, stems, iat_fallback_target, kx_index, baseline,
                    extra_dirs, actions, dry_run, log):
    """Scan-driven bootstrap patch of python3XX.dll[/t]: every import that
    cannot resolve on bare Win7 (after the file copies of steps 1-3) gets
    redirected to a Kx*.dll (or retargeted wholesale for file-less api-set
    names).  Zero patches is a normal outcome on older Pythons."""
    for stem in stems:
        dll = "python%s.dll" % stem
        path = os.path.join(tree, dll)
        if not os.path.isfile(path):
            continue
        extra = pemod.ExtraDllIndex(extra_dirs)
        r = pemod.scan_file(path, baseline, extra)
        missing = r["missing"]
        if not missing:
            log("  %s: nothing to patch (no unresolvable imports)" % dll)
            continue
        if is_patched(path):
            log("  already patched: %s" % dll)
            continue

        patcher = IATPatcher(path)
        jobs_desc = []
        bad = []
        by_dll = {}
        for mm in missing:
            by_dll.setdefault(mm["dll"], []).append(mm["func"])
        for src_dll, funcs in sorted(by_dll.items()):
            low = src_dll.lower()
            if low in gate.UNSUPPORTED_DLLS:
                bad.append("%s (unsupported on bare Win7)" % src_dll)
                continue
            if low in baseline:
                for fn in sorted(set(funcs)):
                    tgt = fixers.find_kx_target(src_dll, fn, kx_index)
                    if not tgt and iat_fallback_target:
                        tgt = iat_fallback_target
                    if not tgt:
                        bad.append("%s!%s (no shim implementation)"
                                   % (src_dll, fn))
                        continue
                    # queue the redirect even in dry-run mode (rolled back
                    # below): donor auto-pick and import-table lookup are
                    # pure reads, and queueing is what validates them, so
                    # the dry-run stays a faithful preview.
                    try:
                        patcher.redirect(src_dll, fn, tgt)
                    except PatchError as e:
                        bad.append("%s!%s (%s)" % (src_dll, fn, e))
                        continue
                    jobs_desc.append("%s!%s->%s" % (src_dll, fn, tgt))
                continue
            # DLL with no file on bare Win7: whole-descriptor retarget
            rtgt = fixers.find_runtime_redirect(src_dll)
            if rtgt and not dry_run:
                ctx = gate.GateContext(root=tree, log=log)
                ctx.lazy_init()
                exp = ctx.dll_exports(rtgt.lower())
                if exp is not None:
                    patcher.retarget_dll(src_dll, rtgt, exp)
                    jobs_desc.append("%s=>%s" % (src_dll, rtgt))
                    continue
            elif rtgt:
                jobs_desc.append("%s=>%s" % (src_dll, rtgt))
                continue
            bad.append("%s (%s) -- no resolution" %
                       (src_dll, ", ".join(sorted(set(funcs))[:4])))
        if bad:
            for line in bad:
                log("  !! %s" % line)
            raise SystemExit("core DLL %s has unfixable imports -- aborting"
                             % dll)
        before = sha256_of(path)
        rec = None
        if not dry_run:
            rec = patcher.commit(backup=True)
            n = len(rec["redirects"]) + len(rec.get("retargets", []))
            log("  patched: %s (%d import job(s))" % (dll, n))
        else:
            patcher.rollback()
            for j in jobs_desc:
                log("  would patch: %s  %s" % (dll, j))
        actions.append({"action": "iat-patch", "file": dll,
                        "sha256_before": before,
                        "imports": jobs_desc})


_JLAB_HELPERS = '''def _suppress_loader_popups():
    """PythonWin7: on Windows, keep a broken child process (e.g. a Win8+-only
    node.exe found on PATH) from popping a modal loader dialog; the error
    mode is inherited by the child.  Returns the previous mode, else None."""
    if os.name != "nt":
        return None
    import ctypes
    SEM_FAILCRITICALERRORS = 0x1
    SEM_NOGPFAULTERRORBOX = 0x2
    SEM_NOOPENFILEERRORBOX = 0x8000
    return ctypes.windll.kernel32.SetErrorMode(
        SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)


def _restore_error_mode(prev):
    if prev is not None:
        import ctypes
        ctypes.windll.kernel32.SetErrorMode(prev)


'''

# (anchor, replacement) pairs against upstream jupyterlab/commands.py 4.x
_JLAB_SUBS = [
    ("def _node_check(logger):",
     _JLAB_HELPERS + "def _node_check(logger):"),
    ('    node = which("node")\n'
     '    try:\n'
     '        output = subprocess.check_output([node, "node-version-check.js"], cwd=HERE)  # noqa S603\n'
     '        logger.debug(output.decode("utf-8"))\n'
     '    except Exception:',
     '    node = which("node")\n'
     '    _em = _suppress_loader_popups()\n'
     '    try:\n'
     '        try:\n'
     '            output = subprocess.check_output([node, "node-version-check.js"], cwd=HERE)  # noqa S603\n'
     '            logger.debug(output.decode("utf-8"))\n'
     '        finally:\n'
     '            _restore_error_mode(_em)\n'
     '    except Exception:'),
    ('    try:\n'
     '        output_binary = subprocess.check_output(  # noqa S603\n'
     '            [node, YARN_PATH, "config", "--json"],',
     '    _em = _suppress_loader_popups()\n'
     '    try:\n'
     '        output_binary = subprocess.check_output(  # noqa S603\n'
     '            [node, YARN_PATH, "config", "--json"],'),
    ('    except Exception as e:\n'
     '        logger.error(f"Fail to get yarn configuration. {e!s}")\n'
     '\n'
     '    return configuration',
     '    except Exception as e:\n'
     '        logger.error(f"Fail to get yarn configuration. {e!s}")\n'
     '    finally:\n'
     '        _restore_error_mode(_em)\n'
     '\n'
     '    return configuration'),
]


def patch_jupyterlab_probe(tree, actions, dry_run, log):
    """Site-patch: wrap jupyterlab's node/yarn probes in SetErrorMode so a
    broken Win8+-only node.exe found on PATH (common on machines with
    Anaconda) fails silently instead of hanging startup behind a modal
    loader dialog on bare Win7.  Idempotent; skips cleanly when jupyterlab
    is absent or its internals have drifted from the 4.x anchors."""
    path = os.path.join(tree, "Lib", "site-packages", "jupyterlab",
                        "commands.py")
    if not os.path.isfile(path):
        log("   jupyterlab not installed; skipped")
        return
    rel = os.path.relpath(path, tree)
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if "_suppress_loader_popups" in text:
        log("   already patched: %s" % rel)
        return
    for old, new in _JLAB_SUBS:
        if old not in text:
            print("   !! jupyterlab commands.py layout drifted; apply the "
                  "node-probe patch manually (docs/playbook.md)")
            return
        text = text.replace(old, new, 1)
    try:
        compile(text, path, "exec")
    except SyntaxError:
        print("   !! patched jupyterlab commands.py failed to compile; "
              "leaving it untouched (docs/playbook.md)")
        return
    if dry_run:
        log("   would patch: %s" % rel)
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    actions.append({"action": "site-patch", "file": rel})
    log("   patched: %s" % rel)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True,
                    help="the Python tree to patch (install or embeddable)")
    ap.add_argument("--kb-dir", default=KB_DIR)
    ap.add_argument("--msvcp-dir", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--skip-gate", action="store_true",
                    help="do not install pywin7gate/sitecustomize")
    ap.add_argument("--no-vxkex", action="store_true",
                    help="fallback route: no VxKex binaries; IAT redirects "
                         "to PyKexShim.dll instead of Kx*.dll")
    ap.add_argument("--no-launcher", action="store_true",
                    help="skip the runtime layer (PyKexLdr/PyKexBoot); the "
                         "tree then relies on the static file layer only")
    ap.add_argument("--launcher", action="store_true",
                    help=argparse.SUPPRESS)  # legacy alias (now the default)
    args = ap.parse_args(argv)

    tree = os.path.normpath(args.target)
    log = print
    mpath = os.path.join(tree, MANIFEST)

    if not args.dry_run:
        locked = interpreter_inside_tree(tree)
        if locked:
            print("error: the running interpreter (%s) lives inside the "
                  "target tree." % locked)
            print("       Its core python3XX.dll is loaded by this very "
                  "process and Windows keeps loaded DLLs locked against")
            print("       in-place rewrite, so patching (and --restore) "
                  "would fail partway.")
            print("       Re-run build_pack.py with a DIFFERENT Python "
                  "interpreter (any 3.9+: another tree, a system Python, ")
            print("       ...).  --dry-run is unaffected.")
            return 2

    if args.restore:
        if not os.path.isfile(mpath):
            print("no manifest:", mpath)
            return 1
        with open(mpath, "r", encoding="utf-8") as f:
            m = json.load(f)
        for rec in reversed(m.get("actions", [])):
            if rec["action"] in ("copy", "flatten-copy"):
                p = os.path.join(tree, rec["file"])
                if os.path.exists(p):
                    os.remove(p)
                    print("removed:", rec["file"])
            elif rec["action"] == "rename":
                src = os.path.join(tree, rec["to"])
                dst = os.path.join(tree, rec["from"])
                if os.path.exists(src) and not os.path.exists(dst):
                    os.rename(src, dst)
                    print("renamed back: %s -> %s" % (rec["to"], rec["from"]))
            elif rec["action"] == "iat-patch":
                try:
                    iat_restore(os.path.join(tree, rec["file"]))
                    print("restored:", rec["file"])
                except PatchError as e:
                    print("restore failed for", rec["file"], ":", e)
            elif rec["action"] == "pth-append":
                p = os.path.join(tree, rec["file"])
                try:
                    with open(p, "w", encoding="ascii",
                              newline="\r\n") as f:
                        f.write("\r\n".join(rec["original"]) + "\r\n")
                    print("restored:", rec["file"])
                except OSError as e:
                    print("._pth restore failed:", e)
            elif rec["action"] == "shim-convert":
                p = os.path.join(tree, rec["file"])
                if os.path.exists(p):
                    os.remove(p)
                bak = os.path.join(tree, rec["backup"]) \
                    if rec.get("backup") else None
                if bak and os.path.exists(bak):
                    os.rename(bak, p)
                    print("restored shim:", rec["file"])
                else:
                    print("removed converted shim:", rec["file"])
            elif rec["action"] == "write-file":
                p = os.path.join(tree, rec["file"])
                if os.path.exists(p):
                    os.remove(p)
                    print("removed:", rec["file"])
        for rel in ("Lib\\sitecustomize.py",):
            p = os.path.join(tree, rel)
            if os.path.exists(p):
                os.remove(p)
                print("removed:", rel)
        gate_dir = os.path.join(tree, "Lib", "pywin7gate")
        if os.path.isdir(gate_dir):
            shutil.rmtree(gate_dir)
            print("removed: Lib\\pywin7gate")
        os.remove(mpath)
        print("restore complete; *.pyw7bak files kept in tree root")
        return 0

    actions = []
    print("== target tree:", tree)
    if not os.path.isdir(tree):
        return print("error: not a directory: " + tree) or 2
    stems = detect_version_stems(tree)
    if not stems:
        return print("error: no python3*.dll found in " + tree) or 2
    print("== detected Python core DLL stem(s): %s" % ", ".join(stems))
    core_dlls = ["python%s.dll" % s for s in stems]
    entries = launcher_entries(tree, stems)

    print("== 1. KB2999226 UCRT set from", args.kb_dir)
    kb_files = sorted(os.path.basename(p)
                      for p in glob.glob(os.path.join(args.kb_dir, "*.dll")))
    print("   %d files" % len(kb_files))
    copy_set(kb_files, args.kb_dir, tree, actions, args.dry_run, log)

    if args.no_vxkex:
        print("== 2. --no-vxkex: copy PyKexShim.dll instead of VxKex set")
        shim = os.path.join(RUNTIME, "PyKexShim", "PyKexShim.dll")
        if not os.path.isfile(shim):
            print("!! PyKexShim.dll missing -- build it first with "
                  "runtime\\PyKexShim\\build.bat")
            return 2
        copy_set(["PyKexShim.dll"], os.path.dirname(shim), tree, actions,
                 args.dry_run, log)
        shim_pe = pemod.PEFile(shim)
        _i, shim_exp = shim_pe.exports()
        shim_index = {"pykexshim.dll": {e.lower() for e in shim_exp}}
    else:
        print("== 2. VxKex binaries (KexDll + %d Kx*)" % len(KX_FILES))
        copy_set(["KexDll.dll"], KEX_CORE64, tree, actions, args.dry_run, log)
        copy_set(KX_FILES, KEX_KEX64, tree, actions, args.dry_run, log)
        kx_index = fixers.build_kx_index(KEX_KEX64)

    msvcp_dir = args.msvcp_dir or find_msvcp_dir()
    if not msvcp_dir:
        print("!! MSVC redist dir not found; pass --msvcp-dir")
        return 2
    print("== 3. MSVC++ redist from", msvcp_dir)
    copy_set(MSVCP_FILES, msvcp_dir, tree, actions, args.dry_run, log)

    print("== 4. bootstrap IAT patch of core DLLs (scan-driven)")
    baseline = pemod.load_baseline()
    extra_dirs = [tree, os.path.join(tree, "DLLs")]
    if args.dry_run:
        extra_dirs += [args.kb_dir, msvcp_dir]
        extra_dirs.append(KEX_KEX64 if not args.no_vxkex
                          else os.path.join(RUNTIME, "PyKexShim"))
    patch_index = kx_index if not args.no_vxkex else shim_index
    patch_core_dlls(tree, stems, None, patch_index, baseline, extra_dirs,
                    actions, args.dry_run, log)

    if not args.skip_gate:
        print("== 5. install pywin7gate + sitecustomize")
        gate_src = os.path.join(PYW7, "src", "pywin7gate")
        gate_dst = os.path.join(tree, "Lib", "pywin7gate")
        if not args.dry_run:
            os.makedirs(os.path.join(tree, "Lib"), exist_ok=True)
            if os.path.isdir(gate_dst):
                shutil.rmtree(gate_dst)
            shutil.copytree(gate_src, gate_dst)
            sc_src = os.path.join(PYW7, "src", "sitecustomize.py")
            sc_dst = os.path.join(tree, "Lib", "sitecustomize.py")
            if os.path.exists(sc_dst):
                with open(sc_dst, "r", encoding="utf-8") as f:
                    old = f.read()
                if "pywin7gate" not in old:
                    print("   !! existing Lib\\sitecustomize.py without "
                          "pywin7gate -- NOT overwritten; merge manually")
                else:
                    shutil.copy2(sc_src, sc_dst)
            else:
                shutil.copy2(sc_src, sc_dst)
        print("   installed Lib\\pywin7gate + Lib\\sitecustomize.py")
        fix_pth_files(tree, stems, actions, args.dry_run, log)

        print("== 6. flatten vendored *.libs + gate site-packages")
        sp = os.path.join(tree, "Lib", "site-packages")
        if os.path.isdir(sp) and not args.dry_run:
            for libs in fixers.find_vendored_libs(sp):
                for dll, dirs in fixers.flatten_vendored(sp, libs, log=log):
                    for d in dirs:
                        actions.append({
                            "action": "flatten-copy",
                            "file": os.path.relpath(os.path.join(d, dll),
                                                    tree)})
            runtime_on = not args.no_launcher and not args.no_vxkex
            ctx = gate.GateContext(root=tree, sp=sp, log=log,
                                   runtime=runtime_on)
            rep = gate.gate_paths([sp], fix=True, ctx=ctx, log=log)
            print("   gate: ok=%d fixed=%d rejected=%d error=%d" % tuple(
                len(rep.get(k, [])) for k in ("ok", "fixed", "rejected",
                                              "error")))

    if args.no_launcher or args.no_vxkex:
        if args.no_vxkex and not args.no_launcher:
            print("== 7. runtime layer skipped "
                  "(--no-vxkex implies --no-launcher)")
        else:
            print("== 7. runtime layer skipped (--no-launcher)")
    else:
        print("== 7. runtime layer (PyKexLdr entry exes + PyKexBoot)")
        if not entries:
            print("   !! no entry-point exes found; nothing to shim")
        else:
            install_launchers(tree, entries, actions, args.dry_run, log)
        replace_venv_redirectors(tree, actions, args.dry_run, log)

    print("== 8. relocatable Scripts shims (PyKexExe) + relocation stamp")
    exe_stub_dir = os.path.join(RUNTIME, "PyKexExe")
    for stub in (shimod.STUB_CONSOLE, shimod.STUB_GUI):
        if not os.path.isfile(os.path.join(exe_stub_dir, stub)):
            print("!! %s missing -- build it first with "
                  "runtime\\PyKexExe\\build.bat" % stub)
            return 2
    copy_set([shimod.STUB_CONSOLE, shimod.STUB_GUI], exe_stub_dir, tree,
             actions, args.dry_run, log)
    convert_script_shims(tree, actions, args.dry_run, log)
    write_relocation_stamp(tree, actions, args.dry_run, log)

    print("== 9. jupyterlab node-probe popup patch (site-patch)")
    patch_jupyterlab_probe(tree, actions, args.dry_run, log)

    print("== 10. write manifest + final rescan")
    if not args.dry_run:
        m = {"version": 2,
             "when": datetime.datetime.now().isoformat(timespec="seconds"),
             "target": tree, "actions": actions}
        with open(mpath, "w", encoding="utf-8") as f:
            json.dump(m, f, indent=1, ensure_ascii=False)
        print("   manifest:", mpath)

    # final verification scan of the core DLLs.  In dry-run mode simulate
    # the post-apply state: pack sources count as resolvable and scan-driven
    # patches count as applied (we recompute them on the real run anyway).
    bad = 0
    for dll in core_dlls:
        path = os.path.join(tree, dll)
        if not os.path.isfile(path):
            continue
        extra = pemod.ExtraDllIndex(extra_dirs)
        r = pemod.scan_file(path, baseline, extra)
        missing = r["missing"]
        if args.dry_run:
            # simulate: drop anything the patcher would have fixed
            sim = []
            for mm in missing:
                low = mm["dll"].lower()
                if low in baseline and \
                        fixers.find_kx_target(mm["dll"], mm["func"],
                                              patch_index):
                    continue
                if fixers.find_runtime_redirect(mm["dll"]):
                    continue
                sim.append(mm)
            missing = sim
        if missing:
            bad += 1
            print("   STILL MISSING in", dll)
            for mm in missing:
                print("      %s!%s" % (mm["dll"], mm["func"]))
        else:
            print("   clean on Win7 baseline%s: %s" %
                  (" (simulated)" if args.dry_run else "", dll))
    if bad:
        print("!! verification failed")
        return 1
    print("== build_pack complete%s" % (" (dry-run)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())

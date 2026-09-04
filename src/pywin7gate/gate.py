# -*- coding: utf-8 -*-
"""pywin7gate.gate -- scan / decide / fix orchestration for third-party
binaries (wheel .pyd/.dll/.exe) so they load on a bare Windows 7 SP1.

Decision table (per missing import, after resolving against the bare-Win7
baseline plus everything deployed in the tree root):

  1. DLL is part of the private pack (ucrt/api-ms/vcruntime/msvcp140/Kx*)
     -> OK.  If the importing file is an .exe in a subdirectory, the pack
     is provisioned next to it.
  2. DLL is a real system DLL but the *function* is Win8+ (e.g.
     kernel32!GetThreadDescription)
     -> redirect that import to a Kx*.dll that exports the same symbol
        (offline IAT surgery, original backed up as <file>.pyw7bak).
  3. DLL is unknown (not in baseline, not in tree) -> look for a vendored
     copy inside site-packages (delvewheel "<pkg>.libs" convention):
     copy it next to every .pyd that imports it.
  4. Otherwise -> REJECT: the package cannot run on bare Win7; the gate
     reports the exact blocker and (on pip-wrap) suggests uninstalling.

Every fix is recorded in <site-packages>/.pywin7-gate-manifest.json with
before/after SHA-256 so it can be verified or rolled back later.
"""
import datetime
import hashlib
import json
import os
import sys

from . import pe as pemod
from . import fixers

MANIFEST_NAME = ".pywin7-gate-manifest.json"

# DLL names covered by the tree-root pack (checked against real files at
# runtime; prefixes matched case-insensitively)
PACK_PREFIXES = (
    "api-ms-win-crt-",
    "api-ms-win-eventing-provider-",
    "vcruntime140",
    "msvcp140",
    "python3",      # python3.dll / python3XX.dll / python3XXt.dll 核心 DLL
)
PACK_EXACT = {
    "ucrtbase.dll", "api-ms-win-core-path-l1-1-0.dll",
    "api-ms-win-core-file-l1-2-0.dll", "api-ms-win-core-file-l2-1-0.dll",
    "api-ms-win-core-localization-l1-2-0.dll",
    "api-ms-win-core-processthreads-l1-1-1.dll",
    "api-ms-win-core-synch-l1-2-0.dll", "api-ms-win-core-timezone-l1-1-0.dll",
    "api-ms-win-core-xstate-l2-1-0.dll",
    "kxbase.dll", "kxuser.dll", "kxadvapi.dll", "kxcom.dll", "kxcrt.dll",
    "kxcryp.dll", "kxdw.dll", "kxdx.dll", "kxmi.dll", "kxnet.dll",
    "kxnt.dll", "kxschanl.dll", "kxuia.dll", "kexdll.dll",
}
# DLLs we explicitly refuse to support (see plan doc): their dependencies
# cannot be satisfied on bare Win7.
UNSUPPORTED_DLLS = {"msvcp_win.dll", "icuuc.dll", "dwrw10.dll",
                    "mfdevmgr.dll", "mshtmlmedia.dll"}

# Files matching this pattern are build-time launcher stubs shipped inside
# packages (distlib's w32/w64/t32/t64(-arm) stubs, etc.): they contain x86
# machine code but are never loaded directly by the OS loader (distlib
# copies and rewrites them when generating Scripts entry points), so they
# are exempt from gating.
import re as _re
GATE_EXEMPT_RE = _re.compile(r"^[wt](32|64)(-arm)?\.exe$", _re.IGNORECASE)


def is_gate_exempt(path):
    return bool(GATE_EXEMPT_RE.match(os.path.basename(path)))


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_root():
    return os.path.normpath(sys.exec_prefix)


def site_packages():
    return os.path.join(tree_root(), "Lib", "site-packages")


def manifest_path(sp=None):
    return os.path.join(sp or site_packages(), MANIFEST_NAME)


def load_manifest(sp=None):
    try:
        with open(manifest_path(sp), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"version": 1, "files": {}}


def save_manifest(m, sp=None):
    path = manifest_path(sp)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def file_stamp(path):
    st = os.stat(path)
    return {"size": st.st_size, "mtime": int(st.st_mtime),
            "sha256": _sha256(path)}


def is_stamped(path, manifest=None, sp=None):
    m = manifest or load_manifest(sp)
    rel = os.path.relpath(path, sp or site_packages())
    rec = m["files"].get(rel)
    if not rec or rec.get("status") not in ("fixed", "ok"):
        return False
    try:
        st = os.stat(path)
    except OSError:
        return False
    return (st.st_size == rec["stamp"]["size"] and
            int(st.st_mtime) == rec["stamp"]["mtime"])


class GateContext:
    def __init__(self, root=None, sp=None, log=print, runtime=None):
        self.root = os.path.normpath(root) if root else tree_root()
        self.sp = os.path.normpath(sp) if sp else site_packages()
        self.log = log
        # runtime=True means the tree has the injection layer installed
        # (PyKexLdr entry points + KexDll/PyKexBoot in the root): .pyd/.dll
        # loads are then covered by PyKexBoot's in-memory import rewrite and
        # need no on-disk surgery.  None = auto-detect.
        self.runtime = runtime
        self.baseline = None
        self.extra = None
        self.kx_index = None
        self.pack_files = None

    def lazy_init(self):
        if self.baseline is not None:
            return
        self.baseline = pemod.load_baseline()
        self.extra = pemod.ExtraDllIndex([self.root,
                                          os.path.join(self.root, "DLLs")])
        self.kx_index = fixers.build_kx_index(self.root)
        self.pack_files = [
            os.path.join(self.root, f) for f in sorted(os.listdir(self.root))
            if f.lower().endswith(".dll") and (
                f.lower().startswith(PACK_PREFIXES) or
                f.lower() in PACK_EXACT)]
        if self.runtime is None:
            self.runtime = (
                os.path.isfile(os.path.join(self.root, "PyKexBoot.dll")) and
                os.path.isfile(os.path.join(self.root, "KexDll.dll")))

    def dll_exports(self, dll_low):
        """Export name set (lower) for a DLL we can redirect/retarget to:
        a Kx*.dll in the tree, a Win7-baseline system DLL, or a DLL file in
        the tree root.  None when unknown."""
        if dll_low in self.kx_index:
            return self.kx_index[dll_low]
        if dll_low in self.baseline:
            return set(self.baseline[dll_low])
        p = os.path.join(self.root, dll_low)
        if os.path.isfile(p):
            try:
                _i, exp = pemod.PEFile(p).exports()
                return {e.lower() for e in exp}
            except (pemod.PEError, OSError):
                return None
        return None

    def pack_covers(self, dll):
        low = dll.lower()
        if low in UNSUPPORTED_DLLS:
            return False
        if low in PACK_EXACT:
            return True
        return low.startswith(PACK_PREFIXES)


def gate_file(path, ctx, fix=True):
    """Gate one binary. Returns a report dict."""
    ctx.lazy_init()
    extra = pemod.ExtraDllIndex(ctx.extra.dirs + [os.path.dirname(path)])
    try:
        r = pemod.scan_file(path, ctx.baseline, extra)
    except (pemod.PEError, OSError) as e:
        return {"file": path, "status": "error", "error": str(e)}
    rep = {"file": path, "status": "ok", "missing": r["missing"],
           "machine": r["machine"], "subsystem": r["subsystem_version"],
           "actions": []}
    if r["machine"] != "x64":
        # amd64-only pack: non-x64 images (e.g. 32-bit helper DLLs some
        # wheels bundle) can never load into this interpreter; do not let
        # them fail the package
        rep["note"] = "non-x64 image, not gated"
        rep["missing"] = []
        return rep
    if not r["missing"]:
        return rep

    # group by dll
    by_dll = {}
    for m in r["missing"]:
        by_dll.setdefault(m["dll"], []).append(m["func"])

    is_exe = path.lower().endswith(".exe")
    # With the runtime layer installed (launcher + KexDll/PyKexBoot in the
    # tree root), a .pyd/.dll is loaded into an already-injected process and
    # PyKexBoot rewrites its imports in memory at load time -- so Kx/redirect
    # -coverable gaps need no on-disk change.  .exe files can start a new
    # process whose own imports are snapped before injection reaches it, so
    # they always get the static treatment.
    runtime_cover = bool(ctx.runtime) and not is_exe

    redirects = []          # jobs for iatpatch
    retargets = []          # (src_dll, dst_dll) whole-descriptor swaps
    vendored_needed = []    # dll names to find in site-packages
    rejected = []
    for dll, funcs in sorted(by_dll.items()):
        if ctx.pack_covers(dll):
            rep["actions"].append("pack-covered: " + dll)
            continue
        low = dll.lower()
        if low in UNSUPPORTED_DLLS:
            rejected.append("%s (%s) -- unsupported on bare Win7" %
                            (dll, ", ".join(sorted(funcs)[:4])))
            continue
        if low in ctx.baseline:
            # system dll missing some functions -> Kx redirect
            for fn in sorted(funcs):
                tgt = fixers.find_kx_target(dll, fn, ctx.kx_index)
                if tgt:
                    if runtime_cover:
                        rep["actions"].append("runtime-cover: %s!%s (%s)" %
                                              (dll, fn, tgt))
                    else:
                        redirects.append((dll, fn, tgt))
                else:
                    rejected.append("%s!%s (no Kx implementation)" %
                                    (dll, fn))
            continue
        # unknown dll -> covered by the runtime redirect table?
        rtgt = fixers.find_runtime_redirect(dll)
        if rtgt:
            if runtime_cover:
                rep["actions"].append("runtime-cover: %s -> %s" %
                                      (dll, rtgt))
            elif ctx.dll_exports(rtgt.lower()) is not None:
                retargets.append((dll, rtgt))
            else:
                rejected.append("%s (%s) -- redirect target %s unavailable" %
                                (dll, ", ".join(sorted(funcs)[:4]), rtgt))
            continue
        # unknown dll -> vendored inside site-packages?
        hit = None
        for root, _d, files in os.walk(ctx.sp):
            for fn in files:
                if fn.lower() == low:
                    hit = os.path.join(root, fn)
                    break
            if hit:
                break
        if hit:
            vendored_needed.append(hit)
        else:
            rejected.append("%s (%s) -- DLL not found anywhere" %
                            (dll, ", ".join(sorted(funcs)[:4])))

    if rejected:
        rep["status"] = "rejected"
        rep["rejected"] = rejected
        return rep

    if not fix:
        if redirects or retargets or vendored_needed:
            rep["status"] = "fixable"
            rep["redirects"] = ["%s!%s -> %s" % j[:3] for j in redirects]
            rep["retargets"] = ["%s -> %s" % j[:2] for j in retargets]
            rep["vendored"] = vendored_needed
        return rep

    try:
        if redirects or retargets:
            from .iatpatch import IATPatcher
            p = IATPatcher(path)
            for src, fn, tgt in redirects:
                p.redirect(src, fn, tgt)
            for src, dst in retargets:
                p.retarget_dll(src, dst, ctx.dll_exports(dst.lower()))
            rec = p.commit(backup=True)
            n = len(rec["redirects"]) + len(rec.get("retargets", []))
            rep["actions"].append("iat-surgery: %d import(s)" % n)
            rep["redirects"] = rec["redirects"]
            if rec.get("retargets"):
                rep["retargets"] = rec["retargets"]
            if rec.get("backup"):
                rep.setdefault("artifacts", []).append(rec["backup"])
        import shutil as _shutil
        for vend in vendored_needed:
            dst = os.path.join(os.path.dirname(path),
                               os.path.basename(vend))
            if not os.path.exists(dst):
                _shutil.copy2(vend, dst)
                rep.setdefault("artifacts", []).append(dst)
            rep["actions"].append("vendored-copy: %s" %
                                  os.path.basename(vend))
        # re-scan to prove the fix
        extra2 = pemod.ExtraDllIndex(ctx.extra.dirs + [os.path.dirname(path)])
        r2 = pemod.scan_file(path, ctx.baseline, extra2)
        if r2["missing"]:
            rep["status"] = "rejected"
            rep["rejected"] = ["still missing after fix: %s!%s" %
                               (m["dll"], m["func"]) for m in r2["missing"]]
        elif rep["actions"]:
            rep["status"] = "fixed"
    except Exception as e:  # noqa: BLE001 -- gate must never crash python
        rep["status"] = "error"
        rep["error"] = "fix failed: %r" % (e,)
    return rep


def iter_binaries(paths):
    for p in paths:
        if os.path.isfile(p):
            if p.lower().endswith((".pyd", ".dll", ".exe")) and \
                    not is_gate_exempt(p):
                yield p
            continue
        for root, _d, files in os.walk(p):
            for fn in files:
                fp = os.path.join(root, fn)
                if fn.lower().endswith((".pyd", ".dll", ".exe")) and \
                        not is_gate_exempt(fp):
                    yield fp


def gate_paths(paths, fix=True, ctx=None, log=print):
    ctx = ctx or GateContext(log=log)
    m = load_manifest(ctx.sp)
    changed = False
    report = {"fixed": [], "ok": [], "rejected": [], "error": []}
    for path in iter_binaries(paths):
        rel = os.path.relpath(path, ctx.sp)
        if is_stamped(path, m, ctx.sp):
            continue
        rep = gate_file(path, ctx, fix=fix)
        status = rep["status"]
        report.setdefault(status, []).append(rel)
        # .exe tools additionally get the runtime pack next to them
        if (fix and status in ("ok", "fixed") and
                path.lower().endswith(".exe")):
            try:
                fixers.provision_exe_dir(os.path.dirname(path),
                                         ctx.pack_files, log=log)
            except OSError:
                pass
        if fix:
            try:
                m["files"][rel] = {
                    "status": status,
                    "when": datetime.datetime.now().isoformat(
                        timespec="seconds"),
                    "stamp": file_stamp(path),
                    "actions": rep.get("actions", []),
                    "artifacts": rep.get("artifacts", []),
                    "rejected": rep.get("rejected", []),
                }
                changed = True
            except OSError:
                pass
        if status == "rejected":
            log("REJECTED: %s" % rel)
            for line in rep.get("rejected", []):
                log("    %s" % line)
        elif status == "fixed":
            log("FIXED:    %s (%s)" % (rel, "; ".join(rep["actions"])))
        elif status == "error":
            log("ERROR:    %s (%s)" % (rel, rep.get("error", "?")))
    if fix and changed:
        save_manifest(m, ctx.sp)
    return report

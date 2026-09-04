# -*- coding: utf-8 -*-
"""pywin7gate.hook -- import-time safety net (audit-hook based).

Installed by Lib/sitecustomize.py at every interpreter start (cheap:
one dict lookup per import event).  When a .pyd/.dll under
Lib/site-packages is about to be loaded and is NOT in the gate manifest
(e.g. the package was installed with plain `python -m pip` or copied in
by hand), the gate is run on the fly:

  * fixable  -> fixed in place (IAT redirect / vendored-DLL copy), then
                the import proceeds;
  * rejected -> ImportError with the exact Win7 blocker list.

Disable entirely with environment variable PYW7GATE=0.
The hook NEVER raises for its own internal failures (worst case: import
proceeds ungated, exactly like without the hook).
"""
import os

_installed = False
_manifest_cache = {"path": None, "mtime": 0.0, "data": None}


def _manifest(sp):
    import json
    mp = os.path.join(sp, ".pywin7-gate-manifest.json")
    try:
        mt = os.stat(mp).st_mtime
    except OSError:
        mt = 0.0
    if _manifest_cache["data"] is not None and \
            _manifest_cache["path"] == mp and _manifest_cache["mtime"] == mt:
        return _manifest_cache["data"]
    try:
        with open(mp, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {"version": 1, "files": {}}
    _manifest_cache.update({"path": mp, "mtime": mt, "data": data})
    return data


def _audit(event, args):
    if event != "import":
        return
    try:
        _name, filename, _sys_path, _meta, _path_hooks = args
    except (TypeError, ValueError):
        return
    if not filename:
        return
    low = filename.lower()
    if not low.endswith((".pyd", ".dll")):
        return
    try:
        import sys
        sp = os.path.normpath(os.path.join(sys.exec_prefix, "lib",
                                           "site-packages"))
        norm = os.path.normpath(filename)
        # ntpath.commonpath is case-sensitive; normcase both sides for the
        # containment check ("Lib" vs "lib" both occur in practice).
        if os.path.commonpath((os.path.normcase(norm),
                               os.path.normcase(sp))) != os.path.normcase(sp):
            return
        rel = os.path.relpath(norm, sp)
        m = _manifest(sp)
        files_ci = {k.lower(): k for k in m["files"]}
        key = files_ci.get(rel.lower())
        rec = m["files"].get(key) if key is not None else None
        if rec is not None and rec.get("status") in ("fixed", "ok"):
            st = os.stat(norm)
            if (st.st_size == rec["stamp"]["size"] and
                    int(st.st_mtime) == rec["stamp"]["mtime"]):
                return  # known-good, fast path
        # unstamped / changed -> run the gate now
        from . import gate
        ctx = gate.GateContext(sp=sp, log=lambda *a: None)
        rep = gate.gate_file(norm, ctx, fix=True)
        if rep["status"] in ("fixed", "ok"):
            rec = {"status": rep["status"], "stamp": gate.file_stamp(norm),
                   "actions": rep.get("actions", []),
                   "artifacts": rep.get("artifacts", []),
                   "when": "import-hook"}
            m["files"][key if key is not None else rel] = rec
            gate.save_manifest(m, sp)
            _manifest_cache["mtime"] = 0.0  # force reload
            return
        raise ImportError(
            "pywin7gate: %s cannot run on bare Windows 7: %s  "
            "(run `python -m pywin7gate fix \"%s\"` for details, or "
            "PYW7GATE=0 to bypass this gate)" %
            (rel, "; ".join(rep.get("rejected", [rep.get("error", "?")])),
             norm))
    except ImportError:
        raise
    except Exception:
        return  # never break imports because of gate bugs


def install():
    global _installed
    if _installed:
        return
    if os.environ.get("PYW7GATE", "1") == "0":
        return
    import sys
    sys.addaudithook(_audit)
    _installed = True

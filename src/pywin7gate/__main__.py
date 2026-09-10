# -*- coding: utf-8 -*-
"""pywin7gate CLI.

  python -m pywin7gate scan <paths...>    report Win7 blockers (no changes)
  python -m pywin7gate fix  <paths...>    scan + auto-fix + manifest
  python -m pywin7gate fix-all            fix all of Lib\\site-packages
  python -m pywin7gate flatten            flatten every *.libs vendored dir
  python -m pywin7gate pip <args...>      run pip, then auto fix-all
                                          (this is what local-pip.bat calls)
  python -m pywin7gate verify             verify manifest hashes
  python -m pywin7gate prune              drop manifest entries whose files
                                          were removed by package upgrades
  python -m pywin7gate relocate           rewrite Scripts\\*.exe shebangs to
                                          THIS tree (legacy distlib shims;
                                          PyKexExe-converted shims need no
                                          relocation and are skipped)
  python -m pywin7gate shims              convert Scripts\\*.exe python-script
                                          shims to the relocatable PyKexExe
                                          stub (originals -> Scripts\\pyw7bak)
  python -m pywin7gate restore <path>     roll back fixes for one file
  python -m pywin7gate status             summary
"""
import os
import sys

from . import fixers, gate, shims
from .iatpatch import restore as iat_restore, is_patched

# canonical implementations live in pywin7gate.shims (shared with build_pack)
_shim_zip_start = shims.shim_zip_start
_split_shebang = shims.split_shebang
_join_shebang = shims.join_shebang


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
        try:
            if shims.stubs_available(gate.tree_root()):
                _cmd_shims()
        except Exception as e:
            print("[pywin7gate] shim conversion skipped:", e)
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


def _cmd_prune():
    m = gate.load_manifest()
    sp = gate.site_packages()
    gone = [rel for rel in m["files"]
            if not os.path.exists(os.path.join(sp, rel))]
    for rel in gone:
        del m["files"][rel]
        print("pruned:", rel)
    if gone:
        gate.save_manifest(m, sp)
    print("prune: %d removed, %d entries remain" % (len(gone),
                                                    len(m["files"])))
    return 0


def _relocate_one(path, root):
    """Rewrite the embedded python interpreter shebang of a console-script
    exe shim to point into <root>.  Handles both shim generations:
    new-style (stub | '#!exe\\n' | zip) and old distlib-style (stub | zip
    whose stored __main__.py carries the '#!exe' first line).
    Returns 'rewritten' / 'ok' / 'skip'."""
    import io
    import zipfile
    with open(path, "rb") as f:
        data = f.read()
    zstart = _shim_zip_start(data)
    if zstart < 0:
        return "skip"

    def remap(exe):
        """-> (new_path_or_None, skip_flag)"""
        base = os.path.basename(exe).lower()
        if not (base.startswith("python") and base.endswith(".exe")):
            return None, True                      # not a python shim
        new = os.path.join(root, base)
        if os.path.normcase(exe) == os.path.normcase(new):
            return None, False                     # already points here
        return new, False

    # --- new generation: plain shebang line between stub and zip -----------
    sh = data.rfind(b"#!", 0, zstart)
    if sh >= 0 and b"\n" not in data[sh:zstart].rstrip(b"\r\n"):
        line = data[sh:zstart]
        body = line[2:].rstrip(b"\r\n")
        nl = line[2 + len(body):] or b"\r\n"
        try:
            exe, suffix = _split_shebang(body)
        except UnicodeDecodeError:
            return "skip"
        new, skip = remap(exe)
        if skip:
            return "skip"
        if new is None:
            return "ok"
        out = (data[:sh] + b"#!" +
               _join_shebang(new, suffix).encode("utf-8") + nl +
               data[zstart:])
    # --- old distlib generation: shebang inside the embedded __main__.py ---
    else:
        try:
            zin = zipfile.ZipFile(io.BytesIO(data[zstart:]))
            names = zin.namelist()
        except zipfile.BadZipFile:
            return "skip"
        if "__main__.py" not in names:
            return "skip"
        content = zin.read("__main__.py")
        if not content.startswith(b"#!"):
            return "skip"
        eol = content.find(b"\n")
        if eol < 0:
            return "skip"
        try:
            exe, suffix = _split_shebang(content[2:eol])
        except UnicodeDecodeError:
            return "skip"
        new, skip = remap(exe)
        if skip:
            return "skip"
        if new is None:
            return "ok"
        nl = b"\r\n" if content[eol - 1:eol] == b"\r" else b"\n"
        newmain = (b"#!" + _join_shebang(new, suffix).encode("utf-8") +
                   nl + content[eol + 1:])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                d = newmain if item.filename == "__main__.py" \
                    else zin.read(item.filename)
                zout.writestr(item, d)
        out = data[:zstart] + buf.getvalue()

    tmp = path + ".pyw7tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.replace(tmp, path)
    return "rewritten"


def _cmd_relocate(root=None):
    root = root or gate.tree_root()
    scripts = os.path.join(root, "Scripts")
    if not os.path.isdir(scripts):
        print("no Scripts dir:", scripts)
        return 1
    counts = {"rewritten": 0, "ok": 0, "skip": 0}
    for fn in sorted(os.listdir(scripts)):
        if not fn.lower().endswith(".exe"):
            continue
        r = _relocate_one(os.path.join(scripts, fn), root)
        counts[r] += 1
        if r == "rewritten":
            print("relocated:", fn)
    print("relocate: %d rewritten, %d already ok, %d skipped; target %s"
          % (counts["rewritten"], counts["ok"], counts["skip"], root))
    return 0


def _cmd_shims():
    root = gate.tree_root()
    if not os.path.isdir(os.path.join(root, "Scripts")):
        print("no Scripts dir:", os.path.join(root, "Scripts"))
        return 1
    if not shims.stubs_available(root):
        print("PyKexExe stubs missing from the tree root -- expected:",
              ", ".join(sorted(shims.stub_paths(root).values())))
        print("run tools\\build_pack.py (it copies them), or copy "
              "PyKexExe.exe / PyKexExeW.exe next to python.exe first")
        return 1
    counts = shims.convert_tree(root)
    print("shims: %d converted, %d stub-refreshed, %d already relocatable, "
          "%d skipped (originals in Scripts\\%s)"
          % (counts["converted"], counts["updated"], counts["ok"],
             counts["skip"], shims.BACKUP_DIRNAME))
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
    if cmd == "prune":
        return _cmd_prune()
    if cmd == "relocate":
        return _cmd_relocate()
    if cmd == "shims":
        return _cmd_shims()
    if cmd == "restore" and rest:
        return _cmd_restore(rest[0])
    if cmd == "status":
        return _cmd_status()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

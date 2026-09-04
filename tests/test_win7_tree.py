#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_win7_tree.py -- G0..G5+S acceptance suite for the Win7 Python tree.

Runs on the dev machine AND on the bare Win7 target (same script, stdlib
only).  Point it at the tree under test:

    python tests\\test_win7_tree.py --tree D:\\Python314
    python tests\\test_win7_tree.py --tree D:\\Python314 --skip-static
    python tests\\test_win7_tree.py --python C:\\path\\python.exe

Groups:
  G0  interpreter starts, version sane
  G1  stdlib binary modules import (ssl/sqlite3/ctypes/lzma/bz2/zstd/...)
  G2  functional smoke: SSL context, ctypes call, add_dll_directory cookie,
      time sources, zlib roundtrip, sqlite query
  G3  third-party (numpy if present): linalg + multiprocessing + subprocess
  G4  venv creation + venv interpreter prefix detection
  G5  runtime layer: TestWin8Api.dll (imports three kernel32 functions that
      a bare Win7 SP1 lacks: GetSystemTimePreciseAsFileTime,
      GetCurrentThreadStackLimits, IsWow64Process2) loads unmodified via
      ctypes and works; its in-memory import descriptor must name kxbase.dll
      (proof the PyKexBoot load-time import rewrite fired); negative control
      PYW7HOOK=0 keeps kernel32.dll
  S   static acceptance: tools\\scan_tree.py + pywin7gate verify +
      PyKexBoot/fixers redirect-table consistency

Exit code 0 = all enabled groups pass.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PYW7 = os.path.normpath(os.path.join(HERE, ".."))

RESULTS = []


def expected_version_tag(tree):
    """Derive the expected '3.N' tag from the tree's python3XX.dll stem
    (python312.dll -> '3.12').  Returns None when unknown (--python-only
    runs): G0 then accepts any sane 3.x version string."""
    if not tree:
        return None
    try:
        names = os.listdir(tree)
    except OSError:
        return None
    for fn in names:
        m = re.match(r"^python3(\d+)t?\.dll$", fn.lower())
        if m:
            return "3." + m.group(1)
    return None


def record(group, name, ok, detail=""):
    RESULTS.append((group, name, ok, detail))
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                           (" -- " + detail) if detail else ""))


def run_py(py, code, timeout=120, extra_env=None):
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    p = subprocess.run([py, "-c", code], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout,
                       env=env)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def g0(py, tag=None):
    print("== G0: interpreter starts")
    rc, out = run_py(py, "import sys; print(sys.version)")
    ok = rc == 0 and (tag or "3.") in out
    record("G0", "starts + version %s" % (tag or "3.x"), ok,
           out.strip().splitlines()[0] if out.strip() else "")


def g1(py):
    print("== G1: stdlib binary modules import")
    mods = ["ssl", "sqlite3", "ctypes", "lzma", "bz2", "zlib",
            "hashlib", "decimal", "unicodedata", "select", "socket",
            "_overlapped", "multiprocessing", "_queue", "_datetime",
            "_elementtree", "pyexpat", "_ssl", "_socket",
            "_tkinter", "tkinter"]
    code = ("import importlib,sys; mods=%r; bad=[]\n"
            "for m in mods:\n"
            "    try: importlib.import_module(m)\n"
            "    except Exception as e: bad.append((m, repr(e)))\n"
            "print('BAD:', bad if bad else 'none')\n"
            "sys.exit(1 if bad else 0)" % mods)
    rc, out = run_py(py, code)
    record("G1", "stdlib imports", rc == 0,
           out.strip().splitlines()[-1] if out.strip() else "")


def g2(py):
    print("== G2: functional smoke")
    code = r"""
import ssl, ctypes, os, tempfile, time, zlib, sqlite3, sys
fails = []
try:
    ctx = ssl.create_default_context()
    if not ctx.get_ciphers():
        fails.append('ssl: no ciphers')
except Exception as e:
    fails.append('ssl: %r' % e)
try:
    if ctypes.windll.kernel32.GetTickCount() <= 0:
        fails.append('ctypes: GetTickCount')
except Exception as e:
    fails.append('ctypes: %r' % e)
try:
    d = tempfile.mkdtemp()
    cookie = os.add_dll_directory(d)
    if not cookie:
        fails.append('add_dll_directory: falsy cookie')
    close = getattr(cookie, 'close', None)
    if close:
        close()
    else:
        os._remove_dll_directory(cookie)
except Exception as e:
    fails.append('add_dll_directory: %r' % e)
try:
    t1 = time.perf_counter(); time.sleep(0.05); t2 = time.perf_counter()
    if not (0.01 < t2 - t1 < 5):
        fails.append('perf_counter broken')
    time.time_ns(); time.monotonic_ns()
except Exception as e:
    fails.append('time: %r' % e)
try:
    blob = zlib.compress(b'win7' * 1000)
    assert zlib.decompress(blob) == b'win7' * 1000
except Exception as e:
    fails.append('zlib: %r' % e)
try:
    con = sqlite3.connect(':memory:')
    assert con.execute('select sqlite_version()').fetchone()[0]
except Exception as e:
    fails.append('sqlite3: %r' % e)
print('FAILS:', fails if fails else 'none')
sys.exit(1 if fails else 0)
"""
    rc, out = run_py(py, code)
    record("G2", "ssl/ctypes/add_dll_directory/time/zlib/sqlite",
           rc == 0, out.strip().splitlines()[-1] if out.strip() else "")


def g3(py):
    print("== G3: third-party + process model")
    rc, out = run_py(py, "import numpy", timeout=60)
    if rc != 0:
        record("G3", "numpy present", True, "numpy not installed, skipped")
    else:
        code = ("import numpy as np; "
                "m = np.array([[2.,0.,0.],[0.,3.,0.],[0.,0.,4.]]); "
                "d = np.linalg.det(m); "
                "assert abs(d - 24.0) < 1e-9, d; "
                "print('numpy', np.__version__, 'det ok')")
        rc, out = run_py(py, code, timeout=180)
        record("G3", "numpy linalg (OpenBLAS path)", rc == 0,
               out.strip().splitlines()[-1] if out.strip() else "")
    code = ("import subprocess, sys; "
            "p = subprocess.run([sys.executable, '-c', 'print(7*6)'], "
            "capture_output=True, text=True); "
            "assert p.stdout.strip() == '42', p.stdout; print('subproc ok')")
    rc, out = run_py(py, code)
    record("G3", "subprocess child", rc == 0,
           out.strip().splitlines()[-1] if out.strip() else "")
    code = ("import multiprocessing as mp\n"
            "def f(c):\n    c.send('pong'); c.close()\n"
            "if __name__ == '__main__':\n"
            "    mp.freeze_support()\n"
            "    a, b = mp.Pipe()\n"
            "    p = mp.Process(target=f, args=(b,))\n"
            "    p.start(); got = a.recv(); p.join(20)\n"
            "    assert got == 'pong', got\n"
            "    print('multiprocessing ok')\n")
    import tempfile as tf
    fd, script = tf.mkstemp(suffix=".py", prefix="pyw7mp_")
    with os.fdopen(fd, "w") as fh:
        fh.write(code)
    try:
        p = subprocess.run([py, script], capture_output=True, text=True,
                           timeout=120)
        out = (p.stdout or "") + (p.stderr or "")
        record("G3", "multiprocessing spawn", p.returncode == 0,
               out.strip().splitlines()[-1] if out.strip() else "")
    finally:
        os.unlink(script)


def g4(py):
    print("== G4: venv")
    vdir = tempfile.mkdtemp(prefix="pyw7venv_")
    vdir = os.path.join(vdir, "v")
    p = subprocess.run([py, "-m", "venv", vdir], capture_output=True,
                       text=True, timeout=300)
    if p.returncode != 0:
        record("G4", "venv create", False,
               ((p.stdout or "") + (p.stderr or "")).strip()[-300:])
        return
    vpy = os.path.join(vdir, "Scripts", "python.exe")
    rc, out = run_py(vpy, "import sys; print(sys.prefix)")
    ok = rc == 0 and os.path.normpath(out.strip()) == os.path.normpath(vdir)
    record("G4", "venv create + prefix detection", ok,
           out.strip() if out.strip() else "")
    import shutil
    shutil.rmtree(os.path.dirname(vdir), ignore_errors=True)


G5_CODE = r"""
import ctypes, os, struct, sys
dll = os.environ["PYW7_TESTDLL"]
try:
    h = ctypes.CDLL(dll)
except OSError as e:
    print("LOAD-FAILED: %r" % (e,))
    sys.exit(10)
rc = h.CallWin8Apis()
print("CallWin8Apis rc =", rc)

# walk the loaded module's in-memory import descriptor names
k = ctypes.windll.kernel32
k.GetModuleHandleW.restype = ctypes.c_void_p
base = k.GetModuleHandleW(os.path.basename(dll))
if not base:
    print("no module handle")
    sys.exit(11)
def rd(addr, n):
    return ctypes.string_at(addr, n)
e_lfanew = struct.unpack("<i", rd(base + 0x3C, 4))[0]
nt = base + e_lfanew
opt = nt + 24
magic = struct.unpack("<H", rd(opt, 2))[0]
dd = opt + (112 if magic == 0x20B else 96)
imp_rva, _sz = struct.unpack("<II", rd(dd + 8, 8))
names = []
i = 0
while imp_rva:
    desc = base + imp_rva + i * 20
    ilt, _t, _f, name_rva, _ft = struct.unpack("<IIIII", rd(desc, 20))
    if ilt == 0 and name_rva == 0:
        break
    nm = rd(base + name_rva, 64).split(b"\0")[0].decode("ascii", "replace")
    names.append(nm)
    i += 1
    if i > 64:
        break
print("IMPORT-NAMES:", sorted(names))
print("CALL-RC:", rc)
"""


def g5(py):
    print("== G5: runtime import rewrite (TestWin8Api.dll)")
    dll = os.path.join(PYW7, "tests", "testdll", "TestWin8Api.dll")
    if not os.path.isfile(dll):
        record("G5", "TestWin8Api.dll present", False,
               "build tests\\testdll\\build.bat first")
        return
    env = {"PYW7_TESTDLL": dll, "PYW7GATE": "0"}  # gate off: runtime only
    rc, out = run_py(py, G5_CODE, extra_env=env)
    if rc == 10:
        record("G5", "load with runtime layer", False,
               out.strip().splitlines()[-1] if out.strip() else "")
        return
    names_line = [ln for ln in out.splitlines()
                  if ln.startswith("IMPORT-NAMES:")]
    rc_line = [ln for ln in out.splitlines() if ln.startswith("CALL-RC:")]
    names = names_line[0].lower() if names_line else ""
    rewritten = "kxbase.dll" in names
    call_ok = bool(rc_line) and rc_line[0].strip().endswith("0")
    record("G5", "load + rewrite to kxbase.dll + calls work",
           rc == 0 and rewritten and call_ok,
           (names_line[0] if names_line else out.strip()[-200:]) +
           ("; " + rc_line[0] if rc_line else ""))
    # negative control: PYW7HOOK=0 must leave the descriptor untouched
    env2 = {"PYW7_TESTDLL": dll, "PYW7GATE": "0", "PYW7HOOK": "0"}
    rc2, out2 = run_py(py, G5_CODE, extra_env=env2)
    if rc2 == 10:
        record("G5", "negative control (PYW7HOOK=0)", True,
               "load fails without the runtime layer "
               "(expected on bare Win7)")
    else:
        names2 = [ln for ln in out2.splitlines()
                  if ln.startswith("IMPORT-NAMES:")]
        n2 = names2[0].lower() if names2 else ""
        record("G5", "negative control (PYW7HOOK=0)",
               "kxbase.dll" not in n2 and "kernel32.dll" in n2,
               names2[0] if names2 else out2.strip()[-200:])


def check_redirect_table_consistency():
    import re
    sys.path.insert(0, os.path.join(PYW7, "src"))
    # see tools/build_pack.py: evict a patched tree's preloaded pywin7gate
    for m in [m for m in list(sys.modules)
              if m == "pywin7gate" or m.startswith("pywin7gate.")]:
        del sys.modules[m]
    from pywin7gate import fixers
    src = open(os.path.join(PYW7, "runtime", "PyKexBoot", "PyKexBoot.c"),
               encoding="utf-8").read()
    c_entries = set(re.findall(r'\{\s*"([^"]+)",\s*"([^"]+)"\s*\}', src))
    py_entries = set(fixers.RUNTIME_REDIRECT_PAIRS)
    ok = c_entries == py_entries
    record("S", "PyKexBoot redirect table == fixers.RUNTIME_REDIRECT_PAIRS",
           ok, "" if ok else
           "diff: %s" % sorted(c_entries ^ py_entries)[:6])
    return ok


def static_scan(tree, py):
    print("== S: static acceptance")
    scan = os.path.join(PYW7, "tools", "scan_tree.py")
    p = subprocess.run([sys.executable, scan, tree, "--quiet",
                        "--no-version-warn"],
                       capture_output=True, text=True, timeout=900)
    record("S", "scan_tree clean (bare Win7 SP1)", p.returncode == 0,
           ((p.stdout or "") + (p.stderr or "")).strip().splitlines()[-1]
           if ((p.stdout or "") + (p.stderr or "")).strip() else "")
    p = subprocess.run([py, "-m", "pywin7gate", "verify"],
                       capture_output=True, text=True, timeout=300)
    record("S", "gate manifest verify", p.returncode == 0,
           ((p.stdout or "") + (p.stderr or "")).strip()[-200:])
    check_redirect_table_consistency()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tree", default=None,
                    help="patched Python tree root")
    ap.add_argument("--python", default=None,
                    help="interpreter to test (default: <tree>\\python.exe)")
    ap.add_argument("--skip-static", action="store_true")
    ap.add_argument("--groups", default="G0,G1,G2,G3,G4,G5,S")
    args = ap.parse_args(argv)

    if not args.python and not args.tree:
        ap.error("pass --tree <PYTHON_DIR> or --python <python.exe>")
    py = args.python or os.path.join(args.tree, "python.exe")
    print("tree:  ", args.tree)
    print("python:", py)
    groups = {g.strip().upper() for g in args.groups.split(",")}
    if "G0" in groups:
        g0(py, expected_version_tag(args.tree))
    if "G1" in groups:
        g1(py)
    if "G2" in groups:
        g2(py)
    if "G3" in groups:
        g3(py)
    if "G4" in groups:
        g4(py)
    if "G5" in groups:
        g5(py)
    if "S" in groups and not args.skip_static:
        static_scan(args.tree, py)

    fails = [r for r in RESULTS if not r[2]]
    print("\n=== SUMMARY: %d passed, %d failed ===" %
          (len(RESULTS) - len(fails), len(fails)))
    for group, name, ok, detail in fails:
        print("  FAIL %s %s -- %s" % (group, name, detail))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

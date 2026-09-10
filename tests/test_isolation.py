#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_isolation.py -- hermetic-tree acceptance suite.

A packed tree must behave as a self-contained environment even on machines
that have their own Python / Anaconda installed.  This suite fabricates a
foreign "Anaconda" (a dir with python.exe + Scripts\\jupyter-lab.exe +
node.exe) in front of PATH, sets hostile PYTHONHOME/PYTHONPATH/CONDA_*/
VIRTUAL_ENV, and asserts the tree's interpreter:

  I1  which()/jupyter_core dispatch resolve to the TREE's shims, never the
      foreign ones (jupyter_core's `python -m jupyter lab` dispatch being
      the canonical real-world victim)
  I2  PATH inside the tree python is scrubbed of foreign-interpreter dirs
  I3  CONDA_*/VIRTUAL_ENV activation identity is cleared
  I4  the shared per-user site (%APPDATA%\\Python) is disabled
  I5  the scrub propagates to grandchildren (subprocess of subprocess)
  I6  a hostile PYTHONHOME does not hijack boot (C launchers clear it)
  I7  a hostile PYTHONPATH never enters sys.path (shadow module must NOT
      be importable)

Stdlib only; runs on the dev machine and on the bare Win7 target:

    python tests\\test_isolation.py --tree <PYTHON_DIR>

Exit code 0 = all checks pass.  Escape hatch under test: PYW7ISOLATE=0
disables the in-process half (sitecustomize); the C launchers' boot-time
PYTHONHOME/PYTHONPATH clearing is unconditional.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok))
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                           (" -- " + detail) if detail else ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tree", required=True, help="the Python tree to test")
    args = ap.parse_args()
    tree = os.path.abspath(args.tree)
    py = os.path.join(tree, "python.exe")
    print("tree:  ", tree)
    if not os.path.isfile(py):
        print("python.exe not found in tree")
        return 2

    fake = tempfile.mkdtemp(prefix="pyw7fakeconda_")
    os.makedirs(os.path.join(fake, "Scripts"))
    for f in ("python.exe", "pythonw.exe"):
        with open(os.path.join(fake, f), "wb") as fh:
            fh.write(b"MZfake")
    for f in ("jupyter-lab.exe", "node.exe", "python.exe"):
        with open(os.path.join(fake, "Scripts", f), "wb") as fh:
            fh.write(b"MZfake")

    env = dict(os.environ)
    env["PATH"] = fake + os.pathsep + os.path.join(fake, "Scripts") + \
        os.pathsep + env.get("PATH", "")
    env["CONDA_PREFIX"] = fake
    env["CONDA_DEFAULT_ENV"] = "base"
    env["VIRTUAL_ENV"] = fake

    code = r"""
import json, os, sys
from shutil import which
out = {
    "which_jlab": which("jupyter-lab"),
    "which_node": which("node"),
    "which_python": which("python"),
    "path_has_fake": any("pyw7fakeconda" in p
                         for p in os.environ.get("PATH", "").split(os.pathsep)),
    "conda_gone": "CONDA_PREFIX" not in os.environ
                  and "CONDA_DEFAULT_ENV" not in os.environ,
    "venv_gone": "VIRTUAL_ENV" not in os.environ,
    "usersite_off": __import__("site").ENABLE_USER_SITE is False,
}
try:
    from jupyter_core.command import _jupyter_abspath
    out["jlab_abspath"] = _jupyter_abspath("lab")
except Exception as e:
    out["jlab_err"] = repr(e)
print("RESULT " + json.dumps(out))
"""
    p = subprocess.run([py, "-c", code], env=env, capture_output=True,
                       text=True, timeout=180)
    if p.returncode or "RESULT " not in p.stdout:
        print("probe failed:", p.stderr[-400:])
        return 2
    res = json.loads(p.stdout.strip().split("RESULT ", 1)[1])
    low_tree = tree.lower()

    def in_tree(path):
        return bool(path) and path.lower().startswith(low_tree)

    if res["which_jlab"] is None:
        record("I1 which(jupyter-lab) ignores foreign install", True,
               "tree has no jupyter-lab shim (skipped)")
    else:
        record("I1 which(jupyter-lab) -> tree shim",
               in_tree(res["which_jlab"]), repr(res["which_jlab"]))
    record("I1 which(node) -> not foreign",
           not (res["which_node"] and "pyw7fakeconda" in res["which_node"]),
           repr(res["which_node"]))
    record("I1 which(python) -> tree python", in_tree(res["which_python"]),
           repr(res["which_python"]))
    if "jlab_abspath" in res:
        record("I1 jupyter_core dispatch -> tree shim",
               in_tree(res["jlab_abspath"]), repr(res["jlab_abspath"]))
    record("I2 PATH scrubbed of foreign-interpreter dirs",
           res["path_has_fake"] is False)
    record("I3 CONDA_* cleared", res["conda_gone"])
    record("I3 VIRTUAL_ENV cleared", res["venv_gone"])
    record("I4 per-user site disabled", res["usersite_off"])

    code2 = ("import os,subprocess,sys;"
             "r=subprocess.run([sys.executable,'-c','import os;"
             "print(chr(33).join(os.environ[\"PATH\"].split(os.pathsep)))'],"
             "capture_output=True,text=True);"
             "print('GC_FAKE', any('pyw7fakeconda' in x"
             " for x in r.stdout.split(chr(33))))")
    p2 = subprocess.run([py, "-c", code2], env=env, capture_output=True,
                        text=True, timeout=180)
    record("I5 grandchild inherits scrubbed PATH",
           "GC_FAKE False" in p2.stdout, p2.stdout.strip()[-60:])

    fakehome = tempfile.mkdtemp(prefix="pyw7home_")
    env2 = dict(env)
    env2["PYTHONHOME"] = fakehome
    p3 = subprocess.run([py, "-c", "import sys; print('BOOT OK')"],
                        env=env2, capture_output=True, text=True, timeout=180)
    record("I6 boots with hostile PYTHONHOME",
           p3.returncode == 0 and "BOOT OK" in p3.stdout,
           (p3.stdout.strip() or p3.stderr.strip()[-160:]))

    shadow = tempfile.mkdtemp(prefix="pyw7shadow_")
    with open(os.path.join(shadow, "pyw7shadow.py"), "w") as fh:
        fh.write("X = 1\n")
    env3 = dict(env)
    env3["PYTHONPATH"] = shadow
    p4 = subprocess.run([py, "-c", "import pyw7shadow"], env=env3,
                        capture_output=True, text=True, timeout=180)
    record("I7 PYTHONPATH shadow module NOT importable",
           p4.returncode != 0 and "pyw7shadow" in p4.stderr,
           p4.stderr.strip().splitlines()[-1] if p4.stderr else "")

    shutil.rmtree(fake, ignore_errors=True)
    shutil.rmtree(fakehome, ignore_errors=True)
    shutil.rmtree(shadow, ignore_errors=True)

    bad = sum(1 for _n, ok in RESULTS if not ok)
    print("=== SUMMARY: %d passed, %d failed ==="
          % (len(RESULTS) - bad, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pe_scan.py -- PE import/export scanner + per-OS API baseline resolver.

Pure stdlib. Runs on any Windows with Python 3.8+ (including the in-tree
Python 3.14, and including a bare Win7 target machine).

What it does
------------
1. Parses a PE file (.exe/.dll/.pyd): headers, sections, static import
   descriptors, delay-load import descriptors, and the export table
   (including forwarded exports like ``kernel32.CreateFileW``).
2. Loads an OS API baseline from a YY-Thunks analyzer database file
   (``assets/baseline/<arch>/<build>.txt``, INI-like: ``[dllname]`` sections,
   ``ordinal=FunctionName`` lines). The Win7 SP1 baseline is ``6.1.7600``.
3. Reports which imports of the scanned file are NOT resolvable on the
   baseline OS, i.e. the exact list of "will not load on Win7" items.
4. Optionally treats additional directories as "privately deployed DLLs":
   any import that the baseline cannot resolve is looked up in the export
   tables of DLLs found in those directories (this models our tree-root
   backport pack: ucrtbase.dll, api-ms-win-*.dll, Kx*.dll, ...).
   Forwarded exports are chased recursively (KB2999226's
   api-ms-win-core-*.dll forward into kernel32, etc).

Usage
-----
    pe_scan.py FILE [FILE ...] [--target 6.1.7600] [--arch x64]
               [--extra-dir DIR ...] [--json OUT.json] [--quiet] [--tree]

    --tree       treat every directory containing a scanned file as an
                 --extra-dir (models "DLLs next to the binary are found").
    --config-root DIR   where Config/<arch>/<target>.txt lives
                        (default: <repo>/tools/Config, auto-detected).

Exit code: 0 = everything resolvable, 1 = missing imports found,
2 = usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

# --------------------------------------------------------------------------
# PE parsing
# --------------------------------------------------------------------------

MACHINE_NAMES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "arm", 0xAA64: "arm64"}

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_DELAY_IMPORT = 13


class PEError(Exception):
    pass


class PEFile:
    """Minimal PE32/PE32+ parser: headers, sections, imports, exports."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PEError("not a PE file (no MZ)")
        self.pe_off = struct.unpack_from("<I", d, 0x3C)[0]
        if d[self.pe_off:self.pe_off + 4] != b"PE\0\0":
            raise PEError("no PE signature")
        coff = self.pe_off + 4
        (self.machine, self.nsections, _ts, _psym, _nsym,
         self.opt_size, self.characteristics) = struct.unpack_from(
            "<HHIIIHH", d, coff)
        opt = coff + 20
        self.magic = struct.unpack_from("<H", d, opt)[0]
        if self.magic == 0x20B:
            self.is64 = True
            dd_base = opt + 112
        elif self.magic == 0x10B:
            self.is64 = False
            dd_base = opt + 96
        else:
            raise PEError("unknown optional header magic 0x%x" % self.magic)
        # subsystem / OS version (same offsets for PE32 and PE32+)
        self.os_ver = struct.unpack_from("<HH", d, opt + 40)
        self.subsystem_ver = struct.unpack_from("<HH", d, opt + 48)
        self.image_size = struct.unpack_from("<I", d, opt + 56)[0]
        self.data_dirs = []
        for i in range(16):
            rva, size = struct.unpack_from("<II", d, dd_base + i * 8)
            self.data_dirs.append((rva, size))
        # sections
        self.sections = []
        soff = opt + self.opt_size
        for i in range(self.nsections):
            base = soff + i * 40
            name = d[base:base + 8].rstrip(b"\0").decode("ascii", "replace")
            vs, va, rs, rp = struct.unpack_from("<IIII", d, base + 8)
            self.sections.append((name, va, vs, rp, rs))

    # -- helpers -----------------------------------------------------------
    def rva_to_off(self, rva: int):
        for _name, va, vs, rp, rs in self.sections:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        # RVAs into headers
        if rva < 0x1000:
            return rva
        return None

    def cstr(self, off: int) -> str:
        end = self.data.find(b"\0", off)
        if end < 0:
            end = len(self.data)
        return self.data[off:end].decode("ascii", "replace")

    # -- imports -----------------------------------------------------------
    def _read_import_dir(self, rva: int, delay: bool):
        """Yield (dll_name, [(func_name_or_None, ordinal_or_None), ...])."""
        out = []
        if not rva:
            return out
        off = self.rva_to_off(rva)
        if off is None:
            return out
        ptr_size = 8 if self.is64 else 4
        ptr_fmt = "<Q" if self.is64 else "<I"
        ord_flag = 0x8000000000000000 if self.is64 else 0x80000000
        while True:
            if delay:
                # IMAGE_DELAYLOAD_DESCRIPTOR: attrs, name, handle, iat,
                # ilt(unused on disk for VC), bound, unload, ts
                (attrs, name_rva, _hmod, iat_rva, ilt_rva,
                 _b, _u, _ts) = struct.unpack_from("<IIIIIIII", self.data, off)
                if name_rva == 0 and iat_rva == 0:
                    break
                # vc delay descriptors: attrs bit 0 => addresses are RVAs
                thunk_rva = ilt_rva or iat_rva
                first_thunk = iat_rva
            else:
                (ilt_rva, _ts, _fwd, name_rva,
                 first_thunk) = struct.unpack_from("<IIIII", self.data, off)
                if name_rva == 0 and ilt_rva == 0:
                    break
                thunk_rva = ilt_rva or first_thunk
            noff = self.rva_to_off(name_rva)
            if noff is None:
                break
            dll = self.cstr(noff)
            funcs = []
            toff = self.rva_to_off(thunk_rva)
            if toff is not None:
                i = 0
                while True:
                    val = struct.unpack_from(ptr_fmt, self.data,
                                             toff + i * ptr_size)[0]
                    if val == 0:
                        break
                    if val & ord_flag:
                        funcs.append((None, val & 0xFFFF))
                    else:
                        hint_off = self.rva_to_off(val)
                        if hint_off is not None:
                            funcs.append((self.cstr(hint_off + 2), None))
                    i += 1
                    if i > 100000:
                        break
            out.append((dll, funcs, first_thunk, delay))
            off += 32 if delay else 20
        return out

    def imports(self):
        """Static imports: list of (dll, [(name, ordinal)], iat_rva)."""
        return [(dll, funcs, iat)
                for dll, funcs, iat, _d in
                self._read_import_dir(self.data_dirs[DIR_IMPORT][0], False)]

    def delay_imports(self):
        return [(dll, funcs, iat)
                for dll, funcs, iat, _d in
                self._read_import_dir(self.data_dirs[DIR_DELAY_IMPORT][0],
                                      True)]

    # -- exports -----------------------------------------------------------
    def exports(self):
        """Return {name: forward_target_or_None} and dll internal name."""
        rva, size = self.data_dirs[DIR_EXPORT]
        if not rva:
            return "", {}
        off = self.rva_to_off(rva)
        if off is None:
            return "", {}
        (_fl, _ts, _mj, _mn, name_rva, _base, nfunc, nname,
         afunc, aname, aord) = struct.unpack_from("<IIHHIIIIIII",
                                                  self.data, off)
        dllname = ""
        noff = self.rva_to_off(name_rva)
        if noff is not None:
            dllname = self.cstr(noff)
        result = {}
        o_aname, o_aord, o_afunc = (self.rva_to_off(aname),
                                    self.rva_to_off(aord),
                                    self.rva_to_off(afunc))
        if o_aname is None or o_aord is None or o_afunc is None:
            return dllname, result
        for i in range(nname):
            try:
                nm = self.cstr(self.rva_to_off(struct.unpack_from(
                    "<I", self.data, o_aname + 4 * i)[0]))
                ordi = struct.unpack_from("<H", self.data,
                                          o_aord + 2 * i)[0]
                frva = struct.unpack_from("<I", self.data,
                                          o_afunc + 4 * ordi)[0]
            except (struct.error, TypeError):
                continue
            fwd = None
            if rva <= frva < rva + size:
                foff = self.rva_to_off(frva)
                if foff is not None:
                    fwd = self.cstr(foff)
            result[nm] = fwd
        return dllname, result


# --------------------------------------------------------------------------
# OS baseline (YY-Thunks analyzer Config format)
# --------------------------------------------------------------------------

def find_config_root():
    here = os.path.dirname(os.path.abspath(__file__))
    # PythonWin7/tools/pe_scan.py: prefer the vendored copy at
    # PythonWin7/assets/baseline, fall back to the repo's tools/Config.
    for cand in (os.path.join(here, "Config"),
                 os.path.join(os.path.dirname(here), "Config"),
                 os.path.join(os.path.dirname(here), "assets", "baseline"),
                 os.path.join(os.path.dirname(os.path.dirname(here)),
                              "..", "tools", "Config"),
                 os.path.join(os.path.dirname(os.path.dirname(
                     os.path.dirname(here))), "tools", "Config")):
        cand = os.path.normpath(cand)
        if os.path.isdir(cand):
            return cand
    return None


def load_baseline(config_root: str, arch: str, target: str):
    """Return dict dll_name(lower) -> set(function names lower)."""
    path = os.path.join(config_root, arch, target + ".txt")
    if not os.path.isfile(path):
        raise PEError("baseline not found: " + path)
    db = {}
    cur = None
    with open(path, "r", encoding="ascii", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                cur = line[1:-1].lower()
                db.setdefault(cur, set())
            elif cur is not None and "=" in line:
                _ord, _eq, name = line.partition("=")
                name = name.strip()
                if name:
                    db[cur].add(name.lower())
    return db


# --------------------------------------------------------------------------
# Extra (privately deployed) DLL export index, with forward chasing
# --------------------------------------------------------------------------

class ExtraDllIndex:
    def __init__(self, dirs):
        self.by_dll = {}     # dll name (lower) -> {export: fwd}
        self.dirs = list(dirs)
        self._scan_dirs()

    def add_dir(self, d):
        if d and os.path.isdir(d) and d not in self.dirs:
            self.dirs.append(d)
            self._scan_one_dir(d)

    def _scan_dirs(self):
        for d in self.dirs:
            self._scan_one_dir(d)

    def _scan_one_dir(self, d):
        for fn in os.listdir(d):
            low = fn.lower()
            if not low.endswith((".dll", ".pyd", ".exe")):
                continue
            if low in self.by_dll:
                continue
            try:
                pe = PEFile(os.path.join(d, fn))
                _internal, exp = pe.exports()
            except (PEError, struct.error, OSError):
                continue
            self.by_dll[low] = {k.lower(): v for k, v in exp.items()}

    def resolve(self, dll: str, func: str, baseline, depth=0):
        """True if dll!func resolvable via extra dirs (chasing forwards)."""
        if depth > 8:
            return False
        exp = self.by_dll.get(dll.lower())
        if exp is None:
            return False
        if func.lower() not in exp:
            return False
        fwd = exp[func.lower()]
        if not fwd:
            return True  # real implementation inside this DLL
        # forward target: "dllname.function" (dllname without .dll)
        target, _, tfunc = fwd.partition(".")
        tdll = target.lower() + ".dll"
        if not tfunc:
            return False
        # forward into a DLL the baseline OS provides?
        if tdll in baseline and tfunc.lower() in baseline[tdll]:
            return True
        # or into another extra DLL (ucrtbase etc.)
        if self.resolve(tdll, tfunc, baseline, depth + 1):
            return True
        return False


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def scan_file(path, baseline, extra):
    pe = PEFile(path)
    problems = []
    covered = []
    for kind, entries in (("import", pe.imports()),
                          ("delay-import", pe.delay_imports())):
        for dll, funcs, _iat in entries:
            low = dll.lower()
            for name, ordinal in funcs:
                label = name if name else ("#%d" % ordinal)
                ok = False
                via = ""
                if name and low in baseline and name.lower() in baseline[low]:
                    ok = True
                    via = "os"
                elif name and extra.resolve(low, name, baseline):
                    ok = True
                    via = "tree"
                elif not name:
                    ok = True   # ordinal imports: cannot check; assume ok
                    via = "os?"
                rec = {"dll": dll, "func": label, "kind": kind, "via": via}
                (covered if ok else problems).append(rec)
    return {
        "file": path,
        "machine": MACHINE_NAMES.get(pe.machine, hex(pe.machine)),
        "os_version": "%d.%d" % pe.os_ver,
        "subsystem_version": "%d.%d" % pe.subsystem_ver,
        "missing": problems,
        "ok_count": len(covered),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--target", default="6.1.7600")
    ap.add_argument("--arch", default="x64")
    ap.add_argument("--config-root", default=None)
    ap.add_argument("--extra-dir", action="append", default=[])
    ap.add_argument("--tree", action="store_true")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    config_root = args.config_root or find_config_root()
    if not config_root:
        print("error: cannot locate Config database dir", file=sys.stderr)
        return 2
    try:
        baseline = load_baseline(config_root, args.arch, args.target)
    except PEError as e:
        print("error:", e, file=sys.stderr)
        return 2

    extra = ExtraDllIndex(args.extra_dir)
    results = []
    rc = 0
    for f in args.files:
        try:
            if args.tree:
                extra.add_dir(os.path.dirname(os.path.abspath(f)))
            r = scan_file(f, baseline, extra)
        except (PEError, struct.error, OSError) as e:
            r = {"file": f, "error": str(e)}
            rc = 1
        results.append(r)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fp:
            json.dump(results, fp, indent=1, ensure_ascii=False)

    if not args.quiet:
        for r in results:
            print("=" * 70)
            print(r["file"])
            if "error" in r:
                print("  ERROR:", r["error"])
                continue
            print("  machine=%s  PE OS=%s  subsystem=%s  resolved=%d" %
                  (r["machine"], r["os_version"], r["subsystem_version"],
                   r["ok_count"]))
            if r["missing"]:
                rc = 1
                by_dll = {}
                for m in r["missing"]:
                    by_dll.setdefault(m["dll"], []).append(m)
                for dll, items in sorted(by_dll.items()):
                    kinds = sorted({i["kind"] for i in items})
                    names = sorted({i["func"] for i in items})
                    print("  MISSING %-40s (%s)" % (dll, ",".join(kinds)))
                    for n in names:
                        print("      -", n)
            else:
                print("  OK: all imports resolvable on", args.target)
    return rc


if __name__ == "__main__":
    sys.exit(main())

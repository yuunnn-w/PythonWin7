# -*- coding: utf-8 -*-
"""pywin7gate.pe -- self-contained PE parser (headers/imports/delay-imports/
exports with forward chasing) + Win7 baseline loading from the bundled JSON.

Vendored copy of the parsing core of PythonWin7/tools/pe_scan.py so that the
gate works on a bare target machine (no PythonWin7 checkout needed).
Keep in sync with tools/pe_scan.py when fixing parser bugs.
"""
import json
import os
import struct

MACHINE_NAMES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "arm", 0xAA64: "arm64"}

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_IAT = 12
DIR_DELAY_IMPORT = 13


class PEError(Exception):
    pass


class PEFile:
    def __init__(self, path):
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
        self.opt_off = opt
        self.os_ver = struct.unpack_from("<HH", d, opt + 40)
        self.subsystem_ver = struct.unpack_from("<HH", d, opt + 48)
        self.subsystem = struct.unpack_from("<H", d, opt + 68)[0]
        self.image_size = struct.unpack_from("<I", d, opt + 56)[0]
        self.section_align = struct.unpack_from("<I", d, opt + 32)[0]
        self.file_align = struct.unpack_from("<I", d, opt + 36)[0]
        self.size_of_image_off = opt + 56
        self.checksum_off = opt + 64
        self.dd_off = dd_base
        self.data_dirs = []
        for i in range(16):
            self.data_dirs.append(struct.unpack_from("<II", d, dd_base + i * 8))
        self.sections = []
        soff = opt + self.opt_size
        self.section_table_off = soff
        for i in range(self.nsections):
            base = soff + i * 40
            name = d[base:base + 8].rstrip(b"\0").decode("ascii", "replace")
            vs, va, rs, rp = struct.unpack_from("<IIII", d, base + 8)
            chars = struct.unpack_from("<I", d, base + 36)[0]
            self.sections.append([name, va, vs, rp, rs, chars])

    def rva_to_off(self, rva):
        for s in self.sections:
            _name, va, vs, rp, rs = s[0], s[1], s[2], s[3], s[4]
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        if rva < 0x1000:
            return rva
        return None

    def cstr(self, off):
        end = self.data.find(b"\0", off)
        if end < 0:
            end = len(self.data)
        return self.data[off:end].decode("ascii", "replace")

    def _read_import_dir(self, rva, delay):
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
                (attrs, name_rva, _h, iat_rva, ilt_rva, _b, _u, _t) = \
                    struct.unpack_from("<IIIIIIII", self.data, off)
                if name_rva == 0 and iat_rva == 0:
                    break
                thunk_rva = ilt_rva or iat_rva
                first_thunk = iat_rva
            else:
                (ilt_rva, _t, _f, name_rva,
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
        return [(dll, funcs, iat) for dll, funcs, iat, _d in
                self._read_import_dir(self.data_dirs[DIR_IMPORT][0], False)]

    def delay_imports(self):
        return [(dll, funcs, iat) for dll, funcs, iat, _d in
                self._read_import_dir(self.data_dirs[DIR_DELAY_IMPORT][0],
                                      True)]

    def exports(self):
        rva, size = self.data_dirs[DIR_EXPORT]
        if not rva:
            return "", {}
        off = self.rva_to_off(rva)
        if off is None:
            return "", {}
        (_fl, _t, _mj, _mn, name_rva, _base, nfunc, nname,
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


# ----------------------------------------------------------------------
# baseline (bundled JSON) + extra-DLL resolution
# ----------------------------------------------------------------------

_baseline_cache = {}


def load_baseline(target="6.1.7600"):
    """dll(lower) -> frozenset(func lower), from bundled baseline JSON."""
    if target in _baseline_cache:
        return _baseline_cache[target]
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "baseline_" + target.replace(".", "_") + ".json")
    if not os.path.isfile(path):
        raise PEError("baseline not bundled: " + path)
    with open(path, "r", encoding="ascii") as f:
        payload = json.load(f)
    db = {dll: frozenset(funcs) for dll, funcs in payload["dlls"].items()}
    _baseline_cache[target] = db
    return db


class ExtraDllIndex:
    """Export index of privately deployed DLL dirs, with forward chasing."""

    def __init__(self, dirs=()):
        self.by_dll = {}
        self.dirs = []
        for d in dirs:
            self.add_dir(d)

    def add_dir(self, d):
        if d and os.path.isdir(d) and d not in self.dirs:
            self.dirs.append(d)
            for fn in os.listdir(d):
                low = fn.lower()
                if not low.endswith((".dll", ".pyd", ".exe")):
                    continue
                if low in self.by_dll:
                    continue
                try:
                    pe = PEFile(os.path.join(d, fn))
                    _i, exp = pe.exports()
                except (PEError, struct.error, OSError):
                    continue
                self.by_dll[low] = {k.lower(): v for k, v in exp.items()}

    def has_dll(self, dll):
        return dll.lower() in self.by_dll

    def exports_of(self, dll):
        return self.by_dll.get(dll.lower(), {})

    def resolve(self, dll, func, baseline, depth=0):
        if depth > 8:
            return False
        exp = self.by_dll.get(dll.lower())
        if exp is None:
            return False
        if func.lower() not in exp:
            return False
        fwd = exp[func.lower()]
        if not fwd:
            return True
        target, _, tfunc = fwd.partition(".")
        tdll = target.lower() + ".dll"
        if not tfunc:
            return False
        if tdll in baseline and tfunc.lower() in baseline[tdll]:
            return True
        return self.resolve(tdll, tfunc, baseline, depth + 1)


def scan_file(path, baseline, extra):
    """Return dict with missing/resolved import analysis for one PE file."""
    pe = PEFile(path)
    problems = []
    covered = 0
    for kind, entries in (("import", pe.imports()),
                          ("delay-import", pe.delay_imports())):
        for dll, funcs, _iat in entries:
            low = dll.lower()
            for name, ordinal in funcs:
                if name:
                    if name and low in baseline and name.lower() in baseline[low]:
                        covered += 1
                    elif extra.resolve(low, name, baseline):
                        covered += 1
                    else:
                        problems.append({"dll": dll, "func": name,
                                         "kind": kind})
                elif ordinal is not None:
                    covered += 1  # ordinal imports cannot be checked
                else:
                    problems.append({"dll": dll,
                                     "func": "<unreadable-import>",
                                     "kind": kind})
    return {
        "file": path,
        "machine": MACHINE_NAMES.get(pe.machine, hex(pe.machine)),
        "os_version": "%d.%d" % pe.os_ver,
        "subsystem_version": "%d.%d" % pe.subsystem_ver,
        "missing": problems,
        "ok_count": covered,
    }

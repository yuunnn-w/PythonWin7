# -*- coding: utf-8 -*-
"""pywin7gate.iatpatch -- surgical IAT redirection for PE files.

Moves a single by-name import (e.g. KERNEL32.dll!AddDllDirectory) to a
different DLL (e.g. KxBase.dll) **without breaking anything else**.

Why not "move the thunk into a new descriptor and zero the old one":
  * The loader stops scanning a thunk array at the first NULL entry, so
    zeroing a mid-array entry would break every import after it.
  * Code references IAT slots by absolute address, so IAT entries can be
    neither compacted nor reordered.

What we do instead (per redirected function):
  1. In the source DLL descriptor, the victim's ILT entry points at a
     hint/name record.  We rewrite that record's string **in place** to a
     "donor" function that the source DLL genuinely exports on the target
     OS (for kernel32: ``GetLastError``).  The loader therefore resolves
     the donor and writes a harmless valid address into the victim's IAT
     slot.  All other imports of the source DLL are untouched.
  2. We append a NEW import descriptor for the destination DLL at the end
     of the (relocated) descriptor table, whose ``FirstThunk`` points at
     the **same old IAT slot** and whose ILT (living in a new section)
     names the destination function.  The loader processes descriptors in
     table order, so the destination DLL's address overwrites the donor
     address in that slot ("last writer wins").  Call sites keep pointing
     at the same slot and transparently get the new target.

The descriptor table is relocated into the added section ``.pyw7i``
(originals are left in place, harmlessly unused).

Everything is pure-stdlib; works on any host Python 3.8+.
"""
import hashlib
import os
import shutil
import struct

from .pe import PEFile, PEError, DIR_IMPORT


class PatchError(Exception):
    pass


SECTION_NAME = b".pyw7i\0\0"
SECTION_NAME_STR = ".pyw7i"
SEC_CHARACTERISTICS = 0x40000040  # IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ

# Donor candidates for redirect(): names the source DLL genuinely exports on
# the target OS (bare Win7 SP1), in true export case.  The donor's resolved
# address is written into the victim's IAT slot and then overwritten by the
# appended descriptor (last-writer-wins), so any valid export works -- the
# only hard constraint is len(donor) <= len(victim), because the hint/name
# record is rewritten in place.  Ordered longest-first so the first fitting
# candidate keeps the record as close to the original length as possible.
DONOR_CANDIDATES = {
    "kernel32.dll": ("GetLastError", "Sleep", "Beep"),
    "user32.dll": ("GetFocus", "SetFocus"),
    "gdi32.dll": ("OffsetRgn",),
    "advapi32.dll": ("GetUserNameW", "RegCloseKey"),
    "shell32.dll": ("DragFinish",),
    "ntdll.dll": ("DbgPrint",),
    "ole32.dll": ("CoGetMalloc",),
    "ws2_32.dll": ("accept", "bind", "recv", "send"),
}


def pick_donor(src_dll, func_name):
    """Choose a donor for src_dll/func_name from DONOR_CANDIDATES: the first
    candidate short enough to overwrite the victim's name record in place.
    Raises PatchError when nothing fits (pass donor= explicitly then)."""
    for cand in DONOR_CANDIDATES.get(src_dll.lower(), ()):
        if len(cand) <= len(func_name):
            return cand
    raise PatchError("no built-in donor for %s!%s short enough to fit; "
                     "pass donor= explicitly" % (src_dll, func_name))


def _align(v, a):
    return (v + a - 1) // a * a


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class IATPatcher:
    """Batch-redirect imports of one PE file, then write once.

    Usage:
        p = IATPatcher(path)
        p.redirect("KERNEL32.dll", "AddDllDirectory", "KxBase.dll")
        p.redirect("KERNEL32.dll", "RemoveDllDirectory", "KxBase.dll")
        p.commit()          # or p.rollback() to discard
    """

    def __init__(self, path):
        self.path = path
        self.pe = PEFile(path)
        self.buf = bytearray(self.pe.data)
        self.ptr_size = 8 if self.pe.is64 else 4
        self.ptr_fmt = "<Q" if self.pe.is64 else "<I"
        self.ord_flag = (0x8000000000000000 if self.pe.is64
                         else 0x80000000)
        self._jobs = []        # list of dicts, one per redirect
        self._retargets = []   # whole-descriptor DLL-name substitutions
        self._done = False
        if any(s[0] == SECTION_NAME_STR for s in self.pe.sections):
            raise PatchError("%s already patched (.pyw7i present); "
                             "restore first" % path)

    # ------------------------------------------------------------------
    def _find_import(self, src_dll, func_name):
        imp_rva, _size = self.pe.data_dirs[DIR_IMPORT]
        off = self.pe.rva_to_off(imp_rva)
        if off is None:
            raise PatchError("no import directory")
        idx = 0
        while True:
            ilt_rva, ts, _fwd, name_rva, ft_rva = struct.unpack_from(
                "<IIIII", self.buf, off + idx * 20)
            if ilt_rva == 0 and name_rva == 0:
                break
            noff = self.pe.rva_to_off(name_rva)
            dll = self.pe.cstr(noff) if noff is not None else ""
            if dll.lower() == src_dll.lower():
                if ts == 0xFFFFFFFF:
                    raise PatchError("bound import descriptor for %s; "
                                     "refusing" % src_dll)
                thunk_rva = ilt_rva or ft_rva
                toff = self.pe.rva_to_off(thunk_rva)
                i = 0
                while True:
                    val = struct.unpack_from(self.ptr_fmt, self.buf,
                                             toff + i * self.ptr_size)[0]
                    if val == 0:
                        break
                    if not (val & self.ord_flag):
                        rec_off = self.pe.rva_to_off(val)
                        nm = self.pe.cstr(rec_off + 2)
                        if nm.lower() == func_name.lower():
                            return {
                                "desc_index": idx,
                                "thunk_index": i,
                                "iat_slot_rva": ft_rva + i * self.ptr_size,
                                "name_rec_off": rec_off,
                                "orig_name": nm,
                            }
                    i += 1
                    if i > 100000:
                        break
                raise PatchError("%s!%s not found in import table"
                                 % (src_dll, func_name))
            idx += 1
        raise PatchError("descriptor for %s not found" % src_dll)

    # ------------------------------------------------------------------
    def redirect(self, src_dll, func_name, dst_dll, dst_func=None,
                 donor=None):
        """Queue one redirection. donor must exist in src_dll on the
        target OS and satisfy len(donor) <= len(func_name); with the
        default None one is auto-picked from DONOR_CANDIDATES."""
        dst_func = dst_func or func_name
        if donor is None:
            donor = pick_donor(src_dll, func_name)
        if len(donor) > len(func_name):
            raise PatchError("donor %r longer than victim %r; "
                             "pick a shorter donor" % (donor, func_name))
        job = self._find_import(src_dll, func_name)
        job.update({"src_dll": src_dll, "dst_dll": dst_dll,
                    "dst_func": dst_func, "donor": donor})
        self._jobs.append(job)
        return job

    # ------------------------------------------------------------------
    def retarget_dll(self, src_dll, dst_dll, dst_exports):
        """Queue a whole-descriptor DLL substitution: the descriptor that
        imports from ``src_dll`` is pointed at ``dst_dll`` instead, keeping
        every imported function name unchanged.

        Use this when ``src_dll`` does not exist on the target OS at all
        (e.g. an ``api-ms-win-*`` name that has no DLL file): the donor
        technique cannot help there because the loader fails to find the
        *DLL*, not the function.  The descriptor's DLL-name string is
        overwritten in place (requires len(dst_dll) <= len(src_dll)) and
        every imported name must exist in ``dst_exports`` (checked here).
        """
        imp_rva, _size = self.pe.data_dirs[DIR_IMPORT]
        off = self.pe.rva_to_off(imp_rva)
        if off is None:
            raise PatchError("no import directory")
        dst_low = dst_dll.lower()
        if len(dst_dll) > len(src_dll):
            raise PatchError("retarget name %r longer than %r"
                             % (dst_dll, src_dll))
        idx = 0
        while True:
            ilt_rva, ts, _fwd, name_rva, _ft = struct.unpack_from(
                "<IIIII", self.buf, off + idx * 20)
            if ilt_rva == 0 and name_rva == 0:
                break
            noff = self.pe.rva_to_off(name_rva)
            dll = self.pe.cstr(noff) if noff is not None else ""
            if dll.lower() == src_dll.lower():
                if ts != 0:
                    raise PatchError("bound import descriptor for %s; "
                                     "refusing" % src_dll)
                # collect imported names and verify against dst exports
                funcs = []
                toff = self.pe.rva_to_off(ilt_rva)
                i = 0
                while toff is not None:
                    val = struct.unpack_from(self.ptr_fmt, self.buf,
                                             toff + i * self.ptr_size)[0]
                    if val == 0:
                        break
                    if val & self.ord_flag:
                        raise PatchError(
                            "ordinal import from %s cannot be retargeted "
                            "by name" % src_dll)
                    rec_off = self.pe.rva_to_off(val)
                    funcs.append(self.pe.cstr(rec_off + 2))
                    i += 1
                    if i > 100000:
                        break
                exp_low = {e.lower() for e in dst_exports}
                uncovered = [f for f in funcs if f.lower() not in exp_low]
                if uncovered:
                    raise PatchError(
                        "%s does not export %s; cannot retarget %s"
                        % (dst_dll, ", ".join(uncovered[:4]), src_dll))
                self._retargets.append({
                    "name_off": noff, "src_dll": dll, "dst_dll": dst_dll,
                    "funcs": funcs})
                return
            idx += 1
        raise PatchError("descriptor for %s not found" % src_dll)

    # ------------------------------------------------------------------
    def commit(self, backup=True):
        if self._done:
            raise PatchError("already committed")
        if not self._jobs and not self._retargets:
            raise PatchError("nothing to do")
        pe = self.pe

        # -- 0. in-place retargets (no new section needed) ---------------
        for rt in self._retargets:
            dst = rt["dst_dll"].encode("ascii")
            old_len = len(rt["src_dll"]) + 1
            new = dst + b"\0" + b"\0" * (old_len - len(dst) - 1)
            self.buf[rt["name_off"]: rt["name_off"] + old_len] = new

        if not self._jobs:
            # retarget-only commit: invalidate checksum, backup, write
            struct.pack_into("<I", self.buf, pe.checksum_off, 0)
            if backup:
                bak = self.path + ".pyw7bak"
                if not os.path.exists(bak):
                    shutil.copy2(self.path, bak)
            with open(self.path, "wb") as f:
                f.write(self.buf)
            self._done = True
            return {
                "file": self.path,
                "sha256_after": sha256_of(self.path),
                "backup": (self.path + ".pyw7bak") if backup else None,
                "redirects": [],
                "retargets": [
                    {"src": rt["src_dll"], "dst": rt["dst_dll"],
                     "funcs": rt["funcs"]} for rt in self._retargets],
            }

        # -- 1. rewrite victim name records in place (donor swap) -------
        for job in self._jobs:
            rec = job["name_rec_off"]
            donor = job["donor"].encode("ascii")
            old_len = len(job["orig_name"]) + 1          # incl NUL
            new = donor + b"\0"
            new += b"\0" * (old_len - len(new))           # zero the tail
            self.buf[rec + 2: rec + 2 + old_len] = new

        # -- 2. plan new section contents --------------------------------
        imp_rva, imp_size = pe.data_dirs[DIR_IMPORT]
        imp_off = pe.rva_to_off(imp_rva)
        # count existing descriptors
        n_desc = 0
        while True:
            ilt, _t, _f, nm, _ft = struct.unpack_from(
                "<IIIII", self.buf, imp_off + n_desc * 20)
            if ilt == 0 and nm == 0:
                break
            n_desc += 1
        table_bytes = self.buf[imp_off: imp_off + n_desc * 20]

        blob = bytearray()
        # layout: [descriptor table + new descriptors + null]
        #         [per-job ILT arrays] [hint/name records] [dll names]
        n_new = len(self._jobs)
        table_rva_in_blob = 0
        ilt_base = (n_desc + n_new + 1) * 20
        # reserve ILT space
        names_base = ilt_base + n_new * 2 * self.ptr_size
        cursor = names_base
        dll_name_off = {}   # dst_dll.lower() -> blob offset
        job_layout = []
        for job in self._jobs:
            rec = job["dst_func"].encode("ascii")
            dll = job["dst_dll"].encode("ascii")
            job_layout.append({"ilt_blob": ilt_base +
                               len(job_layout) * 2 * self.ptr_size,
                               "rec_blob": cursor})
            cursor += 2 + len(rec) + 1
            if cursor % 2:
                cursor += 1
            if job["dst_dll"].lower() not in dll_name_off:
                dll_name_off[job["dst_dll"].lower()] = cursor
                cursor += len(dll) + 1
                if cursor % 2:
                    cursor += 1
        blob.extend(b"\0" * cursor)

        # -- 3. create the new section -----------------------------------
        hdr_space = (pe.section_table_off + pe.nsections * 40)
        first_raw = min(s[3] for s in pe.sections)
        if hdr_space + 40 > first_raw:
            raise PatchError("no header slack for a new section")
        last_va_end = max(s[1] + s[2] for s in pe.sections)
        sec_va = _align(last_va_end, pe.section_align)
        raw_off = _align(len(self.buf), pe.file_align)
        raw_size = _align(len(blob), pe.file_align)
        # pad file to raw_off
        if len(self.buf) < raw_off:
            self.buf.extend(b"\0" * (raw_off - len(self.buf)))

        # blob RVAs = sec_va + blob offset
        # fill descriptor table copy
        blob[0:len(table_bytes)] = table_bytes
        # append new descriptors + null
        desc_pos = n_desc * 20
        for i, job in enumerate(self._jobs):
            lo = job_layout[i]
            ilt_rva = sec_va + lo["ilt_blob"]
            rec_rva = sec_va + lo["rec_blob"]
            dll_rva = sec_va + dll_name_off[job["dst_dll"].lower()]
            struct.pack_into("<IIIII", blob, desc_pos + i * 20,
                             ilt_rva, 0, 0, dll_rva, job["iat_slot_rva"])
            # ILT: [rec_rva, 0]
            struct.pack_into(self.ptr_fmt, blob, lo["ilt_blob"], rec_rva)
            struct.pack_into(self.ptr_fmt, blob,
                             lo["ilt_blob"] + self.ptr_size, 0)
            # hint/name record: hint=0 + name
            struct.pack_into("<H", blob, lo["rec_blob"], 0)
            blob[lo["rec_blob"] + 2:
                 lo["rec_blob"] + 2 + len(job["dst_func"])] = \
                job["dst_func"].encode("ascii")
        # dll name strings
        for low, off in dll_name_off.items():
            nm = [j for j in self._jobs if j["dst_dll"].lower() == low][0]
            data = nm["dst_dll"].encode("ascii") + b"\0"
            blob[off:off + len(data)] = data
        # null descriptor already zero

        # write section bytes
        self.buf[raw_off:raw_off + len(blob)] = blob
        if len(self.buf) < raw_off + raw_size:
            self.buf.extend(b"\0" * (raw_off + raw_size - len(self.buf)))

        # -- 4. section header -------------------------------------------
        sh_off = pe.section_table_off + pe.nsections * 40
        hdr = bytearray(40)
        hdr[0:8] = SECTION_NAME
        struct.pack_into("<IIIIIIHHI", hdr, 8,
                         len(blob),        # VirtualSize
                         sec_va,            # VirtualAddress
                         raw_size,          # SizeOfRawData
                         raw_off,           # PointerToRawData
                         0, 0, 0, 0,
                         SEC_CHARACTERISTICS)
        self.buf[sh_off:sh_off + 40] = hdr
        # NumberOfSections
        struct.pack_into("<H", self.buf, pe.pe_off + 4 + 2,
                         pe.nsections + 1)
        # SizeOfImage
        struct.pack_into("<I", self.buf, pe.size_of_image_off,
                         _align(sec_va + len(blob), pe.section_align))
        # import data directory -> relocated table
        new_table_rva = sec_va + table_rva_in_blob
        struct.pack_into("<II", self.buf, pe.dd_off + DIR_IMPORT * 8,
                         new_table_rva, (n_desc + n_new + 1) * 20)
        # invalidate checksum (user-mode loader ignores it anyway)
        struct.pack_into("<I", self.buf, pe.checksum_off, 0)

        # -- 5. backup + write -------------------------------------------
        if backup:
            bak = self.path + ".pyw7bak"
            if not os.path.exists(bak):
                shutil.copy2(self.path, bak)
        with open(self.path, "wb") as f:
            f.write(self.buf)
        self._done = True
        return {
            "file": self.path,
            "sha256_after": sha256_of(self.path),
            "backup": (self.path + ".pyw7bak") if backup else None,
            "redirects": [
                {"src": "%s!%s" % (j["src_dll"], j["orig_name"]),
                 "dst": "%s!%s" % (j["dst_dll"], j["dst_func"]),
                 "donor": j["donor"],
                 "iat_slot_rva": "0x%x" % j["iat_slot_rva"]}
                for j in self._jobs],
            "retargets": [
                {"src": rt["src_dll"], "dst": rt["dst_dll"],
                 "funcs": rt["funcs"]} for rt in self._retargets],
        }

    def rollback(self):
        self._jobs = []
        self.buf = bytearray(self.pe.data)


# ----------------------------------------------------------------------
# standalone helpers
# ----------------------------------------------------------------------

def restore(path):
    """Restore a patched file from its .pyw7bak backup."""
    bak = path + ".pyw7bak"
    if not os.path.exists(bak):
        raise PatchError("no backup: " + bak)
    shutil.copy2(bak, path)
    return True


def is_patched(path):
    try:
        pe = PEFile(path)
    except PEError:
        return False
    return any(s[0] == SECTION_NAME_STR for s in pe.sections)


def list_redirects(path):
    """List descriptors whose DLL-name string lives inside .pyw7i
    (i.e. descriptors added by this patcher)."""
    pe = PEFile(path)
    sec = [s for s in pe.sections if s[0] == SECTION_NAME_STR]
    if not sec:
        return []
    sec = sec[0]
    sec_rva_end = sec[1] + max(sec[2], sec[4])
    imp_rva, _sz = pe.data_dirs[DIR_IMPORT]
    off = pe.rva_to_off(imp_rva)
    if off is None:
        return []
    out = []
    idx = 0
    while True:
        ilt, _t, _f, nm, ft = struct.unpack_from("<IIIII", pe.data,
                                                 off + idx * 20)
        if ilt == 0 and nm == 0:
            break
        if sec[1] <= nm < sec_rva_end:
            dll = pe.cstr(pe.rva_to_off(nm))
            funcs = []
            toff = pe.rva_to_off(ilt)
            ptr_size = 8 if pe.is64 else 4
            ptr_fmt = "<Q" if pe.is64 else "<I"
            i = 0
            while toff is not None:
                val = struct.unpack_from(ptr_fmt, pe.data,
                                         toff + i * ptr_size)[0]
                if val == 0:
                    break
                rec = pe.rva_to_off(val)
                if rec is not None:
                    funcs.append(pe.cstr(rec + 2))
                i += 1
            out.append({"dll": dll, "funcs": funcs, "iat_rva": "0x%x" % ft})
        idx += 1
    return out

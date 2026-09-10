# -*- coding: utf-8 -*-
"""pywin7gate.shims -- relocate-proof console-script exe shims.

Stock pip console scripts (Scripts\\*.exe) are distlib launchers:
[native stub]["#!C:\\abs\\python.exe"][zip with __main__.py].  The embedded
ABSOLUTE interpreter path is the one thing that breaks when a packed tree is
moved, copied or renamed.

Conversion replaces the native prefix with the CRT-free PyKexExe stub
(kernel32-only imports, runs on bare Win7 SP1):

    [PyKexExe stub]["#!pyw7-relocatable" [args] CRLF][original zip payload]

At runtime the stub locates python[w].exe relative to its own path (next to
itself -- venv Scripts; one level up -- tree root), then relaunches as
``"<python>" [args] "<shim>" <original args...>`` and CPython executes the
shim file itself as a zipapp.  Result: zero absolute paths, zero commands
needed after unpacking a moved/copied tree.  The marker line makes converted
shims self-describing (relocate skips them; `shims` reports "ok").

Only genuine python console scripts are converted: the file must carry a zip
payload whose __main__.py first line (new-generation shims: the inline
shebang between stub and zip) points at python*.exe.  Real binaries shipped
into Scripts (ruff.exe, ninja.exe, py-spy.exe, magika.exe, ...) are skipped.
"""
import io
import os
import struct
import zipfile

SHIM_MARKER = b"#!pyw7-relocatable"
STUB_CONSOLE = "PyKexExe.exe"
STUB_GUI = "PyKexExeW.exe"
BACKUP_DIRNAME = "pyw7bak"


def shim_zip_start(data):
    """Length of the launcher-stub prefix of an exe shim (stub|zip or
    stub|shebang|zip), derived from the end-of-central-directory record."""
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 22:
        return -1
    cd_size, cd_off = struct.unpack_from("<II", data, eocd + 12)
    start = eocd - cd_size - cd_off
    return start if 0 < start <= eocd else -1


def split_shebang(body):
    """'#!"x\\python.exe" -E' -> ('x\\python.exe', '" -E') style parts."""
    s = body.decode("utf-8", "strict").strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 1:
            return s[1:end], s[end:]           # keep closing quote + args
        return s[1:], ""
    parts = s.split(None, 1)
    return parts[0], (" " + parts[1]) if len(parts) > 1 else ""


def join_shebang(exe, suffix):
    if suffix.startswith('"'):
        return '"%s%s' % (exe, suffix)
    return exe + suffix


def pe_subsystem(data):
    """IMAGE_OPTIONAL_HEADER.Subsystem: 2 = GUI, 3 = console (default)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return 3
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return 3
    return struct.unpack_from("<H", data, e_lfanew + 4 + 20 + 68)[0]


def read_shim(path):
    """Parse a candidate console-script shim.

    Returns None when the file is not a python-script shim (real binary,
    foreign shebang, no zip payload).  Otherwise a dict:
      zstart    offset where the zip payload begins
      gui       True when the shim must relaunch pythonw.exe
      args      interpreter args from the original shebang (may be '')
      converted True when the PyKexExe marker is already present
      data      the whole file content
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if data[:2] != b"MZ":
        return None
    zstart = shim_zip_start(data)
    if zstart < 0:
        return None

    inline = None
    sh = data.rfind(b"#!", 0, zstart)
    if sh >= 0 and b"\n" not in data[sh:zstart].rstrip(b"\r\n"):
        line = data[sh:zstart].rstrip(b"\r\n")
        if line.startswith(SHIM_MARKER):
            args = line[len(SHIM_MARKER):].strip()
            return {"zstart": zstart, "gui": pe_subsystem(data) == 2,
                    "args": args.decode("utf-8", "replace"),
                    "converted": True, "data": data}
        inline = line[2:]

    try:
        zin = zipfile.ZipFile(io.BytesIO(data[zstart:]))
        names = zin.namelist()
    except zipfile.BadZipFile:
        return None
    if "__main__.py" not in names:
        return None
    if inline is not None:
        shebang = inline
    else:
        content = zin.read("__main__.py")
        if not content.startswith(b"#!"):
            return None
        eol = content.find(b"\n")
        if eol < 0:
            return None
        shebang = content[2:eol]
    try:
        exe, suffix = split_shebang(shebang)
    except UnicodeDecodeError:
        return None
    base = os.path.basename(exe).lower()
    if not (base.startswith("python") and base.endswith(".exe")):
        return None
    args = suffix.strip()
    if args.startswith('"'):
        args = args[1:].strip()
    gui = base.startswith("pythonw") or pe_subsystem(data) == 2
    return {"zstart": zstart, "gui": gui, "args": args,
            "converted": False, "data": data}


def stub_paths(root):
    return {False: os.path.join(root, STUB_CONSOLE),
            True: os.path.join(root, STUB_GUI)}


def stubs_available(root):
    return all(os.path.isfile(p) for p in stub_paths(root).values())


def load_stubs(root):
    out = {}
    for gui, p in stub_paths(root).items():
        with open(p, "rb") as f:
            out[gui] = f.read()
    return out


def convert_file(path, stubs, backup_dir=None):
    """Rewrite one shim to the PyKexExe layout.
    stubs: {False: console_stub_bytes, True: gui_stub_bytes}.
    Returns 'converted' / 'updated' / 'ok' / 'skip'."""
    info = read_shim(path)
    if info is None:
        return "skip"
    if info["converted"]:
        # Already ours -- but the stub itself may be an older build.  Refresh
        # the native prefix when it drifts from the current stub bytes, keep
        # the marker line (interpreter args) and zip payload untouched.
        sh = info["data"].rfind(b"#!", 0, info["zstart"])
        if sh < 0 or info["data"][:sh] == stubs[info["gui"]]:
            return "ok"
        out = stubs[info["gui"]] + info["data"][sh:]
        tmp = path + ".pyw7tmp"
        with open(tmp, "wb") as f:
            f.write(out)
        os.replace(tmp, path)
        return "updated"
    marker = SHIM_MARKER
    if info["args"]:
        marker += b" " + info["args"].encode("utf-8")
    marker += b"\r\n"
    out = stubs[info["gui"]] + marker + info["data"][info["zstart"]:]
    if backup_dir:
        os.makedirs(backup_dir, exist_ok=True)
        bak = os.path.join(backup_dir, os.path.basename(path))
        if not os.path.exists(bak):
            with open(bak, "wb") as f:
                f.write(info["data"])
    tmp = path + ".pyw7tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.replace(tmp, path)
    return "converted"


def convert_tree(root, log=print, backup=True, on_convert=None):
    """Convert every python-script shim in <root>\\Scripts.
    on_convert(relpath, backup_relpath) is called for each converted file
    (manifest recording hook for build_pack).  Returns counts dict."""
    scripts = os.path.join(root, "Scripts")
    counts = {"converted": 0, "updated": 0, "ok": 0, "skip": 0}
    if not os.path.isdir(scripts):
        return counts
    stubs = load_stubs(root)
    backup_dir = os.path.join(scripts, BACKUP_DIRNAME) if backup else None
    for fn in sorted(os.listdir(scripts)):
        if not fn.lower().endswith(".exe"):
            continue
        p = os.path.join(scripts, fn)
        r = convert_file(p, stubs, backup_dir)
        counts[r] += 1
        if r == "converted":
            if on_convert:
                on_convert(os.path.relpath(p, root),
                           os.path.relpath(
                               os.path.join(backup_dir, fn), root)
                           if backup_dir else None)
            log("shim->PyKexExe:", fn)
        elif r == "updated":
            if on_convert:
                on_convert(os.path.relpath(p, root), None)
            log("shim stub refreshed:", fn)
    return counts

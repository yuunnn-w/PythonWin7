# -*- coding: utf-8 -*-
"""pywin7gate.fixers -- concrete fix actions for Win7-incompatible binaries.

Actions:
  * redirect_imports   -- IAT surgery (see iatpatch.py)
  * retarget_import_dll-- whole-descriptor DLL substitution (for imported
                          DLL names that have no file on the target OS)
  * flatten_vendored   -- delvewheel-style "<pkg>.libs" DLLs copied next to
                          the .pyd files that import them (Win7 has no real
                          AddDllDirectory, so os.add_dll_directory() is a
                          success-no-op via KxBase; the DLL must sit in a
                          directory the loader actually searches)
  * provision_exe_dir  -- copy the runtime pack next to wheel-bundled .exe
                          tools so they can start on a bare Win7
  * find_kx_target     -- decide whether a missing system-API import can be
                          satisfied by redirecting to a Kx*.dll
  * find_runtime_redirect -- decide whether an imported DLL name is covered
                          by PyKexBoot's load-time in-memory import rewrite
"""
import os
import shutil

from . import pe as pemod
from .iatpatch import IATPatcher

PACK_STAMP = ".pyw7pack.stamp"


# ----------------------------------------------------------------------
# IAT redirection
# ----------------------------------------------------------------------

def redirect_imports(path, jobs, backup=True):
    """jobs: iterable of (src_dll, func_name, dst_dll[, dst_func][, donor]).
    Returns iatpatch commit record."""
    p = IATPatcher(path)
    for j in jobs:
        if len(j) == 3:
            p.redirect(j[0], j[1], j[2])
        elif len(j) == 4:
            p.redirect(j[0], j[1], j[2], j[3])
        else:
            p.redirect(j[0], j[1], j[2], j[3], j[4])
    return p.commit(backup=backup)


def retarget_import_dll(path, src_dll, dst_dll, dst_exports, backup=True):
    """Whole-descriptor DLL substitution (see IATPatcher.retarget_dll).
    Used when src_dll has no file on the target OS (api-ms-win-* names)."""
    p = IATPatcher(path)
    p.retarget_dll(src_dll, dst_dll, dst_exports)
    return p.commit(backup=backup)


# ----------------------------------------------------------------------
# vendored-libs flattening (delvewheel *.libs)
# ----------------------------------------------------------------------

def find_vendored_libs(site_packages):
    """Return list of *.libs directories under site-packages."""
    out = []
    try:
        for name in os.listdir(site_packages):
            if name.lower().endswith(".libs"):
                full = os.path.join(site_packages, name)
                if os.path.isdir(full):
                    out.append(full)
    except OSError:
        pass
    return out


def flatten_vendored(site_packages, libs_dir, dry_run=False, log=print):
    """For every DLL in libs_dir, find .pyd files under site-packages that
    import it (by exact DLL name) and copy the DLL next to them.
    Returns list of (dll, [dst_dirs]) actions."""
    libs = [f for f in os.listdir(libs_dir) if f.lower().endswith(".dll")]
    if not libs:
        return []
    wanted = {f.lower(): f for f in libs}
    actions = []
    hits = {f: set() for f in libs}
    for root, _dirs, files in os.walk(site_packages):
        for fn in files:
            if not fn.lower().endswith(".pyd"):
                continue
            path = os.path.join(root, fn)
            try:
                pe = pemod.PEFile(path)
                imps = pe.imports() + pe.delay_imports()
            except (pemod.PEError, OSError):
                continue
            for dll, _funcs, _iat in imps:
                low = dll.lower()
                if low in wanted:
                    hits[wanted[low]].add(root)
    for dll, dirs in hits.items():
        if not dirs:
            continue
        src = os.path.join(libs_dir, dll)
        copied_to = []
        for d in sorted(dirs):
            dst = os.path.join(d, dll)
            if not os.path.exists(dst):
                if not dry_run:
                    shutil.copy2(src, dst)
                copied_to.append(d)
                log("  flatten: %s -> %s" % (dll, d))
        if copied_to:
            actions.append((dll, copied_to))
    return actions


# ----------------------------------------------------------------------
# exe-dir provisioning
# ----------------------------------------------------------------------

def provision_exe_dir(exe_dir, pack_files, dry_run=False, log=print):
    """Copy pack files into exe_dir (once; stamp file guards repeats)."""
    stamp = os.path.join(exe_dir, PACK_STAMP)
    if os.path.exists(stamp):
        return []
    copied = []
    for src in pack_files:
        if not os.path.isfile(src):
            continue
        dst = os.path.join(exe_dir, os.path.basename(src))
        if not os.path.exists(dst):
            if not dry_run:
                shutil.copy2(src, dst)
            copied.append(dst)
            log("  provision: %s -> %s" % (os.path.basename(src), exe_dir))
    if not dry_run:
        try:
            with open(stamp, "w") as f:
                f.write("pywin7gate pack v1\n")
        except OSError:
            pass
    return copied


# ----------------------------------------------------------------------
# Kx redirect decision
# ----------------------------------------------------------------------

def find_kx_target(missing_dll, missing_func, kx_index):
    """kx_index: {dll_name(lower): set(export lower)} built from the tree's
    Kx*.dll files.  Returns the Kx dll name that exports missing_func, or
    None.  Only sensible when missing_dll is a *system* dll (kernel32 etc).
    """
    target = missing_func.lower()
    for dll in sorted(kx_index):
        if target in kx_index[dll]:
            return dll
    return None


def build_kx_index(tree_root):
    """Exports of every Kx*.dll (+KexDll.dll) in tree_root."""
    idx = {}
    try:
        for fn in os.listdir(tree_root):
            low = fn.lower()
            if low.startswith(("kx", "kexdll")) and low.endswith(".dll"):
                try:
                    pe = pemod.PEFile(os.path.join(tree_root, fn))
                    _i, exp = pe.exports()
                except (pemod.PEError, OSError):
                    continue
                idx[low] = {k.lower() for k in exp}
    except OSError:
        pass
    return idx


# ----------------------------------------------------------------------
# runtime redirect table (load-time in-memory import rewrite)
# ----------------------------------------------------------------------
#
# Mirror of g_Redirects in runtime/PyKexBoot/PyKexBoot.c -- the DLL-name
# substitutions the injected PyKexBoot applies in memory, before the loader
# snaps imports, to every image mapped into an injected process.
# KEEP IN SYNC with PyKexBoot.c (tests/test_win7_tree.py group S checks it).

RUNTIME_REDIRECT_PAIRS = [
    ("ntdll", "kxnt"), ("kernel32", "kxbase"), ("kernelbase", "kxbase"), ("cfgmgr32", "kxbase"),
    ("advapi32", "kxadvapi"), ("user32", "kxuser"), ("shcore", "kxuser"), ("bluetoothapis", "kxuser"),
    ("ole32", "kxcom"), ("combase", "kxcom"), ("msvcrt", "kxcrt"), ("bcrypt", "kxcryp"),
    ("bcryptprimitives", "kxcryp"), ("ncrypt", "kxcryp"), ("secur32", "kxcryp"), ("security", "kxcryp"),
    ("sspicli", "kxcryp"), ("schannel", "kxcryp"), ("d2d1", "kxdx"), ("d3d11", "kxdx"),
    ("d3d12", "kxdx"), ("dcomp", "kxdx"), ("dxgi", "kxdx"), ("mfplat", "kxdx"),
    ("powrprof", "kxmi"), ("userenv", "kxmi"), ("version", "kxmi"), ("wldp", "kxmi"),
    ("wtsapi32", "kxmi"), ("dnsapi", "kxnet"), ("winhttp", "kxnet"), ("ws2_32", "kxnet"),
    ("uiautomationcore", "kxuia"), ("api-ms-win-appmodel-identity", "kxbase"), ("api-ms-win-appmodel-runtime", "kxbase"), ("api-ms-win-core-apiquery", "kxnt"),
    ("api-ms-win-core-atoms", "kxbase"), ("api-ms-win-core-crt", "kxcrt"), ("api-ms-win-core-com", "kxcom"), ("api-ms-win-core-com-midlproxystub", "kxcom"),
    ("api-ms-win-core-com-private", "kxcom"), ("api-ms-win-core-console", "kxbase"), ("api-ms-win-core-datetime", "kxbase"), ("api-ms-win-core-debug", "kxbase"),
    ("api-ms-win-core-delayload", "kxbase"), ("api-ms-win-core-errorhandling", "kxbase"), ("api-ms-win-core-featurestaging", "kxuser"), ("api-ms-win-core-fibers", "kxbase"),
    ("api-ms-win-core-file", "kxbase"), ("api-ms-win-core-handle", "kxbase"), ("api-ms-win-core-heap", "kxbase"), ("api-ms-win-core-heap-obsolete", "kxbase"),
    ("api-ms-win-core-interlocked", "kxbase"), ("api-ms-win-core-io", "kxbase"), ("api-ms-win-core-job", "kxbase"), ("api-ms-win-core-kernel32-legacy", "kxbase"),
    ("api-ms-win-core-largeinteger", "kxbase"), ("api-ms-win-core-libraryloader", "kxbase"), ("api-ms-win-core-localization", "kxbase"), ("api-ms-win-core-localization-ansi", "kxbase"),
    ("api-ms-win-core-localization-obsolete", "kxbase"), ("api-ms-win-core-localregistry", "kxadvapi"), ("api-ms-win-core-marshal", "kxcom"), ("api-ms-win-core-memory", "kxbase"),
    ("api-ms-win-core-namedpipe", "kxbase"), ("api-ms-win-core-namedpipe-ansi", "kxbase"), ("api-ms-win-core-normalization", "normaliz"), ("api-ms-win-core-path", "kxbase"),
    ("api-ms-win-core-privateprofile", "kxbase"), ("api-ms-win-core-processenvironment", "kxbase"), ("api-ms-win-core-processsnapshot", "kxbase"), ("api-ms-win-core-processthreads", "kxbase"),
    ("api-ms-win-core-processtopology", "kxbase"), ("api-ms-win-core-processtopology-obsolete", "kxbase"), ("api-ms-win-core-profile", "kxbase"), ("api-ms-win-core-psapi", "kxbase"),
    ("api-ms-win-core-quirks", "kxbase"), ("api-ms-win-core-realtime", "kxbase"), ("api-ms-win-core-registry", "kxadvapi"), ("api-ms-win-core-registry-private", "kxadvapi"),
    ("api-ms-win-core-registryuserspecific", "kxadvapi"), ("api-ms-win-core-rtlsupport", "kxnt"), ("api-ms-win-core-shlwapi-legacy", "kxuser"), ("api-ms-win-core-shlwapi-obsolete", "kxuser"),
    ("api-ms-win-core-sidebyside", "kxbase"), ("api-ms-win-core-string", "kxbase"), ("api-ms-win-core-string-obsolete", "kxbase"), ("api-ms-win-core-stringansi", "kxbase"),
    ("api-ms-win-core-synch", "kxbase"), ("api-ms-win-core-synch-ansi", "kxbase"), ("api-ms-win-core-sysinfo", "kxbase"), ("api-ms-win-core-systemtopology", "kxbase"),
    ("api-ms-win-core-threadpool", "kxbase"), ("api-ms-win-core-threadpool-legacy", "kxbase"), ("api-ms-win-core-threadpool-private", "kxbase"), ("api-ms-win-core-toolhelp", "kxbase"),
    ("api-ms-win-core-timezone", "kxbase"), ("api-ms-win-core-url", "kxuser"), ("api-ms-win-core-util", "kxbase"), ("api-ms-win-core-version", "version"),
    ("api-ms-win-core-versionansi", "version"), ("api-ms-win-core-windowserrorreporting", "kxbase"), ("api-ms-win-core-winrt", "kxcom"), ("api-ms-win-core-winrt-error", "kxcom"),
    ("api-ms-win-core-winrt-errorprivate", "kxcom"), ("api-ms-win-core-winrt-registration", "kxcom"), ("api-ms-win-core-winrt-robuffer", "kxcom"), ("api-ms-win-core-winrt-roparameterizediid", "kxcom"),
    ("api-ms-win-core-winrt-string", "kxcom"), ("api-ms-win-core-wow64", "kxbase"), ("api-ms-win-core-xstate", "kxnt"), ("api-ms-win-devices-config", "kxbase"),
    ("api-ms-win-devices-query", "kxbase"), ("api-ms-win-devices-swdevice", "kxbase"), ("api-ms-win-downlevel-kernel32", "kxbase"), ("api-ms-win-downlevel-ole32", "kxcom"),
    ("api-ms-win-downlevel-shell32", "kxuser"), ("api-ms-win-eventing-classicprovider", "kxadvapi"), ("api-ms-win-eventing-consumer", "kxadvapi"), ("api-ms-win-eventing-controller", "kxadvapi"),
    ("api-ms-win-eventing-legacy", "kxadvapi"), ("api-ms-win-eventing-provider", "kxadvapi"), ("api-ms-win-eventlog-legacy", "kxadvapi"), ("api-ms-win-kernel32-package-current", "kxbase"),
    ("api-ms-win-mm-time", "winmm"), ("api-ms-win-ntuser-sysparams", "kxuser"), ("api-ms-win-power-base", "kxmi"), ("api-ms-win-power-setting", "kxmi"),
    ("api-ms-win-security-base", "kxbase"), ("api-ms-win-security-base-ansi", "kxadvapi"), ("api-ms-win-security-cryptoapi", "cryptsp"), ("api-ms-win-security-lsalookup", "kxadvapi"),
    ("api-ms-win-security-lsalookup-ansi", "kxadvapi"), ("api-ms-win-security-sddl", "sechost"), ("api-ms-win-security-sddl-ansi", "kxadvapi"), ("api-ms-win-security-systemfunctions", "kxadvapi"),
    ("api-ms-win-service-core", "sechost"), ("api-ms-win-service-core-ansi", "kxadvapi"), ("api-ms-win-service-management", "kxadvapi"), ("api-ms-win-service-private", "sechost"),
    ("api-ms-win-service-winsvc", "kxadvapi"), ("api-ms-win-shcore-comhelpers", "kxuser"), ("api-ms-win-shcore-obsolete", "kxuser"), ("api-ms-win-shcore-path", "kxuser"),
    ("api-ms-win-shcore-registry", "kxuser"), ("api-ms-win-shcore-scaling", "kxuser"), ("api-ms-win-shcore-stream", "kxuser"), ("api-ms-win-shcore-stream-winrt", "kxuser"),
    ("api-ms-win-shcore-sysinfo", "kxuser"), ("api-ms-win-shcore-taskpool", "kxuser"), ("api-ms-win-shcore-thread", "kxuser"), ("api-ms-win-shcore-unicodeansi", "kxuser"),
    ("api-ms-win-shell-namespace", "kxuser"), ("ext-ms-win-branding-winbrand", "winbrand"), ("ext-ms-win-gdi-dc", "gdi32"), ("ext-ms-win-gdi-dc-create", "gdi32"),
    ("ext-ms-win-gdi-draw", "gdi32"), ("ext-ms-win-gdi-font", "gdi32"), ("ext-ms-win-gdi-path", "gdi32"), ("ext-ms-win-ntuser-draw", "kxuser"),
    ("ext-ms-win-ntuser-rotationmanager", "kxuser"), ("ext-ms-win-ntuser-windowclass", "kxuser"), ("ext-ms-win-rtcore-gdi-devcaps", "gdi32"), ("ext-ms-win-rtcore-gdi-object", "gdi32"),
    ("ext-ms-win-rtcore-gdi-rgn", "gdi32"), ("ext-ms-win-rtcore-ntuser-sysparams", "kxuser"), ("ext-ms-win-uiacore", "kxuia"),
]

RUNTIME_REDIRECTS = {}


def normalize_dll_name(name):
    """Same normalization PyKexBoot applies: lowercase, strip '.dll',
    and for api-/ext- set names strip the 7-char '-lX-Y-Z' suffix."""
    low = name.lower()
    if low.endswith(".dll"):
        low = low[:-4]
    if low.startswith(("api-", "ext-")) and len(low) > 7 and low[-7] == "-":
        low = low[:-7]
    return low


def find_runtime_redirect(dll_name):
    """Return the DLL the runtime layer would rewrite dll_name to
    (e.g. 'kernel32.dll' -> 'kxbase.dll'), or None."""
    target = RUNTIME_REDIRECTS.get(normalize_dll_name(dll_name))
    return (target + ".dll") if target else None


def _init_redirects():
    for src, dst in RUNTIME_REDIRECT_PAIRS:
        RUNTIME_REDIRECTS[src] = dst


_init_redirects()

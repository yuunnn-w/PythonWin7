# pywin7gate bootstrap -- installed into Lib\ by build_pack.py.
# Keeps startup cheap and bulletproof: any failure here must not break
# the interpreter.
try:
    import os as _os
    if _os.environ.get("PYW7GATE") == "1":
        import pywin7gate.hook as _pyw7hook
        _pyw7hook.install()
except Exception:
    pass

# Relocation safety net.  PyKexExe-converted Scripts shims find their
# interpreter relative to their own path, so a moved/copied tree works with
# zero commands.  This pass only repairs LEGACY distlib shims (absolute-path
# shebangs) that may remain from packages installed outside the gate: when
# the tree root no longer matches the stamp file Scripts\.pyw7loc, shebangs
# are rewritten to the current root -- silently, at most once per move.
try:
    import contextlib as _cl
    import io as _io
    import os as _os
    import sys as _sys
    _root = _os.path.normpath(getattr(_sys, "base_prefix", _sys.prefix))
    _stamp = _os.path.join(_root, "Scripts", ".pyw7loc")
    try:
        with open(_stamp, "r", encoding="utf-8") as _f:
            _known = _f.read().strip()
    except OSError:
        _known = None
    if _known is None:
        # first start of a packed tree: record the current root, trust the
        # pack-time state
        try:
            with open(_stamp, "w", encoding="utf-8") as _f:
                _f.write(_root)
        except OSError:
            pass
    elif _os.path.normcase(_known) != _os.path.normcase(_root):
        from pywin7gate.__main__ import _cmd_relocate
        with _cl.redirect_stdout(_io.StringIO()):
            _rc = _cmd_relocate(_root)
        if _rc == 0:
            try:
                with open(_stamp, "w", encoding="utf-8") as _f:
                    _f.write(_root)
            except OSError:
                pass
except Exception:
    pass

# ---------------------------------------------------------------------------
# Environment isolation (hermetic tree).  A packed tree must behave as a
# self-contained environment even on machines that have their own Python or
# Anaconda installed:
#   * PATH entries that belong to a FOREIGN interpreter (a dir hosting
#     python.exe/pythonw.exe, the Scripts sibling of such a dir, anything
#     conda-flavoured) are dropped, and the tree's own root/Scripts go in
#     front.  which()/CreateProcess lookups (jupyter_core's subcommand
#     dispatch being the prime example) can then never resolve to foreign
#     shims, and foreign DLL directories stay out of the loader search path.
#   * sys.path entries that live inside a foreign installation (typically
#     injected by a host PYTHONPATH) are dropped.  The C launchers already
#     clear PYTHONHOME/PYTHONPATH before the interpreter boots; this is the
#     in-process net for payload exes started directly.
#   * the shared per-user site (%APPDATA%\Python, common to every install of
#     the same Python version) is removed; activation-identity variables of
#     other environments (VIRTUAL_ENV, CONDA_*) are cleared so subprocesses
#     never inherit them.
# Opt out with PYW7ISOLATE=0.  Cost per start: a few dozen attribute probes.
try:
    import os as _os
    import sys as _sys

    if _os.name == "nt" and _os.environ.get("PYW7ISOLATE") != "0":
        def _pyw7_norm(p):
            return _os.path.normcase(_os.path.normpath(p))

        _exe_dir = _os.path.dirname(_sys.executable) if _sys.executable \
            else ""
        _own_roots = set()
        for _p in (getattr(_sys, "base_prefix", ""), _sys.prefix,
                   _sys.exec_prefix):
            if _p:
                _own_roots.add(_pyw7_norm(_p))
        _own = set(_own_roots)
        for _p in list(_own_roots) + ([_exe_dir] if _exe_dir else []):
            _own.add(_pyw7_norm(_os.path.join(_p, "Scripts")))
        if _exe_dir:
            _own.add(_pyw7_norm(_exe_dir))

        # %LOCALAPPDATA%\Microsoft\WindowsApps hosts Store execution-alias
        # stubs (python.exe among them); it is a general app-alias dir, not
        # an installed interpreter -- never classified as foreign.
        _la = _os.environ.get("LOCALAPPDATA", "")
        _wapps = _pyw7_norm(_os.path.join(
            _la, "Microsoft", "WindowsApps")) if _la else None

        def _pyw7_is_own(p):
            _np = _pyw7_norm(p)
            if _np in _own:
                return True
            for _r in _own_roots:
                if _np == _r or _np.startswith(_r + "\\"):
                    return True
            return False

        def _pyw7_has_python(d):
            return _os.path.isfile(_os.path.join(d, "python.exe")) or \
                _os.path.isfile(_os.path.join(d, "pythonw.exe"))

        def _pyw7_foreign_python_dir(d):
            try:
                _np = _pyw7_norm(d)
                if _pyw7_is_own(d) or (_wapps and _np == _wapps):
                    return False
                if "conda" in _np or "\\envs\\" in _np + "\\":
                    return True
                if _pyw7_has_python(d):
                    return True
                if _os.path.basename(d.rstrip("\\/")).lower() == "scripts":
                    _parent = _os.path.dirname(d.rstrip("\\/"))
                    if "conda" in _pyw7_norm(_parent) or \
                            _pyw7_has_python(_parent):
                        return True
            except Exception:
                pass
            return False

        _path = _os.environ.get("PATH", "")
        if _path:
            _kept = []
            _seen = set()
            for _d in _path.split(_os.pathsep):
                if not _d:
                    continue
                _nd = _pyw7_norm(_d)
                if _nd in _own or _nd in _seen:
                    continue
                _seen.add(_nd)
                if _pyw7_foreign_python_dir(_d):
                    continue
                _kept.append(_d)
            _front = []
            for _d in (_exe_dir,
                       _os.path.join(getattr(_sys, "base_prefix",
                                             _sys.prefix), "Scripts"),
                       getattr(_sys, "base_prefix", _sys.prefix)):
                if _d:
                    _nd = _pyw7_norm(_d)
                    if _nd not in _seen and _os.path.isdir(_d):
                        _seen.add(_nd)
                        _front.append(_d)
            _os.environ["PATH"] = _os.pathsep.join(_front + _kept)

        # sys.path scrub: drop entries that live inside a foreign install
        # (host PYTHONPATH fall-out).  The script dir and plain code dirs
        # are never touched.
        def _pyw7_foreign_syspath(p):
            try:
                if not p or _pyw7_is_own(p):
                    return False
                _np = _pyw7_norm(p)
                if _wapps and _np == _wapps:
                    return False
                if "conda" in _np or "\\envs\\" in _np + "\\":
                    return True
                _parts = _np.replace("/", "\\").split("\\")
                if _parts[-2:] == ["lib", "site-packages"]:
                    if _pyw7_has_python(_os.path.dirname(
                            _os.path.dirname(p))):
                        return True
                elif _parts[-1:] == ["lib"]:
                    if _pyw7_has_python(_os.path.dirname(p)):
                        return True
                if _pyw7_has_python(p):
                    return True
            except Exception:
                pass
            return False

        _sys.path[:] = [_p for _p in _sys.path
                        if not _pyw7_foreign_syspath(_p)]

        # the per-user site is shared with every other install of this
        # Python version on the machine -- exclude it unless explicitly
        # re-enabled with PYTHONNOUSERSITE=0
        if _os.environ.get("PYTHONNOUSERSITE") != "0":
            _os.environ.setdefault("PYTHONNOUSERSITE", "1")
            try:
                import site as _site
                _site.ENABLE_USER_SITE = False
                _us = _pyw7_norm(_site.getusersitepackages())
                _sys.path[:] = [_p for _p in _sys.path
                                if not _p or _pyw7_norm(_p) != _us]
            except Exception:
                pass

        # activation identity of OTHER environments must not leak into
        # subprocesses launched from this tree
        for _v in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                   "VIRTUAL_ENV", "VIRTUAL_ENV_PROMPT",
                   "CONDA_PREFIX", "CONDA_PREFIX_1", "CONDA_DEFAULT_ENV",
                   "CONDA_EXE", "CONDA_PYTHON_EXE", "CONDA_SHLVL",
                   "CONDA_BAT", "_CE_CONDA", "_CE_M"):
            _os.environ.pop(_v, None)
except Exception:
    pass

# pywin7gate bootstrap -- installed into Lib\ by build_pack.py.
# Keeps startup cheap and bulletproof: any failure here must not break
# the interpreter.
try:
    import os as _os
    if _os.environ.get("PYW7GATE", "1") != "0":
        import pywin7gate.hook as _pyw7hook
        _pyw7hook.install()
except Exception:
    pass

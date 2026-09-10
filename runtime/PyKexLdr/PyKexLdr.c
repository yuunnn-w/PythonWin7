// ============================================================================
// PyKexLdr.c -- bootstrap launcher for Win7-compatible Python trees.
//
// This executable takes the place of the original entry-point exes
// (python.exe / pythonw.exe / pythonX.Yt.exe / pythonwX.Yt.exe, which the
// packaging step renamed to python3XX.exe / pythonw3XX.exe / ...).  It:
//
//   1. Resolves the real interpreter exe (generic, works for any Python
//      3.9+ tree):
//        a. next to itself: scan for python3*.dll (excluding the python3.dll
//           stable-ABI shim), derive the version stem ("39", "313", "314t"),
//           real exe = "python[w]" + stem + ".exe";
//        b. if absent (this launcher inside a copied venv's Scripts): read
//           ..\pyvenv.cfg, take its "home" directory, and resolve the real
//           exe there.  In this case __PYVENV_LAUNCHER__=<own path> is set
//           for the child so getpath.py (3.11+) still detects the venv.
//        (On 3.13+ venv copies its own venvlauncher.exe redirector into
//        Scripts; that redirector imports api-ms-win-core-path-l1-1-0.dll
//        and therefore cannot start on a bare Win7, so build_pack replaces
//        it with this launcher -- the fallback above then serves every
//        Python version uniformly.)
//   2. Creates the real interpreter process, initially suspended.
//   3. Injects KexDll.dll and PyKexBoot.dll (found next to the REAL exe)
//      into the child via VirtualAllocEx + WriteProcessMemory +
//      CreateRemoteThread(LoadLibraryW), in that order.
//      KexDll provides the VxKex primitives PyKexBoot uses (inline hook
//      engine, direct-syscall wrappers, CPIW bypass); PyKexBoot propagates
//      the pair into every grandchild process and hooks NtMapViewOfSection
//      for load-time import rewriting.
//   4. Resumes the main thread, waits for the child, and forwards its
//      exit code.
//
// Command line handling: GetCommandLineW() is passed through VERBATIM
// (ApplicationName selects the real image).  This is required for venv
// compatibility: the venv redirector's argv[0] carries the venv path that
// getpath.py uses to detect the virtual environment.
//
// Hermetic-tree policy: before CreateProcess the launcher strips
// PYTHONHOME/PYTHONPATH/PYTHONSTARTUP from its environment and sets
// PYTHONNOUSERSITE=1, so a host-level Python/Anaconda configuration can
// never hijack the payload's stdlib or site-packages resolution.  The
// in-process half (PATH and sys.path sanitizing, conda/venv marker scrub)
// lives in the tree's sitecustomize.py.
//
// Failure policy: if the payload DLLs are missing or injection fails, the
// child still runs (the static file layer does not depend on this launcher).
// A diagnostic is written to stderr.
//
// Build: CRT-free (build.bat: /NODEFAULTLIB /ENTRY), imports kernel32 only.
// Two variants from this one source file:
//   console  (default)         -> python.exe,  pythonX.Yt.exe
//   GUI      (/DPYW7_GUI)      -> pythonw.exe, pythonwX.Yt.exe
// ============================================================================

#include <windows.h>

// ---- our own memset/memcpy so the compiler's intrinsics link CRT-free ------
#pragma function(memset)
#pragma function(memcpy)
void *memset(void *dst, int val, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *) dst;
    while (n--) *p++ = (unsigned char) val;
    return dst;
}
void *memcpy(void *dst, const void *src, size_t n)
{
    volatile unsigned char *d = (volatile unsigned char *) dst;
    const volatile unsigned char *s = (const volatile unsigned char *) src;
    while (n--) *d++ = *s++;
    return dst;
}

// ----------------------------------------------------------------------------
// small local utilities (no CRT)
// ----------------------------------------------------------------------------
static int PykexStrLenW(const WCHAR *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void PykexStrCpyW(WCHAR *dst, const WCHAR *src)
{
    while ((*dst++ = *src++)) {}
}

static WCHAR PykexLowerW(WCHAR c)
{
    if (c >= L'A' && c <= L'Z') c += 32;
    return c;
}

static BOOL PykexStartsWithIW(const WCHAR *s, const WCHAR *prefix)
{
    while (*prefix) {
        if (PykexLowerW(*s) != PykexLowerW(*prefix)) return FALSE;
        s++; prefix++;
    }
    return TRUE;
}

static BOOL PykexEndsWithIW(const WCHAR *s, const WCHAR *suffix)
{
    int ls = PykexStrLenW(s), lf = PykexStrLenW(suffix);
    if (lf > ls) return FALSE;
    s += ls - lf;
    while (*suffix) {
        if (PykexLowerW(*s) != PykexLowerW(*suffix)) return FALSE;
        s++; suffix++;
    }
    return TRUE;
}

// directory part of path (keeps trailing backslash); out == in is allowed
static void PykexDirNameW(WCHAR *path)
{
    int len = PykexStrLenW(path);
    while (len > 0 && path[len - 1] != L'\\' && path[len - 1] != L'/') len--;
    path[len] = 0;
}

static void PykexLog(const char *msg)
{
    DWORD written;
    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    if (hErr && hErr != INVALID_HANDLE_VALUE) {
        DWORD n = 0;
        while (msg[n]) n++;
        WriteFile(hErr, msg, n, &written, NULL);
    }
}

// ----------------------------------------------------------------------------
// version-stem discovery: scan a directory for python3*.dll
//   python39.dll   -> stem "39"   (regular)
//   python314.dll  -> stem "314"  (regular)
//   python314t.dll -> stem "314t" (free-threaded)
//   python3.dll    -> skipped (stable-ABI shim)
// wantT selects the free-threaded stem when available.
// Returns TRUE and fills outStem (e.g. L"314") on success.
// ----------------------------------------------------------------------------
static BOOL PykexFindVersionStem(const WCHAR *dir, BOOL wantT,
                                 WCHAR *outStem, DWORD outCch)
{
    WCHAR pattern[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    WCHAR stemNonT[16];
    WCHAR stemT[16];
    int i;

    stemNonT[0] = 0;
    stemT[0] = 0;

    PykexStrCpyW(pattern, dir);
    PykexStrCpyW(pattern + PykexStrLenW(pattern), L"python3*.dll");
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    do {
        const WCHAR *name = fd.cFileName;
        WCHAR stem[16];
        int len, slen;
        BOOL isT;
        BOOL hasDigit;

        if (!PykexStartsWithIW(name, L"python3") ||
            !PykexEndsWithIW(name, L".dll"))
            continue;
        len = PykexStrLenW(name);
        // stem = middle part between "python" and ".dll", e.g. "314t"
        slen = len - 6 - 4;
        if (slen < 2 || slen > 8)
            continue;
        for (i = 0; i < slen; i++)
            stem[i] = name[6 + i];
        stem[slen] = 0;
        if (PykexLowerW(stem[0]) != L'3')
            continue;
        // remainder after the leading '3' must be digits with an optional
        // trailing t, and must contain at least one digit -- this rejects
        // the stable-ABI shims python3.dll ("3") and python3t.dll ("3t")
        hasDigit = FALSE;
        for (i = 1; i < slen; i++) {
            WCHAR c = PykexLowerW(stem[i]);
            if (c >= L'0' && c <= L'9') {
                hasDigit = TRUE;
                continue;
            }
            if (!(c == L't' && i == slen - 1))
                break;
        }
        if (i < slen || !hasDigit)
            continue;
        isT = (PykexLowerW(stem[slen - 1]) == L't');
        if (isT) {
            if (!stemT[0]) PykexStrCpyW(stemT, stem);
        } else {
            if (!stemNonT[0]) PykexStrCpyW(stemNonT, stem);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    {
        const WCHAR *pick = NULL;
        if (wantT && stemT[0])
            pick = stemT;
        else if (stemNonT[0])
            pick = stemNonT;
        else if (stemT[0])
            pick = stemT;
        if (!pick)
            return FALSE;
        if ((DWORD) (PykexStrLenW(pick) + 1) > outCch)
            return FALSE;
        PykexStrCpyW(outStem, pick);
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// real-exe resolution
// ----------------------------------------------------------------------------
static BOOL PykexFileExists(const WCHAR *path)
{
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

// build "<dir>python[w]<stem>.exe"
static void PykexBuildRealExeName(const WCHAR *dir, BOOL gui,
                                  const WCHAR *stem, WCHAR *out, DWORD outCch)
{
    WCHAR tmp[MAX_PATH];
    PykexStrCpyW(tmp, dir);
    if (gui)
        PykexStrCpyW(tmp + PykexStrLenW(tmp), L"pythonw");
    else
        PykexStrCpyW(tmp + PykexStrLenW(tmp), L"python");
    PykexStrCpyW(tmp + PykexStrLenW(tmp), stem);
    PykexStrCpyW(tmp + PykexStrLenW(tmp), L".exe");
    if ((DWORD) (PykexStrLenW(tmp) + 1) <= outCch)
        PykexStrCpyW(out, tmp);
    else
        out[0] = 0;
}

// parse "home = <dir>" out of a pyvenv.cfg file; returns TRUE on success.
// venv writes pyvenv.cfg as UTF-8; decode the home value as UTF-8 first and
// fall back to the ANSI codepage (naive byte-widening breaks non-ASCII
// install paths).
static BOOL PykexReadVenvHome(const WCHAR *cfgPath, WCHAR *outHome,
                              DWORD outCch)
{
    HANDLE h;
    char buf[2048];
    DWORD got = 0, i;
    BOOL ok = FALSE;

    h = CreateFileW(cfgPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!ReadFile(h, buf, sizeof(buf) - 1, &got, NULL))
        got = 0;
    CloseHandle(h);
    buf[got] = 0;

    for (i = 0; i < got && !ok; i++) {
        // line start: match "home" case-insensitively
        if ((i == 0 || buf[i - 1] == '\n') &&
            (buf[i] == 'h' || buf[i] == 'H') &&
            (buf[i + 1] == 'o' || buf[i + 1] == 'O') &&
            (buf[i + 2] == 'm' || buf[i + 2] == 'M') &&
            (buf[i + 3] == 'e' || buf[i + 3] == 'E')) {
            DWORD j = i + 4;
            char line[1024];
            DWORD k = 0, len;
            int n;
            while (buf[j] == ' ' || buf[j] == '=') j++;
            while (buf[j] && buf[j] != '\r' && buf[j] != '\n' &&
                   k + 1 < sizeof(line))
                line[k++] = buf[j++];
            while (k > 0 && line[k - 1] == ' ') k--;   // rtrim
            if (!k)
                continue;
            n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                    line, (int) k, outHome, (int) outCch - 1);
            if (n <= 0)
                n = MultiByteToWideChar(CP_ACP, 0, line, (int) k,
                                        outHome, (int) outCch - 1);
            if (n <= 0)
                return FALSE;
            outHome[n] = 0;
            len = (DWORD) n;
            ok = len > 0;
        }
    }
    if (ok && outHome[PykexStrLenW(outHome) - 1] != L'\\')
        PykexStrCpyW(outHome + PykexStrLenW(outHome), L"\\");
    return ok;
}

// Resolve the real interpreter exe.  Fills realExe and payloadDir (the
// directory the payload DLLs live in = directory of the real exe).
// Sets *inVenv when the venv fallback was used.
static BOOL PykexResolveRealExe(const WCHAR *selfPath, BOOL gui, BOOL wantT,
                                WCHAR *realExe, DWORD realExeCch,
                                WCHAR *payloadDir, DWORD payloadDirCch,
                                BOOL *inVenv)
{
    WCHAR dir[MAX_PATH];
    WCHAR stem[16];

    *inVenv = FALSE;
    PykexStrCpyW(dir, selfPath);
    PykexDirNameW(dir);

    if (PykexFindVersionStem(dir, wantT, stem, 16)) {
        PykexBuildRealExeName(dir, gui, stem, realExe, realExeCch);
        if (realExe[0] && PykexFileExists(realExe)) {
            PykexStrCpyW(payloadDir, dir);
            return TRUE;
        }
    }

    // venv fallback: we are a copied launcher inside venv\Scripts (<=3.12)
    {
        WCHAR parent[MAX_PATH];
        WCHAR cfg[MAX_PATH];
        WCHAR home[MAX_PATH];
        int len;

        PykexStrCpyW(parent, dir);
        len = PykexStrLenW(parent);
        if (len > 0) parent[len - 1] = 0;      // strip trailing backslash
        PykexDirNameW(parent);                  // one level up = venv root
        PykexStrCpyW(cfg, parent);
        PykexStrCpyW(cfg + PykexStrLenW(cfg), L"pyvenv.cfg");
        if (PykexFileExists(cfg) &&
            PykexReadVenvHome(cfg, home, MAX_PATH) &&
            PykexFindVersionStem(home, wantT, stem, 16)) {
            PykexBuildRealExeName(home, gui, stem, realExe, realExeCch);
            if (realExe[0] && PykexFileExists(realExe)) {
                PykexStrCpyW(payloadDir, home);
                *inVenv = TRUE;
                return TRUE;
            }
        }
    }

    realExe[0] = 0;
    return FALSE;
}

// ----------------------------------------------------------------------------
// remote LoadLibraryW injection into a suspended process
// ----------------------------------------------------------------------------
static BOOL PykexInjectDll(HANDLE hProcess, const WCHAR *dllPath)
{
    SIZE_T bytes;
    SIZE_T size;
    LPVOID remote;
    HANDLE hThread;
    DWORD  threadId;
    DWORD  exitCode = 0;
    static HMODULE hKernel32 = NULL;
    static LPVOID  pLoadLibraryW = NULL;

    if (!hKernel32) {
        hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32)
            pLoadLibraryW = (LPVOID) GetProcAddress(hKernel32, "LoadLibraryW");
        if (!pLoadLibraryW)
            return FALSE;
    }

    size = (SIZE_T) (PykexStrLenW(dllPath) + 1) * sizeof(WCHAR);
    remote = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);
    if (!remote)
        return FALSE;
    if (!WriteProcessMemory(hProcess, remote, dllPath, size, &bytes) ||
        bytes != size) {
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return FALSE;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE) pLoadLibraryW,
                                 remote, 0, &threadId);
    if (!hThread) {
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return FALSE;
    }
    WaitForSingleObject(hThread, 10000);
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);

    // LoadLibraryW returns the module handle (NULL on failure)
    return exitCode != 0;
}

// ----------------------------------------------------------------------------
// main logic
// ----------------------------------------------------------------------------
static DWORD PykexMain(void)
{
    WCHAR selfPath[MAX_PATH];
    WCHAR realExe[MAX_PATH];
    WCHAR payloadDir[MAX_PATH];
    WCHAR kexDll[MAX_PATH];
    WCHAR bootDll[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD flags = CREATE_SUSPENDED;
    DWORD exitCode = 1;
    BOOL injected = FALSE;
    BOOL inVenv = FALSE;
    BOOL wantT = FALSE;
    BOOL gui = FALSE;

    GetModuleFileNameW(NULL, selfPath, MAX_PATH);

    // flavor from our own file name: a trailing 't' before .exe selects the
    // free-threaded variant (python3.14t.exe); GUI/console comes from the
    // build variant (PYW7_GUI)
    {
        const WCHAR *base = selfPath;
        const WCHAR *p;
        WCHAR nameOnly[64];
        int i = 0;
        for (p = selfPath; *p; p++)
            if (*p == L'\\' || *p == L'/') base = p + 1;
        while (base[i] && i < 63) { nameOnly[i] = base[i]; i++; }
        nameOnly[i] = 0;
#ifdef PYW7_GUI
        gui = TRUE;
#else
        gui = FALSE;
#endif
        wantT = PykexEndsWithIW(nameOnly, L"t.exe");
    }

    if (!PykexResolveRealExe(selfPath, gui, wantT,
                             realExe, MAX_PATH,
                             payloadDir, MAX_PATH, &inVenv)) {
        PykexLog("PyKexLdr: real interpreter not found "
                 "(looked next to launcher, then ..\\pyvenv.cfg home)\r\n");
        return 9009;
    }

    // inside a copied venv, tell getpath.py which launcher was used so the
    // venv is still detected even though the process image is the base exe
    if (inVenv)
        SetEnvironmentVariableW(L"__PYVENV_LAUNCHER__", selfPath);

    // Hermetic-tree policy, boot-time half: a host-level PYTHONHOME or
    // PYTHONPATH (left behind by another Python / an Anaconda install) would
    // hijack the payload's stdlib and site-packages resolution BEFORE any
    // Python-side guard could run, so clear them here where the environment
    // block is still ours to fix.  PYTHONNOUSERSITE keeps the per-user site
    // (%APPDATA%\Python, shared across installs of the same version) out of
    // sys.path for the whole process tree.  sitecustomize finishes the
    // in-process half (PATH + sys.path + conda/venv marker scrub).
    SetEnvironmentVariableW(L"PYTHONHOME", NULL);
    SetEnvironmentVariableW(L"PYTHONPATH", NULL);
    SetEnvironmentVariableW(L"PYTHONSTARTUP", NULL);
    SetEnvironmentVariableW(L"PYTHONNOUSERSITE", L"1");

    // payload paths live next to the real exe
    PykexStrCpyW(kexDll, payloadDir);
    PykexStrCpyW(kexDll + PykexStrLenW(kexDll), L"KexDll.dll");
    PykexStrCpyW(bootDll, payloadDir);
    PykexStrCpyW(bootDll + PykexStrLenW(bootDll), L"PyKexBoot.dll");

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    GetStartupInfoW(&si);
    memset(&pi, 0, sizeof(pi));

    // The command line is forwarded untouched: argv[0] semantics are load
    // bearing for venv detection (getpath.py).
    if (!CreateProcessW(realExe, GetCommandLineW(), NULL, NULL, TRUE,
                        flags, NULL, NULL, &si, &pi)) {
        PykexLog("PyKexLdr: CreateProcessW failed\r\n");
        return 9009;
    }

    // Injection is best-effort: the statically patched tree runs without it.
    if (GetFileAttributesW(kexDll) != INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesW(bootDll) != INVALID_FILE_ATTRIBUTES) {
        injected = PykexInjectDll(pi.hProcess, kexDll);
        if (injected)
            injected = PykexInjectDll(pi.hProcess, bootDll);
        if (!injected)
            PykexLog("PyKexLdr: payload injection failed; "
                     "continuing without the runtime layer\r\n");
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    return exitCode;
}

// ----------------------------------------------------------------------------
// CRT-free entry points
// ----------------------------------------------------------------------------
#ifdef PYW7_GUI
void WINAPI PykexEntryPoint(void)
#else
void PykexEntryPoint(void)
#endif
{
#ifndef PYW7_GUI
    // Do not let Ctrl+C/Ctrl+Break kill the launcher before the child:
    // the child shares the console and receives the event itself.
    SetConsoleCtrlHandler(NULL, TRUE);
#endif
    ExitProcess(PykexMain());
}

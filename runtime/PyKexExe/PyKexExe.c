// ============================================================================
// PyKexExe.c -- relocatable stub for console-script exe shims (Scripts\*.exe).
//
// Stock pip shims are distlib launchers: [native stub]["#!C:\abs\python.exe"]
// [zip with __main__.py].  The embedded ABSOLUTE interpreter path is the one
// thing that breaks when a packed Python tree is moved, copied or renamed.
//
// build_pack / `python -m pywin7gate shims` rewrites every python-script shim
// in a tree's Scripts directory to:
//
//     [PyKexExe stub]["#!pyw7-relocatable" [args] CRLF][original zip payload]
//
// This stub replaces the native prefix.  It imports kernel32 only, so it runs
// on a bare Win7 SP1, and it contains NO path of any kind.  At runtime it:
//
//   1. locates the interpreter relative to ITSELF:
//        a. <own dir>\python[w].exe   -- shim inside a venv's Scripts (the
//           venv python.exe/pythonw.exe sits next to every script shim);
//        b. <own dir>\..\python[w].exe -- shim inside <tree>\Scripts (the
//           interpreter, stock or PyKexLdr, lives in the tree root);
//   2. reads its own file, finds the "#!pyw7-relocatable" marker line and
//      takes any interpreter arguments stored after it (e.g. "-E");
//   3. relaunches as  "<python>" [args] "<own path>" <original args...>.
//      CPython executes the shim file itself as a zipapp (the zip payload is
//      located through the end-of-central-directory record, so the native
//      prefix -- of any size -- is simply skipped);
//   4. waits for the child and forwards its exit code.
//
// It also enforces the tree's hermetic policy before the launch: host-level
// PYTHONHOME/PYTHONPATH/PYTHONSTARTUP are removed and PYTHONNOUSERSITE=1 is
// set, so a foreign Python on the machine (e.g. Anaconda) can never steer
// stdlib/site-packages resolution of the tree's interpreter.
//
// Because the interpreter is found relative to the shim's own location, the
// packed tree works from ANY directory with ZERO commands after unpacking.
// The marker line makes the conversion self-describing: tools detect it and
// skip (pywin7gate relocate) or report it.
//
// Non-python exes in Scripts (real binaries such as ruff.exe) are never
// converted -- the converter requires a zip payload whose __main__.py (or
// inline shebang) points at python*.exe.
//
// Build: CRT-free (build.bat: /NODEFAULTLIB /ENTRY), imports kernel32 only.
// Two variants from this one source file:
//   console  (default)    -> PyKexExe.exe   (subsystem CONSOLE)
//   GUI      (/DPYW7_GUI) -> PyKexExeW.exe  (subsystem WINDOWS, uses pythonw)
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

// directory part of path (keeps trailing backslash); in-place
static void PykexDirNameW(WCHAR *path)
{
    int len = PykexStrLenW(path);
    while (len > 0 && path[len - 1] != L'\\' && path[len - 1] != L'/') len--;
    path[len] = 0;
}

static BOOL PykexFileExists(const WCHAR *path)
{
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

// ----------------------------------------------------------------------------
// interpreter resolution relative to our own location
// ----------------------------------------------------------------------------
static BOOL PykexResolvePython(const WCHAR *selfPath, BOOL gui,
                               WCHAR *out, DWORD outCch)
{
    WCHAR dir[MAX_PATH];
    const WCHAR *name = gui ? L"pythonw.exe" : L"python.exe";
    int len;

    PykexStrCpyW(dir, selfPath);
    PykexDirNameW(dir);                        // "<...>\Scripts\"

    // 1. next to ourselves: venv\Scripts\python.exe
    if (PykexStrLenW(dir) + PykexStrLenW(name) + 1 <= (int) outCch) {
        PykexStrCpyW(out, dir);
        PykexStrCpyW(out + PykexStrLenW(out), name);
        if (PykexFileExists(out))
            return TRUE;
    }

    // 2. one level up: <tree>\python.exe
    len = PykexStrLenW(dir);
    if (len > 0)
        dir[len - 1] = 0;                      // strip trailing backslash
    PykexDirNameW(dir);                        // parent, trailing '\' kept
    if (PykexStrLenW(dir) + PykexStrLenW(name) + 1 <= (int) outCch) {
        PykexStrCpyW(out, dir);
        PykexStrCpyW(out + PykexStrLenW(out), name);
        if (PykexFileExists(out))
            return TRUE;
    }

    out[0] = 0;
    return FALSE;
}

// ----------------------------------------------------------------------------
// marker line: "#!pyw7-relocatable" [args] -- read extra interpreter args
// out of our own file (the marker sits between this stub and the zip).
// ----------------------------------------------------------------------------
#define PYKEX_MARKER      "#!pyw7-relocatable"
#define PYKEX_MARKER_LEN  18

static BOOL PykexIsMarkerAt(const char *p)
{
    static const char m[] = PYKEX_MARKER;
    int i;
    for (i = 0; i < PYKEX_MARKER_LEN; i++)
        if (p[i] != m[i])
            return FALSE;
    return TRUE;
}

static void PykexReadMarkerArgs(const WCHAR *selfPath, WCHAR *outArgs,
                                DWORD outCch)
{
    HANDLE h;
    static char buf[32768];
    DWORD got = 0, i, k;
    char line[512];
    int n;

    outArgs[0] = 0;
    h = CreateFileW(selfPath, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    if (!ReadFile(h, buf, sizeof(buf) - 1, &got, NULL))
        got = 0;
    CloseHandle(h);
    if (got < PYKEX_MARKER_LEN + 4)
        return;
    buf[got] = 0;

    for (i = 0; i + PYKEX_MARKER_LEN <= got; i++) {
        if (buf[i] == '#' && buf[i + 1] == '!' &&
            PykexIsMarkerAt(buf + i)) {
            const char *p = buf + i + PYKEX_MARKER_LEN;
            if (*p == ' ')
                p++;
            k = 0;
            while (p[k] && p[k] != '\r' && p[k] != '\n' &&
                   k + 1 < sizeof(line)) {
                line[k] = p[k];
                k++;
            }
            while (k > 0 && line[k - 1] == ' ')
                k--;
            line[k] = 0;
            if (!k)
                return;
            n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                    line, (int) k, outArgs, (int) outCch - 1);
            if (n <= 0)
                n = MultiByteToWideChar(CP_ACP, 0, line, (int) k,
                                        outArgs, (int) outCch - 1);
            if (n <= 0) {
                outArgs[0] = 0;
                return;
            }
            outArgs[n] = 0;
            return;
        }
    }
}

// ----------------------------------------------------------------------------
// strip our own argv[0] from the command line (quoted or bare)
// ----------------------------------------------------------------------------
static WCHAR *PykexStripArgv0(WCHAR *cmd)
{
    while (*cmd == L' ' || *cmd == L'\t')
        cmd++;
    if (*cmd == L'"') {
        cmd++;
        while (*cmd && *cmd != L'"')
            cmd++;
        if (*cmd == L'"')
            cmd++;
    } else {
        while (*cmd && *cmd != L' ' && *cmd != L'\t')
            cmd++;
    }
    return cmd;
}

// ----------------------------------------------------------------------------
// main logic
// ----------------------------------------------------------------------------
static DWORD PykexMain(void)
{
    WCHAR selfPath[MAX_PATH];
    WCHAR python[MAX_PATH];
    WCHAR args[512];
    WCHAR *rest;
    WCHAR *cmdLine;
    DWORD need, exitCode = 1;
    int lp, la, ls, lr;
    WCHAR *w;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL gui;

#ifdef PYW7_GUI
    gui = TRUE;
#else
    gui = FALSE;
#endif

    GetModuleFileNameW(NULL, selfPath, MAX_PATH);

    if (!PykexResolvePython(selfPath, gui, python, MAX_PATH)) {
        PykexLog("PyKexExe: python.exe not found next to this shim or one "
                 "level up\r\n");
        return 9009;
    }

    // Hermetic-tree policy: never let a host-level PYTHONHOME/PYTHONPATH
    // (e.g. from another Python or Anaconda on the machine) steer the
    // interpreter we are about to launch, and keep the shared per-user
    // site-packages out of its sys.path.  The interpreter's sitecustomize
    // completes the isolation in-process (PATH/sys.path/conda markers).
    SetEnvironmentVariableW(L"PYTHONHOME", NULL);
    SetEnvironmentVariableW(L"PYTHONPATH", NULL);
    SetEnvironmentVariableW(L"PYTHONSTARTUP", NULL);
    SetEnvironmentVariableW(L"PYTHONNOUSERSITE", L"1");

    PykexReadMarkerArgs(selfPath, args, 512);
    rest = PykexStripArgv0(GetCommandLineW());

    // "\"<python>\" [args ]\"<self>\"<rest>"
    lp = PykexStrLenW(python);
    la = PykexStrLenW(args);
    ls = PykexStrLenW(selfPath);
    lr = PykexStrLenW(rest);
    need = (DWORD) (lp + la + ls + lr + 8);
    cmdLine = (WCHAR *) HeapAlloc(GetProcessHeap(), 0, need * sizeof(WCHAR));
    if (!cmdLine) {
        PykexLog("PyKexExe: out of memory\r\n");
        return 9009;
    }
    w = cmdLine;
    *w++ = L'"';
    PykexStrCpyW(w, python);
    w += lp;
    *w++ = L'"';
    *w++ = L' ';
    if (la) {
        PykexStrCpyW(w, args);
        w += la;
        *w++ = L' ';
    }
    *w++ = L'"';
    PykexStrCpyW(w, selfPath);
    w += ls;
    *w++ = L'"';
    PykexStrCpyW(w, rest);                     // rest keeps its leading space

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    GetStartupInfoW(&si);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessW(python, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL,
                        &si, &pi)) {
        PykexLog("PyKexExe: CreateProcessW failed\r\n");
        HeapFree(GetProcessHeap(), 0, cmdLine);
        return 9009;
    }
    HeapFree(GetProcessHeap(), 0, cmdLine);

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
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
    // Do not let Ctrl+C/Ctrl+Break kill the shim before the child:
    // the child shares the console and receives the event itself.
    SetConsoleCtrlHandler(NULL, TRUE);
#endif
    ExitProcess(PykexMain());
}

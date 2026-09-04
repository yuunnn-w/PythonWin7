// ============================================================================
// PyKexBoot.dll -- in-process compatibility bootstrap for Win7 Python trees.
//
// Injected by PyKexLdr into the interpreter process (right after KexDll.dll),
// and from there into every descendant process, so one runtime compatibility
// layer covers the whole process tree without installing VxKex (no service,
// no IFEO, no registry, no system footprint).
//
// On attach (idempotent) it installs up to three mechanisms:
//
//   1. CPIW bypass: KexDll!KexPatchCpiwSubsystemVersionCheck() -- defeats the
//      "this application requires a newer Windows" subsystem-version check.
//
//   2. Propagation: KexDll!KexHkInstallBasicHook(ntdll!NtCreateUserProcess).
//      Every child process is created with its initial thread suspended and
//      a widened access mask, then a lazy watcher thread polls (Toolhelp,
//      <=3 s) until kernel32.dll is mapped in the child and injects
//      KexDll.dll + PyKexBoot.dll (recursing to any depth of grandchildren).
//      Immediate injection at hook time is NOT possible: kernel32 is not yet
//      mapped inside a freshly NtCreateUserProcess-ed child.  Callers that
//      asked for CREATE_SUSPENDED keep their semantics (kernel32's
//      CreateProcessInternalW balances the forced suspension on the normal
//      path).  WOW64 (32-bit) children are skipped -- this build is x64-only.
//
//   3. Load-time import rewrite (VxKex-style): KexDll!KexHkInstallBasicHook
//      (ntdll!NtMapViewOfSection).  Every PE image mapped into the process
//      AFTER this point gets its import directory rewritten IN MEMORY before
//      the loader snaps its imports: the DLL names listed in g_Redirects
//      (kernel32, user32, advapi32, ws2_32, bcrypt, ..., api-ms-win-* sets)
//      are replaced by the corresponding VxKex extension DLL (kxbase, kxuser,
//      ...), which re-exports the host DLL's entire surface and adds the
//      Win8+ implementations.  This is the same mechanism VxKex NEXT uses
//      (KexDll.dllnotif.c / dllrewrt.c), reimplemented CRT-free on the
//      primitives KexDll exports.  Consequence: any .pyd/.dll dropped by a
//      wheel and loaded into an injected interpreter is covered WITHOUT any
//      per-file patching.  Set PYW7HOOK=0 to disable this hook (debug).
//
//      Not covered by design: images mapped before injection (the
//      interpreter core itself -- handled by the static file layer plus the
//      bootstrap IAT patch on python3xx.dll), and a child process's own
//      static imports (snapped before the watcher can inject -- such exes
//      are fixed on disk by the pywin7gate layer instead).
//
// Failure policy: every step degrades silently; worst case a process runs
// without this layer and the static file layer still applies.
//
// Diagnostics: PYW7DEBUG=1 appends low-noise lifecycle events (child-process
// creation, injection results, import rewrites) to %TEMP%\pykexboot-dbg.log.
//
// Build: CRT-free, imports kernel32 only; KexDll/ntdll functions are
// resolved at runtime with GetProcAddress.
// ============================================================================

#include <windows.h>
#include <tlhelp32.h>

// ---- compiler intrinsics without CRT ---------------------------------------
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

// ---- minimal NT declarations ------------------------------------------------
#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

typedef LONG NTSTATUS;
#define PYKEX_NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

#define PYKEX_MEMORY_MAPPED_FILENAME_INFORMATION 2

typedef NTSTATUS (NTAPI *KEX_NT_CREATE_USER_PROCESS)(
    PHANDLE ProcessHandle, PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
    PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes,
    ULONG ProcessFlags, ULONG ThreadFlags,
    PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList);

typedef NTSTATUS (NTAPI *KEX_HK_INSTALL_BASIC_HOOK)(
    PVOID ApiAddress, PVOID RedirectedAddress, PVOID HookContext);

typedef NTSTATUS (NTAPI *KEX_PATCH_CPIW)(void);

typedef NTSTATUS (NTAPI *KEX_NT_MAP_VIEW_OF_SECTION)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG ZeroBits, SIZE_T CommitSize, PLONGLONG SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, DWORD AllocationType,
    DWORD MemoryProtection);

typedef NTSTATUS (NTAPI *KEX_NT_QUERY_VIRTUAL_MEMORY)(
    HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
    PVOID MemoryInformation, SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength);

// ntdll UNICODE_STRING (not exposed by windows.h)
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} PYKEX_UNICODE_STRING;

// ---- module state -----------------------------------------------------------
static LONG      g_Initialized = 0;
static HMODULE   g_hKexDll = NULL;
static KEX_NT_CREATE_USER_PROCESS g_RealNtCreateUserProcess = NULL;
static KEX_NT_MAP_VIEW_OF_SECTION g_RealNtMapViewOfSection = NULL;
static KEX_NT_QUERY_VIRTUAL_MEMORY g_NtQueryVirtualMemory = NULL;
static WCHAR     g_PayloadDir[MAX_PATH];   // directory containing this DLL
static WCHAR     g_KexDllPath[MAX_PATH];
static WCHAR     g_BootDllPath[MAX_PATH];

// per-thread reentry guard without CRT TLS (__declspec(thread) needs CRT)
static DWORD     g_TlsIndex = TLS_OUT_OF_INDEXES;

static BOOL PykexInHook(void)
{
    return g_TlsIndex != TLS_OUT_OF_INDEXES &&
           TlsGetValue(g_TlsIndex) != NULL;
}
static void PykexSetInHook(BOOL on)
{
    if (g_TlsIndex != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_TlsIndex, on ? (LPVOID) 1 : NULL);
}

// ---- debug logging (PYW7DEBUG=1 -> %TEMP%\pykexboot-dbg.log) ----------------
static LONG  g_Debug = -1;              // -1 unknown, 0 off, 1 on
static CRITICAL_SECTION g_DbgLock;
static LONG  g_DbgLockInit = 0;

static BOOL PykexDebugOn(void)
{
    WCHAR buf[8];
    if (g_Debug >= 0)
        return g_Debug != 0;
    g_Debug = (GetEnvironmentVariableW(L"PYW7DEBUG", buf, 8) > 0 &&
               buf[0] == L'1') ? 1 : 0;
    return g_Debug != 0;
}

static void PykexDbgWrite(const char *msg, int msgLen)
{
    HANDLE h;
    WCHAR path[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, path);
    DWORD written;
    if (!n || n >= MAX_PATH - 24)
        return;
    {
        static const WCHAR fn[] = L"pykexboot-dbg.log";
        int i = 0;
        while (fn[i]) { path[n + i] = fn[i]; i++; }
        path[n + i] = 0;
    }
    h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    WriteFile(h, msg, (DWORD) msgLen, &written, NULL);
    CloseHandle(h);
}

// append helpers into a fixed line buffer (CRT-free)
static int PykexAppendStr(char *dst, int pos, int cap, const char *s)
{
    while (*s && pos < cap - 1) dst[pos++] = *s++;
    return pos;
}
static int PykexAppendWStr(char *dst, int pos, int cap, const WCHAR *s)
{
    while (s && *s && pos < cap - 1) {
        WCHAR c = *s++;
        dst[pos++] = (c >= 32 && c < 127) ? (char) c : '?';
    }
    return pos;
}
static int PykexAppendHex(char *dst, int pos, int cap, ULONG_PTR v)
{
    char tmp[16];
    int i = 0;
    if (!v) {
        if (pos < cap - 1) dst[pos++] = '0';
        return pos;
    }
    while (v && i < 16) {
        int d = (int) (v & 0xF);
        tmp[i++] = (char) (d < 10 ? '0' + d : 'a' + d - 10);
        v >>= 4;
    }
    while (i-- > 0 && pos < cap - 1) dst[pos++] = tmp[i];
    return pos;
}

// one-line debug record: "[pid.tid] tag warg 0xnum"
static void PykexDbg(const char *tag, const WCHAR *warg, ULONG_PTR num)
{
    char line[1024];
    int pos = 0;
    if (!PykexDebugOn())
        return;
    if (InterlockedCompareExchange(&g_DbgLockInit, 1, 0) == 0)
        InitializeCriticalSection(&g_DbgLock);
    line[pos++] = '[';
    pos = PykexAppendHex(line, pos, (int) sizeof(line),
                         (ULONG_PTR) GetCurrentProcessId());
    line[pos++] = '.';
    pos = PykexAppendHex(line, pos, (int) sizeof(line),
                         (ULONG_PTR) GetCurrentThreadId());
    line[pos++] = ']';
    line[pos++] = ' ';
    pos = PykexAppendStr(line, pos, (int) sizeof(line), tag);
    if (warg) {
        line[pos++] = ' ';
        pos = PykexAppendWStr(line, pos, (int) sizeof(line), warg);
    }
    if (num) {
        line[pos++] = ' ';
        line[pos++] = '0';
        line[pos++] = 'x';
        pos = PykexAppendHex(line, pos, (int) sizeof(line), num);
    }
    line[pos++] = '\r';
    line[pos++] = '\n';
    EnterCriticalSection(&g_DbgLock);
    PykexDbgWrite(line, pos);
    LeaveCriticalSection(&g_DbgLock);
}

static void PykexDbgA(const char *tag, const char *arg, ULONG_PTR num)
{
    WCHAR w[128];
    int i = 0;
    if (!PykexDebugOn())
        return;
    while (arg && arg[i] && i < 127) {
        w[i] = (WCHAR) (unsigned char) arg[i];
        i++;
    }
    w[i] = 0;
    PykexDbg(tag, arg ? w : NULL, num);
}

// ---- tiny string helpers (CRT-free) -----------------------------------------
static char PykexLowerA(char c)
{
    if (c >= 'A' && c <= 'Z') c += 32;
    return c;
}

static WCHAR PykexLowerW(WCHAR c)
{
    if (c >= L'A' && c <= L'Z') c += 32;
    return c;
}

// case-insensitive ASCII equality
static BOOL PykexEqualsIA(const char *a, const char *b)
{
    while (*a && *b) {
        if (PykexLowerA(*a) != PykexLowerA(*b)) return FALSE;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static BOOL PykexStartsWithIA(const char *s, const char *prefix)
{
    while (*prefix) {
        if (PykexLowerA(*s) != PykexLowerA(*prefix)) return FALSE;
        s++; prefix++;
    }
    return TRUE;
}

static BOOL PykexStartsWithIW(const WCHAR *s, const WCHAR *prefix)
{
    while (*prefix) {
        if (PykexLowerW(*s) != PykexLowerW(*prefix)) return FALSE;
        s++; prefix++;
    }
    return TRUE;
}

// case-insensitive substring search (wide)
static BOOL PykexContainsIW(const WCHAR *haystack, const WCHAR *needle)
{
    for (; *haystack; haystack++) {
        const WCHAR *h = haystack, *n = needle;
        while (*n && *h && PykexLowerW(*h) == PykexLowerW(*n)) { h++; n++; }
        if (!*n) return TRUE;
    }
    return FALSE;
}

// ============================================================================
// Load-time import rewrite
// ============================================================================
//
// DLL-name redirect table, distilled from VxKex NEXT's KexDll/redirects.h
// (same mapping data).  Names are matched after lowercasing, stripping a
// trailing ".dll", and -- for api-/ext- names -- stripping the 7-character
// "-lX-Y-Z" suffix.  api-ms-win-crt-* entries are deliberately omitted: the
// tree ships the real KB2999226 api-ms files, which resolve directly.
// ---------------------------------------------------------------------------
typedef struct {
    const char *From;
    const char *To;
} PYKEX_REDIRECT;

static const PYKEX_REDIRECT g_Redirects[] = {
    // core host DLLs -> Kx* extension DLLs
    { "ntdll",              "kxnt"      },
    { "kernel32",           "kxbase"    },
    { "kernelbase",         "kxbase"    },
    { "cfgmgr32",           "kxbase"    },
    { "advapi32",           "kxadvapi"  },
    { "user32",             "kxuser"    },
    { "shcore",             "kxuser"    },
    { "bluetoothapis",      "kxuser"    },
    { "ole32",              "kxcom"     },
    { "combase",            "kxcom"     },
    { "msvcrt",             "kxcrt"     },
    { "bcrypt",             "kxcryp"    },
    { "bcryptprimitives",   "kxcryp"    },
    { "ncrypt",             "kxcryp"    },
    { "secur32",            "kxcryp"    },
    { "security",           "kxcryp"    },
    { "sspicli",            "kxcryp"    },
    { "schannel",           "kxcryp"    },
    { "d2d1",               "kxdx"      },
    { "d3d11",              "kxdx"      },
    { "d3d12",              "kxdx"      },
    { "dcomp",              "kxdx"      },
    { "dxgi",               "kxdx"      },
    { "mfplat",             "kxdx"      },
    { "powrprof",           "kxmi"      },
    { "userenv",            "kxmi"      },
    { "version",            "kxmi"      },
    { "wldp",               "kxmi"      },
    { "wtsapi32",           "kxmi"      },
    { "dnsapi",             "kxnet"     },
    { "winhttp",            "kxnet"     },
    { "ws2_32",             "kxnet"     },
    { "uiautomationcore",   "kxuia"     },
    // api-/ext- sets (matched without the -lX-Y-Z suffix)
    { "api-ms-win-appmodel-identity",             "kxbase"   },
    { "api-ms-win-appmodel-runtime",              "kxbase"   },
    { "api-ms-win-core-apiquery",                 "kxnt"     },
    { "api-ms-win-core-atoms",                    "kxbase"   },
    { "api-ms-win-core-crt",                      "kxcrt"    },
    { "api-ms-win-core-com",                      "kxcom"    },
    { "api-ms-win-core-com-midlproxystub",        "kxcom"    },
    { "api-ms-win-core-com-private",              "kxcom"    },
    { "api-ms-win-core-console",                  "kxbase"   },
    { "api-ms-win-core-datetime",                 "kxbase"   },
    { "api-ms-win-core-debug",                    "kxbase"   },
    { "api-ms-win-core-delayload",                "kxbase"   },
    { "api-ms-win-core-errorhandling",            "kxbase"   },
    { "api-ms-win-core-featurestaging",           "kxuser"   },
    { "api-ms-win-core-fibers",                   "kxbase"   },
    { "api-ms-win-core-file",                     "kxbase"   },
    { "api-ms-win-core-handle",                   "kxbase"   },
    { "api-ms-win-core-heap",                     "kxbase"   },
    { "api-ms-win-core-heap-obsolete",            "kxbase"   },
    { "api-ms-win-core-interlocked",              "kxbase"   },
    { "api-ms-win-core-io",                       "kxbase"   },
    { "api-ms-win-core-job",                      "kxbase"   },
    { "api-ms-win-core-kernel32-legacy",          "kxbase"   },
    { "api-ms-win-core-largeinteger",             "kxbase"   },
    { "api-ms-win-core-libraryloader",            "kxbase"   },
    { "api-ms-win-core-localization",             "kxbase"   },
    { "api-ms-win-core-localization-ansi",        "kxbase"   },
    { "api-ms-win-core-localization-obsolete",    "kxbase"   },
    { "api-ms-win-core-localregistry",            "kxadvapi" },
    { "api-ms-win-core-marshal",                  "kxcom"    },
    { "api-ms-win-core-memory",                   "kxbase"   },
    { "api-ms-win-core-namedpipe",                "kxbase"   },
    { "api-ms-win-core-namedpipe-ansi",           "kxbase"   },
    { "api-ms-win-core-normalization",            "normaliz" },
    { "api-ms-win-core-path",                     "kxbase"   },
    { "api-ms-win-core-privateprofile",           "kxbase"   },
    { "api-ms-win-core-processenvironment",       "kxbase"   },
    { "api-ms-win-core-processsnapshot",          "kxbase"   },
    { "api-ms-win-core-processthreads",           "kxbase"   },
    { "api-ms-win-core-processtopology",          "kxbase"   },
    { "api-ms-win-core-processtopology-obsolete", "kxbase"   },
    { "api-ms-win-core-profile",                  "kxbase"   },
    { "api-ms-win-core-psapi",                    "kxbase"   },
    { "api-ms-win-core-quirks",                   "kxbase"   },
    { "api-ms-win-core-realtime",                 "kxbase"   },
    { "api-ms-win-core-registry",                 "kxadvapi" },
    { "api-ms-win-core-registry-private",         "kxadvapi" },
    { "api-ms-win-core-registryuserspecific",     "kxadvapi" },
    { "api-ms-win-core-rtlsupport",               "kxnt"     },
    { "api-ms-win-core-shlwapi-legacy",           "kxuser"   },
    { "api-ms-win-core-shlwapi-obsolete",         "kxuser"   },
    { "api-ms-win-core-sidebyside",               "kxbase"   },
    { "api-ms-win-core-string",                   "kxbase"   },
    { "api-ms-win-core-string-obsolete",          "kxbase"   },
    { "api-ms-win-core-stringansi",               "kxbase"   },
    { "api-ms-win-core-synch",                    "kxbase"   },
    { "api-ms-win-core-synch-ansi",               "kxbase"   },
    { "api-ms-win-core-sysinfo",                  "kxbase"   },
    { "api-ms-win-core-systemtopology",           "kxbase"   },
    { "api-ms-win-core-threadpool",               "kxbase"   },
    { "api-ms-win-core-threadpool-legacy",        "kxbase"   },
    { "api-ms-win-core-threadpool-private",       "kxbase"   },
    { "api-ms-win-core-toolhelp",                 "kxbase"   },
    { "api-ms-win-core-timezone",                 "kxbase"   },
    { "api-ms-win-core-url",                      "kxuser"   },
    { "api-ms-win-core-util",                     "kxbase"   },
    { "api-ms-win-core-version",                  "version"  },
    { "api-ms-win-core-versionansi",              "version"  },
    { "api-ms-win-core-windowserrorreporting",    "kxbase"   },
    { "api-ms-win-core-winrt",                    "kxcom"    },
    { "api-ms-win-core-winrt-error",              "kxcom"    },
    { "api-ms-win-core-winrt-errorprivate",       "kxcom"    },
    { "api-ms-win-core-winrt-registration",       "kxcom"    },
    { "api-ms-win-core-winrt-robuffer",           "kxcom"    },
    { "api-ms-win-core-winrt-roparameterizediid", "kxcom"    },
    { "api-ms-win-core-winrt-string",             "kxcom"    },
    { "api-ms-win-core-wow64",                    "kxbase"   },
    { "api-ms-win-core-xstate",                   "kxnt"     },
    { "api-ms-win-devices-config",                "kxbase"   },
    { "api-ms-win-devices-query",                 "kxbase"   },
    { "api-ms-win-devices-swdevice",              "kxbase"   },
    { "api-ms-win-downlevel-kernel32",            "kxbase"   },
    { "api-ms-win-downlevel-ole32",               "kxcom"    },
    { "api-ms-win-downlevel-shell32",             "kxuser"   },
    { "api-ms-win-eventing-classicprovider",      "kxadvapi" },
    { "api-ms-win-eventing-consumer",             "kxadvapi" },
    { "api-ms-win-eventing-controller",           "kxadvapi" },
    { "api-ms-win-eventing-legacy",               "kxadvapi" },
    { "api-ms-win-eventing-provider",             "kxadvapi" },
    { "api-ms-win-eventlog-legacy",               "kxadvapi" },
    { "api-ms-win-kernel32-package-current",      "kxbase"   },
    { "api-ms-win-mm-time",                       "winmm"    },
    { "api-ms-win-ntuser-sysparams",              "kxuser"   },
    { "api-ms-win-power-base",                    "kxmi"     },
    { "api-ms-win-power-setting",                 "kxmi"     },
    { "api-ms-win-security-base",                 "kxbase"   },
    { "api-ms-win-security-base-ansi",            "kxadvapi" },
    { "api-ms-win-security-cryptoapi",            "cryptsp"  },
    { "api-ms-win-security-lsalookup",            "kxadvapi" },
    { "api-ms-win-security-lsalookup-ansi",       "kxadvapi" },
    { "api-ms-win-security-sddl",                 "sechost"  },
    { "api-ms-win-security-sddl-ansi",            "kxadvapi" },
    { "api-ms-win-security-systemfunctions",      "kxadvapi" },
    { "api-ms-win-service-core",                  "sechost"  },
    { "api-ms-win-service-core-ansi",             "kxadvapi" },
    { "api-ms-win-service-management",            "kxadvapi" },
    { "api-ms-win-service-private",               "sechost"  },
    { "api-ms-win-service-winsvc",                "kxadvapi" },
    { "api-ms-win-shcore-comhelpers",             "kxuser"   },
    { "api-ms-win-shcore-obsolete",               "kxuser"   },
    { "api-ms-win-shcore-path",                   "kxuser"   },
    { "api-ms-win-shcore-registry",               "kxuser"   },
    { "api-ms-win-shcore-scaling",                "kxuser"   },
    { "api-ms-win-shcore-stream",                 "kxuser"   },
    { "api-ms-win-shcore-stream-winrt",           "kxuser"   },
    { "api-ms-win-shcore-sysinfo",                "kxuser"   },
    { "api-ms-win-shcore-taskpool",               "kxuser"   },
    { "api-ms-win-shcore-thread",                 "kxuser"   },
    { "api-ms-win-shcore-unicodeansi",            "kxuser"   },
    { "api-ms-win-shell-namespace",               "kxuser"   },
    { "ext-ms-win-branding-winbrand",             "winbrand" },
    { "ext-ms-win-gdi-dc",                        "gdi32"    },
    { "ext-ms-win-gdi-dc-create",                 "gdi32"    },
    { "ext-ms-win-gdi-draw",                      "gdi32"    },
    { "ext-ms-win-gdi-font",                      "gdi32"    },
    { "ext-ms-win-gdi-path",                      "gdi32"    },
    { "ext-ms-win-ntuser-draw",                   "kxuser"   },
    { "ext-ms-win-ntuser-rotationmanager",        "kxuser"   },
    { "ext-ms-win-ntuser-windowclass",            "kxuser"   },
    { "ext-ms-win-rtcore-gdi-devcaps",            "gdi32"    },
    { "ext-ms-win-rtcore-gdi-object",             "gdi32"    },
    { "ext-ms-win-rtcore-gdi-rgn",                "gdi32"    },
    { "ext-ms-win-rtcore-ntuser-sysparams",       "kxuser"   },
    { "ext-ms-win-uiacore",                       "kxuia"    },
};

// Normalize an imported DLL name for table lookup: lowercase in place,
// strip a trailing ".dll", and for api-/ext- names strip the 7-char
// "-lX-Y-Z" suffix.
static void PykexNormalizeDllNameA(char *name)
{
    char *p = name;
    char *end;
    while (*p) { *p = PykexLowerA(*p); p++; }
    end = p;
    if (end - name >= 4 && end[-4] == '.' &&
        PykexLowerA(end[-3]) == 'd' && end[-2] == 'l' && end[-1] == 'l') {
        end -= 4;
        *end = 0;
    }
    if ((PykexStartsWithIA(name, "api-") || PykexStartsWithIA(name, "ext-")) &&
        end - name > 7 && end[-7] == '-') {
        end[-7] = 0;
    }
}

static const char *PykexLookupRedirect(const char *normalized)
{
    int i;
    for (i = 0; i < (int) (sizeof(g_Redirects) / sizeof(g_Redirects[0])); i++) {
        if (PykexEqualsIA(normalized, g_Redirects[i].From))
            return g_Redirects[i].To;
    }
    return NULL;
}

// Rewrite one import-directory DLL name string in place.  The replacement
// ("kxbase.dll" etc.) is never longer than the source names we accept.
static BOOL PykexRewriteNameInPlace(char *nameInImage, const char *targetNoExt)
{
    PVOID page = nameInImage;
    SIZE_T size = lstrlenA(nameInImage) + 1;
    ULONG oldProtect = 0;
    char replacement[32];
    int i = 0;
    const char *t = targetNoExt;

    while (*t && i < (int) sizeof(replacement) - 5)
        replacement[i++] = *t++;
    replacement[i++] = '.'; replacement[i++] = 'd';
    replacement[i++] = 'l'; replacement[i++] = 'l';
    replacement[i] = 0;

    if (lstrlenA(replacement) > lstrlenA(nameInImage))
        return FALSE;   // table bug guard: never overflow the original slot

    if (!VirtualProtect(page, size, PAGE_READWRITE, &oldProtect)) {
        page = (PVOID) ((ULONG_PTR) nameInImage & ~(ULONG_PTR) 0xFFF);
        size = ((ULONG_PTR) nameInImage + size) - (ULONG_PTR) page;
        if (!VirtualProtect(page, size, PAGE_READWRITE, &oldProtect))
            return FALSE;
    }
    memset(nameInImage, 0, lstrlenA(nameInImage) + 1);
    memcpy(nameInImage, replacement, lstrlenA(replacement) + 1);
    VirtualProtect(page, size, oldProtect, &oldProtect);
    return TRUE;
}

// Walk an import-style descriptor array (regular or delay) and rewrite every
// DLL name that has a redirect entry.  All offsets are validated against
// sizeOfImage so a malformed image cannot make us touch uncommitted pages
// (this build is CRT-free, so no SEH: bounds are checked explicitly).
// Returns TRUE if anything changed.
static BOOL PykexRewriteDescriptorNames(PVOID base, SIZE_T sizeOfImage,
                                        DWORD dirRva, BOOL rvaBased)
{
    BOOL changed = FALSE;
    int guard = 0;

    if (!dirRva || dirRva >= sizeOfImage)
        return FALSE;

    for (;;) {
        char *desc = (char *) base + dirRva;
        DWORD nameRva;
        char *name;
        SIZE_T maxName;
        char norm[64];
        const char *target;
        SIZE_T i;

        if (++guard > 512)          // descriptor-array runaway guard
            break;
        if (dirRva + 20 > sizeOfImage)
            break;

        nameRva = rvaBased
            ? *(DWORD *) (desc + 4)                          // ImgDelayDescr.DllNameRVA
            : ((PIMAGE_IMPORT_DESCRIPTOR) desc)->Name;
        if (!nameRva)
            break;
        if (nameRva >= sizeOfImage)
            break;
        name = (char *) base + nameRva;
        maxName = sizeOfImage - nameRva;
        if (maxName > sizeof(norm) - 1)
            maxName = sizeof(norm) - 1;

        for (i = 0; i < maxName && name[i]; i++)
            norm[i] = name[i];
        norm[i] = 0;
        if (i == maxName)
            break;                  // unterminated string: malformed image
        PykexNormalizeDllNameA(norm);

        target = PykexLookupRedirect(norm);
        if (target) {
            PykexDbgA("rewrite-name", norm, (ULONG_PTR) 0);
            PykexDbgA("rewrite-to  ", target, (ULONG_PTR) 0);
        }
        if (target && PykexRewriteNameInPlace(name, target))
            changed = TRUE;

        dirRva += (DWORD) (rvaBased ? 32 : sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }
    return changed;
}

// Policy: which mapped images get their imports rewritten.
static BOOL PykexShouldRewriteImage(PVOID base, const WCHAR *devPath)
{
    const WCHAR *baseName = devPath;

    // never touch OS files (\Device\HarddiskVolumeN\Windows\...)
    if (PykexContainsIW(devPath, L"\\windows\\"))
        return FALSE;

    if (*baseName) {
        const WCHAR *p;
        for (p = devPath; *p; p++)
            if (*p == L'\\') baseName = p + 1;
    }

    // our own runtime files load correctly by construction; leave them alone
    if (PykexStartsWithIW(baseName, L"kx") ||
        PykexStartsWithIW(baseName, L"api-ms-win-") ||
        PykexStartsWithIW(baseName, L"vcruntime140") ||
        PykexStartsWithIW(baseName, L"msvcp140") ||
        PykexStartsWithIW(baseName, L"pykex") ||
        PykexStartsWithIW(baseName, L"kexdll") ||
        PykexStartsWithIW(baseName, L"ucrtbase"))
        return FALSE;

    (void) base;
    return TRUE;
}

static void PykexMaybeRewriteImage(PVOID base, SIZE_T viewSize)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *) base;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *dir;
    SIZE_T sizeOfImage;
    SIZE_T retLen = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BOOL changed = FALSE;

    // no SEH in a CRT-free build: every read is bounded by the mapped
    // view size first and by the image's own SizeOfImage afterwards.
    if (viewSize < sizeof(IMAGE_DOS_HEADER))
        return;

    // Probe BEFORE the first dereference.  Non-image views (pagefile-backed
    // data sections, process-snapshot clones, guard/no-access pages) can
    // fault on read; only real image mappings (MEM_IMAGE, committed,
    // readable) are of interest anyway.
    memset(&mbi, 0, sizeof(mbi));
    if (!g_NtQueryVirtualMemory ||
        !PYKEX_NT_SUCCESS(g_NtQueryVirtualMemory(
            GetCurrentProcess(), base, 0 /* MemoryBasicInformation */,
            &mbi, sizeof(mbi), &retLen)))
        return;
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE ||
        mbi.Protect == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD))
        return;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    if (dos->e_lfanew < (LONG) sizeof(IMAGE_DOS_HEADER) ||
        (SIZE_T) dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > viewSize)
        return;
    nt = (IMAGE_NT_HEADERS *) ((char *) base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;
    if (nt->FileHeader.Machine != 0x8664)   // x64 build only rewrites x64
        return;
    sizeOfImage = nt->OptionalHeader.SizeOfImage;
    if (!sizeOfImage || sizeOfImage > viewSize)
        sizeOfImage = viewSize;

    // path-scoped policy; on query failure, skip (conservative)
    if (g_NtQueryVirtualMemory) {
        struct {
            PYKEX_UNICODE_STRING Name;
            WCHAR Buffer[1500];
        } mi;
        SIZE_T retLen = 0;
        memset(&mi, 0, sizeof(mi));
        if (!PYKEX_NT_SUCCESS(g_NtQueryVirtualMemory(
                GetCurrentProcess(), base,
                PYKEX_MEMORY_MAPPED_FILENAME_INFORMATION,
                &mi, sizeof(mi), &retLen)))
            return;
        if (PykexShouldRewriteImage(base, mi.Name.Buffer))
            PykexDbg("rewrite-scan", mi.Name.Buffer, (ULONG_PTR) base);
        else
            return;
    } else {
        return;
    }

    if (nt->OptionalHeader.NumberOfRvaAndSizes >
        IMAGE_DIRECTORY_ENTRY_IMPORT) {
        dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        changed |= PykexRewriteDescriptorNames(base, sizeOfImage,
                                               dir->VirtualAddress, FALSE);
    }
    if (nt->OptionalHeader.NumberOfRvaAndSizes >
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
        dir = &nt->OptionalHeader
                  .DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (dir->VirtualAddress &&
            dir->VirtualAddress + 4 <= sizeOfImage) {
            // ImgDelayDescr.Attributes bit 0 = RVAs (always set by modern linkers)
            DWORD attrs = *(DWORD *) ((char *) base + dir->VirtualAddress);
            if (attrs & 1) {
                changed |= PykexRewriteDescriptorNames(
                    base, sizeOfImage, dir->VirtualAddress, TRUE);
            }
        }
    }

    if (changed) {
        // bound-import addresses are invalid after a DLL substitution
        IMAGE_DATA_DIRECTORY *bound =
            &nt->OptionalHeader
                 .DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
        ULONG oldProtect = 0;
        PykexDbg("bound-clear", NULL, (ULONG_PTR) base);
        if (VirtualProtect(bound, sizeof(*bound), PAGE_READWRITE,
                           &oldProtect)) {
            bound->VirtualAddress = 0;
            bound->Size = 0;
            VirtualProtect(bound, sizeof(*bound), oldProtect,
                           &oldProtect);
        }
    }
}

static NTSTATUS NTAPI PykexNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG ZeroBits, SIZE_T CommitSize, PLONGLONG SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, DWORD AllocationType,
    DWORD MemoryProtection)
{
    NTSTATUS status = g_RealNtMapViewOfSection(
        SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
        SectionOffset, ViewSize, InheritDisposition, AllocationType,
        MemoryProtection);

    if (PYKEX_NT_SUCCESS(status) &&
        ProcessHandle == GetCurrentProcess() &&   // pseudo-handle: own process
        BaseAddress && *BaseAddress &&
        ViewSize && *ViewSize >= sizeof(IMAGE_DOS_HEADER) &&
        !PykexInHook()) {
        PykexSetInHook(TRUE);
        PykexMaybeRewriteImage(*BaseAddress, *ViewSize);
        PykexSetInHook(FALSE);
    }
    return status;
}

// ============================================================================
// Propagation: pending-injection registry + watcher
// ============================================================================
#define PYKEX_MAX_PENDING 64
#define PYKEX_POLL_MS     25
#define PYKEX_DEADLINE_MS 3000

typedef struct {
    HANDLE hProcess;    // duplicated handle, watcher owns and closes it
    DWORD  Pid;
    DWORD  FirstSeen;   // GetTickCount
} PYKEX_PENDING;

static PYKEX_PENDING g_Pending[PYKEX_MAX_PENDING];
static LONG          g_PendingCount = 0;      // guarded by g_PendingLock
static CRITICAL_SECTION g_PendingLock;
static LONG          g_LockInit = 0;
static HANDLE        g_WatcherThread = NULL;

static BOOL PykexKernel32Mapped(DWORD pid)
{
    HANDLE snap;
    MODULEENTRY32W me;
    BOOL found = FALSE;

    PykexDbg("watcher-snap", NULL, (ULONG_PTR) pid);
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        PykexDbg("watcher-snap-fail", NULL, (ULONG_PTR) GetLastError());
        return FALSE;
    }
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            const WCHAR *a = me.szModule;
            const WCHAR *b = L"kernel32.dll";
            while (*a && *b) {
                WCHAR ca = *a, cb = *b;
                if (ca >= L'A' && ca <= L'Z') ca += 32;
                if (cb >= L'A' && cb <= L'Z') cb += 32;
                if (ca != cb) break;
                a++; b++;
            }
            if (*a == 0 && *b == 0) { found = TRUE; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    PykexDbg("watcher-snap-done", NULL, (ULONG_PTR) found);
    return found;
}

static BOOL PykexInjectRunning(HANDLE hProcess, const WCHAR *dllPath)
{
    SIZE_T bytes, size;
    LPVOID remote;
    HANDLE hThread;
    DWORD  exitCode = 0;
    LPVOID pLoadLibraryW;

    pLoadLibraryW = (LPVOID) GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                            "LoadLibraryW");
    if (!pLoadLibraryW)
        return FALSE;

    size = (SIZE_T) (lstrlenW(dllPath) + 1) * sizeof(WCHAR);
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
                                 remote, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return FALSE;
    }
    WaitForSingleObject(hThread, 5000);
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    return exitCode != 0;
}

static void PykexInjectChild(HANDLE hProcess, DWORD pid)
{
    BOOL wow64 = FALSE;
    PykexDbg("inject-child", NULL, (ULONG_PTR) pid);
    if (!IsWow64Process(hProcess, &wow64) || wow64) {
        PykexDbg("inject-skip-wow64", NULL, (ULONG_PTR) pid);
        return;    // x64 DLLs cannot go into a 32-bit child
    }
    if (!PykexInjectRunning(hProcess, g_KexDllPath)) {
        PykexDbg("inject-kexdll-fail", NULL, (ULONG_PTR) pid);
        return;
    }
    PykexDbg("inject-kexdll-ok", NULL, (ULONG_PTR) pid);
    PykexInjectRunning(hProcess, g_BootDllPath);
    PykexDbg("inject-boot-done", NULL, (ULONG_PTR) pid);
}

static DWORD WINAPI PykexWatcher(LPVOID unused)
{
    (void) unused;
    PykexDbg("watcher-enter", NULL, 0);
    for (;;) {
        int i;
        BOOL any = FALSE;
        EnterCriticalSection(&g_PendingLock);
        for (i = 0; i < PYKEX_MAX_PENDING; i++) {
            if (!g_Pending[i].hProcess)
                continue;
            any = TRUE;
            if (PykexKernel32Mapped(g_Pending[i].Pid)) {
                HANDLE h = g_Pending[i].hProcess;
                DWORD pid = g_Pending[i].Pid;
                g_Pending[i].hProcess = NULL;
                InterlockedDecrement(&g_PendingCount);
                LeaveCriticalSection(&g_PendingLock);
                PykexInjectChild(h, pid);
                CloseHandle(h);
                EnterCriticalSection(&g_PendingLock);
            } else if ((DWORD) (GetTickCount() - g_Pending[i].FirstSeen)
                       > PYKEX_DEADLINE_MS) {
                CloseHandle(g_Pending[i].hProcess);
                g_Pending[i].hProcess = NULL;
                InterlockedDecrement(&g_PendingCount);
            } else {
                DWORD wr = WaitForSingleObject(g_Pending[i].hProcess, 0);
                if (wr == WAIT_OBJECT_0) {   // child exited unpropagated
                    CloseHandle(g_Pending[i].hProcess);
                    g_Pending[i].hProcess = NULL;
                    InterlockedDecrement(&g_PendingCount);
                }
            }
        }
        LeaveCriticalSection(&g_PendingLock);
        if (!any)
            break;
        Sleep(PYKEX_POLL_MS);
    }

    PykexDbg("watcher-exit", NULL, 0);
    EnterCriticalSection(&g_PendingLock);
    CloseHandle(g_WatcherThread);
    g_WatcherThread = NULL;
    LeaveCriticalSection(&g_PendingLock);
    return 0;
}

static void PykexScheduleInjection(HANDLE hProcess)
{
    int i;
    DWORD pid;

    if (!g_LockInit)
        return;
    pid = GetProcessId(hProcess);
    PykexDbg("schedule", NULL, (ULONG_PTR) pid);
    if (!pid)
        return;

    EnterCriticalSection(&g_PendingLock);
    PykexDbg("schedule-locked", NULL, (ULONG_PTR) pid);
    for (i = 0; i < PYKEX_MAX_PENDING; i++) {
        if (g_Pending[i].hProcess)
            continue;
        if (DuplicateHandle(GetCurrentProcess(), hProcess,
                            GetCurrentProcess(), &g_Pending[i].hProcess,
                            0, FALSE, DUPLICATE_SAME_ACCESS)) {
            g_Pending[i].Pid = pid;
            g_Pending[i].FirstSeen = GetTickCount();
            InterlockedIncrement(&g_PendingCount);
            if (!g_WatcherThread) {
                PykexDbg("watcher-spawn", NULL, (ULONG_PTR) pid);
                g_WatcherThread = CreateThread(NULL, 0, PykexWatcher,
                                               NULL, 0, NULL);
                PykexDbg("watcher-spawned", NULL,
                         (ULONG_PTR) g_WatcherThread);
            }
        }
        break;
    }
    LeaveCriticalSection(&g_PendingLock);
    PykexDbg("schedule-done", NULL, (ULONG_PTR) pid);
}

// ---- the NtCreateUserProcess hook -------------------------------------------
static NTSTATUS NTAPI PykexNtCreateUserProcess(
    PHANDLE ProcessHandle, PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
    PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes,
    ULONG ProcessFlags, ULONG ThreadFlags,
    PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList)
{
    NTSTATUS status;

    if (PykexInHook() || !g_RealNtCreateUserProcess) {
        // recursion guard tripped or runtime unresolved: pass through raw
        return g_RealNtCreateUserProcess
            ? g_RealNtCreateUserProcess(ProcessHandle, ThreadHandle,
                  ProcessDesiredAccess, ThreadDesiredAccess,
                  ProcessObjectAttributes, ThreadObjectAttributes,
                  ProcessFlags, ThreadFlags, ProcessParameters,
                  CreateInfo, AttributeList)
            : 0xC0000001L /* STATUS_UNSUCCESSFUL */;
    }

    PykexSetInHook(TRUE);
    status = g_RealNtCreateUserProcess(
        ProcessHandle, ThreadHandle,
        ProcessDesiredAccess | PROCESS_VM_OPERATION | PROCESS_VM_READ |
            PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION,
        ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags,
        ThreadFlags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        ProcessParameters, CreateInfo, AttributeList);

    if (PYKEX_NT_SUCCESS(status)) {
        PykexDbg("create-child", NULL, 0);
        PykexScheduleInjection(*ProcessHandle);   // best-effort
    }

    PykexSetInHook(FALSE);
    return status;
}

// ---- attach -----------------------------------------------------------------
static void PykexAttach(HINSTANCE hSelf)
{
    HMODULE hNtdll;
    WCHAR *slash;
    KEX_HK_INSTALL_BASIC_HOOK pInstallHook;
    KEX_PATCH_CPIW pPatchCpiw;
    PVOID pNtCreateUserProcess;
    PVOID pNtMapViewOfSection;
    WCHAR envBuf[8];

    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0)
        return;

    // remember our own directory for payload paths
    if (GetModuleFileNameW(hSelf, g_PayloadDir, MAX_PATH)) {
        slash = g_PayloadDir + lstrlenW(g_PayloadDir);
        while (slash > g_PayloadDir && slash[-1] != L'\\') slash--;
        *slash = 0;
        lstrcpyW(g_KexDllPath, g_PayloadDir);
        lstrcpyW(g_KexDllPath + lstrlenW(g_KexDllPath), L"KexDll.dll");
        lstrcpyW(g_BootDllPath, g_PayloadDir);
        lstrcpyW(g_BootDllPath + lstrlenW(g_BootDllPath), L"PyKexBoot.dll");
    } else {
        return;
    }

    g_hKexDll = GetModuleHandleW(L"KexDll.dll");
    if (!g_hKexDll)
        return;    // KexDll must be injected first (PyKexLdr does)

    pPatchCpiw = (KEX_PATCH_CPIW) GetProcAddress(
        g_hKexDll, "KexPatchCpiwSubsystemVersionCheck");
    if (pPatchCpiw)
        pPatchCpiw();

    pInstallHook = (KEX_HK_INSTALL_BASIC_HOOK) GetProcAddress(
        g_hKexDll, "KexHkInstallBasicHook");
    hNtdll = GetModuleHandleW(L"ntdll.dll");

    g_RealNtCreateUserProcess = (KEX_NT_CREATE_USER_PROCESS) GetProcAddress(
        g_hKexDll, "KexNtCreateUserProcess");
    g_RealNtMapViewOfSection = (KEX_NT_MAP_VIEW_OF_SECTION) GetProcAddress(
        g_hKexDll, "KexNtMapViewOfSection");
    g_NtQueryVirtualMemory = (KEX_NT_QUERY_VIRTUAL_MEMORY) GetProcAddress(
        g_hKexDll, "KexNtQueryVirtualMemory");

    if (!pInstallHook || !hNtdll)
        return;

    g_TlsIndex = TlsAlloc();
    if (InterlockedCompareExchange(&g_LockInit, 1, 0) == 0)
        InitializeCriticalSection(&g_PendingLock);

    // 1. propagation hook
    pNtCreateUserProcess = (PVOID) GetProcAddress(hNtdll,
                                                  "NtCreateUserProcess");
    if (g_RealNtCreateUserProcess && pNtCreateUserProcess)
        pInstallHook(pNtCreateUserProcess, PykexNtCreateUserProcess, NULL);

    // 2. load-time import-rewrite hook (PYW7HOOK=0 disables it)
    envBuf[0] = 0;
    if (GetEnvironmentVariableW(L"PYW7HOOK", envBuf, 8) == 0 ||
        envBuf[0] != L'0') {
        pNtMapViewOfSection = (PVOID) GetProcAddress(hNtdll,
                                                     "NtMapViewOfSection");
        if (g_RealNtMapViewOfSection && g_NtQueryVirtualMemory &&
            pNtMapViewOfSection)
            pInstallHook(pNtMapViewOfSection, PykexNtMapViewOfSection, NULL);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void) reserved;
    if (reason == DLL_PROCESS_ATTACH)
        PykexAttach(hinst);
    return TRUE;
}

// ============================================================================
// PyKexShim.dll -- fallback IAT-redirect target when the VxKex runtime
// (KxBase.dll) is NOT used.
//
// Exports the two kernel32 functions that python314.dll / python314t.dll
// import and that bare Windows 7 lacks:
//
//   AddDllDirectory     -- Win8+.  Here: appends the directory to the PATH
//                          environment variable (standard LoadLibrary search
//                          picks it up from there) and returns a non-NULL
//                          simulated cookie.  NULL only on hard failure,
//                          matching real semantics.
//   RemoveDllDirectory  -- Win8+.  Here: validates the cookie and returns
//                          TRUE (PATH entries are left in place; documented
//                          limitation of the fallback route).
//
// The packaging step (build_pack.py) patches the IAT of python314*.dll to
// import from PyKexShim.dll instead of KxBase.dll when this fallback is
// selected.  CRT-free, imports kernel32 only.
// ============================================================================

#include <windows.h>

// We deliberately provide these kernel32-looking exports ourselves.
#pragma warning(disable: 4273)

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

#define PYKEX_PATH_MAX 32000

static LONG  g_Cookie = 0;
static LONG  g_LockInit = 0;
static CRITICAL_SECTION g_PathLock;

static BOOL PykexPathContains(const WCHAR *path, const WCHAR *dir)
{
    // case-insensitive component-wise search for dir in ';'-separated path
    int dlen = lstrlenW(dir);
    const WCHAR *p = path;
    while (*p) {
        const WCHAR *end = p;
        while (*end && *end != L';') end++;
        if ((int) (end - p) == dlen) {
            int i;
            for (i = 0; i < dlen; i++) {
                WCHAR a = p[i], b = dir[i];
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) break;
            }
            if (i == dlen)
                return TRUE;
        }
        p = *end ? end + 1 : end;
    }
    return FALSE;
}

__declspec(dllexport) PVOID WINAPI AddDllDirectory(PCWSTR NewDirectory)
{
    static WCHAR path[PYKEX_PATH_MAX];
    DWORD got;
    int plen, dlen;

    if (!NewDirectory || !NewDirectory[0])
        return NULL;
    if (!g_LockInit) {
        if (InterlockedCompareExchange(&g_LockInit, 1, 0) == 0)
            InitializeCriticalSection(&g_PathLock);
    }

    EnterCriticalSection(&g_PathLock);
    got = GetEnvironmentVariableW(L"PATH", path, PYKEX_PATH_MAX);
    if (got >= PYKEX_PATH_MAX) {
        LeaveCriticalSection(&g_PathLock);
        return NULL;
    }
    if (got == 0)
        path[0] = 0;

    if (!PykexPathContains(path, NewDirectory)) {
        plen = lstrlenW(path);
        dlen = lstrlenW(NewDirectory);
        if (plen + dlen + 2 >= PYKEX_PATH_MAX) {
            LeaveCriticalSection(&g_PathLock);
            return NULL;
        }
        if (plen > 0 && path[plen - 1] != L';')
            path[plen++] = L';';
        memcpy(path + plen, NewDirectory, (SIZE_T) (dlen + 1) * sizeof(WCHAR));
        SetEnvironmentVariableW(L"PATH", path);
    }
    LeaveCriticalSection(&g_PathLock);

    // non-NULL simulated cookie, monotonically increasing
    return (PVOID) (ULONG_PTR) InterlockedIncrement(&g_Cookie);
}

__declspec(dllexport) BOOL WINAPI RemoveDllDirectory(PVOID Cookie)
{
    if (!Cookie)
        return FALSE;
    return TRUE;   // PATH entries intentionally left in place (fallback)
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void) hinst; (void) reason; (void) reserved;
    return TRUE;
}

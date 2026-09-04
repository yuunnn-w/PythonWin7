// ============================================================================
// TestWin8Api.dll -- test subject for the load-time import-rewrite engine.
//
// Statically imports from kernel32 three functions that are absent from a
// bare Win7 SP1 kernel32:
//
//   GetSystemTimePreciseAsFileTime   (Windows 8+)
//   GetCurrentThreadStackLimits      (Windows 8+)
//   IsWow64Process2                  (Windows 10 1511+)
//
// On a patched tree the PyKexBoot map hook rewrites this DLL's kernel32
// import descriptor to kxbase.dll in memory at load time, so it loads on
// Win7 with no file modification.  These three were picked because their
// KxBase implementations are self-contained (TEB read / NtQuerySystemTime /
// NtQueryInformationProcess) and work on both bare Win7 and modern Windows
// -- unlike e.g. Get/SetThreadDescription, which VxKex-NEXT 1.2.3.2462
// implements on top of NtQueryInformationThread(ThreadNameInformation)
// (Win10 1607+ only) and whose KxBase!GetThreadDescription is broken
// upstream (passes &Description instead of Description, stack corruption).
//
// Exported function CallWin8Apis() runs all three APIs and returns:
//   0 = all worked, 1/2/3 = failure stage.
//
// Build: CRT-free (only kernel32 imports besides the three test victims).
// ============================================================================

#include <windows.h>

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

__declspec(dllexport) int WINAPI CallWin8Apis(void)
{
    FILETIME ftPrecise, ftCoarse;
    ULONG_PTR lowLimit, highLimit;
    USHORT processMachine, nativeMachine;
    ULONGLONG precise, coarse, diff;
    int probe;

    // 1. GetSystemTimePreciseAsFileTime: must be sane (close to the
    //    coarse GetSystemTimeAsFileTime).
    GetSystemTimeAsFileTime(&ftCoarse);
    GetSystemTimePreciseAsFileTime(&ftPrecise);
    precise = ((ULONGLONG) ftPrecise.dwHighDateTime << 32) |
              ftPrecise.dwLowDateTime;
    coarse = ((ULONGLONG) ftCoarse.dwHighDateTime << 32) |
             ftCoarse.dwLowDateTime;
    if (!precise || !coarse)
        return 1;
    diff = precise > coarse ? precise - coarse : coarse - precise;
    if (diff > (ULONGLONG) 60 * 60 * 10000000)   // more than 1 hour apart
        return 1;

    // 2. GetCurrentThreadStackLimits: limits must bracket a live stack
    //    variable and be nonzero.
    lowLimit = 0;
    highLimit = 0;
    GetCurrentThreadStackLimits(&lowLimit, &highLimit);
    if (!lowLimit || !highLimit || lowLimit >= highLimit)
        return 2;
    if ((ULONG_PTR) &probe < lowLimit || (ULONG_PTR) &probe >= highLimit)
        return 2;

    // 3. IsWow64Process2: must succeed; native machine must be AMD64.
    processMachine = 0;
    nativeMachine = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &processMachine,
                         &nativeMachine))
        return 3;
    if (nativeMachine != IMAGE_FILE_MACHINE_AMD64)
        return 3;

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void) hinst; (void) reason; (void) reserved;
    return TRUE;
}

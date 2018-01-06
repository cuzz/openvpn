/**
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER within this package.
 */

#ifndef _INC_VERSIONHELPERS
#define _INC_VERSIONHELPERS

//#include <winapifamily.h>

//#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) && !defined(__WIDL__)

#ifdef __cplusplus
#define VERSIONHELPERAPI inline bool
#else
#define VERSIONHELPERAPI FORCEINLINE BOOL
#endif

#define _WIN32_WINNT_WINBLUE    0x0603
#define _WIN32_WINNT_WIN8    0x0602

VERSIONHELPERAPI IsWindowsVersionOrGreater(WORD major, WORD minor, WORD servpack)
{
    OSVERSIONINFOEXW vi = {sizeof(vi),major,minor,0,0,{0},servpack};
    return VerifyVersionInfoW(&vi, VER_MAJORVERSION|VER_MINORVERSION|VER_SERVICEPACKMAJOR,
        VerSetConditionMask(VerSetConditionMask(VerSetConditionMask(0,
            VER_MAJORVERSION,VER_GREATER_EQUAL),
            VER_MINORVERSION,VER_GREATER_EQUAL),
            VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL));
}

VERSIONHELPERAPI IsWindowsXPOrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0501), LOBYTE(0x0501), 0);
}

VERSIONHELPERAPI IsWindowsXPSP1OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0501), LOBYTE(0x0501), 1);
}

VERSIONHELPERAPI IsWindowsXPSP2OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0501), LOBYTE(0x0501), 2);
}

VERSIONHELPERAPI IsWindowsXPSP3OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0501), LOBYTE(0x0501), 3);
}

VERSIONHELPERAPI IsWindowsVistaOrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0600), LOBYTE(0x0600), 0);
}

VERSIONHELPERAPI IsWindowsVistaSP1OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0600), LOBYTE(0x0600), 1);
}

VERSIONHELPERAPI IsWindowsVistaSP2OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0600), LOBYTE(0x0600), 2);
}

VERSIONHELPERAPI IsWindows7OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0601), LOBYTE(0x0601), 0);
}

VERSIONHELPERAPI IsWindows7SP1OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(0x0601), LOBYTE(0x0601), 1);
}

VERSIONHELPERAPI IsWindows8OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN8), LOBYTE(_WIN32_WINNT_WIN8), 0);
}

VERSIONHELPERAPI IsWindows8Point1OrGreater(void) {
    return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINBLUE), LOBYTE(_WIN32_WINNT_WINBLUE), 0);
}

VERSIONHELPERAPI IsWindowsServer(void) {
    OSVERSIONINFOEXW vi = {sizeof(vi),0,0,0,0,{0},0,0,0,VER_NT_WORKSTATION};
    return !VerifyVersionInfoW(&vi, VER_PRODUCT_TYPE, VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL));
}

//#endif
#endif

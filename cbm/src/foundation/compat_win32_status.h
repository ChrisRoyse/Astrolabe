/*
 * compat_win32_status.h — Win32 status-code values on a non-Windows host.
 *
 * ASTROLABE targets aarch64-apple-darwin only (owner directive, 2026-08-02).
 * This header is NOT Windows support and does not reintroduce any.
 *
 * Why it exists: a large amount of otherwise portable diagnostic code records a
 * "native error" alongside every failure, and it spells those values with the
 * Win32 names because that is where the convention originated. Roughly a dozen
 * of those uses sit OUTSIDE any `_WIN32` guard — sentinel initialisers such as
 * `native_error = ERROR_SUCCESS` and `probe_native_error =
 * ERROR_INVALID_PARAMETER` in code that is genuinely platform-neutral.
 *
 * There were two ways to make that compile here: rewrite every scattered use
 * into a parallel set of portable spellings, or define the values once. The
 * first churns unrelated code across many call sites and risks changing a
 * recorded status by hand; this file is the second. One place to look, one
 * place to change.
 *
 * The values are the authentic <winerror.h> numbers, so a native error crossing
 * the FFI boundary or landing in a log means the same thing regardless of which
 * host produced it — which is the entire point of recording it.
 *
 * Deliberately absent: HANDLE, INVALID_HANDLE_VALUE, and every Win32 *function*.
 * Those are real API surface, not status values, and code needing them must stay
 * behind `#if defined(_WIN32)`.
 */
#ifndef CBM_COMPAT_WIN32_STATUS_H
#define CBM_COMPAT_WIN32_STATUS_H

#if !defined(_WIN32)

#define ERROR_SUCCESS 0UL
#define ERROR_FILE_NOT_FOUND 2UL
#define ERROR_PATH_NOT_FOUND 3UL
#define ERROR_ACCESS_DENIED 5UL
#define ERROR_INVALID_HANDLE 6UL
#define ERROR_NOT_ENOUGH_MEMORY 8UL
#define ERROR_INVALID_DATA 13UL
#define ERROR_OUTOFMEMORY 14UL
#define ERROR_NO_MORE_FILES 18UL
#define ERROR_CRC 23UL
#define ERROR_WRITE_FAULT 29UL
#define ERROR_GEN_FAILURE 31UL
#define ERROR_SHARING_VIOLATION 32UL
#define ERROR_LOCK_VIOLATION 33UL
#define ERROR_HANDLE_EOF 38UL
#define ERROR_NOT_SUPPORTED 50UL
#define ERROR_FILE_EXISTS 80UL
#define ERROR_INVALID_PARAMETER 87UL
#define ERROR_BUFFER_OVERFLOW 111UL
#define ERROR_INSUFFICIENT_BUFFER 122UL
#define ERROR_INVALID_NAME 123UL
#define ERROR_PROC_NOT_FOUND 127UL
#define ERROR_BUSY 170UL
#define ERROR_ALREADY_EXISTS 183UL
#define ERROR_FILENAME_EXCED_RANGE 206UL
#define ERROR_MORE_DATA 234UL
#define ERROR_ARITHMETIC_OVERFLOW 534UL
#define ERROR_ABANDONED_WAIT_0 735UL
#define ERROR_NO_UNICODE_TRANSLATION 1113UL
#define ERROR_USER_MAPPED_FILE 1224UL
#define ERROR_RETRY 1237UL
#define ERROR_FILE_CORRUPT 1392UL

/* Wait results. WAIT_OBJECT_0 is 0 and WAIT_ABANDONED is 0x80 on Windows; both
 * appear in platform-neutral comparisons against a recorded wait status. */
#define WAIT_OBJECT_0 0UL
#define WAIT_ABANDONED 128UL
#define WAIT_TIMEOUT 258UL

#endif /* !_WIN32 */

#endif /* CBM_COMPAT_WIN32_STATUS_H */

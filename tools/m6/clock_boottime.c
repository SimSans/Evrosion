// SPDX-License-Identifier: GPL-3.0-only
/* Explicit owned Linux/x86-64 QEMU clock profile. No host clock is written.
 * Redirects every imported process MONOTONIC read, not just RTC. Failure exits
 * this process, preventing QEMU's silent gettimeofday initialization fallback.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#if !defined(__linux__) || !defined(__x86_64__)
#error explicit Linux x86_64 profile required
#endif

static int audit_fd = -1;
static unsigned audit_count;
/* Keep the bounded witness for distinct imported callsites. GUI libraries may
 * read a clock thousands of times before QEMU initializes its own timer. Those
 * repeats must not consume all witness entries before the required QEMU call.
 * Each slot is immutable after release publication; a concurrent duplicate may
 * consume another slot, but neither waiting nor unbounded storage is needed.
 */
static struct {
    uintptr_t caller;
    clockid_t requested;
    unsigned ready; /* 0 = vacant, 1 = claimed, 2 = published */
} audit_keys[32];

static long raw_clock(clockid_t clock, struct timespec *value) {
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "0"((long)SYS_clock_gettime), "D"((long)clock), "S"(value)
        : "rcx", "r11", "memory", "cc");
    return result;
}

__attribute__((noreturn)) static void unavailable(void) {
    static const char text[] = "EVROSION_CLOCK_SOURCE_UNAVAILABLE boottime\n";
    long ignored;
    __asm__ volatile("syscall" : "=a"(ignored)
        : "0"((long)SYS_write), "D"(2L), "S"(text), "d"((long)(sizeof text - 1))
        : "rcx", "r11", "memory", "cc");
    __asm__ volatile("syscall" : "=a"(ignored)
        : "0"((long)SYS_exit_group), "D"(125L)
        : "rcx", "r11", "memory", "cc");
    __builtin_unreachable();
}

struct record {
    char magic[8];
    int32_t requested, actual;
    int64_t seconds, nanoseconds;
    uint64_t caller, sequence;
};
_Static_assert(sizeof(struct record) == 48, "fixed audit extent");

static void audit(clockid_t requested, clockid_t actual,
                  const struct timespec *value, uintptr_t caller) {
    int fd = __atomic_load_n(&audit_fd, __ATOMIC_ACQUIRE);
    if (fd < 0 || __atomic_load_n(&audit_count, __ATOMIC_RELAXED) >= 32) return;
    for (unsigned i = 0; i < 32; ++i) {
        if (__atomic_load_n(&audit_keys[i].ready, __ATOMIC_ACQUIRE) == 2
            && audit_keys[i].caller == caller
            && audit_keys[i].requested == requested) return;
    }
    unsigned slot;
    for (slot = 0; slot < 32; ++slot) {
        unsigned vacant = 0;
        if (__atomic_compare_exchange_n(&audit_keys[slot].ready, &vacant, 1,
                0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) break;
    }
    if (slot == 32) return;
    audit_keys[slot].caller = caller;
    audit_keys[slot].requested = requested;
    __atomic_store_n(&audit_keys[slot].ready, 2, __ATOMIC_RELEASE);
    unsigned sequence = __atomic_fetch_add(&audit_count, 1, __ATOMIC_RELAXED);
    if (sequence >= 32) return;
    struct record r = {{'E','V','C','L','K','B','0','2'}, requested, actual,
        value->tv_sec, value->tv_nsec, caller, sequence + 1};
    long written;
    __asm__ volatile("syscall" : "=a"(written)
        : "0"((long)SYS_write), "D"((long)fd), "S"(&r), "d"((long)sizeof r)
        : "rcx", "r11", "memory", "cc");
    if (written != (long)sizeof r) unavailable();
}

__attribute__((constructor)) static void initialize(void) {
    struct timespec value;
    if (raw_clock(CLOCK_BOOTTIME, &value) != 0) unavailable();
    /* The launcher supplies a new path beneath its private evidence directory.
     * Exclusive/no-follow creation refuses old, foreign and symlink state.
     * No ambient descriptor inheritance or process-global configuration is used.
     */
    const char *path = getenv("EVROSION_CLOCK_AUDIT_PATH");
    if (!path || path[0] != '/') unavailable();
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) unavailable();
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_nlink != 1
        || info.st_uid != geteuid() || (info.st_mode & 077)) unavailable();
    __atomic_store_n(&audit_fd, fd, __ATOMIC_RELEASE);
    /* This proves the constructor/source probe ran. The launcher separately
     * requires an actual QEMU imported MONOTONIC -> BOOTTIME callsite record.
     */
    audit(CLOCK_BOOTTIME, CLOCK_BOOTTIME, &value, 0);
}

__attribute__((visibility("default")))
int clock_gettime(clockid_t requested, struct timespec *value) {
    clockid_t actual = requested == CLOCK_MONOTONIC ? CLOCK_BOOTTIME : requested;
    long result = raw_clock(actual, value);
    if (result < 0) {
        if (requested == CLOCK_MONOTONIC) unavailable();
        errno = (int)-result;
        return -1;
    }
    audit(requested, actual, value, (uintptr_t)__builtin_return_address(0));
    return 0;
}

// POSIX 结构体/常量/Stdio 适配（Bionic -> Darwin）
#include "bionic_shim.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h>

// ---------------- errno ----------------
int* bionic_errno_slot(void) {
    static _Thread_local int slot;
    return &slot;
}
int darwin_to_bionic_errno(int d) {
    switch (d) {
        case 0: return 0;
        case EAGAIN: return 11;            // darwin 35 -> linux 11
        case EDEADLK: return 35;           // darwin 11 -> linux 35
        case ETIMEDOUT: return 110;
        case ENOTSUP: case EOPNOTSUPP: return 95;
        default: return d;
    }
}
int bionic_to_darwin_errno(int b) {
    switch (b) {
        case 11: return EAGAIN;
        case 35: return EDEADLK;
        case 110: return ETIMEDOUT;
        case 95: return EOPNOTSUPP;
        default: return b;
    }
}
int* bionic___errno(void) { return bionic_errno_slot(); }

// ---------------- stat 系列：逐字段翻译 ----------------
static void stat_to_bionic(const struct stat* ds, struct bionic_stat* bs) {
    memset(bs, 0, sizeof(*bs));
    bs->st_dev = ds->st_dev;
    bs->st_ino = ds->st_ino;
    bs->st_mode = (uint32_t)ds->st_mode;
    bs->st_nlink = (uint32_t)ds->st_nlink;
    bs->st_uid = ds->st_uid;
    bs->st_gid = ds->st_gid;
    bs->st_rdev = ds->st_rdev;
    bs->st_size = ds->st_size;
    bs->st_blksize = (int32_t)ds->st_blksize;
    bs->st_blocks = ds->st_blocks;
    bs->st_atim = ds->st_atimespec.tv_sec;   bs->st_atim_nsec = ds->st_atimespec.tv_nsec;
    bs->st_mtim = ds->st_mtimespec.tv_sec;   bs->st_mtim_nsec = ds->st_mtimespec.tv_nsec;
    bs->st_ctim = ds->st_ctimespec.tv_sec;   bs->st_ctim_nsec = ds->st_ctimespec.tv_nsec;
}
int bionic_stat(const char* p, struct bionic_stat* out) {
    struct stat ds;
    if (stat(p, &ds) != 0) return bionic_errno_slot() ? (*bionic_errno_slot() = darwin_to_bionic_errno(errno), -1) : -1;
    stat_to_bionic(&ds, out);
    return 0;
}
int bionic_lstat(const char* p, struct bionic_stat* out) {
    struct stat ds;
    if (lstat(p, &ds) != 0) return -1;
    stat_to_bionic(&ds, out);
    return 0;
}
int bionic_fstat(int fd, struct bionic_stat* out) {
    struct stat ds;
    if (fstat(fd, &ds) != 0) return -1;
    stat_to_bionic(&ds, out);
    return 0;
}
int bionic_statvfs(const char* p, struct bionic_statvfs* out) {
    struct statvfs ds;
    if (statvfs(p, &ds) != 0) return -1;
    memset(out, 0, sizeof(*out));
    out->f_bsize = ds.f_bsize; out->f_frsize = ds.f_frsize;
    out->f_blocks = ds.f_blocks; out->f_bfree = ds.f_bfree; out->f_bavail = ds.f_bavail;
    out->f_files = ds.f_files; out->f_ffree = ds.f_ffree; out->f_favail = ds.f_favail;
    out->f_fsid = ds.f_fsid; out->f_flag = ds.f_flag; out->f_namemax = ds.f_namemax;
    return 0;
}

// ---------------- mmap 标志位翻译 ----------------
// Darwin: MAP_ANON=0x1000, MAP_FIXED=0x10；Linux: MAP_ANONYMOUS=0x20, MAP_FIXED=0x10
void* bionic_mmap(void* addr, size_t len, int prot, int flags, int fd, long off) {
    int f = flags;
    if (flags & 0x20) { f &= ~0x20; f |= MAP_ANON; }
    return mmap(addr, len, prot, f, fd, off);
}
int bionic_munmap(void* addr, size_t len) { return munmap(addr, len); }
int bionic_madvise(void* addr, size_t len, int adv) { return madvise(addr, len, adv); }

// ---------------- stdio 伪 FILE ----------------
// Bionic 的 __sF 是 3 个内联 FILE 结构；这里只提供地址空间，实参仍交给 libc。
// 但 stdout/stderr 这两个**变量**必须真的指向 Darwin 的流：guest 里
// fprintf(stderr, ...) 会先读这个指针再解引用，留 0 就是立刻段错误。
static unsigned char g_sF[3 * 512];
void* bionic___sF = g_sF;
FILE* bionic_stdout = (FILE*)0;
FILE* bionic_stderr = (FILE*)0;
__attribute__((constructor)) static void bionic_stdio_init(void) {
    bionic_stdout = stdout;
    bionic_stderr = stderr;
}

// ---------------- 其它 Linux 专有 ----------------
unsigned long bionic_getauxval(unsigned long type) {
    (void)type; return 0;                      // AT_HWCAP 等一律 0，glslang 不依赖
}
int bionic_fallocate(int fd, int mode, long off, long len) {
    (void)mode;
    return ftruncate(fd, off + len) == 0 ? 0 : -1;   // 近似实现
}
long bionic_sendfile(int out_fd, int in_fd, long* offp, unsigned long count) {
    static char buf[65536];
    long total = 0;
    while ((unsigned long)total < count) {
        size_t want = count - total > sizeof(buf) ? sizeof(buf) : (size_t)(count - total);
        ssize_t n = read(in_fd, buf, want);
        if (n <= 0) break;
        ssize_t w = write(out_fd, buf, (size_t)n);
        if (w <= 0) break;
        total += w;
    }
    if (offp) *offp += total;
    return total;
}

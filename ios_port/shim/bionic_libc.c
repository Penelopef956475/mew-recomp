// libbionic_shim 的 libc/stdio 大补丁：把 shim_symbols.txt 里剩下那些
// 「Darwin 有等价物」和「glibc 风格的 __xxx_chk」一次性补齐。
//
// 三条原则：
//   1) 只做形参/返回值层面的翻译，绝不改动调用约定 —— 否则调用方栈会歪；
//   2) 变参函数不在这里实现（必须走 bionic_varargs.S 的 thunk 把 x0..x7/d0..d7
//      落到栈上再重排），这里只做 va_list 版本；
//   3) 明显不兼容却一定要有符号的（syscall / dl_iterate_phdr）宁可再生一个
//      失败值也不要漏符号 —— 漏符号会在 dlopen 阶段直接 "symbol not found"。
#include "bionic_shim.h"
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#if __has_include(<xlocale.h>)
#include <xlocale.h>
#endif
#include <wchar.h>

// ================= 文件 IO：签名与 Darwin 一致，纯透传 =================
// open/openat 的第三个参数（mode）只在带 O_CREAT 时有效，多读一个寄存器无害。
int bionic_open(const char* p, int flags, int mode) { return open(p, flags, mode); }
int bionic_openat(int dfd, const char* p, int flags, int mode) { return openat(dfd, p, flags, mode); }
int bionic_close(int fd) { return close(fd); }
ssize_t bionic_read(int fd, void* b, size_t n) { return read(fd, b, n); }
ssize_t bionic_write(int fd, const void* b, size_t n) { return write(fd, b, n); }
ssize_t bionic_pread(int fd, void* b, size_t n, off_t o) { return pread(fd, b, n, o); }
ssize_t bionic_pwrite(int fd, const void* b, size_t n, off_t o) { return pwrite(fd, b, n, o); }
off_t   bionic_lseek(int fd, off_t o, int w) { return lseek(fd, o, w); }
int     bionic_fsync(int fd) { return fsync(fd); }
int     bionic_ftruncate(int fd, off_t n) { return ftruncate(fd, n); }
int     bionic_truncate(const char* p, off_t n) { return truncate(p, n); }
int     bionic_rename(const char* a, const char* b) { return rename(a, b); }
int     bionic_unlink(const char* p) { return unlink(p); }
int     bionic_rmdir(const char* p) { return rmdir(p); }
int     bionic_mkdir(const char* p, mode_t m) { return mkdir(p, m); }
int     bionic_chdir(const char* p) { return chdir(p); }
char*   bionic_getcwd(char* b, size_t n) { return getcwd(b, n); }
int     bionic_access(const char* p, int m) { return access(p, m); }
char*   bionic_realpath(const char* p, char* out) { return realpath(p, out); }
ssize_t bionic_readlink(const char* p, char* b, size_t n) { return readlink(p, b, n); }
int     bionic_utimensat(int dfd, const char* p, const struct timespec t[2], int f) {
    return utimensat(dfd, p, t, f);
}
int     bionic_sysconf(int name) { return (int)sysconf(name); }

// ================= 目录：bionic_dirent 布局与 Darwin 不同，必须逐条翻译 =================
static _Thread_local struct bionic_dirent g_de;
struct bionic_dirent* bionic_readdir(DIR* d) {
    struct dirent* e = readdir(d);
    if (!e) return NULL;
    memset(&g_de, 0, sizeof(g_de));
    g_de.d_ino = (uint64_t)e->d_ino;
    g_de.d_off = 0;
    g_de.d_reclen = (uint16_t)(sizeof(g_de.d_ino) + sizeof(g_de.d_off) +
                               sizeof(g_de.d_reclen) + sizeof(g_de.d_type) +
                               strlen(e->d_name) + 1);
    g_de.d_type = (uint8_t)e->d_type;      // DT_* 数值 Linux/Darwin 基本一致
    strlcpy(g_de.d_name, e->d_name, sizeof(g_de.d_name));
    return &g_de;
}
DIR* bionic_opendir(const char* p) { return opendir(p); }
DIR* bionic_fdopendir(int fd) { return fdopendir(fd); }
int  bionic_closedir(DIR* d) { return closedir(d); }

// ================= stdio =================
FILE* bionic_fopen(const char* p, const char* m) { return fopen(p, m); }
int   bionic_fclose(FILE* f) { return fclose(f); }
int   bionic_fflush(FILE* f) { return fflush(f); }
size_t bionic_fread(void* b, size_t s, size_t n, FILE* f) { return fread(b, s, n, f); }
size_t bionic_fwrite(const void* b, size_t s, size_t n, FILE* f) { return fwrite(b, s, n, f); }
int   bionic_fputc(int c, FILE* f) { return fputc(c, f); }
int   bionic_fputs(const char* s, FILE* f) { return fputs(s, f); }
int   bionic_puts(const char* s) { return puts(s); }
int   bionic_putchar(int c) { return putchar(c); }
int   bionic_fseek(FILE* f, long o, int w) { return fseek(f, o, w); }
int   bionic_fseeko(FILE* f, off_t o, int w) { return fseeko(f, o, w); }
off_t bionic_ftello(FILE* f) { return ftello(f); }
char* bionic_strerror(int e) { return strerror(e); }

// strerror_r：Darwin 是 POSIX 的 int 版本，与 bionic 一致
int bionic_strerror_r(int e, char* buf, size_t n) { return strerror_r(e, buf, n); }

long double bionic_strtold(const char* s, char** end) { return strtold(s, end); }
long double bionic_strtold_l(const char* s, char** end, locale_t loc) { return strtold_l(s, end, loc); }
long double bionic_wcstold(const wchar_t* s, wchar_t** end) { return wcstold(s, end); }

// ================= 时间 =================
// clockid 数值两边不同：Linux CLOCK_REALTIME=0 / MONOTONIC=1 / PROCESS_CPUTIME=2 /
// MONOTONIC_RAW=4 / BOOTTIME=7；Darwin 走的是它的 CLOCK_* 语义，这里只翻译常用的。
int bionic_clock_gettime(int clk, struct timespec* ts) {
    clockid_t d;
    switch (clk) {
        case 0: d = CLOCK_REALTIME; break;
        case 1: d = CLOCK_MONOTONIC; break;
        case 2: d = CLOCK_PROCESS_CPUTIME_ID; break;
        case 3: d = CLOCK_THREAD_CPUTIME_ID; break;
        default: d = CLOCK_MONOTONIC; break;   // 4/7 等退回单调钟
    }
    return clock_gettime(d, ts);
}
int bionic_nanosleep(const struct timespec* req, struct timespec* rem) { return nanosleep(req, rem); }
struct tm* bionic_gmtime_r(const time_t* t, struct tm* out) { return gmtime_r(t, out); }
struct tm* bionic_localtime_r(const time_t* t, struct tm* out) { return localtime_r(t, out); }

// ================= glibc/bionic 的 __xxx_chk：直接降级成普通版本 =================
void* bionic___memcpy_chk(void* d, const void* s, size_t n, size_t bl) { (void)bl; return memcpy(d, s, n); }
void* bionic___memmove_chk(void* d, const void* s, size_t n, size_t bl) { (void)bl; return memmove(d, s, n); }
char* bionic___strcat_chk(char* d, const char* s, size_t bl) { (void)bl; return strcat(d, s); }
char* bionic___strncat_chk(char* d, const char* s, size_t n, size_t bl) { (void)bl; return strncat(d, s, n); }
size_t bionic___strlen_chk(const char* s, size_t bl) { (void)bl; return strlen(s); }
char* bionic___strchr_chk(const char* s, int c, size_t bl) { (void)bl; return strchr(s, c); }
char* bionic___strrchr_chk(const char* s, int c, size_t bl) { (void)bl; return strrchr(s, c); }
void bionic___stack_chk_fail(void) {
    fprintf(stderr, "[shim] *** stack smashing detected ***\n");
    abort();
}
size_t bionic___fwrite_chk(const void* p, size_t s, size_t n, FILE* f, size_t bl) { (void)bl; return fwrite(p, s, n, f); }
ssize_t bionic___read_chk(int fd, void* b, size_t n, size_t bl) { (void)bl; return read(fd, b, n); }
ssize_t bionic___write_chk(int fd, const void* b, size_t n, size_t bl) { (void)bl; return write(fd, b, n); }
ssize_t bionic___pread_chk(int fd, void* b, size_t n, off_t o, size_t bl) { (void)bl; return pread(fd, b, n, o); }
ssize_t bionic___pwrite_chk(int fd, const void* b, size_t n, off_t o, size_t bl) { (void)bl; return pwrite(fd, b, n, o); }
int bionic___open_2(const char* p, int flags) { return open(p, flags); }
// 注意：ap 是**指向 bionic 32 字节 va_list 的地址**（AAPCS64 里超过 16 字节的
// 复合参数按引用传），不能当成 Darwin 的 char* 直接甩给 vsnprintf。
int bionic___vsnprintf_chk(char* s, size_t n, int flag, size_t bl, const char* f, void* ap) {
    (void)flag; (void)bl; return mew_vararg_vsnprintf(s, n, f, (BionicVaList*)ap);
}
int bionic___vsprintf_chk(char* s, int flag, size_t bl, const char* f, void* ap) {
    (void)flag; (void)bl;
    return mew_vararg_vsnprintf(s, (size_t)-1, f, (BionicVaList*)ap);
}
int bionic_vfprintf(void* f, const char* fmt, void* ap) {
    return mew_vararg_vfprintf(f, fmt, (BionicVaList*)ap);
}
int bionic_vsnprintf(char* s, size_t n, const char* fmt, void* ap) {
    return mew_vararg_vsnprintf(s, n, fmt, (BionicVaList*)ap);
}
int bionic_vasprintf(char** out, const char* fmt, void* ap) {
    return mew_vararg_vasprintf(out, fmt, (BionicVaList*)ap);
}
int bionic_vsscanf(const char* s, const char* fmt, void* ap) {
    return mew_vararg_vsscanf(s, fmt, (BionicVaList*)ap);
}
void bionic_openlog(const char* ident, int opt, int facility) {
    (void)opt; (void)facility;
    if (ident) fprintf(stderr, "[openlog] %s\n", ident);
}

// ================= C++ 运行时 / atfork =================
extern int __cxa_atexit(void (*)(void*), void*, void*);
extern void __cxa_finalize(void*);
int  bionic___cxa_atexit(void (*fn)(void*), void* arg, void* dso) { return __cxa_atexit(fn, arg, dso); }
void bionic___cxa_finalize(void* dso) { __cxa_finalize(dso); }
int  bionic___register_atfork(void (*prep)(void), void (*parent)(void), void (*child)(void), void* dso) {
    (void)dso; return pthread_atfork(prep, parent, child);
}
// 线程退出时的析构：Linux 的 __cxa_thread_atexit_impl 用 TLS dtor；
// Darwin 没有同名 API，用 pthread key 析构模拟（足够跑游戏里的 thread_local）。
#define MEW_MAX_TLS_DTORS 64
typedef struct { void (*fn)(void*); void* arg; } mew_tls_dtor;
static _Thread_local mew_tls_dtor g_tls_dtors[MEW_MAX_TLS_DTORS];
static _Thread_local int g_tls_n;
static pthread_key_t g_tls_key;
static pthread_once_t g_tls_once = PTHREAD_ONCE_INIT;
static void mew_tls_run(void* p) {
    (void)p;
    while (g_tls_n > 0) { mew_tls_dtor d = g_tls_dtors[--g_tls_n]; d.fn(d.arg); }
}
static void mew_tls_key_init(void) { pthread_key_create(&g_tls_key, mew_tls_run); }
int bionic___cxa_thread_atexit_impl(void (*fn)(void*), void* arg, void* dso) {
    (void)dso;
    pthread_once(&g_tls_once, mew_tls_key_init);
    if (g_tls_n >= MEW_MAX_TLS_DTORS) return -1;
    g_tls_dtors[g_tls_n].fn = fn;
    g_tls_dtors[g_tls_n].arg = arg;
    g_tls_n++;
    pthread_setspecific(g_tls_key, g_tls_dtors);
    return 0;
}

// ================= 其它 =================
size_t bionic___ctype_get_mb_cur_max(void) { return MB_CUR_MAX; }

// dl_iterate_phdr：Darwin 没有这个 API（<link.h> 都不存在），但 guest 里的
// libgcc/libc++ 会用它找自己的 PT_GNU_EH_FRAME，用来注册 .eh_frame 的 unwind 表。
// 我们手里没有真实 program header，就按 ElF 布局**静态构造 2 条**：
//   #0 PT_LOAD(R|X) 覆盖整个 __TEXT（平移后 0x443c000）
//   #1 PT_GNU_EH_FRAME 指向 __eh_frame（0x48e4d0，大小 0x15f0c）
// 这两个数是 converter 实测出来的：原 ELF GNU_EH_FRAME 在 0x48a4d0，统一 +0x4000。
// 宿主 dlopen 成功后调 mew_eh_register_image() 把真实基址传进来。
static uintptr_t g_mew_image_base = 0;
void mew_eh_register_image(uintptr_t base) { g_mew_image_base = base; }

struct mew_elf64_phdr {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};
struct bionic_dl_phdr_info {
    uint64_t dlpi_addr;
    const char* dlpi_name;
    const struct mew_elf64_phdr* dlpi_phdr;
    uint16_t dlpi_phnum;
};

#define MEW_TEXT_SIZE     0x443c000ULL
#define MEW_EHFRAME_OFF   0x48e4d0ULL
#define MEW_EHFRAME_SIZE  0x15f0cULL

int bionic_dl_iterate_phdr(int (*cb)(struct bionic_dl_phdr_info*, size_t, void*), void* data) {
    if (!cb || !g_mew_image_base) return 0;
    static const struct mew_elf64_phdr phdrs[2] = {
        { 1 /*PT_LOAD*/, 5 /*R|X*/, 0, 0, 0, MEW_TEXT_SIZE, MEW_TEXT_SIZE, 0x4000 },
        { 0x6474e550 /*PT_GNU_EH_FRAME*/, 4 /*R*/,
          MEW_EHFRAME_OFF, MEW_EHFRAME_OFF, MEW_EHFRAME_OFF,
          MEW_EHFRAME_SIZE, MEW_EHFRAME_SIZE, 4 },
    };
    struct bionic_dl_phdr_info info;
    info.dlpi_addr = (uint64_t)g_mew_image_base;
    info.dlpi_name = "libmew_relinked.dylib";
    info.dlpi_phdr = phdrs;
    info.dlpi_phnum = 2;
    return cb(&info, sizeof info, data);
}

// syscall()：Linux 的调用号在 Darwin 完全无效，只补两个真正被用到的：
//   SYS_gettid(178)       -> pthread_threadid_np
//   SYS_memfd_create(279) -> ENOSYS，让引擎走自带的 [lowmem] 降级分支
long bionic_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    if (n == 178) {
        uint64_t tid = 0;
        pthread_threadid_np(NULL, &tid);
        return (long)tid;
    }
    errno = ENOSYS;
    return -1;
}

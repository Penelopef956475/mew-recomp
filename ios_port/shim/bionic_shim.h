// libbionic_shim —— Android NDK (Bionic) ABI 到 Apple Darwin 的适配层
// 只覆盖 libmew_relinked.dylib 里「非 SDL3 / 非直连」的 132 个符号。
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------- Bionic 结构体尺寸（AArch64 Android） ----------------
// pthread_mutex_t 40B / pthread_cond_t 48B / pthread_rwlock_t 56B / pthread_attr_t 56B
#define BIONIC_MUTEX_SIZE   40
#define BIONIC_COND_SIZE    48
#define BIONIC_RWLOCK_SIZE  56
#define BIONIC_ATTR_SIZE    56
#define BIONIC_MUTEX_INIT   0x40000000u   // Bionic PTHREAD_MUTEX_INITIALIZER 首个 word

// ---------------- Bionic errno 数值（与 Darwin 不同的那几个） ----------------
// Darwin:  EAGAIN 35, EDEADLK 11, ETIMEDOUT 60, ENOTSUP 45, EOPNOTSUPP 102
// Linux:   EAGAIN 11, EDEADLK 35, ETIMEDOUT 110, ENOTSUP 95, EOPNOTSUPP 95
int *bionic_errno_slot(void);            // 返回线程局部 int*（Bionic 语义）
int  darwin_to_bionic_errno(int d);
int  bionic_to_darwin_errno(int b);

// ---------------- Bionic AArch64 va_list（32 字节结构体） ----------------
// q0..q7 保存区每槽 16 字节，所以 __vr_offs 步长是 16（不是 8）。
typedef struct {
    uint8_t* __stack;
    uint8_t* __gr_top;
    uint8_t* __vr_top;
    int      __gr_offs;
    int      __vr_offs;
} BionicVaList;

// 把 bionic va_list 重排成 Darwin 的扁平槽数组，再由调用方转给 v*printf
int mew_va_build_from_bionic(uint64_t* out, int cap, const char* fmt, BionicVaList* ap);
int mew_vararg_vfprintf(void* f, const char* fmt, BionicVaList* ap);
int mew_vararg_vsnprintf(char* buf, size_t n, const char* fmt, BionicVaList* ap);
int mew_vararg_vasprintf(char** out, const char* fmt, BionicVaList* ap);
int mew_vararg_vsscanf(const char* str, const char* fmt, BionicVaList* ap);

// ---------------- Bionic 结构体（只列用到的字段布局） ----------------
// Linux arm64 struct stat（严格 128B，字段偏移见下方断言）
struct bionic_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint64_t __pad1;
    int64_t  st_size;
    int32_t  st_blksize;
    int32_t  __pad2;
    int64_t  st_blocks;
    // 注意：字段名不能叫 st_atime —— Darwin 的 <sys/stat.h> 把它定义成
    // #define st_atime st_atimespec.tv_sec，会把任何结构体的这个字段展开成
    // 不存在的 st_atimespec。叫 st_atim 就没冲突（Linux 官方名也是 st_atim）。
    int64_t  st_atim;
    uint64_t st_atim_nsec;
    int64_t  st_mtim;
    uint64_t st_mtim_nsec;
    int64_t  st_ctim;
    uint64_t st_ctim_nsec;
    uint32_t __unused4;
    uint32_t __unused5;
};

_Static_assert(sizeof(struct bionic_stat) == 128, "Linux arm64 struct stat must be 128B");
_Static_assert(offsetof(struct bionic_stat, st_size) == 48, "st_size offset must be 48");
_Static_assert(offsetof(struct bionic_stat, st_blksize) == 56, "st_blksize offset must be 56");
_Static_assert(offsetof(struct bionic_stat, st_blocks) == 64, "st_blocks offset must be 64");
_Static_assert(offsetof(struct bionic_stat, st_atim) == 72, "st_atim offset must be 72");

// Linux arm64 struct dirent（d_name 256B）
struct bionic_dirent {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[256];
};

// Linux arm64 statvfs
struct bionic_statvfs {
    uint64_t f_bsize, f_frsize, f_blocks, f_bfree, f_bavail;
    uint64_t f_files, f_ffree, f_favail, f_fsid, f_flag, f_namemax;
    uint32_t __f_spare[6];
};

#ifdef __cplusplus
}
#endif

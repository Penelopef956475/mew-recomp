// 变参桥 C 侧：AAPCS64(x0..x7 / d0..d7 / 栈上第 9 个起) -> Darwin 扁平 va_list
#include "bionic_shim.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>

// 取下一个参数：前 8 个在寄存器槽；第 9 个起落在调用方栈上，
// 整数与浮点共用同一个顺序栈游标（AAPCS64 规定栈上参数按出现顺序排）。
static uint64_t pick(const uint64_t* reg, int* idx, const uint64_t* stack, int stack_n, int* si) {
    int i = *idx;
    uint64_t v;
    if (i < 8) {
        v = reg[i];
    } else {
        v = (stack && *si < stack_n) ? stack[(*si)++] : 0;
    }
    (*idx)++;
    return v;
}

int mew_vararg_build(uint64_t* out, int cap, const char* fmt,
                     const uint64_t* x, int xi, const uint64_t* d, int di,
                     const uint64_t* stack_args, int stack_n) {
    int n = 0;
    int si = 0;                  // 整数/浮点共用的栈参数游标
    const char* p = fmt;
    while (p && *p && n < cap) {
        if (*p != '%') { p++; continue; }
        p++;
        if (*p == '%') { p++; continue; }
        while (*p && strchr("-+ #0'", *p)) p++;
        // 动态宽度 %*d / %.*f：先从整数槽吃一个
        if (*p == '*') { out[n++] = pick(x, &xi, stack_args, stack_n, &si); p++; }
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') {
            p++;
            if (*p == '*') { out[n++] = pick(x, &xi, stack_args, stack_n, &si); p++; }
            while (*p >= '0' && *p <= '9') p++;
        }
        while (*p && strchr("hljztLq", *p)) p++;
        char conv = *p ? *p++ : 0;
        int is_fp = (conv=='f'||conv=='F'||conv=='e'||conv=='E'||conv=='g'||conv=='G'||conv=='a'||conv=='A');
        if (is_fp) out[n++] = pick(d, &di, stack_args, stack_n, &si);
        else        out[n++] = pick(x, &xi, stack_args, stack_n, &si);
    }
    return n;
}

int mew_vararg_snprintf(const uint64_t* x, const uint64_t* d, const uint64_t* stk) {
    char* buf = (char*)(uintptr_t)x[0];
    size_t cap = (size_t)x[1];
    const char* fmt = (const char*)(uintptr_t)x[2];
    uint64_t flat[32];
    mew_vararg_build(flat, 32, fmt, x, 3, d, 0, stk, 16);
    return vsnprintf(buf, cap, fmt, (va_list)flat);
}

int mew_vararg_android_log_print(const uint64_t* x, const uint64_t* d, const uint64_t* stk) {
    const char* tag = (const char*)(uintptr_t)x[1];
    const char* fmt = (const char*)(uintptr_t)x[2];
    uint64_t flat[32];
    mew_vararg_build(flat, 32, fmt, x, 3, d, 0, stk, 16);
    fprintf(stderr, "[%s] ", tag ? tag : "?");
    vfprintf(stderr, fmt, (va_list)flat);
    fputc('\n', stderr);
    return 0;
}

// ---------------- Linux AArch64 va_list -> Darwin 扁平 va_list ----------------
// Bionic va_list 是 32 字节结构体；q0..q7 保存区每槽 16 字节（不是 8！）。
static uint64_t mew_next_int(BionicVaList* b) {
    if (b->__gr_offs < 0) {
        uint64_t v = *(uint64_t*)(b->__gr_top + b->__gr_offs);
        b->__gr_offs += 8;
        return v;
    }
    uint64_t v = *(uint64_t*)b->__stack;
    b->__stack += 8;
    return v;
}
static uint64_t mew_next_fp(BionicVaList* b) {
    if (b->__vr_offs < 0) {
        uint64_t v = *(uint64_t*)(b->__vr_top + b->__vr_offs);   // 每槽 16 字节，只取低 8
        b->__vr_offs += 16;
        return v;
    }
    uint64_t v = *(uint64_t*)b->__stack;
    b->__stack += 8;
    return v;
}
// 把 bionic __builtin_va_list（已在调用方栈上）重排成 Darwin 的 flat[]
int mew_va_build_from_bionic(uint64_t* out, int cap, const char* fmt, BionicVaList* ap) {
    int n = 0;
    const char* p = fmt;
    while (p && *p && n < cap) {
        if (*p != '%') { p++; continue; }
        p++;
        if (*p == '%') { p++; continue; }
        while (*p && strchr("-+ #0'", *p)) p++;
        if (*p == '*') { out[n++] = mew_next_int(ap); p++; }
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') {
            p++;
            if (*p == '*') { out[n++] = mew_next_int(ap); p++; }
            while (*p >= '0' && *p <= '9') p++;
        }
        while (*p && strchr("hljztLq", *p)) p++;
        char conv = *p ? *p++ : 0;
        int is_fp = (conv=='f'||conv=='F'||conv=='e'||conv=='E'||conv=='g'||conv=='G'||conv=='a'||conv=='A');
        out[n++] = is_fp ? mew_next_fp(ap) : mew_next_int(ap);
    }
    return n;
}

// vfprintf(FILE*, fmt, va_list)：bionic 的 va_list 是结构体指针
int mew_vararg_vfprintf(void* f, const char* fmt, BionicVaList* ap) {
    uint64_t flat[32];
    mew_va_build_from_bionic(flat, 32, fmt, ap);
    return vfprintf((FILE*)f, fmt, (va_list)flat);
}
int mew_vararg_vsnprintf(char* buf, size_t n, const char* fmt, BionicVaList* ap) {
    uint64_t flat[32];
    mew_va_build_from_bionic(flat, 32, fmt, ap);
    return vsnprintf(buf, n, fmt, (va_list)flat);
}
int mew_vararg_vasprintf(char** out, const char* fmt, BionicVaList* ap) {
    uint64_t flat[32];
    mew_va_build_from_bionic(flat, 32, fmt, ap);
    return vasprintf(out, fmt, (va_list)flat);
}

// ---------------- scanf 家族：可变参数全是指针，只走整数槽 ----------------
// %f/%lf 传的也是 float*/double*，所以永远不碰 d0..d7。
// 只需要数出「非 %% 、非赋值抑制 %*」的转换个数，按顺序取指针即可。
int mew_vararg_sscanf(const uint64_t* x, const uint64_t* stack_args) {
    const char* str = (const char*)(uintptr_t)x[0];
    const char* fmt = (const char*)(uintptr_t)x[1];
    uint64_t flat[32];
    int n = 0, xi = 0, si = 0;
    const char* p = fmt;
    while (p && *p && n < 30) {
        if (*p != '%') { p++; continue; }
        p++;
        if (*p == '%') { p++; continue; }         // 字面量 %
        int suppress = (*p == '*');                // %*d：赋值抑制，不消费参数
        if (suppress) p++;
        while (*p && strchr("-+ #0'", *p)) p++;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') { p++; while (*p >= '0' && *p <= '9') p++; }
        while (*p && strchr("hljztLq", *p)) p++;
        if (*p == '[') {                           // %[...] 字符集扫描
            p++;
            if (*p == '^') p++;
            if (*p == ']') p++;
            while (*p && *p != ']') p++;
            if (*p == ']') p++;
        } else if (*p) {
            p++;                                   // 普通转换字符
        }
        if (!suppress) {
            uint64_t v;
            if (xi < 6) v = x[2 + xi];             // x0=str, x1=fmt
            else v = stack_args[si < 16 ? si : 15];
            if (xi < 6) xi++; else si++;
            flat[n++] = v;
        }
    }
    return vsscanf(str, fmt, (va_list)flat);
}

// ---------------- 剩下几个变参入口（由 bionic_varargs.S 的 thunk 调用） ----------------
int mew_vararg_printf(const uint64_t* x, const uint64_t* d, const uint64_t* stk) {
    const char* fmt = (const char*)(uintptr_t)x[0];
    uint64_t flat[32];
    mew_vararg_build(flat, 32, fmt, x, 1, d, 0, stk, 16);
    return vfprintf(stdout, fmt, (va_list)flat);
}
int mew_vararg_fprintf(const uint64_t* x, const uint64_t* d, const uint64_t* stk) {
    FILE* f = (FILE*)(uintptr_t)x[0];
    const char* fmt = (const char*)(uintptr_t)x[1];
    uint64_t flat[32];
    mew_vararg_build(flat, 32, fmt, x, 2, d, 0, stk, 16);
    return vfprintf(f, fmt, (va_list)flat);
}
int mew_vararg_syslog(const uint64_t* x, const uint64_t* d, const uint64_t* stk) {
    int prio = (int)x[0];
    const char* fmt = (const char*)(uintptr_t)x[1];
    uint64_t flat[32];
    mew_vararg_build(flat, 32, fmt, x, 2, d, 0, stk, 16);
    fprintf(stderr, "[syslog%d] ", prio);
    return vfprintf(stderr, fmt, (va_list)flat);
}
int mew_vararg_swprintf(const uint64_t* x, const uint64_t* d, const uint64_t* stk) {
    wchar_t* buf = (wchar_t*)(uintptr_t)x[0];
    size_t cap = (size_t)x[1];
    const wchar_t* fmt = (const wchar_t*)(uintptr_t)x[2];
    uint64_t flat[32];
    // 宽字符格式串：只需要按 % 数量顺序取值，直接复用整数/浮点槽扫描
    char narrow[512];
    size_t i = 0;
    for (; fmt[i] && i < sizeof(narrow) - 1; i++) narrow[i] = (char)fmt[i];
    narrow[i] = 0;
    mew_vararg_build(flat, 32, narrow, x, 3, d, 0, stk, 16);
    return vswprintf(buf, cap, fmt, (va_list)flat);
}
int mew_vararg_vsscanf(const char* str, const char* fmt, BionicVaList* ap) {
    uint64_t flat[32];
    int n = 0;
    const char* p = fmt;
    while (p && *p && n < 30) {
        if (*p != '%') { p++; continue; }
        p++;
        if (*p == '%') { p++; continue; }
        int suppress = (*p == '*');
        if (suppress) p++;
        while (*p && strchr("-+ #0'", *p)) p++;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') { p++; while (*p >= '0' && *p <= '9') p++; }
        while (*p && strchr("hljztLq", *p)) p++;
        if (*p == '[') {
            p++;
            if (*p == '^') p++;
            if (*p == ']') p++;
            while (*p && *p != ']') p++;
            if (*p == ']') p++;
        } else if (*p) {
            p++;
        }
        if (!suppress) flat[n++] = mew_next_int(ap);   // 扫描目标全是指针，只走整数槽
    }
    return vsscanf(str, fmt, (va_list)flat);
}

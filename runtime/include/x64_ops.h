#pragma once
// 标志位与运算辅助（方案书：标志位惰性/按需计算，交给 Clang DCE）
#include <cstdint>
#include "x64_runtime.h"

static inline void set_zsp(X64Ctx* c, uint64_t r, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    r &= mask;
    c->zf = (r == 0);
    c->pf = (__builtin_parity((unsigned)(r & 0xFF)) == 0);  // PF：低字节偶数个 1
    c->sf = ((r >> (width * 8 - 1)) & 1) != 0;
}

static inline uint64_t add_flags(X64Ctx* c, uint64_t a, uint64_t b, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    uint64_t r = (a + b) & mask;
    set_zsp(c, r, width);
    c->cf = ((a & mask) + (b & mask)) > mask;
    uint64_t signbit = 1ULL << (width * 8 - 1);
    c->of = (((a ^ r) & (b ^ r)) & signbit) != 0;
    return r;
}

static inline uint64_t sub_flags(X64Ctx* c, uint64_t a, uint64_t b, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    uint64_t r = (a - b) & mask;
    set_zsp(c, r, width);
    c->cf = (a & mask) < (b & mask);
    uint64_t signbit = 1ULL << (width * 8 - 1);
    c->of = (((a ^ b) & (a ^ r)) & signbit) != 0;
    return r;
}

static inline uint64_t sbb_flags(X64Ctx* c, uint64_t a, uint64_t b, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    uint64_t borrow = c->cf ? 1ULL : 0ULL;
    uint64_t sub = (b + borrow) & mask;
    uint64_t r = (a - sub) & mask;
    set_zsp(c, r, width);
    c->cf = (a & mask) < sub;
    uint64_t signbit = 1ULL << (width * 8 - 1);
    c->of = (((a ^ b) & (a ^ r)) & signbit) != 0;
    return r;
}

static inline uint64_t logic_flags(X64Ctx* c, uint64_t r, int width) {
    c->cf = false;
    c->of = false;
    set_zsp(c, r, width);
    return r;
}

// 写寄存器：32 位写清零高 32 位；8/16 位写保留高位（方案书硬性要求）
// CPUID / RDTSC：x86 宿主用真实指令，其它架构返回稳定占位值
static inline void x64_cpuid(uint32_t leaf, uint32_t sub,
                             uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(leaf), "c"(sub));
    *a = eax; *b = ebx; *c = ecx; *d = edx;
#else
    (void)leaf; (void)sub;
    *a = 0x756E6547; *b = 0x49656E69; *c = 0x6C65746E; *d = 0x000006F2;  // "GenuineIntel"
#endif
}

static inline uint64_t x64_rdtsc() {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

static inline uint64_t x64_ctz(uint64_t v, int bits) {
    if (!v) return (uint64_t)bits;
    return (uint64_t)__builtin_ctzll(v);
}
static inline uint64_t x64_clz(uint64_t v, int bits) {
    if (!v) return (uint64_t)bits;
    if (bits == 64) return (uint64_t)__builtin_clzll(v);
    return (uint64_t)(__builtin_clzll(v) - (64 - bits));
}
// BSR = Bit Scan Reverse：返回**最高置位 bit 的下标**（0 基），不是前导零个数！
// 之前 lifter 把 bsr 和 lzcnt 一起映射到 x64_clz，于是
//   bsr(0x0FFF_FFFF_FFFF_FFFF) 得到 4（前导零数），而正确值是 59
// 结果 _Hash 的 _Max_bucket_count 被算成 1<<4 = 16，任何 64 桶的哈希表
// 一初始化就 `ja` 进 _Xlength_error("invalid hash bucket count")。
// LZCNT 才是前导零个数，两者差 bits-1-idx，不能混用。
static inline uint64_t x64_bsr(uint64_t v, int bits) {
    if (!v) return 0;                       // 源为 0 时目标未定义，ZF=1
    if (bits == 64) return (uint64_t)(63u - __builtin_clzll(v));
    return (uint64_t)(bits - 1 - (__builtin_clzll(v) - (64 - bits)));
}
static inline uint64_t x64_popcnt(uint64_t v, int bits) {
    (void)bits;
    return (uint64_t)__builtin_popcountll(v);
}

static inline void write_reg(X64Ctx* c, int regid, uint64_t v, int width) {
    uint64_t* preg = nullptr;
    switch (regid) {
        case 0: preg = &c->rax; break;
        case 1: preg = &c->rcx; break;
        case 2: preg = &c->rdx; break;
        case 3: preg = &c->rbx; break;
        case 4: preg = &c->rsp; break;
        case 5: preg = &c->rbp; break;
        case 6: preg = &c->rsi; break;
        case 7: preg = &c->rdi; break;
        case 8: preg = &c->r8; break;
        case 9: preg = &c->r9; break;
        case 10: preg = &c->r10; break;
        case 11: preg = &c->r11; break;
        case 12: preg = &c->r12; break;
        case 13: preg = &c->r13; break;
        case 14: preg = &c->r14; break;
        case 15: preg = &c->r15; break;
        default: return;
    }
    if (width >= 8) {
        *preg = v;
    } else if (width == 4) {
        *preg = (uint32_t)v;
    } else {
        uint64_t mask = (1ULL << (width * 8)) - 1;
        *preg = (*preg & ~mask) | (v & mask);
    }
}

static inline uint64_t read_reg(X64Ctx* c, int regid, int width) {
    uint64_t v = 0;
    switch (regid) {
        case 0: v = c->rax; break;
        case 1: v = c->rcx; break;
        case 2: v = c->rdx; break;
        case 3: v = c->rbx; break;
        case 4: v = c->rsp; break;
        case 5: v = c->rbp; break;
        case 6: v = c->rsi; break;
        case 7: v = c->rdi; break;
        case 8: v = c->r8; break;
        case 9: v = c->r9; break;
        case 10: v = c->r10; break;
        case 11: v = c->r11; break;
        case 12: v = c->r12; break;
        case 13: v = c->r13; break;
        case 14: v = c->r14; break;
        case 15: v = c->r15; break;
        default: return 0;
    }
    if (width < 8) {
        uint64_t mask = (1ULL << (width * 8)) - 1;
        v &= mask;
    }
    return v;
}

// ---- XMM 辅助 ----
static inline void xmm_write_bytes(X64Ctx* c, int idx, const void* src, int bytes) {
    std::memcpy(&c->xmm[idx], src, (size_t)bytes);
}
static inline uint64_t xmm_u64(X64Ctx* c, int idx) {
    uint64_t v;
    std::memcpy(&v, &c->xmm[idx], 8);
    return v;
}
static inline void xmm_set_u64(X64Ctx* c, int idx, uint64_t v) {
    std::memcpy(&c->xmm[idx], &v, 8);
}
static inline float xmm_f32(X64Ctx* c, int idx) { return c->xmm[idx].f32[0]; }
static inline void xmm_set_f32(X64Ctx* c, int idx, float v) { c->xmm[idx].f32[0] = v; }
static inline double xmm_f64(X64Ctx* c, int idx) { return c->xmm[idx].f64[0]; }
static inline void xmm_set_f64(X64Ctx* c, int idx, double v) { c->xmm[idx].f64[0] = v; }

// ---- 位运算辅助 ----
template <typename T> static inline T rotl(T v, T n) {
    int s = (int)(n & (sizeof(T) * 8 - 1));
    return (T)((v << s) | (v >> ((int)sizeof(T) * 8 - s)));
}
template <typename T> static inline T rotr(T v, T n) {
    int s = (int)(n & (sizeof(T) * 8 - 1));
    return (T)((v >> s) | (v << ((int)sizeof(T) * 8 - s)));
}
static inline uint64_t bswap64(uint64_t v) {
    return __builtin_bswap64(v);
}

// ---- 字符串指令（Windows ABI 要求 DF=0）----
static inline uint64_t x64_stride_dir(X64Ctx* c, int bytes) {
    return c->df ? (uint64_t)(-(int64_t)bytes) : (uint64_t)bytes;
}

static inline void x64_stos(X64Ctx* c, int bytes, int rep) {
    uint64_t count = rep ? c->rcx : 1;
    uint64_t mask = bytes >= 8 ? ~0ULL : ((1ULL << (bytes * 8)) - 1);
    uint64_t val = c->rax & mask;
    uint64_t step = x64_stride_dir(c, bytes);
    for (uint64_t i = 0; i < count; ++i) {
        if (bytes == 1) mem_write<uint8_t>(c, c->rdi, (uint8_t)val);
        else if (bytes == 2) mem_write<uint16_t>(c, c->rdi, (uint16_t)val);
        else if (bytes == 4) mem_write<uint32_t>(c, c->rdi, (uint32_t)val);
        else mem_write<uint64_t>(c, c->rdi, val);
        c->rdi += step;
    }
    if (rep) c->rcx = 0;
}

static inline void x64_movs(X64Ctx* c, int bytes, int rep) {
    uint64_t count = rep ? c->rcx : 1;
    uint64_t step = x64_stride_dir(c, bytes);
    for (uint64_t i = 0; i < count; ++i) {
        if (bytes == 1) mem_write<uint8_t>(c, c->rdi, mem_read<uint8_t>(c, c->rsi));
        else if (bytes == 2) mem_write<uint16_t>(c, c->rdi, mem_read<uint16_t>(c, c->rsi));
        else if (bytes == 4) mem_write<uint32_t>(c, c->rdi, mem_read<uint32_t>(c, c->rsi));
        else mem_write<uint64_t>(c, c->rdi, mem_read<uint64_t>(c, c->rsi));
        c->rdi += step; c->rsi += step;
    }
    if (rep) c->rcx = 0;
}

static inline void x64_lods(X64Ctx* c, int bytes, int rep) {
    uint64_t count = rep ? c->rcx : 1;
    uint64_t step = x64_stride_dir(c, bytes);
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t v = 0;
        if (bytes == 1) v = mem_read<uint8_t>(c, c->rsi);
        else if (bytes == 2) v = mem_read<uint16_t>(c, c->rsi);
        else if (bytes == 4) v = mem_read<uint32_t>(c, c->rsi);
        else v = mem_read<uint64_t>(c, c->rsi);
        write_reg(c, 0, v, bytes);
        c->rsi += step;
    }
    if (rep) c->rcx = 0;
}

static inline void x64_scas(X64Ctx* c, int bytes, int rep, int repne) {
    uint64_t step = x64_stride_dir(c, bytes);
    for (;;) {
        uint64_t v = 0;
        if (bytes == 1) v = mem_read<uint8_t>(c, c->rdi);
        else if (bytes == 2) v = mem_read<uint16_t>(c, c->rdi);
        else if (bytes == 4) v = mem_read<uint32_t>(c, c->rdi);
        else v = mem_read<uint64_t>(c, c->rdi);
        (void)sub_flags(c, c->rax, v, bytes);
        c->rdi += step;
        if (!rep) break;
        c->rcx -= 1;
        if (c->rcx == 0) break;
        if (!repne && !c->zf) break;
        if (repne && c->zf) break;
    }
}

static inline void x64_cmps(X64Ctx* c, int bytes, int rep, int repne) {
    uint64_t step = x64_stride_dir(c, bytes);
    for (;;) {
        uint64_t a = 0, b = 0;
        if (bytes == 1) { a = mem_read<uint8_t>(c, c->rsi); b = mem_read<uint8_t>(c, c->rdi); }
        else if (bytes == 2) { a = mem_read<uint16_t>(c, c->rsi); b = mem_read<uint16_t>(c, c->rdi); }
        else if (bytes == 4) { a = mem_read<uint32_t>(c, c->rsi); b = mem_read<uint32_t>(c, c->rdi); }
        else { a = mem_read<uint64_t>(c, c->rsi); b = mem_read<uint64_t>(c, c->rdi); }
        (void)sub_flags(c, a, b, bytes);
        c->rsi += step; c->rdi += step;
        if (!rep) break;
        c->rcx -= 1;
        if (c->rcx == 0) break;
        if (!repne && !c->zf) break;
        if (repne && c->zf) break;
    }
}

#include "x64_sse_helpers.h"

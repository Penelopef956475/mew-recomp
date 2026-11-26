#pragma once
// 方案书 4.2：寄存器上下文与间接调用分发表
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include "guest_heap.h"
#include <unistd.h>
#include <unordered_map>
#include <algorithm>
#include <vector>

struct X64Ctx;  // 前向声明：环形追踪与 SSE 辅助早于完整定义

struct alignas(16) XmmReg {
    union {
        uint8_t  u8[16];
        uint16_t u16[8];
        uint32_t u32[4];
        uint64_t u64[2];
        float    f32[4];
        double   f64[2];
    };
};

struct TraceEntry {
    uint64_t va;
    const char* tag;   // 普通函数为 nullptr，垫片传 API 名
    uint64_t rcx;
    uint64_t ret;      // 调用点（函数入口时的返回地址），用于定位是谁调的这一层
};

struct CallRingTrace {
    static constexpr size_t N = 64;
    TraceEntry buf[N]{};
    size_t idx = 0;

    void push(uint64_t va, const char* tag, uint64_t rcx, uint64_t ret = 0) {
        buf[idx & (N - 1)] = TraceEntry{va, tag, rcx, ret};
        idx++;
    }

    // 只打印最后 n 帧（周期采样用）
    void dump_tail(size_t n) const {
        size_t start = idx > n ? idx - n : 0;
        for (size_t i = start; i < idx; ++i) {
            const auto& e = buf[i & (N - 1)];
            if (e.tag) std::fprintf(stderr, "    [%zu] API  %s\n", i, e.tag);
            else std::fprintf(stderr, "    [%zu] FUNC sub_0x%llx (rcx=0x%llx)\n", i,
                              (unsigned long long)e.va, (unsigned long long)e.rcx);
        }
    }

    void dump(const char* reason) const {
        std::fprintf(stderr, "\n===== CALL RING TRACE (%s) =====\n", reason);
        size_t start = idx > N ? idx - N : 0;
        for (size_t i = start; i < idx; ++i) {
            const auto& e = buf[i & (N - 1)];
            if (e.tag)
                std::fprintf(stderr, "  [%zu] API  %s (rcx=0x%llx ret=0x%llx)\n", i, e.tag,
                             (unsigned long long)e.rcx, (unsigned long long)e.ret);
            else
                std::fprintf(stderr, "  [%zu] FUNC sub_0x%llx (rcx=0x%llx ret=0x%llx)\n", i,
                             (unsigned long long)e.va, (unsigned long long)e.rcx,
                             (unsigned long long)e.ret);
        }
        std::fprintf(stderr, "====================================\n");
    }
};

inline CallRingTrace& call_trace() {
    static thread_local CallRingTrace t;
    return t;
}

inline X64Ctx*& cur_ctx_ptr() {
    static X64Ctx* p = nullptr;
    return p;
}

inline uint64_t& cur_fn_va() {
    static uint64_t v = 0;
    return v;
}

// 入口观测：MEW_TRACE_FN=0x<va> 时，每次进入该函数打印一次寄存器快照（前 40 次）。
inline uint64_t mew_trace_fn() {
    static uint64_t v = [] {
        const char* e = std::getenv("MEW_TRACE_FN");
        return e ? (uint64_t)std::strtoull(e, nullptr, 0) : 0ULL;
    }();
    return v;
}

// MEW_TRACE_FN_MIN_RDX=0x<阈值>：只在这个函数的 rdx >= 阈值时才打印，**不限次数**。
// 用途：哈希表 rehash 那个函数平时被调几千次、rdx 都是 8/16/64 这种正常值，
// 真正要看的是「哪一次 rdx 突然变成天文数字」，前 40 次采样根本抓不到。
inline uint64_t mew_trace_min_rdx() {
    static uint64_t v = [] {
        const char* e = std::getenv("MEW_TRACE_FN_MIN_RDX");
        return e ? (uint64_t)std::strtoull(e, nullptr, 0) : 0ULL;
    }();
    return v;
}

#define MEW_SET_CUR_FN(CTX, VA)                                                   \
    do {                                                                          \
        cur_ctx_ptr() = (CTX);                                                    \
        cur_fn_va() = (uint64_t)(VA);                                             \
        call_trace().push((uint64_t)(VA), nullptr, (CTX)->rcx, mew_guest_ret(CTX)); \
        {                                                                         \
            FnEntryFrame& _f = fn_entry_frame();                                  \
            _f.rsp = (CTX)->rsp; _f.rbx = (CTX)->rbx; _f.rbp = (CTX)->rbp;        \
            _f.rsi = (CTX)->rsi; _f.rdi = (CTX)->rdi; _f.r12 = (CTX)->r12;        \
            _f.r13 = (CTX)->r13; _f.r14 = (CTX)->r14; _f.r15 = (CTX)->r15;        \
            _f.valid = true;                                                      \
        }                                                                         \
        if (mew_trace_fn() == (uint64_t)(VA) && mew_trace_min_rdx() &&        \
            (CTX)->rdx >= mew_trace_min_rdx()) {                                  \
            static int _mew_tb = 0;                                               \
            if (_mew_tb++ < 200) {                                                \
                std::fprintf(stderr,                                               \
                    "[fn!] 0x%llx rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx rsp=0x%llx\n", \
                    (unsigned long long)(VA), (unsigned long long)(CTX)->rcx,      \
                    (unsigned long long)(CTX)->rdx, (unsigned long long)(CTX)->r8, \
                    (unsigned long long)(CTX)->r9, (unsigned long long)(CTX)->rsp);\
                mew_probe_qword("[fn:d8]", (CTX)->rcx + 0xd8);                    \
                mew_probe_qword("[fn:dc]", (CTX)->rcx + 0xdc);                    \
                mew_probe_qword("[fn:e0]", (CTX)->rcx + 0xe0);                    \
            }                                                                     \
        }                                                                         \
        if (mew_trace_fn() == (uint64_t)(VA)) {                                   \
            static int _mew_tn = 0;                                               \
            if (_mew_tn++ < 40) {                                                 \
                std::fprintf(stderr,                                               \
                    "[fn] 0x%llx rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx rsp=0x%llx rax=0x%llx\n", \
                    (unsigned long long)(VA), (unsigned long long)(CTX)->rcx,      \
                    (unsigned long long)(CTX)->rdx, (unsigned long long)(CTX)->r8, \
                    (unsigned long long)(CTX)->r9, (unsigned long long)(CTX)->rsp, \
                    (unsigned long long)(CTX)->rax);                              \
                mew_probe_qword("[fn:rcx+0x88]", (CTX)->rcx + 0x88);              \
                mew_probe_qword("[fn:rdx]", (CTX)->rdx);                          \
            }                                                                     \
        }                                                                         \
    } while (0)
#define MEW_TRACE_API(CTX, NAME) \
    call_trace().push(0, (NAME), (CTX)->rcx, mew_guest_ret(CTX))

struct X64Ctx {
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    XmmReg   xmm[16];
    bool zf, sf, cf, of, pf, df;
    int64_t mem_bias;
    uint64_t gs_base;   // 伪 TEB 的 guest 地址（gs:[disp] 路由到这里）
    uint64_t fs_base;
};

// 函数入口帧快照：占位指令（UNIMPL_INSN）让函数"提前 return"时，
// 会把 epilogue 整段跳过 —— rsp 不平、rbx/rbp/rsi/rdi/r12-r15 停在被改写后的值。
// 实测代价：__acrt_initialize_locks 清空 rbx 后撞到占位直接返回，
// 调用方 __acrt_execute_initializers 的 `add rbx,0x10; mov rax,[rbx]` 就读到 [0x10] 崩掉。
// 因此占位返回前必须把入口帧原样恢复，保证 ABI 干净。
struct FnEntryFrame {
    uint64_t rsp, rbx, rbp, rsi, rdi, r12, r13, r14, r15;
    bool valid;
};
inline FnEntryFrame& fn_entry_frame() {
    static thread_local FnEntryFrame f{};
    return f;
}
inline void restore_entry_frame(X64Ctx* c) {
    const FnEntryFrame& f = fn_entry_frame();
    if (!f.valid || !c) return;
    c->rsp = f.rsp;
    c->rbx = f.rbx;
    c->rbp = f.rbp;
    c->rsi = f.rsi;
    c->rdi = f.rdi;
    c->r12 = f.r12;
    c->r13 = f.r13;
    c->r14 = f.r14;
    c->r15 = f.r15;
}


using RecompFn = void (*)(X64Ctx*);

inline std::unordered_map<uint64_t, RecompFn>& g_dispatch_table() {
    static std::unordered_map<uint64_t, RecompFn> tbl;
    return tbl;
}

inline std::vector<uint64_t>& dispatch_vas() {
    static std::vector<uint64_t> v;
    return v;
}

inline void register_recomp_fn(uint64_t guest_va, RecompFn fn) {
    g_dispatch_table()[guest_va] = fn;
    dispatch_vas().push_back(guest_va);
}

inline void init_dispatch_diag() {
    auto& v = dispatch_vas();
    std::sort(v.begin(), v.end());
}

static inline bool mew_unimpl_continue() {
    static int cached = -1;
    if (cached < 0) { const char* v = std::getenv("MEW_UNIMPL_CONTINUE"); cached = (v && v[0] == '1') ? 1 : 0; }
    return cached == 1;
}

static inline bool mew_safe_mem() {
    static int cached = -1;
    if (cached < 0) { const char* v = std::getenv("MEW_SAFE_MEM"); cached = (v && v[0] == '1') ? 1 : 0; }
    return cached == 1;
}

inline void record_missing_entry(uint64_t target_va, uint64_t caller_fn) {
    if (target_va >= 0x140001000ULL && target_va < 0x140e3f000ULL) {
        if (FILE* fp = std::fopen("discovered_entries.txt", "a")) {
            std::fprintf(fp, "0x%llx # caller=0x%llx\n",
                         (unsigned long long)target_va, (unsigned long long)caller_fn);
            std::fclose(fp);
        }
    }
}

// 合成地址（0x5000000xx）调用追踪钩子：post=0 调用前，post=1 调用后。
using ApiTraceHook = void (*)(uint64_t, X64Ctx*, int);
inline ApiTraceHook& api_trace_hook() {
    static ApiTraceHook h = nullptr;
    return h;
}

// ABI 守卫：Win64 规定 rbx/rbp/rsi/rdi/r12-r15 由被调方保存恢复。
// 若某个转译函数或垫片没恢复，上层循环（例如 __acrt_execute_initializers 的
// `mov rax,[rbx]` / `add rbx,0x10`）就会读到垃圾地址。
inline bool mew_abi_guard_on() {
    static int v = [] { const char* e = std::getenv("MEW_ABI_GUARD"); return (e && e[0] == '1') ? 1 : 0; }();
    return v == 1;
}

struct AbiSnapshot {
    uint64_t rbx, rbp, rsi, rdi, r12, r13, r14, r15, rsp;
};
inline AbiSnapshot abi_snap(const X64Ctx* c) {
    return AbiSnapshot{c->rbx, c->rbp, c->rsi, c->rdi, c->r12, c->r13, c->r14, c->r15, c->rsp};
}
inline void abi_check(const X64Ctx* c, const AbiSnapshot& s, uint64_t target, uint64_t caller);

// MEW_STACK_REPAIR=1：调用边界强制平衡模拟栈。
// 实测存在 rsp 逐层漏 8 字节（-8/-24/-48/-64），会让 MSVC 的 stack cookie
// （xor rsp）校验失败 → __fastfail(2)。修复前先用它把执行流推过去。
inline bool mew_stack_repair_on() {
    static int v = [] { const char* e = std::getenv("MEW_STACK_REPAIR"); return (e && e[0] == '1') ? 1 : 0; }();
    return v == 1;
}

// 调用点用：期望返回后 rsp == 调用前的 rsp + push 的数量（direct call 压 1 个）
inline void abi_guard_after_call(X64Ctx* ctx, const AbiSnapshot& s, uint64_t target, uint64_t caller,
                                 long long expect_delta) {
    if (mew_stack_repair_on()) {
        long long d = (long long)(ctx->rsp - s.rsp);
        if (d != expect_delta) {
            static int fixed = 0;
            if (fixed++ < 40)
                std::fprintf(stderr, "[rsp-repair] target=0x%llx caller=0x%llx delta=%lld -> %lld\n",
                             (unsigned long long)target, (unsigned long long)caller, d, expect_delta);
            ctx->rsp = s.rsp + (uint64_t)expect_delta;
        }
    }
    abi_check(ctx, s, target, caller);
}

inline void abi_check(const X64Ctx* c, const AbiSnapshot& s, uint64_t target, uint64_t caller) {
    static int logged = 0;
    if (logged > 40) return;
    long long dsp = (long long)(c->rsp - s.rsp);
    bool bad = c->rbx != s.rbx || c->rbp != s.rbp || c->rsi != s.rsi || c->rdi != s.rdi ||
               c->r12 != s.r12 || c->r13 != s.r13 || c->r14 != s.r14 || c->r15 != s.r15 ||
               (dsp != 0 && dsp != 8);
    if (!bad) return;
    ++logged;
    call_trace().dump("abi-violation");
    std::fprintf(stderr,
        "[ABI VIOLATION] target=0x%llx caller=0x%llx rbx:0x%llx->0x%llx rsi:0x%llx->0x%llx "
        "rdi:0x%llx->0x%llx rbp:0x%llx->0x%llx rsp_delta=%lld\n",
        (unsigned long long)target, (unsigned long long)caller,
        (unsigned long long)s.rbx, (unsigned long long)c->rbx,
        (unsigned long long)s.rsi, (unsigned long long)c->rsi,
        (unsigned long long)s.rdi, (unsigned long long)c->rdi,
        (unsigned long long)s.rbp, (unsigned long long)c->rbp, dsp);
}

// is_call=true 表示这是 call（调用方已经 push 了模拟返回地址）；
// 目标若是合成地址上的垫片，垫片不会执行 ret，必须由这里补一次 rsp += 8，
// 否则返回地址永久留在栈上，调用方的 add rsp,0x20 / pop rbx 全部错位。
// 观测某个调用方发出的每一次间接调用（用于看清初始化器循环的完整顺序）
inline uint64_t mew_trace_caller() {
    static uint64_t v = [] {
        const char* e = std::getenv("MEW_TRACE_CALLER");
        return e ? (uint64_t)std::strtoull(e, nullptr, 0) : 0ULL;
    }();
    return v;
}

// 返回点观测：MEW_TRACE_FN 指定的函数在 ret 前打印 rbx/rsi/rdi/rsp
inline void mew_ret_trace(X64Ctx* c) {
    if (!c) return;
    if (!mew_trace_fn() || cur_fn_va() != mew_trace_fn()) return;
    static int n = 0;
    if (n++ > 60) return;
    std::fprintf(stderr, "[ret] fn=0x%llx rbx=0x%llx rsi=0x%llx rdi=0x%llx rsp=0x%llx rax=0x%llx\n",
                 (unsigned long long)cur_fn_va(), (unsigned long long)c->rbx,
                 (unsigned long long)c->rsi, (unsigned long long)c->rdi,
                 (unsigned long long)c->rsp, (unsigned long long)c->rax);
}
#define MEW_RET_TRACE(CTX) mew_ret_trace(CTX)

inline bool tracer_note(bool on, uint64_t target, bool is_call, uint64_t rsp0, uint64_t rbx0) {
    static int n = 0;
    if (!on || n >= 40) return false;
    std::fprintf(stderr, "[disp#%02d] target=0x%llx is_call=%d rsp_in=0x%llx rbx_in=0x%llx\n",
                 n + 1, (unsigned long long)target, (int)is_call,
                 (unsigned long long)rsp0, (unsigned long long)rbx0);
    ++n;
    return true;
}
inline void tracer_done(bool on, uint64_t target, X64Ctx* c) {
    if (!on || !c) return;
    std::fprintf(stderr, "        -> done target=0x%llx rsp_out=0x%llx rbx=0x%llx rsi=0x%llx rdi=0x%llx\n",
                 (unsigned long long)target, (unsigned long long)c->rsp,
                 (unsigned long long)c->rbx, (unsigned long long)c->rsi,
                 (unsigned long long)c->rdi);
}

inline void dispatch_indirect(uint64_t target_va, X64Ctx* ctx, bool is_call = false) {
    const bool trace_this = mew_trace_caller() && cur_fn_va() == mew_trace_caller();
    const uint64_t t_rsp0 = ctx ? ctx->rsp : 0;
    const uint64_t t_rbx0 = ctx ? ctx->rbx : 0;
    const bool t_hit = tracer_note(trace_this, target_va, is_call, t_rsp0, t_rbx0);
    (void)t_hit;
    auto& tbl = g_dispatch_table();
    auto it = tbl.find(target_va);
    if (it != tbl.end()) {
        const bool guard = mew_abi_guard_on();
        const uint64_t caller = cur_fn_va();
        AbiSnapshot snap = guard ? abi_snap(ctx) : AbiSnapshot{};
        if (target_va >= 0x500000000ULL && target_va < 0x500100000ULL) {
            if (api_trace_hook()) api_trace_hook()(target_va, ctx, 0);
            it->second(ctx);
            if (guard) abi_check(ctx, snap, target_va, caller);
            if (api_trace_hook()) api_trace_hook()(target_va, ctx, 1);
            // 垫片替代了目标函数体，目标函数本该用 ret 弹一次返回地址；
            // 无论外层是 call 还是尾跳（含 CFG 蹦床 jmp rax），都必须由这里补弹。
            (void)is_call;
            ctx->rsp += 8;
            tracer_done(trace_this, target_va, ctx);
            return;
        }
        it->second(ctx);
        if (guard) abi_check(ctx, snap, target_va, caller);
        tracer_done(trace_this, target_va, ctx);
        return;
    }
    // 诊断：找最近的下界函数，判断是“函数内偏移”还是“完全在表外”
    auto& v = dispatch_vas();
    auto it2 = std::lower_bound(v.begin(), v.end(), target_va);
    uint64_t near_lo = 0;
    if (it2 != v.begin()) near_lo = *(it2 - 1);
    std::fprintf(stderr, "[FATAL] Unmapped indirect target: 0x%llx (nearest_lo=0x%llx delta=%lld) in_fn=0x%llx\n",
                 static_cast<unsigned long long>(target_va),
                 (unsigned long long)near_lo,
                 (long long)((int64_t)target_va - (int64_t)near_lo),
                 (unsigned long long)cur_fn_va());
    // guard-dispatch 蹦床：槽里不是有效代码指针时，真正目标通常在 rax。
    // 但这个回退会自杀式递归（rax 常常就是调用者本身，实测 0x140d3e654 -> 0x140d6adc8
    // 无限循环到超时），因此默认关闭，只在显式要求时启用。
    static const bool allow_rax_fallback = [] {
        const char* e = std::getenv("MEW_GUARD_RAX_FALLBACK");
        return e && e[0] == '1';
    }();
    if (allow_rax_fallback && ctx && ctx->rax && ctx->rax != target_va) {
        auto it3 = tbl.find(ctx->rax);
        if (it3 != tbl.end()) {
            std::fprintf(stderr, "[shim] guard-dispatch fallback slot=0x%llx -> rax=0x%llx\n",
                         (unsigned long long)target_va, (unsigned long long)ctx->rax);
            it3->second(ctx);
            return;
        }
    }
    record_missing_entry(target_va, cur_fn_va());
    static int miss_logged = 0;
    if (miss_logged++ < 3) call_trace().dump("dispatch miss");
    if (mew_unimpl_continue()) return;  // 收集模式：记录后继续，便于观察后续路径
    std::abort();
}

// ---------------- guest 已映射区间登记（垫片防崩） ----------------
struct GuestMemRange { uint64_t lo, hi; };

inline std::vector<GuestMemRange>& guest_mem_ranges() {
    static std::vector<GuestMemRange> r;
    return r;
}

inline void register_guest_range(uint64_t guest_lo, uint64_t len) {
    if (!len) return;
    guest_mem_ranges().push_back({guest_lo, guest_lo + len});
}

// 宿主地址是否真的映射（mincore 不触碰内存内容，只查页表）。
// 用于放行那些由垫片/系统库分配、但没经过我们登记表的合法堆地址。
inline bool host_page_mapped(uint64_t addr, size_t n) {
    static const long page = sysconf(_SC_PAGESIZE);
    if (!page) return false;
    uint64_t lo = addr & ~(uint64_t)(page - 1);
    uint64_t hi = (addr + n - 1) & ~(uint64_t)(page - 1);
    unsigned char vec = 0;
    for (uint64_t a = lo; a <= hi; a += (uint64_t)page)
        if (mincore(reinterpret_cast<void*>(a), (size_t)page, &vec) != 0) return false;
    return true;
}

inline bool guest_mapped(uint64_t addr, size_t n = 1) {
    if (!addr) return false;
    // O(1)：固定 Guest 堆池 / 镜像 / 栈区 都在这几条区间比较里
    if (g_guest_heap.contains(addr, n)) return true;
    for (const auto& r : guest_mem_ranges())
        if (addr >= r.lo && addr + n <= r.hi) return true;
    // 未登记的地址：交给宿主页表判断。bias=0 时 guest 地址就是宿主地址，
    // 这样 malloc/系统库给的内存不会被 SAFE_MEM 误杀（实测 0x140d6cb90 往堆对象写字段）。
    return host_page_mapped(addr, n);
}

// 函数/垫片入口处的返回地址（= guest 栈顶）。用来在调用环里定位"是谁调的这一层"。
inline uint64_t mew_guest_ret(X64Ctx* ctx) {
    if (!ctx) return 0;
    if (ctx->rsp <= 0x10000ULL || ctx->rsp >= 0x7fffffff0000ULL) return 0;
    if (!guest_mapped(ctx->rsp, 8)) return 0;
    uint64_t ret = 0;
    std::memcpy(&ret, reinterpret_cast<const void*>((uintptr_t)(ctx->rsp + ctx->mem_bias)), sizeof(ret));
    return ret;
}

// MEW_WATCH=0xaddr[,0xaddr...]：对指定地址的读写打点（定位"谁把它清零了"）。
inline std::vector<uint64_t>& mew_watch_addrs() {
    static std::vector<uint64_t> v = [] {
        std::vector<uint64_t> out;
        const char* e = std::getenv("MEW_WATCH");
        if (e) {
            std::string s(e);
            size_t p = 0;
            while (p <= s.size()) {
                size_t q = s.find(',', p);
                std::string tok = s.substr(p, q == std::string::npos ? std::string::npos : q - p);
                if (!tok.empty()) out.push_back(std::strtoull(tok.c_str(), nullptr, 0));
                if (q == std::string::npos) break;
                p = q + 1;
            }
        }
        return out;
    }();
    return v;
}
inline bool mew_watch_on() {
    static const bool on = !mew_watch_addrs().empty();
    return on;
}
inline uint64_t mew_bits(const void* p, size_t n) {
    uint64_t b = 0;
    if (n > 8) n = 8;
    std::memcpy(&b, p, n);
    return b;
}
inline bool mew_watch_hit(uint64_t addr, size_t n) {
    if (!mew_watch_on()) return false;
    for (uint64_t w : mew_watch_addrs())
        if (addr <= w && w < addr + n) return true;
    return false;
}

template <typename T>
inline T mem_read(X64Ctx* ctx, uint64_t guest_addr) {
    T v;
    std::memset(&v, 0, sizeof(T));
    if (mew_safe_mem() && !guest_mapped(guest_addr, sizeof(T))) {
        static int logged = 0;
        if (logged < 20) {
            std::fprintf(stderr, "[SAFE] unmapped read addr=0x%llx size=%zu in_fn=0x%llx\n",
                         (unsigned long long)guest_addr, sizeof(T),
                         (unsigned long long)cur_fn_va());
            if (logged < 3) call_trace().dump("safe-mem");
            ++logged;
        }
        return v;
    }
    std::memcpy(&v, reinterpret_cast<const void*>(guest_addr + ctx->mem_bias), sizeof(T));
    if (mew_watch_hit(guest_addr, sizeof(T))) {
        static int n = 0;
        if (n++ < 60)
            std::fprintf(stderr, "[watch] R addr=0x%llx size=%zu val=0x%llx in_fn=0x%llx\n",
                         (unsigned long long)guest_addr, sizeof(T),
                         (unsigned long long)mew_bits(&v, sizeof(T)),
                         (unsigned long long)cur_fn_va());
    }
    return v;
}

template <typename T>
inline void mem_write(X64Ctx* ctx, uint64_t guest_addr, T val) {
    if (mew_safe_mem() && !guest_mapped(guest_addr, sizeof(T))) {
        static int logged = 0;
        if (logged < 20) {
            std::fprintf(stderr, "[SAFE] unmapped write addr=0x%llx size=%zu in_fn=0x%llx\n",
                         (unsigned long long)guest_addr, sizeof(T),
                         (unsigned long long)cur_fn_va());
            ++logged;
        }
        return;
    }
    std::memcpy(reinterpret_cast<void*>(guest_addr + ctx->mem_bias), &val, sizeof(T));
    if (mew_watch_hit(guest_addr, sizeof(T))) {
        static int n = 0;
        if (n++ < 60)
            std::fprintf(stderr, "[watch] W addr=0x%llx size=%zu val=0x%llx in_fn=0x%llx\n",
                         (unsigned long long)guest_addr, sizeof(T),
                         (unsigned long long)mew_bits(&val, sizeof(T)),
                         (unsigned long long)cur_fn_va());
    }
}

// ---------------- 阶段 3 占位与日志 ----------------
// MEW_UNIMPL_CONTINUE=1 时只记录并返回（用于批量收集缺失项），否则中止
#define UNIMPL_INSN(RIP, MNEM)                                                   \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL INSN] rip=0x%llx mnemonic=%s\n",           \
                     (unsigned long long)(RIP), (MNEM));                         \
        if (mew_unimpl_continue()) return;                                       \
        std::abort();                                                            \
    } while (0)

#define UNIMPL_API(NAME)                                                         \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL API] %s\n", (NAME));                       \
        if (mew_unimpl_continue()) { ctx->rax = 0; return; }                     \
        std::abort();                                                            \
    } while (0)

#define UNIMPL_FUNC(VA)                                                          \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL FUNC] va=0x%llx\n",                        \
                     (unsigned long long)(VA));                                  \
        if (mew_unimpl_continue()) return;                                       \
        std::abort();                                                            \
    } while (0)

// 整函数占位：打印缺失的助记符，并保持调用约定平衡。
// 被 call 进来时栈顶是模拟返回地址（call 前由调用方 push），返回前必须弹掉，
// 否则调用方 rsp 偏移 8 字节；被尾跳（jmp）进来时栈顶不是返回地址，不能弹。
inline bool mew_pop_if_retaddr(X64Ctx* c) {
    if (!c) return false;
    if (!guest_mapped(c->rsp, 8)) return false;
    uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const void*>((uintptr_t)(c->rsp + c->mem_bias)), 8);
    if (v >= 0x140000000ULL && v < 0x141400000ULL) { c->rsp += 8; return true; }
    return false;
}

#define UNIMPL_FUNC_M(VA, MNEMS)                                                 \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL FUNC] va=0x%llx missing=%s\n",             \
                     (unsigned long long)(VA), (MNEMS));                         \
        if (mew_unimpl_continue()) {                                             \
            mew_pop_if_retaddr(cur_ctx_ptr());                                   \
            return;                                                              \
        }                                                                        \
        std::abort();                                                            \
    } while (0)

// int N（N != 3）：x64 上 int 0x29 = __fastfail，int 0x2c = 断言。
// 旧实现把它当未知占位跳过，导致 CRT 致命路径被静默吞掉、后续空指针崩溃。
inline void mew_dump_guest_str(const char* tag, uint64_t va) {
    if (va < 0x140000000ULL || va >= 0x141400000ULL) return;
    if (!guest_mapped(va, 1)) return;
    const char* p = reinterpret_cast<const char*>((uintptr_t)(va + cur_ctx_ptr()->mem_bias));
    char buf[160];
    size_t n = 0;
    for (; n + 1 < sizeof(buf); ++n) {
        char c = p[n];
        if (!c) break;
        buf[n] = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    buf[n] = 0;
    if (n >= 2) std::fprintf(stderr, "    %s=0x%llx \"%s\"\n", tag,
                             (unsigned long long)va, buf);
}

// 读一个 guest 指针指向的 qword；不可映射时打印 n/a
inline void mew_probe_qword(const char* tag, uint64_t va) {
    if (!va || !guest_mapped(va, 8) || !cur_ctx_ptr()) {
        std::fprintf(stderr, "    %s=0x%llx -> n/a\n", tag, (unsigned long long)va);
        return;
    }
    uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const void*>((uintptr_t)(va + cur_ctx_ptr()->mem_bias)), 8);
    std::fprintf(stderr, "    %s=0x%llx -> 0x%llx\n", tag, (unsigned long long)va,
                 (unsigned long long)v);
}

#define MEW_FASTFAIL(CTX, RIP, CODE)                                             \
    do {                                                                         \
        std::fprintf(stderr, "[FASTFAIL] rip=0x%llx int=0x%x in_fn=0x%llx\n",     \
                     (unsigned long long)(RIP), (unsigned)(CODE),                \
                     (unsigned long long)cur_fn_va());                           \
        std::fprintf(stderr, "    rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx rsp=0x%llx\n", \
                     (unsigned long long)(CTX)->rcx, (unsigned long long)(CTX)->rdx,     \
                     (unsigned long long)(CTX)->r8, (unsigned long long)(CTX)->r9,       \
                     (unsigned long long)(CTX)->rsp);                            \
        /* 非易失寄存器：abort 路径上它们保存着"是谁判定失败"的对象指针 */       \
        std::fprintf(stderr, "    rdi=0x%llx rsi=0x%llx rbx=0x%llx rbp=0x%llx rax=0x%llx\n", \
                     (unsigned long long)(CTX)->rdi, (unsigned long long)(CTX)->rsi,     \
                     (unsigned long long)(CTX)->rbx, (unsigned long long)(CTX)->rbp,     \
                     (unsigned long long)(CTX)->rax);                            \
        std::fprintf(stderr, "    r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx\n", \
                     (unsigned long long)(CTX)->r12, (unsigned long long)(CTX)->r13,     \
                     (unsigned long long)(CTX)->r14, (unsigned long long)(CTX)->r15);    \
        mew_probe_qword("[rsi]", (CTX)->rsi);                                    \
        mew_probe_qword("[rdi+0x88]", (CTX)->rdi + 0x88);                        \
        mew_probe_qword("[rdi+0x90]", (CTX)->rdi + 0x90);                        \
        mew_probe_qword("[rdi+0x3a8]", (CTX)->rdi + 0x3a8);                      \
        mew_probe_qword("[flags 0x1412f2f80]", 0x1412f2f80ULL);                  \
        mew_probe_qword("[rbx]", (CTX)->rbx);                                    \
        mew_dump_guest_str("rcx_str", (CTX)->rcx);                               \
        mew_dump_guest_str("rdx_str", (CTX)->rdx);                               \
        mew_dump_guest_str("r8_str", (CTX)->r8);                                 \
        mew_dump_guest_str("r9_str", (CTX)->r9);                                 \
        for (int _i = 0; _i < 12; ++_i) {                                        \
            uint64_t _a = (CTX)->rsp + (uint64_t)_i * 8;                          \
            if (!guest_mapped(_a, 8)) break;                                      \
            uint64_t _v = 0;                                                      \
            std::memcpy(&_v, reinterpret_cast<const void*>((uintptr_t)(_a + (CTX)->mem_bias)), 8); \
            std::fprintf(stderr, "    [rsp+0x%x]=0x%llx\n", _i * 8, (unsigned long long)_v);       \
            mew_dump_guest_str("  str", _v);                                      \
        }                                                                        \
        call_trace().dump("fastfail");                                           \
        /* 真实语义：__fastfail 永不返回。以前在 MEW_UNIMPL_CONTINUE 下 return，   \
           会让 abort 的兜底路径继续跑，产生垃圾指针与十万级 dispatch miss，        \
           日志全是噪声。除非显式要求继续，否则到此终止。 */                       \
        if (mew_unimpl_continue() && std::getenv("MEW_FASTFAIL_CONTINUE")) return; \
        std::fflush(stderr);                                                     \
        std::_Exit(3);                                                           \
    } while (0)

// 由生成的 dispatch_table.cpp 提供
void init_dispatch_table(const char* extra_url = nullptr, void* extra = nullptr);

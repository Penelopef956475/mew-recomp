// 阶段 5：宿主启动器 —— 加载 PE 镜像、初始化主线程 ctx、调用入口点
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <execinfo.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#include "x64_runtime.h"
#include "pe_image.h"
#include "seh_x64.h"

namespace {
// 每 15 秒采样一次调用环顶部，用来判断"卡死"发生在哪个循环里
void sample_handler(int) {
    static int tick = 0;
    std::fprintf(stderr, "[SAMPLE %d] top frames:\n", ++tick);
    call_trace().dump_tail(6);
    std::fflush(stderr);
}

void timeout_handler(int) {
    std::fprintf(stderr, "\n[TIMEOUT] terminated by watchdog\n");
    call_trace().dump("timeout");
    std::fflush(stderr);
    _exit(124);
}

void crash_handler(int sig, siginfo_t* si, void*) {
    void* bt[64];
    int n = backtrace(bt, 64);
    const uint64_t fault = (uint64_t)(uintptr_t)(si ? si->si_addr : nullptr);
    const uint64_t in_fn = cur_fn_va();

    // 重点三件事：**fault_addr**、**in_fn（哪个 guest 函数在跑）**、最后 15 帧。
    // 关掉 MEW_SAFE_MEM 时这里是唯一的现场来源：开安全内存时非法访存被静默
    // 拦成 0，循环条件永远不满足、原地空转（表现为 rc=124 超时）；一关掉就
    // 当场 SIGSEGV——所以这行就是「真凶地址」。
    std::fprintf(stderr, "\n[CRASH] signal=%d fault=0x%llx in_fn=sub_0x%llx frames=%d\n",
                 sig, (unsigned long long)fault, (unsigned long long)in_fn, n);

    if (X64Ctx* c = cur_ctx_ptr()) {
        std::fprintf(stderr,
            "[CRASH] ctx: rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx\n"
            "[CRASH]      rsi=0x%llx rdi=0x%llx rbp=0x%llx rsp=0x%llx r8=0x%llx r9=0x%llx\n",
            (unsigned long long)c->rax, (unsigned long long)c->rbx,
            (unsigned long long)c->rcx, (unsigned long long)c->rdx,
            (unsigned long long)c->rsi, (unsigned long long)c->rdi,
            (unsigned long long)c->rbp, (unsigned long long)c->rsp,
            (unsigned long long)c->r8,  (unsigned long long)c->r9);
    }

    std::fprintf(stderr, "[CRASH] 最后 15 帧 guest 调用环：\n");
    call_trace().dump_tail(15);

    backtrace_symbols_fd(bt, n, 2);
    if (std::getenv("MEW_CRASH_FULL"))      // 需要完整环时再开，默认只打 15 帧
        call_trace().dump("crash");
    std::fflush(stderr);
    _exit(139);
}
void install_crash_handler() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    sigaction(SIGFPE, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    struct sigaction ta;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_handler;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGALRM, &sa, nullptr);

    if (std::getenv("MEW_SAMPLE_SEC")) {
        struct sigaction sa2;
        std::memset(&sa2, 0, sizeof(sa2));
        sa2.sa_handler = sample_handler;
        sigaction(SIGALRM, &sa2, nullptr);
        struct itimerval it;
        it.it_interval.tv_sec = std::atol(std::getenv("MEW_SAMPLE_SEC"));
        it.it_interval.tv_usec = 0;
        it.it_value = it.it_interval;
        setitimer(ITIMER_REAL, &it, nullptr);
    }
}
}  // namespace

int main(int argc, char** argv) {
    std::fprintf(stderr, "[runner] marker: seh headers linked, dispatch=%d\n",
                 (int)seh::seh_dispatch_enabled());
    install_crash_handler();
    const char* exe = argc > 1 ? argv[1] : "Mewgenics.exe";
    uint64_t call_va = 0;
    size_t   call_obj_size = 0;
    unsigned long long cargs[4] = {0, 0, 0, 0};
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--call") == 0 && i + 1 < argc) call_va = std::strtoull(argv[++i], nullptr, 0);
        else if (std::strcmp(argv[i], "--call-obj") == 0 && i + 2 < argc) {
            call_va = std::strtoull(argv[++i], nullptr, 0);
            call_obj_size = (size_t)std::strtoull(argv[++i], nullptr, 0);
        }
        else if (std::strcmp(argv[i], "--arg") == 0 && i + 1 < argc) {
            const char* p = argv[++i];
            int k = 0;
            while (*p && k < 4) {
                char* end = nullptr;
                cargs[k++] = std::strtoull(p, &end, 0);
                if (end == p) break;
                p = end;
                if (*p == ',') ++p;
            }
        }
    }
    GuestImage img;
    std::string err;
    if (!load_pe_image(exe, &img, &err)) {
        std::fprintf(stderr, "load image failed: %s\n", err.c_str());
        return 1;
    }

    uint64_t entry = img.orig_image_base;
    {
        FILE* fp = std::fopen(exe, "rb");
        if (fp) {
            uint32_t peOff = 0;
            std::fseek(fp, 0x3c, SEEK_SET);
            std::fread(&peOff, 4, 1, fp);
            uint32_t entryRva = 0;
            std::fseek(fp, (long)peOff + 24 + 16, SEEK_SET);
            std::fread(&entryRva, 4, 1, fp);
            std::fclose(fp);
            entry = img.orig_image_base + entryRva;
        }
    }

    std::printf("runner: image_base=0x%llx entry=0x%llx bias=%lld\n",
                (unsigned long long)img.orig_image_base,
                (unsigned long long)entry, (long long)img.mem_bias);

    init_dispatch_table();

    X64Ctx ctx;
    init_guest_thread_ctx(&ctx, img);
    if (!call_va) {
        ctx.rcx = 0;   // hInstance
        ctx.rdx = 0;   // hPrevInstance
        ctx.r8 = 0;    // lpCmdLine
        ctx.r9 = 1;    // nCmdShow
    } else {
        if (call_obj_size) {
            uint64_t obj = g_guest_heap.alloc(call_obj_size, true);
            std::fprintf(stderr, "runner: --call-obj allocated 0x%llx (%zu bytes, zeroed)\n",
                         (unsigned long long)obj, call_obj_size);
            cargs[0] = obj;
        }
        ctx.rcx = cargs[0];
        ctx.rdx = cargs[1];
        ctx.r8 = cargs[2];
        ctx.r9 = cargs[3];
        entry = call_va;
        std::printf("runner: direct call 0x%llx args=%llu,%llu,%llu,%llu\n",
                    (unsigned long long)entry, cargs[0], cargs[1], cargs[2], cargs[3]);
    }

    std::printf("runner: calling entry...\n");
    std::fflush(stdout);

    // SEH 恢复点：异常派发里 resume_at() 会 longjmp 回这里，
    // 然后把宿主上下文换成"展开后恢复的目标上下文"，从新的 Rip 继续跑。
    seh::init_image_va(reinterpret_cast<uint64_t>(img.host_base), img.image_size,
                       img.pdata_va, img.pdata_bytes);
    uint64_t next_entry = entry;
    volatile bool from_resume = false;
    int rounds = 0;
    for (; rounds < 128; ++rounds) {
        if (from_resume) {
            seh::win_to_ctx(&seh::resume_ctx(), &ctx);
            next_entry = seh::resume_ctx().Rip;
            std::fprintf(stderr, "[seh] RESUME #%d rip=0x%llx rsp=0x%llx rbp=0x%llx\n", rounds,
                         (unsigned long long)next_entry, (unsigned long long)ctx.rsp,
                         (unsigned long long)ctx.rbp);
        }
        seh::resume_armed() = true;
        if (setjmp(seh::resume_buf()) == 0) {
            dispatch_indirect(next_entry, &ctx);
            break;  // guest 正常返回
        }
        from_resume = true;
    }
    std::printf("runner: entry returned rax=%llu resumes=%d\n",
                (unsigned long long)ctx.rax, rounds);
    return 0;
}

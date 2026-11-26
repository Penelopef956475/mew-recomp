// iOS 宿主：让 SDL3 接管 UIApplicationMain，再在它回调进来的函数里 dlopen
// 构建期重链接出来的 libmew_relinked.dylib，最后调它的 _SDL_main。
//
// 为什么必须是 SDL_RunApp 而不是裸 int main：
//   iOS 上一个普通的 C main() 不会启动 UIKit 的窗口/事件循环，屏幕会永远停在
//   系统白色 LaunchScreen 上（我们第一版真机就是这个白屏）。SDL3 的正确姿势是
//   由它调 UIApplicationMain，再由它的 AppDelegate 回调「用户 main」。
//   所以我们把真正的入口交给 SDL_RunApp(argc, argv, mew_app_main, NULL)，
//   mew_app_main 才是我们的主逻辑。这也是 SDL_main.h 那套宏背后实际做的事。
//
// 日志：main 一进来就把 stdout/stderr 无缓冲重定向到 Documents/mew.log，
// 之后所有输出（宿主、shim、游戏内部的 __android_log_print）都落盘到
// 「文件」App 里能直接看的位置 —— 没 Mac 连 Xcode Console 时这是唯一命根子。
//
// 数据包：4.78 GiB 的 resources.gpak 不进 IPA，走「文件」App 直接放进
// Documents/game/。覆盖安装时 Documents/ 原地保留，不用重传重签。

#define SDL_MAIN_HANDLED 1          // 我们自己写 main，不要 SDL_main.h 改名
#include <SDL3/SDL_main.h>
#include <SDL3/SDL_messagebox.h>   // SDL_MESSAGEBOX_INFORMATION

#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MEW_SDL_MAIN_OFFSET 0x4075e60ULL
#define MEW_DYLIB_NAME      "libmew_relinked.dylib"
#define MEW_LOG_MAX_BYTES   (8 * 1024 * 1024L)

// SDL_RunApp 是 SDL3 的「平台入口启动器」，iOS 上它负责 UIApplicationMain。
// 声明成 weak_import：万一某个 SDL3 构建没导出它，我们还能退回去直接跑主逻辑。
extern int SDL_RunApp(int argc, char* argv[], SDL_main_func mainFunction, void* reserved)
    __attribute__((weak_import));

static char g_exe_dir[4096];
static char g_docs[1024], g_game[1200], g_gpak[1400], g_log[1400];

static const char* exe_dir(void) {
    uint32_t sz = sizeof g_exe_dir;
    if (_NSGetExecutablePath(g_exe_dir, &sz) != 0) return ".";
    char* s = strrchr(g_exe_dir, '/');
    if (s) *s = '\0';
    return g_exe_dir;
}

// 日志超过 8 MB 滚动一次；游戏日志刷得很凶
static void rotate_log(const char* log) {
    struct stat st;
    if (stat(log, &st) != 0 || st.st_size < MEW_LOG_MAX_BYTES) return;
    char old[1400];
    snprintf(old, sizeof old, "%s.1", log);
    unlink(old);
    rename(log, old);
}

static void ensure_dir(const char* p) {
    if (mkdir(p, 0755) == 0) fprintf(stderr, "[host] 建目录 %s\n", p);
    else if (errno != EEXIST)
        fprintf(stderr, "[host] WARN: mkdir(%s) 失败（%s）\n", p, strerror(errno));
}

// 建目录 + 把 stdout/stderr 接到 mew.log 并关缓冲。返回 0 表示日志已落盘。
static int logs_setup(void) {
    const char* home = getenv("HOME");
    if (!home || !*home) return -1;
    snprintf(g_docs, sizeof g_docs, "%s/Documents", home);
    snprintf(g_game, sizeof g_game, "%s/game", g_docs);
    snprintf(g_gpak, sizeof g_gpak, "%s/resources.gpak", g_game);
    snprintf(g_log,  sizeof g_log,  "%s/mew.log", g_docs);
    ensure_dir(g_docs);
    ensure_dir(g_game);
    rotate_log(g_log);
    if (!freopen(g_log, "a", stdout)) return -1;
    if (!freopen(g_log, "a", stderr)) return -1;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return 0;
}

static void log_images(const char* tag) {
    uint32_t n = _dyld_image_count();
    fprintf(stderr, "[host] %s: dyld images = %u\n", tag, n);
    for (uint32_t i = 0; i < n; i++) {
        const char* nm = _dyld_get_image_name(i);
        if (nm && (strstr(nm, "mew") || strstr(nm, "bionic") || strstr(nm, "SDL")))
            fprintf(stderr, "[host]   [%u] %s hdr=%p slide=%ld\n", i, nm,
                    (void*)_dyld_get_image_header(i), (long)_dyld_get_image_vmaddr_slide(i));
    }
}

// 逐库显式 dlopen：三个库的报错绝不能混成一团（dlerror 只保留最后一次）
static void* must_dlopen(const char* label, const char* path) {
    fprintf(stderr, "[host] dlopen %s (%s)...\n", label, path);
    void* h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        const char* e = dlerror();
        fprintf(stderr, "[host] dlopen %s FAILED: %s\n", label, e ? e : "unknown");
    } else {
        fprintf(stderr, "[host] dlopen %s -> h=%p\n", label, h);
    }
    return h;
}

// 按 uuid/path 子串找镜像真实加载基址（= mach_header 地址；我们 __TEXT vmaddr 是 0）
static uintptr_t find_image_base_by_name(const char* want) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char* nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, want))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static void* find_mew_header(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char* nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, MEW_DYLIB_NAME)) return (void*)_dyld_get_image_header(i);
    }
    return NULL;
}

static void write_lowmem_settings_once(const char* base) {
    char cfg[1600];
    snprintf(cfg, sizeof cfg, "%s/settings.txt", base);
    if (access(cfg, F_OK) == 0) return;
    FILE* f = fopen(cfg, "w");
    if (!f) { fprintf(stderr, "[host] WARN: 写 %s 失败（%s）\n", cfg, strerror(errno)); return; }
    fputs("texture_scale_big 0.5\n"
          "curve_resolution 2.5\n"
          "soundeffect_cache_size_mb 64\n"
          "antialias 0\n", f);
    fclose(f);
    fprintf(stderr, "[host] 已写入低内存配置：%s\n", cfg);
}

static long file_size(const char* p) {
    struct stat st;
    return (stat(p, &st) == 0) ? (long)st.st_size : -1;
}

// ---------------- SDL3 回调进来的「用户 main」 ----------------
static int mew_app_main(int argc, char** argv) {
    (void)argc; (void)argv;
    const char* dir = exe_dir();

    fprintf(stderr, "\n[host 1] enter app main: docs=%s game=%s\n", g_docs, g_game);
    log_images("boot");

    write_lowmem_settings_once(g_docs);
    write_lowmem_settings_once(g_game);

    // ---- 资源 ----
    long gsz = file_size(g_gpak);
    fprintf(stderr, "[host 2] gpak exists=%s size=%ld\n", gsz >= 0 ? "yes" : "no", gsz);
    if (gsz < 0) {
        fprintf(stderr, "[host] MISSING resources.gpak（预期 %s）\n", g_gpak);
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "缺少游戏数据",
                                 "请将 resources.gpak 放入「文件 → 我的 iPhone → MewRelink → game」"
                                 " 后重新打开。\n\n详细日志：文件 → 我的 iPhone → MewRelink → mew.log",
                                 NULL);
        fprintf(stderr, "[host] 已提示用户，正常退出\n");
        return 0;
    }

    if (chdir(g_game) != 0) {
        fprintf(stderr, "[host] WARN: chdir(%s) 失败（%s），留在 %s\n", g_game, strerror(errno), dir);
        chdir(dir);
    }
    char real[4096];
    if (getcwd(real, sizeof real)) fprintf(stderr, "[host] cwd = %s\n", real);

    // ---- 分库 dlopen：SDL3 → shim → 主库，每一步都留 dlerror 原文 ----
    fprintf(stderr, "[host 3] before dlopen(libmew_relinked.dylib)\n");
    void* h = NULL;
    {
        char p3[4096];
        snprintf(p3, sizeof p3, "%s/Frameworks/libmew_relinked.dylib", dir);
        // SDK 的 rpath 已指向 @executable_path/Frameworks，但这里用绝对路径更可靠
        if (!must_dlopen("SDL3", "@rpath/SDL3.framework/SDL3"))
            fprintf(stderr, "[host] WARN: SDL3 预加载失败，继续试主库\n");
        if (!must_dlopen("shim", "@rpath/libbionic_shim.dylib"))
            fprintf(stderr, "[host] WARN: shim 预加载失败，继续试主库\n");
        h = must_dlopen("mew", p3);
        if (!h) h = must_dlopen("mew(rpath)", MEW_DYLIB_NAME);
    }
    fprintf(stderr, "[host 3b] dlopen result h=%p\n", h);
    if (!h) {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "装载失败",
                                 "找不到 libmew_relinked.dylib，包不完整。", NULL);
        return 2;
    }

    // 把主库真实基址登记给 bionic libc 的 dl_iterate_phdr（PT_GNU_EH_FRAME 上报）
    {
        uintptr_t base = find_image_base_by_name(MEW_DYLIB_NAME);
        typedef void (*set_base_fn)(uintptr_t);
        set_base_fn set_base = (set_base_fn)dlsym(RTLD_DEFAULT, "mew_eh_register_image");
        fprintf(stderr, "[host 3c] mew_base=0x%lx set_base=%p\n",
                (unsigned long)base, (void*)set_base);
        if (set_base && base) set_base(base);
    }

    // ---- 入口地址 ----
    void* entry = dlsym(h, "SDL_main");
    if (entry) {
        fprintf(stderr, "[host] SDL_main via dlsym = %p\n", entry);
    } else {
        void* hdr = find_mew_header();
        if (hdr) {
            entry = (void*)((char*)hdr + MEW_SDL_MAIN_OFFSET);
            fprintf(stderr, "[host] dlsym 失败（%s），退到 header+0x%llx = %p\n",
                    dlerror(), (unsigned long long)MEW_SDL_MAIN_OFFSET, entry);
        }
    }
    if (!entry) {
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "入口缺失", "拿不到 SDL_main 地址。", NULL);
        return 3;
    }

    // ---- 交给引擎 ----
    log_images("pre-target-main");
    fprintf(stderr, "[host 4] calling target _SDL_main at %p\n", entry);
    fflush(stderr);
    int (*fn)(int, char**) = (int (*)(int, char**))entry;
    int rc = fn(0, NULL);
    fprintf(stderr, "[host 5] target _SDL_main returned rc=%d\n", rc);
    fflush(stderr);
    return rc;
}

// ---------------- 真正的进程入口 ----------------
int main(int argc, char* argv[]) {
    int logged = logs_setup();
    fprintf(stderr, "\n[host 0] main() entered, logs_setup=%d, calling SDL_RunApp\n", logged);

    if (SDL_RunApp) {
        // iOS 上这一步会进 UIApplicationMain，窗口/事件循环由 SDL3 建好；
        // 它在 AppDelegate 里回调 mew_app_main。
        int rc = SDL_RunApp(argc, argv, mew_app_main, NULL);
        fprintf(stderr, "[host 9] SDL_RunApp returned %d\n", rc);
        return rc;
    }

    fprintf(stderr, "[host 0b] WARN: 没有 SDL_RunApp，退回裸跑主逻辑（iOS 上会白屏）\n");
    return mew_app_main(argc, argv);
}

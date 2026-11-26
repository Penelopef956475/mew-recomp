// iOS 宿主：dlopen 构建期重链接出来的 libmew_relinked.dylib，然后调 SDL_main。
//
// 启动顺序（顺序本身就是设计，别随手调换）：
//   1) 定位 exe 目录 → 建好 Documents/ 与 Documents/game/
//   2) **先把 stdout/stderr 重定向到 Documents/mew.log（无缓冲）**，之后所有日志
//      都会落到「文件」App 里能直接看的地方 —— 没 Mac 连 Xcode Console 时，这是
//      真机排错的唯一命根子
//   3) 首次启动写低内存 settings.txt（Documents/ 与 Documents/game/ 各一份）
//   4) 检查 Documents/game/resources.gpak；缺了就弹窗 + 正常退出，别闪退
//   5) gpak 就位才 dlopen，然后 dlsym("SDL_main")，失败退到 header + 0x4075e60
//   6) 调 SDL_main(0, NULL)，把控制权交给引擎
//
// 数据包策略：4.78 GiB 的 resources.gpak **不进 IPA**（超 ZIP32 4 GiB 上限、侧载签名
// 极慢易失败、每次改代码重传 5 GB 没法调试）。走「文件」App 直传 Documents/game/
// （Info.plist 已开 UIFileSharingEnabled + LSSupportsOpeningDocumentsInPlace），
// 覆盖安装时 Documents/ 原地保留。

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

// 不引 SDL 头，避免宿主依赖 SDL 的编译期宏；只声明要用的那一个符号。
extern int SDL_ShowSimpleMessageBox(unsigned int flags, const char* title,
                                    const char* message, void* window);

static char g_exe_dir[4096];

static const char* exe_dir(void) {
    uint32_t sz = sizeof g_exe_dir;
    if (_NSGetExecutablePath(g_exe_dir, &sz) != 0) return ".";
    char* s = strrchr(g_exe_dir, '/');
    if (s) *s = '\0';
    return g_exe_dir;
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

// 在已加载镜像里找 libmew_relinked.dylib 的 mach_header
static void* find_mew_header(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char* nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, MEW_DYLIB_NAME)) return (void*)_dyld_get_image_header(i);
    }
    return NULL;
}

// 日志超过 8 MB 就滚动一次，只保留 .1 一份 —— 游戏的日志刷得很凶
static void rotate_log(const char* log) {
    struct stat st;
    if (stat(log, &st) != 0) return;
    if (st.st_size < MEW_LOG_MAX_BYTES) return;
    char old[1200];
    snprintf(old, sizeof old, "%s.1", log);
    unlink(old);
    rename(log, old);
}

// 把 stdout/stderr 都接到日志文件上，并且**关掉缓冲**：
// 崩溃时缓冲区里的最后几百行正是我们最需要的那些。
static void redirect_logs(const char* log) {
    rotate_log(log);
    if (!freopen(log, "a", stdout)) return;
    if (!freopen(log, "a", stderr)) return;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void write_lowmem_settings_once(const char* base) {
    char cfg[1400];
    snprintf(cfg, sizeof cfg, "%s/settings.txt", base);
    if (access(cfg, F_OK) == 0) {
        fprintf(stderr, "[host] settings.txt 已存在，保留：%s\n", cfg);
        return;
    }
    FILE* f = fopen(cfg, "w");
    if (!f) {
        fprintf(stderr, "[host] WARN: 写 %s 失败（%s）\n", cfg, strerror(errno));
        return;
    }
    fputs("texture_scale_big 0.5\n"
          "curve_resolution 2.5\n"
          "soundeffect_cache_size_mb 64\n"
          "antialias 0\n", f);
    fclose(f);
    fprintf(stderr, "[host] 已写入低内存配置：%s\n", cfg);
}

static void ensure_dir(const char* p) {
    if (mkdir(p, 0755) == 0) fprintf(stderr, "[host] 建目录 %s\n", p);
    else if (errno != EEXIST) fprintf(stderr, "[host] WARN: mkdir(%s) 失败（%s）\n", p, strerror(errno));
}

static long file_size(const char* p) {
    struct stat st;
    return (stat(p, &st) == 0) ? (long)st.st_size : -1;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    const char* dir = exe_dir();

    const char* home = getenv("HOME");
    if (!home || !*home) {
        fprintf(stderr, "[host] FATAL: HOME 取不到\n");
        return 4;
    }

    // ---- 1) 目录 ----
    char docs[1024], game[1200], gpak[1400], log[1400];
    snprintf(docs, sizeof docs, "%s/Documents", home);
    snprintf(game, sizeof game, "%s/game", docs);
    snprintf(gpak, sizeof gpak, "%s/resources.gpak", game);
    snprintf(log,  sizeof log,  "%s/mew.log", docs);
    ensure_dir(docs);
    ensure_dir(game);

    // ---- 2) 日志落盘（必须在任何有意义的输出之前）----
    redirect_logs(log);
    fprintf(stderr, "\n[host] ================= boot ================\n");
    fprintf(stderr, "[host] exe dir  = %s\n", dir);
    fprintf(stderr, "[host] Documents= %s\n", docs);
    fprintf(stderr, "[host] game dir = %s\n", game);
    fprintf(stderr, "[host] log      = %s\n", log);
    log_images("boot");

    // ---- 3) 低内存配置（两处各写一份，引擎从哪读都能读到）----
    write_lowmem_settings_once(docs);
    write_lowmem_settings_once(game);

    // ---- 4) 资源就位检查 ----
    long gsz = file_size(gpak);
    if (gsz < 0) {
        fprintf(stderr, "[host] MISSING resources.gpak（预期位置 %s）\n", gpak);
        SDL_ShowSimpleMessageBox(0x00000010 /* SDL_MESSAGEBOX_INFORMATION */,
                                 "缺少游戏数据",
                                 "请将 resources.gpak 放入「文件 → 我的 iPhone → MewRelink → game」"
                                 " 后重新打开。\n\n详细日志：文件 → 我的 iPhone → MewRelink → mew.log",
                                 NULL);
        fprintf(stderr, "[host] 已提示用户，正常退出（不是崩溃）\n");
        return 0;
    }
    fprintf(stderr, "[host] resources.gpak = %ld bytes\n", gsz);

    // 引擎用相对路径找资源，工作目录必须是 game/
    if (chdir(game) != 0) {
        fprintf(stderr, "[host] WARN: chdir(%s) 失败（%s），留在 %s\n", game, strerror(errno), dir);
        chdir(dir);
    }
    char real[4096];
    if (getcwd(real, sizeof real)) fprintf(stderr, "[host] cwd = %s\n", real);

    // ---- 5) 加载重链接产物 ----
    const char* cand[] = {
        MEW_DYLIB_NAME,
        "Frameworks/" MEW_DYLIB_NAME,
        "../Frameworks/" MEW_DYLIB_NAME,
    };
    char path[4096];
    void* h = NULL;
    for (size_t i = 0; i < sizeof cand / sizeof cand[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, cand[i]);
        h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
        if (h) {
            fprintf(stderr, "[host] dlopen OK: %s\n", path);
            break;
        }
        fprintf(stderr, "[host] dlopen miss %s: %s\n", path, dlerror());
    }
    if (!h) {
        fprintf(stderr, "[host] FATAL: 找不到 %s\n", MEW_DYLIB_NAME);
        SDL_ShowSimpleMessageBox(0x00000010, "装载失败",
                                 "找不到 libmew_relinked.dylib，包不完整。", NULL);
        return 2;
    }

    void* entry = dlsym(h, "SDL_main");
    if (entry) {
        fprintf(stderr, "[host] SDL_main via dlsym = %p\n", entry);
    } else {
        void* hdr = find_mew_header();
        if (hdr) {
            entry = (void*)((char*)hdr + MEW_SDL_MAIN_OFFSET);
            fprintf(stderr, "[host] dlsym(SDL_main) 失败（%s），退到 header+0x%llx = %p\n",
                    dlerror(), (unsigned long long)MEW_SDL_MAIN_OFFSET, entry);
        }
    }
    if (!entry) {
        fprintf(stderr, "[host] FATAL: 拿不到 SDL_main\n");
        SDL_ShowSimpleMessageBox(0x00000010, "入口缺失", "拿不到 SDL_main 地址。", NULL);
        return 3;
    }

    // ---- 6) 交给引擎 ----
    log_images("pre-SDL_main");
    fprintf(stderr, "[host] entering SDL_main\n");
    fflush(stderr);
    int (*fn)(int, char**) = (int (*)(int, char**))entry;
    int rc = fn(0, NULL);
    fprintf(stderr, "[host] SDL_main returned %d\n", rc);
    fflush(stderr);
    return rc;
}

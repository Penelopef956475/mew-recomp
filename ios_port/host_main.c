// iOS 宿主：dlopen 构建期重链接出来的 libmew_relinked.dylib，然后调 SDL_main。
//
// 职责只有五件：
//   1) 找到随包分发的那几个 dylib（同目录 / Frameworks）
//   2) dlopen（RTLD_NOW，符号缺失当场炸，不要 RTLD_LAZY 拖到运行中途）
//   3) 把工作目录切到 Documents/，并把 resources.gpak 是否就位说清楚
//   4) 首次启动写一份低内存 settings.txt，避免 iPhone 首帧被 Jetsam 干掉
//   5) 调 SDL_main(0, NULL)，之后一切交给引擎
//
// 拿入口地址有两条路：优先 dlsym("SDL_main")；失败就退回到「mach_header + 固定偏移」。
// 我们的 __TEXT vmaddr 就是 0，所以镜像头地址就是基址，0x4075e60 直接加得上——
// 这条兜底是为了把「dlsym 莫名返回 NULL」这种沉默失败换成能跑通的路径。
//
// 数据包策略：机身 4.78 GiB 的 resources.gpak **不进 IPA**（超过 ZIP32 4 GiB 上限，
// 侧载签名会超时/OOM，而且每次改代码都得重传 5 GB）。改为走「文件」App 直传
// Documents/（Info.plist 已开 UIFileSharingEnabled + LSSupportsOpeningDocumentsInPlace），
// 覆盖安装时 Documents/ 里的数据原地保留。

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MEW_SDL_MAIN_OFFSET 0x4075e60ULL
#define MEW_DYLIB_NAME      "libmew_relinked.dylib"

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

static void write_lowmem_settings_once(const char* dir) {
    char cfg[1200];
    snprintf(cfg, sizeof cfg, "%s/settings.txt", dir);
    if (access(cfg, F_OK) == 0) {
        fprintf(stderr, "[host] settings.txt 已存在，保留用户配置\n");
        return;
    }
    FILE* f = fopen(cfg, "w");
    if (!f) {
        fprintf(stderr, "[host] WARN: 写 settings.txt 失败（%s）\n", cfg);
        return;
    }
    fputs("texture_scale_big 0.5\n"
          "curve_resolution 2.5\n"
          "soundeffect_cache_size_mb 64\n"
          "antialias 0\n", f);
    fclose(f);
    fprintf(stderr, "[host] 已写入低内存 settings.txt（防首帧 Jetsam）\n");
}

static long file_size(const char* p) {
    struct stat st;
    return (stat(p, &st) == 0) ? (long)st.st_size : -1;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    log_images("boot");

    const char* dir = exe_dir();
    fprintf(stderr, "[host] exe dir = %s\n", dir);

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
        SDL_ShowSimpleMessageBox(0x00000010 /* INFORMATION */, "装载失败",
                                 "找不到 libmew_relinked.dylib，包不完整。", NULL);
        return 2;
    }

    // 入口：dlsym 优先，失败退到「镜像头 + 固定偏移」
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

    // ---- 数据目录：Documents/ ----
    const char* home = getenv("HOME");
    char docs[1024], gpak[1200];
    if (!home) {
        fprintf(stderr, "[host] FATAL: HOME 取不到\n");
        return 4;
    }
    snprintf(docs, sizeof docs, "%s/Documents", home);
    snprintf(gpak, sizeof gpak, "%s/resources.gpak", docs);
    fprintf(stderr, "[host] Documents = %s\n", docs);

    write_lowmem_settings_once(docs);
    if (chdir(docs) != 0) {
        fprintf(stderr, "[host] WARN: chdir(%s) 失败\n", docs);
        chdir(dir);
    }
    char real[4096];
    if (getcwd(real, sizeof real)) fprintf(stderr, "[host] cwd = %s\n", real);

    long gsz = file_size(gpak);
    if (gsz < 0) {
        fprintf(stderr, "[host] MISSING resources.gpak\n");
        SDL_ShowSimpleMessageBox(0x00000010, "缺少游戏数据",
                                 "请把 resources.gpak 放进「文件 App → 我的 iPhone → MewRelink」"
                                 "（也就是本 App 的 Documents 目录），然后重新打开。", NULL);
        return 0;
    }
    fprintf(stderr, "[host] resources.gpak = %ld bytes\n", gsz);

    log_images("pre-SDL_main");
    fprintf(stderr, "[host] entering SDL_main\n");
    fflush(stderr);
    int (*fn)(int, char**) = (int (*)(int, char**))entry;
    int rc = fn(0, NULL);
    fprintf(stderr, "[host] SDL_main returned %d\n", rc);
    return rc;
}

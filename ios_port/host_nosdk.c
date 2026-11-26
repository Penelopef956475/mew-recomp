// MewHost（无 SDK 版）：不 include 任何 Apple 头文件，所有 libSystem 原型自己声明，
// 因此可以在 Ubuntu 上 `clang -target arm64-apple-ios15.0 -nostdlibinc` 编译，
// 再用 ld64.lld 链接成 ios arm64 可执行文件 —— 不需要 Xcode / iPhoneOS.sdk。
//
// 与带 SDK 版等价的行为：
//   1) main 进来第一件事：建 Documents/ 与 Documents/game/，把 fd 1/2 dup2 到
//      Documents/mew.log（append），之后所有输出（宿主、shim、游戏自己的
//      __android_log_print）都落盘
//   2) 首次启动写低内存 settings.txt（埋点用，两处各一份）
//   3) 检查 Documents/game/resources.gpak；缺了就弹窗 + 正常退出
//   4) 分库 dlopen：SDL3 → libbionic_shim → libmew_relinked（每步记 dlerror）
//   5) dlsym("SDL_main")，失败退到 mach_header + 0x4075e60
//   6) **通过 dlsym 拿 SDL_RunApp 并由它接管 UIApplicationMain**（iOS 不这么做就白屏）
#include <stdarg.h>
#include <stddef.h>

// ---------------- 自己声明的最小 libSystem 接口 ----------------
typedef unsigned long size_t;
typedef long off_t;
typedef long ssize_t;

extern void* dlopen(const char*, int);
extern void* dlsym(void*, const char*);
extern char* dlerror(void);
extern char* getenv(const char*);
extern int open(const char*, int, ...);
extern off_t lseek(int, off_t, int);
extern int close(int);
extern ssize_t write(int, const void*, size_t);
extern int dup2(int, int);
extern int mkdir(const char*, unsigned);
extern int chdir(const char*);
extern char* getcwd(char*, size_t);
extern int access(const char*, int);
extern int unlink(const char*);
extern int rename(const char*, const char*);
extern int snprintf(char*, size_t, const char*, ...);
extern void exit(int);
extern int _NSGetExecutablePath(char*, unsigned*);
extern unsigned _dyld_image_count(void);
extern const char* _dyld_get_image_name(unsigned);
extern const void* _dyld_get_image_header(unsigned);

#define RTLD_NOW 2
#define RTLD_GLOBAL 8
#define O_WRONLY 1
#define O_CREAT 0x200
#define O_APPEND 8
#define O_RDONLY 0
#define F_OK 0

#define MEW_SDL_MAIN_OFFSET 0x4075e60ULL
#define MEW_DYLIB_NAME "libmew_relinked.dylib"
#define LOG_MAX 8388608L

static char g_exe_dir[4096];
static char g_docs[1024], g_game[1200], g_gpak[1400], g_log[1400];
static int g_logfd = -1;

static size_t mew_strlen(const char* s) { size_t n = 0; while (s && s[n]) n++; return n; }
static int mew_has(const char* hay, const char* needle) {
    if (!hay || !needle) return 0;
    size_t n = mew_strlen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] == needle[i]) i++;
        if (i == n) return 1;
    }
    return 0;
}

// 统一日志：先格式化，再写 fd（dup2 之后就是 mew.log）
static void say(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof buf) n = (int)sizeof buf - 1;
    if (g_logfd >= 0) { (void)write(g_logfd, buf, (size_t)n); }
    (void)write(2, buf, (size_t)n);
}

static const char* exe_dir(void) {
    unsigned sz = sizeof g_exe_dir;
    if (_NSGetExecutablePath(g_exe_dir, &sz) != 0) return ".";
    size_t n = mew_strlen(g_exe_dir);
    while (n > 0 && g_exe_dir[n - 1] != '/') n--;
    if (n > 0) g_exe_dir[n - 1] = '\0';
    return g_exe_dir;
}

static long file_size(const char* p) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    long sz = (long)lseek(fd, 0, 2);
    close(fd);
    return sz;
}

static void rotate_log(const char* log) {
    long sz = file_size(log);
    if (sz < LOG_MAX) return;
    char old[1500];
    snprintf(old, sizeof old, "%s.1", log);
    unlink(old);
    rename(log, old);
}

static int logs_setup(void) {
    const char* home = getenv("HOME");
    if (!home || !*home) return -1;
    snprintf(g_docs, sizeof g_docs, "%s/Documents", home);
    snprintf(g_game, sizeof g_game, "%s/game", g_docs);
    snprintf(g_gpak, sizeof g_gpak, "%s/resources.gpak", g_game);
    snprintf(g_log,  sizeof g_log,  "%s/mew.log", g_docs);
    (void)mkdir(g_docs, 0755);
    (void)mkdir(g_game, 0755);
    rotate_log(g_log);
    int fd = open(g_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    g_logfd = fd;
    dup2(fd, 1);
    dup2(fd, 2);
    return 0;
}

static void write_lowmem_once(const char* base) {
    char cfg[1500];
    snprintf(cfg, sizeof cfg, "%s/settings.txt", base);
    if (access(cfg, F_OK) == 0) return;
    int fd = open(cfg, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) { say("[host] WARN: 写 %s 失败\n", cfg); return; }
    static const char body[] =
        "texture_scale_big 0.5\ncurve_resolution 2.5\n"
        "soundeffect_cache_size_mb 64\nantialias 0\n";
    (void)write(fd, body, sizeof body - 1);
    close(fd);
    say("[host] 已写入低内存配置：%s\n", cfg);
}

static void* find_mew_header(void) {
    unsigned n = _dyld_image_count();
    for (unsigned i = 0; i < n; i++) {
        const char* nm = _dyld_get_image_name(i);
        if (nm && mew_has(nm, MEW_DYLIB_NAME)) return (void*)_dyld_get_image_header(i);
    }
    return 0;
}

// ---------------- 真正的 App 主逻辑（由 SDL_RunApp 回调进来） ----------------
static int app_main(int argc, char** argv) {
    (void)argc; (void)argv;
    const char* dir = exe_dir();
    say("\n[host 1] enter app main: docs=%s game=%s\n", g_docs, g_game);

    write_lowmem_once(g_docs);
    write_lowmem_once(g_game);

    long gsz = file_size(g_gpak);
    say("[host 2] gpak exists=%s size=%ld\n", gsz >= 0 ? "yes" : "no", gsz);

    void* h_sdl = dlopen("@rpath/SDL3.framework/SDL3", RTLD_NOW | RTLD_GLOBAL);
    say("[host] dlopen SDL3 -> %p %s\n", h_sdl, h_sdl ? "" : (dlerror() ? dlerror() : "?"));
    void* h_shim = dlopen("@rpath/libbionic_shim.dylib", RTLD_NOW | RTLD_GLOBAL);
    say("[host] dlopen shim -> %p %s\n", h_shim, h_shim ? "" : (dlerror() ? dlerror() : "?"));

    if (gsz < 0) {
        if (!h_sdl) h_sdl = dlopen("@rpath/SDL3.framework/SDL3", RTLD_NOW | RTLD_GLOBAL);
        typedef int (*mb_fn)(unsigned, const char*, const char*, void*);
        mb_fn mb = h_sdl ? (mb_fn)dlsym(h_sdl, "SDL_ShowSimpleMessageBox") : 0;
        if (mb) mb(0x10, "缺少游戏数据",
                   "请将 resources.gpak 放入「文件 → 我的 iPhone → MewRelink → game」后重新打开。"
                   "\n\n详细日志：文件 → 我的 iPhone → MewRelink → mew.log", 0);
        say("[host] 已提示用户，正常退出\n");
        return 0;
    }

    if (chdir(g_game) != 0) chdir(dir);
    char cwd[4096];
    if (getcwd(cwd, sizeof cwd)) say("[host] cwd = %s\n", cwd);

    say("[host 3] before dlopen(%s)\n", MEW_DYLIB_NAME);
    char p3[4200];
    void* h = 0;
    snprintf(p3, sizeof p3, "%s/Frameworks/%s", dir, MEW_DYLIB_NAME);
    h = dlopen(p3, RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        say("[host] dlopen %s 失败：%s\n", p3, dlerror() ? dlerror() : "?");
        h = dlopen(MEW_DYLIB_NAME, RTLD_NOW | RTLD_GLOBAL);
    }
    say("[host 3b] dlopen result h=%p %s\n", h, h ? "" : (dlerror() ? dlerror() : "?"));
    if (!h) return 2;

    void* hdr = find_mew_header();
    typedef void (*set_base_fn)(unsigned long);
    set_base_fn set_base = (set_base_fn)dlsym((void*)-2 /*RTLD_DEFAULT*/, "mew_eh_register_image");
    say("[host 3c] mew_base=%p set_base=%p\n", hdr, (void*)set_base);
    if (set_base && hdr) set_base((unsigned long)hdr);

    void* entry = dlsym(h, "SDL_main");
    if (!entry && hdr) {
        entry = (void*)((char*)hdr + MEW_SDL_MAIN_OFFSET);
        say("[host 4] dlsym 失败，退到 header+0x%llx = %p\n",
            (unsigned long long)MEW_SDL_MAIN_OFFSET, entry);
    } else {
        say("[host 4] calling target _SDL_main at %p\n", entry);
    }
    if (!entry) return 3;

    typedef int (*sdl_main_fn)(int, char**);
    int rc = ((sdl_main_fn)entry)(0, (char**)0);
    say("[host 5] target _SDL_main returned rc=%d\n", rc);
    return rc;
}

// ---------------- 入口：必须走 SDL_RunApp（iOS 靠它进 UIApplicationMain） ----------------
int main(int argc, char** argv) {
    int logged = logs_setup();
    say("\n[host 0] main() entered, logs_setup=%d\n", logged);

    // 先用 dlopen 把 SDL3 拉进来，再 dlsym 取 SDL_RunApp：
    // 这样 MewHost 不需要在链接期依赖 SDL3.framework（Ubuntu 上没有 .tbd 也能链）。
    void* h_sdl = dlopen("@rpath/SDL3.framework/SDL3", RTLD_NOW | RTLD_GLOBAL);
    if (!h_sdl) {
        char alt[4200];
        snprintf(alt, sizeof alt, "%s/Frameworks/SDL3.framework/SDL3", exe_dir());
        h_sdl = dlopen(alt, RTLD_NOW | RTLD_GLOBAL);
    }
    typedef int (*run_app_fn)(int, char**, int (*)(int, char**), void*);
    run_app_fn run = h_sdl ? (run_app_fn)dlsym(h_sdl, "SDL_RunApp") : 0;
    say("[host 0b] SDL3=%p SDL_RunApp=%p\n", h_sdl, (void*)run);
    if (run) {
        int rc = run(argc, argv, app_main, 0);
        say("[host 9] SDL_RunApp returned %d\n", rc);
        return rc;
    }
    say("[host 0c] 没有 SDL_RunApp，退回裸跑（iOS 上会白屏）\n");
    return app_main(argc, argv);
}

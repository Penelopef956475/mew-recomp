// Android 专有 API 的最小实现
#include "bionic_shim.h"
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// __android_log_print 是变参：实现在 bionic_varargs.c 的 mew_vararg_android_log_print，
// 由 bionic_varargs.S 的 VARARG_THUNK 桥进来。这里**不能**再定义一个同名函数，
// 否则链接期直接 duplicate symbol '_bionic___android_log_print'。
int bionic___android_log_write(int prio, const char* tag, const char* msg) {
    (void)prio;
    fprintf(stderr, "[%s] %s\n", tag ? tag : "?", msg ? msg : "");
    return 0;
}
void bionic_android_set_abort_message(const char* msg) {
    fprintf(stderr, "[abort] %s\n", msg ? msg : "");
}
int bionic___system_property_get(const char* name, char* value) {
    (void)name;
    if (value) value[0] = '\0';
    return 0;
}
void bionic___assert2(const char* file, int line, const char* func, const char* expr) {
    fprintf(stderr, "[assert2] %s:%d %s: %s\n", file ? file : "?", line, func ? func : "?", expr ? expr : "?");
    __builtin_trap();
}
// ANativeWindow_*：不硬编码 1280x720，实时查 SDL3 当前窗口的像素尺寸；
// 还没建窗时回退 1280x720。SDL_GL_GetCurrentWindow 在游戏调 SDL_GL_CreateContext
// 之前返回 NULL，所以两个分支都要有。
// 注意：不得在 shim 里包含 SDL 头（会和 bionic_shim.h 的结构体命名打架），
// 这里只做前置声明，符号由 SDL3.framework 在运行时提供。
// 用 dlsym 而不是硬链接 SDL3：shim 可能在 SDL3 之前被加载，二命名空间下
// 直接 bind 会 "symbol not found"；dlsym(RTLD_DEFAULT) 只看运行时已有的镜像。
typedef struct SDL_Window SDL_Window;
typedef SDL_Window* (*get_current_window_fn)(void);
typedef int (*get_window_size_pixels_fn)(SDL_Window*, int*, int*);

static int g_win_w = 1280, g_win_h = 720;

static void mew_query_window(int* w, int* h) {
    *w = 1280; *h = 720;
    static get_current_window_fn s_get_win = NULL;
    static get_window_size_pixels_fn s_get_px = NULL;
    static int s_tried = 0;
    if (!s_tried) {
        s_tried = 1;
        s_get_win = (get_current_window_fn)dlsym(RTLD_DEFAULT, "SDL_GL_GetCurrentWindow");
        s_get_px  = (get_window_size_pixels_fn)dlsym(RTLD_DEFAULT, "SDL_GetWindowSizeInPixels");
    }
    if (!s_get_win || !s_get_px) return;
    SDL_Window* win = s_get_win();
    if (!win) return;
    int pw = 0, ph = 0;
    if (s_get_px(win, &pw, &ph) == 0 && pw > 0 && ph > 0) { *w = pw; *h = ph; }
}
int bionic_ANativeWindow_getWidth(void* w)  { (void)w; int a, b; mew_query_window(&a, &b); return a; }
int bionic_ANativeWindow_getHeight(void* w) { (void)w; int a, b; mew_query_window(&a, &b); return b; }
int bionic_ANativeWindow_setBuffersGeometry(void* w, int width, int height, int format) {
    (void)w; g_win_w = width; g_win_h = height; (void)format; return 0;
}

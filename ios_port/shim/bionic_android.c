// Android 专有 API 的最小实现
#include "bionic_shim.h"
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
// ANativeWindow_* 在 iOS 上由 SDL 窗口尺寸提供（P2 接入真值）
static int g_win_w = 1280, g_win_h = 720;
int bionic_ANativeWindow_getWidth(void* w)  { (void)w; return g_win_w; }
int bionic_ANativeWindow_getHeight(void* w) { (void)w; return g_win_h; }
int bionic_ANativeWindow_setBuffersGeometry(void* w, int width, int height, int format) {
    (void)w; g_win_w = width; g_win_h = height; (void)format; return 0;
}

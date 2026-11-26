// 变参桥：Bionic(ELF, AAPCS64) -> Darwin
//   AAPCS64 : 整数 x0..x7，浮点 d0..d7
//   Darwin  : va_list 是扁平 char*，所有参数按格式串顺序连续排 8 字节槽
// 做法：x0..x7 / d0..d7 溢写到两块槽，第 9 个起的参数从 callar_sp 取，交给 mew_vararg_build 重排。
    .text
    .p2align 2

.macro VARARG_THUNK name, target
    .globl _bionic_\name
_bionic_\name:
    sub  sp, sp, #0x120
    stp  x0, x1, [sp, #0x00]
    stp  x2, x3, [sp, #0x10]
    stp  x4, x5, [sp, #0x20]
    stp  x6, x7, [sp, #0x30]
    stp  d0, d1, [sp, #0x80]
    stp  d2, d3, [sp, #0x90]
    stp  d4, d5, [sp, #0xa0]
    stp  d6, d7, [sp, #0xb0]
    add  x0, sp, #0x00      // x_slots
    add  x1, sp, #0x80      // d_slots
    add  x2, sp, #0x120     // 调用方栈上第 9 个起的参数（caller_sp）
    bl   _\target
    add  sp, sp, #0x120
    ret
.endm

VARARG_THUNK snprintf, mew_vararg_snprintf

VARARG_THUNK __android_log_print, mew_vararg_android_log_print
VARARG_THUNK printf, mew_vararg_printf
VARARG_THUNK fprintf, mew_vararg_fprintf
VARARG_THUNK syslog, mew_vararg_syslog
VARARG_THUNK swprintf, mew_vararg_swprintf

// sscanf 只需要整数槽：x_slots + caller_sp
    .globl _bionic_sscanf
_bionic_sscanf:
    sub  sp, sp, #0x60
    stp  x0, x1, [sp, #0x00]
    stp  x2, x3, [sp, #0x10]
    stp  x4, x5, [sp, #0x20]
    stp  x6, x7, [sp, #0x30]
    mov  x0, sp
    add  x1, sp, #0x60      // caller_sp：第 7 个及以后的指针
    bl   _mew_vararg_sscanf
    add  sp, sp, #0x60
    ret

// ELF AArch64 TLSDESC 解析器（严格按 AAPCS64 TLSDESC 约定）。
//
// 关键点：调用方（libmain.so）认为 TLSDESC resolver **只改 x0 和 NZCV**，
// 所以 x1..x18 与 q0..q31 这些 caller-saved 寄存器一个都不能被动。
// 如果这里直接 `bl` 进一个普通 C 函数，编译器会按 AAPCS64 自由破坏 x1..x18
// 与 q0..q7，真机上第一次访问 TLS 之后就会出现「莫名其妙的随机崩溃」。
//
// 约定：
//   入参 x0 = 指向 16 字节描述符 { resolver_fn, slot_offset } 的指针
//   出参 x0 = 目标 TLS 变量地址 - tpidr_el0
//   除 x0 与 NZCV 外，x1..x30 / q0..q31 必须原样返回
    .text
    .p2align 4

    .globl _bionic_tlsdesc_resolver
_bionic_tlsdesc_resolver:
    // 栈帧：16(fp/lr) + 9*16(x1..x18) + 12*32(q0..q7, q16..q31) = 544 B
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x1,  x2,  [sp, #-16]!
    stp  x3,  x4,  [sp, #-16]!
    stp  x5,  x6,  [sp, #-16]!
    stp  x7,  x8,  [sp, #-16]!
    stp  x9,  x10, [sp, #-16]!
    stp  x11, x12, [sp, #-16]!
    stp  x13, x14, [sp, #-16]!
    stp  x15, x16, [sp, #-16]!
    stp  x17, x18, [sp, #-16]!
    stp  q0,  q1,  [sp, #-32]!
    stp  q2,  q3,  [sp, #-32]!
    stp  q4,  q5,  [sp, #-32]!
    stp  q6,  q7,  [sp, #-32]!
    stp  q16, q17, [sp, #-32]!
    stp  q18, q19, [sp, #-32]!
    stp  q20, q21, [sp, #-32]!
    stp  q22, q23, [sp, #-32]!
    stp  q24, q25, [sp, #-32]!
    stp  q26, q27, [sp, #-32]!
    stp  q28, q29, [sp, #-32]!
    stp  q30, q31, [sp, #-32]!

    // 描述符 [x0+8] 就是 .tbss 内的槽偏移；再取 tpidr_el0 作为第二个参数
    ldr  x0, [x0, #8]
    mrs  x1, tpidr_el0
    bl   _bionic_tlsdesc_get_offset

    // 逆序恢复；x0（返回的偏移）不在恢复列表里，天然保持不变
    ldp  q30, q31, [sp], #32
    ldp  q28, q29, [sp], #32
    ldp  q26, q27, [sp], #32
    ldp  q24, q25, [sp], #32
    ldp  q22, q23, [sp], #32
    ldp  q20, q21, [sp], #32
    ldp  q18, q19, [sp], #32
    ldp  q16, q17, [sp], #32
    ldp  q6,  q7,  [sp], #32
    ldp  q4,  q5,  [sp], #32
    ldp  q2,  q3,  [sp], #32
    ldp  q0,  q1,  [sp], #32
    ldp  x17, x18, [sp], #16
    ldp  x15, x16, [sp], #16
    ldp  x13, x14, [sp], #16
    ldp  x11, x12, [sp], #16
    ldp  x9,  x10, [sp], #16
    ldp  x7,  x8,  [sp], #16
    ldp  x5,  x6,  [sp], #16
    ldp  x3,  x4,  [sp], #16
    ldp  x1,  x2,  [sp], #16
    ldp  x29, x30, [sp], #16
    ret

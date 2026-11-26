// setjmp/longjmp：bionic 与 Darwin 的 jmp_buf 布局不同（bionic arm64 是 200 字节的
// 一段 long[]，Darwin 的 jmp_buf 由 libSystem 自己的 sigjmp 布局占满），所以两者
// 不能互相透传 —— 必须成对实现。这里只保存 C longjmp 需要恢复的被调方保存寄存器：
//   x19..x28 (fp/lr 另算)、x29(fp)、x30(lr)、sp、d8..d15
// 合计 (10 + 1 + 1 + 1 + 8) * 8 = 168 字节，塞进 bionic 的 jmp_buf 绰绰有余。
    .text
    .p2align 2

    .globl _bionic_setjmp
_bionic_setjmp:                  // x0 = jmp_buf
    stp  x19, x20, [x0, #0x00]
    stp  x21, x22, [x0, #0x10]
    stp  x23, x24, [x0, #0x20]
    stp  x25, x26, [x0, #0x30]
    stp  x27, x28, [x0, #0x40]
    stp  x29, x30, [x0, #0x50]
    mov  x1, sp
    str  x1, [x0, #0x60]
    stp  d8,  d9,  [x0, #0x68]
    stp  d10, d11, [x0, #0x78]
    stp  d12, d13, [x0, #0x88]
    stp  d14, d15, [x0, #0x98]
    mov  w0, #0
    ret

    .globl _bionic_longjmp
_bionic_longjmp:                 // x0 = jmp_buf, w1 = value
    ldp  x19, x20, [x0, #0x00]
    ldp  x21, x22, [x0, #0x10]
    ldp  x23, x24, [x0, #0x20]
    ldp  x25, x26, [x0, #0x30]
    ldp  x27, x28, [x0, #0x40]
    ldp  x29, x30, [x0, #0x50]
    ldr  x2,  [x0, #0x60]
    mov  sp, x2
    ldp  d8,  d9,  [x0, #0x68]
    ldp  d10, d11, [x0, #0x78]
    ldp  d12, d13, [x0, #0x88]
    ldp  d14, d15, [x0, #0x98]
    cmp  w1, #0
    cinc w0, w1, eq              // longjmp(buf, 0) 必须返回 1
    ret

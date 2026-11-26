// 没有 crt1.o 的情况下的进程入口：从初始栈里取 argc/argv，调用 main，再把返回值交给 exit。
// xnu 在进入 LC_MAIN 指定的入口时，sp 指向 { argc, argv[0..], NULL, envp... }。
    .text
    .p2align 4
    .globl _start
_start:
    mov  x29, #0
    mov  x30, #0
    ldr  w0, [sp]           // argc
    add  x1, sp, #8         // argv
    bl   _main
    bl   _exit              // 不返回
    brk  #0

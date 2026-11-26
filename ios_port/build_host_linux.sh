#!/usr/bin/env bash
# 在 Linux 上凭空编出 iOS arm64 的 MewHost —— 不需要 Xcode、不需要 iPhoneOS.sdk。
#
# 原理：MewHost 只用 libSystem 的十几个函数和 SDL3 的两个入口，所以
#   1) 源码里不 include 任何 Apple 头（只有 <stdarg.h>/<stddef.h>，那是编译器自带）
#   2) clang 用 -target arm64-apple-ios15.0 直接出 Mach-O 目标文件
#   3) ld64.lld（Ubuntu 的 lld 包里就有）负责链接，-undefined dynamic_lookup
#      让 libSystem 符号留到 dyld 绑定期，因此**不需要 .tbd 存根**
#   4) 没有 crt1.o，所以自己写 _start 从初始栈取 argc/argv
#
# 产物：out/products/MewHost（MH_EXECUTE / arm64 / platform=iOS）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-${ROOT}/out}"
PROD="${OUT}/products"
REPORT="${OUT}/build_host_linux.txt"
mkdir -p "$OUT" "$PROD"
: > "$REPORT"
say() { echo "==> [$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
num() { echo "    $*" | tee -a "$REPORT"; }

CC="${CC:-clang}"
LD64="${LD64:-ld64.lld}"

say "工具链"
$CC --version | head -1 | tee -a "$REPORT"
command -v "$LD64" >/dev/null || { sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq lld clang; }
$LD64 --version 2>&1 | head -2 | tee -a "$REPORT" || true

say "编译（arm64-apple-ios15.0，无 SDK 头）"
$CC -target arm64-apple-ios15.0 -O2 -fno-stack-protector -fno-builtin \
    -nostdlibinc -isystem "$($CC -print-resource-dir)/include" \
    -c "$ROOT/ios_port/host_nosdk.c" -o /tmp/host_nosdk.o 2>&1 | tee -a "$REPORT"
$CC -target arm64-apple-ios15.0 -c "$ROOT/ios_port/start_nosdk.S" -o /tmp/start_nosdk.o 2>&1 | tee -a "$REPORT"
num "host.o $(stat -c%s /tmp/host_nosdk.o) B  start.o $(stat -c%s /tmp/start_nosdk.o) B"

say "链接（ld64.lld，undefined dynamic_lookup）"
"$LD64" -arch arm64 \
    -platform_version ios 15.0 15.0 \
    -undefined dynamic_lookup \
    -e _start \
    -o "$PROD/MewHost" \
    /tmp/start_nosdk.o /tmp/host_nosdk.o 2>&1 | tee -a "$REPORT"
chmod +x "$PROD/MewHost"
num "MewHost $(stat -c%s "$PROD/MewHost") B"

say "产物自检"
python3 - "$PROD/MewHost" 2>&1 | tee -a "$REPORT" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
magic, cpu, sub, ft, ncmds, sz, flags, _ = struct.unpack_from('<IIIIIIII', d, 0)
print('    magic=0x%x cpu=%d filetype=%d(H2=EXECUTE) ncmds=%d flags=0x%x' %
      (magic, cpu, ft, ncmds, flags))
assert magic == 0xFEEDFACF, '不是 64 位 Mach-O'
assert ft == 2, 'filetype 不是 MH_EXECUTE'
assert cpu == 0x0100000C, 'CPU 不是 arm64'
o = 32
plat = None
for _i in range(ncmds):
    cmd, size = struct.unpack_from('<II', d, o)
    if cmd == 0x32:  # LC_BUILD_VERSION
        platform, minos, sdk = struct.unpack_from('<III', d, o + 8)
        plat = platform
        print('    LC_BUILD_VERSION platform=%d(iOS=2) minos=0x%x sdk=0x%x' % (platform, minos, sdk))
    if cmd == 0x80000028:  # LC_MAIN
        entryoff = struct.unpack_from('<Q', d, o + 8)[0]
        print('    LC_MAIN entryoff=0x%x' % entryoff)
    o += size
assert plat == 2, 'platform 不是 iOS(2)'
PY

say "硬门禁：必须真含 SDL_RunApp 与 mew.log"
grep -c 'mew.log' "$PROD/MewHost" >/dev/null 2>&1 || { strings "$PROD/MewHost" | grep -q 'mew.log' || { echo "::error::MewHost 里没有 mew.log 字符串"; exit 1; }; }
strings "$PROD/MewHost" | grep -q 'SDL_RunApp' || { echo "::error::MewHost 里没有 SDL_RunApp"; exit 1; }
strings "$PROD/MewHost" | grep -q 'mew.log' || { echo "::error::MewHost 里没有 mew.log"; exit 1; }
num "门禁通过：SDL_RunApp ✓  mew.log ✓"
say "完成：$PROD/MewHost"

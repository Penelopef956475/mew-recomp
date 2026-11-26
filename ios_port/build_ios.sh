#!/usr/bin/env bash
# 一次 macOS runner 跑完全程：APK 分片 → Mach-O 重链接 → 编 SDL3(iOS) → 编 bionic shim
# → 编宿主 → 组 .app → ad-hoc 签名 → 打包 .ipa。
#
# 设计意图：macOS 队列很贵，所以不在多轮里来回排队；每一阶段的数字都打到日志和
# 报告文件里，任何一步失败都能单独定位（不会整轮白跑）。
set -euo pipefail

ARCH=arm64
MIN_IOS=15.0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/out"
REPORT="${OUT}/build_report.txt"
mkdir -p "$OUT"
: > "$REPORT"

say() { echo "==> [$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
num() { echo "    $*" | tee -a "$REPORT"; }

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CLANG="$(xcrun -sdk iphoneos --find clang)"
say "SDK        $SDK"
say "clang      $CLANG"
num "$("$CLANG" --version | head -1)"

# SKIP_RELINK=1：dylib 已由 Ubuntu job 产出并放在 out/libmew_relinked.dylib，
# 本机跳过「组装 APK + 转换」两段（macOS 槽位宝贵，只做编译+签名+打包）
if [ "${SKIP_RELINK:-0}" = "1" ] && [ -f "${OUT}/libmew_relinked.dylib" ]; then
    say "stage 1-2/7 跳过（SKIP_RELINK=1，复用 ${OUT}/libmew_relinked.dylib）"
    num "dylib $(stat -f%z "${OUT}/libmew_relinked.dylib") bytes"
else
say "stage 1/7 组装 APK 分片"
cat "${ROOT}"/ios_port/vendor/apk_part_*.bin > "${OUT}/app.apk"
APK="${OUT}/app.apk" LMO="${OUT}/libmain.so" python3 <<'PY' | tee -a "$REPORT"
import os, zipfile
apk, out = os.environ['APK'], os.environ['LMO']
z = zipfile.ZipFile(apk)
open(out, 'wb').write(z.read('lib/arm64-v8a/libmain.so'))
print('    apk        %d bytes' % os.path.getsize(apk))
print('    libmain.so %d bytes' % os.path.getsize(out))
PY

# ---------- 2) ELF → Mach-O ----------
say "stage 2/7 ELF→Mach-O 重链接"
python3 "${ROOT}/tools/elf2macho_dylib.py" "${OUT}/libmain.so" \
        -o "${OUT}/libmew_relinked.dylib" --platform ios 2>&1 | tee -a "$REPORT"
python3 "${ROOT}/ios_port/verify_macho.py" "${OUT}/libmew_relinked.dylib" 2>&1 | tee -a "$REPORT"
fi

# ---------- 3) SDL3 (iOS) ----------
say "stage 3/7 编译 SDL3 for iOS"
SDL_TAG="${SDL_TAG:-release-3.2.0}"
if [ -f "${OUT}/sdlbuild/SDL3.framework/SDL3" ]; then
    say "SDL3 已缓存，跳过 clone/build"
elif [ -d "${OUT}/SDL/.git" ]; then
    timeout 240 git -C "${OUT}/SDL" fetch --depth 1 origin "refs/tags/${SDL_TAG}:refs/tags/${SDL_TAG}" || true
else
    timeout 300 git clone --depth 1 --branch "$SDL_TAG" https://github.com/libsdl-org/SDL.git "${OUT}/SDL"
fi
num "SDL commit $(git -C "${OUT}/SDL" rev-parse --short HEAD 2>/dev/null || echo cached)"
if [ ! -f "${OUT}/sdlbuild/SDL3.framework/SDL3" ]; then
timeout 240 cmake -S "${OUT}/SDL" -B "${OUT}/sdlbuild" \
      -DCMAKE_SYSTEM_NAME=iOS \
      -DCMAKE_OSX_ARCHITECTURES=$ARCH \
      -DCMAKE_OSX_DEPLOYMENT_TARGET=$MIN_IOS \
      -DCMAKE_BUILD_TYPE=Release \
      -DSDL_SHARED=ON -DSDL_STATIC=OFF -DSDL_FRAMEWORK=ON \
      -DSDL_OPENGLES=ON -DSDL_METAL=ON -DSDL_GPU=ON \
      -DSDL_TESTS=OFF -DSDL_EXAMPLES=OFF -DSDL_INSTALL_TESTS=OFF \
      > "${OUT}/sdl_cmake.log" 2>&1 || { tail -30 "${OUT}/sdl_cmake.log"; exit 1; }
timeout 600 cmake --build "${OUT}/sdlbuild" --config Release -j "$(sysctl -n hw.ncpu)" \
      > "${OUT}/sdl_build.log" 2>&1 || { tail -40 "${OUT}/sdl_build.log"; exit 1; }
fi
SDLF="$(find "${OUT}/sdlbuild" -name 'SDL3.framework' -maxdepth 5 | head -1 || true)"
SDLDYLIB=""
if [ -z "$SDLF" ]; then
    SDLDYLIB="$(find "${OUT}/sdlbuild" -name 'libSDL3*.dylib' | head -1 || true)"
    say "没产出 framework，改用 dylib 手工拼 framework: ${SDLDYLIB:-none}"
fi
num "SDL3 artifact: ${SDLF:-$SDLDYLIB}"

# ---------- 4) bionic shim ----------
say "stage 4/7 编译 libbionic_shim.dylib"
SHIMDIR="${ROOT}/ios_port/shim"
mkdir -p "${OUT}/shimbuild"
"$CLANG" -target "${ARCH}-apple-ios${MIN_IOS}" -isysroot "$SDK" -O2 -fPIC \
    -I "$SHIMDIR" -I "$SDLF/Headers" \
    -dynamiclib -install_name @rpath/libbionic_shim.dylib \
    "${SHIMDIR}"/bionic_pthread.c "${SHIMDIR}"/bionic_posix.c \
    "${SHIMDIR}"/bionic_android.c "${SHIMDIR}"/bionic_tlsdesc.c \
    "${SHIMDIR}"/bionic_varargs.c "${SHIMDIR}"/bionic_varargs.S \
    "${SHIMDIR}"/bionic_libc.c "${SHIMDIR}"/bionic_jmp.S \
    "${SHIMDIR}"/bionic_tlsdesc.S \
    -o "${OUT}/shimbuild/libbionic_shim.dylib" 2>&1 | tail -40 | tee -a "$REPORT"
SHIMDYLIB="${OUT}/shimbuild/libbionic_shim.dylib"
num "libbionic_shim.dylib $(stat -f%z "$SHIMDYLIB") bytes"
num "shim 导出符号 $(nm -gU "$SHIMDYLIB" | wc -l | tr -d ' ') 个"

# 符号覆盖门禁：guest 要的 132 个名字必须全部存在，缺一个就是运行时 dlopen 失败
say "stage 4b 符号覆盖门禁（清单 -> _bionic_*）"
python3 - "$ROOT/ios_port/shim_symbols.txt" > "${OUT}/expected_syms.txt" <<'EXPSYM'
import sys
for line in open(sys.argv[1]):
    s = line.strip()
    if not s or s.startswith('#'):
        continue
    print('_bionic_' + s)
EXPSYM
nm -gU "$SHIMDYLIB" | awk '{print $NF}' | sort -u > "${OUT}/actual_syms.txt"
MISSING="$(comm -23 <(sort -u "${OUT}/expected_syms.txt") "${OUT}/actual_syms.txt" || true)"
NEXP=$(wc -l < "${OUT}/expected_syms.txt" | tr -d ' ')
if [ -n "$MISSING" ]; then
    echo "缺 $(echo "$MISSING" | wc -l | tr -d ' ') 个 / 共 $NEXP：" | tee -a "$REPORT"
    echo "$MISSING" | head -40 | tee -a "$REPORT"
    echo "::error::libbionic_shim 符号未覆盖，dlopen 会失败"
    exit 1
fi
num "符号覆盖 $NEXP / $NEXP 全部就位"

# ---------- 5) 宿主 ----------
say "stage 5/7 编译 MewHost"
# 宿主也要链 SDL3：缺数据时要弹 SDL_ShowSimpleMessageBox，光声明不链接会在
# dyld 绑定时 "symbol not found"。framework 就在包里 Frameworks/ 下，用 rpath 找。
"$CLANG" -target "${ARCH}-apple-ios${MIN_IOS}" -isysroot "$SDK" -O2 \
    -F "${OUT}/sdlbuild" -framework SDL3 -I "${OUT}/sdlbuild/SDL3.framework/Headers" \
    -o "${OUT}/shimbuild/MewHost" "${ROOT}/ios_port/host_main.c" \
    -Wl,-rpath,@executable_path/Frameworks 2>&1 | tail -20 | tee -a "$REPORT"
num "MewHost $(stat -f%z "${OUT}/shimbuild/MewHost") bytes"

# ---------- 6) 组 app + ad-hoc 签名 ----------
say "stage 6/7 组 .app 并 ad-hoc 签名"
APP="${OUT}/Mewgenics.app"
rm -rf "$APP"
mkdir -p "$APP/Frameworks"
cp "${OUT}/shimbuild/MewHost" "$APP/MewHost"
cp "${ROOT}/ios_port/ios_app/Info.plist" "$APP/Info.plist"
if [ -d "${ROOT}/ios_port/ios_app/icons" ]; then
    cp "${ROOT}/ios_port/ios_app/icons"/*.png "$APP/" 2>/dev/null || true
fi
cp "${OUT}/libmew_relinked.dylib" "$APP/Frameworks/libmew_relinked.dylib"
cp "${OUT}/shimbuild/libbionic_shim.dylib" "$APP/Frameworks/libbionic_shim.dylib"
if [ -n "$SDLF" ]; then
    cp -R "$SDLF" "$APP/Frameworks/"
else
    mkdir -p "$APP/Frameworks/SDL3.framework/Headers"
    cp "$SDLDYLIB" "$APP/Frameworks/SDL3.framework/SDL3"
fi
SDLFW="$APP/Frameworks/SDL3.framework/Info.plist" python3 <<'PY' | tee -a "$REPORT"
import os, plistlib
plistlib.dump({
    'CFBundleIdentifier': 'org.libsdl.SDL3',
    'CFBundleName': 'SDL3',
    'CFBundleExecutable': 'SDL3',
    'CFBundlePackageType': 'FMWK',
    'CFBundleShortVersionString': '3.2.0',
    'CFBundleVersion': '1',
    'MinimumOSVersion': '15.0',
}, open(os.environ['SDLFW'], 'wb'))
print('    SDL3.framework/Info.plist 已写')
PY

codesign --force --sign - --timestamp=none "$APP/Frameworks/SDL3.framework" 2>&1 | tee -a "$REPORT"
for f in "$APP/Frameworks/libbionic_shim.dylib" "$APP/Frameworks/libmew_relinked.dylib" "$APP/MewHost"; do
    codesign --force --sign - --timestamp=none "$f" 2>&1 | tee -a "$REPORT"
done
codesign --force --sign - --timestamp=none "$APP" 2>&1 | tee -a "$REPORT"
codesign -dvv "$APP/MewHost" 2>&1 | grep -E 'Identifier|Format|CodeDirectory' | tee -a "$REPORT" || true
say "otool -L MewHost"
otool -L "$APP/MewHost" | tee -a "$REPORT"
say "otool -L libmew_relinked.dylib（前 12 行，确认 @rpath 就位）"
otool -L "$APP/Frameworks/libmew_relinked.dylib" | head -12 | tee -a "$REPORT"

# ---------- 7) 打 ipa ----------
say "stage 7/7 打包 ad-hoc .ipa"
PAY="${OUT}/Payload"
rm -rf "$PAY"
mkdir -p "$PAY"
cp -R "$APP" "$PAY/"
IPA="${OUT}/Mewgenics-relink-v0.1.0-unsigned.ipa"
rm -f "$IPA"
(cd "$OUT" && zip -qry "$IPA" Payload)
num "app $(du -sm "$APP" | cut -f1) MB"
num "ipa $(stat -f%z "$IPA") bytes"

say "汇总"
num "libmew_relinked.dylib $(stat -f%z "${OUT}/libmew_relinked.dylib") bytes"
ls -l "$OUT"/*.ipa | tee -a "$REPORT"

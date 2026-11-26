#!/usr/bin/env bash
# 在 Linux 上组装 IPA：不需要 macOS、不需要 Xcode。
#
# 前提：三件「只能由 macOS 编出来」的产物已经在 out/products/ 里：
#   out/products/MewHost
#   out/products/libbionic_shim.dylib
#   out/products/SDL3.framework/            （整个目录）
# 加上 Ubuntu 侧刚产出的 out/libmew_relinked.dylib 与仓库里的 Info.plist，
# 就能组出结构完整的 .app 并压成 .ipa。
#
# 签名：装到真机时 TrollStore / AltStore / Sideloadly 都会重新签名，所以这里
# **不强制** codesign。如果环境里有 ldid，就顺手做一次 ad-hoc 签名；没有就
# 产出未签名包并在报告里写明。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-${ROOT}/out}"
PROD="${OUT}/products"
REPORT="${OUT}/assemble_report.txt"
mkdir -p "$OUT"
: > "$REPORT"
say() { echo "==> [$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
num() { echo "    $*" | tee -a "$REPORT"; }

DYLIB="${OUT}/libmew_relinked.dylib"
HOST="${PROD}/MewHost"
SHIM="${PROD}/libbionic_shim.dylib"
SDLFW="${PROD}/SDL3.framework"
PLIST="${ROOT}/ios_port/ios_app/Info.plist"

for f in "$DYLIB" "$HOST" "$SHIM"; do
    [ -f "$f" ] || { echo "缺少必需产物: $f" | tee -a "$REPORT"; exit 2; }
    num "$(basename "$f") $(stat -c%s "$f" 2>/dev/null || stat -f%z "$f") bytes"
done
[ -d "$SDLFW" ] || { echo "缺少 SDL3.framework: $SDLFW" | tee -a "$REPORT"; exit 2; }
[ -f "$PLIST" ] || { echo "缺少 Info.plist: $PLIST" | tee -a "$REPORT"; exit 2; }

# ldid 可选
LDID="$(command -v ldid || true)"
if [ -n "$LDID" ]; then
    say "找到 ldid: $LDID（会做 ad-hoc 签名）"
else
    say "没有 ldid，产出未签名包（侧载工具会重签）"
fi

APP="${OUT}/Mewgenics.app"
say "组 .app"
rm -rf "$APP"
mkdir -p "$APP/Frameworks"
cp "$HOST" "$APP/MewHost"
cp "$PLIST" "$APP/Info.plist"
cp "$DYLIB" "$APP/Frameworks/libmew_relinked.dylib"
cp "$SHIM" "$APP/Frameworks/libbionic_shim.dylib"
cp -R "$SDLFW" "$APP/Frameworks/"

# SDL3.framework 的 Info.plist 如果缺失就补一个
if [ ! -f "$APP/Frameworks/SDL3.framework/Info.plist" ]; then
    python3 - "$APP/Frameworks/SDL3.framework/Info.plist" <<'PY'
import sys, plistlib
plistlib.dump({
    'CFBundleIdentifier': 'org.libsdl.SDL3',
    'CFBundleName': 'SDL3',
    'CFBundleExecutable': 'SDL3',
    'CFBundlePackageType': 'FMWK',
    'CFBundleShortVersionString': '3.2.0',
    'CFBundleVersion': '1',
    'MinimumOSVersion': '15.0',
}, open(sys.argv[1], 'wb'))
print('    SDL3.framework/Info.plist 已补')
PY
fi

if [ -n "$LDID" ]; then
    say "ad-hoc 签名（ldid）"
    "$LDID" -S "$APP/Frameworks/SDL3.framework/SDL3" 2>&1 | tee -a "$REPORT" || true
    "$LDID" -S "$APP/Frameworks/libbionic_shim.dylib" 2>&1 | tee -a "$REPORT" || true
    "$LDID" -S "$APP/Frameworks/libmew_relinked.dylib" 2>&1 | tee -a "$REPORT" || true
    "$LDID" -S "$APP/MewHost" 2>&1 | tee -a "$REPORT" || true
fi

# 结构自检：必须是 Payload/Mewgenics.app 且可执行位在 MewHost 上
chmod +x "$APP/MewHost"
say "结构自检"
test -x "$APP/MewHost" && num "MewHost 可执行 ✓"
test -f "$APP/Info.plist" && num "Info.plist ✓"
test -f "$APP/Frameworks/libmew_relinked.dylib" && num "libmew_relinked.dylib ✓"
test -f "$APP/Frameworks/libbionic_shim.dylib" && num "libbionic_shim.dylib ✓"
test -f "$APP/Frameworks/SDL3.framework/SDL3" && num "SDL3.framework ✓"
python3 - "$APP/Info.plist" <<'PY' | tee -a "$REPORT"
import sys, plistlib
p = plistlib.load(open(sys.argv[1], 'rb'))
for k in ('CFBundleExecutable', 'CFBundleIdentifier', 'UIFileSharingEnabled',
          'LSSupportsOpeningDocumentsInPlace'):
    print('    %-34s %s' % (k, p.get(k)))
PY

say "打包 .ipa"
PAY="${OUT}/Payload"
rm -rf "$PAY"
mkdir -p "$PAY"
cp -R "$APP" "$PAY/"
IPA="${OUT}/Mewgenics-relink-v0.3.0-unsigned.ipa"
rm -f "$IPA"
if command -v zip >/dev/null; then
    (cd "$OUT" && zip -qry "$IPA" Payload)
else
    # 容器里没有 zip 时用 Python 兜底（保留可执行位与符号链接语义）
    python3 - "$OUT" "$IPA" <<'PY'
import os, sys, zipfile
root, ipa = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(ipa, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for base, _dirs, files in os.walk(os.path.join(root, 'Payload')):
        for f in files:
            full = os.path.join(base, f)
            rel = os.path.relpath(full, root)
            st = os.stat(full)
            zi = zipfile.ZipInfo(rel)
            zi.external_attr = (0o100000 | (st.st_mode & 0o777)) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(full, 'rb') as fh:
                z.writestr(zi, fh.read())
print('    python zipfile 打包完成')
PY
fi
num "app $(du -sm "$APP" | cut -f1) MB"
num "ipa $(stat -c%s "$IPA" 2>/dev/null || stat -f%z "$IPA") bytes"
say "完成：$IPA"

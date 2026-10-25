#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/validate_ui1.py
BDS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
BDS_COMMON=(-isysroot "$BDS_SDK" -miphoneos-version-min=15.0 -fobjc-arc -fblocks -Werror=return-type -Werror=implicit-function-declaration)
BDS_FRAMEWORKS=(-framework Foundation -framework UIKit -framework CoreGraphics -framework AdSupport -framework CoreTelephony -framework Security -framework WebKit -framework SystemConfiguration -framework CoreLocation -framework Contacts -framework EventKit)
mkdir -p build-ui1 dist-ui1
for BDS_ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$BDS_ARCH" "${BDS_COMMON[@]}" "${BDS_FRAMEWORKS[@]}" -dynamiclib -install_name @rpath/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib BDSpoofer.m -o "build-ui1/BDSpoofer_$BDS_ARCH.dylib"
    xcrun --sdk iphoneos clang -arch "$BDS_ARCH" "${BDS_COMMON[@]}" -framework Foundation -framework UIKit -framework CoreGraphics CraneManager/BDSCraneManager.m -o "build-ui1/BDSCraneManager_$BDS_ARCH"
done
lipo -create build-ui1/BDSpoofer_arm64.dylib build-ui1/BDSpoofer_arm64e.dylib -output dist-ui1/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib
codesign --force --sign - --timestamp=none dist-ui1/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib
BDS_APP=build-ui1/package/Applications/BDSCraneManager.app
mkdir -p "$BDS_APP" build-ui1/package/Library/libSandy build-ui1/package/DEBIAN build-ui1/deb
lipo -create build-ui1/BDSCraneManager_arm64 build-ui1/BDSCraneManager_arm64e -output "$BDS_APP/BDSCraneManager"
cp CraneManager/Info.plist bdspoofer_config.plist CraneManager/AppIcon60x60@2x.png CraneManager/AppIcon60x60@3x.png "$BDS_APP/"
cp CraneManager/BDSCraneManager.libSandy.plist build-ui1/package/Library/libSandy/BDSCraneManager.plist
cp CraneManager/control CraneManager/postinst CraneManager/prerm build-ui1/package/DEBIAN/
chmod 0755 "$BDS_APP/BDSCraneManager" build-ui1/package/DEBIAN/postinst build-ui1/package/DEBIAN/prerm
codesign --force --sign - --timestamp=none --entitlements CraneManager/BDSCraneManager.entitlements "$BDS_APP"
printf '2.0\n' > build-ui1/deb/debian-binary
COPYFILE_DISABLE=1 tar -C build-ui1/package/DEBIAN -czf build-ui1/deb/control.tar.gz .
COPYFILE_DISABLE=1 tar -C build-ui1/package --exclude='./DEBIAN' -czf build-ui1/deb/data.tar.gz .
(cd build-ui1/deb && ar -rc ../../dist-ui1/BDSpooferCraneManager_1.0.3-ui1_10.18.02_RootHide.deb debian-binary control.tar.gz data.tar.gz)
codesign --verify --strict dist-ui1/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib
codesign --verify --strict "$BDS_APP"
lipo -info dist-ui1/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib
lipo -info "$BDS_APP/BDSCraneManager"
otool -hv dist-ui1/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib
otool -L dist-ui1/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib
ar -t dist-ui1/BDSpooferCraneManager_1.0.3-ui1_10.18.02_RootHide.deb
tar -tzf build-ui1/deb/data.tar.gz
cp RELEASE_UI1.md bdspoofer_config.plist dist-ui1/
cp dist-ui1/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib "dist-ui1/鍗愯В_1.8.1_UI1.3_10.18.05.dylib"
cp dist-ui1/BDSpooferCraneManager_1.0.3-ui1_10.18.02_RootHide.deb "dist-ui1/鍗嶈В_1.0.2_UI1.3_10.17.09_RootHide.deb"
# 浜や粯鍛藉悕锛歁 = 鎻掍欢 dylib锛孹 = 绠＄悊鍣?deb锛岀増鏈彿閫掑
cp dist-ui1/BDSpoofer_1.8.1_UI1.3_10.18.05.dylib "dist-ui1/M-10.18.05.dylib"
cp dist-ui1/BDSpooferCraneManager_1.0.3-ui1_10.18.02_RootHide.deb "dist-ui1/X-10.18.02.deb"
(cd dist-ui1 && shasum -a 256 M-10.18.05.dylib X-10.18.02.deb BDSpoofer_1.8.1_UI1.3_10.18.05.dylib BDSpooferCraneManager_1.0.3-ui1_10.18.02_RootHide.deb > SHA256SUMS.txt)

# L2TP看门：只注入 SpringBoard，不进极速。
GUARD_ROOT=build-ui1/l2tpguard
rm -rf "$GUARD_ROOT"
mkdir -p "$GUARD_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries" \
         "$GUARD_ROOT/var/jb/var/mobile/Library/Preferences" \
         "$GUARD_ROOT/DEBIAN" build-ui1/guarddeb
for BDS_ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$BDS_ARCH" "${BDS_COMMON[@]}" \
        -framework Foundation -framework UIKit \
        -dynamiclib -install_name @rpath/L2TPGuard.dylib \
        L2TPGuard/L2TPGuard.m -o "build-ui1/L2TPGuard_$BDS_ARCH.dylib"
done
lipo -create build-ui1/L2TPGuard_arm64.dylib build-ui1/L2TPGuard_arm64e.dylib \
    -output "$GUARD_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries/L2TPGuard.dylib"
cp L2TPGuard/L2TPGuard.plist "$GUARD_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries/L2TPGuard.plist"
cp L2TPGuard/com.bds.l2tpguard.plist "$GUARD_ROOT/var/jb/var/mobile/Library/Preferences/com.bds.l2tpguard.plist"
cp L2TPGuard/control L2TPGuard/postinst "$GUARD_ROOT/DEBIAN/"
chmod 0755 "$GUARD_ROOT/DEBIAN/postinst"
codesign --force --sign - --timestamp=none "$GUARD_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries/L2TPGuard.dylib"
printf '2.0\n' > build-ui1/guarddeb/debian-binary
COPYFILE_DISABLE=1 tar -C "$GUARD_ROOT/DEBIAN" -czf build-ui1/guarddeb/control.tar.gz .
COPYFILE_DISABLE=1 tar -C "$GUARD_ROOT" --exclude='./DEBIAN' -czf build-ui1/guarddeb/data.tar.gz .
(cd build-ui1/guarddeb && ar -rc ../../dist-ui1/L2TPGuard_10.17.09_RootHide.deb debian-binary control.tar.gz data.tar.gz)
(cd dist-ui1 && shasum -a 256 L2TPGuard_10.17.09_RootHide.deb >> SHA256SUMS.txt)

# ── 快手检测探针（只读，不修改 App 逻辑）──
for BDS_ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$BDS_ARCH" "${BDS_COMMON[@]}" \
        -framework Foundation -framework UIKit -framework CoreGraphics \
        -dynamiclib -install_name @rpath/KSProbe.dylib \
        KSProbe/KSProbe.m -o "build-ui1/KSProbe_$BDS_ARCH.dylib"
done
lipo -create build-ui1/KSProbe_arm64.dylib build-ui1/KSProbe_arm64e.dylib \
    -output "dist-ui1/KSProbe.dylib"
codesign --force --sign - --timestamp=none "dist-ui1/KSProbe.dylib"
codesign --verify --strict "dist-ui1/KSProbe.dylib"
lipo -info "dist-ui1/KSProbe.dylib"

# ── 快手设备信息伪装插件（KSSpoofer）──
for BDS_ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$BDS_ARCH" "${BDS_COMMON[@]}"         -framework Foundation -framework UIKit -framework CoreGraphics -framework Security -framework AdSupport         -dynamiclib -install_name @rpath/KSSpoofer.dylib         KSSpoofer/KSSpoofer.m -o "build-ui1/KSSpoofer_$BDS_ARCH.dylib"
done
lipo -create build-ui1/KSSpoofer_arm64.dylib build-ui1/KSSpoofer_arm64e.dylib     -output "dist-ui1/KSSpoofer.dylib"
codesign --force --sign - --timestamp=none "dist-ui1/KSSpoofer.dylib"
codesign --verify --strict "dist-ui1/KSSpoofer.dylib"
lipo -info "dist-ui1/KSSpoofer.dylib"

# ── 快手伪装 deb（和极速一样的安装方式）──
KSDEB_ROOT=build-ui1/ksspooferdeb_root
KSDEB_OUT=build-ui1/ksspooferdeb
rm -rf "$KSDEB_ROOT" "$KSDEB_OUT"
mkdir -p "$KSDEB_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries" "$KSDEB_ROOT/DEBIAN" "$KSDEB_OUT"
cp dist-ui1/KSSpoofer.dylib "$KSDEB_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries/KSSpoofer.dylib"
cp KSSpoofer/KSSpoofer.plist "$KSDEB_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries/KSSpoofer.plist"
cp KSSpoofer/control KSSpoofer/postinst "$KSDEB_ROOT/DEBIAN/"
chmod 0755 "$KSDEB_ROOT/DEBIAN/postinst"
codesign --force --sign - --timestamp=none "$KSDEB_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries/KSSpoofer.dylib"
printf '2.0\n' > "$KSDEB_OUT/debian-binary"
COPYFILE_DISABLE=1 tar -C "$KSDEB_ROOT/DEBIAN" -czf "$KSDEB_OUT/control.tar.gz" .
COPYFILE_DISABLE=1 tar -C "$KSDEB_ROOT" --exclude='./DEBIAN' -czf "$KSDEB_OUT/data.tar.gz" .
(cd "$KSDEB_OUT" && ar -rc ../../dist-ui1/KSSpoofer_10.18.06_RootHide.deb debian-binary control.tar.gz data.tar.gz)
(cd dist-ui1 && shasum -a 256 KSSpoofer_10.18.06_RootHide.deb >> SHA256SUMS.txt)

# ── 快手伪装管理器 App（独立图标，先随机再启动快手）──
KSMGR_ROOT=build-ui1/ksmanager
KSMGR_APP="$KSMGR_ROOT/Applications/KSSpooferManager.app"
rm -rf "$KSMGR_ROOT"
mkdir -p "$KSMGR_APP" "$KSMGR_ROOT/DEBIAN" build-ui1/ksmgrdeb
for BDS_ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$BDS_ARCH" "${BDS_COMMON[@]}" \
        -framework Foundation -framework UIKit -framework CoreGraphics \
        KSSpooferManager/main.m -o "build-ui1/KSSpooferManager_$BDS_ARCH"
done
lipo -create build-ui1/KSSpooferManager_arm64 build-ui1/KSSpooferManager_arm64e \
    -output "$KSMGR_APP/KSSpooferManager"
cp KSSpooferManager/Info.plist KSSpooferManager/AppIcon60x60@2x.png KSSpooferManager/AppIcon60x60@3x.png "$KSMGR_APP/"
codesign --force --sign - --timestamp=none --entitlements KSSpooferManager/KSSpooferManager.entitlements "$KSMGR_APP"
cp KSSpoofer/control.kSMGR "$KSMGR_ROOT/DEBIAN/control"
cat > "$KSMGR_ROOT/DEBIAN/postinst" << 'KSPOST'
#!/bin/sh
set -e
ROOT_PREFIX="/var/jb"
if [ "$(dpkg --print-architecture 2>/dev/null)" = "iphoneos-arm" ]; then
    ROOT_PREFIX=""
fi
APP_PATH="$ROOT_PREFIX/Applications/KSSpooferManager.app"
if [ -d "$APP_PATH" ]; then
    chown -R root:wheel "$APP_PATH" 2>/dev/null || true
    chmod 0755 "$APP_PATH/KSSpooferManager" 2>/dev/null || true
fi
if command -v uicache >/dev/null 2>&1; then
    uicache -p "$APP_PATH" >/dev/null 2>&1 || uicache >/dev/null 2>&1 || true
fi
exit 0
KSPOST
cat > "$KSMGR_ROOT/DEBIAN/prerm" << 'KSPRE'
#!/bin/sh
if command -v uicache >/dev/null 2>&1; then
    uicache -u com.bds.ksspooffer.manager >/dev/null 2>&1 || true
fi
exit 0
KSPRE
#!/bin/sh
LOG=/tmp/ksmgr_postinst.log
echo "=== $(date) postinst ===" > "$LOG"
APP_PATH=/var/jb/Applications/KSSpooferManager.app
[ -d "$APP_PATH" ] || APP_PATH=/Applications/KSSpooferManager.app
echo "APP_PATH=$APP_PATH" >> "$LOG"
if [ -d "$APP_PATH" ]; then
    chown -R root:wheel "$APP_PATH" 2>/dev/null || true
    chmod 0755 "$APP_PATH/KSSpooferManager" 2>/dev/null || true
    echo "chmod ok" >> "$LOG"
else
    echo "APP NOT FOUND" >> "$LOG"
fi
if command -v uicache >/dev/null 2>&1; then
    uicache -p "$APP_PATH" >> "$LOG" 2>&1 || uicache >> "$LOG" 2>&1 || true
    echo "uicache done" >> "$LOG"
else
    echo "uicache missing" >> "$LOG"
fi
command -v sbreload >/dev/null 2>&1 && sbreload >> "$LOG" 2>&1 || true
killall -9 com.jiangjia.gif 2>/dev/null || true
exit 0
KSPOST
chmod 0755 "$KSMGR_ROOT/DEBIAN/postinst" "$KSMGR_ROOT/DEBIAN/prerm"
printf '2.0\n' > build-ui1/ksmgrdeb/debian-binary
COPYFILE_DISABLE=1 tar -C "$KSMGR_ROOT/DEBIAN" -czf build-ui1/ksmgrdeb/control.tar.gz .
COPYFILE_DISABLE=1 tar -C "$KSMGR_ROOT" --exclude='./DEBIAN' -czf build-ui1/ksmgrdeb/data.tar.gz .
(cd build-ui1/ksmgrdeb && ar -rc ../../dist-ui1/KSSpooferManager_10.18.06.deb debian-binary control.tar.gz data.tar.gz)
(cd dist-ui1 && shasum -a 256 KSSpooferManager_10.18.06.deb >> SHA256SUMS.txt)

# ── 管理器 IPA（TrollStore 安装，一定有图标）──
KSIPA_ROOT=build-ui1/ksipa
rm -rf "$KSIPA_ROOT"
mkdir -p "$KSIPA_ROOT/Payload"
cp -R "$KSMGR_APP" "$KSIPA_ROOT/Payload/"
codesign --force --sign - --timestamp=none --entitlements KSSpooferManager/KSSpooferManager.entitlements "$KSIPA_ROOT/Payload/KSSpooferManager.app"
(cd "$KSIPA_ROOT" && zip -qry ../../dist-ui1/KSSpooferManager_10.18.06.ipa Payload)

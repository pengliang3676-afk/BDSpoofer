#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/validate_ui1.py
BDS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
BDS_COMMON=(-isysroot "$BDS_SDK" -miphoneos-version-min=15.0 -fobjc-arc -fblocks -Werror=return-type -Werror=implicit-function-declaration)
BDS_FRAMEWORKS=(-framework Foundation -framework UIKit -framework CoreGraphics -framework AdSupport -framework CoreTelephony -framework Security -framework WebKit -framework SystemConfiguration -framework CoreLocation -framework Contacts -framework EventKit)
mkdir -p build-ui1 dist-ui1
for BDS_ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$BDS_ARCH" "${BDS_COMMON[@]}" "${BDS_FRAMEWORKS[@]}" -dynamiclib -install_name @rpath/BDSpoofer_1.8.1_UI1.2_9.23-01.dylib BDSpoofer.m -o "build-ui1/BDSpoofer_$BDS_ARCH.dylib"
    xcrun --sdk iphoneos clang -arch "$BDS_ARCH" "${BDS_COMMON[@]}" -framework Foundation -framework UIKit -framework CoreGraphics CraneManager/BDSCraneManager.m -o "build-ui1/BDSCraneManager_$BDS_ARCH"
done
lipo -create build-ui1/BDSpoofer_arm64.dylib build-ui1/BDSpoofer_arm64e.dylib -output dist-ui1/BDSpoofer_1.8.1_UI1.2_9.23-01.dylib
codesign --force --sign - --timestamp=none dist-ui1/BDSpoofer_1.8.1_UI1.2_9.23-01.dylib
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
(cd build-ui1/deb && ar -rc ../../dist-ui1/BDSpooferCraneManager_1.0.2-ui1_9.23-01_RootHide.deb debian-binary control.tar.gz data.tar.gz)
codesign --verify --strict dist-ui1/BDSpoofer_1.8.1_UI1.2_9.23-01.dylib
codesign --verify --strict "$BDS_APP"
lipo -info dist-ui1/BDSpoofer_1.8.1_UI1.2_9.23-01.dylib
lipo -info "$BDS_APP/BDSCraneManager"
otool -hv dist-ui1/BDSpoofer_1.8.1_UI1.2_9.23-01.dylib
otool -L dist-ui1/BDSpoofer_1.8.1_UI1.2_9.23-01.dylib
ar -t dist-ui1/BDSpooferCraneManager_1.0.2-ui1_9.23-01_RootHide.deb
tar -tzf build-ui1/deb/data.tar.gz
cp RELEASE_UI1.md bdspoofer_config.plist dist-ui1/
cp dist-ui1/BDSpoofer_1.8.1_UI1.2_9.23-01.dylib "dist-ui1/卐解_1.8.1_UI1.2_9.23-01.dylib"
cp dist-ui1/BDSpooferCraneManager_1.0.2-ui1_9.23-01_RootHide.deb "dist-ui1/卍解_1.0.2_UI1_9.23-01_RootHide.deb"
(cd dist-ui1 && shasum -a 256 BDSpoofer_1.8.1_UI1.2_9.23-01.dylib BDSpooferCraneManager_1.0.2-ui1_9.23-01_RootHide.deb > SHA256SUMS.txt)

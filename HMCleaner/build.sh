#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build-hmcleaner dist-hmcleaner
COMMON=(-fobjc-arc -fblocks -O2 -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations -Werror=return-type -Werror=implicit-function-declaration)
CORE=(HMCleaner/HMEngine.m HMCleaner/HMEnvironment.m HMCleaner/HMFileStore.c)

xcrun --sdk macosx clang "${COMMON[@]}" -framework Foundation HMCleaner/Tests.m "${CORE[@]}" -o build-hmcleaner/tests
build-hmcleaner/tests | tee dist-hmcleaner/TEST_RESULTS.txt
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
for ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$ARCH" -isysroot "$SDK" -target "$ARCH-apple-ios15.0" \
        "${COMMON[@]}" -framework Foundation -framework UIKit \
        HMCleaner/HMCleaner.m "${CORE[@]}" -o "build-hmcleaner/HMCleaner-$ARCH"
done
APP=build-hmcleaner/package/Applications/HMCleaner.app
mkdir -p "$APP" build-hmcleaner/package/DEBIAN build-hmcleaner/package/Library/libSandy build-hmcleaner/deb
lipo -create build-hmcleaner/HMCleaner-arm64 build-hmcleaner/HMCleaner-arm64e -output "$APP/HMCleaner"
cp HMCleaner/Info.plist "$APP/"
swift HMCleaner/make_icon.swift "$APP"
cp HMCleaner/control HMCleaner/postinst HMCleaner/prerm build-hmcleaner/package/DEBIAN/
cp HMCleaner/HMCleaner.libSandy.plist build-hmcleaner/package/Library/libSandy/HMCleaner.plist
chmod 0755 "$APP/HMCleaner" build-hmcleaner/package/DEBIAN/postinst build-hmcleaner/package/DEBIAN/prerm
codesign --force --sign - --timestamp=none --entitlements HMCleaner/HMCleaner.entitlements "$APP"
codesign --verify --strict "$APP"
lipo "$APP/HMCleaner" -verify_arch arm64 arm64e
plutil -lint "$APP/Info.plist" HMCleaner/HMCleaner.entitlements
printf '2.0\n' > build-hmcleaner/deb/debian-binary
COPYFILE_DISABLE=1 tar -C build-hmcleaner/package/DEBIAN -czf build-hmcleaner/deb/control.tar.gz .
COPYFILE_DISABLE=1 tar -C build-hmcleaner/package --exclude='./DEBIAN' -czf build-hmcleaner/deb/data.tar.gz .
(cd build-hmcleaner/deb && ar -rc ../../dist-hmcleaner/HMCleaner_0.1.0_RootHide.deb debian-binary control.tar.gz data.tar.gz)
cp HMCleaner/README.md dist-hmcleaner/
git rev-parse HEAD > dist-hmcleaner/COMMIT.txt
(cd dist-hmcleaner && shasum -a 256 HMCleaner_0.1.0_RootHide.deb > SHA256SUMS.txt)
ar -t dist-hmcleaner/HMCleaner_0.1.0_RootHide.deb
tar -tzf build-hmcleaner/deb/data.tar.gz
otool -L "$APP/HMCleaner"

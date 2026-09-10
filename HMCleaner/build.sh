#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=1.2.1
BUILD=build-hmcleaner
OUT=dist-hmcleaner
PKG="$BUILD/package"
APP="$PKG/Applications/HMCleaner.app"
APP_HELPER="$APP/hmcleaner-helper"
CLI_HELPER="$PKG/usr/local/bin/hmcleaner"
COMMON=(-fobjc-arc -fblocks -O2 -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations -Werror=return-type -Werror=implicit-function-declaration)

rm -rf "$BUILD" "$OUT"
mkdir -p "$APP" "$PKG/usr/local/bin" "$PKG/DEBIAN" "$BUILD/deb" "$OUT"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
for ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$ARCH" -isysroot "$SDK" -target "$ARCH-apple-ios15.0" \
        "${COMMON[@]}" -framework Foundation -framework UIKit \
        HMCleaner/HMCleaner.m -o "$BUILD/gui-app-$ARCH"
    xcrun --sdk iphoneos clang -arch "$ARCH" -isysroot "$SDK" -target "$ARCH-apple-ios15.0" \
        "${COMMON[@]}" -framework Foundation -lsqlite3 \
        HMCleaner/hmcleaner-standalone.m -o "$BUILD/root-helper-$ARCH"
done

xcrun lipo -create "$BUILD/gui-app-arm64" "$BUILD/gui-app-arm64e" -output "$APP/HMCleaner"
xcrun lipo -create "$BUILD/root-helper-arm64" "$BUILD/root-helper-arm64e" -output "$APP_HELPER"
cp "$APP_HELPER" "$CLI_HELPER"
cp HMCleaner/Info.plist "$APP/"
swift HMCleaner/make_icon.swift "$APP"
cp HMCleaner/control HMCleaner/postinst HMCleaner/prerm "$PKG/DEBIAN/"
chmod 0755 "$APP/HMCleaner" "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"
chmod 4755 "$APP_HELPER" "$CLI_HELPER"

codesign --force --sign - --timestamp=none --entitlements HMCleaner/HMCleaner.entitlements "$APP_HELPER"
cp "$APP_HELPER" "$CLI_HELPER"
codesign --force --sign - --timestamp=none --entitlements HMCleaner/HMCleaner.entitlements "$APP"
chmod 4755 "$APP_HELPER" "$CLI_HELPER"
codesign --verify --strict "$APP"
codesign --verify --strict "$APP_HELPER"
codesign --verify --strict "$CLI_HELPER"
xcrun lipo "$APP/HMCleaner" -verify_arch arm64 arm64e
xcrun lipo "$APP_HELPER" -verify_arch arm64 arm64e
xcrun lipo "$CLI_HELPER" -verify_arch arm64 arm64e
plutil -lint "$APP/Info.plist" HMCleaner/HMCleaner.entitlements

printf '2.0\n' > "$BUILD/deb/debian-binary"
COPYFILE_DISABLE=1 tar -C "$PKG/DEBIAN" -czf "$BUILD/deb/control.tar.gz" .
COPYFILE_DISABLE=1 tar -C "$PKG" --exclude='./DEBIAN' -czf "$BUILD/deb/data.tar.gz" .
(cd "$BUILD/deb" && ar -rc "../../$OUT/HMCleaner_${VERSION}_RootHide.deb" debian-binary control.tar.gz data.tar.gz)

cp HMCleaner/README.md "$OUT/"
git rev-parse HEAD > "$OUT/COMMIT.txt"
shasum -a 256 HMCleaner/HMCleaner.m HMCleaner/hmcleaner-standalone.m \
    "$APP/HMCleaner" "$APP_HELPER" "$CLI_HELPER" "$OUT/HMCleaner_${VERSION}_RootHide.deb" > "$OUT/SHA256SUMS.txt"
xcrun lipo -archs "$APP/HMCleaner" > "$OUT/app-archs.txt"
xcrun lipo -archs "$APP_HELPER" > "$OUT/helper-archs.txt"
codesign -d --entitlements :- "$APP" > "$OUT/app-entitlements.txt" 2>&1
codesign -d --entitlements :- "$APP_HELPER" > "$OUT/helper-entitlements.txt" 2>&1
ar -t "$OUT/HMCleaner_${VERSION}_RootHide.deb" > "$OUT/deb-members.txt"
tar -tzvf "$BUILD/deb/data.tar.gz" > "$OUT/payload.txt"
python3 HMCleaner/verify_package.py "$OUT"

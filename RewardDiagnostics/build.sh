#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --test RewardDiagnostics/observer.test.cjs RewardDiagnostics/telemetry.test.cjs
BDSD_BUILD=build-ui1/reward-diagnostics
BDSD_DIST=dist-ui1/reward-diagnostics
mkdir -p "$BDSD_BUILD" "$BDSD_DIST"
python3 - <<'PY'
from pathlib import Path
import base64
script = Path("RewardDiagnostics/telemetry.js").read_bytes()
encoded = base64.b64encode(script).decode("ascii")
Path("build-ui1/reward-diagnostics/ObserverScript.h").write_text(
    'static NSString *const BDSDObserverBase64 = @"' + encoded + '";\n', encoding="utf-8")
PY
BDSD_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
for BDSD_ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$BDSD_ARCH" -isysroot "$BDSD_SDK" \
        -miphoneos-version-min=15.0 -fobjc-arc -fblocks -Wall -Wextra \
        -Wno-unused-parameter -Werror=return-type -Werror=implicit-function-declaration \
        -framework Foundation -framework UIKit -framework WebKit \
        -I "$BDSD_BUILD" -dynamiclib -install_name @rpath/BDSRewardDiagnostics_0.5.0.dylib \
        RewardDiagnostics/BDSRewardDiagnostics.m -o "$BDSD_BUILD/$BDSD_ARCH.dylib"
done
lipo -create "$BDSD_BUILD/arm64.dylib" "$BDSD_BUILD/arm64e.dylib" \
    -output "$BDSD_DIST/BDSRewardDiagnostics_0.5.0.dylib"
codesign --force --sign - --timestamp=none "$BDSD_DIST/BDSRewardDiagnostics_0.5.0.dylib"
codesign --verify --strict "$BDSD_DIST/BDSRewardDiagnostics_0.5.0.dylib"
lipo "$BDSD_DIST/BDSRewardDiagnostics_0.5.0.dylib" -verify_arch arm64 arm64e
lipo -info "$BDSD_DIST/BDSRewardDiagnostics_0.5.0.dylib"
otool -L "$BDSD_DIST/BDSRewardDiagnostics_0.5.0.dylib"
cp RewardDiagnostics/README.md "$BDSD_DIST/"
mkdir -p "$BDSD_DIST/RewardDiagnostics"
cp RewardDiagnostics/BDSRewardDiagnostics.m RewardDiagnostics/observer.js \
    RewardDiagnostics/observer.test.cjs RewardDiagnostics/telemetry.js RewardDiagnostics/telemetry.test.cjs RewardDiagnostics/build.sh RewardDiagnostics/README.md "$BDSD_DIST/RewardDiagnostics/"
(cd "$BDSD_DIST" && shasum -a 256 BDSRewardDiagnostics_0.5.0.dylib > SHA256SUMS.txt)

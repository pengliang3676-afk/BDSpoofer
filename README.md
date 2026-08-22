# BDSpoofer - 百度极速版设备信息虚拟化插件

通过 TrollFools 注入到百度极速版，虚拟化设备信息。

## 当前版本：1.5.0 默认开启与随机身份版

> 总开关、百度 SDK、Keychain、User-Agent 和越狱检测绕过默认开启；
> sysctl 保持关闭。随机身份由用户手动生成一次并持久保存，不会在启动时自动变化。

### 基础功能（默认开启）

- UIDevice：systemVersion、model、localizedModel、name、systemName、identifierForVendor
- ASIdentifierManager：advertisingIdentifier、isAdvertisingTrackingEnabled
- ATTrackingManager：trackingAuthorizationStatus（返回 denied）
- NSProcessInfo：operatingSystemVersion、operatingSystemVersionString、hostName、physicalMemory
- NSLocale：localeIdentifier
- CTTelephonyNetworkInfo / CTCarrier：运营商名称、MCC、MNC、国家码
- UIScreen：bounds、nativeBounds、scale
- NSFileManager：磁盘大小

### 高级功能（除 sysctl 外默认开启）

- **百度 SDK 标识**（spoofBaiduSDK）：hook CuidSDK、UTDIDModule、MobStat、DeviceIdentifierFetcher，返回伪造的 CUID/UTDID/DeviceID
- **sysctlbyname**（spoofSysctl）：配置项保留，但常规构建保持关闭且不生成对应 interpose
- **Keychain 拦截**（spoofKeychain）：查询的 access group、service、account、description、label 或 agrp 包含 baidu 时返回未找到
- **User-Agent**（spoofUserAgent）：hook WKWebView customUserAgent 和 NSMutableURLRequest 请求头，自动保持与系统版本一致。注意：只覆盖显式设置的 UA 和 WKWebView 的 UA，NSURLSession 自动生成的默认 UA 不经过这两个方法，可能无法覆盖。
- **越狱检测绕过**（bypassJailbreakDetect）：hook fileExistsAtPath/canOpenURL，对越狱路径和 URL scheme 返回否定结果

### 一键随机身份

高级功能面板末尾的“一键随机更换身份参数”会生成并持久保存新的 IDFA、IDFV、DeviceID、CUID、UTDID 和设备名称。后续 API 读取立即使用新值；App 已缓存的启动值不会被追溯修改。

### 不包含

- Cookie 过滤（后续版本）
- App Group 隔离（后续版本）
- MGCopyAnswer 私有 API（后续版本）
- WiFi SSID/BSSID、MAC 地址、本地 IP（后续版本）

## 编译

### GitHub Actions（推荐）

1. 将项目文件推送到 GitHub 仓库根目录：
   ```
   .github/workflows/build.yml
   BDSpoofer.m
   bdspoofer_config.plist
   README.md
   ```
2. Actions 自动编译
3. 在 Artifacts 下载 BDSpoofer.zip，解压得到 BDSpoofer.dylib

### 本地编译（macOS + Xcode）

```bash
SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)

# arm64
xcrun --sdk iphoneos clang -arch arm64 -isysroot "$SDK_PATH" -miphoneos-version-min=15.0 \
  -fobjc-arc -dynamiclib \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -framework AdSupport -framework CoreTelephony -framework Security -framework WebKit \
  -install_name @rpath/BDSpoofer.dylib -o BDSpoofer_arm64.dylib BDSpoofer.m

# arm64e
xcrun --sdk iphoneos clang -arch arm64e -isysroot "$SDK_PATH" -miphoneos-version-min=15.0 \
  -fobjc-arc -dynamiclib \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -framework AdSupport -framework CoreTelephony -framework Security -framework WebKit \
  -install_name @rpath/BDSpoofer.dylib -o BDSpoofer_arm64e.dylib BDSpoofer.m

# 合并
lipo -create BDSpoofer_arm64.dylib BDSpoofer_arm64e.dylib -output BDSpoofer.dylib
```

## 安装

1. 将 BDSpoofer.dylib 传到手机
2. 打开 TrollFools → 选择百度极速版 → 添加 dylib → 注入
3. 杀掉百度极速版重新打开
4. 点击右侧"隐"按钮打开配置；按钮可以拖动

## 配置建议

### 测试顺序

1. 先开启基础功能，用"公开 API 自检"确认生效
2. 逐项开启高级功能，每开一项重启 App 确认不崩溃
3. 推荐顺序：百度 SDK → sysctlbyname → User-Agent → 越狱检测绕过

### 多机防关联

每台手机必须修改为不同的值：
- idfa、idfv（UUID 格式）
- cuid、utdid（32 位十六进制）
- deviceID（UUID 格式）
- 设备名称

设备型号、系统版本、屏幕尺寸等硬件参数可以相同，但建议与真实设备匹配。

### 配置文件位置

"隐"面板会自动把配置写入百度极速版的 Documents 目录：
`/var/mobile/Containers/Data/Application/<UUID>/Documents/bdspoofer_config.plist`

也可以使用 Filza 手工放入或编辑同名 plist。

## 验证

1. 注入后先确认百度极速版能够正常启动和登录
2. 点击"隐"→"公开 API 自检"，确认基础 hook 生效
3. 在"我的 → 设置 → 关于"里查看系统版本是否变成配置值
4. 高级功能开启后，确认 App 不崩溃、登录正常

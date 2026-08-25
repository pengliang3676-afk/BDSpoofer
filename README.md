# BDSpoofer - 百度极速版设备信息虚拟化插件

通过 TrollFools 注入到百度极速版，虚拟化设备信息。

## 当前版本：1.8.0 统一 10 款机型随机版

> 基础功能 6 个开关继续默认开启；屏幕参数保持真机值。
> Keychain 和 User-Agent 默认关闭，其余现有高级/隐私功能保持原默认值。
> 随机参数只在用户手动点击时生成并持久保存，不会在启动时自动变化。

### 基础功能（默认开启）

- UIDevice：systemVersion、model、localizedModel、name、systemName、identifierForVendor
- ASIdentifierManager：advertisingIdentifier（遵循真实 ATT 状态）
- NSProcessInfo：operatingSystemVersion、operatingSystemVersionString、hostName、physicalMemory
- NSLocale：localeIdentifier
- CTTelephonyNetworkInfo / CTCarrier：运营商名称、MCC、MNC、国家码
- UIScreen：bounds、nativeBounds、scale（支持但默认关闭）
- NSFileManager：磁盘大小

### 高级功能

- **百度 SDK 标识**（spoofBaiduSDK）：hook CuidSDK、UTDIDModule、MobStat、DeviceIdentifierFetcher，返回伪造的 CUID/UTDID/DeviceID
- **sysctlbyname**（spoofSysctl）：返回配置的 hw.machine、hw.model、kern.osversion、kern.hostname
- **Keychain 拦截**（spoofKeychain，默认关闭）：查询的 access group、service、account、description、label 或 agrp 包含 baidu 时返回未找到
- **User-Agent**（spoofUserAgent，默认关闭）：只在用户明确填写自定义值时替换 WKWebView 和显式设置的请求头
- **越狱检测绕过**（bypassJailbreakDetect）：hook fileExistsAtPath/canOpenURL，对越狱路径和 URL scheme 返回否定结果

### 一键随机参数

“一键随机整套基础参数”从统一的 10 款机型池选择机型，并生成匹配的 iOS/Build、硬件型号、内存、磁盘、设备名称和主机名。机型池包含 iPhone 8、X、XR、XS、11、11 Pro、12 mini、12、13 mini、SE3；iPhone SE2 不参与随机。iPhone 8/X 只使用 iOS 15/16，其余机型使用 iOS 15-18。基础随机会保持 6 个基础开关开启，屏幕继续使用真机尺寸。

“一键随机整套高级参数”单独生成并持久保存 IDFA、IDFV、DeviceID、CUID 和 UTDID，不修改基础参数。

### 隐私功能

- WiFi、本地 IP、App Group、剪贴板、定位、代理、iCloud 容器保护
- 启动时间、CPU、磁盘剩余空间和电池信息处理
- 通讯录、日历权限返回拒绝
- WebKit 设备标识 Cookie 过滤，保留 BDUSS/STOKEN 登录 Cookie
- 相机和照片权限均不 Hook

### 不包含

- MGCopyAnswer 私有 API（后续版本）
- 相机权限 Hook
- 照片权限 Hook

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
  -framework SystemConfiguration -framework CoreLocation -framework Contacts -framework EventKit \
  -install_name @rpath/BDSpoofer_1.8.0.dylib -o BDSpoofer_1.8.0_arm64.dylib BDSpoofer.m

# arm64e
xcrun --sdk iphoneos clang -arch arm64e -isysroot "$SDK_PATH" -miphoneos-version-min=15.0 \
  -fobjc-arc -dynamiclib \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -framework AdSupport -framework CoreTelephony -framework Security -framework WebKit \
  -framework SystemConfiguration -framework CoreLocation -framework Contacts -framework EventKit \
  -install_name @rpath/BDSpoofer_1.8.0.dylib -o BDSpoofer_1.8.0_arm64e.dylib BDSpoofer.m

# 合并
lipo -create BDSpoofer_1.8.0_arm64.dylib BDSpoofer_1.8.0_arm64e.dylib -output BDSpoofer_1.8.0.dylib
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

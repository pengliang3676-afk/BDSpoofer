# 当前交付：1.8.2 UI1.2

插件与卍解的配套修改、默认开关和独立随机规则见 [UI1 发布说明](RELEASE_UI1.md)。反越狱检测底层实现本次保持原样。

---

# 卐解（BDSpoofer）- 百度极速版设备信息虚拟化插件

通过 TrollFools 注入到百度极速版，虚拟化设备信息。

## 当前版本：1.8.2 UI1.2

> 基础功能 7 项（含系统硬件参数）和反关联常规开关默认开启。
> 高级参数前 2 项（百度身份参数、防越狱检测）默认开启，后 4 项默认关闭；已有配置的开关选择保留。
> 出厂模板为 iPhone 17 Pro Max（iPhone18,2 / iOS 26.6 / 256GB），一键基础随机后按机型池重新抽取。
> 金额上报阻止功能默认关闭。
> 随机参数只在用户手动点击时生成并持久保存，不会在启动时自动变化。

### 基础功能（默认开启）

- UIDevice：systemVersion、model、localizedModel、name、systemName
- ASIdentifierManager：advertisingIdentifier（遵循真实 ATT 状态）
- NSProcessInfo：operatingSystemVersion、operatingSystemVersionString、hostName、physicalMemory
- NSLocale：localeIdentifier
- CTTelephonyNetworkInfo / CTCarrier：运营商名称、MCC、MNC、国家码
- **sysctlbyname**（spoofSysctl，默认开启）：返回配置的 hw.machine、hw.model、kern.osversion、kern.hostname
- UIScreen：bounds、nativeBounds、scale（支持但默认关闭）
- NSFileManager：磁盘大小

### 高级功能（前 2 项默认开启，后 4 项默认关闭）

- **高级身份**：identifierForVendor 使用已保存的 IDFV；高级随机仍由用户单独触发
- **百度 SDK 标识**（spoofBaiduSDK）：hook CuidSDK、UTDIDModule、MobStat、DeviceIdentifierFetcher，返回伪造的 CUID/UTDID/DeviceID
- **Keychain 拦截**（spoofKeychain，默认关闭）：查询的 access group、service、account、description、label 或 agrp 包含 baidu 时返回未找到
- **User-Agent**（spoofUserAgent，默认关闭）：只在用户明确填写自定义值时替换 WKWebView 和显式设置的请求头
- **越狱检测绕过**（bypassJailbreakDetect）：hook fileExistsAtPath/canOpenURL，对越狱路径和 URL scheme 返回否定结果

### 一键随机参数

注入插件和外部 Crane 配置器统一使用 36 款机型、78 个稳定 iOS/Build 资料生成兼容组合，覆盖 iPhone 8 至 iPhone 17 系列；iPhone SE2 保留兼容记录但不参与随机。iPhone 8/X 只匹配 iOS 15/16，新机型按实际最低系统版本选择，iPhone 11 及更新机型可以匹配 iOS 26。

“一键随机整套基础参数”会生成匹配的 iOS/Build、硬件型号、内存、磁盘、设备名称和主机名。屏幕继续使用真机尺寸；高级身份参数及高级开关不变。

基础随机会显式开启基础功能 7 项（含系统硬件参数），不改变高级参数组 6 项的开关状态；新配置中高级前 2 项默认开启，后 4 项默认关闭，需要时单独调整。

“一键随机整套高级参数”单独生成并持久保存 IDFA、IDFV、DeviceID、CUID 和 UTDID，不修改基础参数。

### 隐私功能

- WiFi、本地 IP、App Group、剪贴板、定位、代理、iCloud 容器保护
- 启动时间、CPU、磁盘剩余空间和电池信息处理
- 通讯录、日历权限返回拒绝
- WebKit 设备标识 Cookie 过滤，保留 BDUSS/STOKEN 登录 Cookie
- 相机和照片权限均不 Hook

### 兼容风险测试页面

- 集中显示 Keychain、App Group、WebKit Cookie、User-Agent 4 个开关
- 支持逐项切换、一键开启本页 4 项、一键关闭本页 4 项
- 这些项目可能影响登录、共享数据或网络请求，修改后需要重启 App

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
  -install_name @rpath/BDSpoofer_1.8.2_UI1.2.dylib -o BDSpoofer_1.8.2_arm64.dylib BDSpoofer.m

# arm64e
xcrun --sdk iphoneos clang -arch arm64e -isysroot "$SDK_PATH" -miphoneos-version-min=15.0 \
  -fobjc-arc -dynamiclib \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -framework AdSupport -framework CoreTelephony -framework Security -framework WebKit \
  -framework SystemConfiguration -framework CoreLocation -framework Contacts -framework EventKit \
  -install_name @rpath/BDSpoofer_1.8.2_UI1.2.dylib -o BDSpoofer_1.8.2_arm64e.dylib BDSpoofer.m

# 合并
lipo -create BDSpoofer_1.8.2_arm64.dylib BDSpoofer_1.8.2_arm64e.dylib -output BDSpoofer_1.8.2_UI1.2.dylib
```

## 安装

1. 将 BDSpoofer.dylib 传到手机
2. 打开 TrollFools → 选择百度极速版 → 添加 dylib → 注入
3. 杀掉百度极速版重新打开
4. 点击右侧"隐"按钮打开配置；按钮可以拖动

### 外部配置 Crane 容器（可选）

1. 保持上面的 dylib 注入不变。
2. 用 Sileo 安装 `BDSpooferCraneManager_1.0.3-ui1_RootHide.deb`。
3. 从桌面打开“卍解”，勾选一个或多个 Crane 容器并执行一键随机。
4. 配置会直接写入各容器自己的 `Documents/bdspoofer_config.plist`。尚未运行的容器可直接首次打开；已在后台运行的百度需要彻底结束后再打开。
5. 容器列表分别显示基础、高级、定向是否执行过随机；只给正在使用的容器标记“当前”。随机状态保存在各容器内部，删除容器时一并删除。

从未使用定向指纹的容器不会写入备用定向参数；执行定向一键随机时自动开启总开关和全部 5 个子开关，并写入一套匹配的系统、机型、屏幕、User-Agent 与 Push 参数。基础或高级模式的配置文件保持在约 4KB。

详细说明见 `CraneManager/README.md`。

## 配置建议

### 测试顺序

1. 在需要的 Crane 容器中点击“一键随机整套基础参数”，重启后用“公开 API 自检”确认生效
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

# 卍解 1.0.5

这是 BDSpoofer 1.9.0 的外部容器配置器，不替代 TrollFools 已注入的
`BDSpoofer_1.9.0.dylib`。

## 使用方式

1. 用 Sileo 安装 `BDSpooferCraneManager_1.0.5_RootHide.deb`。
2. 保持 BDSpoofer dylib 只注入百度极速版。
3. 从桌面打开“卍解”。
4. 勾选需要配置的 Crane 容器，按需要点击基础、高级或定向随机按钮。
5. 尚未运行过的容器可直接首次打开；已经在后台运行的百度需要彻底结束后再打开。

配置器通过 Crane 的 `libCrane` 接口枚举容器，并按 Crane 1.3.14 的实际目录
结构解析目标：`DEFAULT` 写入百度数据根目录，其他容器写入
`Library/___Crane_Containers/<ID>`。配置保存到各自的
`Documents/bdspoofer_config.plist`，写入后会立即回读核对容器 ID、机型和系统版本。

基础随机从 36 个机型中选择一个兼容组合，iPhone SE（第 2 代）不在随机池中；
开启基础、反关联和 3 项常规高级功能，同时关闭定向总开关及 5 个子开关。
定向随机先在界面选择系统版本、机型标识、屏幕参数、User-Agent、Push参数中的
一项或多项，再用同一次抽取的兼容机型/iOS 只更新已选类别；未选类别保持关闭且
参数不变。执行时会开启基础 6 项、常规高级 3 项及反关联 12 项。基础和定向随机
都保持 Keychain、App Group、WebKit Cookie、普通 User-Agent 这 4 个兼容风险
开关原状态，全局屏幕 Hook 保持关闭。

新容器首次生成 IDFA、IDFV、DeviceID、CUID 和 UTDID。之后再次随机基础参数时，
这些身份值保持不变；“一键随机整套高级参数”只重新生成这五项，不改变其他参数和开关。

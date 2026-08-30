# 百度 Crane 参数配置 1.0.0

这是 BDSpoofer 1.8.1 的外部容器配置器，不替代 TrollFools 已注入的
`BDSpoofer_1.8.1.dylib`。

## 使用方式

1. 用 Sileo 安装 `BDSpooferCraneManager_1.0.0_RootHide.deb`。
2. 保持 BDSpoofer dylib 只注入百度极速版。
3. 从桌面打开“百度容器配置”。
4. 勾选需要配置的 Crane 容器，点击“为选中容器一键随机”。
5. 尚未运行过的容器可直接首次打开；已经在后台运行的百度需要彻底结束后再打开。

配置器通过 Crane 官方 `libCrane` 接口枚举容器，并把配置写到所选容器的
`Documents/bdspoofer_config.plist`。每个容器单独保存，互不覆盖。

一键随机从 36 个机型中选择一个兼容组合，iPhone SE（第 2 代）不在随机池中。
基础 6 项和常规高级项随之开启；Keychain、App Group、WebKit Cookie、
User-Agent 这 4 个兼容风险开关保持原状态。

新容器首次生成 IDFA、IDFV、DeviceID、CUID 和 UTDID。之后再次随机基础参数时，
这些身份值保持不变，除非继续在注入插件里手动执行“高级参数随机”。

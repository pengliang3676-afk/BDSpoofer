# HMCleaner CLI 1.1.4 —— 河马剧场外部清理（RootHide deb，root 命令行）

只对 `com.cbn.hmjc`（含 com.cbn.hmjc.* 扩展）生效。**在 App 停止状态下由 root 运行**，不注入 App。
与 Codex 的 GUI 版（HMCleaner.m/HMEngine，桌面 App、只清 5 个文件、不碰钥匙串）并存，互不覆盖。

## 为什么需要它
Crane 新容器只给新沙盒文件，但 **Keychain 跨容器共享**（访问组 `WU3L875P4M.com.cbn.hmjc`）。
数美 FP_SEQ、听云 token、App 自有 local_deviceId 等钥匙串项在新容器仍可读，必须从外部按组清掉。

## 安装与使用
1. Actions 编译（**HMCleaner 目录需作为独立 git 仓库根推送**），安装 `HMCleaner_1.1.4_iphoneos-arm64e.deb`。
2. NewTerm / SSH（root）：

```
hmcleaner list       # 只列出匹配容器，不修改
hmcleaner all        # 推荐：杀进程并确认停止 + 清空全部容器数据 + 清钥匙串访问组
hmcleaner ids        # 杀进程 + 只删已取证 ID 残留文件/偏好键 + 清钥匙串
hmcleaner keychain   # 只清钥匙串访问组
```

## 安全设计
**失败立即中止（1.1.3 强化）**
- 容器发现阶段一旦失败立即退出；清理循环逐项检查 failures，hm_wipeIDs 每个操作段之间也拦截，
  任一段失败立即 return 不再执行后续删除；cfprefsd 只在文件阶段全部成功后才重启；
  文件阶段有任何失败都不进入钥匙串步骤（已完成的修改不回滚，需用备份核对）。
- KERN_PROC 扩容重试 3 次；TERM→等待→KILL→再枚举确认消失；主 App 与 .appex/helper 都覆盖。

**路径不越界（1.1.4 强化）**
- hm_pathClass 锚定容器根对整条路径做四态分类：干净缺失(0)/真实目录(1)/不安全(2，链接、非目录、中间级缺失)/I-O错误(3)；
  任一级是符号链接或读取报错都计失败，绝不靠"再 lstat 一次末级"把错误吞成"不存在"；
- Crane 入口覆盖 c→Library→___Crane_Containers 整条链，偏好覆盖容器根→Preferences 的每一级；
- Crane 递归中普通文件（plist/数据库）正常跳过，只有符号链接/lstat 失败才计失败；
- Crane 副本递归收集；先清副本、最后清主容器；主容器清空 Library 时跳过 ___Crane_Containers。

**备份与恢复（1.1.2 修复）**
- 备份根固定 `/var/mobile/Library/Application Support/HMCleaner/Backups`（修复双层 HMCleaner）：
  逐级校验非链接、逐级创建、只对本次新建目录 lchown、Backups 强制 0700 并检查结果；
- 偏好备份文件名只清洗文件名组件再拼接（修复对完整路径替换 / 导致的相对路径落点）；
- 备份失败则保持原文件不动；损坏 plist（解析报错）计失败中止，合法非字典 plist 正常跳过；
  改写后仅对该文件 lchown 恢复原属主、chmod 恢复原权限并检查；
  保留原二进制/XML 格式；不再对整个容器递归 chown。

**钥匙串**
- 路径候选含实际的 `/private/var/Keychains/keychain-2.db`，经 jbroot()/rootfs()/JBRootPath/直接/var/jb/rootfs 展开；
- 删除前 sqlite3 Backup API 一致性在线备份（覆盖 WAL），备份失败立即中止；
- busy_timeout + BEGIN IMMEDIATE，逐步检查返回值，失败 ROLLBACK 中止且不重启 securityd；
- 按 agrp 整组删 genp/inet/keys/cert，COMMIT 后计数复核 + quick_check；
- 提示 iCloud sync=1 条目可能回补；成功后重启 securityd/cfprefsd。

## 已知边界
- **可恢复范围**：只有偏好 plist 和钥匙串在容器外有备份；all/ids 删除的普通文件与目录不逐个备份、不可恢复；
- 整组删除会移除该访问组内全部条目（含登录凭据/证书），换号场景适用；需要保留登录态时不要用；
- iCloud 钥匙串开启时 sync=1 条目理论上可能回补，工具会打印数量提示；
- RootHide 上 root/SSH 进程仍可能继承沙盒；CLI 必须以 `platform-application`/`no-container`/`no-sandbox`/`AppDataContainers`
  entitlement 签名才能读取应用容器，但不依赖 GUI 版的 libSandy Crane mach 扩展；
- 只清本机，不影响云端历史画像；清理期间不要手动打开河马。

## 标准换号 SOP
杀河马 → Crane 新建容器 → `hmcleaner all` → 换 IP 节点 → 冷启动（HMSpoofer 自动出新身份）→ 注册。

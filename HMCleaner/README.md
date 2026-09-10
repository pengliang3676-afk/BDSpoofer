# 河马清理 1.2.1

RootHide 越狱环境的桌面 App，目标固定为河马剧场 `com.cbn.hmjc`。通过 Sileo 安装后显示“河马清理”图标，不注入河马 App。

## 使用

1. 打开桌面的“河马清理”。
2. 可先点“只读检测容器”核对主容器和 Crane 分身。
3. 点“执行全部清理”，在系统确认框中再次点“执行清理”。
4. 等待界面显示“清理完成”，换 IP 后把河马从后台划掉并重新打开。

不需要 NewTerm、`sudo` 或输入密码。执行期间不要打开河马或切换 Crane 容器。

## 实际清理范围

- 结束并确认停止 `com.cbn.hmjc` 主 App、扩展和 helper 进程。
- Crane 分身先、主容器最后，清空全部匹配容器的数据，保留 `___Crane_Containers` 结构。
- 清理钥匙串访问组 `WU3L875P4M.com.cbn.hmjc`，完成后重启 `securityd` 和 `cfprefsd`。
- 普通文件删除没有逐个备份、不可恢复。
- 偏好 plist 在定点 `ids` 模式中修改前备份；钥匙串清理前创建一致性数据库备份。备份统一位于 `/var/mobile/Library/Application Support/HMCleaner/Backups`。
- iCloud 可同步钥匙串项在开启 iCloud 钥匙串时可能再次同步回来。

界面只允许固定的 `list` 和 `all`，不接受自定义路径或任意 shell 命令。包内命令行助手仍支持 root 下手工运行：

```sh
hmcleaner list
hmcleaner all
hmcleaner ids
hmcleaner keychain
```

无参数启动助手会显示用法并拒绝执行，避免误触发完整清理。

## 权限设计

桌面 App 本身以普通移动用户运行；App 内置 `hmcleaner-helper` 是固定目标、固定模式的提权助手，另在 `/usr/local/bin/hmcleaner` 保留同一助手的命令行副本。安装脚本将两者设为 `root:wheel`、模式 `4755`。助手不执行外部 shell，不接受路径参数，只处理编译时写死的河马 Bundle ID、容器和钥匙串访问组。

路径安全、失败中止和钥匙串事务逻辑沿用真机验证过的 1.1.4 核心：路径逐级 `lstat` 四态分类，任何链接、不确定或 I/O 错误都计失败；文件阶段失败不会继续进入钥匙串阶段。已经完成的普通文件删除不会自动回滚。

## 安装与构建

软件包 ID 为 `com.peng.hmcleaner`，1.2.1 会直接升级现有 CLI 1.1.4/桌面版 1.2.0，避免两个包同时占用 `/usr/local/bin/hmcleaner`。同时声明替换旧 GUI 包 `com.codex.hmcleaner`。

在带 iPhoneOS SDK 的 macOS 上运行：

```sh
bash HMCleaner/build.sh
```

构建脚本编译 arm64 + arm64e 的桌面 App 和助手，签名、封装并运行只读包验证。构建成功不等于真机上的图标、提权和清理流程已经验证；这些需要安装后的设备测试。

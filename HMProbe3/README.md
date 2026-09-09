# HMProbe3 —— 河马剧场 只读诊断探针 v3

在 v2（SDK 普查 / 设备出口 / 网络 / 风控类深度枚举 / Keychain / NSUserDefaults / ObjC 文件写入）基础上，补齐三个盲区：**启动最早期取值、C 层落盘、快照截断**。
**全程只读**：不改任何返回值、不拦截任何请求、不外传数据；报告只写到 App 沙盒 Documents 并可手动导出。

## v3 相对 v2 的改动
1. **Hook 安装提前到 constructor（pre-main）**
   - v2 的固定目标/Defaults/文件 Hook/首轮深度枚举在启动后 0.1~0.3s 才装，数美 getDeviceId、UMID getSyncUmid 在更早几十毫秒内已取缓存，导致 0 命中。
   - v3 在 constructor 内先**同步安装一轮**（ObjC runtime 在 pre-main 可用，幂等），之后仍由主队列 0.5s×60 重试覆盖晚加载类（Flutter/广告 SDK）。
2. **新增 7.2：C 层 open/openat/fopen 观测（dyld interpose，全镜像生效）**
   - 只记录“以写方式打开、且路径在本 App 沙盒内”的路径（O_RDONLY 与沙盒外直接放行，热路径只做 C 字符串前缀比较）。
   - 每个路径去重、计次，首次抓短栈；重点钉死 v2 遗留疑似文件：Documents/.PID4SM.txt、FP_SEQ.txt、come2、PdnuLKiM、.UTSystemConfig/Alvin。
   - 原函数使用 dyld interposer 镜像内的直接系统符号绑定，避免 dlsym 结果再次应用 interpose 后回到包装函数；记录过程保持原始 errno。
3. **沙盒快照增强**
   - 完整目录树上限 500 → 3000，关键词命中 120 → 300；
   - 新增“小文件清单（≤4KB）”，重点找 ID 小文件；
   - 目录树/清单中运行期被 ObjC 或 C 层写过的文件标 `[运行期写]`，关键词命中标 `[重点]`；
   - 输出超限未列计数。

v2 的九节结构、ABI 白名单、Keychain 不记值、脱敏、线程局部递归抑制、自身镜像栈帧剔除、浮窗透传全部保留。

## 门控
仅在 App 显示名含“河马”或 bundleId 含 hema/hmjc/hemojc 的主进程运行，跳过 .appex。

## 操作步骤
1. Codex 只读复审本工程；通过后 Actions 编译（arm64+arm64e，链接 Security.framework，产物 HMProbe3.dylib）；
2. TrollFools 注入前**先移除 HMProbe2**，避免两个探针同时挂；
3. 杀进程冷启动（constructor 首轮安装只有冷启动才赶在 SDK 取值前）→ 打标记 → 走登录/任务 2~3 分钟 → 点「HM探针3 导出」；
4. 重点看：
   - 四：数美 getDeviceId/getVdata 这次是否有命中与返回样本；
   - 7.2：.PID4SM.txt / FP_SEQ.txt 等是被谁（短栈）以写方式打开；
   - 七小文件清单：哪些 ≤4KB 文件带 [运行期写][重点]。

## 边界（v3 仍不覆盖）
- C 层 write/pwrite/mmap 到“已打开 fd”的内容写入不可见（open/openat 路径可见即可定位归属）；
- open$NOCANCEL / fopen$NOCANCEL 变体未挂（ObjC 层 NSData/NSString 写入已覆盖）；
- Flutter(Dart) 层、BoringSSL 加密直连、sysctl/getifaddrs 仍不覆盖；
- Keychain 只记键名不取值；不做任何写/删操作；动态 Hook 只覆盖 ABI 白名单方法。

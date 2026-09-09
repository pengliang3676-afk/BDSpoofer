# HMProbe4 —— 河马剧场 只读诊断探针 v4（取证收尾版）

在 v3（constructor 提前安装 / C 层 open/fopen interpose / 快照增强）基础上，只做两处增量，目标是给 v3 未抓到写入栈的三个数美疑似文件（.PID4SM.txt、come2、PdnuLKiM；FP_SEQ 已由 Keychain 生命周期实锤）最终定罪。
**全程只读**：不改任何返回值、不拦截任何请求、不外传数据；报告只写到 App 沙盒 Documents 并可手动导出。

## v4 相对 v3 的改动
1. **重点路径规则扩大（hm_interestPath）**
   - 关键词补 `pid4sm`、`fp_seq`；
   - 新增 hm_topLevelProbe：先规范化 `.`/`..`，统一 `/var` 与 `/private/var`，并按完整沙盒目录边界剥离前缀；相对沙盒路径中 **Documents 顶层路径**（深度=2）一律视为重点，**任意点开头目录/文件**（.PID4SM.txt、.UTSystemConfig）一律视为重点；
   - 这些路径的首次 ObjC 写入（NSString/NSData writeToFile、NSFileManager createFile）和 C 层写打开都会在报告 7.1/7.2 打印首次短栈。v3 其实已对每个首次路径抓栈，只是报告只打印关键词命中项，v4 让目标文件的栈能被打印出来。
2. **Hook 安装再提前一个身位：新增 +load 首轮安装**
   - 初始化（门控、自身 __TEXT 区间、全局状态、Hook 槽位）抽成 hm_bootstrap()，dispatch_once 保证只执行一次；
   - 新增 HMProbeEarly 的 +load：注入库作为主程序依赖，在此只同步安装 NSUserDefaults、文件写入和固定目标 Hook；类簇安装共享一次类列表，不在 +load 做风控类方法深度枚举；
   - 首轮安装由独立 `dispatch_once` 保证线程安全和跨线程可见性；constructor 调同一入口兜底，并把全量类枚举留给原有主队列深度扫描重试链，普查/浮窗调度不变。

v3 的九节结构、ABI 白名单、Keychain 不记值、脱敏、线程局部递归抑制、自身镜像栈帧剔除、浮窗透传、dyld interpose 全部保留。

## 门控
仅在 App 显示名含“河马”或 bundleId 含 hema/hmjc/hemojc 的主进程运行，跳过 .appex。

## 操作步骤
1. Codex 只读复审本工程；通过后 Actions 编译（arm64+arm64e，链接 Security.framework，产物 HMProbe4.dylib）；
2. TrollFools 注入前**先移除 HMProbe3/HMProbe2**，避免多个探针同时挂；
3. **杀进程冷启动**（+load/constructor 首轮安装只有冷启动才赶在 SDK 取值前）→ 打标记 → 走登录/任务 2~3 分钟 → 点「HM探针4 导出」；
4. 验收只看 7.1：
   - .PID4SM.txt / FP_SEQ.txt / come2 / PdnuLKiM 各自的「首次短栈」是否落在主二进制，且与 FP_SEQ Keychain 栈（0x3f75xxx/0x3feexxx 区）、getDeviceId 栈（+0x6805f4 区）同源 → 同源即数美，取证闭环；
   - 若某文件冷启动全程 0 写入却存在，说明写入早于 +load，再单独议。

## 边界（v4 仍不覆盖）
- C 层 write/pwrite/mmap 到“已打开 fd”的内容写入不可见；
- Flutter(Dart) 层、BoringSSL 加密直连、sysctl/getifaddrs 不覆盖；
- Keychain 只记键名不取值；不做任何写/删操作；动态 Hook 只覆盖 ABI 白名单方法。

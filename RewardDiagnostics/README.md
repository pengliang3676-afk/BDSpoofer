# 百度活动异常临时诊断插件 0.3.0

目标 Bundle ID：com.baidu.BaiduMobileInfo。独立诊断组件，不包含随机参数或越狱隐藏功能。

## 本次用途

0.2.0 的实际记录已出现 HTTP 200、errno 为数字 0、data.isSafe 为 false，且目标请求的 zid 非空。
此前只保存白名单字段，不能排除深层结构中还有原因字段。0.3.0 补充一次完整响应文本采集。
它帮助确认接口实际返回了哪些信息；即使正文没有原因码，也不能据此还原服务器内部规则。

## 安装及唯一配合步骤

1. 在巨魔注入器 / TrollFools 中移除旧的 BDSRewardDiagnostics_0.2.0.dylib（如有 0.1.0 也移除）。
2. 给目标百度应用注入 BDSRewardDiagnostics_0.3.0.dylib，不要同时加载多个诊断版本。
3. 完全退出后重新打开百度，进入原来的异常页面，手机保持连接以便读取结果。
   保持账号、Crane 容器、原插件状态和随机参数不变。无需额外执行提现或反复领取操作。
4. 诊断结束后可移除这个诊断 dylib，再重启应用。移除组件不会自动删除诊断文件。

本组件没有 UI；最低 iOS 15.0，包含 arm64 和 arm64e。
编译、签名和模拟测试不等于已经验证本机注入成功或获得真实响应。

## 两种本地文件

均位于当前百度数据容器的 Documents/BDSRewardDiagnostics/ 下：

- session-时间-随机编号.jsonl：有限、经过字段过滤的摘要，保留 HTTP 状态、JSON 类型、errno、isSafe、
  zid 是否存在/非空/占位以及根层和 data 层的短原因字段。摘要不包含完整正文。
- response-once-0.3.0.json：私有完整响应文件。response_text 字符串保存 XHR 暴露的原始文本，
  包括空白、未知字段和嵌套结构；其他键记录版本、采集时间、本地页面编号、请求序号和 HTTP 状态。
  读取外层 JSON 后才能取得原正文；这不是 TLS 报文原始字节，也不是服务器签名的证据。

完整响应可能含有账号标识或其他私密字段，不做正文脱敏以免丢失待检查字段。
文件只写入本机专用目录，不上传、不输出到控制台、不混入摘要、源代码或分发包。
分析/对外反馈时需要选择必要字段并脱敏，不要公开整个文件。

## 一次性采集规则

- 只观察 HTTPS 百度域名上精确路径 /incentive/uanti 的 XMLHttpRequest。
- 只有收到正常 load 终止事件、最终 responseURL 仍匹配目标、HTTP 状态为 100–599，才尝试保存。
- 只保存 responseType 为空或 text 的 responseText；JSON 对象和二进制不会被重新序列化冒充原文。
- 最多 1,048,576 个 UTF-16 代码单元。超过上限会跳过并记录 size_limit，绝不截断后声称完整。
  最终文件还受 8 MiB 大小限制。空文本或无效 JSON 也会原样保存，方便区分空响应和解析失败。
- 每页最多成功发送一次私有消息；原生层每次应用进程只尝试写一次。
  同一数据容器、同一版本只保留一个成功文件，重新启动或刷新不覆盖它。
  如一次写入失败，摘要显示失败；重启应用后可重新尝试。已有文件则保留原文件及其原采集时间。
- 原生层先写独立临时文件并刷新，再以不覆盖的方式发布最终文件；失败时清理本次临时文件。
  进程突然终止可能留下自己的临时文件，不会自动删除其他文件。目录 0700，文件 0600，
  使用 iOS 首次解锁后的文件保护属性。

## 摘要事件判读

| 事件 | 含义 |
| --- | --- |
| native_ready / observer_ready | 原生组件/页面观察器已运行，不表示目标请求已经发生 |
| request_started / request_complete | 目标 XHR 开始/结束；结合 terminal_event、http_status、json_state 判断 |
| full_response_saved | 原生层已成功保存完整文件；含 filename、file_bytes、本地请求关联信息 |
| full_response_already_exists | 原文件已存在并保留，不能当作本次的新响应 |
| full_response_save_failed | 私有文件未成功保存，capture_reason 表明写入或序列化阶段问题 |
| full_response_skipped | 正文类型不支持、读取失败、超限或消息发送失败；没有声称完整采集成功 |
| observation_window_elapsed | 15 秒观察窗口结束，不代表请求本身超时；不会主动取消请求 |

同一个 WKWebView 重新导航会重置 request_id；按日志顺序、observer_ready、page_id 和时间关联。
security_param_nonempty=true 只说明查询参数里有非空值，不证明该值有效或服务器据此拒绝。
errno 字符串 "0" 和数字 0 不同，isSafe 字符串 "0" 在 JS 中为真；摘要保留实际类型。
若只有弹窗而没有新的 request_started，可能是页面沿用了先前结果，不能视作新请求。

## 行为边界与测试

不读取请求体、Cookie、请求头，不保存完整请求 URL 或请求参数值。
不修改请求、响应、资格结果、插件配置、账号或容器，不自动发请求、重放请求或领取奖励。
只覆盖 XHR；不覆盖 fetch、原生请求或请求前的 SDK 回调。
页面消息属于不可信输入，原生层检查类型、字段和大小；日志仍然只是客户端观测证据。
摘要每页最多 128 次请求，每个进程最多 1024 条/512 KiB，单行最多 4096 字节。
完整响应有独立的写入路径和上限，不会被摘要单行限制丢弃。
方法包装仍可能产生运行时影响，模拟测试不能保证与所有第三方插件完全兼容。

开发测试：node --test RewardDiagnostics/observer.test.cjs
macOS/Xcode 构建：bash RewardDiagnostics/build.sh
输出：dist-ui1/reward-diagnostics/，包含 dylib、SHA256SUMS.txt、源码和本说明。
构建检查两个架构、临时签名与签名校验。包内不包含真实手机日志。

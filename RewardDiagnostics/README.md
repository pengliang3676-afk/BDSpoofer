# 百度现金统计临时取证组件 0.4.0

目标 Bundle ID：com.baidu.BaiduMobileInfo。只记录活动页现金统计的客户端发送证据，不修改收益或资格。

## 使用

1. 在巨魔注入器 / TrollFools 中移除旧 BDSRewardDiagnostics_0.3.0.dylib，注入 BDSRewardDiagnostics_0.4.0.dylib。
   如有更早诊断版本，也先移除；不同版本不能同时加载。原插件与账号、容器配置保持当前状态。
2. 完全退出百度后重新打开活动页，停留约 5 秒。无需额外执行领取或提现。
3. 手机保持连接，读取当前容器 Documents/BDSRewardDiagnostics/session-*.jsonl，按 version=0.4.0 筛选。
4. 取证结束后移除本诊断组件。旧日志仍保留，本版本不删除或覆盖旧完整响应文件。

## 本次运行范围

0.4.0 实际嵌入 telemetry.js，停止运行旧的资格接口观察器。
observer.js 和 observer.test.cjs 保留为历史源码/回归资料，编译脚本不再嵌入它们。

仅处理 HTTPS h2tcbox.baidu.com 的 /ztbox，且解析出的事件 actiondata.id=10290、content.page=y_mission_index。
从实际交给图片 src/setAttribute、XHR 或 sendBeacon 的参数中提取现金字段 actiondata.content.ext.num。
同时通过 PerformanceObserver 被动记录这个目标的资源条目，补充浏览器的加载信息。
不主动发送、重放或重试统计，不创建额外图片请求，不改变原请求和回调，不读响应正文或请求头。

查询参数 data 中的 JSON 是重点路径。XHR/Beacon 使用表单字符串时也检查其中 data 字段。
不消费 Blob、流或自定义对象，不额外调用对象 toString；这类数据不在本版本捕获范围。
不覆盖原生 SDK 内部发送，或未知第三方地址；不能把范围外的缺失记录解释成没有上传。

## 保留字段与隐私

保留固定目标地址、原始现金值及类型、事件 ID、事件类型、事件时间、本地 document/page/capture 编号和加载状态。
现金字符串必须是限定长度的数字，不保留任意文本。JS 和原生层都过滤字段。
完整 URL 的查询值、原始日志正文、Cookie、账号 ID、安全参数等不写入诊断文件。
每个文档最多观察 128 个 API 请求、128 个资源条目、768 条消息；每个应用进程日志最多 1024 条/512 KiB，单条 4096 字节。
没有 UI；iOS 最低 15.0，包含 arm64 与 arm64e。

## 证据如何解释

| 事件 | 能证明什么 |
| --- | --- |
| telemetry_ready | 各观察入口是否安装成功，不能当作请求已发生 |
| telemetry_attempt | 在原始发送 API 调用前看到了目标参数，原 API 仍可能抛错 |
| telemetry_handed_to_browser | 原始 src setter/XHR send 正常返回，不能单凭这个证明网络成功 |
| telemetry_image_load | 对应图片产生 load；支持图片加载成功，不直接提供 HTTP 状态码、最终重定向主机或服务器处理内容 |
| telemetry_image_error | 图片产生 error；可能是网络或解码错误，不能断言服务器没有收到 |
| telemetry_xhr_complete | 记录 loadend、终止类型、实际 HTTP 状态及最终 URL 是否仍为目标，不能把 HTTP 200 当作余额业务被接受 |
| telemetry_beacon_return | queued=true 仅表示浏览器接受排队，不表示服务器确认收到 |
| telemetry_resource | 浏览器产生资源记录，保留可用的时长、大小、responseStatus；0 或缺失不是 HTTP 200，也不能直接判断缓存命中 |
| telemetry_api_threw | 原 API 抛错，同一异常仍交给应用 |
| telemetry_observation_expired | 20 秒观察窗口到期，仅移除观察监听，不取消请求 |
| telemetry_superseded | 同一图片/XHR 被改为另一次请求，旧记录不能对应后续加载事件 |
| telemetry_listener_failed | 监听未完整安装，不影响原始请求调用 |

用 document_id + page_id + capture_id 关联 API 与加载结果。capture_id=0 表示资源记录未对应到一个已捕获 API。
相同 URL 被多次使用时，资源条目标记 correlation_ambiguous=true，不强行关联到其中一次。
事件 payload_timestamp_ms 来自原统计参数；timestamp_ms 由原生层记录消息时间。
若统计事件有现金值，cash_num 才会出现；cash_num_present 及类型可以区分缺失和不符合允许格式。

核实“实际带出 2.53”至少应看到原发送入口记录 cash_num=2.53；加载/资源结果可补充传输完成情况。
这属于客户端观测，不是服务端签名审计。跨域图片 load 或不完整 Resource Timing 不能证明服务器内部最终如何使用数据。
不能凭源码，或另一时间、另一条 action=zubc 的通信记录，替代目标 action=zpblog 的实际记录。
如果本次没有目标事件，先检查 ready 和浏览器是否真的产生该统计，不生成一个假的测试上报来冒充证据。

## 构建验证

node --test RewardDiagnostics/observer.test.cjs RewardDiagnostics/telemetry.test.cjs
bash RewardDiagnostics/build.sh

测试检查原始参数/返回值/异常/回调保持、端点与事件范围、字段过滤、并发与复用关联、生命周期与资源状态。
macOS/Xcode 编译两个架构、合并并执行临时签名和校验。构建与测试通过不等于手机已经采到证据。
分发包只含组件、源码与说明，不含真实手机日志或账号数据。

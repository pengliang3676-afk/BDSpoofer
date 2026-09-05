# 百度活动异常临时诊断插件 0.2.0

这是独立的临时诊断组件，适用目标 Bundle ID 为 com.baidu.BaiduMobileInfo。
它不包含原插件的随机参数、反关联或越狱隐藏功能。

## 0.2.0 新增

- 仅检查目标 URL 查询参数中 zid 是否存在、是否非空、是否为 null/undefined 占位文本，以及重复个数；不保存值。
- 从响应根层与 data 层提取允许的原因码和简短说明，记录为 reason_fields。
  只允许 reasonCode、reason_code、riskCode、risk_code、subErrno、sub_errno、reason、
  riskMessage、message、errmsg、msg、tips，最多 8 项、总计 256 个文本字符。
- 原因文本过滤常见凭据赋值、URL、邮箱、长标识和长数字；不保存完整响应。
  短说明仍可能包含业务上下文，诊断日志保留在本地专用目录。
- security_param_nonempty=true 只证明 URL 中有非空值，不证明值有效，也不证明服务器据此拒绝。
  没有原因字段也不等于后台没有原因；本版本不观察原生 SDK 回调。

升级时先在注入器中移除旧的 BDSRewardDiagnostics_0.1.0.dylib，再注入 0.2.0。
不要同时加载两个版本。这里只替换诊断组件。

## 它要回答什么

此前读取的当前版本活动页代码中，/incentive/uanti 的正常返回未通过资格检查，
以及请求失败、业务错误、JSON 解析失败，都可能进入同一个“账号存在风险”提示。
本组件记录下一次实际请求的有限结果，帮助区分这些分支。
即使捕获到资格未通过，也不能据此知道服务器采用了哪条风控规则。

## 安装与采集

1. 用巨魔注入器 / TrollFools 给目标百度应用注入 BDSRewardDiagnostics_0.2.0.dylib；已装旧诊断版本时先移除旧版。
   它是单独的诊断文件。原有插件和配置保持当前状态，以便比较。
2. 完全退出百度后重新打开，进入此前出现异常的活动页面。
3. 手工进行一次正常操作，等待原有异常出现；记录当时的时间和操作。
   组件不会代替用户领取奖励或提现，也不会改变资格判断。
4. 日志位于百度当前数据容器 Documents/BDSRewardDiagnostics/ 下，
   文件名为 session-时间-随机编号.jsonl。
   使用 Crane 时，要读取这次实际使用的容器，不能只按显示名称猜测路径。
5. 导出对应日志后，只移除这个诊断 dylib，再完全退出并重新打开百度。
   移除组件不会自动删除日志；需要时可单独删除 BDSRewardDiagnostics 目录。

组件没有设置界面，也没有“修复异常”按钮。安装必须使用原始、完整的构建文件。
iOS 最低部署版本为 15.0，包含 arm64 和 arm64e。
本次构建与模拟测试不代表已经验证当前手机的注入和页面捕获效果。

## 日志判读

| 事件或字段 | 含义与限制 |
| --- | --- |
| native_ready | 原生组件已运行，init_hook/view_hook 是各 Hook 的安装结果 |
| observer_ready | 某个页面已装入 XHR 观察器，不代表请求已发生 |
| request_started | 观察到目标 XHR 即将调用原始 send；它仍可能同步抛错 |
| request_complete | 观察到 loadend；结合 terminal_event、http_status 和 JSON 字段判断 |
| send_threw | 原始 send 同步抛错；同一异常继续交给应用处理 |
| terminal_event=error/timeout/abort | 分别为 XHR 的错误、超时、取消事件 |
| json_state=invalid | 捕获的文本未能解析为 JSON |
| business_code_is_number_zero=true | errno 严格等于数字 0，与此前所读页面的判断一致 |
| is_safe_present / is_safe_type / is_safe_truthy | 字段是否存在、类型、按 JavaScript 规则转换的真假值 |
| observation_window_elapsed | 观察已超过 15 秒并停止；不能当作实际网络超时 |
| controller_install_failed / observer_install_failed / existing_page_install_failed / view_attach_failed | 观察器未成功安装，不能从缺失记录推断请求结果 |

例如：同一次 request_complete 中，terminal_event 为 load、HTTP 成功、JSON 有效、
errno 为数字 0、data 是对象且 isSafe 确实存在但为假，
支持“这次返回的资格未通过”，不支持“已经查明服务器拒绝原因”。

errno 为字符串 "0" 与数字 0 不同；isSafe 为字符串 "0" 在 JavaScript 中仍为真。
日志保留类型，不能仅按显示文字解释。

只有 observer_ready，没有 request_started，可能是未触发、页面沿用之前的缓存判断、
请求在进入 XHR 前失败、页面使用了别的传输方式，或捕获范围未覆盖。
只出现旧的异常弹窗也不证明新请求已经发生。

request_id 只在当前页面脚本实例内递增；page_id 只标记本地 WKWebView。
同一 WebView 重新导航后序号会重置，请按文件顺序和 observer_ready 分段判读。
这些记录是客户端观测，不是经过服务器签名的审计记录。

## 采集范围与隐私

- 仅处理 HTTPS 百度域名上的精确路径 /incentive/uanti。
- 仅观察 XMLHttpRequest。依据此前缓存页面代码选择该通道，不覆盖 fetch、原生请求或请求前的 SDK 步骤。
- 不读取请求体、Cookie 或请求头。不保存完整 URL 或安全参数值；只检查目标 URL 中 zid 的存在性和空值状态。
- 对范围内的文本响应，仅在内存中解析不超过 65536 个字符的正文，随后提取允许字段。
  不保存完整正文；原因文本只按上述允许字段提取并过滤。
- 不修改 URL、参数、请求头、请求体、响应、资格字段、页面拦截逻辑或原有插件配置。
- 每个页面最多观察 128 次目标请求；每个应用进程最多写入 1024 条、512 KiB 日志。
- JS 消息进入原生层后再次按允许字段过滤。
- JS 的 XHR 方法和 WKWebView 方法会被包装，因此诊断组件本身存在运行时影响。
  模拟测试只能降低行为改变的风险，不能保证与所有页面脚本及其他插件完全兼容。

## 开发与验证

在仓库根目录运行：

    node --test RewardDiagnostics/observer.test.cjs

在带 iPhoneOS SDK 的 macOS / Xcode 环境编译：

    bash RewardDiagnostics/build.sh

输出在 dist-ui1/reward-diagnostics/。
构建脚本编译两个架构、合并、执行临时签名与签名校验，并生成 SHA256SUMS.txt。
本包没有包含真实手机日志或任何账号数据。

# BDDiagCoh —— 百度极速版「三层设备身份对质」只读探针

不修改任何返回值，只观测并出报告。配合 BDSpoofer（卐解）使用。

## 注入顺序（重要）
TrollFools 注入时**先选 BDSpoofer dylib，再选 BDDiagCoh.dylib**，保证探针读到的是伪装之后的最终值。

## 使用步骤
1. 新容器点完卍解红色「一键基础随机」，TrollFools 同时注入两个 dylib；
2. 打开百度极速版，正常走到要验证的页面（登录、7天签到、首页刷一会），让网络请求真实发出；
3. 点屏幕上的「三层对质 导出」浮窗，分享/保存 `BDDiagCoh_log_*.txt`。

## 报告怎么看
- 开头【三层身份对质表】按 系统版本 / 机型标识 / 物理分辨率 / IDFV / UA中的iOS版本 五个维度，
  自动判 MATCH（全部出口一致）、MISMATCH（括号列出每个值来自哪些出口）、数据不足（该出口本次没被调用）；
- 公共层直采：UIDevice / NSProcessInfo / sysctl / UIScreen 的报告时刻读数；
- UA/网络层：NSMutableURLRequest、WKWebView 实际携带的 User-Agent；每条同时给出
  「入站」（调用方传入的原始值）和「出站最终」（下游伪装链执行后回读到的最终生效值），
  对质表的 UA 判定优先按出站最终值。
- 内部层 Hook 明细：17 个百度内部接口 + 2 个 UA 接口的签名、命中次数、返回样本与短栈。

IDFV 只保留前 8 位用于比对，手机号/UUID/token 全部脱敏。

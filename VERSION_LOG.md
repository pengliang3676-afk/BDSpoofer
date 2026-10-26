# BDSpoofer 版本日志与备份索引（百度极速）

> **任何 AI 接手先看这里，再跑 `git tag`。** 本文件是版本/备份的唯一权威清单。
> 远程仓库：https://github.com/pengliang3676-afk/BDSpoofer.git
> 发布分支：`ship/10.14-01`（`origin/main` 只到 8-25 的 1.8.0，不是主线）。
> 本仓库还含 KSSpoofer（快手）、QuarkSpoofer（夸克）、NDSpoofer（网盘，另仓）等模块，非本清单范围。

---

## 当前最新版本（接手起点）

| 项 | 值 |
|---|---|
| **M 卐解 dylib**（`BDSpoofer.m`） | **10.27.03**（CUID 隔离拆成独立开关） |
| **X 卍解管理器**（`CraneManager/BDSCraneManager.m`） | **10.18.02**（本次未改，保持） |
| 基线 commit | `4003875`（= v10.27.02，`ship/10.14-01`） |
| 基线 tag | **`v10.27.02`**（本次改前干净基线） |
| 本地产物 | `Desktop\极速\卐-10.27.03.dylib`（CI 出） |
| 本地快照 | `Desktop\极速\backups\10.27.03\`（源码 zip + 产物 + INDEX.txt） |
| 当前状态 | CUID 五件套（cuid/iid/mtjNewCuid/ppaCuid/utdid）容器隔离已从「百度身份参数」总开关拆出，独立成基础组开关「设备标识(CUID)隔离」(cuidIsolation)：默认关、一键基础开、恢复安全关；di/DVIF/UA/IDFV 等仍归 spoofBaiduSDK。三容器真机验证跨容器 CUID 已全部不同。 |

---

## 版本记录表

| 日期 | M(dylib) | X(管理器) | commit | tag | 主要改动 |
|---|---|---|---|---|---|
| 10-27 | 10.27.03 | 10.18.02 | 见 `v10.27.03` | `v10.27.03` | CUID 五件套容器隔离从「百度身份参数」总开关拆成独立基础组开关「设备标识(CUID)隔离」(cuidIsolation)：默认关、一键基础显式开、恢复安全关；di/DVIF/UA/IDFV 等其余百度身份项仍归 spoofBaiduSDK。仅 M 升，X 不重编（手机上旧 X 不显示该开关，用 M 悬浮球一键基础即可）。自检零段加开关状态行。 |
| 10-27 | 10.27.02 | 10.18.02 | `4003875` | `v10.27.02` | 修 BaiduMTJNewCUID（统计 CUID）跨容器剪贴板残留：它不走钥匙串而存 named UIPasteboard（com.baidu.mtj.pasteboard.cuid，跨容器共享），hook 首次捕获前先清空，逼原 IMP 回退取本容器已换新的主 CUID 自然写回。三容器真机验证跨容器五标识两两不同。 |
| 10-27 | 10.27.01 | 10.18.02 | `dfb71cb` | `v10.27.01` | 修主 CUID 从未被随机的根因：新容器/新随机首启 SecItemDelete 物理清空共享钥匙串 CUID 组（B83JBVZ6M5.com.baidu.baidumobile.cuid，含 seedid），让 SDK 自然重生合法 51 位 CUID；hook 7.17.0 真实类（BBACuidSDK/BaiduMtjCuidSDK/BaiduMTJNewCUID/PPACUID/UTDIDMain），首次取新值后按容器锁定，isDeviceCloned 固定 NO。 |
| 10-26 | 10.26.01 | 10.18.02 | 见 `v10.26.01` | `v10.26.01` | 自检面板加「设备标识实测（只读·抓CUID）」：运行时反射枚举 BBACuidSDK/BaiduMobStat/UTDID 真实类，安全只读调用抓真实 CUID 明文（核对 len=51、无空格），**不改任何值、不实现补丁**；仅 M 升 10.26.01，X 保持 10.18.02 |
| 10-26 | 10.18.05 | 10.18.02 | `8a420a9` | `base-10.18.05-pre-cuid` | **CUID 修复前基线锁定**（之后为 KSSpoofer 快手改动，不影响极速版本号） |
| 10-18 | 10.18.05 | 10.18.02 | `0e89907` | — | UDID 只替换百度自己的读取，不再钩钥匙串 |
| 10-18 | 10.18.04 | 10.18.02 | `c502624` | — | 停用 UDID 钩子，先让极速能打开 |
| 10-18 | 10.18.03 | 10.18.02 | `cc67e24` | — | 去掉启动时 UDID 钩子，避免极速闪退 |
| 10-18 | 10.18.02 | 10.18.02 | `b9ab542` | — | 主界面显示容器 UDID，卍解可清除推送编号 |
| 10-18 | 10.18.01 | 10.18.01 | `662d90b` | — | 删掉仅走代理网，代理检测隐藏默认一直开 |
| 10-17 | 10.17.09 | — | `363aa7b` | — | 独立 L2TP 看门，断开时关闭极速 |
| 10-17 | 10.17.07 | — | `64bc050` | — | 金额上报同时拦提现页浏览和点击 |
| 10-17 | 10.17.01 | — | `56b76cb` | — | 版本号改按日期递增 |
| 10-14 | 10.14.02 | 10.14.02 | `bf39a14` | `v10.14.02` | 修复悬浮窗 overlay 自身拦截触摸（hitTest 空白穿透，协议按钮可点） |
| 10-14 | 10.14.01 | 10.14.01 | `113823d` | `v10.14.01` | 悬浮球改独立 overlay window（高层级防遮挡+穿透） |
| 10-09 | 10.01.31 | — | `d2924b8` | — | 二维码整屏单码 |
| 10-09 | 10.01.23 | — | `ba6fdc3` | — | 面板排版重构 |
| 10-02 | 10.01.03 | — | `db5e346` | `base-10.01.03-good` | 反 Hook 自检（稳定基线） |
| 10-02 | 10.01.02 | — | `2c8f29c` | `v10.01.02` / `broken-10.01.02-dyld` | dyld 钩子补判空修崩溃 |
| 09-30 | 9.30-29 | — | — | `good-9.30-29` | 稳定基线 |
| 09-30 | 9.30-19 | — | — | `good-9.30-19` | 电池重开不跳变、仅一键基础换新 |
| 08-25 | 1.8.0 | — | `c0a77ae` | `v1.7.3` 等 | 见 `origin/main`（旧主线，1.8.x 统一随机池） |

> 更早版本与完整提交：`git log --oneline --all`、`git tag`。

---

## 每次发布必须做的备份规范（四件套）

> 目的：任何 AI 接手，靠 `git tag` + 本文件 + 本地固定目录三处即可定位，不依赖记忆。

1. **改前打 tag**：在当前干净 commit 打 tag，命名 `base-<版本>-<说明>`（基线）或 `v<版本>`（发布），并 `git push origin <tag>`。
2. **改后再打 release tag**：新版编译验证通过后打 `v<新版本>` 并推送。
3. **本地固定目录**：`Desktop\极速\backups\<版本>\` 内放三样：
   - 源码快照：`git archive --format=zip --prefix=BDSpoofer-<版本>/ <tag> -o BDSpoofer-source-<版本>-<commit前7位>.zip`
   - 产物：`卐-<版本>.dylib`、`卍-<版本>.deb`
   - `INDEX.txt`：版本 / commit / tag / 内容 / 回退方法 / 下一版计划。
4. **更新本文件**：在版本记录表追加一行，commit 并推送。

> 网络：git 直连 GitHub 时通时断（连接重置）。失败时挂本机 xray：
> `git -c http.proxy=socks5://127.0.0.1:10808 -c https.proxy=socks5://127.0.0.1:10808 <push|fetch>`

---

## 回退方法

- 有网：`git checkout <tag>`（例：`git checkout base-10.18.05-pre-cuid`）
- 离线：解压 `Desktop\极速\backups\<版本>\BDSpoofer-source-*.zip`，得到完整工程。

## 命名约定

- M/X 版本号：`月.日.当天序号`，如 `10.26.01`；M dylib 与 X 管理器同次发布共用日期标签。
- 旧版永不覆盖、必须可回退；每次改动升版本号。
- 内部 `configVersion` 整数仅作配置迁移计数，不等于发布版本号。
- 编译：Windows 无 iPhone SDK，本机只跑 `python scripts/validate_ui1.py`；真编译靠 GitHub Actions（push 触发，产物 `M-<ver>.dylib` / `X-<ver>.deb`，FAT arm64+arm64e）。

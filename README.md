# HMSpoofer 1.1.1

河马剧场 `com.cbn.hmjc` 主 App 的注入式设备参数 dylib，跳过 App 扩展。
源码不执行清理，不直接修改业务请求或第三方 SDK。

## 1.1.1 修复

- sysctl/sysctlbyname 对四个明确的只读查询先使用内部缓冲调用真实函数，失败立即原样返回；成功后按调用前容量处理输出。长度查询不读取未初始化容量，短缓冲返回 -1、errno=ENOMEM 并回写所需长度。用户地址访问通过同进程 Mach VM 接口检查，访问失败返回 EFAULT。
- uname/statfs 原调用失败时不覆写；四个符号分别 dlsym 并原子发布，解析重入不会自等。所有必需出口安装、身份保存成功后才激活。
- ObjC 检查完整返回类型及 self/_cmd 参数，先保存原 IMP，继承方法通过 class_addMethod 建立本类覆盖。runtime IMP 保留原签名，不手工 ptrauth_strip。
- 配置校验类型、数值范围、UUID、8 套机型关联和 SKU。自洽旧配置只迁移 schema；无效配置重新生成。保存失败不发布新状态。
- 当前身份在进程内不再替换；“换一套”和“开/关”都只更改待冷启动配置。随机后再切开关不会覆盖待生效身份，随机保留待生效开关选择。
- statfs 仅接受 f_fstypename=apfs 且 f_mntonname 精确为 /var 或 /private/var 的数据卷；原容量至少 50GB，f_bavail<=f_bfree<=f_blocks。
- UIScreen 五个出口仅变换主屏；bounds/applicationFrame 保留方向和窗口边缘语义。增加状态栏以及 UIView/UIWindow 安全区查询，保留隐藏状态和导航栏等额外内边距。外接屏与非全屏窗口保持原值。

## 机型池

| 机型 | machine | board | 标称内存 | 点数 / scale / 像素 | 磁盘 GB |
|---|---|---|---|---|---|
| X | iPhone10,6 | D221AP | 3GiB | 375x812 / 3 / 1125x2436 | 64/256 |
| XS | iPhone11,2 | D321AP | 4GiB | 375x812 / 3 / 1125x2436 | 64/256/512 |
| XS Max | iPhone11,6 | D331pAP | 4GiB | 414x896 / 3 / 1242x2688 | 64/256/512 |
| XR | iPhone11,8 | N841AP | 3GiB | 414x896 / 2 / 828x1792 | 64/128/256 |
| 11 | iPhone12,1 | N104AP | 4GiB | 414x896 / 2 / 828x1792 | 64/128/256 |
| 11 Pro | iPhone12,3 | D421AP | 4GiB | 375x812 / 3 / 1125x2436 | 64/256/512 |
| 11 Pro Max | iPhone12,5 | D431AP | 4GiB | 414x896 / 3 / 1242x2688 | 64/256/512 |
| SE2 | iPhone12,8 | D79AP | 3GiB | 375x667 / 2 / 750x1334 | 64/128/256 |

X 只选 16.x；其余选列明的 16.x/17.x，无 15.7.x。磁盘为十进制 SKU；标称 RAM 和磁盘 SKU 不等于实测系统可用容量。

## 构建和验证

将本目录作为仓库根目录提交即可触发 `.github/workflows/build.yml`。若放在父仓库 HMSpoofer 子目录，必须将工作流另行放到父仓库根 `.github/workflows`；工作流会自动识别源码位置。

工作流固定 Xcode 15.4，先运行 macOS 上的源码回归测试，再编译 iOS 15+ arm64/arm64e、合并并 ad-hoc 签名，逐架构检查 interpose 段并严格校验签名。产物 `HMSpoofer-1.1.1-dylib` 包含 dylib、测试摘要、构建提交和 SHA-256。

## 验证边界

主机测试覆盖 C 输出契约、错误路径、配置、继承方法和结构体返回。iOS 编译不能替代真机的 arm64e PAC、dyld interpose 生效、UIKit 场景/安全区和实际业务采集验证。安全区变换限普通全屏窗口；它不改变物理屏幕，也不能保证所有私有 UIKit 子类出口均被覆盖。

只改已列明的系统出口，不保证全部设备字段来源都已覆盖，不据此声称业务请求已经上传了伪装值，亦不保证服务端的身份判断结果。
